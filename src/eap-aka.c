/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <ell/ell.h>

#include "src/missing.h"
#include "src/eap.h"
#include "src/eap-private.h"
#include "src/crypto.h"
#include "src/simutil.h"
#include "src/simauth.h"

/*
 * EAP-AKA specific values
 */
#define EAP_AKA_AUTN_LEN	16
#define EAP_AKA_AUTS_LEN	14
#define EAP_AKA_RES_LEN		8
#define EAP_AKA_K_RE_LEN	32

#define EAP_AKA_KDF_DEFAULT	0x0001

#define EAP_AKA_ST_CHALLENGE	0x01
#define EAP_AKA_ST_AUTH_REJECT	0x02
#define EAP_AKA_ST_SYNC_FAILURE	0x04
#define EAP_AKA_ST_IDENTITY	0x05
#define EAP_AKA_ST_NOTIFICATION	0x0c
#define EAP_AKA_ST_CLIENT_ERROR	0x0e

/*
 * Internal client state, tracked to ensure that we are receiving the right
 * messages at the right time.
 */
enum eap_aka_state {
	EAP_AKA_STATE_UNCONNECTED = 0,
	EAP_AKA_STATE_IDENTITY,
	EAP_AKA_STATE_CHALLENGE,
	EAP_AKA_STATE_SUCCESS,
	EAP_AKA_STATE_ERROR
};

struct eap_aka_handle {
	enum eap_aka_state state;
	enum eap_type type;
	/* Identity from SIM */
	char *identity;

	/* Derived master key */
	uint8_t mk[EAP_SIM_MK_LEN];

	/* Derived K_encr key from PRNG */
	uint8_t k_encr[EAP_SIM_K_ENCR_LEN];

	/* Derived K_aut key from PRNG, extended for AKA' */
	uint8_t k_aut[EAP_AKA_PRIME_K_AUT_LEN];

	/* Derived MSK from PRNG */
	uint8_t msk[EAP_SIM_MSK_LEN];

	/* Derived EMSK from PRNG */
	uint8_t emsk[EAP_SIM_EMSK_LEN];

	/* Flag set if AT_ANY_ID_REQ was present */
	bool any_id_req : 1;

	/* Flag to indicate protected status indications */
	bool protected : 1;

	/* Authentication value from AuC */
	uint8_t autn[EAP_AKA_AUTN_LEN];

	/* re-auth key */
	uint8_t k_re[EAP_AKA_K_RE_LEN];

	uint8_t rand[EAP_SIM_RAND_LEN];

	char *kdf_in;

	uint8_t *chal_pkt;
	uint32_t pkt_len;

	struct iwd_sim_auth *auth;
	unsigned int auth_watch;
};

static void eap_aka_clear_secrets(struct eap_aka_handle *aka)
{
	explicit_bzero(aka->mk, sizeof(aka->mk));
	explicit_bzero(aka->k_encr, sizeof(aka->k_encr));
	explicit_bzero(aka->k_aut, sizeof(aka->k_aut));
	explicit_bzero(aka->k_re, sizeof(aka->k_re));
	explicit_bzero(aka->msk, sizeof(aka->msk));
	explicit_bzero(aka->emsk, sizeof(aka->emsk));
}

static void eap_aka_free(struct eap_state *eap)
{
	struct eap_aka_handle *aka = eap_get_data(eap);

	if (aka->auth)
		sim_auth_unregistered_watch_remove(aka->auth, aka->auth_watch);

	eap_aka_clear_secrets(aka);

	l_free(aka->identity);
	l_free(aka->kdf_in);
	l_free(aka);

	eap_set_data(eap, NULL);
}

static bool derive_aka_mk(const char *identity, const uint8_t *ik,
		const uint8_t *ck, uint8_t *mk)
{
	int ret;
	struct iovec iov[5];
	struct l_checksum *checksum = l_checksum_new(L_CHECKSUM_SHA1);

	if (!checksum) {
		l_error("could not create SHA1 checksum");
		return false;
	}

	iov[0].iov_base = (void *)identity;
	iov[0].iov_len = strlen(identity);
	iov[1].iov_base = (void *)ik;
	iov[1].iov_len = EAP_AKA_IK_LEN;
	iov[2].iov_base = (void *)ck;
	iov[2].iov_len = EAP_AKA_CK_LEN;

	if (!l_checksum_updatev(checksum, iov, 3))
		goto mk_error;

	ret = l_checksum_get_digest(checksum, mk, EAP_SIM_MK_LEN);
	l_checksum_free(checksum);

	return (ret == EAP_SIM_MK_LEN);

mk_error:
	l_checksum_free(checksum);
	l_error("error deriving master key");
	return false;
}

static void eap_aka_finish(struct eap_state *eap)
{
	struct eap_aka_handle *aka = eap_get_data(eap);
	uint8_t session_id[1 + EAP_SIM_RAND_LEN + EAP_AKA_AUTN_LEN];

	session_id[0] = EAP_TYPE_AKA;
	memcpy(session_id + 1, aka->rand, EAP_SIM_RAND_LEN);
	memcpy(session_id + 1 + EAP_SIM_RAND_LEN, aka->autn, EAP_AKA_AUTN_LEN);

	eap_method_success(eap);
	eap_set_key_material(eap, aka->msk, 32, aka->emsk, 32, NULL, 0,
					session_id, sizeof(session_id));
}

static void check_milenage_cb(const uint8_t *res, const uint8_t *ck,
		const uint8_t *ik, const uint8_t *auts, void *data)
{
	struct eap_state *eap = data;
	struct eap_aka_handle *aka = eap_get_data(eap);

	size_t resp_len = aka->protected ? 44 : 40;
	uint8_t response[EAP_SIM_ROUND(resp_len + 4)];
	uint8_t *pos = response;

	if (auts) {
		/*
		 * If AUTS is non NULL then the SQN was not correct, send AUTS
		 * to server which will update the SQN and send another
		 * challenge packet.
		 */
		l_free(aka->chal_pkt);
		aka->chal_pkt = NULL;

		pos += eap_sim_build_header(eap, aka->type,
				EAP_AKA_ST_SYNC_FAILURE, pos, 24);
		pos += eap_sim_add_attribute(pos, EAP_SIM_AT_AUTS,
				EAP_SIM_PAD_NONE, auts, EAP_AKA_AUTS_LEN);

		eap_method_respond(eap, response, 24);

		return;
	}

	if (!res || !ck || !ik)
		goto chal_error;

	if (aka->type == EAP_TYPE_AKA_PRIME) {
		bool r;
		uint8_t ik_p[EAP_AKA_IK_LEN];
		uint8_t ck_p[EAP_AKA_CK_LEN];

		if (!eap_aka_derive_primes(ck, ik, aka->autn,
				(uint8_t *)aka->kdf_in, strlen(aka->kdf_in),
				ck_p, ik_p)) {
			l_error("could not derive primes");
			goto chal_fatal;
		}

		r = eap_aka_prf_prime(ik_p, ck_p, aka->identity, aka->k_encr,
				aka->k_aut, aka->k_re, aka->msk, aka->emsk);
		explicit_bzero(ik_p, sizeof(ik_p));
		explicit_bzero(ck_p, sizeof(ck_p));

		if (!r) {
			l_error("could not derive encryption keys");
			goto chal_fatal;
		}
	} else {
		uint8_t prng_buf[160];
		bool r;

		if (!derive_aka_mk(aka->identity, ik, ck, aka->mk)) {
			l_error("error deriving MK");
			goto chal_fatal;
		}

		eap_sim_fips_prf(aka->mk, 20, prng_buf, 160);

		r = eap_sim_get_encryption_keys(prng_buf, aka->k_encr,
					aka->k_aut, aka->msk, aka->emsk);
		explicit_bzero(prng_buf, sizeof(prng_buf));

		if (!r) {
			l_error("could not derive encryption keys");
			goto chal_fatal;
		}
	}

	if (!eap_sim_verify_mac(eap, aka->type, aka->chal_pkt, aka->pkt_len,
			aka->k_aut, NULL, 0)) {
		l_error("MAC was not valid");
		goto chal_error;
	}

	aka->state = EAP_AKA_STATE_CHALLENGE;

	pos += eap_sim_build_header(eap, aka->type, EAP_AKA_ST_CHALLENGE,
			pos, resp_len);
	pos += eap_sim_add_attribute(pos, EAP_SIM_AT_RES,
			EAP_SIM_PAD_LENGTH_BITS, res, EAP_AKA_RES_LEN);

	if (aka->protected)
		pos += eap_sim_add_attribute(pos, EAP_SIM_AT_RESULT_IND,
				EAP_SIM_PAD_NONE, NULL, 2);

	pos += eap_sim_add_attribute(pos, EAP_SIM_AT_MAC, EAP_SIM_PAD_NONE,
			NULL, EAP_SIM_MAC_LEN);

	if (!eap_sim_derive_mac(aka->type, response, resp_len, aka->k_aut,
			pos - EAP_SIM_MAC_LEN)) {
		l_error("error deriving MAC");
		goto chal_fatal;
	}

	l_free(aka->chal_pkt);
	aka->chal_pkt = NULL;

	eap_method_respond(eap, response, resp_len);

	if (!aka->protected) {
		eap_aka_finish(eap);

		aka->state = EAP_AKA_STATE_SUCCESS;
	}

	return;

chal_fatal:
	eap_method_error(eap);
	aka->state = EAP_AKA_STATE_ERROR;

	return;

chal_error:
	l_free(aka->chal_pkt);
	aka->chal_pkt = NULL;
	eap_sim_client_error(eap, aka->type, EAP_SIM_ERROR_PROCESS);
}

/*
 * Handles EAP-AKA Challenge subtype
 */
static void handle_challenge(struct eap_state *eap, const uint8_t *pkt,
		size_t len)
{
	struct eap_aka_handle *aka = eap_get_data(eap);
	struct eap_sim_tlv_iter iter;
	const uint8_t *rand = NULL;
	const uint8_t *autn = NULL;
	bool kdf_func = false;
	uint16_t kdf_in_len = 0;

	if (len < 3) {
		l_error("packet is too small");
		goto chal_error;
	}

	if (aka->state != EAP_AKA_STATE_IDENTITY) {
		l_error("invalid packet for EAP-AKA state");
		goto chal_error;
	}

	eap_sim_tlv_iter_init(&iter, pkt + 3, len - 3);

	while (eap_sim_tlv_iter_next(&iter)) {
		const uint8_t *contents = eap_sim_tlv_iter_get_data(&iter);
		uint16_t length = eap_sim_tlv_iter_get_length(&iter);

		switch (eap_sim_tlv_iter_get_type(&iter)) {
		case EAP_SIM_AT_AUTN:
			if (length < EAP_AKA_AUTN_LEN + 2) {
				l_error("malformed AT_AUTN");
				goto chal_error;
			}

			autn = contents + 2;

			break;

		case EAP_SIM_AT_RAND:
			if (length < EAP_SIM_RAND_LEN + 2) {
				l_error("malformed AT_RAND");
				goto chal_error;
			}

			rand = contents + 2;

			break;

		case EAP_SIM_AT_RESULT_IND:
			if (length < 2) {
				l_error("malformed AT_RESULT_IND");
				goto chal_error;
			}

			aka->protected = 1;

			break;

		case EAP_SIM_AT_KDF:
			if (aka->type != EAP_TYPE_AKA_PRIME) {
				l_error("invalid attribute found for EAP-AKA");
				goto chal_error;
			}

			if (length < 2) {
				l_error("malformed AT_KDF");
				goto chal_error;
			}

			if (l_get_be16(contents) != EAP_AKA_KDF_DEFAULT) {
				l_error("KDF requested is not supported");
				goto chal_error;
			}

			kdf_func = true;

			break;

		case EAP_SIM_AT_KDF_INPUT:
			if (aka->type != EAP_TYPE_AKA_PRIME) {
				l_error("invalid attribute found for EAP-AKA");
				goto chal_error;
			}

			if (length < 3) {
				l_error("malformed AT_KDF_INPUT");
				goto chal_error;
			}

			kdf_in_len = l_get_be16(contents);

			if (length < kdf_in_len + 2) {
				l_error("malformed AT_KDF_INPUT");
				goto chal_error;
			}

			aka->kdf_in = l_strndup((const char *)(contents + 2),
					kdf_in_len);

			break;

		case EAP_SIM_AT_NEXT_PSEUDONYM:
		case EAP_SIM_AT_NEXT_REAUTH_ID:
		case EAP_SIM_AT_IV:
		case EAP_SIM_AT_ENCR_DATA:
		case EAP_SIM_AT_PADDING:
		case EAP_SIM_AT_CHECKCODE:
		case EAP_SIM_AT_MAC:
		/*
		 * AT_BIDDING is defined in RFC 5448 (AKA'). It is used to
		 * communicate support for AKA', if supported.
		 */
		case EAP_SIM_AT_BIDDING:
			/* RFC 4187, Section 10.1 */
			break;

		default:
			l_error("attribute %u was found in Challenge",
					eap_sim_tlv_iter_get_type(&iter));
			goto chal_error;
		}
	}

	/* check that the right attributes were found */
	if (!rand || !autn) {
		l_error("AT_RAND or AT_AUTN were not found");
		goto chal_error;
	}

	if (aka->type == EAP_TYPE_AKA_PRIME && (!aka->kdf_in || !kdf_func)) {
		l_error("AT_KDF or AT_KDF_INPUT were not found");
		goto chal_error;
	}

	aka->chal_pkt = l_memdup(pkt, len);
	aka->pkt_len = len;

	/* AKA' needs AUTN for prime derivation */
	memcpy(aka->autn, autn, EAP_AKA_AUTN_LEN);
	/* Keep RAND for session ID derivation */
	memcpy(aka->rand, rand, EAP_SIM_RAND_LEN);

	if (sim_auth_check_milenage(aka->auth, rand, autn, check_milenage_cb,
			eap) < 0) {
		l_free(aka->chal_pkt);
		aka->chal_pkt = NULL;
		goto chal_error;
	}

	return;

chal_error:
	eap_sim_client_error(eap, aka->type, EAP_SIM_ERROR_PROCESS);
}

/*
 * Handles Notification subtype
 */
static void handle_notification(struct eap_state *eap, const uint8_t *pkt,
		size_t len)
{
	struct eap_aka_handle *aka = eap_get_data(eap);
	struct eap_sim_tlv_iter iter;
	int32_t value = -1;

	if (len < 3) {
		l_error("packet is too small");
		goto notif_error;
	}

	eap_sim_tlv_iter_init(&iter, pkt + 3, len - 3);

	while (eap_sim_tlv_iter_next(&iter)) {
		const uint8_t *contents = eap_sim_tlv_iter_get_data(&iter);
		uint16_t length = eap_sim_tlv_iter_get_length(&iter);

		switch (eap_sim_tlv_iter_get_type(&iter)) {
		case EAP_SIM_AT_NOTIFICATION:
			if (length < 2) {
				l_error("malformed AT_NOTIFICATION");
				goto notif_error;
			}

			value = l_get_be16(contents);
			break;

		case EAP_SIM_AT_IV:
		case EAP_SIM_AT_ENCR_DATA:
		case EAP_SIM_AT_PADDING:
		case EAP_SIM_AT_MAC:
			/* RFC 4186, Section 10.1 */
			break;

		default:
			l_error("attribute type %u not allowed in Notification",
					eap_sim_tlv_iter_get_type(&iter));
			goto notif_error;
		}
	}

	if (value == EAP_SIM_SUCCESS && aka->protected &&
			aka->state == EAP_AKA_STATE_CHALLENGE) {
		/* header + MAC + MAC header */
		uint8_t response[EAP_SIM_ROUND(8 + EAP_SIM_MAC_LEN + 4)];
		uint8_t *pos = response;

		/*
		 * Server sent successful result indication
		 */
		eap_aka_finish(eap);

		/*
		 * Build response packet
		 */
		pos += eap_sim_build_header(eap, aka->type,
				EAP_AKA_ST_NOTIFICATION, pos, 20);
		pos += eap_sim_add_attribute(pos, EAP_SIM_AT_MAC,
				EAP_SIM_PAD_NONE, NULL, EAP_SIM_MAC_LEN);

		if (!eap_sim_derive_mac(aka->type, response, pos - response,
				aka->k_aut, response + 12)) {
			l_error("could not derive MAC");
			eap_method_error(eap);
			aka->state = EAP_AKA_STATE_ERROR;
			return;
		}

		eap_method_respond(eap, response, pos - response);

		aka->state = EAP_AKA_STATE_SUCCESS;

		return;
	} else if (value == EAP_SIM_SUCCESS) {
		/*
		 * Unexpected success notification, what should
		 * be done here?
		 */
		l_error("Unexpected success notification");
	} else {
		/*
		 * All other values are error conditions.
		 * Nothing unique can be done for any error so
		 * print the code and signal EAP failure.
		 */
		l_error("Error authenticating: code=%u", value);
	}

notif_error:
	eap_sim_client_error(eap, aka->type, EAP_SIM_ERROR_PROCESS);
}

static void handle_identity(struct eap_state *eap, const uint8_t *pkt,
		size_t len)
{
	struct eap_aka_handle *aka = eap_get_data(eap);
	uint8_t response[EAP_SIM_ROUND(8 + strlen(aka->identity) + 4)];
	uint8_t *pos = response;

	if (aka->state != EAP_AKA_STATE_UNCONNECTED) {
		l_error("invalid packet for EAP-AKA state");
		eap_sim_client_error(eap, aka->type, EAP_SIM_ERROR_PROCESS);
		return;
	}

	aka->state = EAP_AKA_STATE_IDENTITY;
	/*
	 * Build response packet
	 */
	pos += eap_sim_build_header(eap, aka->type, EAP_AKA_ST_IDENTITY, pos,
			20);
	pos += eap_sim_add_attribute(pos, EAP_SIM_AT_IDENTITY,
			EAP_SIM_PAD_LENGTH, (uint8_t *)aka->identity,
			strlen(aka->identity));

	eap_method_respond(eap, response, pos - response);
}

static void eap_aka_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_aka_handle *aka = eap_get_data(eap);

	if (len < 1) {
		l_error("packet is too small");
		goto req_error;
	}

	switch (pkt[0]) {
	case EAP_AKA_ST_IDENTITY:
		handle_identity(eap, pkt, len);
		break;

	case EAP_AKA_ST_CHALLENGE:
		handle_challenge(eap, pkt, len);
		break;

	case EAP_AKA_ST_NOTIFICATION:
		handle_notification(eap, pkt, len);
		break;

	default:
		l_error("unknown EAP-SIM subtype: %u", pkt[0]);
		goto req_error;
	}

	return;

req_error:
	eap_sim_client_error(eap, aka->type, EAP_SIM_ERROR_PROCESS);
}

static const char *eap_aka_get_identity(struct eap_state *eap)
{
	struct eap_aka_handle *aka = eap_get_data(eap);

	return aka->identity;
}

static void auth_destroyed(void *data)
{
	struct eap_state *eap = data;
	struct eap_aka_handle *aka = eap_get_data(eap);

	/*
	 * If AKA was already successful we can return. Also if the state
	 * has been set to ERROR, then eap_method_error has already been called,
	 * so we can return.
	 */
	if (aka->state == EAP_AKA_STATE_SUCCESS ||
			aka->state == EAP_AKA_STATE_ERROR)
		return;

	l_error("auth provider destroyed before AKA could finish");

	aka->state = EAP_AKA_STATE_ERROR;
	eap_method_error(eap);
}

static int eap_aka_check_settings(struct l_settings *settings,
					struct l_queue *secrets,
					const char *prefix,
					struct l_queue **out_missing)
{
	struct iwd_sim_auth *auth;

	auth = iwd_sim_auth_find(false, true);
	if (!auth) {
		l_debug("No SIM driver available for EAP-AKA");
		return -EUNATCH;
	}

	if (!iwd_sim_auth_get_nai(auth)) {
		l_error("SIM driver didn't provide NAI");
		return -ENOENT;
	}

	return 0;
}

static bool eap_aka_common_load_settings(struct eap_state *eap,
						struct l_settings *settings,
						const char *prefix)
{
	struct eap_aka_handle *aka = eap_get_data(eap);
	/*
	 * RFC 4187 Section 4.1.1.6
	 * For AKA, the permanent username prefix is '0'
	 *
	 * RFC 5448 Section 3
	 * For AKA', the permanent username prefix is '6'
	 */
	char id_prefix = (aka->type == EAP_TYPE_AKA) ? '0' : '6';

	/*
	 * No specific settings for EAP-SIM, the auth provider will have all
	 * required data.
	 */

	aka->auth = iwd_sim_auth_find(false, true);
	if (!aka->auth)
		return false;

	aka->auth_watch = sim_auth_unregistered_watch_add(aka->auth,
			auth_destroyed, eap);
	aka->identity = l_strdup_printf("%c%s", id_prefix,
			iwd_sim_auth_get_nai(aka->auth));

	return true;
}

static bool eap_aka_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_aka_handle *aka = l_new(struct eap_aka_handle, 1);

	aka->type = EAP_TYPE_AKA;
	eap_set_data(eap, aka);

	return eap_aka_common_load_settings(eap, settings, prefix);
}

static bool eap_aka_prime_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_aka_handle *aka = l_new(struct eap_aka_handle, 1);

	aka->type = EAP_TYPE_AKA_PRIME;
	eap_set_data(eap, aka);

	return eap_aka_common_load_settings(eap, settings, prefix);
}

static bool eap_aka_reset_state(struct eap_state *eap)
{
	struct eap_aka_handle *aka = eap_get_data(eap);

	aka->state = EAP_AKA_STATE_UNCONNECTED;

	l_free(aka->kdf_in);
	aka->kdf_in = NULL;
	l_free(aka->chal_pkt);
	aka->chal_pkt = NULL;

	eap_aka_clear_secrets(aka);
	memset(aka->autn, 0, sizeof(aka->autn));

	return true;
}

static struct eap_method eap_aka = {
	.request_type = EAP_TYPE_AKA,
	.exports_msk = true,
	.name = "AKA",
	.free = eap_aka_free,
	.handle_request = eap_aka_handle_request,
	.check_settings = eap_aka_check_settings,
	.load_settings = eap_aka_load_settings,
	.get_identity = eap_aka_get_identity,
	.reset_state = eap_aka_reset_state
};

static struct eap_method eap_aka_prime = {
	.request_type = EAP_TYPE_AKA_PRIME,
	.exports_msk = true,
	.name = "AKA'",
	.free = eap_aka_free,
	.handle_request = eap_aka_handle_request,
	.check_settings = eap_aka_check_settings,
	.load_settings = eap_aka_prime_load_settings,
	.get_identity = eap_aka_get_identity,
	.reset_state = eap_aka_reset_state
};

static int eap_aka_init(void)
{
	l_debug("");
	return eap_register_method(&eap_aka);
}

static void eap_aka_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_aka);
}

static int eap_aka_prime_init(void)
{
	l_debug("");
	return eap_register_method(&eap_aka_prime);
}

static void eap_aka_prime_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_aka_prime);
}

EAP_METHOD_BUILTIN(eap_aka, eap_aka_init, eap_aka_exit);
EAP_METHOD_BUILTIN(eap_aka_prime, eap_aka_prime_init, eap_aka_prime_exit);
