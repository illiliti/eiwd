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
#include <alloca.h>
#include <ell/ell.h>

#include "src/missing.h"
#include "src/eap.h"
#include "src/eap-private.h"
#include "src/crypto.h"
#include "src/simutil.h"
#include "src/simauth.h"
#include "src/util.h"

/*
 * EAP-SIM authentication protocol.
 *
 * Open Items:
 *    - Fast Re-authentication. In order to implement this, the higher level
 *      EAP code would need to know/retrieve a fast re-authentication identity
 *      that it would send in the EAP-Start packet. This ID is provided by
 *      the server during the challenge in full authentication. EAP-SIM does
 *      save this ID, but there is no mechanism to provide it to the upper
 *      level EAP system. Once this is done the server will recognize the
 *      ID and send a SIM/Re-authentication request.
 *
 *    - Version validation. Perhaps a real SIM card will provide a version
 *      of EAP-SIM that it supports? Currently we accept any version the
 *      server provides.
 *
 *    - Real SIM authentication. Right now Kc/SRES/Identity values are loaded
 *      from a settings file. If a real SIM is used they would need to be
 *      obtained there. This would require providing the SIM with a RAND, to
 *      have it run its GSM algorithm. Kc/SRES can then be derived from that.
 */

/* RFC 4187, Section 11 */
#define EAP_SIM_ST_START		0x0a
#define EAP_SIM_ST_CHALLENGE		0x0b
#define EAP_SIM_ST_NOTIFICATION		0x0c
#define EAP_SIM_ST_CLIENT_ERROR		0x0e

/* EAP-SIM value lengths */
#define EAP_SIM_NONCE_LEN	16

/*
 * Internal client state, tracked to ensure that we are receiving the right
 * messages at the right time.
 */
enum eap_sim_state {
	EAP_SIM_STATE_UNCONNECTED = 0,
	EAP_SIM_STATE_START,
	EAP_SIM_STATE_CHALLENGE,
	EAP_SIM_STATE_SUCCESS,
	EAP_SIM_STATE_ERROR
};

struct eap_sim_handle {
	enum eap_sim_state state;
	/* Identity from SIM */
	char *identity;

	/* EAP-SIM supported version list */
	uint16_t *vlist;
	uint16_t vlist_len;

	/* Negotiated EAP-SIM version */
	uint16_t selected_version;

	/* Random generated nonce */
	uint8_t nonce[EAP_SIM_NONCE_LEN];

	/* Derived master key */
	uint8_t mk[EAP_SIM_MK_LEN];

	/* Derived K_encr key from PRNG */
	uint8_t k_encr[EAP_SIM_K_ENCR_LEN];

	/* Derived K_aut key from PRNG */
	uint8_t k_aut[EAP_SIM_K_AUT_LEN];

	/* Derived MSK from PRNG */
	uint8_t msk[EAP_SIM_MSK_LEN];

	/* Derived EMSK from PRNG */
	uint8_t emsk[EAP_SIM_EMSK_LEN];

	/* Save RANDS from AT_RAND attribute for session ID derivation */
	uint8_t rands[EAP_SIM_RAND_LEN * 3];

	/* Flag set if AT_ANY_ID_REQ was present */
	bool any_id_req : 1;

	/* Flag to indicate protected status indications */
	bool protected : 1;

	uint8_t *chal_pkt;
	uint32_t pkt_len;

	struct iwd_sim_auth *auth;
	unsigned int auth_watch;
};

static void eap_sim_clear_secrets(struct eap_sim_handle *sim)
{
	explicit_bzero(sim->mk, sizeof(sim->mk));
	explicit_bzero(sim->k_encr, sizeof(sim->k_encr));
	explicit_bzero(sim->k_aut, sizeof(sim->k_aut));
	explicit_bzero(sim->msk, sizeof(sim->msk));
	explicit_bzero(sim->emsk, sizeof(sim->emsk));
}

static void eap_sim_free(struct eap_state *eap)
{
	struct eap_sim_handle *sim = eap_get_data(eap);

	if (sim->auth)
		sim_auth_unregistered_watch_remove(sim->auth, sim->auth_watch);

	eap_sim_clear_secrets(sim);

	l_free(sim->identity);
	l_free(sim->vlist);
	l_free(sim);

	eap_set_data(eap, NULL);
}

/*
 * Derive the master key (MK):
 *  SHA1(identity | kc | nonce | version list | selected version)
 */
static bool derive_master_key(const char *identity, const void *kc,
		const void *nonce, const void *vlist, uint16_t vlist_len,
		uint16_t selected_version, uint8_t *mk)
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
	iov[1].iov_base = (void *)kc;
	iov[1].iov_len = EAP_SIM_KC_LEN * 3;
	iov[2].iov_base = (void *)nonce;
	iov[2].iov_len = EAP_SIM_NONCE_LEN;
	iov[3].iov_base = (void *)vlist;
	iov[3].iov_len = vlist_len;
	iov[4].iov_base = &selected_version;
	iov[4].iov_len = 2;

	if (!l_checksum_updatev(checksum, iov, 5))
		goto mk_error;

	ret = l_checksum_get_digest(checksum, mk, EAP_SIM_MK_LEN);
	l_checksum_free(checksum);

	return (ret == EAP_SIM_MK_LEN);

mk_error:
	l_checksum_free(checksum);
	l_error("error deriving master key");
	return false;
}

/*
 * Handles EAP-SIM Start subtype
 */
static void handle_start(struct eap_state *eap, const uint8_t *pkt,
		size_t len)
{
	struct eap_sim_handle *sim = eap_get_data(eap);
	struct eap_sim_tlv_iter iter;
	uint16_t resp_len;
	uint8_t *response;
	uint8_t *pos;

	if (len < 3) {
		l_error("packet is too small");
		goto start_error;
	}

	if (sim->state != EAP_SIM_STATE_UNCONNECTED) {
		l_error("invalid packet for EAP-SIM state");
		goto start_error;
	}

	eap_sim_tlv_iter_init(&iter, pkt + 3, len - 3);

	while (eap_sim_tlv_iter_next(&iter)) {
		const uint8_t *contents = eap_sim_tlv_iter_get_data(&iter);
		uint16_t length = eap_sim_tlv_iter_get_length(&iter);

		switch (eap_sim_tlv_iter_get_type(&iter)) {
		case EAP_SIM_AT_VERSION_LIST:
			/* Actual len (2) + version 1 (2) + padding (2) */
			if (length < 6) {
				l_error("AT_VERSION_LIST was malformed");
				goto start_error;
			}

			sim->vlist_len = l_get_be16(contents);

			/* check that attribute was properly padded */
			if (length < 2 + align_len(sim->vlist_len, 4)) {
				l_error("AT_VERSION_LIST was malformed");
				goto start_error;
			}

			sim->vlist = l_memdup(contents + 2, sim->vlist_len);

			sim->selected_version = sim->vlist[0];

			break;

		case EAP_SIM_AT_ANY_ID_REQ:
			sim->any_id_req = true;

			break;

		case EAP_SIM_AT_PERMANENT_ID_REQ:
		case EAP_SIM_AT_FULLAUTH_ID_REQ:
			/*
			 * TODO: Server requesting permanent ID/pseudonym
			 */
			break;

		default:
			l_error("attribute %u was found in Start",
					eap_sim_tlv_iter_get_type(&iter));
			goto start_error;
		}
	}

	sim->state = EAP_SIM_STATE_START;

	/* header + AT_NONCE + AT_SELECTED_VERSION */
	resp_len = (8) + (20) + (4);
	if (sim->any_id_req) {
		/* + AT_IDENTITY */
		resp_len += EAP_SIM_ROUND(strlen(sim->identity) + 4);
	}

	l_getrandom(sim->nonce, EAP_SIM_NONCE_LEN);

	response = alloca(resp_len);
	pos = response;

	pos += eap_sim_build_header(eap, EAP_TYPE_SIM, EAP_SIM_ST_START, pos,
			resp_len);
	pos += eap_sim_add_attribute(pos, EAP_SIM_AT_NONCE, EAP_SIM_PAD_ZERO,
			sim->nonce, EAP_SIM_NONCE_LEN);
	pos += eap_sim_add_attribute(pos, EAP_SIM_AT_SELECTED_VERSION,
			EAP_SIM_PAD_NONE, (uint8_t *)&sim->selected_version,
			2);

	if (sim->any_id_req)
		pos += eap_sim_add_attribute(pos, EAP_SIM_AT_IDENTITY,
				EAP_SIM_PAD_LENGTH, (uint8_t *)sim->identity,
				strlen(sim->identity));

	eap_method_respond(eap, response, resp_len);

	return;

start_error:
	eap_sim_client_error(eap, EAP_TYPE_SIM, EAP_SIM_ERROR_PROCESS);
}

static void eap_sim_finish(struct eap_state *eap)
{
	struct eap_sim_handle *sim = eap_get_data(eap);
	uint8_t session_id[1 + sizeof(sim->rands) + EAP_SIM_NONCE_LEN];

	session_id[0] = EAP_TYPE_SIM;

	memcpy(session_id + 1, sim->rands, sizeof(sim->rands));
	memcpy(session_id + 1 + sizeof(sim->rands), sim->nonce,
				EAP_SIM_NONCE_LEN);

	eap_method_success(eap);
	eap_set_key_material(eap, sim->msk, 32, sim->emsk, 32, NULL, 0,
					session_id, sizeof(session_id));
}

static void gsm_callback(const uint8_t *sres, const uint8_t *kc,
		void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_sim_handle *sim = eap_get_data(eap);
	uint16_t resp_len = 8 + 20;
	uint8_t response[resp_len + 4 + (EAP_SIM_SRES_LEN * 3)];
	uint8_t *pos = response;
	uint8_t prng_buf[160];
	uint8_t *mac_pos;
	bool r;

	if (!sres || !kc)
		goto chal_error;

	if (sim->protected)
		resp_len += 4;

	if (!derive_master_key(sim->identity, kc, sim->nonce, sim->vlist,
			sim->vlist_len, sim->selected_version, sim->mk)) {
		l_error("error deriving master key");
		goto chal_fatal;
	}

	eap_sim_fips_prf(sim->mk, 20, prng_buf, 160);

	r = eap_sim_get_encryption_keys(prng_buf, sim->k_encr, sim->k_aut,
					sim->msk, sim->emsk);
	explicit_bzero(prng_buf, sizeof(prng_buf));

	if (!r) {
		l_error("could not derive encryption keys");
		goto chal_fatal;
	}

	if (!eap_sim_verify_mac(eap, EAP_TYPE_SIM, sim->chal_pkt,
			sim->pkt_len, sim->k_aut, sim->nonce,
			EAP_SIM_NONCE_LEN)) {
		l_error("server MAC was invalid");
		goto chal_error;
	}

	sim->state = EAP_SIM_STATE_CHALLENGE;

	/*
	 * TODO: When/If fast re-authentication is supported, the AT_ENCR_DATA
	 *       attribute would be decrypted here. Currently there is no need
	 *       or reason to do this without support for fast
	 *       re-authentication.
	 */

	/* build response packet */
	pos += eap_sim_build_header(eap, EAP_TYPE_SIM, EAP_SIM_ST_CHALLENGE,
			pos, resp_len);

	if (sim->protected)
		pos += eap_sim_add_attribute(pos, EAP_SIM_AT_RESULT_IND,
				EAP_SIM_PAD_NONE, NULL, 2);

	/* save MAC position to know where to write it to */
	mac_pos = pos;
	pos += eap_sim_add_attribute(pos, EAP_SIM_AT_MAC, EAP_SIM_PAD_NONE,
			NULL, EAP_SIM_MAC_LEN);

	/* append SRES for MAC derivation */
	memcpy(pos, sres, EAP_SIM_SRES_LEN * 3);
	pos += EAP_SIM_SRES_LEN * 3;

	if (!eap_sim_derive_mac(EAP_TYPE_SIM, response, pos - response,
			sim->k_aut, mac_pos + 4)) {
		l_error("could not derive MAC");
		goto chal_fatal;
	}

	l_free(sim->chal_pkt);
	sim->chal_pkt = NULL;

	eap_method_respond(eap, response, resp_len);

	if (!sim->protected) {
		/*
		 * Result indication not required, we must accept success.
		 */
		eap_sim_finish(eap);

		sim->state = EAP_SIM_STATE_SUCCESS;
	}

	return;

	/*
	 * fatal, unrecoverable error
	 */
chal_fatal:
	eap_method_error(eap);
	sim->state = EAP_SIM_STATE_ERROR;
	return;

chal_error:
	l_free(sim->chal_pkt);
	sim->chal_pkt = NULL;
	eap_sim_client_error(eap, EAP_TYPE_SIM, EAP_SIM_ERROR_PROCESS);
}

/*
 * Handles EAP-SIM Challenge subtype
 */
static void handle_challenge(struct eap_state *eap, const uint8_t *pkt,
		size_t len)
{
	struct eap_sim_handle *sim = eap_get_data(eap);
	struct eap_sim_tlv_iter iter;
	enum eap_sim_error code = EAP_SIM_ERROR_PROCESS;

	if (sim->state != EAP_SIM_STATE_START) {
		l_error("invalid packet for EAP-SIM state");
		goto chal_error;
	}

	if (len < 3) {
		l_error("packet is too small");
		goto chal_error;
	}

	eap_sim_tlv_iter_init(&iter, pkt + 3, len - 3);

	while (eap_sim_tlv_iter_next(&iter)) {
		const uint8_t *contents = eap_sim_tlv_iter_get_data(&iter);
		uint16_t length = eap_sim_tlv_iter_get_length(&iter);

		switch (eap_sim_tlv_iter_get_type(&iter)) {
		case EAP_SIM_AT_RAND:
			if ((length - 2) / 16 != 3) {
				l_error("insufficient RAND's %u",
					(length - 2) / 16);
				code = EAP_SIM_ERROR_CHALLENGE;
				goto chal_error;
			}
			/*
			 * TODO: check that RAND's are fresh. Existing RAND's
			 * should only exist if we are re-authenticating to the
			 * server, which is currently not implemented.
			 */
			memcpy(sim->rands, contents + 2, EAP_SIM_RAND_LEN * 3);
			break;

		case EAP_SIM_AT_RESULT_IND:
			sim->protected = true;
			break;

		case EAP_SIM_AT_IV:
		case EAP_SIM_AT_ENCR_DATA:
		case EAP_SIM_AT_MAC:
			/* need a case for these so the default won't get hit */
			break;

		default:
			l_error("attribute type %u not allowed in Challenge",
					eap_sim_tlv_iter_get_type(&iter));
			goto chal_error;
		}
	}

	sim->chal_pkt = l_memdup(pkt, len);
	sim->pkt_len = len;

	if (sim_auth_run_gsm(sim->auth, sim->rands, 3, gsm_callback, eap) < 0) {
		l_free(sim->chal_pkt);
		sim->chal_pkt = NULL;
		goto chal_error;
	}

	return;

chal_error:
	eap_sim_client_error(eap, EAP_TYPE_SIM, code);
}

/*
 * Handles EAP-SIM Notification subtype
 */
static void handle_notification(struct eap_state *eap, const uint8_t *pkt,
		size_t len)
{
	struct eap_sim_handle *sim = eap_get_data(eap);
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

	if (value == EAP_SIM_SUCCESS && sim->protected &&
			sim->state == EAP_SIM_STATE_CHALLENGE) {
		/* header + MAC + MAC header */
		uint8_t response[8 + EAP_SIM_MAC_LEN + 4];
		uint8_t *pos = response;

		/*
		 * Server sent successful result indication
		 */
		eap_sim_finish(eap);

		/*
		 * Build response packet
		 */
		pos += eap_sim_build_header(eap, EAP_TYPE_SIM,
				EAP_SIM_ST_NOTIFICATION, pos, 20);
		pos += eap_sim_add_attribute(pos, EAP_SIM_AT_MAC,
				EAP_SIM_PAD_NONE, NULL, EAP_SIM_MAC_LEN);

		if (!eap_sim_derive_mac(EAP_TYPE_SIM, response, pos - response,
				sim->k_aut, response + 12)) {
			l_error("could not derive MAC");
			eap_method_error(eap);
			sim->state = EAP_SIM_STATE_ERROR;
			return;
		}

		eap_method_respond(eap, response, pos - response);

		sim->state = EAP_SIM_STATE_SUCCESS;
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
	eap_sim_client_error(eap, EAP_TYPE_SIM, EAP_SIM_ERROR_PROCESS);
}

static void eap_sim_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	if (len < 1) {
		l_error("packet is too small");
		goto req_error;
	}

	switch (pkt[0]) {
	case EAP_SIM_ST_START:
		handle_start(eap, pkt, len);
		break;
	case EAP_SIM_ST_CHALLENGE:
		handle_challenge(eap, pkt, len);
		break;
	case EAP_SIM_ST_NOTIFICATION:
		handle_notification(eap, pkt, len);
		break;
	default:
		l_error("unknown EAP-SIM subtype: %u", pkt[0]);
		goto req_error;
	}

	return;

req_error:
	eap_sim_client_error(eap, EAP_TYPE_SIM, EAP_SIM_ERROR_PROCESS);
}

static const char *eap_sim_get_identity(struct eap_state *eap)
{
	struct eap_sim_handle *sim = eap_get_data(eap);

	return sim->identity;
}

static void auth_destroyed(void *data)
{
	struct eap_state *eap = data;
	struct eap_sim_handle *sim = eap_get_data(eap);

	/*
	 * If AKA was already successful we can return. Also if the state
	 * has been set to ERROR, then eap_method_error has already been called,
	 * so we can return.
	 */
	if (sim->state == EAP_SIM_STATE_SUCCESS ||
			sim->state == EAP_SIM_STATE_ERROR)
		return;

	l_error("auth provider destroyed before SIM could finish");

	sim->state = EAP_SIM_STATE_ERROR;
	eap_method_error(eap);
}

static int eap_sim_check_settings(struct l_settings *settings,
					struct l_queue *secrets,
					const char *prefix,
					struct l_queue **out_missing)
{
	struct iwd_sim_auth *auth;

	auth = iwd_sim_auth_find(true, false);
	if (!auth) {
		l_debug("No SIM driver available for EAP-SIM");
		return -EUNATCH;
	}

	if (!iwd_sim_auth_get_nai(auth)) {
		l_error("SIM driver didn't provide NAI");
		return -ENOENT;
	}

	return 0;
}

static bool eap_sim_reset_state(struct eap_state *eap)
{
	struct eap_sim_handle *sim = eap_get_data(eap);

	sim->state = EAP_SIM_STATE_UNCONNECTED;

	l_free(sim->vlist);
	sim->vlist = NULL;
	l_free(sim->chal_pkt);
	sim->chal_pkt = NULL;

	memset(sim->nonce, 0, sizeof(sim->nonce));
	eap_sim_clear_secrets(sim);

	return true;
}

static bool eap_sim_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_sim_handle *sim;

	/*
	 * No specific settings for EAP-SIM, the auth provider will have all
	 * required data.
	 */
	sim = l_new(struct eap_sim_handle, 1);
	eap_set_data(eap, sim);

	sim->auth = iwd_sim_auth_find(true, false);
	if (!sim->auth)
		return false;

	sim->auth_watch = sim_auth_unregistered_watch_add(sim->auth,
			auth_destroyed, eap);
	/*
	 * RFC 4186 Section 4.2.1.6
	 * EAP-SIM identity prefix is '1'
	 */
	sim->identity = l_strdup_printf("%c%s", '1',
			iwd_sim_auth_get_nai(sim->auth));

	return true;
}

static struct eap_method eap_sim = {
	.request_type = EAP_TYPE_SIM,
	.exports_msk = true,
	.name = "SIM",
	.free = eap_sim_free,
	.handle_request = eap_sim_handle_request,
	.check_settings = eap_sim_check_settings,
	.load_settings = eap_sim_load_settings,
	.get_identity = eap_sim_get_identity,
	.reset_state = eap_sim_reset_state
};

static int eap_sim_init(void)
{
	l_debug("");
	return eap_register_method(&eap_sim);
}

static void eap_sim_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_sim);
}

EAP_METHOD_BUILTIN(eap_sim, eap_sim_init, eap_sim_exit)
