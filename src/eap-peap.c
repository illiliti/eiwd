/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ell/ell.h>

#include "src/crypto.h"
#include "src/missing.h"
#include "src/eap.h"
#include "src/eap-private.h"
#include "src/eap-tls-common.h"

/*
 * Protected EAP Protocol (PEAP): EAP type 25 as described in:
 *
 * PEAPv0: draft-kamath-pppext-peapv0-00
 * PEAPv1: draft-josefsson-pppext-eap-tls-eap-05
 */

struct peap_state {
	struct eap_state *phase2;

	uint8_t key[128];
	uint8_t isk[32];
};

static void eap_peap_phase2_key_ready(const uint8_t *msk_data, size_t msk_len,
				const uint8_t *emsk_data, size_t emsk_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *session_id, size_t session_len,
				void *user_data)
{
	struct peap_state *peap_state =
				eap_tls_common_get_variant_data(user_data);

	l_debug("PEAP: New ISK received");

	memcpy(peap_state->isk, msk_data, sizeof(peap_state->isk));
}

static void eap_peap_phase2_send_response(const uint8_t *pdu, size_t pdu_len,
								void *user_data)
{
	struct eap_state *eap = user_data;

	if (eap_tls_common_get_negotiated_version(eap) == EAP_TLS_VERSION_0) {
		if (pdu_len < 5)
			return;

		if (pdu[4] != EAP_TYPE_EXTENSIONS) {
			pdu += 4;
			pdu_len -= 4;
		}
	}

	eap_tls_common_tunnel_send(eap, pdu, pdu_len);
}

static void eap_peap_phase2_complete(enum eap_result result, void *user_data)
{
	struct eap_state *eap = user_data;
	struct peap_state *peap_state;

	l_debug("result: %d", result);

	/*
	 * PEAPv1: draft-josefsson-pppext-eap-tls-eap-05, Section 2.2
	 *
	 * The receipt of a EAP-Failure or EAP-Success within the TLS protected
	 * channel results in a shutdown of the TLS channel by the peer.
	 */
	if (result == EAP_RESULT_SUCCESS)
		/*
		 * Some of the EAP-PEAP server implementations seem to require a
		 * cleartext ACK for the tunneled EAP-Success messages instead
		 * of simply closing the tunnel.
		 */
		eap_tls_common_send_empty_response(eap);
	else
		eap_tls_common_tunnel_close(eap);

	eap_discard_success_and_failure(eap, false);
	eap_tls_common_set_completed(eap);

	if (result != EAP_RESULT_SUCCESS) {
		eap_tls_common_set_phase2_failed(eap);

		return;
	}

	peap_state = eap_tls_common_get_variant_data(eap);

	eap_set_key_material(eap, peap_state->key + 0, 64, NULL, 0, NULL,
								0, NULL, 0);
	explicit_bzero(peap_state->key, sizeof(peap_state->key));
	explicit_bzero(peap_state->isk, sizeof(peap_state->isk));

	eap_method_success(eap);
}

/*
 * PEAPv0: draft-kamath-pppext-peapv0-00, Section 2
 */
#define EAP_EXTENSIONS_HEADER_LEN 5
#define EAP_EXTENSIONS_TLV_HEADER_LEN 4
#define EAP_EXTENSIONS_TLV_M_BIT_MASK 0x8000

enum eap_extensions_tlv_type {
	/* Reserved = 0x0000, */
	/* Reserved = 0x0001, */
	/* Reserved = 0x0002, */
	EAP_EXTENSIONS_TLV_TYPE_RESULT        = 0x8003,
	EAP_EXTENSIONS_TLV_TYPE_CRYPTOBINDING = 0x000C,
};

enum TLV_CRYPTOBINDING_TYPE {
	TLV_CRYPTOBINDING_TYPE_REQUEST =  0,
	TLV_CRYPTOBINDING_TYPE_RESPONSE = 1,
};

static bool cryptobinding_tlv_generate_csk(struct eap_state *eap, uint8_t *imck)
{
	struct peap_state *peap_state = eap_tls_common_get_variant_data(eap);
	static const char *label = "Session Key Generating Function";

	if (!prf_plus_sha1(imck, 40, label, strlen(label), "\00", 1,
				peap_state->key, sizeof(peap_state->key)))
		return false;

	return true;
}

static bool cryptobinding_tlv_generate_imck(struct eap_state *eap,
							uint8_t *imck_out)
{
	struct peap_state *peap_state = eap_tls_common_get_variant_data(eap);
	static const char *label = "Inner Methods Compound Keys";

	if (!prf_plus_sha1(peap_state->key, 40, label, strlen(label),
					peap_state->isk, 32, imck_out, 60))
		return false;

	return true;
}

static int eap_extensions_handle_cryptobinding_tlv(struct eap_state *eap,
							const uint8_t *data,
							uint16_t tlv_value_len,
							uint8_t *response)
{
	static const uint8_t cryptobinding_val_len = 56;
	static const uint8_t cryptobinding_compound_mac_len = 20;
	static const uint8_t cryptobinding_nonce_len = 32;
	const uint8_t *nonce;
	const uint8_t *server_compound_mac;
	uint8_t client_compound_mac[cryptobinding_compound_mac_len];
	const uint8_t *cryptobinding_tlv_value;
	uint8_t buf[61];
	uint8_t imck[60];

	l_debug("");

	if (tlv_value_len != cryptobinding_val_len)
		return -EBADMSG;

	cryptobinding_tlv_value = data;

	/* Reserved byte: must be ignored on receipt. */
	data += 1;

	/* Version byte: must be set to 0. */
	if (*data)
		return -EBADMSG;

	data += 1;

	/* RecvVersion byte: must be set to 0. */
	if (*data)
		return -EBADMSG;

	data += 1;

	/* SubType byte: cryptobinding TLV request. */
	if (*data != TLV_CRYPTOBINDING_TYPE_REQUEST)
		return -EBADMSG;

	data += 1;

	nonce = data;
	data += cryptobinding_nonce_len;

	server_compound_mac = data;

	l_put_be16(EAP_EXTENSIONS_TLV_TYPE_CRYPTOBINDING, &buf[0]);
	l_put_be16(tlv_value_len, &buf[2]);
	memcpy(&buf[4], cryptobinding_tlv_value,
					4 + cryptobinding_nonce_len);
	memset(&buf[EAP_EXTENSIONS_TLV_HEADER_LEN + 4 +
						cryptobinding_nonce_len],
					0, cryptobinding_compound_mac_len);
	buf[60] = EAP_TYPE_PEAP;

	if (!cryptobinding_tlv_generate_imck(eap, imck)) {
		l_error("PEAP: Failed to generate IMCK to validate "
						"server compound MAC.");

		return -EIO;
	}

	if (!hmac_sha1(imck + 40, 20, buf, sizeof(buf), client_compound_mac,
					cryptobinding_compound_mac_len)) {
		l_error("PEAP: Failed to generate compound MAC to validate "
						"server compound MAC.");

		return -EIO;
	}

	if (memcmp(server_compound_mac, client_compound_mac,
					cryptobinding_compound_mac_len)) {
		l_error("PEAP: Generated compound MAC and server compound MAC "
							"don't match.");
		return -EIO;
	}

	/* Build response Crypto-Binding TLV */
	data = response;

	l_put_be16(EAP_EXTENSIONS_TLV_TYPE_CRYPTOBINDING, response);
	response += 2;

	l_put_be16(cryptobinding_val_len, response);
	response += 2;

	/* Reserved - must be set to 0. */
	l_put_u8(0, response);
	response += 1;

	/* Version */
	l_put_u8(EAP_TLS_VERSION_0, response);
	response += 1;

	/* Received Version */
	l_put_u8(EAP_TLS_VERSION_0, response);
	response += 1;

	/* Sub-Type */
	l_put_u8(TLV_CRYPTOBINDING_TYPE_RESPONSE, response);
	response += 1;

	memcpy(response, nonce, cryptobinding_nonce_len);
	response += cryptobinding_nonce_len;

	memcpy(buf, data, EAP_EXTENSIONS_TLV_HEADER_LEN + 4 +
						cryptobinding_nonce_len);

	if (!hmac_sha1(imck + 40, 20, buf, sizeof(buf), client_compound_mac,
					cryptobinding_compound_mac_len)) {
		l_error("PEAP: Failed to generate client compound MAC.");

		return -EIO;
	}

	memcpy(response, client_compound_mac, cryptobinding_compound_mac_len);

	if (!cryptobinding_tlv_generate_csk(eap, imck)) {
		l_error("PEAP: Failed to generate Compound Session Key.");

		return -EIO;
	}

	return EAP_EXTENSIONS_TLV_HEADER_LEN + cryptobinding_val_len;
}

enum eap_extensions_result {
	EAP_EXTENSIONS_RESULT_SUCCCESS = 1,
	EAP_EXTENSIONS_RESULT_FAILURE  = 2,
};

static int eap_extensions_handle_result_tlv(struct eap_state *eap,
						const uint8_t *data,
						size_t data_len,
						uint8_t *response,
						uint8_t *result)
{
	static const uint8_t result_tlv_len = 2;
	struct peap_state *peap_state;

	if (data_len != result_tlv_len)
		return -EBADMSG;

	*result = l_get_be16(data);

	l_debug("result: %d", *result);

	switch (*result) {
	case EAP_EXTENSIONS_RESULT_SUCCCESS:
		peap_state = eap_tls_common_get_variant_data(eap);

		*result = eap_method_is_success(peap_state->phase2) ?
					EAP_EXTENSIONS_RESULT_SUCCCESS :
					EAP_EXTENSIONS_RESULT_FAILURE;
		/* fall through */
	case EAP_EXTENSIONS_RESULT_FAILURE:
		break;
	default:
		return -ENOENT;
	}

	/* Build response Result TLV */

	l_put_be16(EAP_EXTENSIONS_TLV_TYPE_RESULT, response);
	response += 2;

	l_put_be16(result_tlv_len, response);
	response += 2;

	l_put_be16(*result, response);

	return EAP_EXTENSIONS_TLV_HEADER_LEN + result_tlv_len;
}

static int eap_extensions_process_tlvs(struct eap_state *eap,
						const uint8_t *data,
						size_t data_len,
						uint8_t *response,
						uint8_t *result)
{
	int response_len = 0;
	uint16_t tlv_type;
	uint16_t tlv_value_len;
	bool seen_result_tlv = false;
	bool seen_cryptobinding_tlv = false;

	while (data_len >= EAP_EXTENSIONS_TLV_HEADER_LEN) {
		int response_tlv_len = 0;

		tlv_type = l_get_be16(data);
		data += 2;

		tlv_value_len = l_get_be16(data);
		data += 2;

		data_len -= EAP_EXTENSIONS_TLV_HEADER_LEN;

		if (data_len < tlv_value_len)
			return -EBADMSG;

		switch (tlv_type) {
		case EAP_EXTENSIONS_TLV_TYPE_RESULT:
			if (seen_result_tlv)
				return -EBADMSG;

			seen_result_tlv = true;

			response_tlv_len = eap_extensions_handle_result_tlv(eap,
						data, tlv_value_len, response,
						result);

			break;
		case EAP_EXTENSIONS_TLV_TYPE_CRYPTOBINDING:
			if (seen_cryptobinding_tlv)
				return -EBADMSG;

			seen_cryptobinding_tlv = true;

			response_tlv_len =
				eap_extensions_handle_cryptobinding_tlv(eap,
						data, tlv_value_len, response);

			break;
		default:
			if (tlv_type & EAP_EXTENSIONS_TLV_M_BIT_MASK)
				return -ENOENT;

			break;
		}

		if (response_tlv_len < 0)
			return response_tlv_len;

		response += response_tlv_len;
		response_len += response_tlv_len;

		data += tlv_value_len;
		data_len -= tlv_value_len;
	}

	return response_len;
}

static void eap_extensions_handle_request(struct eap_state *eap,
							uint8_t id,
							const uint8_t *pkt,
							size_t len)
{
	struct peap_state *peap_state;
	uint8_t result = EAP_EXTENSIONS_RESULT_FAILURE;
	/*
	 * The buffer size is chosen to satisfy the needs of the two supported
	 * TLVs.
	 */
	uint8_t response[256];
	int response_len;

	response_len = eap_extensions_process_tlvs(eap, pkt, len,
					&response[EAP_EXTENSIONS_HEADER_LEN],
					&result);

	if (response_len < 0) {
		l_debug("PEAP: Failed to process TLVs %d", response_len);

		return;
	}

	response_len += EAP_EXTENSIONS_HEADER_LEN;

	response[0] = EAP_CODE_RESPONSE;
	response[1] = id;
	l_put_be16(response_len, &response[2]);
	response[4] = EAP_TYPE_EXTENSIONS;

	eap_peap_phase2_send_response(response, response_len, eap);

	eap_discard_success_and_failure(eap, false);
	eap_tls_common_set_completed(eap);

	if (result != EAP_EXTENSIONS_RESULT_SUCCCESS) {
		eap_tls_common_set_phase2_failed(eap);

		eap_tls_common_tunnel_close(eap);

		return;
	}

	peap_state = eap_tls_common_get_variant_data(eap);

	eap_set_key_material(eap, peap_state->key + 0, 64, NULL, 0, NULL,
								0, NULL, 0);
	explicit_bzero(peap_state->key, sizeof(peap_state->key));
	explicit_bzero(peap_state->isk, sizeof(peap_state->isk));

	eap_method_success(eap);
}

static bool eap_peap_tunnel_ready(struct eap_state *eap,
						const char *peer_identity,
						bool resumed)
{
	struct peap_state *peap_state = eap_tls_common_get_variant_data(eap);

	/*
	 * PEAPv1: draft-josefsson-pppext-eap-tls-eap-05, Section 2.1.1
	 *
	 * Cleartext Success/Failure packets MUST be silently discarded once
	 * TLS tunnel has been brought up.
	*/
	eap_discard_success_and_failure(eap, true);

	/*
	 * In case of a resumed session, the server will typically not run
	 * phase2 methods at all, but will instead send a result TLV right
	 * away.  Treat this like a successful phase2.  In case the server
	 * does proceed with phase2, the success/failure state will be updated.
	 */
	if (resumed)
		eap_method_success(peap_state->phase2);

	/* MSK, EMSK and challenge derivation */
	eap_tls_common_tunnel_prf_get_bytes(eap, true, "client EAP encryption",
						peap_state->key, 128);

	eap_tls_common_send_empty_response(eap);

	return true;
}

static bool eap_peap_tunnel_handle_request(struct eap_state *eap,
							const uint8_t *pkt,
								size_t len)
{
	struct peap_state *peap_state;
	uint8_t id;

	if (len > 4 && pkt[4] == EAP_TYPE_EXTENSIONS) {
		uint16_t pkt_len;
		uint8_t code = pkt[0];

		if (code != EAP_CODE_REQUEST)
			return false;

		pkt_len = l_get_be16(pkt + 2);
		if (pkt_len != len)
			return false;

		id = pkt[1];

		eap_extensions_handle_request(eap, id,
					pkt + EAP_EXTENSIONS_HEADER_LEN,
					len - EAP_EXTENSIONS_HEADER_LEN);

		return true;
	}

	peap_state = eap_tls_common_get_variant_data(eap);

	if (eap_tls_common_get_negotiated_version(eap) == EAP_TLS_VERSION_0) {
		if (len < 1)
			return false;

		/*
		 * The PEAPv0 phase2 packets are headerless. Our implementation
		 * of the EAP methods requires packet identifier. Therefore,
		 * PEAP packet identifier is used for the headerless
		 * phase2 packets.
		 */
		eap_save_last_id(eap, &id);

		__eap_handle_request(peap_state->phase2, id, pkt, len);

		return true;
	}

	eap_rx_packet(peap_state->phase2, pkt, len);

	return true;
}

static void eap_peap_state_reset(void *variant_data)
{
	struct peap_state *peap_state = variant_data;

	if (!peap_state)
		return;

	eap_reset(peap_state->phase2);

	explicit_bzero(peap_state->key, sizeof(peap_state->key));
	explicit_bzero(peap_state->isk, sizeof(peap_state->isk));
}

static void eap_peap_state_destroy(void *variant_data)
{
	struct peap_state *peap_state = variant_data;

	if (!peap_state)
		return;

	eap_reset(peap_state->phase2);
	eap_free(peap_state->phase2);

	explicit_bzero(peap_state->key, sizeof(peap_state->key));
	explicit_bzero(peap_state->isk, sizeof(peap_state->isk));

	l_free(peap_state);
}

static int eap_peap_settings_check(struct l_settings *settings,
						struct l_queue *secrets,
						const char *prefix,
						struct l_queue **out_missing)
{
	char setting_key_prefix[72];
	int r;

	snprintf(setting_key_prefix, sizeof(setting_key_prefix),
						"%sPEAP-Phase2-", prefix);

	r = __eap_check_settings(settings, secrets, setting_key_prefix, false,
								out_missing);
	if (r)
		return r;

	snprintf(setting_key_prefix, sizeof(setting_key_prefix), "%sPEAP-",
									prefix);
	return eap_tls_common_settings_check(settings, secrets,
							setting_key_prefix,
							out_missing);
}

static const struct eap_tls_variant_ops eap_ttls_ops = {
	.version_max_supported = EAP_TLS_VERSION_1,
	.tunnel_ready = eap_peap_tunnel_ready,
	.tunnel_handle_request = eap_peap_tunnel_handle_request,
	.reset = eap_peap_state_reset,
	.destroy = eap_peap_state_destroy,
};

static bool eap_peap_settings_load(struct eap_state *eap,
						struct l_settings *settings,
						const char *prefix)
{
	char setting_key_prefix[72];
	struct peap_state *peap_state;
	void *phase2;

	phase2 = eap_new(eap_peap_phase2_send_response,
						eap_peap_phase2_complete, eap);

	if (!phase2) {
		l_error("Could not create the PEAP phase two EAP instance");

		return false;
	}

	snprintf(setting_key_prefix, sizeof(setting_key_prefix),
						"%sPEAP-Phase2-", prefix);

	if (!eap_load_settings(phase2, settings, setting_key_prefix)) {
		eap_free(phase2);

		return false;
	}

	peap_state = l_new(struct peap_state, 1);
	peap_state->phase2 = phase2;
	eap_set_key_material_func(peap_state->phase2,
						eap_peap_phase2_key_ready);

	snprintf(setting_key_prefix, sizeof(setting_key_prefix), "%sPEAP-",
									prefix);

	if (!eap_tls_common_settings_load(eap, settings, setting_key_prefix,
						&eap_ttls_ops, peap_state))
		return false;

	return true;
}

static struct eap_method eap_peap = {
	.request_type = EAP_TYPE_PEAP,
	.name = "PEAP",
	.exports_msk = true,

	.handle_request = eap_tls_common_handle_request,
	.handle_retransmit = eap_tls_common_handle_retransmit,
	.free = eap_tls_common_state_free,
	.reset_state = eap_tls_common_state_reset,

	.check_settings = eap_peap_settings_check,
	.load_settings = eap_peap_settings_load,
};

static int eap_peap_init(void)
{
	l_debug("");
	return eap_register_method(&eap_peap);
}

static void eap_peap_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_peap);
}

EAP_METHOD_BUILTIN(eap_peap, eap_peap_init, eap_peap_exit)
