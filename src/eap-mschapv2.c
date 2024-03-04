/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016  Markus Ongyerth. All rights reserved.
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
#include "src/eap-mschapv2.h"
#include "src/mschaputil.h"

#define MSCHAPV2_CHAL_LEN 16
#define MSCHAPV2_NT_RESPONSE_LEN 24
#define MSCHAPV2_AUTH_RESPONSE_LEN 20
#define MSCHAPV2_MASTER_KEY_LEN 16

#define MSCHAPV2_OP_CHALLENGE 1
#define MSCHAPV2_OP_RESPONSE 2
#define MSCHAPV2_OP_SUCCESS 3
#define MSCHAPV2_OP_FAILURE 4

struct eap_mschapv2_state {
	uint8_t password_hash[16];
	char *user;
	size_t user_len;
	uint8_t current_id;

	uint8_t peer_challenge[MSCHAPV2_CHAL_LEN];
	uint8_t server_challenge[MSCHAPV2_CHAL_LEN];
};

struct mschapv2_header {
	uint8_t op_code;
	uint8_t mschap_id;
	uint16_t mschap_len;
} __attribute__((packed));

struct mschapv2_value {
	uint8_t peer_challenge[MSCHAPV2_CHAL_LEN];
	uint8_t reserved[8];
	uint8_t nt_response[MSCHAPV2_NT_RESPONSE_LEN];
	uint8_t flags;
} __attribute__((packed));

struct mschapv2_response {
	struct mschapv2_header hdr;
	/* This will always be sizeof(value) */
	uint8_t val_length;
	struct mschapv2_value value;
	char name[];
} __attribute__((packed));

/**
 * Generate the asymmetric start keys from our mschapv2 master key for MPPE
 * This function is specified in:
 * https://tools.ietf.org/html/draft-ietf-pppext-mschapv2-keys-02
 *
 * @master_key: The master key
 * @session_key: the destination
 * @session_len: The length of the requested key in octets (<= 20)
 * @server: if the key should be generated for server side
 * @send:  if the send or the receive key should be generated
 *
 * Returns: true on success, false if hash/encrypt couldn't be done
 **/
bool mschapv2_get_asymmetric_start_key(const uint8_t master_key[static 16],
				uint8_t *session_key, size_t session_len,
				bool server, bool send)
{
	static const uint8_t magic2[] = {
		0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
		0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
		0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
		0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
		0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
		0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
		0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
		0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
		0x6b, 0x65, 0x79, 0x2e
	};
	static const uint8_t magic3[] = {
		0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
		0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
		0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
		0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
		0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
		0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
		0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
		0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
		0x6b, 0x65, 0x79, 0x2e
	};
	static const uint8_t shs_pad1[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	static const uint8_t shs_pad2[] = {
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2
	};
	const uint8_t *magic;
	struct l_checksum *check;

	if (send == server)
		magic = magic3;
	else
		magic = magic2;

	check = l_checksum_new(L_CHECKSUM_SHA1);
	if (!check)
		return false;

	l_checksum_update(check, master_key, 16);
	l_checksum_update(check, shs_pad1, 40);
	l_checksum_update(check, magic, 84);
	l_checksum_update(check, shs_pad2, 40);
	l_checksum_get_digest(check, session_key, session_len);

	l_checksum_free(check);

	return true;
}

/**
 * Generate the master key for MPPE from mschapv2
 * This function is specified in:
 * https://tools.ietf.org/html/draft-ietf-pppext-mschapv2-keys-02
 *
 * @pw_hash_hash: The MD4 hash of the password hash
 * @nt_response: The nt_response generated for mschapv2
 * @master_key: The destination
 *
 * Returns: true on success, false if hash/encrypt couldn't be done
 **/
bool mschapv2_get_master_key(const uint8_t pw_hash_hash[static 16],
					const uint8_t nt_response[static 24],
					uint8_t master_key[static 16])
{
	static const uint8_t magic[] = {
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
		0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
		0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79
	};
	struct l_checksum *check;

	check = l_checksum_new(L_CHECKSUM_SHA1);
	if (!check)
		return false;

	l_checksum_update(check, pw_hash_hash, 16);
	l_checksum_update(check, nt_response, 24);
	l_checksum_update(check, magic, sizeof(magic));

	l_checksum_get_digest(check, master_key, 16);
	l_checksum_free(check);

	return true;
}

static bool eap_mschapv2_reset_state(struct eap_state *eap)
{
	struct eap_mschapv2_state *state = eap_get_data(eap);

	memset(state->peer_challenge, 0, sizeof(state->peer_challenge));
	memset(state->server_challenge, 0, sizeof(state->server_challenge));

	return true;
}

static void eap_mschapv2_state_free(struct eap_mschapv2_state *state)
{
	explicit_bzero(state->password_hash, sizeof(state->password_hash));

	explicit_bzero(state->user, state->user_len);
	l_free(state->user);
	state->user_len = 0;

	l_free(state);
}

static void eap_mschapv2_free(struct eap_state *eap)
{
	struct eap_mschapv2_state *state;

	eap_mschapv2_reset_state(eap);

	state = eap_get_data(eap);
	eap_set_data(eap, NULL);

	eap_mschapv2_state_free(state);
}

static bool eap_mschapv2_send_response(struct eap_state *eap)
{
	struct eap_mschapv2_state *state = eap_get_data(eap);
	size_t size = sizeof(struct mschapv2_response) + state->user_len;
	uint8_t output[size + 5];
	struct mschapv2_response *response =
				(struct mschapv2_response *) (output + 5);
	bool ret;

	/*
	 * Make sure to initialize the response structure to 0 since
	 * we're not filling in some of the reserved or optional fields
	 */
	memset(response, 0, size);

	ret = mschapv2_generate_nt_response(state->password_hash,
						state->peer_challenge,
						state->server_challenge,
						state->user,
						response->value.nt_response);

	if (!ret)
		return false;

	response->hdr.op_code = MSCHAPV2_OP_RESPONSE;
	response->hdr.mschap_id = state->current_id;
	response->hdr.mschap_len = L_BE16_TO_CPU(size);
	response->val_length = sizeof(struct mschapv2_value);

	memcpy(response->value.peer_challenge, state->peer_challenge,
							MSCHAPV2_CHAL_LEN);
	memcpy(response->name, state->user, state->user_len);

	eap_method_respond(eap, output, sizeof(output));

	return true;
}

static void eap_mschapv2_handle_challenge(struct eap_state *eap,
						const uint8_t *pkt, size_t len)
{
	struct eap_mschapv2_state *state = eap_get_data(eap);

	if (pkt[0] != MSCHAPV2_CHAL_LEN) {
		l_error("MSCHAPV2-Challenge had unexpected length: %x",
								pkt[0]);
		goto err;
	}

	if (len - 1 < MSCHAPV2_CHAL_LEN) {
		l_error("MSCHAPV2-Challenge packet was to short for challenge");
		goto err;
	}

	memcpy(state->server_challenge, pkt + 1, MSCHAPV2_CHAL_LEN);
	l_getrandom(state->peer_challenge, MSCHAPV2_CHAL_LEN);

	if (eap_mschapv2_send_response(eap))
		return;

err:
	eap_method_error(eap);
}

/*
 * We need to verify the authenticator response from the server
 * and generate the master session key.
 */
static void eap_mschapv2_handle_success(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_mschapv2_state *state = eap_get_data(eap);
	uint8_t nt_response[24];
	uint8_t password_hash_hash[16];
	uint8_t master_key[16];
	uint8_t session_key[32];
	char authenticator_resp[42];
	bool ret;

	uint8_t buffer[5 + 1];

	mschapv2_hash_nt_password_hash(state->password_hash,
							password_hash_hash);

	ret = mschapv2_generate_nt_response(state->password_hash,
						state->peer_challenge,
						state->server_challenge,
						state->user, nt_response);

	if (!ret)
		goto done;

	ret = mschapv2_generate_authenticator_response(password_hash_hash,
						nt_response,
						state->peer_challenge,
						state->server_challenge,
						state->user,
						authenticator_resp);

	if (!ret)
		goto done;

	/*
	 * For iwd timing attacks are unlikely because media access will
	 * influence timing. If this code is ever taken out of iwd, memcmp
	 * should be replaced by a constant time memcmp
	 */
	if (len < 42 || memcmp(authenticator_resp, pkt, 42)) {
		l_warn("Authenticator response didn't match");
		ret = false;
		goto done;
	}

	ret = mschapv2_get_master_key(password_hash_hash, nt_response,
								master_key);
	ret &= mschapv2_get_asymmetric_start_key(master_key, session_key,
							16, false, true);
	ret &= mschapv2_get_asymmetric_start_key(master_key, session_key + 16,
							16, false, false);

	if (!ret)
		goto done;

	eap_method_success(eap);

	buffer[5] = MSCHAPV2_OP_SUCCESS;
	eap_method_respond(eap, buffer, sizeof(buffer));

	/* The eapol set_key_material only needs msk, and that's all we got */
	eap_set_key_material(eap, session_key, 32, NULL, 0, NULL, 0, NULL, 0);

done:
	if (!ret)
		eap_method_error(eap);

	explicit_bzero(master_key, sizeof(master_key));
	explicit_bzero(session_key, sizeof(session_key));
	explicit_bzero(password_hash_hash, sizeof(password_hash_hash));
}

static void eap_mschapv2_handle_failure(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	/*
	 * From what I have seen, we can't prompt the user in any useful way
	 * yet, so we can't do any proper error handling.
	 * The values we can read from this are defined in:
	 * https://tools.ietf.org/html/draft-ietf-pppext-mschap-v2-01
	 * Section 9
	 *
	 * At the current point, this will be a fail.
	 */
	l_debug("");
	eap_method_error(eap);
}

static void eap_mschapv2_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_mschapv2_state *state = eap_get_data(eap);
	const struct mschapv2_header *hdr = (struct mschapv2_header *) pkt;
	size_t size = sizeof(*hdr);

	if (len < sizeof(struct mschapv2_header) + 1) {
		l_error("EAP-MSCHAPV2 packet too short");
		goto err;
	}

	state->current_id = hdr->mschap_id;

	if (L_BE16_TO_CPU(hdr->mschap_len) != len) {
		l_error("EAP-MSCHAPV2 packet contains invalid length");
		goto err;
	}

	switch (hdr->op_code) {
	case MSCHAPV2_OP_CHALLENGE:
		eap_mschapv2_handle_challenge(eap, pkt + size, len - size);
		break;
	case MSCHAPV2_OP_SUCCESS:
		eap_mschapv2_handle_success(eap, pkt + size, len - size);
		break;
	case MSCHAPV2_OP_FAILURE:
		eap_mschapv2_handle_failure(eap, pkt + size, len - size);
		break;
	default:
		l_error("Got unknown OP-Code in MSCHPV2 packet: %x",
							hdr->op_code);
		goto err;
	}

	return;

err:
	eap_method_error(eap);
}

static bool set_password_from_string(struct eap_mschapv2_state *state,
						const char *password)
{
	return mschap_nt_password_hash(password, state->password_hash);
}

static int eap_mschapv2_check_settings(struct l_settings *settings,
					struct l_queue *secrets,
					const char *prefix,
					struct l_queue **out_missing)
{
	L_AUTO_FREE_VAR(uint8_t *, password_hash) = NULL;
	L_AUTO_FREE_VAR(char *, password) = NULL;
	L_AUTO_FREE_VAR(char *, identity);
	const struct eap_secret_info *secret;
	char setting[64], setting2[64];
	uint8_t hash[16];
	int r = 0;
	size_t hash_len;

	snprintf(setting, sizeof(setting), "%sIdentity", prefix);
	identity = l_settings_get_string(settings, "Security", setting);

	snprintf(setting2, sizeof(setting2), "%sPassword", prefix);

	if (!identity) {
		secret = l_queue_find(secrets, eap_secret_info_match, setting);
		if (secret) {
			password = l_strdup(secret->value +
						strlen(secret->value) + 1);

			goto validate;
		}

		eap_append_secret(out_missing, EAP_SECRET_REMOTE_USER_PASSWORD,
					setting, setting2, NULL,
					EAP_CACHE_TEMPORARY);
		return 0;
	}

	password = l_settings_get_string(settings, "Security", setting2);

	snprintf(setting, sizeof(setting), "%sPassword-Hash", prefix);
	password_hash = l_settings_get_bytes(settings, "Security",
						setting, &hash_len);

	if (password && password_hash) {
		l_error("Exactly one of (%s, %s) must be present",
			setting, setting2);
		r = -EEXIST;
		goto cleanup;
	}

	if (password_hash) {
		if (hash_len != 16) {
			l_error("Property %s is not a 16-byte hexstring",
				setting);
			return -EINVAL;
		}

		return 0;
	} else if (password)
		goto validate;

	secret = l_queue_find(secrets, eap_secret_info_match, setting2);
	if (!secret) {
		eap_append_secret(out_missing, EAP_SECRET_REMOTE_PASSWORD,
					setting2, NULL, identity,
					EAP_CACHE_TEMPORARY);
		return 0;
	}

	password = l_strdup(secret->value);

validate:
	if (!mschap_nt_password_hash(password, hash))
		r = -EINVAL;

cleanup:
	explicit_bzero(password, strlen(password));
	return r;
}

static bool eap_mschapv2_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_mschapv2_state *state;
	L_AUTO_FREE_VAR(char *, password) = NULL;
	char setting[64];

	state = l_new(struct eap_mschapv2_state, 1);

	snprintf(setting, sizeof(setting), "%sIdentity", prefix);
	state->user = l_settings_get_string(settings, "Security", setting);
	if (!state->user)
		goto error;

	state->user_len = strlen(state->user);

	/* Either read the password-hash from hexdump or password and hash it */
	snprintf(setting, sizeof(setting), "%sPassword", prefix);
	password = l_settings_get_string(settings, "Security", setting);

	if (password) {
		set_password_from_string(state, password);
		explicit_bzero(password, strlen(password));
	} else {
		size_t hash_len;
		uint8_t *hash;

		snprintf(setting, sizeof(setting), "%sPassword-Hash", prefix);
		hash = l_settings_get_bytes(settings, "Security", setting,
						&hash_len);
		memcpy(state->password_hash, hash, 16);
		explicit_bzero(hash, 16);
		l_free(hash);
	}

	eap_set_data(eap, state);

	return true;

error:
	free(state);
	return false;
}

static struct eap_method eap_mschapv2 = {
	.request_type = EAP_TYPE_MSCHAPV2,
	.exports_msk = true,
	.name = "MSCHAPV2",

	.free = eap_mschapv2_free,
	.handle_request = eap_mschapv2_handle_request,
	.check_settings = eap_mschapv2_check_settings,
	.load_settings = eap_mschapv2_load_settings,
	.reset_state = eap_mschapv2_reset_state,
};

static int eap_mschapv2_init(void)
{
	l_debug("");

	if (!l_checksum_is_supported(L_CHECKSUM_MD4, false)) {
		l_warn("EAP_MSCHAPv2 init: MD4 support not found, skipping");
		l_warn("Ensure that CONFIG_CRYPTO_MD4 is enabled");
		return -ENOTSUP;
	}

	return eap_register_method(&eap_mschapv2);
}

static void eap_mschapv2_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_mschapv2);
}

EAP_METHOD_BUILTIN(eap_mschapv2, eap_mschapv2_init, eap_mschapv2_exit)
