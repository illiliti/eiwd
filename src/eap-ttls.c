/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2019  Intel Corporation. All rights reserved.
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

#include "src/missing.h"
#include "src/util.h"
#include "src/mschaputil.h"
#include "src/eap.h"
#include "src/eap-private.h"
#include "src/eap-tls-common.h"

#define TTLS_AVP_HEADER_LEN 8
#define TTLS_AVP_LEN_MASK 0xFFFFFF

enum ttls_avp_flag {
	TTLS_AVP_FLAG_M =	0x40,
	TTLS_AVP_FLAG_V =	0x80,
	TTLS_AVP_FLAG_MASK =	0xFF,
};

enum radius_attr {
	RADIUS_ATTR_USER_NAME			= 1,
	RADIUS_ATTR_USER_PASSWORD		= 2,
	RADIUS_ATTR_MSCHAPV2_ERROR		= 2,
	RADIUS_ATTR_CHAP_PASSWORD		= 3,
	RADIUS_ATTR_MS_CHAP_CHALLENGE		= 11,
	RADIUS_ATTR_MSCHAPV2_RESPONSE		= 25,
	RADIUS_ATTR_MSCHAPV2_SUCCESS		= 26,
	RADIUS_ATTR_CHAP_CHALLENGE		= 60,
	RADIUS_ATTR_EAP_MESSAGE			= 79,
};

struct avp_builder {
	uint32_t capacity;
	uint8_t *buf;
	uint32_t pos;
	uint8_t *avp_start;
};

static uint8_t *avp_builder_reserve(struct avp_builder *builder,
					uint32_t alignment, size_t len)
{
	size_t aligned_pos = align_len(builder->pos, alignment);
	size_t end = aligned_pos + len;

	if (end > builder->capacity) {
		builder->buf = l_realloc(builder->buf, end);
		builder->capacity = end;
	}

	if (aligned_pos - builder->pos > 0)
		memset(builder->buf + builder->pos, 0,
						aligned_pos - builder->pos);

	builder->pos = end;

	return builder->buf + aligned_pos;
}

static bool avp_builder_finalize_avp(struct avp_builder *builder)
{
	uint8_t *p;
	uint32_t len;

	if (!builder->avp_start)
		return false;

	p = builder->buf + builder->pos;

	len = l_get_be32(builder->avp_start + 4);
	len |= p - builder->avp_start;
	l_put_be32(len, builder->avp_start + 4);

	builder->avp_start = 0;

	return true;
}

static bool avp_builder_start_avp(struct avp_builder *builder,
					enum radius_attr type,
					bool mandatory, uint32_t vendor_id)
{
	uint32_t flags;

	if (builder->avp_start)
		return false;

	builder->avp_start = avp_builder_reserve(builder, 4,
							TTLS_AVP_HEADER_LEN +
							(vendor_id ? 4 : 0));

	l_put_be32(type, builder->avp_start);

	flags = 0;

	if (mandatory)
		flags |= TTLS_AVP_FLAG_M;

	if (vendor_id) {
		flags |= TTLS_AVP_FLAG_V;
		l_put_be32(vendor_id, builder->avp_start + TTLS_AVP_HEADER_LEN);
	}

	l_put_be32(flags << 24, builder->avp_start + 4);

	return true;
}

static struct avp_builder *avp_builder_new(size_t capacity)
{
	struct avp_builder *builder;

	if (!capacity)
		return NULL;

	builder = l_new(struct avp_builder, 1);

	builder->buf = l_malloc(capacity);
	memset(builder->buf, 0, capacity);

	builder->capacity = capacity;

	return builder;
}

static uint8_t *avp_builder_free(struct avp_builder *builder, bool free_data,
							size_t *out_size)
{
	uint8_t *ret;

	if (free_data) {
		explicit_bzero(builder->buf, builder->pos);
		l_free(builder->buf);
		builder->buf = NULL;
	}

	ret = builder->buf;

	if (out_size)
		*out_size = builder->pos;

	l_free(builder);

	return ret;
}

static void build_avp_user_name(struct avp_builder *builder,
							const char *user_name)
{
	size_t len = strlen(user_name);
	uint8_t *to;

	avp_builder_start_avp(builder, RADIUS_ATTR_USER_NAME, true, 0);

	to = avp_builder_reserve(builder, 1, len);
	memcpy(to, user_name, len);

	avp_builder_finalize_avp(builder);
}

static void build_avp_user_password(struct avp_builder *builder,
						const char *user_password)
{
	size_t len = strlen(user_password);
	uint8_t *to;

	avp_builder_start_avp(builder, RADIUS_ATTR_USER_PASSWORD, true, 0);

	/*
	 * Null-pad the password to a multiple of 16 octets, to obfuscate
	 * its length
	 */
	to = avp_builder_reserve(builder, 1, align_len(len, 16));
	memcpy(to, user_password, len);

	avp_builder_finalize_avp(builder);
}

#define CHAP_IDENT_LEN		1
#define CHAP_CHALLENGE_LEN	16
#define CHAP_PASSWORD_LEN	16

static void build_avp_chap_challenge(struct avp_builder *builder,
						const uint8_t *challenge)
{
	avp_builder_start_avp(builder, RADIUS_ATTR_CHAP_CHALLENGE, true, 0);
	memcpy(avp_builder_reserve(builder, 1, CHAP_CHALLENGE_LEN), challenge,
							CHAP_CHALLENGE_LEN);
	avp_builder_finalize_avp(builder);
}

static void build_avp_chap_password(struct avp_builder *builder,
					const uint8_t *ident,
					const uint8_t *password_hash)
{
	avp_builder_start_avp(builder, RADIUS_ATTR_CHAP_PASSWORD, true, 0);

	memcpy(avp_builder_reserve(builder, 1, CHAP_IDENT_LEN), ident,
							CHAP_IDENT_LEN);
	memcpy(avp_builder_reserve(builder, 1, CHAP_PASSWORD_LEN),
					password_hash, CHAP_PASSWORD_LEN);
	avp_builder_finalize_avp(builder);
}

#define RADIUS_VENDOR_ID_MICROSOFT 311
#define RADIUS_ATTR_MS_CHAP_RESPONSE 1

#define MS_CHAP_CHALLENGE_LEN	8
#define MS_CHAP_LM_RESPONSE_LEN 24
#define MS_CHAP_NT_RESPONSE_LEN 24

static void build_avp_ms_chap_challenge(struct avp_builder *builder,
						const uint8_t *challenge)
{
	avp_builder_start_avp(builder, RADIUS_ATTR_MS_CHAP_CHALLENGE, true,
						RADIUS_VENDOR_ID_MICROSOFT);
	memcpy(avp_builder_reserve(builder, 1, MS_CHAP_CHALLENGE_LEN),
					challenge, MS_CHAP_CHALLENGE_LEN);
	avp_builder_finalize_avp(builder);
}

static void build_avp_ms_chap_response(struct avp_builder *builder,
					const uint8_t *ident,
					const uint8_t *challenge,
					const uint8_t *password_hash)
{
	uint8_t *flags;
	uint8_t nt_challenge_response[NT_CHALLENGE_RESPONSE_LEN];

	avp_builder_start_avp(builder, RADIUS_ATTR_MS_CHAP_RESPONSE, true,
						RADIUS_VENDOR_ID_MICROSOFT);

	memcpy(avp_builder_reserve(builder, 1, CHAP_IDENT_LEN),
							ident, CHAP_IDENT_LEN);

	/*
	 * RFC 2548: Section 2.1.3
	 *
	 * The Flags field is set to one (0x01), the NT-Response field is to
	 * be used in preference to the LM-Response field for authentication.
	 */
	flags = avp_builder_reserve(builder, 1, 1);
	*flags = 1;

	/* The LM-Response field is left empty */
	avp_builder_reserve(builder, 1, MS_CHAP_LM_RESPONSE_LEN);

	mschap_challenge_response(challenge, password_hash,
							nt_challenge_response);

	memcpy(avp_builder_reserve(builder, 1, NT_CHALLENGE_RESPONSE_LEN),
			nt_challenge_response, NT_CHALLENGE_RESPONSE_LEN);

	avp_builder_finalize_avp(builder);
}

#define MSCHAPV2_RESERVED_LEN		8
#define MSCHAPV2_RESPONSE_LEN		24
#define MSCHAPV2_CHALLENGE_LEN		16
#define MSCHAPV2_SERVER_RESPONSE_LEN	42

static void build_avp_mschapv2_challenge(struct avp_builder *builder,
						const uint8_t *challenge)
{
	avp_builder_start_avp(builder, RADIUS_ATTR_MS_CHAP_CHALLENGE, true,
						RADIUS_VENDOR_ID_MICROSOFT);
	memcpy(avp_builder_reserve(builder, 1, MSCHAPV2_CHALLENGE_LEN),
					challenge, MSCHAPV2_CHALLENGE_LEN);
	avp_builder_finalize_avp(builder);
}

static void build_avp_mschapv2_response(struct avp_builder *builder,
						const uint8_t *ident,
						const uint8_t *peer_challenge,
						const uint8_t *response)
{
	uint8_t *flags;

	avp_builder_start_avp(builder, RADIUS_ATTR_MSCHAPV2_RESPONSE, true,
						RADIUS_VENDOR_ID_MICROSOFT);

	memcpy(avp_builder_reserve(builder, 1, CHAP_IDENT_LEN),
							ident, CHAP_IDENT_LEN);

	/*
	 * RFC 2548: Section 2.3.2.
	 *
	 * The Flags field is one octet in length. It is reserved for future
	 * use and MUST be zero.
	 */
	flags = avp_builder_reserve(builder, 1, 1);
	*flags = 0;

	memcpy(avp_builder_reserve(builder, 1, MSCHAPV2_CHALLENGE_LEN),
					peer_challenge,
					MSCHAPV2_CHALLENGE_LEN);

	/*
	 * Reserved - This field is 8 octets long and MUST be zero.
	 */
	avp_builder_reserve(builder, 1, MSCHAPV2_RESERVED_LEN);

	memcpy(avp_builder_reserve(builder, 1, MSCHAPV2_RESPONSE_LEN),
					response, MSCHAPV2_RESPONSE_LEN);

	avp_builder_finalize_avp(builder);
}

struct avp_iter {
	enum radius_attr type;
	uint8_t flags;
	uint32_t len;
	uint32_t vendor_id;
	const uint8_t *data;
	const uint8_t *buf;
	size_t buf_len;
	size_t offset;
};

static void avp_iter_init(struct avp_iter *iter, const uint8_t *buf, size_t len)
{
	iter->buf = buf;
	iter->buf_len = len;
	iter->offset = 0;
}

static bool avp_iter_next(struct avp_iter *iter)
{
	const uint8_t *start = iter->buf + iter->offset;
	const uint8_t *end = iter->buf + iter->buf_len;
	enum radius_attr type;
	uint32_t len;
	uint8_t flags;
	uint8_t pad_len;

	/* Make sure we have at least the header fields */
	if (iter->offset + TTLS_AVP_HEADER_LEN >= iter->buf_len)
		return false;

	type = l_get_be32(start);
	start += 4;

	len = l_get_be32(start);
	start += 4;

	flags = (len >> 24) & TTLS_AVP_FLAG_MASK;
	len &= TTLS_AVP_LEN_MASK;

	len -= TTLS_AVP_HEADER_LEN;

	if ((ptrdiff_t) len > end - start)
		return false;

	if (flags & TTLS_AVP_FLAG_V) {
		if (len < 4)
			return false;

		iter->vendor_id = l_get_be32(start);
		start += 4;
		len -= 4;
	} else {
		iter->vendor_id = 0;
	}

	iter->type = type;
	iter->flags = flags;
	iter->len = len;
	iter->data = start;

	if (len & 3)
		pad_len = 4 - (len & 3);
	else
		pad_len = 0;

	iter->offset = start + len + pad_len - iter->buf;

	return true;
}

struct phase2_credentials {
	char *username;
	char *password;
};

struct phase2_method {
	void *state;
	struct phase2_credentials credentials;
	const struct phase2_method_ops *ops;
};

struct phase2_method_ops {
	bool (*init)(struct eap_state *eap);
	bool (*handle_avp)(struct eap_state *eap, enum radius_attr type,
				uint32_t vendor_id, const uint8_t *data,
								size_t len);
	void (*destroy)(struct phase2_method *phase2);
	void (*reset)(struct phase2_method *phase2);
};

static void eap_ttls_phase2_credentials_destroy(
					struct phase2_credentials *credentials)
{
	if (!credentials)
		return;

	if (credentials->password)
		explicit_bzero(credentials->password,
				strlen(credentials->password));

	l_free(credentials->username);
	l_free(credentials->password);
}

static bool eap_ttls_phase2_non_eap_load_settings(struct phase2_method *phase2,
						struct l_settings *settings,
						const char *prefix)
{
	char setting[128];

	snprintf(setting, sizeof(setting), "%sIdentity", prefix);
	phase2->credentials.username =
			l_settings_get_string(settings, "Security", setting);

	if (!phase2->credentials.username) {
		l_error("Phase 2 Identity is missing.");
		return false;
	}

	snprintf(setting, sizeof(setting), "%sPassword", prefix);
	phase2->credentials.password =
			l_settings_get_string(settings, "Security", setting);

	if (!phase2->credentials.password) {
		l_error("Phase 2 Password is missing.");
		l_free(phase2->credentials.username);

		return false;
	}

	return true;
}

static bool eap_ttls_phase2_chap_generate_challenge(struct eap_state *eap,
							uint8_t *challenge,
							size_t challenge_len)
{
	return eap_tls_common_tunnel_prf_get_bytes(eap, true, "ttls challenge",
								challenge,
								challenge_len);
}

static bool eap_ttls_phase2_chap_init(struct eap_state *eap)
{
	struct phase2_method *phase2 = eap_tls_common_get_variant_data(eap);
	struct phase2_credentials *credentials = &phase2->credentials;
	struct avp_builder *builder;
	uint8_t challenge[CHAP_CHALLENGE_LEN + CHAP_IDENT_LEN];
	uint8_t password_hash[CHAP_PASSWORD_LEN];
	uint8_t ident;
	struct l_checksum *hash;
	uint8_t *data;
	size_t data_len;

	if (!eap_ttls_phase2_chap_generate_challenge(eap, challenge,
							CHAP_CHALLENGE_LEN +
							CHAP_IDENT_LEN)) {
		l_error("TTLS Tunneled-CHAP: Failed to generate CHAP "
								"challenge.");
		return false;
	}

	ident = challenge[CHAP_CHALLENGE_LEN];

	hash = l_checksum_new(L_CHECKSUM_MD5);
	if (!hash) {
		l_error("Can't create the MD5 checksum");
		return false;
	}

	l_checksum_update(hash, &ident, CHAP_IDENT_LEN);
	l_checksum_update(hash, credentials->password,
						strlen(credentials->password));
	l_checksum_update(hash, challenge, CHAP_CHALLENGE_LEN);

	l_checksum_get_digest(hash, password_hash, CHAP_PASSWORD_LEN);
	l_checksum_free(hash);

	builder = avp_builder_new(512);

	build_avp_user_name(builder, credentials->username);
	build_avp_chap_challenge(builder, challenge);
	build_avp_chap_password(builder, &ident, password_hash);
	explicit_bzero(password_hash, sizeof(password_hash));

	data = avp_builder_free(builder, false, &data_len);

	eap_tls_common_tunnel_send(eap, data, data_len);
	explicit_bzero(data, data_len);
	l_free(data);

	return true;
}

static const struct phase2_method_ops phase2_chap_ops = {
	.init = eap_ttls_phase2_chap_init,
};

static bool eap_ttls_phase2_ms_chap_init(struct eap_state *eap)
{
	struct phase2_method *phase2 = eap_tls_common_get_variant_data(eap);
	struct phase2_credentials *credentials = &phase2->credentials;
	struct avp_builder *builder;
	uint8_t challenge[MS_CHAP_CHALLENGE_LEN + CHAP_IDENT_LEN];
	uint8_t password_hash[16];
	uint8_t ident;
	uint8_t *data;
	size_t data_len;

	if (!eap_ttls_phase2_chap_generate_challenge(eap, challenge,
							MS_CHAP_CHALLENGE_LEN +
							CHAP_IDENT_LEN)) {
		l_error("TTLS Tunneled-MSCHAP: Failed to generate MS-CHAP "
								"challenge.");
		return false;
	}

	ident = challenge[MS_CHAP_CHALLENGE_LEN];

	builder = avp_builder_new(512);

	build_avp_user_name(builder, credentials->username);
	build_avp_ms_chap_challenge(builder, challenge);

	mschap_nt_password_hash(credentials->password, password_hash);

	build_avp_ms_chap_response(builder, &ident, challenge, password_hash);
	explicit_bzero(password_hash, sizeof(password_hash));

	data = avp_builder_free(builder, false, &data_len);

	eap_tls_common_tunnel_send(eap, data, data_len);
	explicit_bzero(data, data_len);
	l_free(data);

	return true;
}

static const struct phase2_method_ops phase2_mschap_ops = {
	.init = eap_ttls_phase2_ms_chap_init,
};

struct mschapv2_state {
	uint8_t server_challenge[MSCHAPV2_CHALLENGE_LEN + CHAP_IDENT_LEN];
	uint8_t peer_challenge[MSCHAPV2_CHALLENGE_LEN];
	uint8_t password_hash[16];
};

static void mschapv2_state_destroy(struct phase2_method *phase2)
{
	struct mschapv2_state *state = phase2->state;

	if (!state)
		return;

	explicit_bzero(state->server_challenge, MSCHAPV2_CHALLENGE_LEN +
							CHAP_IDENT_LEN);
	explicit_bzero(state->peer_challenge, MSCHAPV2_CHALLENGE_LEN);
	explicit_bzero(state->password_hash, 16);

	l_free(state);
	phase2->state = NULL;
}

static bool eap_ttls_phase2_mschapv2_init(struct eap_state *eap)
{
	struct phase2_method *phase2 = eap_tls_common_get_variant_data(eap);
	struct phase2_credentials *credentials = &phase2->credentials;
	struct mschapv2_state *mschapv2_state;
	struct avp_builder *builder;
	uint8_t response[MSCHAPV2_RESPONSE_LEN];
	uint8_t ident;
	uint8_t *data;
	size_t data_len;

	phase2->state = mschapv2_state = l_new(struct mschapv2_state, 1);

	if (!l_getrandom(mschapv2_state->peer_challenge,
						MSCHAPV2_CHALLENGE_LEN)) {
		l_error("TTLS Tunneled-MSCHAPv2: Failed to generate random for "
							"peer challenge.");
		return false;
	}

	if (!eap_ttls_phase2_chap_generate_challenge(eap,
					mschapv2_state->server_challenge,
					MSCHAPV2_CHALLENGE_LEN +
					CHAP_IDENT_LEN)) {
		l_error("TTLS Tunneled-MSCHAPv2: Failed to generate CHAP "
								"challenge.");
		return false;
	}

	if (!mschap_nt_password_hash(credentials->password,
					mschapv2_state->password_hash)) {
		l_error("TTLS Tunneled-MSCHAPv2: Failed to generate password "
								"hash.");
		return false;
	}

	if (!mschapv2_generate_nt_response(mschapv2_state->password_hash,
					mschapv2_state->peer_challenge,
					mschapv2_state->server_challenge,
					credentials->username, response)) {
		l_error("TTLS Tunneled-MSCHAPv2: Failed to generate "
								"NT response.");
		return false;
	}

	ident = mschapv2_state->server_challenge[MSCHAPV2_CHALLENGE_LEN];

	builder = avp_builder_new(512);

	build_avp_user_name(builder, credentials->username);
	build_avp_mschapv2_challenge(builder, mschapv2_state->server_challenge);
	build_avp_mschapv2_response(builder, &ident,
					mschapv2_state->peer_challenge,
					response);

	data = avp_builder_free(builder, false, &data_len);

	eap_tls_common_tunnel_send(eap, data, data_len);
	l_free(data);

	return true;
}

static bool eap_ttls_phase2_mschapv2_handle_success(struct eap_state *eap,
							const uint8_t *data,
							size_t len)
{
	struct phase2_method *phase2 = eap_tls_common_get_variant_data(eap);
	struct phase2_credentials *credentials = &phase2->credentials;
	struct mschapv2_state *mschapv2_state = phase2->state;
	uint8_t nt_response[MSCHAPV2_RESPONSE_LEN];
	char nt_server_response[MSCHAPV2_SERVER_RESPONSE_LEN];
	uint8_t password_hash_hash[16];
	bool r;

	if (len != CHAP_IDENT_LEN + MSCHAPV2_SERVER_RESPONSE_LEN) {
		l_error("TTLS Tunneled MSCHAPv2: Server response has invalid "
								"length.");
		goto error;
	}

	if (!mschapv2_generate_nt_response(mschapv2_state->password_hash,
					mschapv2_state->peer_challenge,
					mschapv2_state->server_challenge,
					credentials->username,
					nt_response)) {
		l_error("TTLS Tunneled-MSCHAPv2: Failed to generate "
								"NT response.");
		goto error;
	}

	if (!mschapv2_hash_nt_password_hash(mschapv2_state->password_hash,
							password_hash_hash)) {
		l_error("TTLS Tunneled-MSCHAPv2: Failed to generate "
						"hash of the password hash.");
		goto error;
	}

	r = mschapv2_generate_authenticator_response(
					password_hash_hash, nt_response,
					mschapv2_state->peer_challenge,
					mschapv2_state->server_challenge,
					credentials->username,
					nt_server_response);
	explicit_bzero(password_hash_hash, sizeof(password_hash_hash));

	if (!r) {
		l_error("TTLS Tunneled-MSCHAPv2: Failed to generate server "
								"response.");
		goto error;
	}

	if (memcmp(nt_server_response, data + CHAP_IDENT_LEN,
						MSCHAPV2_SERVER_RESPONSE_LEN)) {
		l_error("TTLS Tunneled-MSCHAPv2: Invalid server response.");

		goto error;
	}

	eap_tls_common_send_empty_response(eap);

	return true;

error:
	eap_tls_common_set_phase2_failed(eap);

	return false;
}

static bool eap_ttls_phase2_mschapv2_handle_error(struct eap_state *eap,
							const uint8_t *data,
							size_t len)
{
	l_error("TTLS Tunneled-MSCHAPv2: Authentication failed.");

	eap_tls_common_set_phase2_failed(eap);

	return false;
}

static bool eap_ttls_phase2_mschapv2_handle_avp(struct eap_state *eap,
						enum radius_attr type,
						uint32_t vendor_id,
						const uint8_t *data,
						size_t len)
{
	if (vendor_id != RADIUS_VENDOR_ID_MICROSOFT)
		return false;

	if (type == RADIUS_ATTR_MSCHAPV2_SUCCESS)
		return eap_ttls_phase2_mschapv2_handle_success(eap, data, len);
	else if (type == RADIUS_ATTR_MSCHAPV2_ERROR)
		return eap_ttls_phase2_mschapv2_handle_error(eap, data, len);

	return false;
}

static const struct phase2_method_ops phase2_mschapv2_ops = {
	.init = eap_ttls_phase2_mschapv2_init,
	.handle_avp = eap_ttls_phase2_mschapv2_handle_avp,
	.reset = mschapv2_state_destroy,
	.destroy = mschapv2_state_destroy,
};

static bool eap_ttls_phase2_pap_init(struct eap_state *eap)
{
	struct phase2_method *phase2 = eap_tls_common_get_variant_data(eap);
	struct phase2_credentials *credentials = &phase2->credentials;
	struct avp_builder *builder;
	uint8_t *buf;
	size_t buf_len;

	builder = avp_builder_new(512);

	build_avp_user_name(builder, credentials->username);
	build_avp_user_password(builder, credentials->password);

	buf = avp_builder_free(builder, false, &buf_len);

	eap_tls_common_tunnel_send(eap, buf, buf_len);
	explicit_bzero(buf, buf_len);
	l_free(buf);

	return true;
}

static const struct phase2_method_ops phase2_pap_ops = {
	.init = eap_ttls_phase2_pap_init,
};

static void eap_ttls_phase2_eap_send_response(const uint8_t *data, size_t len,
								void *user_data)
{
	struct eap_state *eap = user_data;
	struct avp_builder *builder;
	uint8_t *msg_data;
	size_t msg_data_len;

	builder = avp_builder_new(TTLS_AVP_HEADER_LEN + len);

	avp_builder_start_avp(builder, RADIUS_ATTR_EAP_MESSAGE, true, 0);
	memcpy(avp_builder_reserve(builder, 1, len), data, len);
	avp_builder_finalize_avp(builder);

	msg_data = avp_builder_free(builder, false, &msg_data_len);

	eap_tls_common_tunnel_send(eap, msg_data, msg_data_len);
	l_free(msg_data);
}

static void eap_ttls_phase2_eap_complete(enum eap_result result,
								void *user_data)
{
	struct eap_state *eap = user_data;

	eap_tls_common_set_completed(eap);

	if (result != EAP_RESULT_SUCCESS) {
		eap_tls_common_set_phase2_failed(eap);

		return;
	}

	eap_method_success(eap);
}

static bool eap_ttls_phase2_eap_load_settings(struct eap_state *eap,
						struct phase2_method *phase2,
						struct l_settings *settings,
						const char *prefix)
{
	phase2->state = eap_new(eap_ttls_phase2_eap_send_response,
						eap_ttls_phase2_eap_complete,
						eap);
	if (!phase2->state) {
		l_error("Could not create the TTLS Phase 2 EAP instance");
		return false;
	}

	if (!eap_load_settings(phase2->state, settings, prefix)) {
		eap_free(phase2->state);
		return false;
	}

	return true;
}

static bool eap_ttls_phase2_eap_init(struct eap_state *eap)
{
	struct phase2_method *phase2 = eap_tls_common_get_variant_data(eap);
	uint8_t packet[5] = { EAP_CODE_REQUEST, 0, 0, 5, EAP_TYPE_IDENTITY };

	if (!phase2->state)
		return false;
	/*
	 * Consume a fake Request/Identity packet so that the EAP instance
	 * starts with its Response/Identity right away.
	 */
	eap_rx_packet(phase2->state, packet, sizeof(packet));

	return true;
}

static bool eap_ttls_phase2_eap_handle_avp(struct eap_state *eap,
						enum radius_attr type,
						uint32_t vendor_id,
						const uint8_t *data,
						size_t len)
{
	struct phase2_method *phase2 = eap_tls_common_get_variant_data(eap);

	if (type != RADIUS_ATTR_EAP_MESSAGE)
		return false;

	eap_rx_packet(phase2->state, data, len);

	return true;
}

static void eap_ttls_phase2_eap_destroy(struct phase2_method *phase2)
{
	if (!phase2->state)
		return;

	eap_reset(phase2->state);
	eap_free(phase2->state);
}

static void eap_ttls_phase2_eap_reset(struct phase2_method *phase2)
{
	if (!phase2->state)
		return;

	eap_reset(phase2->state);
}

static const struct phase2_method_ops phase2_eap_ops = {
	.init = eap_ttls_phase2_eap_init,
	.handle_avp = eap_ttls_phase2_eap_handle_avp,
	.destroy = eap_ttls_phase2_eap_destroy,
	.reset = eap_ttls_phase2_eap_reset,
};

static bool eap_ttls_tunnel_ready(struct eap_state *eap,
						const char *peer_identity)
{
	struct phase2_method *phase2 = eap_tls_common_get_variant_data(eap);
	uint8_t msk_emsk[128];

	/*
	 * TTLSv0 seems to assume that the TLS handshake phase authenticates
	 * the server to the client enough that the inner method success or
	 * failure status doesn't matter as long as the server lets us in,
	 * although in various places it says the client may also have a
	 * specific policy.
	 */
	eap_method_success(eap);

	/* MSK, EMSK and challenge derivation */
	eap_tls_common_tunnel_prf_get_bytes(eap, true, "ttls keying material",
								msk_emsk, 128);

	eap_set_key_material(eap, msk_emsk + 0, 64, msk_emsk + 64, 64, NULL, 0,
				NULL, 0);
	explicit_bzero(msk_emsk, sizeof(msk_emsk));

	if (phase2->ops->init)
		return phase2->ops->init(eap);

	return true;
}

static bool eap_ttls_tunnel_handle_request(struct eap_state *eap,
							const uint8_t *data,
							size_t data_len)
{
	struct phase2_method *phase2 = eap_tls_common_get_variant_data(eap);
	struct avp_iter iter;

	if (!phase2->ops->handle_avp)
		return true;

	avp_iter_init(&iter, data, data_len);

	while (avp_iter_next(&iter)) {
		if (phase2->ops->handle_avp(eap, iter.type, iter.vendor_id,
							iter.data, iter.len))
			continue;

		if (iter.flags & TTLS_AVP_FLAG_M)
			return false;
	}

	return true;
}

static void eap_ttls_state_reset(void *data)
{
	struct phase2_method *phase2 = data;

	if (!phase2->ops->reset)
		return;

	phase2->ops->reset(phase2);
}

static void eap_ttls_state_destroy(void *data)
{
	struct phase2_method *phase2 = data;

	eap_ttls_phase2_credentials_destroy(&phase2->credentials);

	if (phase2->ops->destroy)
		phase2->ops->destroy(phase2);

	l_free(phase2);
}

static const struct {
	const char *name;
	const struct phase2_method_ops *method_ops;
} tunneled_non_eap_method_ops[] = {
	{ "Tunneled-CHAP", &phase2_chap_ops },
	{ "Tunneled-MSCHAP", &phase2_mschap_ops },
	{ "Tunneled-MSCHAPv2", &phase2_mschapv2_ops },
	{ "Tunneled-PAP", &phase2_pap_ops },
	{ }
};

static int eap_ttls_check_tunneled_auth_settings(struct l_settings *settings,
						struct l_queue *secrets,
						const char *prefix,
						struct l_queue **out_missing)
{
	const struct eap_secret_info *secret;
	char identity_key[128];
	char password_key[128];

	L_AUTO_FREE_VAR(char *, identity);
	L_AUTO_FREE_VAR(char *, password) = NULL;

	snprintf(identity_key, sizeof(identity_key), "%sIdentity", prefix);
	snprintf(password_key, sizeof(password_key), "%sPassword", prefix);

	identity = l_settings_get_string(settings, "Security", identity_key);

	if (!identity) {
		secret = l_queue_find(secrets, eap_secret_info_match,
								identity_key);
		if (!secret) {
			eap_append_secret(out_missing,
					EAP_SECRET_REMOTE_USER_PASSWORD,
					identity_key, password_key, NULL,
					EAP_CACHE_TEMPORARY);
		}

		return 0;
	}

	password = l_settings_get_string(settings, "Security", password_key);

	if (!password) {
		secret = l_queue_find(secrets, eap_secret_info_match,
								password_key);
		if (!secret) {
			eap_append_secret(out_missing,
					EAP_SECRET_REMOTE_PASSWORD,
					password_key, NULL, identity,
					EAP_CACHE_TEMPORARY);
		}
	} else
		explicit_bzero(password, strlen(password));

	return 0;
}

static int eap_ttls_settings_check(struct l_settings *settings,
						struct l_queue *secrets,
						const char *prefix,
						struct l_queue **out_missing)
{
	char setting_key[72];
	char setting_prefix[72];
	const char *phase2_method_name;
	uint8_t i;
	int r;

	snprintf(setting_prefix, sizeof(setting_prefix), "%sTTLS-", prefix);
	r = eap_tls_common_settings_check(settings, secrets, setting_prefix,
								out_missing);
	if (r)
		return r;

	snprintf(setting_key, sizeof(setting_key), "%sTTLS-Phase2-Method",
									prefix);
	phase2_method_name = l_settings_get_value(settings, "Security",
								setting_key);
	if (!phase2_method_name) {
		l_error("Setting %s is missing", setting_key);
		return -ENOENT;
	}

	snprintf(setting_prefix, sizeof(setting_prefix), "%sTTLS-Phase2-",
									prefix);

	for (i = 0; tunneled_non_eap_method_ops[i].name; i++) {
		if (strcmp(tunneled_non_eap_method_ops[i].name,
							phase2_method_name))
			continue;

		return eap_ttls_check_tunneled_auth_settings(settings, secrets,
								setting_prefix,
								out_missing);
	}

	return __eap_check_settings(settings, secrets, setting_prefix, false,
								out_missing);
}

static const struct eap_tls_variant_ops eap_ttls_ops = {
	.version_max_supported = EAP_TLS_VERSION_0,
	.tunnel_ready = eap_ttls_tunnel_ready,
	.tunnel_handle_request = eap_ttls_tunnel_handle_request,
	.reset = eap_ttls_state_reset,
	.destroy = eap_ttls_state_destroy,
};

static bool eap_ttls_settings_load(struct eap_state *eap,
						struct l_settings *settings,
						const char *prefix)
{
	struct phase2_method *phase2;
	const char *phase2_method_name;
	char setting[72];
	uint8_t i;

	snprintf(setting, sizeof(setting), "%sTTLS-Phase2-Method", prefix);
	phase2_method_name = l_settings_get_value(settings, "Security",
								setting);
	if (!phase2_method_name)
		return false;

	phase2 = l_new(struct phase2_method, 1);

	snprintf(setting, sizeof(setting), "%sTTLS-Phase2-", prefix);

	for (i = 0; tunneled_non_eap_method_ops[i].name; i++) {
		if (strcmp(tunneled_non_eap_method_ops[i].name,
							phase2_method_name))
			continue;

		phase2->ops = tunneled_non_eap_method_ops[i].method_ops;

		if (!eap_ttls_phase2_non_eap_load_settings(phase2, settings,
								setting))
			goto error;

		break;
	}

	if (!phase2->ops) {
		phase2->ops = &phase2_eap_ops;

		if (!eap_ttls_phase2_eap_load_settings(eap, phase2, settings,
								setting))
			goto error;
	}

	snprintf(setting, sizeof(setting), "%sTTLS-", prefix);

	if (!eap_tls_common_settings_load(eap, settings, setting,
							&eap_ttls_ops, phase2))
		goto error;

	return true;
error:
	l_free(phase2);

	return false;
}

static struct eap_method eap_ttls = {
	.request_type = EAP_TYPE_TTLS,
	.exports_msk = true,
	.name = "TTLS",

	.handle_request = eap_tls_common_handle_request,
	.handle_retransmit = eap_tls_common_handle_retransmit,
	.reset_state = eap_tls_common_state_reset,
	.free = eap_tls_common_state_free,

	.check_settings = eap_ttls_settings_check,
	.load_settings = eap_ttls_settings_load,
};

static int eap_ttls_init(void)
{
	l_debug("");
	return eap_register_method(&eap_ttls);
}

static void eap_ttls_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_ttls);
}

EAP_METHOD_BUILTIN(eap_ttls, eap_ttls_init, eap_ttls_exit)
