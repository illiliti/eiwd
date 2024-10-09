/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
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

#include "src/defs.h"

struct l_ecc_point;
struct l_ecc_scalar;
enum ie_rsn_akm_suite;
struct scan_freq_set;

struct dpp_uri_info {
	struct scan_freq_set *freqs;
	struct l_ecc_point *boot_public;
	uint8_t mac[6];
	char *information;
	uint8_t version;
	char *host;
};

enum dpp_frame_type {
	DPP_FRAME_AUTHENTICATION_REQUEST	= 0,
	DPP_FRAME_AUTHENTICATION_RESPONSE	= 1,
	DPP_FRAME_AUTHENTICATION_CONFIRM	= 2,
	/* 3 - 4 reserved */
	DPP_FRAME_PEER_DISCOVERY_REQUEST	= 5,
	DPP_FRAME_PEER_DISCOVERY_RESPONSE	= 6,
	DPP_FRAME_PKEX_VERSION1_XCHG_REQUEST	= 7,
	DPP_FRAME_PKEX_XCHG_RESPONSE		= 8,
	DPP_FRAME_PKEX_COMMIT_REVEAL_REQUEST	= 9,
	DPP_FRAME_PKEX_COMMIT_REVEAL_RESPONSE	= 10,
	DPP_FRAME_CONFIGURATION_RESULT		= 11,
	DPP_FRAME_CONNECTION_STATUS_RESULT	= 12,
	DPP_FRAME_PRESENCE_ANNOUNCEMENT		= 13,
	DPP_FRAME_RECONF_ANNOUNCEMENT		= 14,
	DPP_FRAME_RECONF_AUTHENTICATION_REQUEST	= 15,
	DPP_FRAME_RECONF_AUTHENTICATION_RESPONSE = 16,
	DPP_FRAME_RECONF_AUTHENTICATION_CONFIRM = 17,
	DPP_FRAME_PKEX_XCHG_REQUEST		= 18,
	/* 19 - 255 reserved */
};

enum dpp_status {
	DPP_STATUS_OK,
	DPP_STATUS_NOT_COMPATIBLE,
	DPP_STATUS_AUTH_FAILURE,
	DPP_STATUS_BAD_CODE,
	DPP_STATUS_BAD_GROUP,
	DPP_STATUS_CONFIGURE_FAILURE,
	DPP_STATUS_RESPONSE_PENDING,
	DPP_STATUS_INVALID_CONNECTOR,
	DPP_STATUS_NO_MATCH,
	DPP_STATUS_CONFIG_REJECTED,
	DPP_STATUS_NO_AP,
	DPP_STATUS_CONFIGURE_PENDING,
	DPP_STATUS_CSR_NEEDED,
	DPP_STATUS_CSR_BAD,
	DPP_STATUS_NEW_KEY_NEEDED,
};

enum dpp_attribute_type {
	/* 0000 - 0FFF reserved */
	DPP_ATTR_STATUS				= 0x1000,
	DPP_ATTR_INITIATOR_BOOT_KEY_HASH	= 0x1001,
	DPP_ATTR_RESPONDER_BOOT_KEY_HASH	= 0x1002,
	DPP_ATTR_INITIATOR_PROTOCOL_KEY		= 0x1003,
	DPP_ATTR_WRAPPED_DATA			= 0x1004,
	DPP_ATTR_INITIATOR_NONCE		= 0x1005,
	DPP_ATTR_INITIATOR_CAPABILITIES		= 0x1006,
	DPP_ATTR_RESPONDER_NONCE		= 0x1007,
	DPP_ATTR_RESPONDER_CAPABILITIES		= 0x1008,
	DPP_ATTR_RESPONDER_PROTOCOL_KEY		= 0x1009,
	DPP_ATTR_INITIATOR_AUTH_TAG		= 0x100a,
	DPP_ATTR_RESPONDER_AUTH_TAG		= 0x100b,
	DPP_ATTR_CONFIGURATION_OBJECT		= 0x100c,
	DPP_ATTR_CONNECTOR			= 0x100d,
	DPP_ATTR_CONFIGURATION_REQUEST		= 0x100e,
	DPP_ATTR_BOOTSTRAPPING_KEY		= 0x100f,
	/* 1010 - 1011 reserved */
	DPP_ATTR_FINITE_CYCLIC_GROUP		= 0x1012,
	DPP_ATTR_ENCRYPTED_KEY			= 0x1013,
	DPP_ATTR_ENROLLEE_NONCE			= 0x1014,
	DPP_ATTR_CODE_IDENTIFIER		= 0x1015,
	DPP_ATTR_TRANSACTION_ID			= 0x1016,
	DPP_ATTR_BOOTSTRAPPING_INFO		= 0x1017,
	DPP_ATTR_CHANNEL			= 0x1018,
	DPP_ATTR_PROTOCOL_VERSION		= 0x1019,
	DPP_ATTR_ENVELOPED_DATA			= 0x101a,
	DPP_ATTR_SEND_CONN_STATUS		= 0x101b,
	DPP_ATTR_CONN_STATUS			= 0x101c,
	DPP_ATTR_RECONFIGURATION_FLAGS		= 0x101d,
	DPP_ATTR_C_SIGN_KEY_HASH		= 0x101e,
	DPP_ATTR_CSR_ATTRIBUTES_REQUEST		= 0x101f,
	DPP_ATTR_ANONCE				= 0x1020,
	DPP_ATTR_EID				= 0x1021,
	DPP_ATTR_CONFIGURATOR_NONCE		= 0x1022,
};

struct dpp_configuration {
	char ssid[SSID_MAX_SIZE + 1];
	size_t ssid_len;
	uint32_t akm_suites;
	char *passphrase;
	char *psk;		/* hex string */

	/* "3rd party extensions" only applicable for two IWD peers */
	bool send_hostname : 1;
	bool hidden : 1;
};

struct dpp_configuration *dpp_parse_configuration_object(const char *json,
							size_t json_len);
struct dpp_configuration *dpp_configuration_new(
					const struct l_settings *settings,
					const char *ssid,
					enum ie_rsn_akm_suite akm_suite);
char *dpp_configuration_to_json(struct dpp_configuration *config);
void dpp_configuration_free(struct dpp_configuration *conf);

struct dpp_attr_iter {
	const uint8_t *pos;
	const uint8_t *end;
};

void dpp_attr_iter_init(struct dpp_attr_iter *iter, const uint8_t *pdu,
			size_t len);
bool dpp_attr_iter_next(struct dpp_attr_iter *iter,
			enum dpp_attribute_type *type, size_t *len,
			const uint8_t **data);
uint8_t *dpp_unwrap_attr(const void *ad0, size_t ad0_len, const void *ad1,
				size_t ad1_len, const void *key, size_t key_len,
				const void *wrapped, size_t wrapped_len,
				size_t *unwrapped_len);
size_t dpp_append_attr(uint8_t *to, enum dpp_attribute_type type,
				void *attr, size_t attr_len);
size_t dpp_append_wrapped_data(const void *ad0, size_t ad0_len, const void *ad1,
				size_t ad1_len, uint8_t *to, size_t to_len,
				const void *key, size_t key_len,
				size_t num_attrs, ...);

char *dpp_generate_uri(const uint8_t *asn1, size_t asn1_len, uint8_t version,
			const uint8_t *mac, const uint32_t *freqs,
			size_t freqs_len, const char *info, const char *host);

size_t dpp_nonce_len_from_key_len(size_t len);

bool dpp_hash(enum l_checksum_type type, uint8_t *out, unsigned int num, ...);

bool dpp_derive_r_auth(const void *i_nonce, const void *r_nonce,
				size_t nonce_len, struct l_ecc_point *i_proto,
				struct l_ecc_point *r_proto,
				struct l_ecc_point *i_boot,
				struct l_ecc_point *r_boot,
				void *r_auth);
bool dpp_derive_i_auth(const void *r_nonce, const void *i_nonce,
				size_t nonce_len, struct l_ecc_point *r_proto,
				struct l_ecc_point *i_proto,
				struct l_ecc_point *r_boot,
				struct l_ecc_point *i_boot, void *i_auth);
struct l_ecc_scalar *dpp_derive_k1(const struct l_ecc_point *i_proto_public,
				const struct l_ecc_scalar *boot_private,
				void *k1);
struct l_ecc_scalar *dpp_derive_k2(const struct l_ecc_point *i_proto_public,
				const struct l_ecc_scalar *proto_private,
				void *k2);
bool dpp_derive_ke(const uint8_t *i_nonce, const uint8_t *r_nonce,
				struct l_ecc_scalar *m, struct l_ecc_scalar *n,
				struct l_ecc_point *l, void *ke);

uint8_t *dpp_point_to_asn1(const struct l_ecc_point *p, size_t *len_out);
struct l_ecc_point *dpp_point_from_asn1(const uint8_t *asn1, size_t len);

struct dpp_uri_info *dpp_parse_uri(const char *uri);
void dpp_free_uri_info(struct dpp_uri_info *info);

struct l_ecc_point *dpp_derive_qi(const struct l_ecc_curve *curve,
					const char *key,
					const char *identifier,
					const uint8_t *mac_initiator);
struct l_ecc_point *dpp_derive_qr(const struct l_ecc_curve *curve,
					const char *key,
					const char *identifier,
					const uint8_t *mac_responder);
struct l_ecc_point *dpp_derive_li(
				const struct l_ecc_point *boot_public,
				const struct l_ecc_point *proto_public,
				const struct l_ecc_scalar *boot_private);
struct l_ecc_point *dpp_derive_lr(
				const struct l_ecc_scalar *boot_private,
				const struct l_ecc_scalar *proto_private,
				const struct l_ecc_point *peer_public);
bool dpp_derive_z(const uint8_t *mac_i, const uint8_t *mac_r,
				const struct l_ecc_point *n,
				const struct l_ecc_point *m,
				const struct l_ecc_point *k,
				const char *key,
				const char *identifier,
				void *z_out, size_t *z_len);
bool dpp_derive_u(const struct l_ecc_point *j,
			const uint8_t *mac_i,
			const struct l_ecc_point *a,
			const struct l_ecc_point *y,
			const struct l_ecc_point *x,
			void *u_out, size_t *u_len);
bool dpp_derive_v(const struct l_ecc_point *l, const uint8_t *mac,
			const struct l_ecc_point *b,
			const struct l_ecc_point *x,
			const struct l_ecc_point *y,
			void *v_out, size_t *v_len);
