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

typedef struct l_settings *(*eap_tls_session_cache_load_func_t)(void);
typedef void (*eap_tls_session_cache_sync_func_t)(const struct l_settings *);

enum eap_tls_version {
	EAP_TLS_VERSION_0               = 0x00,
	EAP_TLS_VERSION_1               = 0x01,
	EAP_TLS_VERSION_MASK            = 0x07,
	EAP_TLS_VERSION_NOT_NEGOTIATED  = 0x08,
};

struct eap_tls_variant_ops {
	enum eap_tls_version version_max_supported;

	bool (*tunnel_ready)(struct eap_state *eap, const char *peer_identity);
	bool (*tunnel_handle_request)(struct eap_state *eap,
					const uint8_t *data, size_t data_len);
	void (*reset)(void *variant_data);
	void (*destroy)(void *variant_data);
};

bool eap_tls_common_state_reset(struct eap_state *eap);
void eap_tls_common_state_free(struct eap_state *eap);

void eap_tls_common_set_completed(struct eap_state *eap);
void eap_tls_common_set_phase2_failed(struct eap_state *eap);

void eap_tls_common_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len);
void eap_tls_common_handle_retransmit(struct eap_state *eap,
						const uint8_t *pkt, size_t len);

struct l_certchain *eap_tls_load_client_cert(struct l_settings *settings,
						const char *value,
						const char *passphrase,
						bool *out_is_encrypted);
struct l_key *eap_tls_load_priv_key(struct l_settings *settings,
					const char *value,
					const char *passphrase,
					bool *out_is_encrypted);

int eap_tls_common_settings_check(struct l_settings *settings,
						struct l_queue *secrets,
						const char *prefix,
						struct l_queue **out_missing);
bool eap_tls_common_settings_load(struct eap_state *eap,
				struct l_settings *settings, const char *prefix,
				const struct eap_tls_variant_ops *variant_ops,
				void *variant_data);
void eap_tls_common_set_keys(struct eap_state *eap,
				struct l_certchain *client_cert,
				struct l_key *client_key);

void eap_tls_common_send_empty_response(struct eap_state *eap);
enum eap_tls_version eap_tls_common_get_negotiated_version(
							struct eap_state *eap);
void *eap_tls_common_get_variant_data(struct eap_state *eap);

bool eap_tls_common_tunnel_prf_get_bytes(struct eap_state *eap,
						bool use_master_secret,
						const char *label,
						uint8_t *buf, size_t len);
void eap_tls_common_tunnel_send(struct eap_state *eap, const uint8_t *data,
							size_t data_len);
void eap_tls_common_tunnel_close(struct eap_state *eap);

void eap_tls_set_session_cache_ops(eap_tls_session_cache_load_func_t load,
					eap_tls_session_cache_sync_func_t sync);
void eap_tls_forget_peer(const char *peer_id);
