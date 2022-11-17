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

#include <stdint.h>
#include <stdbool.h>
#include <asm/byteorder.h>
#include <linux/types.h>

struct eap_state;

enum eap_result {
	EAP_RESULT_SUCCESS,
	EAP_RESULT_FAIL,
	EAP_RESULT_TIMEOUT,
};

enum eap_secret_type {
	EAP_SECRET_LOCAL_PKEY_PASSPHRASE,
	EAP_SECRET_REMOTE_PASSWORD,
	EAP_SECRET_REMOTE_USER_PASSWORD,
};

enum eap_secret_cache_policy {
	EAP_CACHE_NEVER,
	EAP_CACHE_TEMPORARY,
};

struct eap_secret_info {
	char *id;
	char *id2;
	enum eap_secret_type type;
	char *parameter;
	char *value;
	enum eap_secret_cache_policy cache_policy;
};

typedef void (*eap_tx_packet_func_t)(const uint8_t *eap_data, size_t len,
					void *user_data);
typedef void (*eap_key_material_func_t)(const uint8_t *msk_data, size_t msk_len,
				const uint8_t *emsk_data, size_t emsk_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *session_id, size_t session_len,
				void *user_data);
typedef void (*eap_complete_func_t)(enum eap_result result, void *user_data);
typedef void (*eap_event_func_t)(unsigned int event, const void *event_data,
							void *user_data);

bool eap_secret_info_match(const void *a, const void *b);
void eap_secret_info_free(void *data);

struct eap_state *eap_new(eap_tx_packet_func_t tx_packet,
			eap_complete_func_t complete, void *user_data);
void eap_free(struct eap_state *eap);

void eap_append_secret(struct l_queue **out_missing, enum eap_secret_type type,
			const char *id, const char *id2, const char *parameter,
			enum eap_secret_cache_policy cache_policy);

int eap_check_settings(struct l_settings *settings, struct l_queue *secrets,
			const char *prefix, bool set_key_material,
			struct l_queue **out_missing);
bool eap_load_settings(struct eap_state *eap, struct l_settings *settings,
			const char *prefix);
bool eap_reset(struct eap_state *eap);
void eap_start(struct eap_state *eap);

void eap_set_key_material_func(struct eap_state *eap,
				eap_key_material_func_t func);
void eap_set_event_func(struct eap_state *eap, eap_event_func_t func);

void eap_set_mtu(struct eap_state *eap, size_t mtu);
size_t eap_get_mtu(struct eap_state *eap);

const char *eap_get_identity(struct eap_state *eap);

void eap_rx_packet(struct eap_state *eap, const uint8_t *pkt, size_t len);

void eap_set_peer_id(struct eap_state *eap, const char *id);
const char *eap_get_peer_id(struct eap_state *eap);

void __eap_set_config(struct l_settings *config);

int eap_init(void);
void eap_exit(void);
