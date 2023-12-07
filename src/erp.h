/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

struct erp_state;
struct erp_cache_entry;

enum erp_result {
	ERP_RESULT_SUCCESS,
	ERP_RESULT_FAIL,
};

typedef void (*erp_tx_packet_func_t)(const uint8_t *erp_data, size_t len,
					void *user_data);

struct erp_state *erp_new(struct erp_cache_entry *cache,
				erp_tx_packet_func_t tx_packet,
				void *user_data);
void erp_free(struct erp_state *erp);

bool erp_start(struct erp_state *erp);
int erp_rx_packet(struct erp_state *erp, const uint8_t *erp_data, size_t len);

const void *erp_get_rmsk(struct erp_state *erp, size_t *rmsk_len);

void erp_cache_add(const char *id, const void *session_id, size_t session_len,
			const void *emsk, size_t emsk_len,
			const uint8_t *ssid, size_t ssid_len);

void erp_cache_remove(const char *id);

struct erp_cache_entry *erp_cache_get(const char *ssid);
void erp_cache_put(struct erp_cache_entry *cache);

const char *erp_cache_entry_get_identity(struct erp_cache_entry *cache);
