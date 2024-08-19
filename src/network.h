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

#include <stdbool.h>
#include <time.h>

enum security;
struct device;
struct station;
struct network;
struct scan_bss;
struct handshake_state;
struct erp_cache_entry;
struct scan_freq_set;

void network_connected(struct network *network);
void network_disconnected(struct network *network);
bool network_rankmod(const struct network *network, double *rankmod);

struct network *network_create(struct station *station, const char *ssid,
				enum security security);

const char *network_get_ssid(const struct network *network);
const char *network_get_path(const struct network *network);
enum security network_get_security(const struct network *network);
bool network_set_passphrase(struct network *network, const char *passphrase);
int network_get_signal_strength(const struct network *network);
struct l_settings *network_get_settings(const struct network *network);
struct station *network_get_station(const struct network *network);

bool network_set_psk(struct network *network, const uint8_t *psk);

int network_set_transition_disable(struct network *network,
					const uint8_t *td, size_t len);

int network_handshake_setup(struct network *network, struct scan_bss *bss,
						struct handshake_state *hs);

void network_sync_settings(struct network *network);

const struct network_info *network_get_info(const struct network *network);
void network_set_info(struct network *network, struct network_info *info);
void network_set_force_default_ecc_group(struct network *network);
bool network_get_force_default_ecc_group(struct network *network);

bool network_update_known_frequencies(struct network *network);

int network_can_connect_bss(struct network *network,
						const struct scan_bss *bss);
int network_autoconnect(struct network *network, struct scan_bss *bss);
void network_connect_failed(struct network *network, bool in_handshake);
void network_bss_start_update(struct network *network);
bool network_bss_add(struct network *network, struct scan_bss *bss);
bool network_bss_update(struct network *network, struct scan_bss *bss);
const char *network_bss_get_path(const struct network *network,
						const struct scan_bss *bss);
bool network_bss_list_isempty(struct network *network);

const char *__network_path_append_bss(const char *network_path,
					const struct scan_bss *bss);

struct scan_bss *network_bss_list_pop(struct network *network);
struct scan_bss *network_bss_find_by_addr(struct network *network,
							const uint8_t *addr);
struct scan_bss *network_bss_select(struct network *network,
					bool fallback_to_blacklist);

bool network_register(struct network *network, const char *path);

void network_remove(struct network *network, int reason);

int network_rank_compare(const void *a, const void *b, void *user);
void network_rank_update(struct network *network, bool connected);

struct l_dbus_message *network_connect_new_hidden_network(
						struct network *network,
						struct l_dbus_message *message);

void network_blacklist_add(struct network *network, struct scan_bss *bss);

struct erp_cache_entry *network_get_erp_cache(struct network *network);

const struct l_queue_entry *network_bss_list_get_entries(
						const struct network *network);

struct l_dbus_message *__network_connect(struct network *network,
						struct scan_bss *bss,
						struct l_dbus_message *message);
