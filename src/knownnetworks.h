/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016-2019  Intel Corporation. All rights reserved.
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

#define SETTINGS "Settings"
#define NET_HIDDEN SETTINGS, "Hidden"
#define NET_AUTOCONNECT SETTINGS, "AutoConnect"
#define NET_ALWAYS_RANDOMIZE_ADDRESS SETTINGS, "AlwaysRandomizeAddress"
#define NET_ADDRESS_OVERRIDE SETTINGS, "AddressOverride"
#define NET_TRANSITION_DISABLE SETTINGS, "TransitionDisable"
#define NET_TRANSITION_DISABLE_MODES SETTINGS, "DisabledTransitionModes"
#define NET_USE_DEFAULT_ECC_GROUP SETTINGS, "UseDefaultEccGroup"

enum security;
struct scan_freq_set;
struct network_info;

enum known_networks_event {
	KNOWN_NETWORKS_EVENT_ADDED,
	KNOWN_NETWORKS_EVENT_REMOVED,
	KNOWN_NETWORKS_EVENT_UPDATED,
};

enum known_network_ecc_group {
	KNOWN_NETWORK_ECC_GROUP_AUTO = 0,
	KNOWN_NETWORK_ECC_GROUP_DEFAULT,
	KNOWN_NETWORK_ECC_GROUP_MOST_SECURE,
};

struct network_info_ops {
	struct l_settings *(*open)(struct network_info *info);
	int (*touch)(struct network_info *info);
	void (*sync)(struct network_info *info, struct l_settings *settings);
	void (*remove)(struct network_info *info);
	void (*free)(struct network_info *info);
	const char *(*get_path)(const struct network_info *info);
	const char *(*get_name)(const struct network_info *info);
	const char *(*get_type)(const struct network_info *info);
	const struct iovec *(*get_extra_ies)(const struct network_info *info,
						struct scan_bss *bss,
						size_t *num_elems);
	char *(*get_file_path)(const struct network_info *info);

	bool (*match_hessid)(const struct network_info *info,
						const uint8_t *hessid);
	const uint8_t *(*match_roaming_consortium)(
						const struct network_info *info,
						const uint8_t *rc_ie,
						size_t rc_len,
						size_t *rc_len_out);
	bool (*match_nai_realms)(const struct network_info *info,
						const char **nai_realms);
};

struct network_config {
	uint64_t connected_time;	/* Time last connected */
	bool is_hidden:1;
	bool is_autoconnectable:1;
	bool override_addr:1;
	bool always_random_addr:1;
	uint8_t sta_addr[6];
	bool have_transition_disable : 1;
	uint8_t transition_disable;
	enum known_network_ecc_group ecc_group;
};

struct network_info {
	const struct network_info_ops *ops;
	char ssid[SSID_MAX_SIZE + 1];
	enum security type;
	struct l_queue *known_frequencies;
	int seen_count;			/* Ref count for network.info */
	uint8_t uuid[16];
	bool is_hotspot:1;
	bool has_uuid:1;
	struct network_config config;
};

typedef bool (*known_networks_foreach_func_t)(const struct network_info *info,
						void *user_data);

typedef void (*known_networks_watch_func_t)(enum known_networks_event event,
						const struct network_info *info,
						void *user_data);
typedef void (*known_networks_destroy_func_t)(void *user_data);

struct known_frequency {
	uint32_t frequency;
};

void __network_config_parse(const struct l_settings *settings,
					const char *path,
					struct network_config *config);
void __network_info_init(struct network_info *info,
				const char *ssid, enum security security,
				struct network_config *config);

int known_network_offset(const struct network_info *target);
bool known_networks_foreach(known_networks_foreach_func_t function,
				void *user_data);
bool known_networks_has_hidden(void);
struct network_info *known_networks_find(const char *ssid,
						enum security security);

struct scan_freq_set *known_networks_get_recent_frequencies(
						uint8_t num_networks_tosearch,
						uint8_t freqs_per_network);
int known_network_add_frequency(struct network_info *info,
				uint32_t frequency);
void known_network_frequency_sync(struct network_info *info);

uint32_t known_networks_watch_add(known_networks_watch_func_t func,
					void *user_data,
					known_networks_destroy_func_t destroy);
void known_networks_watch_remove(uint32_t id);

struct l_settings *network_info_open_settings(struct network_info *info);
int network_info_touch(struct network_info *info);
const char *network_info_get_path(const struct network_info *info);
const char *network_info_get_name(const struct network_info *info);
const char *network_info_get_type(const struct network_info *info);
const struct iovec *network_info_get_extra_ies(const struct network_info *info,
						struct scan_bss *bss,
						size_t *num_elems);
/* Gets the UUID, or generates one if not yet created */
const uint8_t *network_info_get_uuid(struct network_info *info);
void network_info_set_uuid(struct network_info *info, const uint8_t *uuid);
struct scan_freq_set *network_info_get_roam_frequencies(
					const struct network_info *info,
					uint32_t current_freq,
					uint8_t max);

bool network_info_match_hessid(const struct network_info *info,
				const uint8_t *hessid);
const uint8_t *network_info_match_roaming_consortium(
						const struct network_info *info,
						const uint8_t *rc,
						size_t rc_len,
						size_t *rc_len_out);
bool network_info_match_nai_realm(const struct network_info *info,
						const char **nai_realms);

void known_networks_add(struct network_info *info);
void known_network_update(struct network_info *info,
					struct network_config *new_config);
void known_network_set_connected_time(struct network_info *network,
					uint64_t connected_time);
void known_networks_remove(struct network_info *info);
