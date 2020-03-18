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

struct wiphy;
struct scan_bss;
struct scan_freq_set;

enum wiphy_state_watch_event {
	WIPHY_STATE_WATCH_EVENT_POWERED,
	WIPHY_STATE_WATCH_EVENT_RFKILLED,
};

typedef void (*wiphy_state_watch_func_t)(struct wiphy *wiphy,
					enum wiphy_state_watch_event event,
					void *user_data);
typedef void (*wiphy_destroy_func_t)(void *user_data);

enum ie_rsn_cipher_suite wiphy_select_cipher(struct wiphy *wiphy,
							uint16_t mask);
enum ie_rsn_akm_suite wiphy_select_akm(struct wiphy *wiphy,
					struct scan_bss *bss,
					bool fils_capable_hint);

struct wiphy *wiphy_find(int wiphy_id);
bool wiphy_is_blacklisted(const struct wiphy *wiphy);

struct wiphy *wiphy_create(uint32_t wiphy_id, const char *name);
void wiphy_update_name(struct wiphy *wiphy, const char *name);
void wiphy_create_complete(struct wiphy *wiphy);
bool wiphy_destroy(struct wiphy *wiphy);
void wiphy_update_from_genl(struct wiphy *wiphy, struct l_genl_msg *msg);

bool wiphy_constrain_freq_set(const struct wiphy *wiphy,
						struct scan_freq_set *set);

uint32_t wiphy_get_id(struct wiphy *wiphy);
const char *wiphy_get_path(struct wiphy *wiphy);
uint32_t wiphy_get_supported_bands(struct wiphy *wiphy);
const struct scan_freq_set *wiphy_get_supported_freqs(
						const struct wiphy *wiphy);
bool wiphy_can_connect(struct wiphy *wiphy, struct scan_bss *bss);
bool wiphy_can_randomize_mac_addr(struct wiphy *wiphy);
bool wiphy_rrm_capable(struct wiphy *wiphy);
bool wiphy_has_feature(struct wiphy *wiphy, uint32_t feature);
bool wiphy_has_ext_feature(struct wiphy *wiphy, uint32_t feature);
uint8_t wiphy_get_max_num_ssids_per_scan(struct wiphy *wiphy);
uint16_t wiphy_get_max_scan_ie_len(struct wiphy *wiphy);
uint32_t wiphy_get_max_roc_duration(struct wiphy *wiphy);
bool wiphy_supports_iftype(struct wiphy *wiphy, uint32_t iftype);
const uint8_t *wiphy_get_supported_rates(struct wiphy *wiphy, unsigned int band,
						unsigned int *out_num);
bool wiphy_supports_adhoc_rsn(struct wiphy *wiphy);
bool wiphy_can_offchannel_tx(struct wiphy *wiphy);
bool wiphy_supports_qos_set_map(struct wiphy *wiphy);
const char *wiphy_get_driver(struct wiphy *wiphy);
const char *wiphy_get_name(struct wiphy *wiphy);
const uint8_t *wiphy_get_permanent_address(struct wiphy *wiphy);
const uint8_t *wiphy_get_extended_capabilities(struct wiphy *wiphy,
							uint32_t iftype);
const uint8_t *wiphy_get_rm_enabled_capabilities(struct wiphy *wiphy);

void wiphy_generate_random_address(struct wiphy *wiphy, uint8_t addr[static 6]);
void wiphy_generate_address_from_ssid(struct wiphy *wiphy, const char *ssid,
					uint8_t addr[static 6]);

uint32_t wiphy_state_watch_add(struct wiphy *wiphy,
				wiphy_state_watch_func_t func, void *user_data,
				wiphy_destroy_func_t destroy);
bool wiphy_state_watch_remove(struct wiphy *wiphy, uint32_t id);
