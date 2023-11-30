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

struct netdev;
struct scan_bss;
struct handshake_state;
struct eapol_sm;
struct mmpdu_header;
struct diagnostic_station_info;

enum netdev_result {
	NETDEV_RESULT_OK,
	NETDEV_RESULT_AUTHENTICATION_FAILED,
	NETDEV_RESULT_ASSOCIATION_FAILED,
	NETDEV_RESULT_HANDSHAKE_FAILED,
	NETDEV_RESULT_KEY_SETTING_FAILED,
	NETDEV_RESULT_ABORTED,
};

enum netdev_event {
	NETDEV_EVENT_AUTHENTICATING,
	NETDEV_EVENT_ASSOCIATING,
	NETDEV_EVENT_ROAMING,
	NETDEV_EVENT_ROAMED,
	NETDEV_EVENT_CHANNEL_SWITCHED,
	NETDEV_EVENT_DISCONNECT_BY_AP,
	NETDEV_EVENT_DISCONNECT_BY_SME,
	NETDEV_EVENT_RSSI_THRESHOLD_LOW,
	NETDEV_EVENT_RSSI_THRESHOLD_HIGH,
	NETDEV_EVENT_RSSI_LEVEL_NOTIFY,
	NETDEV_EVENT_PACKET_LOSS_NOTIFY,
	NETDEV_EVENT_FT_ROAMED,
	NETDEV_EVENT_BEACON_LOSS_NOTIFY,
};

enum netdev_watch_event {
	NETDEV_WATCH_EVENT_NEW,
	NETDEV_WATCH_EVENT_DEL,
	NETDEV_WATCH_EVENT_UP,
	NETDEV_WATCH_EVENT_DOWN,
	NETDEV_WATCH_EVENT_NAME_CHANGE,
	NETDEV_WATCH_EVENT_ADDRESS_CHANGE,
	NETDEV_WATCH_EVENT_IFTYPE_CHANGE,
};

/* Mirror definitions from nl80211.h to make conversions simpler */
enum netdev_iftype {
	NETDEV_IFTYPE_ADHOC = 1,
	NETDEV_IFTYPE_STATION = 2,
	NETDEV_IFTYPE_AP = 3,
	NETDEV_IFTYPE_P2P_CLIENT = 8,
	NETDEV_IFTYPE_P2P_GO = 9,
};

typedef void (*netdev_command_cb_t)(struct netdev *netdev, int result,
						void *user_data);
/*
 * Callback for a connection attempt. This callback is called on both success
 * and failure. Depending on result, the event_data will have different
 * meanings:
 *
 * NETDEV_RESULT_OK - unused
 * NETDEV_RESULT_AUTHENTICATION_FAILED - MMPDU_STATUS_CODE
 * NETDEV_RESULT_ASSOCIATION_FAILED - MMPDU_STATUS_CODE
 * NETDEV_RESULT_HANDSHAKE_FAILED - MMPDU_REASON_CODE
 * NETDEV_RESULT_KEY_SETTING_FAILED - unused
 * NETDEV_RESULT_ABORTED - unused.
 */
typedef void (*netdev_connect_cb_t)(struct netdev *netdev,
					enum netdev_result result,
					void *event_data,
					void *user_data);
/*
 * Notify function for netdev events. Depending on the event type, event_data
 * will have different meanings:
 *
 * NETDEV_EVENT_AUTHENTICATING - unused
 * NETDEV_EVENT_ASSOCIATING - unused
 * NETDEV_EVENT_DISCONNECT_BY_AP - MMPDU_REASON_CODE
 * NETDEV_EVENT_DISCONNECT_BY_SME - MMPDU_REASON_CODE
 * NETDEV_EVENT_RSSI_THRESHOLD_LOW - unused
 * NETDEV_EVENT_RSSI_THRESHOLD_HIGH - unused
 * NETDEV_EVENT_RSSI_LEVEL_NOTIFY - rssi level index (uint8_t)
 */
typedef void (*netdev_event_func_t)(struct netdev *netdev,
					enum netdev_event event,
					void *event_data,
					void *user_data);
typedef void (*netdev_disconnect_cb_t)(struct netdev *netdev, bool result,
					void *user_data);
typedef void (*netdev_watch_func_t)(struct netdev *netdev,
					enum netdev_watch_event event,
					void *user_data);
typedef void (*netdev_destroy_func_t)(void *user_data);
typedef void (*netdev_neighbor_report_cb_t)(struct netdev *netdev, int err,
					const uint8_t *reports,
					size_t reports_len, void *user_data);
typedef void (*netdev_preauthenticate_cb_t)(struct netdev *netdev,
					enum netdev_result result,
					const uint8_t *pmk, void *user_data);
typedef void (*netdev_station_watch_func_t)(struct netdev *netdev,
					const uint8_t *mac, bool added,
					void *user_data);

typedef void (*netdev_get_station_cb_t)(
				const struct diagnostic_station_info *info,
				void *user_data);

const char *netdev_iftype_to_string(uint32_t iftype);

typedef void (*netdev_ft_over_ds_cb_t)(struct netdev *netdev,
					uint16_t status, const uint8_t *bssid,
					void *user_data);

struct wiphy *netdev_get_wiphy(struct netdev *netdev);
const uint8_t *netdev_get_address(struct netdev *netdev);
uint32_t netdev_get_ifindex(struct netdev *netdev);
uint64_t netdev_get_wdev_id(struct netdev *netdev);
enum netdev_iftype netdev_get_iftype(struct netdev *netdev);
int netdev_set_iftype(struct netdev *netdev, enum netdev_iftype type,
			netdev_command_cb_t cb, void *user_data,
			netdev_destroy_func_t destroy);
int netdev_set_4addr(struct netdev *netdev, bool use_4addr,
			netdev_command_cb_t cb, void *user_data,
			netdev_destroy_func_t destroy);
bool netdev_get_4addr(struct netdev *netdev);
const char *netdev_get_name(struct netdev *netdev);
bool netdev_get_is_up(struct netdev *netdev);
const char *netdev_get_path(struct netdev *netdev);
uint8_t netdev_get_rssi_level_idx(struct netdev *netdev);

struct handshake_state *netdev_handshake_state_new(struct netdev *netdev);
struct handshake_state *netdev_get_handshake(struct netdev *netdev);

int netdev_connect(struct netdev *netdev, const struct scan_bss *bss,
				struct handshake_state *hs,
				netdev_event_func_t event_filter,
				netdev_connect_cb_t cb, void *user_data);
int netdev_disconnect(struct netdev *netdev,
				netdev_disconnect_cb_t cb, void *user_data);
int netdev_reassociate(struct netdev *netdev,
			const struct scan_bss *target_bss,
			const struct scan_bss *orig_bss,
			struct handshake_state *hs,
			netdev_event_func_t event_filter,
			netdev_connect_cb_t cb, void *user_data);

int netdev_preauthenticate(struct netdev *netdev,
				const struct scan_bss *target_bss,
				netdev_preauthenticate_cb_t cb,
				void *user_data);

int netdev_del_station(struct netdev *netdev, const uint8_t *sta,
		uint16_t reason_code, bool disassociate);

int netdev_join_adhoc(struct netdev *netdev, const char *ssid,
			struct iovec *extra_ie, size_t extra_ie_elems,
			bool control_port, netdev_command_cb_t cb,
			void *user_data);
int netdev_leave_adhoc(struct netdev *netdev, netdev_command_cb_t cb,
			void *user_data);

int netdev_set_powered(struct netdev *netdev, bool powered,
				netdev_command_cb_t cb, void *user_data,
				netdev_destroy_func_t destroy);

int netdev_neighbor_report_req(struct netdev *netdev,
				netdev_neighbor_report_cb_t cb);

int netdev_set_rssi_report_levels(struct netdev *netdev, const int8_t *levels,
					size_t levels_num);

int netdev_get_station(struct netdev *netdev, const uint8_t *mac,
			netdev_get_station_cb_t cb, void *user_data,
			netdev_destroy_func_t destroy);
int netdev_get_current_station(struct netdev *netdev,
			netdev_get_station_cb_t cb, void *user_data,
			netdev_destroy_func_t destroy);
int netdev_get_all_stations(struct netdev *netdev, netdev_get_station_cb_t cb,
				void *user_data, netdev_destroy_func_t destroy);

void netdev_handshake_failed(struct handshake_state *hs, uint16_t reason_code);

struct netdev *netdev_find(int ifindex);

uint32_t netdev_watch_add(netdev_watch_func_t func,
				void *user_data, netdev_destroy_func_t destroy);
bool netdev_watch_remove(uint32_t id);

uint32_t netdev_station_watch_add(struct netdev *netdev,
		netdev_station_watch_func_t func, void *user_data);

bool netdev_station_watch_remove(struct netdev *netdev, uint32_t id);

struct netdev *netdev_create_from_genl(struct l_genl_msg *msg,
					const uint8_t *set_mac);
bool netdev_destroy(struct netdev *netdev);
