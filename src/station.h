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

#include <stdbool.h>

struct wiphy;
struct netdev;
struct station;
enum security;
struct scan_bss;
struct scan_freq_set;
struct network;

enum station_state {
	/* Disconnected, no auto-connect */
	STATION_STATE_DISCONNECTED,
	/* Disconnected, try auto-connect with quick scan */
	STATION_STATE_AUTOCONNECT_QUICK,
	/* Disconnected, try auto-connect with full scan */
	STATION_STATE_AUTOCONNECT_FULL,
	/* Connecting */
	STATION_STATE_CONNECTING,
	STATION_STATE_CONNECTING_AUTO,
	STATION_STATE_CONNECTED,
	STATION_STATE_DISCONNECTING,
	STATION_STATE_ROAMING,		/* Reassociation */
	STATION_STATE_FT_ROAMING,	/* Fast transition */
	STATION_STATE_FW_ROAMING,	/* Firmware roamed by itself */
};

enum station_event {
	STATION_EVENT_ANQP_STARTED,
	STATION_EVENT_ANQP_FINISHED,
	STATION_EVENT_OWE_HIDDEN_STARTED,
	STATION_EVENT_OWE_HIDDEN_FINISHED,
};

typedef void (*station_foreach_func_t)(struct station *, void *data);
typedef void (*station_state_watch_func_t)(enum station_state, void *userdata);
typedef void (*station_event_watch_func_t)(enum station_event,
						struct network *network,
						void *user_data);
typedef void (*station_destroy_func_t)(void *userdata);
typedef void (*station_network_foreach_func_t)(struct network *, void *data);

struct wiphy *station_get_wiphy(struct station *station);
struct netdev *station_get_netdev(struct station *station);
struct network *station_get_connected_network(struct station *station);
bool station_is_busy(struct station *station);

struct network *station_network_find(struct station *station, const char *ssid,
					enum security security);

void station_set_scan_results(struct station *station, struct l_queue *bss_list,
				const struct scan_freq_set *freqs,
				bool add_to_autoconnect);

enum station_state station_get_state(struct station *station);
uint32_t station_add_state_watch(struct station *station,
					station_state_watch_func_t func,
					void *user_data,
					station_destroy_func_t destroy);
bool station_remove_state_watch(struct station *station, uint32_t id);

uint32_t station_add_event_watch(station_event_watch_func_t func,
				void *user_data,
				station_destroy_func_t destroy);
void station_remove_event_watch(uint32_t id);

bool station_set_autoconnect(struct station *station, bool autoconnect);

int __station_connect_network(struct station *station, struct network *network,
				struct scan_bss *bss);
void station_connect_network(struct station *station, struct network *network,
				struct scan_bss *bss,
				struct l_dbus_message *message);
int station_disconnect(struct station *station);

struct station *station_find(uint32_t ifindex);
void station_foreach(station_foreach_func_t func, void *user_data);

void station_network_foreach(struct station *station,
				station_network_foreach_func_t func,
				void *user_data);
struct l_queue *station_get_bss_list(struct station *station);
struct scan_bss *station_get_connected_bss(struct station *station);

int station_hide_network(struct station *station, struct network *network);
