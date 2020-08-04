/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
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

struct ap_state;
struct iovec;

enum ap_event_type {
	AP_EVENT_START_FAILED,
	AP_EVENT_STARTED,
	AP_EVENT_STOPPING,
	AP_EVENT_STATION_ADDED,
	AP_EVENT_STATION_REMOVED,
};

struct ap_event_station_added_data {
	const uint8_t *mac;
	const uint8_t *rsn_ie;
};

struct ap_event_station_removed_data {
	const uint8_t *mac;
	enum mmpdu_reason_code reason;
};

typedef void (*ap_event_func_t)(enum ap_event_type type, const void *event_data,
				void *user_data);
typedef void (*ap_stopped_func_t)(void *user_data);

struct ap_state *ap_start(struct netdev *netdev, const char *ssid,
				const char *psk, int channel,
				ap_event_func_t event_func, void *user_data);
void ap_shutdown(struct ap_state *ap, ap_stopped_func_t stopped_func,
			void *user_data);
void ap_free(struct ap_state *ap);

bool ap_station_disconnect(struct ap_state *ap, const uint8_t *mac,
				enum mmpdu_reason_code reason);
