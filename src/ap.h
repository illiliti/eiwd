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
enum mpdu_management_subtype;

enum ap_event_type {
	AP_EVENT_START_FAILED,
	AP_EVENT_STARTED,
	AP_EVENT_STOPPING,
	AP_EVENT_STATION_ADDED,
	AP_EVENT_STATION_REMOVED,
	AP_EVENT_REGISTRATION_START,
	AP_EVENT_REGISTRATION_SUCCESS,
	AP_EVENT_PBC_MODE_EXIT,
};

struct ap_event_station_added_data {
	const uint8_t *mac;
	const uint8_t *assoc_ies;
	size_t assoc_ies_len;
};

struct ap_event_station_removed_data {
	const uint8_t *mac;
	enum mmpdu_reason_code reason;
};

struct ap_event_registration_start_data {
	const uint8_t *mac;
	const uint8_t *assoc_ies;
	size_t assoc_ies_len;
};

struct ap_event_registration_success_data {
	const uint8_t *mac;
};

typedef void (*ap_stopped_func_t)(void *user_data);

struct ap_ops {
	void (*handle_event)(enum ap_event_type type, const void *event_data,
				void *user_data);
	/*
	 * If .write_extra_ies is provided, this callback must return an upper
	 * bound on the buffer space needed for the extra IEs to be sent in
	 * the frame of given type and, if it's not a beacon frame, in
	 * response to a given client frame.
	 */
	size_t (*get_extra_ies_len)(enum mpdu_management_subtype type,
					const struct mmpdu_header *client_frame,
					size_t client_frame_len,
					void *user_data);
	/*
	 * If not null, writes extra IEs to be added to the outgoing frame of
	 * given type and, if it's not a beacon frame, in reponse to a given
	 * client frame.  May also react to the extra IEs in that frame.
	 * Returns the number of bytes written which must be less than or
	 * equal to the number returned by .get_extra_ies_len when called
	 * with the same parameters.
	 */
	size_t (*write_extra_ies)(enum mpdu_management_subtype type,
					const struct mmpdu_header *client_frame,
					size_t client_frame_len,
					uint8_t *out_buf, void *user_data);
};

struct ap_state *ap_start(struct netdev *netdev, struct l_settings *config,
				const struct ap_ops *ops, int *err,
				void *user_data);
void ap_shutdown(struct ap_state *ap, ap_stopped_func_t stopped_func,
			void *user_data);
void ap_free(struct ap_state *ap);

bool ap_station_disconnect(struct ap_state *ap, const uint8_t *mac,
				enum mmpdu_reason_code reason);

bool ap_push_button(struct ap_state *ap);
void ap_update_beacon(struct ap_state *ap);
