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

struct mmpdu_header;

typedef void (*frame_watch_cb_t)(const struct mmpdu_header *frame,
					const void *body, size_t body_len,
					int rssi, void *user_data);
typedef bool (*frame_xchg_resp_cb_t)(const struct mmpdu_header *frame,
					const void *body, size_t body_len,
					int rssi, void *user_data);
typedef void (*frame_xchg_cb_t)(int err, void *user_data);
typedef void (*frame_xchg_destroy_func_t)(void *user_data);

struct frame_xchg_prefix {
	uint16_t frame_type;
	const uint8_t *data;
	size_t len;
};

bool frame_watch_add(uint64_t wdev_id, uint32_t group, uint16_t frame_type,
			const uint8_t *prefix, size_t prefix_len,
			frame_watch_cb_t handler, void *user_data,
			frame_xchg_destroy_func_t destroy);
bool frame_watch_group_remove(uint64_t wdev_id, uint32_t group);
bool frame_watch_wdev_remove(uint64_t wdev_id);

uint32_t frame_xchg_start(uint64_t wdev_id, struct iovec *frame, uint32_t freq,
			unsigned int retry_interval, unsigned int resp_timeout,
			unsigned int retries_on_ack, uint32_t group_id,
			frame_xchg_cb_t cb, void *user_data,
			frame_xchg_destroy_func_t destroy, ...);
uint32_t frame_xchg_startv(uint64_t wdev_id, struct iovec *frame, uint32_t freq,
			unsigned int retry_interval, unsigned int resp_timeout,
			unsigned int retries_on_ack, uint32_t group_id,
			frame_xchg_cb_t cb, void *user_data,
			frame_xchg_destroy_func_t destroy, va_list resp_args);
void frame_xchg_stop_wdev(uint64_t wdev_id);
void frame_xchg_cancel(uint32_t id);
