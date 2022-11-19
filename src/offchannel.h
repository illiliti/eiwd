/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
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

typedef void (*offchannel_started_cb_t)(void *user_data);
typedef void (*offchannel_destroy_cb_t)(int error, void *user_data);

uint32_t offchannel_start(uint64_t wdev_id, int priority, uint32_t freq,
			uint32_t duration, offchannel_started_cb_t started,
			void *user_data, offchannel_destroy_cb_t destroy);
void offchannel_cancel(uint64_t wdev_id, uint32_t id);
