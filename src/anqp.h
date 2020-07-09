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

struct scan_bss;

enum anqp_result {
	ANQP_SUCCESS,
	ANQP_TIMEOUT,
	ANQP_FAILED,
};

typedef void (*anqp_destroy_func_t)(void *user_data);

typedef void (*anqp_response_func_t)(enum anqp_result result,
					const void *anqp, size_t len,
					void *user_data);

uint32_t anqp_request(uint64_t wdev_id, const uint8_t *addr,
			struct scan_bss *bss, const uint8_t *anqp, size_t len,
			anqp_response_func_t cb, void *user_data,
			anqp_destroy_func_t destroy);
void anqp_cancel(uint32_t id);
