/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
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

struct network_args {
	const char *name;
	const char *type;
};

const struct proxy_interface *network_get_proxy(const char *path);
bool network_is_connected(const struct proxy_interface *network_proxy);
const char *network_get_type(const struct proxy_interface *network_proxy);
const char *network_get_name(const struct proxy_interface *network_proxy);
void network_connect(const struct proxy_interface *network_proxy);

char *network_name_completion(const struct proxy_interface *device,
						const char *text, int state);

struct l_queue *network_match_by_device_and_args(
					const struct proxy_interface *device,
					const struct network_args *args);
struct l_queue *network_get_bss_list(
				const struct proxy_interface *network_proxy);
