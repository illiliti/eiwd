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

struct netconfig;
struct ie_fils_ip_addr_request_info;
struct ie_fils_ip_addr_response_info;

enum netconfig_event {
	NETCONFIG_EVENT_CONNECTED,
};

typedef void (*netconfig_notify_func_t)(enum netconfig_event event,
							void *user_data);

bool netconfig_load_settings(struct netconfig *netconfig,
				const struct l_settings *active_settings);
bool netconfig_configure(struct netconfig *netconfig,
				netconfig_notify_func_t notify,
				void *user_data);
bool netconfig_reconfigure(struct netconfig *netconfig, bool set_arp_gw);
bool netconfig_reset(struct netconfig *netconfig);
char *netconfig_get_dhcp_server_ipv4(struct netconfig *netconfig);
bool netconfig_get_fils_ip_req(struct netconfig *netconfig,
				struct ie_fils_ip_addr_request_info *info);
void netconfig_handle_fils_ip_resp(struct netconfig *netconfig,
			const struct ie_fils_ip_addr_response_info *info);

struct netconfig *netconfig_new(uint32_t ifindex);
void netconfig_destroy(struct netconfig *netconfig);

bool netconfig_enabled(void);
