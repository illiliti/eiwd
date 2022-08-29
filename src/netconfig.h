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

struct netdev;
struct netconfig;
struct ie_fils_ip_addr_request_info;
struct ie_fils_ip_addr_response_info;

enum netconfig_event {
	NETCONFIG_EVENT_CONNECTED,
};

typedef void (*netconfig_notify_func_t)(enum netconfig_event event,
							void *user_data);

struct netconfig {
	struct l_netconfig *nc;
	struct netdev *netdev;

	char *mdns;
	struct ie_fils_ip_addr_response_info *fils_override;
	bool enabled[2];
	bool static_config[2];
	bool gateway_overridden[2];
	bool dns_overridden[2];

	const struct l_settings *active_settings;

	netconfig_notify_func_t notify;
	void *user_data;

	struct resolve *resolve;

	void *commit_data;
};

/* 0 for AF_INET, 1 for AF_INET6 */
#define INDEX_FOR_AF(af)	((af) != AF_INET)

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
bool netconfig_use_fils_addr(struct netconfig *netconfig, int af);

struct netconfig *netconfig_new(uint32_t ifindex);
void netconfig_destroy(struct netconfig *netconfig);

bool netconfig_enabled(void);

void netconfig_commit_init(struct netconfig *netconfig);
void netconfig_commit_free(struct netconfig *netconfig, const char *reasonstr);
void netconfig_commit(struct netconfig *netconfig, uint8_t family,
			enum l_netconfig_event event);

void netconfig_dhcp_gateway_to_arp(struct netconfig *netconfig);
