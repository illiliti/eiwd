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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ell/ell.h>

#include "src/util.h"
#include "src/iwd.h"
#include "src/module.h"
#include "src/netdev.h"
#include "src/ip-pool.h"

struct ip_pool_addr4_record {
	uint32_t ifindex;
	struct l_rtnl_address *addr;
};

static struct l_queue *used_addr4_list;
static struct l_netlink *rtnl;

static void ip_pool_addr4_record_free(void *data)
{
	struct ip_pool_addr4_record *rec = data;

	l_rtnl_address_free(rec->addr);
	l_free(rec);
}

static bool ip_pool_addr4_match_ifindex(const void *a, const void *b)
{
	const struct ip_pool_addr4_record *addr = a;

	return addr->ifindex == L_PTR_TO_UINT(b);
}

struct l_rtnl_address *ip_pool_get_addr4(uint32_t ifindex)
{
	const struct ip_pool_addr4_record *rec =
		l_queue_find(used_addr4_list, ip_pool_addr4_match_ifindex,
				L_UINT_TO_PTR(ifindex));

	return rec ? l_rtnl_address_clone(rec->addr) : 0;
}

static bool ip_pool_addr4_match_free(void *data, void *user_data)
{
	const struct ip_pool_addr4_record *a = data;
	const struct ip_pool_addr4_record *b = user_data;
	char a_addr_str[INET_ADDRSTRLEN];
	char b_addr_str[INET_ADDRSTRLEN];

	if (a->ifindex != b->ifindex ||
			l_rtnl_address_get_prefix_length(a->addr) !=
			l_rtnl_address_get_prefix_length(b->addr))
		return false;

	if (!l_rtnl_address_get_address(a->addr, a_addr_str) ||
			!l_rtnl_address_get_address(b->addr, b_addr_str) ||
			strcmp(a_addr_str, b_addr_str))
		return false;

	ip_pool_addr4_record_free(data);
	return true;
}

static void ip_pool_addr_notify(uint16_t type, const void *data, uint32_t len,
				void *user_data)
{
	const struct ifaddrmsg *ifa = data;
	struct l_rtnl_address *addr;

	if (ifa->ifa_family != AF_INET || ifa->ifa_prefixlen < 1)
		return;

	len -= NLMSG_ALIGN(sizeof(struct ifaddrmsg));

	addr = l_rtnl_ifaddr_extract(ifa, len);
	if (!addr)
		return;

	if (type == RTM_NEWADDR) {
		struct ip_pool_addr4_record *rec;

		rec = l_new(struct ip_pool_addr4_record, 1);
		rec->ifindex = ifa->ifa_index;
		rec->addr = l_steal_ptr(addr);
		l_queue_push_tail(used_addr4_list, rec);
	} else if (type == RTM_DELADDR) {
		struct ip_pool_addr4_record rec;

		rec.ifindex = ifa->ifa_index;
		rec.addr = addr;

		l_queue_foreach_remove(used_addr4_list,
					ip_pool_addr4_match_free, &rec);
	}

	l_rtnl_address_free(addr);
}

static void ip_pool_addr4_dump_cb(int error,
					uint16_t type, const void *data,
					uint32_t len, void *user_data)
{
	if (error) {
		l_error("addr4_dump_cb: %s (%i)", strerror(-error), -error);
		return;
	}

	ip_pool_addr_notify(type, data, len, user_data);
}

static int ip_pool_init(void)
{
	const struct l_settings *settings = iwd_get_config();
	bool netconfig_enabled;

	if (!l_settings_get_bool(settings, "General",
				"EnableNetworkConfiguration",
				&netconfig_enabled))
		netconfig_enabled = false;

	if (!netconfig_enabled)
		return 0;

	rtnl = iwd_get_rtnl();

	if (!l_netlink_register(rtnl, RTNLGRP_IPV4_IFADDR,
				ip_pool_addr_notify, NULL, NULL)) {
		l_error("Failed to register for RTNL link notifications");
		return -EIO;
	}

	if (!l_rtnl_ifaddr4_dump(rtnl, ip_pool_addr4_dump_cb, NULL, NULL)) {
		l_error("Sending the IPv4 addr dump req failed");
		return -EIO;
	}

	used_addr4_list = l_queue_new();
	return 0;
}

static void ip_pool_exit(void)
{
	l_queue_destroy(used_addr4_list, ip_pool_addr4_record_free);
	used_addr4_list = NULL;
}

IWD_MODULE(ip_pool, ip_pool_init, ip_pool_exit)
