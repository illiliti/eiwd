/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
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

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/icmpv6.h>

#include <ell/ell.h>

#include "ell/useful.h"
#include "src/iwd.h"
#include "src/common.h"
#include "src/util.h"
#include "src/netdev.h"
#include "src/ie.h"
#include "src/resolve.h"
#include "src/netconfig.h"

struct netconfig_commit_ops {
	bool (*init_data)(struct netconfig *netconfig);
	void (*free_data)(struct netconfig *netconfig, const char *reasonstr);
	void (*commit)(struct netconfig *netconfig, uint8_t family,
			enum l_netconfig_event event);
};

static struct l_netlink *rtnl;

static void netconfig_rtnl_commit(struct netconfig *netconfig, uint8_t family,
					enum l_netconfig_event event);

/* Default backend */
static struct netconfig_commit_ops netconfig_rtnl_ops = {
	.commit = netconfig_rtnl_commit,
};

/* Same backend for all netconfig objects */
static const struct netconfig_commit_ops *commit_ops = &netconfig_rtnl_ops;

static struct l_queue *netconfig_list;

void netconfig_commit_init(struct netconfig *netconfig)
{
	if (!rtnl)
		rtnl = l_rtnl_get();

	if (!netconfig_list)
		netconfig_list = l_queue_new();

	l_queue_push_tail(netconfig_list, netconfig);

	L_WARN_ON(netconfig->commit_data);

	if (commit_ops->init_data)
		commit_ops->init_data(netconfig);
}

void netconfig_commit_free(struct netconfig *netconfig, const char *reasonstr)
{
	if (commit_ops->free_data)
		commit_ops->free_data(netconfig, reasonstr);

	L_WARN_ON(!l_queue_remove(netconfig_list, netconfig));

	if (l_queue_isempty(netconfig_list))
		l_queue_destroy(l_steal_ptr(netconfig_list), NULL);
}

void netconfig_commit(struct netconfig *netconfig, uint8_t family,
			enum l_netconfig_event event)
{
	commit_ops->commit(netconfig, family, event);

	if (event == L_NETCONFIG_EVENT_CONFIGURE) {
		/*
		 * Done here instead of in ops->commit because the MACs are
		 * not considered part of the network configuration
		 * (particularly Network Manager's "level 3 config" or l3cfg)
		 * so we can handle this ourselves independent of the backend.
		 */
		if (family == AF_INET &&
				!netconfig->static_config[INDEX_FOR_AF(family)])
			netconfig_dhcp_gateway_to_arp(netconfig);
	}
}

/*
 * Called by all backends when netconfig_commit finishes, synchronously or
 * asynchronously.
 */
static void netconfig_commit_done(struct netconfig *netconfig, uint8_t family,
					enum l_netconfig_event event,
					bool success)
{
	bool connected = netconfig->connected[INDEX_FOR_AF(family)];

	if (!success) {
		netconfig->connected[INDEX_FOR_AF(family)] = false;

		if (netconfig->notify && family == AF_INET)
			netconfig->notify(NETCONFIG_EVENT_FAILED,
						netconfig->user_data);
		return;
	}

	switch (event) {
	case L_NETCONFIG_EVENT_CONFIGURE:
	case L_NETCONFIG_EVENT_UPDATE:
		netconfig->connected[INDEX_FOR_AF(family)] = true;

		if (family == AF_INET && !connected && netconfig->notify)
			netconfig->notify(NETCONFIG_EVENT_CONNECTED,
						netconfig->user_data);

		break;

	case L_NETCONFIG_EVENT_UNCONFIGURE:
	case L_NETCONFIG_EVENT_FAILED:
		break;
	}
}

static void netconfig_set_neighbor_entry_cb(int error,
						uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	if (error)
		l_error("l_rtnl_neighbor_set_hwaddr failed: %s (%i)",
			strerror(-error), error);
}

void netconfig_dhcp_gateway_to_arp(struct netconfig *netconfig)
{
	struct l_dhcp_client *dhcp = l_netconfig_get_dhcp_client(netconfig->nc);
	const struct l_dhcp_lease *lease;
	_auto_(l_free) char *server_id = NULL;
	_auto_(l_free) char *gw = NULL;
	const uint8_t *server_mac;
	struct in_addr in_gw;
	uint32_t ifindex = netdev_get_ifindex(netconfig->netdev);

	/* Can only do this for DHCP in certain network setups */
	if (netconfig->static_config[INDEX_FOR_AF(AF_INET)] ||
			netconfig->fils_override)
		return;

	lease = l_dhcp_client_get_lease(dhcp);
	if (!lease)
		return;

	server_id = l_dhcp_lease_get_server_id(lease);
	gw = l_dhcp_lease_get_gateway(lease);
	server_mac = l_dhcp_lease_get_server_mac(lease);

	if (!gw || strcmp(server_id, gw) || !server_mac)
		return;

	l_debug("Gateway MAC is known, setting into ARP cache");
	in_gw.s_addr = l_dhcp_lease_get_gateway_u32(lease);

	if (!l_rtnl_neighbor_set_hwaddr(rtnl, ifindex, AF_INET,
					&in_gw, server_mac, ETH_ALEN,
					netconfig_set_neighbor_entry_cb, NULL,
					NULL))
		l_debug("l_rtnl_neighbor_set_hwaddr failed");
}

static void netconfig_dns_list_update(struct netconfig *netconfig)
{
	_auto_(l_strv_free) char **dns_list =
		l_netconfig_get_dns_list(netconfig->nc);

	if (netconfig->resolve && dns_list)
		resolve_set_dns(netconfig->resolve, dns_list);
}

static void netconfig_domains_update(struct netconfig *netconfig)
{
	_auto_(l_strv_free) char **domains =
		l_netconfig_get_domain_names(netconfig->nc);

	if (netconfig->resolve && domains)
		resolve_set_domains(netconfig->resolve, domains);
}

static void netconfig_rtnl_commit(struct netconfig *netconfig, uint8_t family,
					enum l_netconfig_event event)
{
	l_netconfig_apply_rtnl(netconfig->nc);

	/* TODO: cache values and skip updates if unchanged */
	netconfig_dns_list_update(netconfig);
	netconfig_domains_update(netconfig);

	if (event == L_NETCONFIG_EVENT_CONFIGURE && family == AF_INET)
		/*
		 * netconfig->mdns is currently only loaded in
		 * netconfig_load_settings() so we can set it once on
		 * the CONFIGURE event.
		 */
		resolve_set_mdns(netconfig->resolve, netconfig->mdns);

	if (event == L_NETCONFIG_EVENT_UNCONFIGURE && family == AF_INET)
		resolve_revert(netconfig->resolve);

	netconfig_commit_done(netconfig, family, event, true);
}
