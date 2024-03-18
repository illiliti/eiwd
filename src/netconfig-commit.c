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
#include "src/dbus.h"
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
static void netconfig_rtnl_free_data(struct netconfig *netconfig,
					const char *reasonstr);

/* Default backend */
static struct netconfig_commit_ops netconfig_rtnl_ops = {
	.commit    = netconfig_rtnl_commit,
	.free_data = netconfig_rtnl_free_data,
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

static void netconfig_commit_print_addrs(const char *verb,
					const struct l_queue_entry *addrs)
{
	for (; addrs; addrs = addrs->next) {
		const struct l_rtnl_address *addr = addrs->data;
		char str[INET6_ADDRSTRLEN];

		if (l_rtnl_address_get_address(addr, str))
			l_debug("%s address: %s", verb, str);
	}
}

void netconfig_commit(struct netconfig *netconfig, uint8_t family,
			enum l_netconfig_event event)
{
	const struct l_queue_entry *added;
	const struct l_queue_entry *removed;
	const struct l_queue_entry *expired;

	l_netconfig_get_addresses(netconfig->nc, &added, NULL,
						&removed, &expired);

	/* Only print IP additions and removals to avoid cluttering the log */
	netconfig_commit_print_addrs("installing", added);
	netconfig_commit_print_addrs("removing", removed);
	netconfig_commit_print_addrs("expired", expired);

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

		if (!netconfig->connected[INDEX_FOR_AF(family)] &&
				netconfig_use_fils_addr(netconfig, family))
			netconfig_commit_fils_macs(netconfig, family);
	}
}

static void netconfig_switch_backend(const struct netconfig_commit_ops *new_ops)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(netconfig_list); entry;
			entry = entry->next) {
		struct netconfig *netconfig = entry->data;

		if (commit_ops->free_data)
			commit_ops->free_data(netconfig, "");

		if (new_ops->init_data)
			new_ops->init_data(netconfig);
	}

	commit_ops = new_ops;
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

void netconfig_commit_fils_macs(struct netconfig *netconfig, uint8_t family)
{
	const struct ie_fils_ip_addr_response_info *fils =
		netconfig->fils_override;
	const void *addr;
	const void *hwaddr;
	size_t addr_len = (family == AF_INET ? 4 : 16);
	uint32_t ifindex = netdev_get_ifindex(netconfig->netdev);

	if (!fils)
		return;

	/*
	 * Attempt to use the gateway/DNS MAC addressed received from the AP
	 * by writing the mapping directly into the netdev's ARP table so as
	 * to save one data frame roundtrip before first IP connections are
	 * established.  This is very low-priority but print error messages
	 * just because they may indicate bigger problems.
	 */

	addr = (family == AF_INET ? (void *) &fils->ipv4_gateway :
			(void *) &fils->ipv6_gateway);
	hwaddr = (family == AF_INET ?
			&fils->ipv4_gateway_mac : &fils->ipv6_gateway_mac);

	if (!l_memeqzero(addr, addr_len) && !l_memeqzero(hwaddr, ETH_ALEN) &&
			unlikely(!l_rtnl_neighbor_set_hwaddr(rtnl, ifindex,
						family, addr, hwaddr, ETH_ALEN,
						netconfig_set_neighbor_entry_cb,
						NULL, NULL)))
		l_debug("l_rtnl_neighbor_set_hwaddr(%s, gateway) failed",
			family == AF_INET ? "AF_INET" : "AF_INET6");

	addr = (family == AF_INET ? (void *) &fils->ipv4_dns :
			(void *) &fils->ipv6_dns);
	hwaddr = (family == AF_INET ?
			&fils->ipv4_dns_mac : &fils->ipv6_dns_mac);

	if (!l_memeqzero(addr, addr_len) && !l_memeqzero(hwaddr, ETH_ALEN) &&
			unlikely(!l_rtnl_neighbor_set_hwaddr(rtnl, ifindex,
						family, addr, hwaddr, ETH_ALEN,
						netconfig_set_neighbor_entry_cb,
						NULL, NULL)))
		l_debug("l_rtnl_neighbor_set_hwaddr(%s, DNS) failed",
			family == AF_INET ? "AF_INET" : "AF_INET6");
}

static void netconfig_dns_list_update(struct netconfig *netconfig)
{
	_auto_(l_strv_free) char **dns_list =
		l_netconfig_get_dns_list(netconfig->nc);

	if (l_strv_eq(netconfig->dns_list, dns_list))
		return;

	if (netconfig->resolve && dns_list)
		resolve_set_dns(netconfig->resolve, dns_list);

	l_strv_free(netconfig->dns_list);
	netconfig->dns_list = l_steal_ptr(dns_list);
}

static void netconfig_domains_update(struct netconfig *netconfig)
{
	_auto_(l_strv_free) char **domains =
		l_netconfig_get_domain_names(netconfig->nc);

	if (l_strv_eq(netconfig->domains, domains))
		return;

	if (netconfig->resolve && domains)
		resolve_set_domains(netconfig->resolve, domains);

	l_strv_free(netconfig->domains);
	netconfig->domains = l_steal_ptr(domains);
}

static void netconfig_rtnl_commit(struct netconfig *netconfig, uint8_t family,
					enum l_netconfig_event event)
{
	l_netconfig_apply_rtnl(netconfig->nc);

	netconfig_dns_list_update(netconfig);
	netconfig_domains_update(netconfig);

	if (event == L_NETCONFIG_EVENT_CONFIGURE && family == AF_INET)
		/*
		 * netconfig->mdns is currently only loaded in
		 * netconfig_load_settings() so we can set it once on
		 * the CONFIGURE event.
		 */
		resolve_set_mdns(netconfig->resolve, netconfig->mdns);

	if (event == L_NETCONFIG_EVENT_UNCONFIGURE && family == AF_INET) {
		l_strv_free(l_steal_ptr(netconfig->dns_list));
		l_strv_free(l_steal_ptr(netconfig->domains));
		resolve_revert(netconfig->resolve);
	}

	netconfig_commit_done(netconfig, family, event, true);
}

static void netconfig_rtnl_free_data(struct netconfig *netconfig,
					const char *reasonstr)
{
	l_strv_free(l_steal_ptr(netconfig->dns_list));
	l_strv_free(l_steal_ptr(netconfig->domains));
}


struct netconfig_agent_data {
	uint32_t pending_id[2];
};

struct netconfig_agent_call_data {
	struct netconfig *netconfig;
	uint8_t family;
	enum l_netconfig_event event;
};

static char *netconfig_agent_name;
static char *netconfig_agent_path;
static unsigned int netconfig_agent_watch;

static void netconfig_agent_cancel(struct netconfig *netconfig, uint8_t family,
					const char *reasonstr)
{
	struct netconfig_agent_data *data = netconfig->commit_data;
	struct l_dbus *dbus = dbus_get_bus();
	const char *dev_path = netdev_get_path(netconfig->netdev);
	struct l_dbus_message *message;
	const char *method;

	if (!data || !data->pending_id[INDEX_FOR_AF(family)])
		return;

	l_dbus_cancel(dbus, data->pending_id[INDEX_FOR_AF(family)]);
	data->pending_id[INDEX_FOR_AF(family)] = 0;

	method = (family == AF_INET ? "CancelIPv4" : "CancelIPv6");
	l_debug("sending a %s(%s, %s) to %s %s", method, dev_path, reasonstr,
		netconfig_agent_name, netconfig_agent_path);

	message = l_dbus_message_new_method_call(dbus, netconfig_agent_name,
						netconfig_agent_path,
						IWD_NETCONFIG_AGENT_INTERFACE,
						method);
	l_dbus_message_set_arguments(message, "os", dev_path, reasonstr);
	l_dbus_message_set_no_reply(message, true);
	l_dbus_send(dbus, message);
}

static void netconfig_agent_receive_reply(struct l_dbus_message *reply,
						void *user_data)
{
	struct netconfig_agent_call_data *cd = user_data;
	struct netconfig_agent_data *data = cd->netconfig->commit_data;
	const char *error, *text;
	bool success = true;

	l_debug("agent reply from %s", l_dbus_message_get_sender(reply));

	data->pending_id[INDEX_FOR_AF(cd->family)] = 0;

	if (!cd->netconfig->started)
		return;

	if (l_dbus_message_get_error(reply, &error, &text)) {
		success = false;
		l_error("netconfig agent call returned %s(\"%s\")",
			error, text);
	} else if (!l_dbus_message_get_arguments(reply, "")) {
		success = false;
		l_error("netconfig agent call reply signature wrong: %s",
			l_dbus_message_get_signature(reply));
	}

	netconfig_commit_done(cd->netconfig, cd->family, cd->event, success);
}

#define IS_IPV6_STR_FAST(str)	(strchr(str, ':') != NULL)

typedef void (*netconfig_build_entry_fn)(struct l_dbus_message_builder *builder,
					const void *data, uint8_t family);

static void netconfig_agent_append_dict_dict_array(
					struct l_dbus_message_builder *builder,
					const char *key,
					const struct l_queue_entry *value,
					netconfig_build_entry_fn build_entry,
					uint8_t family)
{
	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', key);
	l_dbus_message_builder_enter_variant(builder, "aa{sv}");
	l_dbus_message_builder_enter_array(builder, "a{sv}");

	for (; value; value = value->next)
		build_entry(builder, value->data, family);

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);
}

static void netconfig_agent_append_dict_strv(
					struct l_dbus_message_builder *builder,
					const char *key, char **value,
					uint8_t family)
{
	if (!value)
		return;

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', key);
	l_dbus_message_builder_enter_variant(builder, "as");
	l_dbus_message_builder_enter_array(builder, "s");

	for (; *value; value++) {
		uint8_t value_family = IS_IPV6_STR_FAST((char *) *value) ?
			AF_INET6 : AF_INET;

		if (family == AF_UNSPEC || value_family == family)
			l_dbus_message_builder_append_basic(builder, 's',
								*value);
	}

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);
}

static void netconfig_agent_append_address(
					struct l_dbus_message_builder *builder,
					const void *data, uint8_t family)
{
	const struct l_rtnl_address *addr = data;
	char addr_str[INET6_ADDRSTRLEN];
	uint64_t valid_expiry_time;
	uint64_t preferred_expiry_time;
	uint64_t now = l_time_now();

	if (l_rtnl_address_get_family(addr) != family)
		return;

	l_dbus_message_builder_enter_array(builder, "{sv}");

	l_rtnl_address_get_address(addr, addr_str);
	dbus_append_dict_basic(builder, "Address", 's', addr_str);

	if (family == AF_INET) {
		uint8_t plen = l_rtnl_address_get_prefix_length(addr);
		dbus_append_dict_basic(builder, "PrefixLength", 'y', &plen);

		if (l_rtnl_address_get_broadcast(addr, addr_str) &&
				strcmp(addr_str, "0.0.0.0"))
			dbus_append_dict_basic(builder, "Broadcast", 's',
						addr_str);
	}

	l_rtnl_address_get_expiry(addr, &preferred_expiry_time,
					&valid_expiry_time);

	if (valid_expiry_time > now) {
		uint32_t lt = l_time_to_secs(valid_expiry_time - now);

		dbus_append_dict_basic(builder, "ValidLifetime", 'u', &lt);
	}

	if (preferred_expiry_time > now) {
		uint32_t lt = l_time_to_secs(preferred_expiry_time - now);

		dbus_append_dict_basic(builder, "PreferredLifetime", 'u', &lt);
	}

	l_dbus_message_builder_leave_array(builder);
}

static void netconfig_agent_append_route(struct l_dbus_message_builder *builder,
						const void *data,
						uint8_t family)
{
	const struct l_rtnl_route *rt = data;
	char addr_str[INET6_ADDRSTRLEN];
	uint8_t prefix_len;
	uint64_t expiry_time;
	uint64_t now = l_time_now();
	uint32_t priority;
	uint8_t preference;
	uint32_t mtu;

	if (l_rtnl_route_get_family(rt) != family)
		return;

	l_dbus_message_builder_enter_array(builder, "{sv}");

	if (l_rtnl_route_get_dst(rt, addr_str, &prefix_len) && prefix_len) {
		l_dbus_message_builder_enter_dict(builder, "sv");
		l_dbus_message_builder_append_basic(builder, 's',
							"Destination");
		l_dbus_message_builder_enter_variant(builder, "(sy)");
		l_dbus_message_builder_enter_struct(builder, "sy");
		l_dbus_message_builder_append_basic(builder, 's', addr_str);
		l_dbus_message_builder_append_basic(builder, 'y', &prefix_len);
		l_dbus_message_builder_leave_struct(builder);
		l_dbus_message_builder_leave_variant(builder);
		l_dbus_message_builder_leave_dict(builder);
	}

	if (l_rtnl_route_get_gateway(rt, addr_str))
		dbus_append_dict_basic(builder, "Router", 's', addr_str);

	if (l_rtnl_route_get_prefsrc(rt, addr_str))
		dbus_append_dict_basic(builder, "PreferredSource", 's',
					addr_str);

	expiry_time = l_rtnl_route_get_expiry(rt);
	if (expiry_time > now) {
		uint32_t lt = l_time_to_secs(expiry_time - now);

		dbus_append_dict_basic(builder, "Lifetime", 'u', &lt);
	}

	priority = l_rtnl_route_get_priority(rt);
	dbus_append_dict_basic(builder, "Priority", 'u', &priority);

	/*
	 * ICMPV6_ROUTER_PREF_MEDIUM is returned by default even for IPv4
	 * routes where this property doesn't make sense so filter those out.
	 */
	preference = l_rtnl_route_get_preference(rt);
	if (preference != ICMPV6_ROUTER_PREF_INVALID && family == AF_INET6)
		dbus_append_dict_basic(builder, "Preference", 'y', &preference);

	mtu = l_rtnl_route_get_mtu(rt);
	if (mtu)
		dbus_append_dict_basic(builder, "Priority", 'u', &mtu);

	l_dbus_message_builder_leave_array(builder);
}

static void netconfig_agent_commit(struct netconfig *netconfig, uint8_t family,
					enum l_netconfig_event event)
{
	struct netconfig_agent_data *data;
	struct netconfig_agent_call_data *cd;
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *message;
	struct l_dbus_message_builder *builder;
	const char *dev_path = netdev_get_path(netconfig->netdev);
	const char *dbus_method =
		(family == AF_INET ? "ConfigureIPv4" : "ConfigureIPv6");
	const char *cfg_method =
		netconfig->static_config[INDEX_FOR_AF(family)] ?
		"static" : "auto";
	_auto_(l_strv_free) char **dns_list = NULL;
	_auto_(l_strv_free) char **domains = NULL;

	if (!netconfig->commit_data)
		netconfig->commit_data = l_new(struct netconfig_agent_data, 1);

	netconfig_agent_cancel(netconfig, family, "superseded");

	l_debug("sending a %s(%s, ...) to %s %s", dbus_method, dev_path,
		netconfig_agent_name, netconfig_agent_path);

	message = l_dbus_message_new_method_call(dbus, netconfig_agent_name,
						netconfig_agent_path,
						IWD_NETCONFIG_AGENT_INTERFACE,
						dbus_method);

	/*
	 * Build the call arguments: the Device object path and
	 * the complicated config dict.
	 */
	builder = l_dbus_message_builder_new(message);
	l_dbus_message_builder_append_basic(builder, 'o', dev_path);
	l_dbus_message_builder_enter_array(builder, "{sv}");
	dbus_append_dict_basic(builder, "Method", 's', cfg_method);

	netconfig_agent_append_dict_dict_array(builder, "Addresses",
					l_netconfig_get_addresses(netconfig->nc,
							NULL, NULL, NULL, NULL),
					netconfig_agent_append_address, family);

	netconfig_agent_append_dict_dict_array(builder, "Routes",
					l_netconfig_get_routes(netconfig->nc,
							NULL, NULL, NULL, NULL),
					netconfig_agent_append_route, family);

	dns_list = l_netconfig_get_dns_list(netconfig->nc);
	netconfig_agent_append_dict_strv(builder, "DomainNameServers",
						dns_list, family);

	domains = l_netconfig_get_domain_names(netconfig->nc);
	netconfig_agent_append_dict_strv(builder, "DomainNames",
						domains, AF_UNSPEC);

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	cd = l_new(struct netconfig_agent_call_data, 1);
	cd->netconfig = netconfig;
	cd->family = family;
	cd->event = event;
	data = netconfig->commit_data;
	data->pending_id[INDEX_FOR_AF(family)] =
		l_dbus_send_with_reply(dbus, message,
					netconfig_agent_receive_reply,
					cd, l_free);
}

static void netconfig_agent_free_data(struct netconfig *netconfig,
					const char *reasonstr)
{
	if (!netconfig->commit_data)
		return;

	netconfig_agent_cancel(netconfig, AF_INET, reasonstr);
	netconfig_agent_cancel(netconfig, AF_INET6, reasonstr);
	l_free(l_steal_ptr(netconfig->commit_data));
}

static struct netconfig_commit_ops netconfig_agent_ops = {
	.commit    = netconfig_agent_commit,
	.free_data = netconfig_agent_free_data,
};

static void netconfig_agent_disconnect_handle(void *user_data)
{
	netconfig_unregister_agent(netconfig_agent_name, netconfig_agent_path);
}

static void netconfig_agent_disconnect_cb(struct l_dbus *dbus, void *user_data)
{
	l_debug("");
	l_idle_oneshot(netconfig_agent_disconnect_handle, NULL, NULL);
}

int netconfig_register_agent(const char *name, const char *path)
{
	if (netconfig_agent_path)
		return -EEXIST;

	netconfig_agent_name = l_strdup(name);
	netconfig_agent_path = l_strdup(path);
	netconfig_agent_watch = l_dbus_add_disconnect_watch(dbus_get_bus(),
						name,
						netconfig_agent_disconnect_cb,
						NULL, NULL);

	netconfig_switch_backend(&netconfig_agent_ops);

	return 0;
}

int netconfig_unregister_agent(const char *name, const char *path)
{
	if (!netconfig_agent_path || strcmp(netconfig_agent_path, path))
		return -ENOENT;

	if (strcmp(netconfig_agent_name, name))
		return -EPERM;

	l_free(l_steal_ptr(netconfig_agent_name));
	l_free(l_steal_ptr(netconfig_agent_path));
	l_dbus_remove_watch(dbus_get_bus(), netconfig_agent_watch);

	netconfig_switch_backend(&netconfig_rtnl_ops);
	return 0;
}
