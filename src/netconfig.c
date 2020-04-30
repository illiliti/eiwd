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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <linux/rtnetlink.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/module.h"
#include "src/netdev.h"
#include "src/station.h"
#include "src/common.h"
#include "src/network.h"
#include "src/resolve.h"
#include "src/netconfig.h"

struct netconfig {
	uint32_t ifindex;
	struct l_dhcp_client *dhcp_client;
	struct l_queue *ifaddr_list;
	uint8_t rtm_protocol;
	uint8_t rtm_v6_protocol;

	const struct l_settings *active_settings;

	netconfig_notify_func_t notify;
	void *user_data;
};

struct netconfig_ifaddr {
	uint8_t family;
	uint8_t prefix_len;
	char *ip;
	char *broadcast;
};

static struct l_netlink *rtnl;
static struct l_queue *netconfig_list;

/*
 * Routing priority offset, configurable in main.conf. The route with lower
 * priority offset is preferred.
 */
static uint32_t ROUTE_PRIORITY_OFFSET;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void netconfig_ifaddr_destroy(void *data)
{
	struct netconfig_ifaddr *ifaddr = data;

	l_free(ifaddr->ip);
	l_free(ifaddr->broadcast);

	l_free(ifaddr);
}

static void netconfig_free(void *data)
{
	struct netconfig *netconfig = data;

	l_dhcp_client_destroy(netconfig->dhcp_client);

	l_queue_destroy(netconfig->ifaddr_list, netconfig_ifaddr_destroy);

	l_free(netconfig);
}

static struct netconfig *netconfig_find(uint32_t ifindex)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(netconfig_list); entry;
							entry = entry->next) {
		struct netconfig *netconfig = entry->data;

		if (netconfig->ifindex != ifindex)
			continue;

		return netconfig;
	}

	return NULL;
}

static struct netconfig_ifaddr *netconfig_ipv4_get_ifaddr(
						struct netconfig *netconfig,
						uint8_t proto)
{
	const struct l_dhcp_lease *lease;
	struct netconfig_ifaddr *ifaddr;
	struct in_addr in_addr;
	char *netmask;
	char *ip;

	switch (proto) {
	case RTPROT_STATIC:

		ip = l_settings_get_string(netconfig->active_settings, "IPv4",
								"Address");
		if (!ip) {
			ip = l_settings_get_string(netconfig->active_settings,
							"IPv4", "ip");
			if (!ip)
				return NULL;
		}

		ifaddr = l_new(struct netconfig_ifaddr, 1);
		ifaddr->ip = ip;

		netmask = l_settings_get_string(netconfig->active_settings,
							"IPv4", "Netmask");
		if (!netmask)
			netmask = l_settings_get_string(
						netconfig->active_settings,
						"IPv4", "netmask");

		if (netmask && inet_pton(AF_INET, netmask, &in_addr) > 0)
			ifaddr->prefix_len = __builtin_popcountl(
						L_BE32_TO_CPU(in_addr.s_addr));
		else
			ifaddr->prefix_len = 24;

		l_free(netmask);

		ifaddr->broadcast =
			l_settings_get_string(netconfig->active_settings,
							"IPv4", "Broadcast");
		if (!ifaddr->broadcast)
			ifaddr->broadcast =
				l_settings_get_string(
						netconfig->active_settings,
						"IPv4", "broadcast");

		ifaddr->family = AF_INET;

		return ifaddr;

	case RTPROT_DHCP:
		lease = l_dhcp_client_get_lease(netconfig->dhcp_client);
		if (!lease)
			return NULL;

		ip = l_dhcp_lease_get_address(lease);
		if (!ip)
			return NULL;

		ifaddr = l_new(struct netconfig_ifaddr, 1);
		ifaddr->ip = ip;

		netmask = l_dhcp_lease_get_netmask(lease);

		if (netmask && inet_pton(AF_INET, netmask, &in_addr) > 0)
			ifaddr->prefix_len = __builtin_popcountl(
						L_BE32_TO_CPU(in_addr.s_addr));
		else
			ifaddr->prefix_len = 24;

		l_free(netmask);

		ifaddr->broadcast = l_dhcp_lease_get_broadcast(lease);
		ifaddr->family = AF_INET;

		return ifaddr;
	}

	return NULL;
}

static char *netconfig_ipv4_get_gateway(struct netconfig *netconfig)
{
	const struct l_dhcp_lease *lease;
	char *gateway;

	switch (netconfig->rtm_protocol) {
	case RTPROT_STATIC:
		gateway = l_settings_get_string(netconfig->active_settings,
							"IPv4", "Gateway");
		if (!gateway)
			gateway = l_settings_get_string(
						netconfig->active_settings,
						"IPv4", "gateway");

		return gateway;

	case RTPROT_DHCP:
		lease = l_dhcp_client_get_lease(netconfig->dhcp_client);
		if (!lease)
			return NULL;

		return l_dhcp_lease_get_gateway(lease);
	}

	return NULL;
}

static char **netconfig_ipv4_get_dns(struct netconfig *netconfig, uint8_t proto)
{
	const struct l_dhcp_lease *lease;
	struct in_addr in_addr;
	char **dns_list;

	dns_list = l_settings_get_string_list(netconfig->active_settings,
							"IPv4", "DNS", ' ');
	if (!dns_list)
		dns_list = l_settings_get_string_list(
						netconfig->active_settings,
						"IPv4", "dns", ' ');

	if (dns_list && *dns_list) {
		char **p;

		for (p = dns_list; *p; p++) {
			if (inet_pton(AF_INET, *p, &in_addr) == 1)
				continue;

			l_error("netconfig: Invalid IPv4 DNS address '%s' is "
				"provided in network configuration file.", *p);

			l_strv_free(dns_list);

			return NULL;
		}

		/* Allow to override the DHCP DNSs with static addressing. */
		return dns_list;
	} else if (dns_list) {
		l_error("netconfig: No IPv4 DNS address is provided in network "
							"configuration file.");

		l_strv_free(dns_list);

		return NULL;
	}

	if (proto == RTPROT_DHCP) {
		lease = l_dhcp_client_get_lease(netconfig->dhcp_client);
		if (!lease)
			return NULL;

		return l_dhcp_lease_get_dns(lease);
	}

	return NULL;
}

static char *netconfig_ipv4_get_domain_name(struct netconfig *netconfig,
								uint8_t proto)
{
	const struct l_dhcp_lease *lease;
	char *domain_name;

	domain_name = l_settings_get_string(netconfig->active_settings,
							"IPv4", "DomainName");
	if (domain_name)
		/* Allow to override the DHCP domain name with setting entry. */
		return domain_name;

	if (proto != RTPROT_DHCP)
		return NULL;

	lease = l_dhcp_client_get_lease(netconfig->dhcp_client);
	if (!lease)
		return NULL;

	return l_dhcp_lease_get_domain_name(lease);
}

static struct netconfig_ifaddr *netconfig_ipv6_get_ifaddr(
						struct netconfig *netconfig,
						uint8_t proto)
{
	struct in6_addr in6_addr;
	struct netconfig_ifaddr *ifaddr;
	char *ip;
	char *p;

	switch (proto) {
	case RTPROT_STATIC:
		ip = l_settings_get_string(netconfig->active_settings, "IPv6",
								"Address");
		if (!ip) {
			ip = l_settings_get_string(netconfig->active_settings,
								"IPv6", "ip");
			if (!ip)
				return NULL;
		}

		ifaddr = l_new(struct netconfig_ifaddr, 1);
		ifaddr->ip = ip;

		p = strrchr(ifaddr->ip, '/');
		if (!p)
			goto no_prefix_len;

		*p = '\0';

		if (inet_pton(AF_INET6, ifaddr->ip, &in6_addr) < 1) {
			l_error("netconfig: Invalid IPv6 address %s is "
				"provided in network configuration file.",
				ifaddr->ip);

			netconfig_ifaddr_destroy(ifaddr);

			return NULL;
		}

		if (*++p == '\0')
			goto no_prefix_len;

		ifaddr->prefix_len = strtoul(p, NULL, 10);

		if (!unlikely(errno == EINVAL || errno == ERANGE ||
				!ifaddr->prefix_len ||
				ifaddr->prefix_len > 128))
			goto proceed;

no_prefix_len:
		ifaddr->prefix_len = 128;
proceed:
		ifaddr->family = AF_INET6;

		return ifaddr;

	case RTPROT_DHCP:
		/* TODO */

		return NULL;
	}

	return NULL;
}

static char *netconfig_ipv6_get_gateway(struct netconfig *netconfig)
{
	struct in6_addr in6_addr;
	char *gateway;

	switch (netconfig->rtm_v6_protocol) {
	case RTPROT_STATIC:
		gateway = l_settings_get_string(netconfig->active_settings,
							"IPv6", "Gateway");
		if (!gateway)
			gateway = l_settings_get_string(
						netconfig->active_settings,
						"IPv6", "gateway");

		if (inet_pton(AF_INET6, gateway, &in6_addr) < 1) {
			l_error("netconfig: Invalid IPv6 gateway address %s is "
				"provided in network configuration file.",
				gateway);

			l_free(gateway);

			return NULL;
		}

		return gateway;

	case RTPROT_DHCP:
		/* TODO */

		return NULL;
	}

	return NULL;
}

static char **netconfig_ipv6_get_dns(struct netconfig *netconfig, uint8_t proto)
{
	struct in6_addr in6_addr;
	char **dns_list;

	dns_list = l_settings_get_string_list(netconfig->active_settings,
							"IPv6", "DNS", ' ');

	if (!dns_list)
		dns_list = l_settings_get_string_list(
						netconfig->active_settings,
						"IPv6", "dns", ' ');

	if (dns_list && *dns_list) {
		char **p;

		for (p = dns_list; *p; p++) {
			if (inet_pton(AF_INET6, *p, &in6_addr) == 1)
				continue;

			l_error("netconfig: Invalid IPv6 DNS address '%s' is "
				"provided in network configuration file.", *p);

			l_strv_free(dns_list);

			return NULL;
		}

		/* Allow to override the DHCP DNSs with static addressing. */
		return dns_list;
	} else if (dns_list) {
		l_error("netconfig: No IPv6 DNS address is provided in network "
							"configuration file.");

		l_strv_free(dns_list);

		return NULL;
	}

	if (proto == RTPROT_DHCP) {
		/* TODO */

		return NULL;
	}

	return NULL;
}

static bool netconfig_ifaddr_match(const void *a, const void *b)
{
	const struct netconfig_ifaddr *entry = a;
	const struct netconfig_ifaddr *query = b;

	if (entry->family != query->family)
		return false;

	if (entry->prefix_len != query->prefix_len)
		return false;

	if (strcmp(entry->ip, query->ip))
		return false;

	return true;
}

static struct netconfig_ifaddr *netconfig_ifaddr_find(
					const struct netconfig *netconfig,
					uint8_t family, uint8_t prefix_len,
					const char *ip)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(netconfig->ifaddr_list); entry;
							entry = entry->next) {
		struct netconfig_ifaddr *ifaddr = entry->data;

		if (ifaddr->family != family)
			continue;

		if (ifaddr->prefix_len != prefix_len)
			continue;

		if (strcmp(ifaddr->ip, ip))
			continue;

		return ifaddr;
	}

	return NULL;
}

static void netconfig_ifaddr_added(struct netconfig *netconfig,
					const struct ifaddrmsg *ifa,
					uint32_t len)
{
	struct netconfig_ifaddr *ifaddr;
	char *label;

	ifaddr = l_new(struct netconfig_ifaddr, 1);
	ifaddr->family = ifa->ifa_family;
	ifaddr->prefix_len = ifa->ifa_prefixlen;

	l_rtnl_ifaddr4_extract(ifa, len, &label, &ifaddr->ip,
					&ifaddr->broadcast);

	l_debug("%s: ifaddr %s/%u broadcast %s", label, ifaddr->ip,
					ifaddr->prefix_len, ifaddr->broadcast);
	l_free(label);

	l_queue_push_tail(netconfig->ifaddr_list, ifaddr);
}

static void netconfig_ifaddr_deleted(struct netconfig *netconfig,
					const struct ifaddrmsg *ifa,
					uint32_t len)
{
	struct netconfig_ifaddr *ifaddr;
	struct netconfig_ifaddr query;

	l_rtnl_ifaddr4_extract(ifa, len, NULL, &query.ip, NULL);

	query.family = ifa->ifa_family;
	query.prefix_len = ifa->ifa_prefixlen;

	ifaddr = l_queue_remove_if(netconfig->ifaddr_list,
						netconfig_ifaddr_match, &query);
	l_free(query.ip);

	if (!ifaddr)
		return;

	l_debug("ifaddr %s/%u", ifaddr->ip, ifaddr->prefix_len);

	netconfig_ifaddr_destroy(ifaddr);
}

static void netconfig_ifaddr_notify(uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const struct ifaddrmsg *ifa = data;
	struct netconfig *netconfig;
	uint32_t bytes;

	netconfig = netconfig_find(ifa->ifa_index);
	if (!netconfig)
		/* Ignore the interfaces which aren't managed by iwd. */
		return;

	bytes = len - NLMSG_ALIGN(sizeof(struct ifaddrmsg));

	switch (type) {
	case RTM_NEWADDR:
		netconfig_ifaddr_added(netconfig, ifa, bytes);
		break;
	case RTM_DELADDR:
		netconfig_ifaddr_deleted(netconfig, ifa, bytes);
		break;
	}
}

static void netconfig_ifaddr_cmd_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	if (error) {
		l_error("netconfig: ifaddr command failure. "
				"Error %d: %s", error, strerror(-error));
		return;
	}

	if (type != RTM_NEWADDR)
		return;

	netconfig_ifaddr_notify(type, data, len, user_data);
}

static void netconfig_ifaddr_ipv6_added(struct netconfig *netconfig,
					const struct ifaddrmsg *ifa,
					uint32_t len)
{
	struct netconfig_ifaddr *ifaddr;

	ifaddr = l_new(struct netconfig_ifaddr, 1);
	ifaddr->family = ifa->ifa_family;
	ifaddr->prefix_len = ifa->ifa_prefixlen;

	l_rtnl_ifaddr6_extract(ifa, len, &ifaddr->ip);

	l_debug("ifindex %u: ifaddr %s/%u", netconfig->ifindex, ifaddr->ip,
							ifaddr->prefix_len);

	l_queue_push_tail(netconfig->ifaddr_list, ifaddr);
}

static void netconfig_ifaddr_ipv6_deleted(struct netconfig *netconfig,
						const struct ifaddrmsg *ifa,
						uint32_t len)
{
	struct netconfig_ifaddr *ifaddr;
	struct netconfig_ifaddr query;

	l_rtnl_ifaddr6_extract(ifa, len, &query.ip);

	query.family = ifa->ifa_family;
	query.prefix_len = ifa->ifa_prefixlen;

	ifaddr = l_queue_remove_if(netconfig->ifaddr_list,
						netconfig_ifaddr_match, &query);

	l_free(query.ip);

	if (!ifaddr)
		return;

	l_debug("ifaddr %s/%u", ifaddr->ip, ifaddr->prefix_len);

	netconfig_ifaddr_destroy(ifaddr);
}

static void netconfig_ifaddr_ipv6_notify(uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const struct ifaddrmsg *ifa = data;
	struct netconfig *netconfig;
	uint32_t bytes;

	netconfig = netconfig_find(ifa->ifa_index);
	if (!netconfig)
		/* Ignore the interfaces which aren't managed by iwd. */
		return;

	bytes = len - NLMSG_ALIGN(sizeof(struct ifaddrmsg));

	switch (type) {
	case RTM_NEWADDR:
		netconfig_ifaddr_ipv6_added(netconfig, ifa, bytes);
		break;
	case RTM_DELADDR:
		netconfig_ifaddr_ipv6_deleted(netconfig, ifa, bytes);
		break;
	}
}

static void netconfig_ifaddr_ipv6_cmd_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	if (error) {
		l_error("netconfig: ifaddr IPv6 command failure. "
				"Error %d: %s", error, strerror(-error));
		return;
	}

	if (type != RTM_NEWADDR)
		return;

	netconfig_ifaddr_ipv6_notify(type, data, len, user_data);
}

static void netconfig_route_add_cmd_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	struct netconfig *netconfig = user_data;

	if (error) {
		l_error("netconfig: Failed to add route. Error %d: %s",
						error, strerror(-error));
		return;
	}

	if (!netconfig->notify)
		return;

	netconfig->notify(NETCONFIG_EVENT_CONNECTED, netconfig->user_data);
	netconfig->notify = NULL;
}

static void netconfig_route_del_cmd_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	if (!error)
		return;

	l_error("netconfig: Failed to delete route. Error %d: %s",
						error, strerror(-error));

}

static bool netconfig_ipv4_routes_install(struct netconfig *netconfig,
						struct netconfig_ifaddr *ifaddr)
{
	L_AUTO_FREE_VAR(char *, gateway) = NULL;
	struct in_addr in_addr;
	char *network;

	if (inet_pton(AF_INET, ifaddr->ip, &in_addr) < 1)
		return false;

	in_addr.s_addr = in_addr.s_addr &
			htonl(0xFFFFFFFFLU << (32 - ifaddr->prefix_len));

	network = inet_ntoa(in_addr);
	if (!network)
		return false;

	if (!l_rtnl_route4_add_connected(rtnl, netconfig->ifindex,
						ifaddr->prefix_len, network,
						ifaddr->ip,
						netconfig->rtm_protocol,
						netconfig_route_add_cmd_cb,
						netconfig, NULL)) {
		l_error("netconfig: Failed to add subnet route.");

		return false;
	}

	gateway = netconfig_ipv4_get_gateway(netconfig);
	if (!gateway) {
		l_error("netconfig: Failed to obtain gateway from %s.",
				netconfig->rtm_protocol == RTPROT_STATIC ?
				"setting file" : "DHCPv4 lease");

		return false;
	}

	if (!l_rtnl_route4_add_gateway(rtnl, netconfig->ifindex, gateway,
						ifaddr->ip,
						ROUTE_PRIORITY_OFFSET,
						netconfig->rtm_protocol,
						netconfig_route_add_cmd_cb,
						netconfig, NULL)) {
		l_error("netconfig: Failed to add route for: %s gateway.",
								gateway);

		return false;
	}

	return true;
}

static void netconfig_ipv4_ifaddr_add_cmd_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	struct netconfig *netconfig = user_data;
	struct netconfig_ifaddr *ifaddr;
	char **dns;
	char *domain_name;

	if (error && error != -EEXIST) {
		l_error("netconfig: Failed to add IP address. "
				"Error %d: %s", error, strerror(-error));
		return;
	}

	ifaddr = netconfig_ipv4_get_ifaddr(netconfig, netconfig->rtm_protocol);
	if (!ifaddr) {
		l_error("netconfig: Failed to obtain IP address from %s.",
				netconfig->rtm_protocol == RTPROT_STATIC ?
				"setting file" : "DHCPv4 lease");
		return;
	}

	if (!netconfig_ipv4_routes_install(netconfig, ifaddr)) {
		l_error("netconfig: Failed to install IPv4 routes.");

		goto done;
	}

	dns = netconfig_ipv4_get_dns(netconfig, netconfig->rtm_protocol);
	if (!dns) {
		l_error("netconfig: Failed to obtain DNS addresses.");
		goto domain_name;
	}

	resolve_add_dns(netconfig->ifindex, ifaddr->family, dns);
	l_strv_free(dns);

domain_name:
	domain_name = netconfig_ipv4_get_domain_name(netconfig,
						netconfig->rtm_protocol);
	if (!domain_name)
		goto done;

	resolve_add_domain_name(netconfig->ifindex, domain_name);
	l_free(domain_name);

done:
	netconfig_ifaddr_destroy(ifaddr);
}

static bool netconfig_ipv6_routes_install(struct netconfig *netconfig)
{
	L_AUTO_FREE_VAR(char *, gateway) = NULL;

	gateway = netconfig_ipv6_get_gateway(netconfig);
	if (!gateway) {
		l_error("netconfig: Failed to obtain gateway from %s.",
				netconfig->rtm_v6_protocol == RTPROT_STATIC ?
				"settings file" : "DHCPv6 lease");

		return false;
	}

	if (!l_rtnl_route6_add_gateway(rtnl, netconfig->ifindex, gateway,
						ROUTE_PRIORITY_OFFSET,
						netconfig->rtm_v6_protocol,
						netconfig_route_add_cmd_cb,
						netconfig, NULL)) {
		l_error("netconfig: Failed to add route for: %s gateway.",
								gateway);

		return false;
	}

	return true;
}

static void netconfig_ipv6_ifaddr_add_cmd_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	struct netconfig *netconfig = user_data;
	char **dns;

	if (error && error != -EEXIST) {
		l_error("netconfig: Failed to add IPv6 address. "
				"Error %d: %s", error, strerror(-error));
		return;
	}

	if (!netconfig_ipv6_routes_install(netconfig)) {
		l_error("netconfig: Failed to install IPv6 routes.");

		return;
	}

	dns = netconfig_ipv6_get_dns(netconfig, netconfig->rtm_v6_protocol);
	if (!dns) {
		l_error("netconfig: Failed to obtain the DNS addresses from "
			"%s.", netconfig->rtm_v6_protocol == RTPROT_STATIC ?
				"setting file" : "DHCPv6 lease");
		return;
	}

	resolve_add_dns(netconfig->ifindex, AF_INET6, dns);
	l_strv_free(dns);
}

static void netconfig_install_address(struct netconfig *netconfig,
						struct netconfig_ifaddr *ifaddr)
{
	if (netconfig_ifaddr_find(netconfig, ifaddr->family, ifaddr->prefix_len,
								ifaddr->ip))
		return;

	switch (ifaddr->family) {
	case AF_INET:
		if (l_rtnl_ifaddr4_add(rtnl, netconfig->ifindex,
					ifaddr->prefix_len, ifaddr->ip,
					ifaddr->broadcast,
					netconfig_ipv4_ifaddr_add_cmd_cb,
					netconfig, NULL))
			return;

		l_error("netconfig: Failed to set IP %s/%u.", ifaddr->ip,
							ifaddr->prefix_len);
		break;
	case AF_INET6:
		if (l_rtnl_ifaddr6_add(rtnl, netconfig->ifindex,
					ifaddr->prefix_len, ifaddr->ip,
					netconfig_ipv6_ifaddr_add_cmd_cb,
					netconfig, NULL))
			return;

		l_error("netconfig: Failed to set IPv6 address %s/%u.",
					ifaddr->ip, ifaddr->prefix_len);
		break;
	default:
		l_error("netconfig: Unsupported address family: %u",
								ifaddr->family);
		break;
	}
}

static void netconfig_ifaddr_del_cmd_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	if (error == -ENODEV)
		/* The device is unplugged, we are done. */
		return;

	if (!error)
		/*
		 * The kernel removes all of the routes associated with the
		 * deleted IP on its own. There is no need to explicitly remove
		 * them.
		 */
		return;

	l_error("netconfig: Failed to delete IP address. "
				"Error %d: %s", error, strerror(-error));
}

static void netconfig_uninstall_address(struct netconfig *netconfig,
						struct netconfig_ifaddr *ifaddr)
{
	if (!netconfig_ifaddr_find(netconfig, ifaddr->family,
						ifaddr->prefix_len, ifaddr->ip))
		return;

	switch (ifaddr->family) {
	case AF_INET:
		if (l_rtnl_ifaddr4_delete(rtnl, netconfig->ifindex,
					ifaddr->prefix_len, ifaddr->ip,
					ifaddr->broadcast,
					netconfig_ifaddr_del_cmd_cb, netconfig,
					NULL))
			return;

		l_error("netconfig: Failed to delete IP %s/%u.",
						ifaddr->ip, ifaddr->prefix_len);
		break;
	case AF_INET6:
		if (l_rtnl_ifaddr6_delete(rtnl, netconfig->ifindex,
					ifaddr->prefix_len, ifaddr->ip,
					netconfig_ifaddr_del_cmd_cb, netconfig,
					NULL))
			return;

		l_error("netconfig: Failed to delete IPv6 address %s/%u.",
						ifaddr->ip, ifaddr->prefix_len);
		break;
	default:
		l_error("netconfig: Unsupported address family: %u",
								ifaddr->family);
		break;
	}
}

static void netconfig_ipv4_dhcp_event_handler(struct l_dhcp_client *client,
						enum l_dhcp_client_event event,
						void *userdata)
{
	struct netconfig *netconfig = userdata;
	struct netconfig_ifaddr *ifaddr;

	l_debug("DHCPv4 event %d", event);

	switch (event) {
	case L_DHCP_CLIENT_EVENT_LEASE_RENEWED:
	case L_DHCP_CLIENT_EVENT_LEASE_OBTAINED:
	case L_DHCP_CLIENT_EVENT_IP_CHANGED:
		ifaddr = netconfig_ipv4_get_ifaddr(netconfig, RTPROT_DHCP);
		if (!ifaddr) {
			l_error("netconfig: Failed to obtain IP addresses from "
							"DHCPv4 lease.");
			return;
		}

		netconfig_install_address(netconfig, ifaddr);

		netconfig_ifaddr_destroy(ifaddr);

		break;
	case L_DHCP_CLIENT_EVENT_LEASE_EXPIRED:
		ifaddr = netconfig_ipv4_get_ifaddr(netconfig, RTPROT_DHCP);
		if (!ifaddr) {
			l_error("netconfig: Failed to obtain IP addresses from "
							"DHCPv4 lease.");
			return;
		}

		netconfig_uninstall_address(netconfig, ifaddr);

		netconfig_ifaddr_destroy(ifaddr);

		/* Fall through. */
	case L_DHCP_CLIENT_EVENT_NO_LEASE:
		/*
		 * The requested address is no longer available, try to restart
		 * the client.
		 */
		if (!l_dhcp_client_start(client))
			l_error("netconfig: Failed to re-start DHCPv4 client "
					"for interface %u", netconfig->ifindex);

		break;
	default:
		l_error("netconfig: Received unsupported DHCPv4 event: %d",
									event);
	}
}

static bool netconfig_ipv4_dhcp_create(struct netconfig *netconfig)
{
	netconfig->dhcp_client = l_dhcp_client_new(netconfig->ifindex);

	l_dhcp_client_set_event_handler(netconfig->dhcp_client,
					netconfig_ipv4_dhcp_event_handler,
					netconfig, NULL);

	if (getenv("IWD_DHCP_DEBUG"))
		l_dhcp_client_set_debug(netconfig->dhcp_client, do_debug,
							"[DHCPv4] ", NULL);

	return true;
}

static void netconfig_ipv4_select_and_install(struct netconfig *netconfig)
{
	struct netconfig_ifaddr *ifaddr;

	ifaddr = netconfig_ipv4_get_ifaddr(netconfig, RTPROT_STATIC);
	if (ifaddr) {
		netconfig->rtm_protocol = RTPROT_STATIC;
		netconfig_install_address(netconfig, ifaddr);
		netconfig_ifaddr_destroy(ifaddr);

		return;
	}

	netconfig->rtm_protocol = RTPROT_DHCP;

	if (l_dhcp_client_start(netconfig->dhcp_client))
		return;

	l_error("netconfig: Failed to start DHCPv4 client for interface %u",
							netconfig->ifindex);
}

static void netconfig_ipv4_select_and_uninstall(struct netconfig *netconfig)
{
	struct netconfig_ifaddr *ifaddr;

	ifaddr = netconfig_ipv4_get_ifaddr(netconfig, netconfig->rtm_protocol);
	if (ifaddr) {
		netconfig_uninstall_address(netconfig, ifaddr);
		netconfig_ifaddr_destroy(ifaddr);
	}

	l_dhcp_client_stop(netconfig->dhcp_client);
}

static void netconfig_ipv6_select_and_install(struct netconfig *netconfig)
{
	struct netconfig_ifaddr *ifaddr;

	ifaddr = netconfig_ipv6_get_ifaddr(netconfig, RTPROT_STATIC);
	if (ifaddr) {
		netconfig->rtm_v6_protocol = RTPROT_STATIC;
		netconfig_install_address(netconfig, ifaddr);
		netconfig_ifaddr_destroy(ifaddr);

		return;
	}

	/*
	 *      TODO
	 *
	 *      netconfig->rtm_v6_protocol = RTPROT_DHCP;
	 *
	 *      if (l_dhcp_v6_client_start(netconfig->l_dhcp_v6_client))
	 *            return;
	 *
	 *      l_error("netconfig: Failed to start DHCPv6 client for "
	 *                  "interface %u", netconfig->ifindex);
	 */
}

static void netconfig_ipv6_select_and_uninstall(struct netconfig *netconfig)
{
	struct netconfig_ifaddr *ifaddr;
	char *gateway;

	ifaddr = netconfig_ipv6_get_ifaddr(netconfig,
						netconfig->rtm_v6_protocol);
	if (ifaddr) {
		netconfig_uninstall_address(netconfig, ifaddr);
		netconfig_ifaddr_destroy(ifaddr);
	}

	/*
	 * TODO
	 * l_dhcp_v6_client_stop(netconfig->l_dhcp_v6_client);
	 */

	gateway = netconfig_ipv6_get_gateway(netconfig);
	if (!gateway)
		return;

	if (!l_rtnl_route6_delete_gateway(rtnl, netconfig->ifindex,
			gateway, ROUTE_PRIORITY_OFFSET,
			netconfig->rtm_v6_protocol,
			netconfig_route_del_cmd_cb, NULL, NULL)) {
		l_error("netconfig: Failed to delete route for: %s gateway.",
								gateway);
	}

	l_free(gateway);
}

bool netconfig_configure(struct netconfig *netconfig,
				const struct l_settings *active_settings,
				const uint8_t *mac_address,
				netconfig_notify_func_t notify, void *user_data)
{
	netconfig->active_settings = active_settings;
	netconfig->notify = notify;
	netconfig->user_data = user_data;

	l_dhcp_client_set_address(netconfig->dhcp_client, ARPHRD_ETHER,
							mac_address, ETH_ALEN);

	netconfig_ipv4_select_and_install(netconfig);

	netconfig_ipv6_select_and_install(netconfig);

	return true;
}

bool netconfig_reconfigure(struct netconfig *netconfig)
{
	if (netconfig->rtm_protocol == RTPROT_DHCP) {
		/* TODO l_dhcp_client sending a DHCP inform request */
	}

	if (netconfig->rtm_v6_protocol == RTPROT_DHCP) {
		/* TODO l_dhcp_v6_client sending a DHCP inform request */
	}

	return true;
}

bool netconfig_reset(struct netconfig *netconfig)
{
	netconfig_ipv4_select_and_uninstall(netconfig);
	netconfig->rtm_protocol = 0;

	netconfig_ipv6_select_and_uninstall(netconfig);
	netconfig->rtm_v6_protocol = 0;

	resolve_remove(netconfig->ifindex);

	return true;
}

struct netconfig *netconfig_new(uint32_t ifindex)
{
	struct netconfig *netconfig;

	if (!netconfig_list)
		return NULL;

	l_debug("Starting netconfig for interface: %d", ifindex);

	netconfig = netconfig_find(ifindex);
	if (netconfig)
		return netconfig;

	netconfig = l_new(struct netconfig, 1);
	netconfig->ifindex = ifindex;
	netconfig->ifaddr_list = l_queue_new();

	netconfig_ipv4_dhcp_create(netconfig);

	l_queue_push_tail(netconfig_list, netconfig);

	return netconfig;
}

void netconfig_destroy(struct netconfig *netconfig)
{
	if (!netconfig_list)
		return;

	l_debug("");

	l_queue_remove(netconfig_list, netconfig);

	if (netconfig->rtm_protocol)
		netconfig_ipv4_select_and_uninstall(netconfig);

	if (netconfig->rtm_protocol || netconfig->rtm_v6_protocol)
		resolve_remove(netconfig->ifindex);

	netconfig_free(netconfig);
}

static int netconfig_init(void)
{
	uint32_t r;

	if (netconfig_list)
		return -EALREADY;

	rtnl = iwd_get_rtnl();

	r = l_netlink_register(rtnl, RTNLGRP_IPV4_IFADDR,
					netconfig_ifaddr_notify, NULL, NULL);
	if (!r) {
		l_error("netconfig: Failed to register for RTNL link address"
							" notifications.");
		goto error;
	}

	r = l_rtnl_ifaddr4_dump(rtnl, netconfig_ifaddr_cmd_cb, NULL, NULL);
	if (!r) {
		l_error("netconfig: Failed to get addresses from RTNL link.");
		goto error;
	}

	r = l_netlink_register(rtnl, RTNLGRP_IPV6_IFADDR,
				netconfig_ifaddr_ipv6_notify, NULL, NULL);
	if (!r) {
		l_error("netconfig: Failed to register for RTNL link IPv6 "
					"address notifications.");
		goto error;
	}

	r = l_rtnl_ifaddr6_dump(rtnl, netconfig_ifaddr_ipv6_cmd_cb, NULL,
									NULL);
	if (!r) {
		l_error("netconfig: Failed to get IPv6 addresses from RTNL"
								" link.");
		goto error;
	}

	if (!l_settings_get_uint(iwd_get_config(), "Network",
							"RoutePriorityOffset",
							&ROUTE_PRIORITY_OFFSET))
		ROUTE_PRIORITY_OFFSET = 300;

	netconfig_list = l_queue_new();

	return 0;

error:
	rtnl = NULL;

	return r;
}

static void netconfig_exit(void)
{
	if (!netconfig_list)
		return;

	rtnl = NULL;

	l_queue_destroy(netconfig_list, netconfig_free);
}

IWD_MODULE(netconfig, netconfig_init, netconfig_exit)
