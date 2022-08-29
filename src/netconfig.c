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
#include <limits.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ell/ell.h>

#include "ell/useful.h"
#include "src/iwd.h"
#include "src/module.h"
#include "src/netdev.h"
#include "src/station.h"
#include "src/common.h"
#include "src/network.h"
#include "src/resolve.h"
#include "src/util.h"
#include "src/ie.h"
#include "src/netconfig.h"
#include "src/sysfs.h"

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
};

/* 0 for AF_INET, 1 for AF_INET6 */
#define INDEX_FOR_AF(af)	((af) != AF_INET)

static struct l_netlink *rtnl;

/*
 * Routing priority offset, configurable in main.conf. The route with lower
 * priority offset is preferred.
 */
static uint32_t ROUTE_PRIORITY_OFFSET;
static bool ipv6_enabled;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void netconfig_free_settings(struct netconfig *netconfig)
{
	netconfig->enabled[0] = true;
	netconfig->enabled[1] = false;
	netconfig->static_config[0] = false;
	netconfig->static_config[1] = false;
	netconfig->gateway_overridden[0] = false;
	netconfig->gateway_overridden[1] = false;
	netconfig->dns_overridden[0] = false;
	netconfig->dns_overridden[1] = false;
	l_netconfig_reset_config(netconfig->nc);

	l_free(netconfig->mdns);
	netconfig->mdns = NULL;

	l_free(l_steal_ptr(netconfig->fils_override));
}

static void netconfig_free(void *data)
{
	struct netconfig *netconfig = data;

	l_netconfig_destroy(netconfig->nc);
	l_free(netconfig);
}

static bool netconfig_use_fils_addr(struct netconfig *netconfig, int af)
{
	if (!netconfig->enabled[INDEX_FOR_AF(af)])
		return false;

	if (netconfig->static_config[INDEX_FOR_AF(af)])
		return false;

	if (!netconfig->fils_override)
		return false;

	if (af == AF_INET)
		return !!netconfig->fils_override->ipv4_addr;

	return !l_memeqzero(netconfig->fils_override->ipv6_addr, 16);
}

static void netconfig_set_neighbor_entry_cb(int error,
						uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	if (error)
		l_error("l_rtnl_neighbor_set_hwaddr failed: %s (%i)",
			strerror(-error), error);
}

static struct l_rtnl_address *netconfig_get_static4_address(
				const struct l_settings *active_settings)
{
	_auto_(l_rtnl_address_free) struct l_rtnl_address *ifaddr = NULL;
	L_AUTO_FREE_VAR(char *, ip) = NULL;
	L_AUTO_FREE_VAR(char *, netmask) = NULL;
	struct in_addr in_addr;
	L_AUTO_FREE_VAR(char *, broadcast) = NULL;
	uint32_t prefix_len;

	ip = l_settings_get_string(active_settings, "IPv4", "Address");
	if (unlikely(!ip)) {
		l_error("netconfig: Can't load IPv4.Address");
		return NULL;
	}

	if (l_settings_has_key(active_settings, "IPv4", "Netmask") &&
			!(netmask = l_settings_get_string(active_settings,
								"IPv4",
								"Netmask"))) {
		l_error("netconfig: Can't load IPv4.Netmask");
		return NULL;
	}

	if (netmask) {
		if (inet_pton(AF_INET, netmask, &in_addr) != 1) {
			l_error("netconfig: Can't parse IPv4.Netmask");
			return NULL;
		}

		prefix_len = __builtin_popcountl(in_addr.s_addr);

		if (ntohl(in_addr.s_addr) !=
				util_netmask_from_prefix(prefix_len)) {
			l_error("netconfig: Invalid IPv4.Netmask");
			return NULL;
		}
	} else
		prefix_len = 24;

	ifaddr = l_rtnl_address_new(ip, prefix_len);
	if (!ifaddr || l_rtnl_address_get_family(ifaddr) != AF_INET) {
		l_error("netconfig: Unable to parse IPv4.Address");
		return NULL;
	}

	broadcast = l_settings_get_string(active_settings, "IPv4", "Broadcast");
	if (broadcast && !l_rtnl_address_set_broadcast(ifaddr, broadcast)) {
		l_error("netconfig: Unable to parse IPv4.Broadcast");
		return NULL;
	}

	return l_steal_ptr(ifaddr);
}

static struct l_rtnl_address *netconfig_get_static6_address(
				const struct l_settings *active_settings)
{
	L_AUTO_FREE_VAR(char *, ip);
	char *p;
	char *endp;
	_auto_(l_rtnl_address_free) struct l_rtnl_address *ret = NULL;
	uint32_t prefix_len = 64;

	ip = l_settings_get_string(active_settings, "IPv6", "Address");
	if (unlikely(!ip)) {
		l_error("netconfig: Can't load IPv6.Address");
		return NULL;
	}

	p = strrchr(ip, '/');
	if (!p)
		goto no_prefix_len;

	*p = '\0';
	if (*++p == '\0')
		goto no_prefix_len;

	errno = 0;
	prefix_len = strtoul(p, &endp, 10);
	if (unlikely(*endp != '\0' || errno ||
			!prefix_len || prefix_len > 128)) {
		l_error("netconfig: Invalid prefix '%s' provided in network"
				" configuration file", p);
		return NULL;
	}

no_prefix_len:
	ret = l_rtnl_address_new(ip, prefix_len);
	if (!ret || l_rtnl_address_get_family(ret) != AF_INET6) {
		l_error("netconfig: Invalid IPv6 address %s provided in "
			"network configuration file.", ip);
		return NULL;
	}

	return l_steal_ptr(ret);
}

static void netconfig_gateway_to_arp(struct netconfig *netconfig)
{
	struct l_dhcp_client *dhcp = l_netconfig_get_dhcp_client(netconfig->nc);
	const struct l_dhcp_lease *lease;
	_auto_(l_free) char *server_id = NULL;
	_auto_(l_free) char *gw = NULL;
	const uint8_t *server_mac;
	struct in_addr in_gw;

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

	if (!l_rtnl_neighbor_set_hwaddr(rtnl, netconfig->ifindex, AF_INET,
					&in_gw, server_mac, ETH_ALEN,
					netconfig_set_neighbor_entry_cb, NULL,
					NULL))
		l_debug("l_rtnl_neighbor_set_hwaddr failed");
}

static bool netconfig_load_dns(struct netconfig *netconfig,
				const struct l_settings *active_settings,
				const char *group_name, uint8_t family)
{
	_auto_(l_strv_free) char **dns_str_list = NULL;

	if (!l_settings_has_key(active_settings, group_name, "DNS"))
		return true;

	dns_str_list = l_settings_get_string_list(active_settings,
							group_name, "DNS", ' ');
	if (unlikely(!dns_str_list)) {
		l_error("netconfig: Can't load [%s].DNS", group_name);
		return false;
	}

	if (unlikely(!l_netconfig_set_dns_override(netconfig->nc, family,
							dns_str_list))) {
		l_error("netconfig: l_netconfig_set_dns_override(%s) failed",
			family == AF_INET ? "AF_INET" : "AF_INET6");
		return false;
	}

	netconfig->dns_overridden[INDEX_FOR_AF(family)] = true;
	return true;
}

static bool netconfig_load_gateway(struct netconfig *netconfig,
				const struct l_settings *active_settings,
				const char *group_name, uint8_t family)
{
	_auto_(l_free) char *gateway_str = NULL;

	if (!l_settings_has_key(active_settings, group_name, "Gateway"))
		return true;

	gateway_str = l_settings_get_string(active_settings, group_name,
						"Gateway");
	if (unlikely(!gateway_str)) {
		l_error("netconfig: Can't load [%s].Gateway", group_name);
		return false;
	}

	if (unlikely(!l_netconfig_set_gateway_override(netconfig->nc, family,
							gateway_str))) {
		l_error("netconfig: l_netconfig_set_gateway_override(%s) "
			"failed", family == AF_INET ? "AF_INET" : "AF_INET6");
		return false;
	}

	netconfig->gateway_overridden[INDEX_FOR_AF(family)] = true;
	return true;
}

bool netconfig_load_settings(struct netconfig *netconfig,
				const struct l_settings *active_settings)
{
	bool send_hostname = false;
	char hostname[HOST_NAME_MAX + 1];
	_auto_(l_free) char *mdns = NULL;
	bool success = true;
	bool static_ipv4 = false;
	bool static_ipv6 = false;
	bool enable_ipv4 = true;
	bool enable_ipv6 = ipv6_enabled;

	netconfig_free_settings(netconfig);

	/*
	 * Note we try to print errors and continue validating the
	 * configuration until we've gone through all the settings so
	 * as to make fixing the settings more efficient for the user.
	 */

	if (l_settings_has_key(active_settings, "IPv4", "Address")) {
		_auto_(l_rtnl_address_free) struct l_rtnl_address *addr =
			netconfig_get_static4_address(active_settings);

		if (unlikely(!addr)) {
			success = false;
			goto ipv6_addr;
		}

		if (!l_netconfig_set_static_addr(netconfig->nc, AF_INET,
							addr)) {
			l_error("netconfig: l_netconfig_set_static_addr("
				"AF_INET) failed");
			success = false;
			goto ipv6_addr;
		}

		static_ipv4 = true;
	}

ipv6_addr:
	if (l_settings_has_key(active_settings, "IPv6", "Address")) {
		_auto_(l_rtnl_address_free) struct l_rtnl_address *addr =
			netconfig_get_static6_address(active_settings);

		if (unlikely(!addr)) {
			success = false;
			goto gateway;
		}

		if (!l_netconfig_set_static_addr(netconfig->nc, AF_INET6,
							addr)) {
			l_error("netconfig: l_netconfig_set_static_addr("
				"AF_INET6) failed");
			success = false;
			goto gateway;
		}

		static_ipv6 = true;
	}

gateway:
	if (!netconfig_load_gateway(netconfig, active_settings,
					"IPv4", AF_INET))
		success = false;

	if (!netconfig_load_gateway(netconfig, active_settings,
					"IPv6", AF_INET6))
		success = false;

	if (!netconfig_load_dns(netconfig, active_settings, "IPv4", AF_INET))
		success = false;

	if (!netconfig_load_dns(netconfig, active_settings, "IPv6", AF_INET6))
		success = false;

	if (l_settings_has_key(active_settings, "IPv6", "Enabled") &&
			!l_settings_get_bool(active_settings, "IPv6", "Enabled",
						&enable_ipv6)) {
		l_error("netconfig: Can't load IPv6.Enabled");
		success = false;
		goto send_hostname;
	}

	if (!l_netconfig_set_family_enabled(netconfig->nc, AF_INET,
						enable_ipv4) ||
			!l_netconfig_set_family_enabled(netconfig->nc, AF_INET6,
							enable_ipv6)) {
		l_error("netconfig: l_netconfig_set_family_enabled() failed");
		success = false;
	}

send_hostname:
	if (l_settings_has_key(active_settings, "IPv4", "SendHostname") &&
			!l_settings_get_bool(active_settings, "IPv4",
						"SendHostname",
						&send_hostname)) {
		l_error("netconfig: Can't load [IPv4].SendHostname");
		success = false;
		goto mdns;
	}

	if (send_hostname && gethostname(hostname, sizeof(hostname)) != 0) {
		/* Warning only */
		l_warn("netconfig: Unable to get hostname. "
			"Error %d: %s", errno, strerror(errno));
		goto mdns;
	}

	if (send_hostname &&
			!l_netconfig_set_hostname(netconfig->nc, hostname)) {
		l_error("netconfig: l_netconfig_set_hostname() failed");
		success = false;
		goto mdns;
	}

mdns:
	if (l_settings_has_key(active_settings, "Network", "MulticastDNS") &&
			!(mdns = l_settings_get_string(active_settings,
							"Network",
							"MulticastDNS"))) {
		l_error("netconfig: Can't load Network.MulticastDNS");
		success = false;
	}

	if (mdns && !L_IN_STRSET(mdns, "true", "false", "resolve")) {
		l_error("netconfig: Bad Network.MulticastDNS value '%s'", mdns);
		success = false;
	}

	if (!l_netconfig_check_config(netconfig->nc)) {
		l_error("netconfig: Invalid configuration");
		success = false;
	}

	if (success) {
		netconfig->active_settings = active_settings;
		netconfig->static_config[INDEX_FOR_AF(AF_INET)] = static_ipv4;
		netconfig->static_config[INDEX_FOR_AF(AF_INET6)] = static_ipv6;
		netconfig->enabled[INDEX_FOR_AF(AF_INET)] = enable_ipv4;
		netconfig->enabled[INDEX_FOR_AF(AF_INET6)] = enable_ipv6;
		netconfig->mdns = l_steal_ptr(mdns);
		return true;
	}

	l_netconfig_reset_config(netconfig->nc);
	return false;
}

bool netconfig_configure(struct netconfig *netconfig,
				netconfig_notify_func_t notify, void *user_data)
{
	netconfig->notify = notify;
	netconfig->user_data = user_data;

	/* TODO */

	resolve_set_mdns(netconfig->resolve, netconfig->mdns);

	return true;
}

bool netconfig_reconfigure(struct netconfig *netconfig, bool set_arp_gw)
{
	/*
	 * Starting with kernel 4.20, ARP cache is flushed when the netdev
	 * detects NO CARRIER.  This can result in unnecessarily long delays
	 * (about 1 second on some networks) due to ARP query response being
	 * lost or delayed.  Try to force the gateway into the ARP cache
	 * to alleviate this
	 */
	if (set_arp_gw)
		netconfig_gateway_to_arp(netconfig);

	if (!netconfig->static_config[INDEX_FOR_AF(AF_INET)]) {
		/* TODO l_dhcp_client sending a DHCP inform request */
	}

	if (!netconfig->static_config[INDEX_FOR_AF(AF_INET6)]) {
		/* TODO l_dhcp_v6_client sending a DHCP inform request */
	}

	return true;
}

bool netconfig_reset(struct netconfig *netconfig)
{
	l_netconfig_unconfigure(netconfig->nc);
	l_netconfig_stop(netconfig->nc);

	netconfig_free_settings(netconfig);
	return true;
}

char *netconfig_get_dhcp_server_ipv4(struct netconfig *netconfig)
{
	struct l_dhcp_client *client =
		l_netconfig_get_dhcp_client(netconfig->nc);
	const struct l_dhcp_lease *lease;

	if (!client)
		return NULL;

	lease = l_dhcp_client_get_lease(client);
	if (!lease)
		return NULL;

	return l_dhcp_lease_get_server_id(lease);
}

bool netconfig_get_fils_ip_req(struct netconfig *netconfig,
				struct ie_fils_ip_addr_request_info *info)
{
	/*
	 * Fill in the fields used for building the FILS IP Address Assigment
	 * IE during connection if we're configured to do automatic network
	 * configuration (usually DHCP).  If we're configured with static
	 * values return false to mean the IE should not be sent.
	 */
	if (netconfig->static_config[0] && netconfig->static_config[1])
		return false;

	memset(info, 0, sizeof(*info));
	info->ipv4 = !netconfig->static_config[INDEX_FOR_AF(AF_INET)];
	info->ipv6 = !netconfig->static_config[INDEX_FOR_AF(AF_INET6)];
	info->dns = (info->ipv4 &&
			!netconfig->dns_overridden[INDEX_FOR_AF(AF_INET)]) ||
		(info->ipv6 &&
			!netconfig->dns_overridden[INDEX_FOR_AF(AF_INET)]);

	return true;
}

void netconfig_handle_fils_ip_resp(struct netconfig *netconfig,
			const struct ie_fils_ip_addr_response_info *info)
{
	l_free(netconfig->fils_override);
	netconfig->fils_override = l_memdup(info, sizeof(*info));
}

struct netconfig *netconfig_new(uint32_t ifindex)
{
	struct netdev *netdev = netdev_find(ifindex);
	struct netconfig *netconfig;
	const char *debug_level = NULL;
	int dhcp_priority = L_LOG_INFO;
	struct l_dhcp6_client *dhcp6;

	l_debug("Creating netconfig for interface: %d", ifindex);

	netconfig = l_new(struct netconfig, 1);
	netconfig->nc = l_netconfig_new(ifindex);
	netconfig->netdev = netdev;
	netconfig->resolve = resolve_new(ifindex);

	debug_level = getenv("IWD_DHCP_DEBUG");
	if (debug_level != NULL) {
		if (!strcmp("debug", debug_level))
			dhcp_priority = L_LOG_DEBUG;
		else if (!strcmp("info", debug_level))
			dhcp_priority = L_LOG_INFO;
		else if (!strcmp("warn", debug_level))
			dhcp_priority = L_LOG_WARNING;
		else if (!strcmp("error", debug_level))
			dhcp_priority = L_LOG_ERR;
		else	/* Default for backwards compatibility */
			dhcp_priority = L_LOG_DEBUG;
	}

	l_dhcp_client_set_debug(l_netconfig_get_dhcp_client(netconfig->nc),
				do_debug, "[DHCPv4] ", NULL, dhcp_priority);

	dhcp6 = l_netconfig_get_dhcp6_client(netconfig->nc);
	l_dhcp6_client_set_lla_randomized(dhcp6, true);
	l_dhcp6_client_set_nodelay(dhcp6, true);

	if (debug_level)
		l_dhcp6_client_set_debug(dhcp6, do_debug, "[DHCPv6] ", NULL);

	l_netconfig_set_route_priority(netconfig->nc, ROUTE_PRIORITY_OFFSET);

	return netconfig;
}

void netconfig_destroy(struct netconfig *netconfig)
{
	l_debug("");

	netconfig_reset(netconfig);
	resolve_free(netconfig->resolve);
	netconfig_free(netconfig);
}

bool netconfig_enabled(void)
{
	bool enabled;

	return l_settings_get_bool(iwd_get_config(), "General",
					"EnableNetworkConfiguration",
					&enabled) && enabled;
}

static int netconfig_init(void)
{
	if (!l_settings_get_uint(iwd_get_config(), "Network",
							"RoutePriorityOffset",
							&ROUTE_PRIORITY_OFFSET))
		ROUTE_PRIORITY_OFFSET = 300;

	if (!l_settings_get_bool(iwd_get_config(), "Network",
					"EnableIPv6",
					&ipv6_enabled))
		ipv6_enabled = false;

	return 0;
}

static void netconfig_exit(void)
{
}

IWD_MODULE(netconfig, netconfig_init, netconfig_exit)
