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
#include <netinet/in.h>
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

/*
 * Routing priority offset, configurable in main.conf. The route with lower
 * priority offset is preferred.
 */
static uint32_t ROUTE_PRIORITY_OFFSET;
static bool ipv6_enabled;
static char *mdns_global;

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

static bool netconfig_addr_to_str(uint8_t af, const void *v4_addr,
					const void *v6_addr, char *out_str,
					bool *out_is_zero)
{
	const void *addr = (af == AF_INET ? v4_addr : v6_addr);
	uint8_t bytes = (af == AF_INET ? 4 : 16);

	if (l_memeqzero(addr, bytes)) {
		*out_is_zero = true;
		return true;
	}

	*out_is_zero = false;

	if (L_WARN_ON(!inet_ntop(af, addr, out_str, INET6_ADDRSTRLEN)))
		return false;

	return true;
}

bool netconfig_use_fils_addr(struct netconfig *netconfig, int af)
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
	/* If the networks has this set take that over the global */
	if (l_settings_has_key(active_settings, "Network", "MulticastDNS")) {
		mdns = l_settings_get_string(active_settings, "Network",
							"MulticastDNS");
		if (!mdns) {
			l_error("netconfig: Can't load Network.MulticastDNS");
			success = false;
		}

		if (mdns && !L_IN_STRSET(mdns, "true", "false", "resolve")) {
			l_error("netconfig: Bad profile Network.MulticastDNS "
				"value '%s'", mdns);
			success = false;
		}

		if (!success)
			goto route_priority;
	}

	if (!mdns && mdns_global) {
		mdns = l_strdup(mdns_global);

		if (!L_IN_STRSET(mdns, "true", "false", "resolve")) {
			l_error("netconfig: Bad global Network.MulticastDNS "
				"value '%s'", mdns);
			success = false;
		}
	}

route_priority:
	l_netconfig_set_route_priority(netconfig->nc, ROUTE_PRIORITY_OFFSET);
	l_netconfig_set_optimistic_dad_enabled(netconfig->nc, true);

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

static bool netconfig_load_fils_settings(struct netconfig *netconfig,
						uint8_t af)
{
	struct ie_fils_ip_addr_response_info *fils = netconfig->fils_override;
	char addr_str[INET6_ADDRSTRLEN];
	char gw_addr_str[INET6_ADDRSTRLEN];
	char dns_addr_str[INET6_ADDRSTRLEN];
	_auto_(l_rtnl_address_free) struct l_rtnl_address *rtnl_addr = NULL;
	bool is_zero = false;
	uint8_t prefix_len;

	if (!netconfig_addr_to_str(af, &fils->ipv4_addr, &fils->ipv6_addr,
					addr_str, &is_zero) || is_zero)
		return is_zero;

	prefix_len = (af == AF_INET ? fils->ipv4_prefix_len :
			fils->ipv6_prefix_len);

	if (L_WARN_ON(!(rtnl_addr = l_rtnl_address_new(addr_str, prefix_len))))
		return false;

	if (L_WARN_ON(!l_netconfig_set_static_addr(netconfig->nc, af,
							rtnl_addr)))
		return false;

	if (af == AF_INET &&
			L_WARN_ON(!l_netconfig_set_acd_enabled(netconfig->nc,
								false)))
		return false;

	/*
	 * Done with local address, move on to gateway and DNS.
	 *
	 * Since load_settings is called early, generally before the actual
	 * connection setup starts, and load_fils_settings is called after
	 * 802.11 Authentication & Association, we need to check if either
	 * the gateway or DNS settings were overridden in load_settings so
	 * as not to overwrite the user-provided values.  Values received
	 * with FILS are expected to have the same weight as those from
	 * DHCP/SLAAC.
	 *
	 * TODO: If netconfig->fils_override->ipv{4,6}_lifetime is set,
	 * start a timeout to renew the address using FILS IP Address
	 * Assignment or perhaps just start the DHCP client after that
	 * time.
	 *
	 * TODO: validate gateway and/or DNS on local subnet, link-local,
	 * etc.?
	 */

	if (!netconfig_addr_to_str(af, &fils->ipv4_gateway, &fils->ipv6_gateway,
					gw_addr_str, &is_zero))
		return false;

	if (!netconfig->gateway_overridden[INDEX_FOR_AF(af)] && !is_zero &&
			L_WARN_ON(!l_netconfig_set_gateway_override(
								netconfig->nc,
								af,
								gw_addr_str)))
		return false;

	if (!netconfig_addr_to_str(af, &fils->ipv4_dns, &fils->ipv6_dns,
					dns_addr_str, &is_zero))
		return is_zero;

	if (!netconfig->dns_overridden[INDEX_FOR_AF(af)] && !is_zero) {
		char *dns_list[2] = { dns_addr_str, NULL };

		if (L_WARN_ON(!l_netconfig_set_dns_override(netconfig->nc,
								af, dns_list)))
			return false;
	}

	return true;
}

bool netconfig_configure(struct netconfig *netconfig,
				netconfig_notify_func_t notify, void *user_data)
{
	if (netconfig->started)
		return false;

	netconfig->notify = notify;
	netconfig->user_data = user_data;

	if (netconfig_use_fils_addr(netconfig, AF_INET) &&
			!netconfig_load_fils_settings(netconfig, AF_INET))
		return false;

	if (netconfig_use_fils_addr(netconfig, AF_INET6) &&
			!netconfig_load_fils_settings(netconfig, AF_INET6))
		return false;

	if (unlikely(!l_netconfig_start(netconfig->nc)))
		return false;

	netconfig->started = true;
	return true;
}

bool netconfig_reconfigure(struct netconfig *netconfig, bool set_arp_gw)
{
	if (!netconfig->started)
		return false;

	/*
	 * Starting with kernel 4.20, ARP cache is flushed when the netdev
	 * detects NO CARRIER.  This can result in unnecessarily long delays
	 * (about 1 second on some networks) due to ARP query response being
	 * lost or delayed.  Try to force the gateway into the ARP cache
	 * to alleviate this
	 */
	if (set_arp_gw) {
		netconfig_dhcp_gateway_to_arp(netconfig);

		if (netconfig->connected[INDEX_FOR_AF(AF_INET)] &&
				netconfig_use_fils_addr(netconfig, AF_INET))
			netconfig_commit_fils_macs(netconfig, AF_INET);

		if (netconfig->connected[INDEX_FOR_AF(AF_INET6)] &&
				netconfig_use_fils_addr(netconfig, AF_INET6))
			netconfig_commit_fils_macs(netconfig, AF_INET6);
	}

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
	if (!netconfig->started)
		return false;

	netconfig->started = false;
	l_netconfig_unconfigure(netconfig->nc);
	l_netconfig_stop(netconfig->nc);

	netconfig->connected[0] = false;
	netconfig->connected[1] = false;

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

static void netconfig_event_handler(struct l_netconfig *nc, uint8_t family,
					enum l_netconfig_event event,
					void *user_data)
{
	struct netconfig *netconfig = user_data;

	/* Once stopped, only commit a final L_NETCONFIG_EVENT_UNCONFIGURE */
	if (!netconfig->started && event != L_NETCONFIG_EVENT_UNCONFIGURE)
		return;

	l_debug("l_netconfig event %d", event);

	netconfig_commit(netconfig, family, event);

	switch (event) {
	case L_NETCONFIG_EVENT_CONFIGURE:
	case L_NETCONFIG_EVENT_UPDATE:
		break;

	case L_NETCONFIG_EVENT_UNCONFIGURE:
		break;

	case L_NETCONFIG_EVENT_FAILED:
		netconfig->connected[INDEX_FOR_AF(family)] = false;

		/*
		 * l_netconfig might have emitted an UNCONFIGURE before this
		 * but now it tells us it's given up on (re)establishing the
		 * IP setup.
		 */
		if (family == AF_INET && netconfig->notify)
			netconfig->notify(NETCONFIG_EVENT_FAILED,
						netconfig->user_data);

		break;

	default:
		l_error("netconfig: Received unsupported l_netconfig event: %d",
			event);
	}
}

struct netconfig *netconfig_new(uint32_t ifindex)
{
	struct netdev *netdev = netdev_find(ifindex);
	struct netconfig *netconfig;
	const char *debug_level = NULL;
	int dhcp_priority = L_LOG_INFO;
	struct l_dhcp6_client *dhcp6;
	struct l_icmp6_client *icmp6;

	l_debug("Creating netconfig for interface: %d", ifindex);

	netconfig = l_new(struct netconfig, 1);
	netconfig->nc = l_netconfig_new(ifindex);
	netconfig->netdev = netdev;
	netconfig->resolve = resolve_new(ifindex);

	netconfig_commit_init(netconfig);

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

	l_netconfig_set_event_handler(netconfig->nc, netconfig_event_handler,
					netconfig, NULL);

	l_dhcp_client_set_debug(l_netconfig_get_dhcp_client(netconfig->nc),
				do_debug, "[DHCPv4] ", NULL, dhcp_priority);

	dhcp6 = l_netconfig_get_dhcp6_client(netconfig->nc);
	l_dhcp6_client_set_lla_randomized(dhcp6, true);

	icmp6 = l_netconfig_get_icmp6_client(netconfig->nc);
	l_icmp6_client_set_nodelay(icmp6, true);

	if (debug_level) {
		l_dhcp6_client_set_debug(dhcp6, do_debug, "[DHCPv6] ", NULL);
		l_icmp6_client_set_debug(icmp6, do_debug, "[ICMPv6] ", NULL);
	}

	return netconfig;
}

void netconfig_destroy(struct netconfig *netconfig)
{
	l_debug("");

	netconfig_reset(netconfig);
	netconfig_commit_free(netconfig, "aborted");
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
		ipv6_enabled = true;

	mdns_global = l_settings_get_string(iwd_get_config(), "Network",
						"MulticastDNS");

	return 0;
}

static void netconfig_exit(void)
{
	l_free(mdns_global);
}

IWD_MODULE(netconfig, netconfig_init, netconfig_exit)
