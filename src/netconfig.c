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
	uint32_t ifindex;
	uint8_t rtm_protocol;
	uint8_t rtm_v6_protocol;
	struct l_rtnl_address *v4_address;
	struct l_rtnl_address *v6_address;
	char **dns4_overrides;
	char **dns6_overrides;
	char **dns4_list;
	char **dns6_list;
	char *mdns;
	struct ie_fils_ip_addr_response_info *fils_override;
	char *v4_gateway_str;
	char *v6_gateway_str;
	char *v4_domain;
	char **v6_domains;

	const struct l_settings *active_settings;

	netconfig_notify_func_t notify;
	void *user_data;

	struct resolve *resolve;
};

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
	l_rtnl_address_free(netconfig->v4_address);
	netconfig->v4_address = NULL;
	l_rtnl_address_free(netconfig->v6_address);
	netconfig->v6_address = NULL;

	l_strfreev(netconfig->dns4_overrides);
	netconfig->dns4_overrides = NULL;
	l_strfreev(netconfig->dns6_overrides);
	netconfig->dns6_overrides = NULL;

	l_free(netconfig->mdns);
	netconfig->mdns = NULL;
}

static void netconfig_free(void *data)
{
	struct netconfig *netconfig = data;

	l_free(netconfig);
}

static bool netconfig_use_fils_addr(struct netconfig *netconfig, int af)
{
	if ((af == AF_INET ? netconfig->rtm_protocol :
				netconfig->rtm_v6_protocol) != RTPROT_DHCP)
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
	struct l_rtnl_address *ifaddr = NULL;
	L_AUTO_FREE_VAR(char *, ip) = NULL;
	L_AUTO_FREE_VAR(char *, netmask) = NULL;
	struct in_addr in_addr;
	L_AUTO_FREE_VAR(char *, broadcast) = NULL;
	uint32_t prefix_len;

	ip = l_settings_get_string(active_settings, "IPv4", "Address");
	if (!ip)
		return NULL;

	netmask = l_settings_get_string(active_settings, "IPv4", "Netmask");
	if (netmask) {
		if (inet_pton(AF_INET, netmask, &in_addr) != 1) {
			l_error("netconfig: Can't parse IPv4 Netmask");
			return NULL;
		}

		prefix_len = __builtin_popcountl(in_addr.s_addr);

		if (ntohl(in_addr.s_addr) !=
				util_netmask_from_prefix(prefix_len)) {
			l_error("netconfig: Invalid IPv4 Netmask");
			return NULL;
		}
	} else
		prefix_len = 24;

	ifaddr = l_rtnl_address_new(ip, prefix_len);
	if (!ifaddr) {
		l_error("netconfig: Unable to parse IPv4.Address");
		return NULL;
	}

	broadcast = l_settings_get_string(active_settings, "IPv4", "Broadcast");
	if (broadcast && !l_rtnl_address_set_broadcast(ifaddr, broadcast)) {
		l_error("netconfig: Unable to parse IPv4.Broadcast");
		l_rtnl_address_free(ifaddr);
		return NULL;
	}

	l_rtnl_address_set_noprefixroute(ifaddr, true);
	return ifaddr;
}

static struct l_rtnl_address *netconfig_get_static6_address(
				const struct l_settings *active_settings)
{
	L_AUTO_FREE_VAR(char *, ip);
	char *p;
	char *endp;
	struct l_rtnl_address *ret;
	uint32_t prefix_len = 128;

	ip = l_settings_get_string(active_settings, "IPv6", "Address");
	if (!ip)
		return NULL;

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
	if (!ret)
		l_error("netconfig: Invalid IPv6 address %s is "
				"provided in network configuration file.", ip);

	return ret;
}

static void netconfig_gateway_to_arp(struct netconfig *netconfig)
{
	struct l_dhcp_client *dhcp = NULL; /* TODO */
	const struct l_dhcp_lease *lease;
	_auto_(l_free) char *server_id = NULL;
	_auto_(l_free) char *gw = NULL;
	const uint8_t *server_mac;
	struct in_addr in_gw;

	/* Can only do this for DHCP in certain network setups */
	if (netconfig->rtm_protocol != RTPROT_DHCP)
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

static void netconfig_remove_v4_address(struct netconfig *netconfig)
{
	if (!netconfig->v4_address)
		return;

	l_rtnl_address_free(netconfig->v4_address);
	netconfig->v4_address = NULL;
}

static void netconfig_reset_v4(struct netconfig *netconfig)
{
	if (netconfig->rtm_protocol) {
		netconfig_remove_v4_address(netconfig);

		l_strv_free(l_steal_ptr(netconfig->dns4_overrides));
		l_strv_free(l_steal_ptr(netconfig->dns4_list));

		netconfig->rtm_protocol = 0;

		l_free(l_steal_ptr(netconfig->v4_gateway_str));

		l_free(l_steal_ptr(netconfig->v4_domain));
	}
}

static int validate_dns_list(int family, char **dns_list)
{
	unsigned int n_valid = 0;
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	char **p;

	for (p = dns_list; *p; p++) {
		int r;

		if (family == AF_INET)
			r = inet_pton(AF_INET, *p, &in_addr);
		else if (family == AF_INET6)
			r = inet_pton(AF_INET6, *p, &in6_addr);
		else
			r = -EAFNOSUPPORT;

		if (r > 0) {
			n_valid += 1;
			continue;
		}

		l_error("netconfig: Invalid DNS address '%s'.", *p);
		return -EINVAL;
	}

	return n_valid;
}

bool netconfig_load_settings(struct netconfig *netconfig,
				const struct l_settings *active_settings)
{
	_auto_(l_free) char *mdns = NULL;
	bool send_hostname;
	bool v6_enabled;
	char hostname[HOST_NAME_MAX + 1];
	_auto_(l_strv_free) char **dns4_overrides = NULL;
	_auto_(l_strv_free) char **dns6_overrides = NULL;
	_auto_(l_rtnl_address_free) struct l_rtnl_address *v4_address = NULL;
	_auto_(l_rtnl_address_free) struct l_rtnl_address *v6_address = NULL;

	dns4_overrides = l_settings_get_string_list(active_settings,
							"IPv4", "DNS", ' ');
	if (dns4_overrides) {
		int r = validate_dns_list(AF_INET, dns4_overrides);

		if (unlikely(r <= 0)) {
			l_strfreev(dns4_overrides);
			dns4_overrides = NULL;

			if (r < 0)
				return false;
		}

		if (r == 0)
			l_error("netconfig: Empty IPv4.DNS entry, skipping...");
	}

	dns6_overrides = l_settings_get_string_list(active_settings,
							"IPv6", "DNS", ' ');

	if (dns6_overrides) {
		int r = validate_dns_list(AF_INET6, dns6_overrides);

		if (unlikely(r <= 0)) {
			l_strfreev(dns6_overrides);
			dns6_overrides = NULL;

			if (r < 0)
				return false;
		}

		if (r == 0)
			l_error("netconfig: Empty IPv6.DNS entry, skipping...");
	}

	if (!l_settings_get_bool(active_settings,
					"IPv4", "SendHostname", &send_hostname))
		send_hostname = false;

	if (send_hostname) {
		if (gethostname(hostname, sizeof(hostname)) != 0) {
			l_warn("netconfig: Unable to get hostname. "
					"Error %d: %s", errno, strerror(errno));
			send_hostname = false;
		}
	}

	mdns = l_settings_get_string(active_settings,
					"Network", "MulticastDNS");

	if (l_settings_has_key(active_settings, "IPv4", "Address")) {
		v4_address = netconfig_get_static4_address(active_settings);

		if (unlikely(!v4_address)) {
			l_error("netconfig: Can't parse IPv4 address");
			return false;
		}
	}

	if (!l_settings_get_bool(active_settings, "IPv6",
					"Enabled", &v6_enabled))
		v6_enabled = ipv6_enabled;

	if (l_settings_has_key(active_settings, "IPv6", "Address")) {
		v6_address = netconfig_get_static6_address(active_settings);

		if (unlikely(!v6_address)) {
			l_error("netconfig: Can't parse IPv6 address");
			return false;
		}
	}

	/* No more validation steps for now, commit new values */
	netconfig->rtm_protocol = v4_address ? RTPROT_STATIC : RTPROT_DHCP;

	if (!v6_enabled)
		netconfig->rtm_v6_protocol = RTPROT_UNSPEC;
	else if (v6_address)
		netconfig->rtm_v6_protocol = RTPROT_STATIC;
	else
		netconfig->rtm_v6_protocol = RTPROT_DHCP;

	netconfig_free_settings(netconfig);

	if (netconfig->rtm_protocol == RTPROT_STATIC)
		netconfig->v4_address = l_steal_ptr(v4_address);

	if (netconfig->rtm_v6_protocol == RTPROT_STATIC)
		netconfig->v6_address = l_steal_ptr(v6_address);

	netconfig->active_settings = active_settings;
	netconfig->dns4_overrides = l_steal_ptr(dns4_overrides);
	netconfig->dns6_overrides = l_steal_ptr(dns6_overrides);
	netconfig->mdns = l_steal_ptr(mdns);
	return true;
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
	netconfig_reset_v4(netconfig);

	if (netconfig->rtm_v6_protocol) {
		l_rtnl_address_free(netconfig->v6_address);
		netconfig->v6_address = NULL;

		l_strv_free(l_steal_ptr(netconfig->dns6_overrides));
		l_strv_free(l_steal_ptr(netconfig->dns6_list));

		netconfig->rtm_v6_protocol = 0;

		l_free(l_steal_ptr(netconfig->v6_gateway_str));

		l_strv_free(l_steal_ptr(netconfig->v6_domains));
	}

	l_free(l_steal_ptr(netconfig->fils_override));

	return true;
}

char *netconfig_get_dhcp_server_ipv4(struct netconfig *netconfig)
{
	struct l_dhcp_client *client = NULL; /* TODO */
	const struct l_dhcp_lease *lease;

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
	if (netconfig->rtm_protocol != RTPROT_DHCP &&
			netconfig->rtm_v6_protocol != RTPROT_DHCP)
		return false;

	memset(info, 0, sizeof(*info));
	info->ipv4 = (netconfig->rtm_protocol == RTPROT_DHCP);
	info->ipv6 = (netconfig->rtm_v6_protocol == RTPROT_DHCP);
	info->dns = (info->ipv4 && !netconfig->dns4_overrides) ||
		(info->ipv6 && !netconfig->dns6_overrides);

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
	struct l_dhcp_client *dhcp = NULL; /* TODO */
	struct l_dhcp6_client *dhcp6 = NULL; /* TODO */

	l_debug("Starting netconfig for interface: %d", ifindex);

	netconfig = l_new(struct netconfig, 1);
	netconfig->ifindex = ifindex;
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

	l_dhcp_client_set_debug(dhcp, do_debug, "[DHCPv4] ", NULL,
				dhcp_priority);

	l_dhcp6_client_set_lla_randomized(dhcp6, true);
	l_dhcp6_client_set_nodelay(dhcp6, true);

	if (getenv("IWD_DHCP_DEBUG"))
		l_dhcp6_client_set_debug(dhcp6, do_debug, "[DHCPv6] ", NULL);

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
