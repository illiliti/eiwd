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

struct netconfig {
	uint32_t ifindex;
	struct l_dhcp_client *dhcp_client;
	struct l_dhcp6_client *dhcp6_client;
	uint8_t rtm_protocol;
	uint8_t rtm_v6_protocol;
	struct l_rtnl_address *v4_address;
	char **dns4_overrides;
	char **dns6_overrides;
	struct ie_fils_ip_addr_response_info *fils_override;

	const struct l_settings *active_settings;

	netconfig_notify_func_t notify;
	void *user_data;

	struct resolve *resolve;

	struct l_acd *acd;

	uint32_t addr4_add_cmd_id;
	uint32_t addr6_add_cmd_id;
	uint32_t route4_add_gateway_cmd_id;
};

static struct l_netlink *rtnl;
static struct l_queue *netconfig_list;

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

static int write_string(const char *file, const char *value)
{
	size_t l = strlen(value);
	int fd;
	int r;

	fd = L_TFR(open(file, O_WRONLY));
	if (fd < 0)
		return -errno;

	r = L_TFR(write(fd, value, l));
	L_TFR(close(fd));

	return r;
}

static int sysfs_write_ipv6_setting(const char *ifname, const char *setting,
					const char *value)
{
	int r;

	L_AUTO_FREE_VAR(char *, file) =
		l_strdup_printf("/proc/sys/net/ipv6/conf/%s/%s",
							ifname, setting);

	r = write_string(file, value);
	if (r < 0)
		l_error("Unable to write %s to %s", setting, file);

	return r;
}

static void netconfig_free(void *data)
{
	struct netconfig *netconfig = data;

	l_dhcp_client_destroy(netconfig->dhcp_client);
	l_dhcp6_client_destroy(netconfig->dhcp6_client);

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

#define APPEND_STRDUPV(dest, index, src)			\
	do {							\
		char **p;					\
		for (p = src; p && *p; p++)			\
			dest[index++] = l_strdup(*p);		\
	} while (0)						\

#define APPENDV(dest, index, src)				\
	do {							\
		char **p;					\
		for (p = src; p && *p; p++)			\
			dest[index++] = *p;			\
	} while (0)						\

static inline char *netconfig_ipv4_to_string(uint32_t addr)
{
	struct in_addr in_addr = { .s_addr = addr };
	char *addr_str = l_malloc(INET_ADDRSTRLEN);

	if (L_WARN_ON(unlikely(!inet_ntop(AF_INET, &in_addr, addr_str,
						INET_ADDRSTRLEN)))) {
		l_free(addr_str);
		return NULL;
	}

	return addr_str;
}

static inline char *netconfig_ipv6_to_string(const uint8_t *addr)
{
	struct in6_addr in6_addr;
	char *addr_str = l_malloc(INET6_ADDRSTRLEN);

	memcpy(in6_addr.s6_addr, addr, 16);

	if (L_WARN_ON(unlikely(!inet_ntop(AF_INET6, &in6_addr, addr_str,
						INET6_ADDRSTRLEN)))) {
		l_free(addr_str);
		return NULL;
	}

	return addr_str;
}

static void netconfig_set_neighbor_entry_cb(int error,
						uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	if (error)
		l_error("l_rtnl_neighbor_set_hwaddr failed: %s (%i)",
			strerror(-error), error);
}

static int netconfig_set_dns(struct netconfig *netconfig)
{
	char **dns6_list = NULL;
	char **dns4_list = NULL;
	unsigned int n_entries = 0;
	char **dns_list;
	const uint8_t *fils_dns4_mac = NULL;
	const uint8_t *fils_dns6_mac = NULL;
	const struct ie_fils_ip_addr_response_info *fils =
		netconfig->fils_override;

	if (!netconfig->dns4_overrides &&
			netconfig->rtm_protocol == RTPROT_DHCP) {
		const struct l_dhcp_lease *lease;

		if (fils && fils->ipv4_dns) {
			dns4_list = l_new(char *, 2);
			dns4_list[0] = netconfig_ipv4_to_string(fils->ipv4_dns);

			if (!l_memeqzero(fils->ipv4_dns_mac, 6) &&
					util_ip_subnet_match(
							fils->ipv4_prefix_len,
							&fils->ipv4_addr,
							&fils->ipv4_dns))
				fils_dns4_mac = fils->ipv4_dns_mac;
		} else if ((lease = l_dhcp_client_get_lease(
						netconfig->dhcp_client)))
			dns4_list = l_dhcp_lease_get_dns(lease);
	}

	if (!netconfig->dns6_overrides &&
			netconfig->rtm_v6_protocol == RTPROT_DHCP) {
		const struct l_dhcp6_lease *lease;

		if (fils && !l_memeqzero(fils->ipv6_dns,
						16)) {
			dns6_list = l_new(char *, 2);
			dns6_list[0] = netconfig_ipv6_to_string(fils->ipv6_dns);

			if (!l_memeqzero(fils->ipv6_dns_mac, 6) &&
					util_ip_subnet_match(
							fils->ipv6_prefix_len,
							fils->ipv6_addr,
							fils->ipv6_dns))
				fils_dns6_mac = fils->ipv6_dns_mac;
		} else if ((lease = l_dhcp6_client_get_lease(
						netconfig->dhcp6_client)))
			dns6_list = l_dhcp6_lease_get_dns(lease);
	}

	n_entries += l_strv_length(netconfig->dns4_overrides);
	n_entries += l_strv_length(netconfig->dns6_overrides);
	n_entries += l_strv_length(dns4_list);
	n_entries += l_strv_length(dns6_list);

	dns_list = l_new(char *, n_entries + 1);
	n_entries = 0;

	APPEND_STRDUPV(dns_list, n_entries, netconfig->dns4_overrides);
	APPENDV(dns_list, n_entries, dns4_list);
	APPEND_STRDUPV(dns_list, n_entries, netconfig->dns6_overrides);
	APPENDV(dns_list, n_entries, dns6_list);
	resolve_set_dns(netconfig->resolve, dns_list);

	if (fils_dns4_mac && !l_rtnl_neighbor_set_hwaddr(rtnl,
					netconfig->ifindex, AF_INET,
					&fils->ipv4_dns, fils_dns4_mac, 6,
					netconfig_set_neighbor_entry_cb, NULL,
					NULL))
		l_debug("l_rtnl_neighbor_set_hwaddr failed");

	if (fils_dns6_mac && !l_rtnl_neighbor_set_hwaddr(rtnl,
					netconfig->ifindex, AF_INET6,
					fils->ipv6_dns, fils_dns6_mac, 6,
					netconfig_set_neighbor_entry_cb, NULL,
					NULL))
		l_debug("l_rtnl_neighbor_set_hwaddr failed");

	l_strv_free(dns_list);
	/* Contents belonged to dns_list, so not l_strfreev */
	l_free(dns4_list);
	l_free(dns6_list);
	return 0;
}

static void append_domain(char **domains, unsigned int *n_domains,
				size_t max, char *domain)
{
	unsigned int i;

	if (*n_domains == max)
		return;

	for (i = 0; i < *n_domains; i++)
		if (!strcmp(domains[i], domain))
			return;

	domains[*n_domains] = domain;
	*n_domains += 1;
}

static int netconfig_set_domains(struct netconfig *netconfig)
{
	char *domains[31];
	unsigned int n_domains = 0;
	char *v4_domain = NULL;
	char **v6_domains = NULL;
	char **p;

	memset(domains, 0, sizeof(domains));

	/* Allow to override the DHCP domain name with setting entry. */
	v4_domain = l_settings_get_string(netconfig->active_settings,
							"IPv4", "DomainName");
	if (!v4_domain && netconfig->rtm_protocol == RTPROT_DHCP) {
		const struct l_dhcp_lease *lease =
			l_dhcp_client_get_lease(netconfig->dhcp_client);

		if (lease)
			v4_domain = l_dhcp_lease_get_domain_name(lease);
	}

	append_domain(domains, &n_domains,
					L_ARRAY_SIZE(domains) - 1, v4_domain);

	if (netconfig->rtm_v6_protocol == RTPROT_DHCP) {
		const struct l_dhcp6_lease *lease =
			l_dhcp6_client_get_lease(netconfig->dhcp6_client);

		if (lease)
			v6_domains = l_dhcp6_lease_get_domains(lease);
	}

	for (p = v6_domains; p && *p; p++)
		append_domain(domains, &n_domains,
					L_ARRAY_SIZE(domains) - 1, *p);

	resolve_set_domains(netconfig->resolve, domains);
	l_strv_free(v6_domains);
	l_free(v4_domain);

	return 0;
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

static char *netconfig_ipv4_get_gateway(struct netconfig *netconfig,
					const uint8_t **out_mac)
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
		if (netconfig->fils_override &&
				netconfig->fils_override->ipv4_gateway) {
			gateway = netconfig_ipv4_to_string(
					netconfig->fils_override->ipv4_gateway);

			if (gateway && !l_memeqzero(netconfig->fils_override->
							ipv4_gateway_mac, 6))
				*out_mac = netconfig->fils_override->
					ipv4_gateway_mac;

			return gateway;
		}

		lease = l_dhcp_client_get_lease(netconfig->dhcp_client);
		if (!lease)
			return NULL;

		return l_dhcp_lease_get_gateway(lease);
	}

	return NULL;
}

static struct l_rtnl_address *netconfig_get_static6_address(
				const struct l_settings *active_settings)
{
	L_AUTO_FREE_VAR(char *, ip);
	char *p;
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

	prefix_len = strtoul(p, NULL, 10);
	if (!unlikely(errno == EINVAL || errno == ERANGE ||
			!prefix_len || prefix_len > 128)) {
		l_error("netconfig: Invalid prefix '%s'  provided in network"
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

static struct l_rtnl_route *netconfig_get_static6_gateway(
						struct netconfig *netconfig,
						const uint8_t **out_mac)
{
	L_AUTO_FREE_VAR(char *, gateway);
	struct l_rtnl_route *ret;

	gateway = l_settings_get_string(netconfig->active_settings,
						"IPv6", "Gateway");
	if (!gateway && netconfig->rtm_v6_protocol == RTPROT_DHCP &&
			netconfig->fils_override &&
			!l_memeqzero(netconfig->fils_override->ipv6_gateway,
					16)) {
		gateway = netconfig_ipv6_to_string(
					netconfig->fils_override->ipv6_gateway);

		if (!l_memeqzero(netconfig->fils_override->ipv6_gateway_mac, 6))
			*out_mac = netconfig->fils_override->ipv6_gateway_mac;
	} else if (!gateway)
		return NULL;

	ret = l_rtnl_route_new_gateway(gateway);
	if (!ret) {
		l_error("netconfig: Invalid IPv6 gateway address %s is "
			"provided in network configuration file.",
			gateway);
		return ret;
	}

	l_rtnl_route_set_priority(ret, ROUTE_PRIORITY_OFFSET);
	l_rtnl_route_set_protocol(ret, RTPROT_STATIC);

	return ret;
}

static struct l_rtnl_address *netconfig_get_dhcp4_address(
						struct netconfig *netconfig)
{
	const struct l_dhcp_lease *lease =
			l_dhcp_client_get_lease(netconfig->dhcp_client);
	L_AUTO_FREE_VAR(char *, ip) = NULL;
	L_AUTO_FREE_VAR(char *, netmask) = NULL;
	L_AUTO_FREE_VAR(char *, broadcast) = NULL;
	struct in_addr in_addr;
	uint32_t prefix_len;
	struct l_rtnl_address *ret;

	if (L_WARN_ON(!lease))
		return NULL;

	ip = l_dhcp_lease_get_address(lease);
	netmask = l_dhcp_lease_get_netmask(lease);
	broadcast = l_dhcp_lease_get_broadcast(lease);

	if (netmask && inet_pton(AF_INET, netmask, &in_addr) > 0)
		prefix_len = __builtin_popcountl(in_addr.s_addr);
	else
		prefix_len = 24;

	ret = l_rtnl_address_new(ip, prefix_len);
	if (!ret)
		return ret;

	if (broadcast)
		l_rtnl_address_set_broadcast(ret, broadcast);

	l_rtnl_address_set_noprefixroute(ret, true);
	return ret;
}

static void netconfig_ifaddr_added(struct netconfig *netconfig,
					const struct ifaddrmsg *ifa,
					uint32_t len)
{
	L_AUTO_FREE_VAR(char *, label) = NULL;
	L_AUTO_FREE_VAR(char *, ip) = NULL;
	L_AUTO_FREE_VAR(char *, broadcast) = NULL;

	l_rtnl_ifaddr4_extract(ifa, len, &label, &ip, &broadcast);
	l_debug("%s: ifaddr %s/%u broadcast %s", label,
					ip, ifa->ifa_prefixlen, broadcast);
}

static void netconfig_ifaddr_deleted(struct netconfig *netconfig,
					const struct ifaddrmsg *ifa,
					uint32_t len)
{
	L_AUTO_FREE_VAR(char *, ip);

	l_rtnl_ifaddr4_extract(ifa, len, NULL, &ip, NULL);
	l_debug("ifaddr %s/%u", ip, ifa->ifa_prefixlen);
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
	struct in6_addr in6;
	L_AUTO_FREE_VAR(char *, ip) = NULL;

	if (ifa->ifa_flags & IFA_F_TENTATIVE)
		return;

	l_rtnl_ifaddr6_extract(ifa, len, &ip);

	l_debug("ifindex %u: ifaddr %s/%u", netconfig->ifindex,
			ip, ifa->ifa_prefixlen);

	if (netconfig->rtm_v6_protocol != RTPROT_DHCP ||
			(netconfig->fils_override &&
			 !l_memeqzero(netconfig->fils_override->ipv6_addr, 16)))
		return;

	inet_pton(AF_INET6, ip, &in6);
	if (!IN6_IS_ADDR_LINKLOCAL(&in6))
		return;

	l_dhcp6_client_set_link_local_address(netconfig->dhcp6_client, ip);

	if (l_dhcp6_client_start(netconfig->dhcp6_client))
		return;

	l_error("netconfig: Failed to start DHCPv6 client for "
			"interface %u", netconfig->ifindex);
}

static void netconfig_ifaddr_ipv6_deleted(struct netconfig *netconfig,
						const struct ifaddrmsg *ifa,
						uint32_t len)
{
	L_AUTO_FREE_VAR(char *, ip);

	l_rtnl_ifaddr6_extract(ifa, len, &ip);
	l_debug("ifindex %u: ifaddr %s/%u", netconfig->ifindex,
			ip, ifa->ifa_prefixlen);
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

static void netconfig_route_generic_cb(int error, uint16_t type,
					const void *data, uint32_t len,
					void *user_data)
{
	if (error) {
		l_error("netconfig: Failed to add route. Error %d: %s",
						error, strerror(-error));
		return;
	}
}

static void netconfig_route_add_cmd_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	struct netconfig *netconfig = user_data;

	netconfig->route4_add_gateway_cmd_id = 0;

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

static bool netconfig_ipv4_routes_install(struct netconfig *netconfig)
{
	L_AUTO_FREE_VAR(char *, gateway) = NULL;
	const uint8_t *gateway_mac = NULL;
	struct in_addr in_addr;
	char ip[INET_ADDRSTRLEN];
	char network[INET_ADDRSTRLEN];
	unsigned int prefix_len =
		l_rtnl_address_get_prefix_length(netconfig->v4_address);

	if (!l_rtnl_address_get_address(netconfig->v4_address, ip) ||
			inet_pton(AF_INET, ip, &in_addr) < 1)
		return false;

	in_addr.s_addr = in_addr.s_addr &
				htonl(0xFFFFFFFFLU << (32 - prefix_len));

	if (!inet_ntop(AF_INET, &in_addr, network, INET_ADDRSTRLEN))
		return false;

	if (!l_rtnl_route4_add_connected(rtnl, netconfig->ifindex,
						prefix_len, network, ip,
						netconfig->rtm_protocol,
						netconfig_route_generic_cb,
						netconfig, NULL)) {
		l_error("netconfig: Failed to add subnet route.");

		return false;
	}

	gateway = netconfig_ipv4_get_gateway(netconfig, &gateway_mac);
	if (!gateway) {
		l_debug("No gateway obtained from %s.",
				netconfig->rtm_protocol == RTPROT_STATIC ?
				"setting file" : "DHCPv4 lease");

		if (netconfig->notify) {
			netconfig->notify(NETCONFIG_EVENT_CONNECTED,
						netconfig->user_data);
			netconfig->notify = NULL;
		}

		return true;
	}

	netconfig->route4_add_gateway_cmd_id =
		l_rtnl_route4_add_gateway(rtnl, netconfig->ifindex, gateway, ip,
						ROUTE_PRIORITY_OFFSET,
						netconfig->rtm_protocol,
						netconfig_route_add_cmd_cb,
						netconfig, NULL);
	if (!netconfig->route4_add_gateway_cmd_id) {
		l_error("netconfig: Failed to add route for: %s gateway.",
								gateway);

		return false;
	}

	if (gateway_mac) {
		/*
		 * Attempt to use the gateway MAC address received from the AP
		 * by writing the mapping directly into the netdev's ARP table
		 * so as to save one data frame roundtrip before first IP
		 * connections are established.  This is very low-priority but
		 * print error messages just because they may indicate bigger
		 * problems.
		 */
		if (!l_rtnl_neighbor_set_hwaddr(rtnl, netconfig->ifindex,
					AF_INET,
					&netconfig->fils_override->ipv4_gateway,
					gateway_mac, 6,
					netconfig_set_neighbor_entry_cb, NULL,
					NULL))
			l_debug("l_rtnl_neighbor_set_hwaddr failed");
	}

	return true;
}

static void netconfig_ipv4_ifaddr_add_cmd_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	struct netconfig *netconfig = user_data;

	netconfig->addr4_add_cmd_id = 0;

	if (error && error != -EEXIST) {
		l_error("netconfig: Failed to add IP address. "
				"Error %d: %s", error, strerror(-error));
		return;
	}

	if (!netconfig_ipv4_routes_install(netconfig)) {
		l_error("netconfig: Failed to install IPv4 routes.");
		return;
	}

	netconfig_set_dns(netconfig);
	netconfig_set_domains(netconfig);
}

static void netconfig_ipv6_ifaddr_add_cmd_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	struct netconfig *netconfig = user_data;
	struct l_rtnl_route *gateway;
	const uint8_t *gateway_mac = NULL;

	netconfig->addr6_add_cmd_id = 0;

	if (error && error != -EEXIST) {
		l_error("netconfig: Failed to add IPv6 address. "
				"Error %d: %s", error, strerror(-error));
		return;
	}

	gateway = netconfig_get_static6_gateway(netconfig, &gateway_mac);
	if (gateway) {
		L_WARN_ON(!l_rtnl_route_add(rtnl, netconfig->ifindex,
						gateway,
						netconfig_route_generic_cb,
						netconfig, NULL));
		l_rtnl_route_free(gateway);

		if (gateway_mac && !l_rtnl_neighbor_set_hwaddr(rtnl,
					netconfig->ifindex, AF_INET6,
					netconfig->fils_override->ipv6_gateway,
					gateway_mac, 6,
					netconfig_set_neighbor_entry_cb, NULL,
					NULL))
			l_debug("l_rtnl_neighbor_set_hwaddr failed");
	}

	netconfig_set_dns(netconfig);
	netconfig_set_domains(netconfig);
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

static void netconfig_ipv4_dhcp_event_handler(struct l_dhcp_client *client,
						enum l_dhcp_client_event event,
						void *userdata)
{
	struct netconfig *netconfig = userdata;

	l_debug("DHCPv4 event %d", event);

	switch (event) {
	case L_DHCP_CLIENT_EVENT_IP_CHANGED:
		L_WARN_ON(!l_rtnl_ifaddr_delete(rtnl, netconfig->ifindex,
					netconfig->v4_address,
					netconfig_ifaddr_del_cmd_cb,
					netconfig, NULL));
		l_rtnl_address_free(netconfig->v4_address);
		/* Fall through. */
	case L_DHCP_CLIENT_EVENT_LEASE_OBTAINED:
		netconfig->v4_address = netconfig_get_dhcp4_address(netconfig);
		if (!netconfig->v4_address) {
			l_error("netconfig: Failed to obtain IP addresses from "
							"DHCPv4 lease.");
			return;
		}

		L_WARN_ON(!(netconfig->addr4_add_cmd_id =
				l_rtnl_ifaddr_add(rtnl, netconfig->ifindex,
					netconfig->v4_address,
					netconfig_ipv4_ifaddr_add_cmd_cb,
					netconfig, NULL)));
		break;
	case L_DHCP_CLIENT_EVENT_LEASE_RENEWED:
		break;
	case L_DHCP_CLIENT_EVENT_LEASE_EXPIRED:
		L_WARN_ON(!l_rtnl_ifaddr_delete(rtnl, netconfig->ifindex,
					netconfig->v4_address,
					netconfig_ifaddr_del_cmd_cb,
					netconfig, NULL));
		l_rtnl_address_free(netconfig->v4_address);
		netconfig->v4_address = NULL;

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

static void netconfig_dhcp6_event_handler(struct l_dhcp6_client *client,
						enum l_dhcp6_client_event event,
						void *userdata)
{
	struct netconfig *netconfig = userdata;

	switch (event) {
	case L_DHCP6_CLIENT_EVENT_IP_CHANGED:
	case L_DHCP6_CLIENT_EVENT_LEASE_OBTAINED:
	case L_DHCP6_CLIENT_EVENT_LEASE_RENEWED:
		netconfig_set_dns(netconfig);
		netconfig_set_domains(netconfig);
		break;
	case L_DHCP6_CLIENT_EVENT_LEASE_EXPIRED:
		l_debug("Lease for interface %u expired", netconfig->ifindex);
		netconfig_set_dns(netconfig);
		netconfig_set_domains(netconfig);

		/* Fall through */
	case L_DHCP6_CLIENT_EVENT_NO_LEASE:
		if (!l_dhcp6_client_start(netconfig->dhcp6_client))
			l_error("netconfig: Failed to re-start DHCPv6 client "
					"for interface %u", netconfig->ifindex);
		break;
	}
}

static void netconfig_remove_v4_address(struct netconfig *netconfig)
{
	if (!netconfig->v4_address)
		return;

	L_WARN_ON(!l_rtnl_ifaddr_delete(rtnl, netconfig->ifindex,
					netconfig->v4_address,
					netconfig_ifaddr_del_cmd_cb,
					netconfig, NULL));
	l_rtnl_address_free(netconfig->v4_address);
	netconfig->v4_address = NULL;
}

static void netconfig_reset_v4(struct netconfig *netconfig)
{
	if (netconfig->rtm_protocol) {
		netconfig_remove_v4_address(netconfig);

		l_strfreev(netconfig->dns4_overrides);
		netconfig->dns4_overrides = NULL;

		l_dhcp_client_stop(netconfig->dhcp_client);
		netconfig->rtm_protocol = 0;

		l_acd_destroy(netconfig->acd);
		netconfig->acd = NULL;
	}
}

static void netconfig_ipv4_acd_event(enum l_acd_event event, void *user_data)
{
	struct netconfig *netconfig = user_data;

	switch (event) {
	case L_ACD_EVENT_AVAILABLE:
		L_WARN_ON(!(netconfig->addr4_add_cmd_id =
				l_rtnl_ifaddr_add(rtnl, netconfig->ifindex,
					netconfig->v4_address,
					netconfig_ipv4_ifaddr_add_cmd_cb,
					netconfig, NULL)));
		return;
	case L_ACD_EVENT_CONFLICT:
		/*
		 * Conflict found, no IP was actually set so just free/unset
		 * anything we set prior to starting ACD.
		 */
		l_error("netconfig: statically configured address conflict!");
		l_rtnl_address_free(netconfig->v4_address);
		netconfig->v4_address = NULL;
		netconfig->rtm_protocol = 0;
		break;
	case L_ACD_EVENT_LOST:
		/*
		 * Set IP but lost it some time after. Full (IPv4) reset in this
		 * case.
		 */
		l_error("netconfig: statically configured address was lost");
		netconfig_remove_v4_address(netconfig);
		break;
	}
}

static bool netconfig_ipv4_select_and_install(struct netconfig *netconfig)
{
	bool set_address = (netconfig->rtm_protocol == RTPROT_STATIC);

	if (netconfig->rtm_protocol == RTPROT_DHCP &&
			netconfig->fils_override &&
			netconfig->fils_override->ipv4_addr) {
		L_AUTO_FREE_VAR(char *, addr_str) = netconfig_ipv4_to_string(
					netconfig->fils_override->ipv4_addr);
		uint8_t prefix_len = netconfig->fils_override->ipv4_prefix_len;

		if (unlikely(!addr_str))
			return false;

		if (L_WARN_ON(unlikely(!(netconfig->v4_address =
						l_rtnl_address_new(addr_str,
								prefix_len)))))
			return false;

		l_rtnl_address_set_noprefixroute(netconfig->v4_address, true);
		set_address = true;

		/*
		 * TODO: If netconfig->fils_override->ipv4_lifetime is set,
		 * start a timeout to renew the address using FILS IP Address
		 * Assignment or perhaps just start the DHCP client at that
		 * time.
		 */
	}

	if (set_address) {
		char ip[INET6_ADDRSTRLEN];

		if (L_WARN_ON(!netconfig->v4_address ||
					!l_rtnl_address_get_address(
							netconfig->v4_address,
							ip)))
			return false;

		netconfig->acd = l_acd_new(netconfig->ifindex);
		l_acd_set_event_handler(netconfig->acd,
					netconfig_ipv4_acd_event, netconfig,
					NULL);
		if (getenv("IWD_ACD_DEBUG"))
			l_acd_set_debug(netconfig->acd, do_debug,
					"[ACD] ", NULL);

		if (!l_acd_start(netconfig->acd, ip)) {
			l_error("failed to start ACD, continuing anyways");
			l_acd_destroy(netconfig->acd);
			netconfig->acd = NULL;

			L_WARN_ON(!(netconfig->addr4_add_cmd_id =
				l_rtnl_ifaddr_add(rtnl, netconfig->ifindex,
					netconfig->v4_address,
					netconfig_ipv4_ifaddr_add_cmd_cb,
					netconfig, NULL)));
		}

		return true;
	}

	if (l_dhcp_client_start(netconfig->dhcp_client))
		return true;

	l_error("netconfig: Failed to start DHCPv4 client for interface %u",
							netconfig->ifindex);
	return false;
}

static bool netconfig_ipv6_select_and_install(struct netconfig *netconfig)
{
	struct netdev *netdev = netdev_find(netconfig->ifindex);
	struct l_rtnl_address *address = NULL;

	if (netconfig->rtm_v6_protocol == RTPROT_UNSPEC) {
		l_debug("IPV6 configuration disabled");
		return true;
	}

	sysfs_write_ipv6_setting(netdev_get_name(netdev), "disable_ipv6", "0");

	if (netconfig->rtm_v6_protocol == RTPROT_STATIC)
		address = netconfig_get_static6_address(
						netconfig->active_settings);
	else if (netconfig->rtm_v6_protocol == RTPROT_DHCP &&
			netconfig->fils_override &&
			!l_memeqzero(netconfig->fils_override->ipv6_addr, 16)) {
		uint8_t prefix_len = netconfig->fils_override->ipv6_prefix_len;
		L_AUTO_FREE_VAR(char *, addr_str) = netconfig_ipv6_to_string(
					netconfig->fils_override->ipv6_addr);

		if (unlikely(!addr_str))
			return false;

		if (L_WARN_ON(unlikely(!(address = l_rtnl_address_new(addr_str,
								prefix_len)))))
			return false;

		l_rtnl_address_set_noprefixroute(address, true);

		/*
		 * TODO: If netconfig->fils_override->ipv6_lifetime is set,
		 * start a timeout to renew the address using FILS IP Address
		 * Assignment or perhaps just start the DHCP client at that
		 * time.
		 */
	}

	if (address) {
		L_WARN_ON(!(netconfig->addr6_add_cmd_id =
			l_rtnl_ifaddr_add(rtnl, netconfig->ifindex, address,
					netconfig_ipv6_ifaddr_add_cmd_cb,
					netconfig, NULL)));
		l_rtnl_address_free(address);
		return true;
	}

	/* DHCP */
	return true;
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
				const struct l_settings *active_settings,
				const uint8_t *mac_address)
{
	char *mdns;
	bool send_hostname;
	bool v6_enabled;
	char hostname[HOST_NAME_MAX + 1];
	char **dns4_overrides = NULL;
	char **dns6_overrides = NULL;
	struct l_rtnl_address *v4_address = NULL;
	struct l_rtnl_address *v6_address = NULL;

	dns4_overrides = l_settings_get_string_list(active_settings,
							"IPv4", "DNS", ' ');
	if (dns4_overrides) {
		int r = validate_dns_list(AF_INET, dns4_overrides);

		if (unlikely(r <= 0)) {
			l_strfreev(dns4_overrides);
			dns4_overrides = NULL;

			if (r < 0)
				goto err_dns4;
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
				goto err_dns6;
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
			goto err_v4_addr;
		}
	}

	if (!l_settings_get_bool(active_settings, "IPv6",
					"Enabled", &v6_enabled))
		v6_enabled = ipv6_enabled;

	if (l_settings_has_key(active_settings, "IPv6", "Address")) {
		v6_address = netconfig_get_static6_address(active_settings);
		l_rtnl_address_free(v6_address);

		if (unlikely(!v6_address)) {
			l_error("netconfig: Can't parse IPv6 address");
			goto err_v6_addr;
		}
	}

	/* No more validation steps for now, commit new values */

	if (v4_address) {
		netconfig->v4_address = v4_address;
		netconfig->rtm_protocol = RTPROT_STATIC;
	} else
		netconfig->rtm_protocol = RTPROT_DHCP;

	if (!v6_enabled)
		netconfig->rtm_v6_protocol = RTPROT_UNSPEC;
	else if (v6_address)
		netconfig->rtm_v6_protocol = RTPROT_STATIC;
	else
		netconfig->rtm_v6_protocol = RTPROT_DHCP;

	if (send_hostname)
		l_dhcp_client_set_hostname(netconfig->dhcp_client, hostname);

	resolve_set_mdns(netconfig->resolve, mdns);
	l_free(mdns);

	l_dhcp_client_set_address(netconfig->dhcp_client, ARPHRD_ETHER,
							mac_address, ETH_ALEN);
	l_dhcp6_client_set_address(netconfig->dhcp6_client, ARPHRD_ETHER,
							mac_address, ETH_ALEN);

	netconfig->active_settings = active_settings;
	netconfig->dns4_overrides = dns4_overrides;
	netconfig->dns6_overrides = dns6_overrides;
	return true;

err_v6_addr:
	l_rtnl_address_free(v4_address);
err_v4_addr:
	l_free(mdns);
	l_strfreev(dns6_overrides);
err_dns6:
	l_strfreev(dns4_overrides);
err_dns4:
	return false;
}

bool netconfig_configure(struct netconfig *netconfig,
				netconfig_notify_func_t notify, void *user_data)
{
	netconfig->notify = notify;
	netconfig->user_data = user_data;

	if (unlikely(!netconfig_ipv4_select_and_install(netconfig)))
		return false;

	if (unlikely(!netconfig_ipv6_select_and_install(netconfig)))
		return false;

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
	struct netdev *netdev = netdev_find(netconfig->ifindex);

	if (netconfig->route4_add_gateway_cmd_id) {
		l_netlink_cancel(rtnl, netconfig->route4_add_gateway_cmd_id);
		netconfig->route4_add_gateway_cmd_id = 0;
	}

	if (netconfig->addr4_add_cmd_id) {
		l_netlink_cancel(rtnl, netconfig->addr4_add_cmd_id);
		netconfig->addr4_add_cmd_id = 0;
	}

	if (netconfig->addr6_add_cmd_id) {
		l_netlink_cancel(rtnl, netconfig->addr6_add_cmd_id);
		netconfig->addr6_add_cmd_id = 0;
	}

	if (netconfig->rtm_protocol || netconfig->rtm_v6_protocol)
		resolve_revert(netconfig->resolve);

	netconfig_reset_v4(netconfig);

	if (netconfig->rtm_v6_protocol) {
		l_strfreev(netconfig->dns6_overrides);
		netconfig->dns6_overrides = NULL;

		l_dhcp6_client_stop(netconfig->dhcp6_client);
		netconfig->rtm_v6_protocol = 0;

		sysfs_write_ipv6_setting(netdev_get_name(netdev),
						"disable_ipv6", "1");
	}

	l_free(l_steal_ptr(netconfig->fils_override));

	return true;
}

char *netconfig_get_dhcp_server_ipv4(struct netconfig *netconfig)
{
	const struct l_dhcp_lease *lease;

	if (!netconfig->dhcp_client)
		return NULL;

	lease = l_dhcp_client_get_lease(netconfig->dhcp_client);
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
	struct l_icmp6_client *icmp6;

	if (!netconfig_list)
		return NULL;

	l_debug("Starting netconfig for interface: %d", ifindex);

	netconfig = netconfig_find(ifindex);
	if (netconfig)
		return netconfig;

	netconfig = l_new(struct netconfig, 1);
	netconfig->ifindex = ifindex;
	netconfig->resolve = resolve_new(ifindex);

	netconfig->dhcp_client = l_dhcp_client_new(ifindex);
	l_dhcp_client_set_event_handler(netconfig->dhcp_client,
					netconfig_ipv4_dhcp_event_handler,
					netconfig, NULL);

	if (getenv("IWD_DHCP_DEBUG"))
		l_dhcp_client_set_debug(netconfig->dhcp_client, do_debug,
							"[DHCPv4] ", NULL);

	netconfig->dhcp6_client = l_dhcp6_client_new(ifindex);
	l_dhcp6_client_set_event_handler(netconfig->dhcp6_client,
						netconfig_dhcp6_event_handler,
						netconfig, NULL);
	l_dhcp6_client_set_lla_randomized(netconfig->dhcp6_client, true);
	l_dhcp6_client_set_nodelay(netconfig->dhcp6_client, true);
	l_dhcp6_client_set_rtnl(netconfig->dhcp6_client, rtnl);

	if (getenv("IWD_DHCP_DEBUG"))
		l_dhcp6_client_set_debug(netconfig->dhcp6_client, do_debug,
							"[DHCPv6] ", NULL);

	icmp6 = l_dhcp6_client_get_icmp6(netconfig->dhcp6_client);
	l_icmp6_client_set_rtnl(icmp6, rtnl);
	l_icmp6_client_set_route_priority(icmp6, ROUTE_PRIORITY_OFFSET);

	l_queue_push_tail(netconfig_list, netconfig);

	sysfs_write_ipv6_setting(netdev_get_name(netdev), "accept_ra", "0");
	sysfs_write_ipv6_setting(netdev_get_name(netdev), "disable_ipv6", "1");

	return netconfig;
}

void netconfig_destroy(struct netconfig *netconfig)
{
	if (!netconfig_list)
		return;

	l_debug("");

	l_queue_remove(netconfig_list, netconfig);

	netconfig_reset(netconfig);
	resolve_free(netconfig->resolve);
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

	if (!l_settings_get_bool(iwd_get_config(), "Network",
					"EnableIPv6",
					&ipv6_enabled))
		ipv6_enabled = false;

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
