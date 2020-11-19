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
	struct l_dhcp6_client *dhcp6_client;
	struct l_queue *ifaddr_list;
	uint8_t rtm_protocol;
	uint8_t rtm_v6_protocol;
	struct l_rtnl_address *v4_address;
	char **dns4_overrides;
	char **dns6_overrides;

	const struct l_settings *active_settings;

	netconfig_notify_func_t notify;
	void *user_data;

	struct resolve *resolve;
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
	l_dhcp6_client_destroy(netconfig->dhcp6_client);

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

static int netconfig_set_dns(struct netconfig *netconfig)
{
	char **dns6_list = NULL;
	char **dns4_list = NULL;
	unsigned int n_entries = 0;
	char **dns_list;

	if (!netconfig->dns4_overrides &&
			netconfig->rtm_protocol == RTPROT_DHCP) {
		const struct l_dhcp_lease *lease =
			l_dhcp_client_get_lease(netconfig->dhcp_client);

		if (lease)
			dns4_list = l_dhcp_lease_get_dns(lease);
	}

	if (!netconfig->dns6_overrides &&
			netconfig->rtm_v6_protocol == RTPROT_DHCP) {
		const struct l_dhcp6_lease *lease =
			l_dhcp6_client_get_lease(netconfig->dhcp6_client);

		if (lease)
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
	/* Contents now belong to ret, so not l_strfreev */
	l_free(dns4_list);
	APPEND_STRDUPV(dns_list, n_entries, netconfig->dns6_overrides);
	APPENDV(dns_list, n_entries, dns6_list);
	/* Contents now belong to ret, so not l_strfreev */
	l_free(dns6_list);

	resolve_set_dns(netconfig->resolve, dns_list);
	l_strv_free(dns_list);
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
						struct netconfig *netconfig)
{
	struct l_rtnl_address *ifaddr = NULL;
	char *ip;
	char *netmask;
	struct in_addr in_addr;
	char *broadcast;
	uint32_t prefix_len;

	ip = l_settings_get_string(netconfig->active_settings, "IPv4",
								"Address");
	if (!ip)
		return NULL;

	netmask = l_settings_get_string(netconfig->active_settings,
						"IPv4", "Netmask");

	if (netmask && inet_pton(AF_INET, netmask, &in_addr) > 0)
		prefix_len = __builtin_popcountl(in_addr.s_addr);
	else
		prefix_len = 24;

	l_free(netmask);

	ifaddr = l_rtnl_address_new(ip, prefix_len);
	l_free(ip);

	if (!ifaddr) {
		l_error("Unable to parse IPv4.Address, ignoring...");
		return NULL;
	}

	broadcast = l_settings_get_string(netconfig->active_settings,
						"IPv4", "Broadcast");
	if (broadcast) {
		bool r = l_rtnl_address_set_broadcast(ifaddr, broadcast);
		l_free(broadcast);

		if (!r) {
			l_error("Unable to parse IPv4.Broadcast, ignoring...");
			l_rtnl_address_free(ifaddr);
			return NULL;
		}
	}

	l_rtnl_address_set_noprefixroute(ifaddr, true);
	return ifaddr;
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

static struct l_rtnl_address *netconfig_get_static6_address(
						struct netconfig *netconfig)
{
	L_AUTO_FREE_VAR(char *, ip);
	char *p;
	struct l_rtnl_address *ret;
	uint32_t prefix_len = 128;

	ip = l_settings_get_string(netconfig->active_settings, "IPv6",
								"Address");
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
						struct netconfig *netconfig)
{
	L_AUTO_FREE_VAR(char *, gateway);
	struct l_rtnl_route *ret;

	gateway = l_settings_get_string(netconfig->active_settings,
						"IPv6", "Gateway");
	if (!gateway)
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
	struct in6_addr in6;

	if (ifa->ifa_flags & IFA_F_TENTATIVE)
		return;

	ifaddr = l_new(struct netconfig_ifaddr, 1);
	ifaddr->family = ifa->ifa_family;
	ifaddr->prefix_len = ifa->ifa_prefixlen;

	l_rtnl_ifaddr6_extract(ifa, len, &ifaddr->ip);

	l_debug("ifindex %u: ifaddr %s/%u", netconfig->ifindex, ifaddr->ip,
							ifaddr->prefix_len);

	l_queue_push_tail(netconfig->ifaddr_list, ifaddr);

	if (netconfig->rtm_v6_protocol != RTPROT_DHCP)
		return;

	inet_pton(AF_INET6, ifaddr->ip, &in6);
	if (!IN6_IS_ADDR_LINKLOCAL(&in6))
		return;

	l_dhcp6_client_set_link_local_address(netconfig->dhcp6_client,
						ifaddr->ip);

	if (l_dhcp6_client_start(netconfig->dhcp6_client))
		return;

	l_error("netconfig: Failed to start DHCPv6 client for "
			"interface %u", netconfig->ifindex);
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

static bool netconfig_ipv4_routes_install(struct netconfig *netconfig)
{
	L_AUTO_FREE_VAR(char *, gateway) = NULL;
	struct in_addr in_addr;
	char *network;
	char ip[INET6_ADDRSTRLEN];
	unsigned int prefix_len =
		l_rtnl_address_get_prefix_length(netconfig->v4_address);

	if (!l_rtnl_address_get_address(netconfig->v4_address, ip) ||
			inet_pton(AF_INET, ip, &in_addr) < 1)
		return false;

	in_addr.s_addr = in_addr.s_addr &
				htonl(0xFFFFFFFFLU << (32 - prefix_len));

	network = inet_ntoa(in_addr);
	if (!network)
		return false;

	if (!l_rtnl_route4_add_connected(rtnl, netconfig->ifindex,
						prefix_len, network, ip,
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

	if (!l_rtnl_route4_add_gateway(rtnl, netconfig->ifindex, gateway, ip,
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

	if (error && error != -EEXIST) {
		l_error("netconfig: Failed to add IPv6 address. "
				"Error %d: %s", error, strerror(-error));
		return;
	}

	gateway = netconfig_get_static6_gateway(netconfig);
	if (gateway) {
		L_WARN_ON(!l_rtnl_route_add(rtnl, netconfig->ifindex,
						gateway,
						netconfig_route_add_cmd_cb,
						netconfig, NULL));
		l_rtnl_route_free(gateway);
	}

	netconfig_set_dns(netconfig);
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
	case L_DHCP_CLIENT_EVENT_LEASE_RENEWED:
	case L_DHCP_CLIENT_EVENT_LEASE_OBTAINED:
	case L_DHCP_CLIENT_EVENT_IP_CHANGED:
		netconfig->v4_address = netconfig_get_dhcp4_address(netconfig);
		if (!netconfig->v4_address) {
			l_error("netconfig: Failed to obtain IP addresses from "
							"DHCPv4 lease.");
			return;
		}

		L_WARN_ON(!l_rtnl_ifaddr_add(rtnl, netconfig->ifindex,
					netconfig->v4_address,
					netconfig_ipv4_ifaddr_add_cmd_cb,
					netconfig, NULL));
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
		break;
	case L_DHCP6_CLIENT_EVENT_LEASE_EXPIRED:
		l_debug("Lease for interface %u expired", netconfig->ifindex);
		netconfig_set_dns(netconfig);

		/* Fall through */
	case L_DHCP6_CLIENT_EVENT_NO_LEASE:
		if (!l_dhcp6_client_start(netconfig->dhcp6_client))
			l_error("netconfig: Failed to re-start DHCPv6 client "
					"for interface %u", netconfig->ifindex);
		break;
	}
}

static void netconfig_ipv4_select_and_install(struct netconfig *netconfig)
{
	netconfig->v4_address = netconfig_get_static4_address(netconfig);
	if (netconfig->v4_address) {
		netconfig->rtm_protocol = RTPROT_STATIC;
		L_WARN_ON(!l_rtnl_ifaddr_add(rtnl, netconfig->ifindex,
					netconfig->v4_address,
					netconfig_ipv4_ifaddr_add_cmd_cb,
					netconfig, NULL));
		return;
	}

	netconfig->rtm_protocol = RTPROT_DHCP;

	if (l_dhcp_client_start(netconfig->dhcp_client))
		return;

	l_error("netconfig: Failed to start DHCPv4 client for interface %u",
							netconfig->ifindex);
}

static void netconfig_ipv6_select_and_install(struct netconfig *netconfig)
{
	struct netdev *netdev = netdev_find(netconfig->ifindex);
	struct l_rtnl_address *address;
	bool enabled;

	if (!l_settings_get_bool(netconfig->active_settings, "IPv6",
					"Enabled", &enabled))
		enabled = ipv6_enabled;

	if (!enabled) {
		l_debug("IPV6 configuration disabled");
		return;
	}

	sysfs_write_ipv6_setting(netdev_get_name(netdev), "disable_ipv6", "0");

	address = netconfig_get_static6_address(netconfig);
	if (address) {
		netconfig->rtm_v6_protocol = RTPROT_STATIC;
		L_WARN_ON(!l_rtnl_ifaddr_add(rtnl, netconfig->ifindex, address,
					netconfig_ipv6_ifaddr_add_cmd_cb,
					netconfig, NULL));
		l_rtnl_address_free(address);
		return;
	}

	netconfig->rtm_v6_protocol = RTPROT_DHCP;
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

bool netconfig_configure(struct netconfig *netconfig,
				const struct l_settings *active_settings,
				const uint8_t *mac_address,
				netconfig_notify_func_t notify, void *user_data)
{
	netconfig->dns4_overrides = l_settings_get_string_list(active_settings,
							"IPv4", "DNS", ' ');

	if (netconfig->dns4_overrides) {
		int r = validate_dns_list(AF_INET, netconfig->dns4_overrides);

		if (r <= 0) {
			l_strfreev(netconfig->dns4_overrides);
			netconfig->dns4_overrides = NULL;
		}

		if (r == 0)
			l_error("netconfig: Empty IPv4.DNS entry, skipping...");
	}

	netconfig->dns6_overrides = l_settings_get_string_list(active_settings,
							"IPv6", "DNS", ' ');

	if (netconfig->dns6_overrides) {
		int r = validate_dns_list(AF_INET6, netconfig->dns6_overrides);

		if (r <= 0) {
			l_strfreev(netconfig->dns6_overrides);
			netconfig->dns6_overrides = NULL;
		}

		if (r == 0)
			l_error("netconfig: Empty IPv6.DNS entry, skipping...");
	}

	netconfig->active_settings = active_settings;
	netconfig->notify = notify;
	netconfig->user_data = user_data;

	l_dhcp_client_set_address(netconfig->dhcp_client, ARPHRD_ETHER,
							mac_address, ETH_ALEN);
	l_dhcp6_client_set_address(netconfig->dhcp6_client, ARPHRD_ETHER,
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
	struct netdev *netdev = netdev_find(netconfig->ifindex);

	if (netconfig->rtm_protocol || netconfig->rtm_v6_protocol)
		resolve_revert(netconfig->resolve);

	if (netconfig->rtm_protocol) {
		if (netconfig->v4_address) {
			L_WARN_ON(!l_rtnl_ifaddr_delete(rtnl,
						netconfig->ifindex,
						netconfig->v4_address,
						netconfig_ifaddr_del_cmd_cb,
						netconfig, NULL));
			l_rtnl_address_free(netconfig->v4_address);
			netconfig->v4_address = NULL;
		}

		l_strfreev(netconfig->dns4_overrides);
		netconfig->dns4_overrides = NULL;

		l_dhcp_client_stop(netconfig->dhcp_client);
		netconfig->rtm_protocol = 0;
	}

	if (netconfig->rtm_v6_protocol) {
		l_strfreev(netconfig->dns6_overrides);
		netconfig->dns6_overrides = NULL;

		l_dhcp6_client_stop(netconfig->dhcp6_client);
		netconfig->rtm_v6_protocol = 0;

		sysfs_write_ipv6_setting(netdev_get_name(netdev),
						"disable_ipv6", "1");
	}

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
	netconfig->ifaddr_list = l_queue_new();
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
