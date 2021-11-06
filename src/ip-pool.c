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
#include "src/netconfig.h"
#include "src/ip-pool.h"

struct ip_pool_addr4_record {
	uint32_t ifindex;
	struct l_rtnl_address *addr;
};

struct ip_pool_addr4_range {
	uint32_t start;
	uint32_t end;
};

static struct l_queue *used_addr4_list;
static struct l_netlink *rtnl;

static int ip_pool_addr4_range_compare(const void *a, const void *b,
					void *user_data)
{
	const struct ip_pool_addr4_range *range_a = a;
	const struct ip_pool_addr4_range *range_b = b;

	return range_a->start > range_b->start ? 1 : -1;
}

/*
 * Append any address ranges within an input start/end range which contain
 * at least one full subnet and don't intersect with any subnets already in
 * use.  This may result in the input range being split into multiple ranges
 * of different sizes or being skipped altogether.
 * All inputs must be rounded to the subnet boundary and the @used queue
 * sorted by the subnet start address.
 */
static void ip_pool_append_range(struct l_queue *to,
					const struct ip_pool_addr4_range *range,
					struct l_queue *used, const char *str)
{
	const struct l_queue_entry *entry = l_queue_get_entries(used);
	const struct ip_pool_addr4_range *used_range =
		entry ? entry->data : NULL;
	uint32_t start = range->start;
	bool print = true;

	while (range->end > start) {
		while (used_range && used_range->end <= start) {
			entry = entry->next;
			used_range = entry ? entry->data : NULL;
		}

		/* No more used ranges that intersect with @start/@range->end */
		if (!used_range || range->end <= used_range->start) {
			struct ip_pool_addr4_range *sub =
				l_new(struct ip_pool_addr4_range, 1);

			sub->start = start;
			sub->end = range->end;
			l_queue_push_tail(to, sub);
			l_queue_insert(used, l_memdup(sub, sizeof(*sub)),
					ip_pool_addr4_range_compare, NULL);
			return;
		}

		if (print) {
			l_debug("Address spec %s intersects with at least one "
				"subnet already in use on the system or "
				"specified in the settings", str);
			print = false;
		}

		/* Now we know @used_range is non-NULL and intersects */
		if (start < used_range->start) {
			struct ip_pool_addr4_range *sub =
				l_new(struct ip_pool_addr4_range, 1);

			sub->start = start;
			sub->end = used_range->start;
			l_queue_push_tail(to, sub);
			l_queue_insert(used, l_memdup(sub, sizeof(*sub)),
					ip_pool_addr4_range_compare, NULL);
		}

		/* Skip to the start of the next subnet */
		start = used_range->end;
	}
}

/*
 * Select a subnet and a host address from a defined space.
 *
 * Returns:  0 when an address was selected and written to *out_addr,
 *          -EEXIST if all available subnet addresses are in use,
 *          -EINVAL if there was a different error.
 */
int ip_pool_select_addr4(const char **addr_str_list, uint8_t subnet_prefix_len,
				struct l_rtnl_address **out_addr)
{
	uint32_t total = 0;
	uint32_t selected;
	unsigned int i;
	uint32_t subnet_size = 1 << (32 - subnet_prefix_len);
	uint32_t host_mask = subnet_size - 1;
	uint32_t subnet_mask = ~host_mask;
	uint32_t host_addr = 0;
	struct l_queue *ranges = l_queue_new();
	struct l_queue *used = l_queue_new();
	struct in_addr ia;
	const struct l_queue_entry *entry;
	int err = -EINVAL;
	char ipstr[INET_ADDRSTRLEN];

	if (!addr_str_list || !addr_str_list[0])
		goto cleanup;

	/* Build a sorted list of used/unavailable subnets */
	for (entry = l_queue_get_entries(used_addr4_list);
			entry; entry = entry->next) {
		const struct ip_pool_addr4_record *rec = entry->data;
		struct ip_pool_addr4_range *range;
		char addr_str[INET_ADDRSTRLEN];
		uint8_t used_prefix_len =
			l_rtnl_address_get_prefix_length(rec->addr);
		uint32_t used_subnet_size;

		if (l_rtnl_address_get_family(rec->addr) != AF_INET ||
				!l_rtnl_address_get_address(rec->addr,
								addr_str) ||
				used_prefix_len < 1 ||
				inet_pton(AF_INET, addr_str, &ia) != 1)
			continue;

		used_subnet_size = 1 << (32 - used_prefix_len);

		range = l_new(struct ip_pool_addr4_range, 1);
		range->start = ntohl(ia.s_addr) & subnet_mask;
		range->end = (range->start + used_subnet_size + subnet_size -
				1) & subnet_mask;
		l_queue_insert(used, range, ip_pool_addr4_range_compare, NULL);
	}

	/* Build the list of available subnets */

	/* Check for the static IP syntax: Address=<IP> */
	if (l_strv_length((char **) addr_str_list) == 1 &&
			inet_pton(AF_INET, *addr_str_list, &ia) == 1) {
		struct ip_pool_addr4_range range;

		host_addr = ntohl(ia.s_addr);
		range.start = host_addr & subnet_mask;
		range.end = range.start + subnet_size;
		ip_pool_append_range(ranges, &range, used, *addr_str_list);
		goto check_avail;
	}

	for (i = 0; addr_str_list[i]; i++) {
		struct ip_pool_addr4_range range;
		uint32_t addr;
		uint8_t addr_prefix;

		if (!util_ip_prefix_tohl(addr_str_list[i], &addr_prefix, &addr,
						NULL, NULL)) {
			l_error("Can't parse %s as a subnet address",
				addr_str_list[i]);
			goto cleanup;
		}

		if (addr_prefix > subnet_prefix_len) {
			l_debug("Address spec %s smaller than requested "
				"subnet (prefix len %i)", addr_str_list[i],
				subnet_prefix_len);
			continue;
		}

		range.start = addr & subnet_mask;
		range.end = range.start + (1 << (32 - addr_prefix));
		ip_pool_append_range(ranges, &range, used, addr_str_list[i]);
	}

check_avail:
	if (l_queue_isempty(ranges)) {
		l_error("No IP subnets available for new Access Point after "
			"eliminating those already in use on the system");
		err = -EEXIST;
		goto cleanup;
	}

	if (host_addr)
		goto done;

	/* Count available @subnet_prefix_len-sized subnets */
	for (entry = l_queue_get_entries(ranges); entry; entry = entry->next) {
		struct ip_pool_addr4_range *range = entry->data;

		total += (range->end - range->start) >>
			(32 - subnet_prefix_len);
	}

	selected = l_getrandom_uint32() % total;

	/* Find the @selected'th @subnet_prefix_len-sized subnet */
	for (entry = l_queue_get_entries(ranges);; entry = entry->next) {
		struct ip_pool_addr4_range *range = entry->data;
		uint32_t count = (range->end - range->start) >>
			(32 - subnet_prefix_len);

		if (selected < count) {
			host_addr = range->start +
				(selected << (32 - subnet_prefix_len));
			break;
		}

		selected -= count;
	}

	if ((host_addr & host_mask) == 0)
		host_addr += 1;

done:
	err = 0;
	ia.s_addr = htonl(host_addr);
	if (L_WARN_ON(!inet_ntop(AF_INET, &ia, ipstr, INET_ADDRSTRLEN)))
		err = -errno;
	else
		*out_addr = l_rtnl_address_new(ipstr, subnet_prefix_len);

cleanup:
	l_queue_destroy(ranges, l_free);
	l_queue_destroy(used, l_free);
	return err;
}

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
	if (!netconfig_enabled())
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
