/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2019  Intel Corporation. All rights reserved.
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

#include <stdint.h>
#include <sys/time.h>

struct nlmon;

struct nlmon_config {
	bool nortnl;
	bool nowiphy;
	bool noscan;
	bool noies;
	bool read_only;
};

struct nlmon *nlmon_open(const char *ifname, uint16_t id, const char *pathname,
				const struct nlmon_config *config);
void nlmon_close(struct nlmon *nlmon);

struct nlmon *nlmon_create(uint16_t id, const struct nlmon_config *config);
void nlmon_destroy(struct nlmon *nlmon);
void nlmon_print_rtnl(struct nlmon *nlmon, const struct timeval *tv,
					const void *data, uint32_t size);
void nlmon_print_genl(struct nlmon *nlmon, const struct timeval *tv,
					const void *data, int64_t size);
void nlmon_print_pae(struct nlmon *nlmon, const struct timeval *tv,
					uint8_t type, int index,
					const void *data, uint32_t size);
