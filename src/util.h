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

#ifndef __UTIL_H
#define __UTIL_H

#include <stdint.h>
#include <unistd.h>

#define align_len(len, boundary) (((len)+(boundary)-1) & ~((boundary)-1))

#define MAC "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_STR(a) a[0], a[1], a[2], a[3], a[4], a[5]

const char *util_ssid_to_utf8(size_t len, const uint8_t *ssid);
bool util_ssid_is_utf8(size_t len, const uint8_t *ssid);
bool util_ssid_is_hidden(size_t len, const uint8_t *ssid);
const char *util_address_to_string(const uint8_t *addr);
bool util_string_to_address(const char *str, uint8_t *addr);
bool util_is_group_address(const uint8_t *addr);
bool util_is_broadcast_address(const uint8_t *addr);
bool util_is_valid_sta_address(const uint8_t *addr);

const char *util_get_domain(const char *identity);
const char *util_get_username(const char *identity);

static inline uint8_t util_bit_field(const uint8_t oct, int start, int num)
{
	unsigned char mask = (1 << num) - 1;
	return (oct >> start) & mask;
}

static inline bool util_is_bit_set(const uint8_t oct, int bit)
{
	int mask = 1 << bit;
	return oct & mask ? true : false;
}

static inline bool util_mem_is_zero(const uint8_t *field, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		if (field[i] != 0)
			return false;

	return true;
}

static inline void util_set_bit(uint8_t *field, unsigned int bit)
{
	field[bit / 8] = 1 << (bit % 8);
}

#endif /* __UTIL_H */
