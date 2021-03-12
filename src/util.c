/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2014-2019  Intel Corporation. All rights reserved.
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

#include <string.h>
#include <stdio.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ell/ell.h>

#include "ell/useful.h"
#include "src/util.h"

const char *util_ssid_to_utf8(size_t len, const uint8_t *ssid)
{
	static char buf[3* 32 + 1];
	size_t i = 0, pos = 0;
	const uint8_t *start = ssid, *end;

	memset(buf, 0, sizeof(buf));

	if (len > 32)
		goto no_ssid;

	while (i < len && !ssid[i])
		i++;

	if (i == len)
		goto no_ssid;

	i = len;

	while (i && (!l_utf8_validate((const char *)start, i,
						(const char **)&end))) {
		const char replacement[] = { 0xEF, 0xBF, 0xBD };
		int bytes = end - start;

		memcpy(&buf[pos], start, bytes);
		pos += bytes;

		memcpy(&buf[pos], replacement, sizeof(replacement));
		pos += sizeof(replacement);

		start = end + 1;
		i -= (bytes + 1);
	}

	if (i) {
		memcpy(&buf[pos], start, i);
		pos += i;
	}

no_ssid:
	buf[pos] = '\0';

	return buf;
}

bool util_ssid_is_utf8(size_t len, const uint8_t *ssid)
{
	if (len > 32)
		return false;

	return l_utf8_validate((const char *)ssid, len, NULL);
}

/*
 * Checks whether this is a hidden SSID.  Two conditions are checked:
 * 1. If the SSID is length 0
 * 2. If the SSID length > 0 and all bytes are 0
 *
 * The length is not sanitized so the caller must have sanitized the arguments
 * beforehand.
 */
bool util_ssid_is_hidden(size_t len, const uint8_t *ssid)
{
	if (!len)
		return true;

	return l_memeqzero(ssid, len);
}

const char *util_address_to_string(const uint8_t *addr)
{
	static char str[18];

	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	return str;
}

bool util_string_to_address(const char *str, uint8_t *out_addr)
{
	unsigned int i;
	uint8_t addr[6];

	if (!str)
		return false;

	if (strlen(str) != 17)
		return false;

	for (i = 0; i < 15; i += 3) {
		if (!l_ascii_isxdigit(str[i]))
			return false;

		if (!l_ascii_isxdigit(str[i + 1]))
			return false;

		if (str[i + 2] != ':')
			return false;
        }

	if (!l_ascii_isxdigit(str[i]))
		return false;

	if (!l_ascii_isxdigit(str[i + 1]))
		return false;

	if (sscanf(str, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
			&addr[0], &addr[1], &addr[2],
			&addr[3], &addr[4], &addr[5]) != 6)
		return false;

	memcpy(out_addr, addr, sizeof(addr));

	return true;
}

bool util_is_group_address(const uint8_t *addr)
{
	/* 802.11-2016 section 9.2.2 */
	return test_bit(addr, 0);
}

bool util_is_broadcast_address(const uint8_t *addr)
{
	/* 802.11-2016 section 9.2.4.3 */
	static const uint8_t bcast_addr[6] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	return !memcmp(addr, bcast_addr, 6);
}

bool util_is_valid_sta_address(const uint8_t *addr)
{
	return !util_is_broadcast_address(addr) && !util_is_group_address(addr);
}

/* This function assumes that identity is not bigger than 253 bytes */
const char *util_get_domain(const char *identity)
{
	static char domain[256];
	const char *c;

	memset(domain, 0, sizeof(domain));

	for (c = identity; *c; c++) {
		switch (*c) {
		case '\\':
			memcpy(domain, identity, c - identity);
			return domain;
		case '@':
			l_strlcpy(domain, c + 1, sizeof(domain));
			return domain;
		default:
			continue;
		}
	}

	return identity;
}

/* This function assumes that identity is not bigger than 253 bytes */
const char *util_get_username(const char *identity)
{
	static char username[256];
	const char *c;

	memset(username, 0, sizeof(username));

	for (c = identity; *c; c++) {
		switch (*c) {
		case '\\':
			l_strlcpy(username, c + 1, sizeof(username));
			return username;
		case '@':
			memcpy(username, identity, c - identity);
			return username;
		default:
			continue;
		}
	}

	return identity;
}

static bool is_prefix_valid(uint32_t ip, unsigned int prefix)
{
	int i;

	for (i = 31 - prefix; i >= 0; i--) {
		if (ip & (1 << i))
			return false;
	}

	return true;
}

/*
 * Parse a prefix notation IP string (e.g. A.B.C.D/E) into an IP range and
 * netmask. All returned IP addresses/mask will be in host order. The start/end
 * IP will only include the usable IP range where the last octet is not zero or
 * 255.
 */
bool util_ip_prefix_tohl(const char *ip, uint8_t *prefix_out,
				uint32_t *start_out, uint32_t *end_out,
				uint32_t *mask_out)
{
	struct in_addr ia;
	int i;
	unsigned int prefix = 0;
	char no_prefix[INET_ADDRSTRLEN];
	char *endp;
	uint32_t start_ip;
	uint32_t end_ip;
	uint32_t netmask = 0xffffffff;

	/*
	 * Only iterate over the max length of an IP in case of invalid long
	 * inputs.
	 */
	for (i = 0; i < INET_ADDRSTRLEN && ip[i] != '\0'; i++) {
		/* Found '/', check the next byte exists and parse prefix */
		if (ip[i] == '/' && ip[i + 1] != '\0') {
			prefix = strtoul(ip + i + 1, &endp, 10);
			if (*endp != '\0')
				return false;

			break;
		}
	}

	if (prefix < 1 || prefix > 31)
		return false;

	/* 'i' will be at most INET_ADDRSTRLEN - 1 */
	l_strlcpy(no_prefix, ip, i + 1);

	/* Check if IP preceeding prefix is valid */
	if (inet_pton(AF_INET, no_prefix, &ia) != 1 || ia.s_addr == 0)
		return false;

	start_ip = ntohl(ia.s_addr);

	if (!is_prefix_valid(start_ip, prefix))
		return false;

	/* Usable range is start + 1 .. end - 1 */
	start_ip += 1;

	/* Calculate end IP and netmask */
	end_ip = start_ip;
	for (i = 31 - prefix; i >= 0; i--) {
		end_ip |= (1 << i);
		netmask &= ~(1 << i);
	}

	end_ip -= 1;

	if (prefix_out)
		*prefix_out = prefix;

	if (start_out)
		*start_out = start_ip;

	if (end_out)
		*end_out = end_ip;

	if (mask_out)
		*mask_out = netmask;

	return true;
}
