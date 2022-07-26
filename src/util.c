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
#include "src/band.h"

const char *util_ssid_to_utf8(size_t len, const uint8_t *ssid)
{
	static char buf[3 * 32 + 1];
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

struct scan_freq_set {
	uint16_t channels_2ghz;
	struct l_uintset *channels_5ghz;
	struct l_uintset *channels_6ghz;
};

struct scan_freq_set *scan_freq_set_new(void)
{
	struct scan_freq_set *ret = l_new(struct scan_freq_set, 1);

	/* 802.11-2012, 8.4.2.10 hints that 200 is the largest channel number */
	ret->channels_5ghz = l_uintset_new_from_range(1, 200);
	ret->channels_6ghz = l_uintset_new_from_range(1, 233);

	return ret;
}

void scan_freq_set_free(struct scan_freq_set *freqs)
{
	l_uintset_free(freqs->channels_5ghz);
	l_uintset_free(freqs->channels_6ghz);
	l_free(freqs);
}

bool scan_freq_set_add(struct scan_freq_set *freqs, uint32_t freq)
{
	enum band_freq band;
	uint8_t channel;

	channel = band_freq_to_channel(freq, &band);
	if (!channel)
		return false;

	switch (band) {
	case BAND_FREQ_2_4_GHZ:
		freqs->channels_2ghz |= 1 << (channel - 1);
		return true;
	case BAND_FREQ_5_GHZ:
		return l_uintset_put(freqs->channels_5ghz, channel);
	case BAND_FREQ_6_GHZ:
		return l_uintset_put(freqs->channels_6ghz, channel);
	}

	return false;
}

bool scan_freq_set_contains(const struct scan_freq_set *freqs, uint32_t freq)
{
	enum band_freq band;
	uint8_t channel;

	channel = band_freq_to_channel(freq, &band);
	if (!channel)
		return false;

	switch (band) {
	case BAND_FREQ_2_4_GHZ:
		return freqs->channels_2ghz & (1 << (channel - 1));
	case BAND_FREQ_5_GHZ:
		return l_uintset_contains(freqs->channels_5ghz, channel);
	case BAND_FREQ_6_GHZ:
		return l_uintset_contains(freqs->channels_6ghz, channel);
	}

	return false;
}

uint32_t scan_freq_set_get_bands(const struct scan_freq_set *freqs)
{
	uint32_t bands = 0;
	uint32_t max;

	if (freqs->channels_2ghz)
		bands |= BAND_FREQ_2_4_GHZ;

	max = l_uintset_get_max(freqs->channels_5ghz);

	if (l_uintset_find_min(freqs->channels_5ghz) <= max)
		bands |= BAND_FREQ_5_GHZ;

	max = l_uintset_get_max(freqs->channels_6ghz);

	if (l_uintset_find_min(freqs->channels_6ghz) <= max)
		bands |= BAND_FREQ_6_GHZ;

	return bands;
}

static void scan_channels_add(uint32_t channel, void *user_data)
{
	struct l_uintset *to = user_data;

	l_uintset_put(to, channel);
}

void scan_freq_set_merge(struct scan_freq_set *to,
					const struct scan_freq_set *from)
{
	to->channels_2ghz |= from->channels_2ghz;

	l_uintset_foreach(from->channels_5ghz, scan_channels_add,
							to->channels_5ghz);
	l_uintset_foreach(from->channels_6ghz, scan_channels_add,
							to->channels_6ghz);
}

bool scan_freq_set_isempty(const struct scan_freq_set *set)
{
	if (set->channels_2ghz == 0 && l_uintset_isempty(set->channels_5ghz) &&
					l_uintset_isempty(set->channels_6ghz))
		return true;

	return false;
}

struct channels_foreach_data {
	scan_freq_set_func_t func;
	enum band_freq band;
	void *user_data;
};

static void scan_channels_foreach(uint32_t channel, void *user_data)
{
	const struct channels_foreach_data *channels_data = user_data;
	uint32_t freq;

	freq = band_channel_to_freq(channel, channels_data->band);

	channels_data->func(freq, channels_data->user_data);
}

void scan_freq_set_foreach(const struct scan_freq_set *freqs,
				scan_freq_set_func_t func, void *user_data)
{
	struct channels_foreach_data data = { };
	uint8_t channel;
	uint32_t freq;

	if (unlikely(!freqs || !func))
		return;

	data.func = func;
	data.band = BAND_FREQ_5_GHZ;
	data.user_data = user_data;

	l_uintset_foreach(freqs->channels_5ghz, scan_channels_foreach, &data);

	data.band = BAND_FREQ_6_GHZ;

	l_uintset_foreach(freqs->channels_6ghz, scan_channels_foreach, &data);

	if (!freqs->channels_2ghz)
		return;

	for (channel = 1; channel <= 14; channel++) {
		if (freqs->channels_2ghz & (1 << (channel - 1))) {
			freq = band_channel_to_freq(channel, BAND_FREQ_2_4_GHZ);

			func(freq, user_data);
		}
	}
}

void scan_freq_set_constrain(struct scan_freq_set *set,
					const struct scan_freq_set *constraint)
{
	struct l_uintset *intersection;

	intersection = l_uintset_intersect(constraint->channels_5ghz,
							set->channels_5ghz);
	if (!intersection)
		/* This shouldn't ever be the case. */
		return;

	l_uintset_free(set->channels_5ghz);
	set->channels_5ghz = intersection;

	intersection = l_uintset_intersect(constraint->channels_6ghz,
							set->channels_6ghz);
	if (!intersection)
		return;

	l_uintset_free(set->channels_6ghz);
	set->channels_6ghz = intersection;

	set->channels_2ghz &= constraint->channels_2ghz;
}

static void add_foreach(uint32_t freq, void *user_data)
{
	uint32_t **list = user_data;

	**list = freq;

	*list = *list + 1;
}

uint32_t *scan_freq_set_to_fixed_array(const struct scan_freq_set *set,
					size_t *len_out)
{
	uint8_t count = 0;
	uint32_t *freqs;

	count = __builtin_popcount(set->channels_2ghz) +
				l_uintset_size(set->channels_5ghz) +
				l_uintset_size(set->channels_6ghz);

	if (!count)
		return NULL;

	freqs = l_new(uint32_t, count);

	scan_freq_set_foreach(set, add_foreach, &freqs);

	/* Move pointer back to start of list */
	freqs -= count;

	*len_out = count;

	return freqs;
}
