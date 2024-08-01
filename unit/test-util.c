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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ell/ell.h>

#include "src/defs.h"
#include "src/util.h"

struct ssid_test_data {
	size_t len;
	uint8_t ssid[SSID_MAX_SIZE];
	const char *string;
	bool result;
};

const struct ssid_test_data ssid_samples[] = {
	{ 0, { }, "", true },
	{ 1, { }, "", true },
	{ 32, { }, "", true },
	{ 33, { }, "", true },
	{ 33, { 'a', 'b', 'c', }, "", true },
	{ 42, { }, "", true },
	{ 3, { 'f', 'o', 'o', }, "foo", true },
	{ 3, { }, "", true },
	{ 3, { 'f', 'o', 'o', }, "bar", false },
	{ 3, { 'f', 'o', 'o', 0xff, }, "foo", true },
	{ 5, { 'f', 'o', 'o', 'b', 'a', 'r' }, "fooba", true },
	{ 5, { 'f', 'o', 'o', 'b', 'a', 'r' }, "foobar", false },
	{ 5, { 'f', 'o', 'o', 'b', 'a', 'r' }, "oobar", false },
	{ 4, { 'x', 'y', 'z', 0xff }, "xyz�", true },
	{ 6, { 'x', 'y', 'z', 0xff, '1', '2' }, "xyz�12", true },
	{ 7, { 0xf0, 0xf3, '3', '4', '5', '6', '7', }, "��34567", true },
	{ 6, { 0xc3, 0x96, '3', '4', '5', '6' }, "Ö3456", true },
	{ 6, { '1', 0xc3, 0x96, '4', '5', '6' }, "1Ö456", true },
	{ 6, { '1', '2', '3', '4', 0xc3, 0x96 }, "1234Ö", true },
};

static void ssid_to_utf8(const void *data)
{
	const struct ssid_test_data *ssid = data;
	int i = 0, samples = L_ARRAY_SIZE(ssid_samples);

	while (i < samples) {
		const char *result = util_ssid_to_utf8(ssid[i].len,
						ssid[i].ssid);

		assert(!memcmp(ssid[i].string, result,
				strlen(ssid[i].string)) == ssid[i].result);

		i++;
	}

}

static const char ms_id[] = "domain\\user";
static const char id[] = "user@domain";
static const char no_separator[] = "username";

static void get_domain_test(const void *data)
{
	const char *test;

	test = util_get_domain(ms_id);

	assert(strcmp(test, "domain") == 0);

	test = util_get_domain(id);

	assert(strcmp(test, "domain") == 0);

	test = util_get_domain(no_separator);

	assert(strcmp(test, "username") == 0);
}

static void get_username_test(const void *data)
{
	const char *test;

	test = util_get_username(ms_id);

	assert(strcmp(test, "user") == 0);

	test = util_get_username(id);

	assert(strcmp(test, "user") == 0);

	test = util_get_username(no_separator);

	assert(strcmp(test, "username") == 0);
}

static void ip_prefix_test(const void *data)
{
	unsigned int i;
	char *invalid[] = {
		"192.168.0.0", /* Not prefix notation */
		"192.168./22", /* Incomplete notation */
		"192.168.0.1/255", /* Too long prefix */
		"192.168.0.1/0", /* Too short prefix */
		"192.168.0.1/16", /* Invalid prefix */
		"192.168.1.2.3/24", /* IP too long */
		"192.168.111.222.333.444/20", /* IP way too long */
	};

	struct {
		char *ip_prefix;
		uint8_t prefix;
		char *start;
		char *end;
		char *mask;
	} valid[] = {
		{"192.168.80.0/22", 22, "192.168.80.1",
				"192.168.83.254", "255.255.252.0"},
		{"192.168.128.0/20", 20, "192.168.128.1",
				"192.168.143.254", "255.255.240.0"},
		{"192.168.0.0/25", 25, "192.168.0.1",
				"192.168.0.126", "255.255.255.128"},
		{"192.168.0.0/29", 29, "192.168.0.1",
				"192.168.0.6", "255.255.255.248"},
		{"192.168.0.128/25", 25, "192.168.0.129",
				"192.168.0.254", "255.255.255.128"},
		/* Valid notation which is maximum length */
		{"192.168.111.108/30", 30, "192.168.111.109",
				"192.168.111.110", "255.255.255.252"},
	};

	for (i = 0; i < L_ARRAY_SIZE(invalid); i++)
		assert(!util_ip_prefix_tohl(invalid[i], NULL, NULL,
						NULL, NULL));

	for (i = 0; i < L_ARRAY_SIZE(valid); i++) {
		uint8_t prefix;
		uint32_t start;
		uint32_t end;
		uint32_t mask;
		struct in_addr ia;
		char ip[INET_ADDRSTRLEN];

		assert(util_ip_prefix_tohl(valid[i].ip_prefix,
						&prefix, &start, &end, &mask));

		assert(valid[i].prefix == prefix);

		ia.s_addr = htonl(start);
		assert(inet_ntop(AF_INET, &ia, ip, INET_ADDRSTRLEN));
		assert(strcmp(ip, valid[i].start) == 0);

		ia.s_addr = htonl(end);
		assert(inet_ntop(AF_INET, &ia, ip, INET_ADDRSTRLEN));
		assert(strcmp(ip, valid[i].end) == 0);

		ia.s_addr = htonl(mask);
		assert(inet_ntop(AF_INET, &ia, ip, INET_ADDRSTRLEN));
		assert(strcmp(ip, valid[i].mask) == 0);
	}
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/util/ssid_to_utf8/", ssid_to_utf8, ssid_samples);
	l_test_add("/util/get_domain/", get_domain_test, NULL);
	l_test_add("/util/get_username/", get_username_test, NULL);
	l_test_add("/util/ip_prefix/", ip_prefix_test, NULL);

	return l_test_run();
}
