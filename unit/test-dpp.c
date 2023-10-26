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

#include <assert.h>
#include <stdio.h>

#include <ell/ell.h>

#include "src/dpp-util.h"
#include "src/util.h"
#include "ell/useful.h"

struct dpp_test_info {
	const char *uri;
	bool expect_fail;
	uint32_t expected_freqs[10];
	struct dpp_uri_info result;
};

struct dpp_test_info all_values = {
	.uri = "DPP:C:81/1,115/36;I:SN=4774LH2b4044;M:5254005828e5;V:2;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;;",
	.result = {
		.mac = { 0x52, 0x54, 0x00, 0x58, 0x28, 0xe5 },
		.version = 2,
	},
	.expected_freqs = { 2412, 5180, 0 }
};

struct dpp_test_info no_type = {
	.uri = "C:81/1;K:shouldnotmatter;;",
	.expect_fail = true
};

struct dpp_test_info empty = {
	.uri = "DPP:",
	.expect_fail = true
};

struct dpp_test_info no_key = {
	.uri = "DPP:C:81/1,115/36;I:SN=4774LH2b4044;M:5254005828e5;V:2;;",
	.expect_fail = true
};

struct dpp_test_info data_after_terminator = {
	.uri = "DPP:K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;;C:81/1;;",
	.expect_fail = true
};

struct dpp_test_info single_terminator = {
	.uri = "DPP:K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;",
	.expect_fail = true
};

struct dpp_test_info no_terminator = {
	.uri = "DPP:K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=",
	.expect_fail = true
};

struct dpp_test_info bad_key = {
	.uri = "DPP:K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0;;",
	.expect_fail = true
};

struct dpp_test_info unexpected_id = {
	.uri = "DPP:Z:somedata;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;;",
	.expect_fail = true
};

struct dpp_test_info bad_channels[] = {
	{
		.uri = "DPP:C:;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;;",
		.expect_fail = true
	},
	{
		.uri = "DPP:C:81;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;;",
		.expect_fail = true
	},
	{
		.uri = "DPP:C:81/;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;;",
		.expect_fail = true
	},
	{
		.uri = "DPP:C:81/1,;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;;",
		.expect_fail = true
	},
	{
		.uri = "DPP:C:81/1,81/;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;;",
		.expect_fail = true
	},
	{
		.uri = "DPP:C:81/1,/;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;;",
		.expect_fail = true
	},
};

static bool verify_info(const struct dpp_uri_info *parsed,
			const struct dpp_test_info *result)
{
	const struct dpp_uri_info *expected = &result->result;
	uint32_t i;

	assert(!memcmp(parsed->mac, expected->mac, 6));
	assert(parsed->version == expected->version);
	assert(parsed->boot_public != NULL);

	for (i = 0; result->expected_freqs[i]; i++)
		assert(scan_freq_set_contains(parsed->freqs,
						result->expected_freqs[i]));

	return true;
}

static void test_uri_parse(const void *data)
{
	const struct dpp_test_info *test_info = data;
	struct dpp_uri_info *info;

	info = dpp_parse_uri(test_info->uri);
	if (test_info->expect_fail) {
		assert(info == NULL);
		return;
	}

	assert(verify_info(info, test_info));

	dpp_free_uri_info(info);
}


static void test_bad_channels(const void *data)
{
	unsigned int i;

	for (i = 0; i < L_ARRAY_SIZE(bad_channels); i++)
		test_uri_parse(&bad_channels[i]);
}

struct dpp_test_vector {
	/* Initiator values */
	const char *i_proto_public;
	const char *i_proto_private;
	const char *i_boot_public;
	const char *i_boot_private;
	const char *i_nonce;
	const char *i_auth;
	const char *i_asn1;

	/* Responder values */
	const char *r_proto_public;
	const char *r_proto_private;
	const char *r_boot_public;
	const char *r_boot_private;
	const char *r_nonce;
	const char *r_auth;
	const char *r_asn1;

	const char *k1;
	const char *k2;
	const char *ke;
	const char *mx;
	const char *nx;
	const char *lx;
};

/*
 * B.1 Test Vectors for DPP Authentication Using P-256 for
 * Mutual Authentication
 */
static struct dpp_test_vector mutual_p256 = {
	.i_proto_public = "50a532ae2a07207276418d2fa630295d45569be425aa634f02014d00a7d1f61a"
			"e14f35a5a858bccad90d126c46594c49ef82655e78888e15a32d916ac2172491",
	.i_proto_private = "a87de9afbb406c96e5f79a3df895ecac3ad406f95da66314c8cb3165e0c61783",
	/*
	 * The spec uses a 31 octet Y value, a zero byte was prepended to the
	 * Y value here otherwise the point cannot be created
	 */
	.i_boot_public = "88b37ed91938b5197097808a6244847617892046d93b9501afd48fa0f148dfde"
			"00f73b6991287884a9c9a33f8e0691f14d44b59811e9d8242d010270b0d33ec0",
	.i_boot_private = "15b2a83c5a0a38b61f2aa8200ee4994b8afdc01c58507d10d0a38f7eedf051bb",
	.i_nonce = "13f4602a16daeb69712263b9c46cba31",
	.i_auth = "d34944bb4b1f05caebda762c6e4ae034c819ec2f62a57dcfade2473876e007b2",
	.i_asn1 = "3039301306072a8648ce3d020106082a8648ce3d0301070322000288b37ed919"
			"38b5197097808a6244847617892046d93b9501afd48fa0f148dfde",

	.r_proto_public = "5e3fb3576884887f17c3203d8a3a6c2fac722ef0e2201b61ac73bc655c709a90"
			"2d4b030669fb9eff8b0a79fa7c1a172ac2a92c626256963f9274dc90682c81e5",
	.r_proto_private = "f798ed2e19286f6a6efe210b1863badb99af2a14b497634dbfd2a97394fb5aa5",
	.r_boot_public = "09c585a91b4df9fd25a045201885c39cc5cfae397ddaeda957dec57fa0e3503f"
			"52bf05968198a2f92883e96a386d767579883302dbf292105c90a43694c2fd5c",
	.r_boot_private = "54ce181a98525f217216f59b245f60e9df30ac7f6b26c939418cfc3c42d1afa0",
	.r_nonce = "3d0cfb011ca916d796f7029ff0b43393",
	.r_auth = "a725abe6dc66ccf3aa3d6d61a19932fcbb0799ed09ff78e5bc6d4ea5ef8e8670",
	.r_asn1 = "3039301306072a8648ce3d020106082a8648ce3d0301070322000209c585a91b"
			"4df9fd25a045201885c39cc5cfae397ddaeda957dec57fa0e3503f",

	.k1 = "3d832a02ed6d7fc1dc96d2eceab738cf01c0028eb256be33d5a21a720bfcf949",
	.k2 = "ca08bdeeef838ddf897a5f01f20bb93dc5a895cb86788ca8c00a7664899bc310",
	.ke = "b6db65526c9a0174c3bed56f7e614f3a656233c078693249ac3516425127e5d5",
	.mx = "dde2878117d69745be4f916a2dd14269d783d1d788c603bb8746beabbd1dbbbc",
	.nx = "92118478b75c21c2c59340c842b5bce560a535f60bc37a75fe390d738c58d8e8",
	.lx = "fb737234c973cc3a36e64e5170a32f12089d198c73c2fd85a53d0b282530fd02"
};

/*
 * B.2 Test Vectors for DPP Authentication Using P-256 for
 * Responder-only Authentication
 */
static struct dpp_test_vector responder_only_p256 = {
	.i_proto_public = "50a532ae2a07207276418d2fa630295d45569be425aa634f02014d00a7d1f61a"
			"e14f35a5a858bccad90d126c46594c49ef82655e78888e15a32d916ac2172491",
	.i_nonce = "13f4602a16daeb69712263b9c46cba31",
	.i_auth = "787d1189b526448d2901e7f6c22775ce514fce52fc886c1e924f2fbb8d97b210",

	.r_proto_public = "5e3fb3576884887f17c3203d8a3a6c2fac722ef0e2201b61ac73bc655c709a90"
			"2d4b030669fb9eff8b0a79fa7c1a172ac2a92c626256963f9274dc90682c81e5",
	.r_proto_private = "f798ed2e19286f6a6efe210b1863badb99af2a14b497634dbfd2a97394fb5aa5",
	.r_boot_public = "09c585a91b4df9fd25a045201885c39cc5cfae397ddaeda957dec57fa0e3503f"
			"52bf05968198a2f92883e96a386d767579883302dbf292105c90a43694c2fd5c",
	.r_boot_private = "54ce181a98525f217216f59b245f60e9df30ac7f6b26c939418cfc3c42d1afa0",
	.r_nonce = "3d0cfb011ca916d796f7029ff0b43393",
	.r_auth = "43509ef7137d8c2fbe66d802ae09dedd94d41b8cbfafb4954782014ff4a3f91c",
	.r_asn1 = "3039301306072a8648ce3d020106082a8648ce3d0301070322000209c585a91b"
			"4df9fd25a045201885c39cc5cfae397ddaeda957dec57fa0e3503f",

	.k1 = "3d832a02ed6d7fc1dc96d2eceab738cf01c0028eb256be33d5a21a720bfcf949",
	.k2 = "ca08bdeeef838ddf897a5f01f20bb93dc5a895cb86788ca8c00a7664899bc310",
	.ke = "c8882a8ab30c878467822534138c704ede0ab1e873fe03b601a7908463fec87a",
	.mx = "dde2878117d69745be4f916a2dd14269d783d1d788c603bb8746beabbd1dbbbc",
	.nx = "92118478b75c21c2c59340c842b5bce560a535f60bc37a75fe390d738c58d8e8",
};

#define HEX2BUF(s, buf, _len) { \
	size_t _len_out; \
	unsigned char *_tmp = l_util_from_hexstring(s, &_len_out); \
	memcpy(buf, _tmp, _len_out); \
	l_free(_tmp); \
}

#define CHECK_FROM_STR(str, bytes, __len) \
({ \
	uint64_t __tmp[L_ECC_MAX_DIGITS]; \
	HEX2BUF(str, __tmp, __len); \
	assert(!memcmp(bytes, __tmp, __len)); \
})

static void test_key_derivation(const void *data)
{
	const struct dpp_test_vector *vector = data;

	uint64_t tmp[L_ECC_MAX_DIGITS * 2];
	const struct l_ecc_curve *curve = l_ecc_curve_from_ike_group(19);
	_auto_(l_ecc_point_free) struct l_ecc_point *i_boot_public = NULL;
	_auto_(l_ecc_scalar_free) struct l_ecc_scalar *i_boot_private = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *i_proto_public = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *r_boot_public = NULL;
	_auto_(l_ecc_scalar_free) struct l_ecc_scalar *r_boot_private = NULL;
	_auto_(l_ecc_scalar_free) struct l_ecc_scalar *r_proto_private = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *r_proto_public = NULL;
	_auto_(l_ecc_scalar_free) struct l_ecc_scalar *m = NULL;
	_auto_(l_ecc_scalar_free) struct l_ecc_scalar *n = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *l = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *from_asn1 = NULL;
	uint64_t k1[L_ECC_MAX_DIGITS];
	uint64_t k2[L_ECC_MAX_DIGITS];
	uint64_t ke[L_ECC_MAX_DIGITS];
	uint8_t i_nonce[16];
	uint8_t r_nonce[16];
	uint64_t r_auth[L_ECC_MAX_DIGITS];
	uint64_t i_auth[L_ECC_MAX_DIGITS];
	_auto_(l_free) uint8_t *asn1 = NULL;
	size_t asn1_len;

	HEX2BUF(vector->i_proto_public, tmp, 64);
	i_proto_public = l_ecc_point_from_data(curve,
						L_ECC_POINT_TYPE_FULL,
						tmp, 64);
	assert(i_proto_public);

	HEX2BUF(vector->r_boot_public, tmp, 64);
	r_boot_public = l_ecc_point_from_data(curve,
						L_ECC_POINT_TYPE_FULL,
						tmp, 64);
	assert(r_boot_public);

	if (vector->i_boot_public) {
		HEX2BUF(vector->i_boot_public, tmp, 64);
		i_boot_public = l_ecc_point_from_data(curve,
						L_ECC_POINT_TYPE_FULL,
						tmp, 64);
		assert(i_boot_public);
	}

	if (vector->i_boot_private) {
		HEX2BUF(vector->i_boot_private, tmp, 32);
		i_boot_private = l_ecc_scalar_new(curve, tmp, 32);
		assert(i_boot_private);
	}

	HEX2BUF(vector->r_asn1, tmp, sizeof(tmp));
	asn1 = dpp_point_to_asn1(r_boot_public, &asn1_len);

	from_asn1 = dpp_point_from_asn1(asn1, asn1_len);

	assert(l_ecc_points_are_equal(from_asn1, r_boot_public));

	assert(asn1_len == 59);
	assert(memcmp(tmp, asn1, asn1_len) == 0);

	if (vector->i_asn1) {
		HEX2BUF(vector->i_asn1, tmp, sizeof(tmp));
		asn1 = dpp_point_to_asn1(i_boot_public, &asn1_len);

		from_asn1 = dpp_point_from_asn1(asn1, asn1_len);

		assert(l_ecc_points_are_equal(from_asn1, i_boot_public));

		assert(asn1_len == 59);
		assert(memcmp(tmp, asn1, asn1_len) == 0);
	}


	HEX2BUF(vector->r_proto_public, tmp, 64);
	r_proto_public = l_ecc_point_from_data(curve,
						L_ECC_POINT_TYPE_FULL,
						tmp, 64);
	assert(r_proto_public);

	HEX2BUF(vector->r_boot_private, tmp, 32);
	r_boot_private = l_ecc_scalar_new(curve, tmp, 32);
	assert(r_boot_private);

	HEX2BUF(vector->r_proto_private, tmp, 32);
	r_proto_private = l_ecc_scalar_new(curve, tmp, 32);
	assert(r_proto_private);

	m = dpp_derive_k1(i_proto_public, r_boot_private, k1);
	assert(m);

	CHECK_FROM_STR(vector->k1, k1, 32);
	l_ecc_scalar_get_data(m, tmp, sizeof(tmp));
	CHECK_FROM_STR(vector->mx, tmp, 32);

	n = dpp_derive_k2(i_proto_public, r_proto_private, k2);
	assert(n);

	CHECK_FROM_STR(vector->k2, k2, 32);
	l_ecc_scalar_get_data(n, tmp, sizeof(tmp));
	CHECK_FROM_STR(vector->nx, tmp, 32);

	if (vector->lx) {
		/* Check initiator derivation */
		l = dpp_derive_li(r_boot_public, r_proto_public,
					i_boot_private);
		assert(l);
		l_ecc_point_get_x(l, tmp, sizeof(tmp));
		CHECK_FROM_STR(vector->lx, tmp, 32);
		l_ecc_point_free(l);
		l = NULL;

		/* Check responder derivation */
		l = dpp_derive_lr(r_boot_private, r_proto_private,
					i_boot_public);
		assert(l);
		l_ecc_point_get_x(l, tmp, sizeof(tmp));
		CHECK_FROM_STR(vector->lx, tmp, 32);

	}

	HEX2BUF(vector->i_nonce, i_nonce, 16);
	HEX2BUF(vector->r_nonce, r_nonce, 16);
	dpp_derive_ke(i_nonce, r_nonce, m, n, l, ke);

	CHECK_FROM_STR(vector->ke, ke, 32);

	dpp_derive_r_auth(i_nonce, r_nonce, 16, i_proto_public, r_proto_public,
				i_boot_public, r_boot_public, r_auth);
	CHECK_FROM_STR(vector->r_auth, r_auth, 32);

	dpp_derive_i_auth(r_nonce, i_nonce, 16, r_proto_public, i_proto_public,
				r_boot_public, i_boot_public, i_auth);
	CHECK_FROM_STR(vector->i_auth, i_auth, 32);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	if (l_checksum_is_supported(L_CHECKSUM_SHA256, true) &&
						l_getrandom_is_supported()) {
		l_test_add("DPP test responder-only key derivation",
						test_key_derivation,
						&responder_only_p256);
		l_test_add("DPP test mutual key derivation",
						test_key_derivation,
						&mutual_p256);
	}

	l_test_add("DPP URI parse", test_uri_parse, &all_values);
	l_test_add("DPP URI no type", test_uri_parse, &no_type);
	l_test_add("DPP URI empty", test_uri_parse, &empty);
	l_test_add("DPP URI no key", test_uri_parse, &no_key);
	l_test_add("DPP URI data after terminator", test_uri_parse,
				&data_after_terminator);
	l_test_add("DPP URI single terminator", test_uri_parse,
				&single_terminator);
	l_test_add("DPP URI no terminator", test_uri_parse,
				&no_terminator);
	l_test_add("DPP URI bad key", test_uri_parse, &bad_key);
	l_test_add("DPP URI bad channels", test_bad_channels, &bad_channels);
	l_test_add("DPP URI unexpected ID", test_uri_parse, &unexpected_id);

	return l_test_run();
}
