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

#include <stdio.h>

#include <errno.h>

#include <ell/ell.h>

#include "src/dpp-util.h"
#include "src/util.h"
#include "src/band.h"
#include "src/crypto.h"
#include "src/json.h"
#include "ell/useful.h"
#include "ell/asn1-private.h"
#include "src/ie.h"

static void append_freqs(struct l_string *uri,
					const uint32_t *freqs, size_t len)
{
	size_t i;
	enum band_freq band;

	l_string_append_printf(uri, "C:");

	for (i = 0; i < len; i++) {
		uint8_t oper_class;
		uint8_t channel = band_freq_to_channel(freqs[i], &band);

		/* For now use global operating classes */
		if (band == BAND_FREQ_2_4_GHZ)
			oper_class = 81;
		else
			oper_class = 115;

		l_string_append_printf(uri, "%u/%u", oper_class, channel);

		if (i != len - 1)
			l_string_append_c(uri, ',');
	}

	l_string_append_c(uri, ';');
}

char *dpp_generate_uri(const uint8_t *asn1, size_t asn1_len, uint8_t version,
			const uint8_t *mac, const uint32_t *freqs,
			size_t freqs_len, const char *info, const char *host)
{
	struct l_string *uri = l_string_new(256);
	char *base64;

	base64 = l_base64_encode(asn1, asn1_len, 0);

	l_string_append_printf(uri, "DPP:K:%s;", base64);
	l_free(base64);

	if (mac)
		l_string_append_printf(uri, "M:%02x%02x%02x%02x%02x%02x;",
					MAC_STR(mac));

	if (freqs)
		append_freqs(uri, freqs, freqs_len);

	if (info)
		l_string_append_printf(uri, "I:%s;", info);

	if (host)
		l_string_append_printf(uri, "H:%s;", host);

	if (version)
		l_string_append_printf(uri, "V:%u;", version);

	l_string_append_c(uri, ';');

	return l_string_unwrap(uri);
}

static uint32_t dpp_parse_akm(char *akms)
{
	_auto_(l_strv_free) char **split = l_strsplit(akms, '+');
	char **i = split;
	uint32_t akm_out = 0;

	while (*i) {
		if (!strncmp(*i, "psk", 3))
			akm_out |= IE_RSN_AKM_SUITE_PSK;
		else if (!strncmp(*i, "sae", 3))
			akm_out |= IE_RSN_AKM_SUITE_SAE_SHA256;

		i++;
	}

	return akm_out;
}

/*
 * TODO: This handles the most basic configuration. i.e. a configuration object
 * with ssid/passphrase/akm.
 */
struct dpp_configuration *dpp_parse_configuration_object(const char *json,
							size_t json_len)
{
	struct dpp_configuration *config;
	struct json_contents *c;
	struct json_iter iter;
	struct json_iter discovery;
	struct json_iter cred;
	_auto_(l_free) char *tech = NULL;
	_auto_(l_free) char *ssid = NULL;
	_auto_(l_free) char *akm = NULL;
	_auto_(l_free) char *pass = NULL;
	_auto_(l_free) char *psk = NULL;

	c = json_contents_new(json, json_len);
	if (!c)
		return NULL;

	json_iter_init(&iter, c);

	if (!json_iter_parse(&iter,
			JSON_MANDATORY("wi-fi_tech", JSON_STRING, &tech),
			JSON_MANDATORY("discovery", JSON_OBJECT, &discovery),
			JSON_MANDATORY("cred", JSON_OBJECT, &cred),
			JSON_UNDEFINED))
		goto free_contents;

	if (!tech || strncmp(tech, "infra", 5))
		goto free_contents;

	if (!json_iter_parse(&discovery,
			JSON_MANDATORY("ssid", JSON_STRING, &ssid),
			JSON_UNDEFINED))
		goto free_contents;

	if (!ssid || !util_ssid_is_utf8(strlen(ssid), (const uint8_t *) ssid))
		goto free_contents;

	if (!json_iter_parse(&cred,
			JSON_MANDATORY("akm", JSON_STRING, &akm),
			JSON_OPTIONAL("pass", JSON_STRING, &pass),
			JSON_OPTIONAL("psk", JSON_STRING, &psk),
			JSON_UNDEFINED))
		goto free_contents;

	if (!pass && (!psk || strlen(psk) != 64))
		goto free_contents;

	config = l_new(struct dpp_configuration, 1);

	if (pass)
		config->passphrase = l_steal_ptr(pass);
	else
		config->psk = l_steal_ptr(psk);

	memcpy(config->ssid, ssid, strlen(ssid));
	config->ssid_len = strlen(ssid);

	config->akm_suites = dpp_parse_akm(akm);
	if (!config->akm_suites)
		goto free_config;

	json_contents_free(c);

	return config;

free_config:
	dpp_configuration_free(config);
free_contents:
	json_contents_free(c);
	return NULL;
}

/*
 * The DPP spec does not specify a difference between FT AKMs and their normal
 * counterpart. Because of this any FT AKM will just result in the standard
 * 'psk' or 'sae' AKM.
 */
static const char *dpp_akm_to_string(enum ie_rsn_akm_suite akm_suite)
{
	switch (akm_suite) {
	case IE_RSN_AKM_SUITE_PSK:
	case IE_RSN_AKM_SUITE_FT_USING_PSK:
	case IE_RSN_AKM_SUITE_PSK_SHA256:
		return "psk";
	case IE_RSN_AKM_SUITE_SAE_SHA256:
	case IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256:
		return "sae";
	default:
		return NULL;
	}
}

char *dpp_configuration_to_json(struct dpp_configuration *config)
{
	_auto_(l_free) char *pass_or_psk;
	_auto_(l_free) char *ssid;

	ssid = l_malloc(config->ssid_len + 1);
	memcpy(ssid, config->ssid, config->ssid_len);
	ssid[config->ssid_len] = '\0';

	if (config->passphrase)
		pass_or_psk = l_strdup_printf("\"pass\":\"%s\"",
						config->passphrase);
	else
		pass_or_psk = l_strdup_printf("\"psk\":\"%s\"",
						config->psk);

	return l_strdup_printf("{\"wi-fi_tech\":\"infra\","
				"\"discovery\":{\"ssid\":\"%s\"},"
				"\"cred\":{\"akm\":\"%s\",%s}}",
				ssid, dpp_akm_to_string(config->akm_suites),
				pass_or_psk);
}

struct dpp_configuration *dpp_configuration_new(
					const struct l_settings *settings,
					const char *ssid,
					enum ie_rsn_akm_suite akm_suite)
{
	struct dpp_configuration *config;
	_auto_(l_free) char *passphrase = NULL;
	_auto_(l_free) char *psk = NULL;
	size_t ssid_len = strlen(ssid);

	if (!l_settings_has_group(settings, "Security"))
		return NULL;

	passphrase = l_settings_get_string(settings, "Security", "Passphrase");
	if (!passphrase) {
		psk = l_settings_get_string(settings, "Security",
						"PreSharedKey");
		if (!psk)
			return NULL;
	}

	config = l_new(struct dpp_configuration, 1);

	memcpy(config->ssid, ssid, ssid_len);
	config->ssid[ssid_len] = '\0';
	config->ssid_len = ssid_len;

	if (passphrase)
		config->passphrase = l_steal_ptr(passphrase);
	else
		config->psk = l_steal_ptr(psk);


	config->akm_suites = akm_suite;

	return config;
}

void dpp_configuration_free(struct dpp_configuration *config)
{
	if (config->passphrase)
		l_free(config->passphrase);

	if (config->psk)
		l_free(config->psk);

	l_free(config);
}

void dpp_attr_iter_init(struct dpp_attr_iter *iter, const uint8_t *pdu,
			size_t len)
{
	iter->pos = pdu;
	iter->end = pdu + len;
}

bool dpp_attr_iter_next(struct dpp_attr_iter *iter,
			enum dpp_attribute_type *type_out, size_t *len_out,
			const uint8_t **data_out)
{
	enum dpp_attribute_type type;
	uint16_t len;

	if (iter->pos + 4 > iter->end)
		return false;

	type = l_get_le16(iter->pos);
	len = l_get_le16(iter->pos + 2);

	iter->pos += 4;

	if (iter->end - iter->pos < len)
		return false;

	*type_out = type;
	*len_out = len;
	*data_out = iter->pos;

	iter->pos += len;

	return true;
}

size_t dpp_append_attr(uint8_t *to, enum dpp_attribute_type type,
				void *attr, size_t attr_len)
{
	l_put_le16(type, to);
	l_put_le16(attr_len, to + 2);
	memcpy(to + 4, attr, attr_len);

	return attr_len + 4;
}

/*
 * The use of ad0/ad1 differs with different protocol frame types, which is why
 * this is left up to the caller to pass the correct AD bytes. The usage is
 * defined in:
 *
 * 6.3.1.4 Protocol Conventions (for authentication)
 * 6.4.1 Overview (for configuration)
 *
 */
uint8_t *dpp_unwrap_attr(const void *ad0, size_t ad0_len, const void *ad1,
				size_t ad1_len, const void *key, size_t key_len,
				const void *wrapped, size_t wrapped_len,
				size_t *unwrapped_len)
{
	struct iovec ad[2];
	uint8_t *unwrapped;
	size_t ad_size = 0;

	if (ad0) {
		ad[ad_size].iov_base = (void *) ad0;
		ad[ad_size].iov_len = ad0_len;
		ad_size++;
	}

	if (ad1) {
		ad[ad_size].iov_base = (void *) ad1;
		ad[ad_size].iov_len = ad1_len;
		ad_size++;
	}

	unwrapped = l_malloc(wrapped_len - 16);

	if (!aes_siv_decrypt(key, key_len, wrapped, wrapped_len, ad, ad_size,
				unwrapped)) {
		l_free(unwrapped);
		return NULL;
	}

	*unwrapped_len = wrapped_len - 16;

	return unwrapped;
}

/*
 * Encrypt DPP attributes encapsulated in DPP wrapped data.
 *
 * ad0/ad0_len - frame specific AD0 component
 * ad1/ad0_len - frame specific AD1 component
 * to - buffer to encrypt data.
 * to_len - size of 'to'
 * key - key used to encrypt
 * key_len - size of 'key'
 * num_attrs - number of attributes listed (type, length, data triplets)
 * ... - List of attributes, Type, Length, and data
 */
size_t dpp_append_wrapped_data(const void *ad0, size_t ad0_len,
				const void *ad1, size_t ad1_len,
				uint8_t *to, size_t to_len,
				const void *key, size_t key_len,
				size_t num_attrs, ...)
{
	size_t i;
	size_t attrs_len = 0;
	_auto_(l_free) uint8_t *plaintext = NULL;
	uint8_t *ptr;
	struct iovec ad[2];
	size_t ad_size = 0;
	va_list va;

	va_start(va, num_attrs);

	/* Count up total attributes length */
	for (i = 0; i < num_attrs; i++) {
		va_arg(va, enum dpp_attribute_type);
		attrs_len += va_arg(va, size_t) + 4;
		va_arg(va, void*);
	}

	va_end(va);

	if (to_len < attrs_len + 4 + 16)
		return false;

	plaintext = l_malloc(attrs_len);

	ptr = plaintext;

	va_start(va, num_attrs);

	/* Build up plaintext attributes */
	for (i = 0; i < num_attrs; i++) {
		enum dpp_attribute_type type = va_arg(va,
						enum dpp_attribute_type);
		size_t l = va_arg(va, size_t);
		void *p = va_arg(va, void *);

		l_put_le16(type, ptr);
		ptr += 2;
		l_put_le16(l, ptr);
		ptr += 2;
		memcpy(ptr, p, l);
		ptr += l;
	}

	va_end(va);

	ptr = to;

	l_put_le16(DPP_ATTR_WRAPPED_DATA, ptr);
	ptr += 2;
	l_put_le16(attrs_len + 16, ptr);
	ptr += 2;

	if (ad0) {
		ad[ad_size].iov_base = (void *) ad0;
		ad[ad_size].iov_len = ad0_len;
		ad_size++;
	}

	if (ad1) {
		ad[ad_size].iov_base = (void *) ad1;
		ad[ad_size].iov_len = ad1_len;
		ad_size++;
	}

	if (!aes_siv_encrypt(key, key_len, plaintext, attrs_len,
				ad, ad_size, ptr))
		return 0;

	return attrs_len + 4 + 16;
}

/*
 * EasyConnect 2.0 Table 3. Key and Nonce Length Dependency on Prime Length
 */
static enum l_checksum_type dpp_sha_from_key_len(size_t len)
{
	if (len == 32)
		return L_CHECKSUM_SHA256;
	else if (len == 48)
		return L_CHECKSUM_SHA384;
	else if (len == 64)
		return L_CHECKSUM_SHA512;
	else
		return L_CHECKSUM_NONE;

}

size_t dpp_nonce_len_from_key_len(size_t len)
{
	if (len == 32)
		return 16;
	else if (len == 48)
		return 24;
	else if (len == 64)
		return 32;
	else
		return 0;
}

/*
 * 3.2.2
 * H()
 */
bool dpp_hash(enum l_checksum_type type, uint8_t *out, unsigned int num, ...)
{
	struct l_checksum *sha = l_checksum_new(type);
	size_t hsize = l_checksum_digest_length(type);
	unsigned int i;

	va_list va;

	va_start(va, num);

	for (i = 0; i < num; i++) {
		void *data = va_arg(va, void *);
		size_t len = va_arg(va, size_t);

		l_checksum_update(sha, data, len);
	}

	va_end(va);

	l_checksum_get_digest(sha, out, hsize);
	l_checksum_free(sha);

	return true;
}

/*
 * 3.2.2
 *
 * HKDF is defined as:
 *
 * key = HKDF(salt, info, ikm)
 *     = HKDF-Expand(HKDF-Extract(salt, ikm), info, len)
 *
 * Note: A NULL 'salt' means a zero'ed buffer and 'salt_len' should still be
 *       set for this zero'ed buffer length.
 */
static bool dpp_hkdf(enum l_checksum_type sha, const void *salt,
			size_t salt_len, const char *info, const void *ikm,
			size_t ikm_len, void *out, size_t out_len)
{
	uint8_t tmp[64];
	uint8_t zero_salt[64] = { 0 };
	size_t hash_len = l_checksum_digest_length(sha);

	if (!salt)
		salt = zero_salt;

	if (!hkdf_extract(sha, salt, salt_len, 1, tmp,
				ikm, ikm_len))
		return false;

	return hkdf_expand(sha, tmp, hash_len, info, out, out_len);
}

bool dpp_derive_r_auth(const void *i_nonce, const void *r_nonce,
				size_t nonce_len, struct l_ecc_point *i_proto,
				struct l_ecc_point *r_proto,
				struct l_ecc_point *r_boot,
				void *r_auth)
{
	uint64_t pix[L_ECC_MAX_DIGITS];
	uint64_t prx[L_ECC_MAX_DIGITS];
	uint64_t brx[L_ECC_MAX_DIGITS];
	size_t keys_len;
	uint8_t zero = 0;
	enum l_checksum_type type;

	keys_len = l_ecc_point_get_x(i_proto, pix, sizeof(pix));
	l_ecc_point_get_x(r_proto, prx, sizeof(prx));
	l_ecc_point_get_x(r_boot, brx, sizeof(brx));

	type = dpp_sha_from_key_len(keys_len);

	/*
	 * R-auth = H(I-nonce | R-nonce | PI.x | PR.x | [ BI.x | ] BR.x | 0)
	 */
	return dpp_hash(type, r_auth, 6, i_nonce, nonce_len, r_nonce, nonce_len,
			pix, keys_len, prx, keys_len, brx, keys_len, &zero, 1);
}

bool dpp_derive_i_auth(const void *r_nonce, const void *i_nonce,
				size_t nonce_len, struct l_ecc_point *r_proto,
				struct l_ecc_point *i_proto,
				struct l_ecc_point *r_boot, void *i_auth)
{
	uint64_t prx[L_ECC_MAX_DIGITS];
	uint64_t pix[L_ECC_MAX_DIGITS];
	uint64_t brx[L_ECC_MAX_DIGITS];
	size_t keys_len;
	uint8_t one = 1;
	enum l_checksum_type type;

	keys_len = l_ecc_point_get_x(r_proto, prx, sizeof(prx));
	l_ecc_point_get_x(i_proto, pix, sizeof(pix));
	l_ecc_point_get_x(r_boot, brx, sizeof(brx));

	type = dpp_sha_from_key_len(keys_len);

	/*
	 * I-auth = H(R-nonce | I-nonce | PR.x | PI.x | BR.x | [ BI.x | ] 1)
	 */
	return dpp_hash(type, i_auth, 6, r_nonce, nonce_len, i_nonce, nonce_len,
			prx, keys_len, pix, keys_len, brx, keys_len, &one, 1);
}

/*
 * Derives key k1. This returns the intermediate secret M.x used in deriving
 * key ke.
 */
struct l_ecc_scalar *dpp_derive_k1(const struct l_ecc_point *i_proto_public,
				const struct l_ecc_scalar *boot_private,
				void *k1)
{
	struct l_ecc_scalar *m;
	uint64_t mx_bytes[L_ECC_MAX_DIGITS];
	ssize_t key_len;
	enum l_checksum_type sha;

	if (!l_ecdh_generate_shared_secret(boot_private, i_proto_public, &m))
		return NULL;

	key_len = l_ecc_scalar_get_data(m, mx_bytes, sizeof(mx_bytes));
	if (key_len < 0)
		goto free_m;

	sha = dpp_sha_from_key_len(key_len);

	if (!dpp_hkdf(sha, NULL, key_len, "first intermediate key", mx_bytes,
			key_len, k1, key_len))
		goto free_m;

	return m;

free_m:
	l_ecc_scalar_free(m);
	return NULL;
}

/*
 * Derives key k2. This returns the intermediate secret N.x used in deriving
 * key ke.
 */
struct l_ecc_scalar *dpp_derive_k2(const struct l_ecc_point *i_proto_public,
				const struct l_ecc_scalar *proto_private,
				void *k2)
{
	struct l_ecc_scalar *n;
	uint64_t nx_bytes[L_ECC_MAX_DIGITS];
	ssize_t key_len;
	enum l_checksum_type sha;

	if (!l_ecdh_generate_shared_secret(proto_private, i_proto_public, &n))
		return NULL;

	key_len = l_ecc_scalar_get_data(n, nx_bytes, sizeof(nx_bytes));
	if (key_len < 0)
		goto free_n;

	sha = dpp_sha_from_key_len(key_len);

	if (!dpp_hkdf(sha, NULL, key_len, "second intermediate key", nx_bytes,
			key_len, k2, key_len))
		goto free_n;

	return n;

free_n:
	l_ecc_scalar_free(n);
	return NULL;
}

bool dpp_derive_ke(const uint8_t *i_nonce, const uint8_t *r_nonce,
				struct l_ecc_scalar *m, struct l_ecc_scalar *n,
				void *ke)
{
	uint8_t nonces[32 + 32];
	size_t nonce_len;
	uint64_t mx_bytes[L_ECC_MAX_DIGITS];
	uint64_t nx_bytes[L_ECC_MAX_DIGITS];
	uint64_t bk[L_ECC_MAX_DIGITS];
	ssize_t key_len;
	enum l_checksum_type sha;

	key_len = l_ecc_scalar_get_data(m, mx_bytes, sizeof(mx_bytes));
	l_ecc_scalar_get_data(n, nx_bytes, sizeof(nx_bytes));

	nonce_len = dpp_nonce_len_from_key_len(key_len);
	sha = dpp_sha_from_key_len(key_len);

	memcpy(nonces, i_nonce, nonce_len);
	memcpy(nonces + nonce_len, r_nonce, nonce_len);

	/* bk = HKDF-Extract(I-nonce | R-nonce, M.x | N.x [ | L.x]) */
	if (!hkdf_extract(sha, nonces, nonce_len * 2, 2, bk, mx_bytes,
			key_len, nx_bytes, key_len))
		return false;

	/* ke = HKDF-Expand(bk, "DPP Key", length) */
	return hkdf_expand(sha, bk, key_len, "DPP Key", ke, key_len);
}

/*
 * Values derived from OID definitions in https://www.secg.org/sec2-v2.pdf
 * Appendix A.2.1
 *
 * 1.2.840.10045.2.1 (ecPublicKey)
 */
static struct asn1_oid ec_oid = {
	.asn1_len = 7,
	.asn1 = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 }
};

/* 1.2.840.10045.3.1.7 (prime256v1) */
static struct asn1_oid ec_p256_oid = {
	.asn1_len = 8,
	.asn1 = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }
};

/* 1.3.132.0.34 (secp384r1) */
static struct asn1_oid ec_p384_oid = {
	.asn1_len = 5,
	.asn1 = { 0x2B, 0x81, 0x04, 0x00, 0x22 }
};

uint8_t *dpp_point_to_asn1(const struct l_ecc_point *p, size_t *len_out)
{
	uint8_t *asn1;
	uint8_t *ptr;
	struct asn1_oid *key_type;
	const struct l_ecc_curve *curve = l_ecc_point_get_curve(p);
	ssize_t key_size = l_ecc_curve_get_scalar_bytes(curve);
	uint64_t x[L_ECC_MAX_DIGITS];
	ssize_t ret;
	size_t len;
	uint8_t point_type;

	switch (key_size) {
	case 32:
		key_type = &ec_p256_oid;
		break;
	case 48:
		key_type = &ec_p384_oid;
		break;
	default:
		return NULL;
	}

	ret = l_ecc_point_get_x(p, x, sizeof(x));
	if (ret < 0 || ret != key_size)
		return NULL;

	len = 2 + ec_oid.asn1_len + 2 + key_type->asn1_len + 2 + key_size + 4;

	/*
	 * Set the type to whatever avoids doing p - y when reading in the
	 * key. Working backwards from l_ecc_point_from_data if Y is odd and
	 * the type is BIT0 there is no subtraction. Similarly if Y is even
	 * and the type is BIT1.
	 */
	if (l_ecc_point_y_isodd(p))
		point_type = L_ECC_POINT_TYPE_COMPRESSED_BIT0;
	else
		point_type = L_ECC_POINT_TYPE_COMPRESSED_BIT1;

	if (L_WARN_ON(len > 128))
		return NULL;

	asn1 = l_malloc(len + 2);
	ptr = asn1;

	*ptr++ = ASN1_ID_SEQUENCE;
	/* Length of both OIDs and key, plus tag/len bytes */
	*ptr++ = len;

	*ptr++ = ASN1_ID_SEQUENCE;

	len = ec_oid.asn1_len + key_type->asn1_len + 4;

	*ptr++ = len;

	*ptr++ = ASN1_ID_OID;
	*ptr++ = ec_oid.asn1_len;
	memcpy(ptr, ec_oid.asn1, ec_oid.asn1_len);
	ptr += ec_oid.asn1_len;

	*ptr++ = ASN1_ID_OID;
	*ptr++ = key_type->asn1_len;
	memcpy(ptr, key_type->asn1, key_type->asn1_len);
	ptr += key_type->asn1_len;

	*ptr++ = ASN1_ID_BIT_STRING;
	*ptr++ = key_size + 2;
	*ptr++ = 0x00;
	*ptr++ = point_type;
	memcpy(ptr, x, key_size);
	ptr += key_size;

	if (len_out)
		*len_out = ptr - asn1;

	return asn1;
}

/*
 * Only checking for the ASN.1 form:
 *
 * SEQUENCE {
 * 	SEQUENCE {
 * 		OBJECT IDENTIFIER ecPublicKey
 * 		OBJECT IDENTIFIER key type (p256/p384)
 * 	}
 * 	BITSTRING (key data)
 * }
 */
struct l_ecc_point *dpp_point_from_asn1(const uint8_t *asn1, size_t len)
{

	const uint8_t *outer_seq;
	size_t outer_len;
	const uint8_t *inner_seq;
	size_t inner_len;
	const uint8_t *elem;
	const uint8_t *key_data;
	size_t elen = 0;
	uint8_t tag;
	unsigned int curve_num;
	const struct l_ecc_curve *curve;

	/* SEQUENCE */
	outer_seq = asn1_der_find_elem(asn1, len, 0, &tag, &outer_len);
	if (!outer_seq || tag != ASN1_ID_SEQUENCE)
		return NULL;

	/* SEQUENCE */
	inner_seq = asn1_der_find_elem(outer_seq, outer_len, 0, &tag,
					&inner_len);
	if (!inner_seq || tag != ASN1_ID_SEQUENCE)
		return NULL;

	/* OBJECT IDENTIFIER (ecPublicKey) */
	elem = asn1_der_find_elem(inner_seq, inner_len, 0, &tag, &elen);
	if (!elem || tag != ASN1_ID_OID)
		return NULL;

	/* Check that this OID is ecPublicKey */
	if (!asn1_oid_eq(&ec_oid, elen, elem))
		return NULL;

	elem = asn1_der_find_elem(inner_seq, inner_len, 1, &tag, &elen);
	if (!elem || tag != ASN1_ID_OID)
		return NULL;

	/* Check if ELL supports this curve */
	if (asn1_oid_eq(&ec_p256_oid, elen, elem))
		curve_num = 19;
	else if (asn1_oid_eq(&ec_p384_oid, elen, elem))
		curve_num = 20;
	else
		return NULL;

	curve = l_ecc_curve_from_ike_group(curve_num);
	if (!curve)
		return NULL;

	/* BITSTRING */
	key_data = asn1_der_find_elem(outer_seq, outer_len, 1, &tag, &elen);
	if (!key_data || tag != ASN1_ID_BIT_STRING || elen < 2)
		return NULL;

	return l_ecc_point_from_data(curve, key_data[1],
					key_data + 2, elen - 2);
}

/*
 * Advances 'p' to the next character 'sep' plus one. strchr can be trusted to
 * find the next character, but we do need to check that the next character + 1
 * isn't the NULL terminator, i.e. that data actually exists past this point.
 */
#define TOKEN_NEXT(p, sep) \
({ \
	const char *_next = strchr((p), (sep)); \
	if (_next) { \
		if (*(_next + 1) == '\0') \
			_next = NULL; \
		else \
			_next++; \
	} \
	_next; \
})

/*
 * Finds the length of the current token (characters until next 'sep'). If no
 * 'sep' is found zero is returned.
 */
#define TOKEN_LEN(p, sep) \
({ \
	const char *_next = strchr((p), (sep)); \
	if (!_next) \
		_next = (p); \
	(_next - (p)); \
})

/*
 * Ensures 'p' points to something resembling a single character followed by
 * ':' followed by at least one non-null byte of data. This allows the parse
 * loop to safely advance the pointer to each tokens data (pos + 2)
 */
#define TOKEN_OK(p) \
	((p) && (p)[0] != '\0' && (p)[1] == ':' && (p)[2] != '\0') \

static struct scan_freq_set *dpp_parse_class_and_channel(const char *token,
							unsigned int len)
{
	const char *pos = token;
	char *end;
	struct scan_freq_set *freqs = scan_freq_set_new();

	/* Checking for <operclass>/<channel>,<operclass>/<channel>,... */
	for (; pos && pos < token + len; pos = TOKEN_NEXT(pos, ',')) {
		unsigned long r;
		uint8_t channel;
		uint8_t oper_class;
		uint32_t freq;

		/* strtoul accepts minus and plus signs before value */
		if (*pos == '-' || *pos == '+')
			goto free_set;

		/* to check uint8_t overflow */
		errno = 0;
		r = oper_class = strtoul(pos, &end, 10);

		if (errno == ERANGE || errno == EINVAL)
			goto free_set;
		/*
		 * Did strtoul not advance pointer, not reach the next
		 * token, or overflow?
		 */
		if (end == pos || *end != '/' || r != oper_class)
			goto free_set;

		pos = end + 1;

		if (*pos == '-' || *pos == '+')
			goto free_set;

		errno = 0;
		r = channel = strtoul(pos, &end, 10);

		if (errno == ERANGE || errno == EINVAL)
			goto free_set;
		/*
		 * Same verification as above, but also checks either for
		 * another pair (,) or end of this token (;)
		 */
		if (end == pos || (*end != ',' && *end != ';') || r != channel)
			goto free_set;

		freq = oci_to_frequency(oper_class, channel);
		if (!freq)
			goto free_set;

		scan_freq_set_add(freqs, freq);
	}

	if (token + len != end)
		goto free_set;

	if (scan_freq_set_isempty(freqs)) {
free_set:
		scan_freq_set_free(freqs);
		return NULL;
	}

	return freqs;
}

static int dpp_parse_mac(const char *str, unsigned int len, uint8_t *mac_out)
{
	uint8_t mac[6];
	unsigned int i;

	if (len != 12)
		return -EINVAL;

	for (i = 0; i < 12; i += 2) {
		if (!l_ascii_isxdigit(str[i]))
			return -EINVAL;

		if (!l_ascii_isxdigit(str[i + 1]))
			return -EINVAL;
	}

	if (sscanf(str, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
			&mac[0], &mac[1], &mac[2],
			&mac[3], &mac[4], &mac[5]) != 6)
		return -EINVAL;

	if (!util_is_valid_sta_address(mac))
		return -EINVAL;

	memcpy(mac_out, mac, 6);

	return 0;
}

static int dpp_parse_version(const char *str, unsigned int len,
				uint8_t *version_out)
{
	if (len != 1)
		return -EINVAL;

	if (str[0] != '1' && str[0] != '2')
		return -EINVAL;

	*version_out = str[0] - '0';

	return 0;
}

static struct l_ecc_point *dpp_parse_key(const char *str, unsigned int len)
{
	_auto_(l_free) uint8_t *decoded = NULL;
	size_t decoded_len;

	decoded = l_base64_decode(str, len, &decoded_len);
	if (!decoded)
		return NULL;

	return dpp_point_from_asn1(decoded, decoded_len);
}

/*
 * Parse a bootstrapping URI. This parses the tokens defined in the Easy Connect
 * spec, and verifies they are the correct syntax. Some values have extra
 * verification:
 *  - The bootstrapping key is base64 decoded and converted to an l_ecc_point
 *  - The operating class and channels are checked against the OCI table.
 *  - The version is checked to be either 1 or 2, as defined by the spec.
 *  - The MAC is verified to be a valid station address.
 */
struct dpp_uri_info *dpp_parse_uri(const char *uri)
{
	struct dpp_uri_info *info;
	const char *pos = uri;
	const char *end = uri + strlen(uri) - 1;
	int ret = 0;

	if (!l_str_has_prefix(pos, "DPP:"))
		return NULL;

	info = l_new(struct dpp_uri_info, 1);

	pos += 4;

	/* EasyConnect 5.2.1 - Bootstrapping information format */
	for (; TOKEN_OK(pos); pos = TOKEN_NEXT(pos, ';')) {
		unsigned int len = TOKEN_LEN(pos + 2, ';');

		if (!len)
			goto free_info;

		switch (*pos) {
		case 'C':
			info->freqs = dpp_parse_class_and_channel(pos + 2, len);
			if (!info->freqs)
				goto free_info;
			break;
		case 'M':
			ret = dpp_parse_mac(pos + 2, len, info->mac);
			if (ret < 0)
				goto free_info;
			break;
		case 'V':
			ret = dpp_parse_version(pos + 2, len, &info->version);
			if (ret < 0)
				goto free_info;
			break;
		case 'K':
			info->boot_public = dpp_parse_key(pos + 2, len);
			if (!info->boot_public)
				goto free_info;
			break;
		case 'H':
		case 'I':
			break;
		default:
			goto free_info;
		}
	}

	/* Extra data found after last token */
	if (pos != end)
		goto free_info;

	/* The public bootstrapping key is the only required token */
	if (!info->boot_public)
		goto free_info;

	return info;

free_info:
	dpp_free_uri_info(info);
	return NULL;
}

void dpp_free_uri_info(struct dpp_uri_info *info)
{
	if (info->freqs)
		scan_freq_set_free(info->freqs);

	if (info->boot_public)
		l_ecc_point_free(info->boot_public);

	if (info->information)
		l_free(info->information);

	if (info->host)
		l_free(info->host);

	l_free(info);
}
