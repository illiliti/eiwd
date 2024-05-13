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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <arpa/inet.h>

#include <ell/ell.h>

#include "ell/useful.h"
#include "src/util.h"
#include "src/crypto.h"
#include "src/ie.h"

const unsigned char ieee_oui[3] = { 0x00, 0x0f, 0xac };
const unsigned char microsoft_oui[3] = { 0x00, 0x50, 0xf2 };
const unsigned char wifi_alliance_oui[3] = { 0x50, 0x6f, 0x9a };

void ie_tlv_iter_init(struct ie_tlv_iter *iter, const unsigned char *tlv,
			unsigned int len)
{
	iter->tlv = tlv;
	iter->max = len;
	iter->pos = 0;
}

void ie_tlv_iter_recurse(struct ie_tlv_iter *iter,
				struct ie_tlv_iter *recurse)
{
	recurse->tlv = iter->data;
	recurse->max = iter->len;
	recurse->pos = 0;
}

bool ie_tlv_iter_next(struct ie_tlv_iter *iter)
{
	const unsigned char *tlv = iter->tlv + iter->pos;
	const unsigned char *end = iter->tlv + iter->max;
	unsigned int tag;
	unsigned int len;

	if (iter->pos + 1 >= iter->max)
		return false;

	tag = *tlv++;
	len = *tlv++;

	if (tag == IE_TYPE_EXTENSION) {
		if (iter->pos + 2 >= iter->max || len < 1)
			return false;

		tag = 256 + *tlv++;
		len--;
	}

	if (tlv + len > end)
		return false;

	iter->tag = tag;
	iter->len = len;
	iter->data = tlv;

	iter->pos = tlv + len - iter->tlv;

	return true;
}

/*
 * Concatenate all vendor IEs with a given OUI + type.
 *
 * Returns a newly allocated buffer with the contents of the matching ies
 * copied into it.  @out_len is set to the overall size of the contents.
 * If no matching elements were found, NULL is returned and @out_len is
 * set to -ENOENT.
 */
static void *ie_tlv_vendor_ie_concat(const unsigned char oui[],
					unsigned char type,
					const unsigned char *ies,
					unsigned int len,
					bool empty_ok,
					ssize_t *out_len)
{
	struct ie_tlv_iter iter;
	const unsigned char *data;
	unsigned int ie_len;
	unsigned int concat_len = 0;
	unsigned char *ret;
	bool ie_found = false;

	ie_tlv_iter_init(&iter, ies, len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
			continue;

		ie_len = ie_tlv_iter_get_length(&iter);
		if (ie_len < 4)
			continue;

		data = ie_tlv_iter_get_data(&iter);

		if (memcmp(data, oui, 3))
			continue;

		if (data[3] != type)
			continue;

		concat_len += ie_len - 4;
		ie_found = true;
	}

	if (concat_len == 0) {
		if (out_len)
			*out_len = (ie_found && empty_ok) ? 0 : -ENOENT;

		return NULL;
	}

	ie_tlv_iter_init(&iter, ies, len);
	ret = l_malloc(concat_len);

	concat_len = 0;

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
			continue;

		ie_len = ie_tlv_iter_get_length(&iter);
		if (ie_len < 4)
			continue;

		data = ie_tlv_iter_get_data(&iter);

		if (memcmp(data, oui, 3))
			continue;

		if (data[3] != type)
			continue;

		memcpy(ret + concat_len, data + 4, ie_len - 4);
		concat_len += ie_len - 4;
	}

	if (out_len)
		*out_len = concat_len;

	return ret;
}

/*
 * Wi-Fi Simple Configuration v2.0.5, Section 8.2:
 * "There may be more than one instance of the Wi-Fi Simple Configuration
 * Information Element in a single 802.11 management frame. If multiple
 * Information Elements are present, the Wi-Fi Simple Configuration data
 * consists of the concatenation of the Data components of those Information
 * Elements (the order of these elements in the original packet shall be
 * preserved when concatenating Data components)."
 */
void *ie_tlv_extract_wsc_payload(const unsigned char *ies, size_t len,
							ssize_t *out_len)
{
	return ie_tlv_vendor_ie_concat(microsoft_oui, 0x04,
					ies, len, false, out_len);
}

/*
 * Wi-Fi P2P Technical Specification v1.7, Section 8.2:
 * "More than one P2P IE may be included in a single frame.  If multiple P2P
 * IEs are present, the complete P2P attribute data consists of the
 * concatenation of the P2P Attribute fields of the P2P IEs.  The P2P
 * Attributes field of each P2P IE may be any length up to the maximum
 * (251 octets).  The order of the concatenated P2P attribute data shall be
 * preserved in the ordering of the P2P IEs in the frame.  All of the P2P IEs
 * shall fit within a single frame and shall be adjacent in the frame."
 */
void *ie_tlv_extract_p2p_payload(const unsigned char *ies, size_t len,
							ssize_t *out_len)
{
	return ie_tlv_vendor_ie_concat(wifi_alliance_oui, 0x09,
					ies, len, true, out_len);
}

/*
 * Wi-Fi Display Technical Specification v2.1.0, Section 5.1.1:
 * "More than one WFD IE may be included in a single frame.  If multiple WFD
 * IEs are present, the complete WFD subelement data consists of the
 * concatenation of the WFD subelement fields of the WFD IEs.  The WFD
 * subelements field of each WFD IE may be any length up to the maximum
 * (251 octets).  The order of the concatenated WFD subelement data shall be
 * preserved in the ordering of the WFD IEs in the frame.  All of the WFD IEs
 * shall fit within a single frame and shall be adjacent in the frame."
 */
void *ie_tlv_extract_wfd_payload(const unsigned char *ies, size_t len,
							ssize_t *out_len)
{
	return ie_tlv_vendor_ie_concat(wifi_alliance_oui, 0x0a,
					ies, len, true, out_len);
}

/*
 * Encapsulate & Fragment data into Vendor IE with a given OUI + type
 *
 * Returns a newly allocated buffer with the contents of encapsulated into
 * multiple vendor IE.  @out_len is set to the overall size of the contents.
 */
static void *ie_tlv_vendor_ie_encapsulate(const unsigned char oui[],
					uint8_t type,
					const void *data, size_t len,
					bool build_empty,
					size_t *out_len)
{
	size_t overhead;
	size_t ie_len;
	size_t offset;
	uint8_t *ret;

	/*
	 * Each Vendor IE can contain up to 251 bytes of data.
	 * 255 byte maximum length - 3 for oui and 1 for type
	 */
	overhead = (len + 250) / 251 * 6;

	if (len == 0 && build_empty)
		overhead = 6;

	ret = l_malloc(len + overhead);

	if (out_len)
		*out_len = len + overhead;

	offset = 0;

	while (overhead) {
		ie_len = len <= 251 ? len : 251;
		ret[offset++] = IE_TYPE_VENDOR_SPECIFIC;
		ret[offset++] = ie_len + 4;
		memcpy(ret + offset, oui, 3);
		offset += 3;
		ret[offset++] = type;
		memcpy(ret + offset, data, ie_len);

		data += ie_len;
		len -= ie_len;
		overhead -= 6;
	}

	return ret;
}

void *ie_tlv_encapsulate_wsc_payload(const uint8_t *data, size_t len,
								size_t *out_len)
{
	return ie_tlv_vendor_ie_encapsulate(microsoft_oui, 0x04,
						data, len, false, out_len);
}

void *ie_tlv_encapsulate_p2p_payload(const uint8_t *data, size_t len,
								size_t *out_len)
{
	return ie_tlv_vendor_ie_encapsulate(wifi_alliance_oui, 0x09,
						data, len, true, out_len);
}

#define TLV_HEADER_LEN 2

static bool ie_tlv_builder_init_recurse(struct ie_tlv_builder *builder,
					unsigned char *tlv, unsigned int size)
{
	if (!builder)
		return false;

	if (!tlv) {
		memset(builder->buf, 0, MAX_BUILDER_SIZE);
		builder->tlv = builder->buf;
		builder->max = MAX_BUILDER_SIZE;
	} else {
		builder->tlv = tlv;
		builder->max = size;
	}

	builder->pos = 0;
	builder->parent = NULL;
	builder->tag = 0xffff;
	builder->len = 0;

	return true;
}

bool ie_tlv_builder_init(struct ie_tlv_builder *builder, unsigned char *buf,
				size_t len)
{
	return ie_tlv_builder_init_recurse(builder, buf, len);
}

static void ie_tlv_builder_write_header(struct ie_tlv_builder *builder)
{
	unsigned char *tlv = builder->tlv + builder->pos;

	if (builder->tag < 256) {
		tlv[0] = builder->tag;
		tlv[1] = builder->len;
	} else {
		tlv[0] = IE_TYPE_EXTENSION;
		tlv[1] = builder->len + 1;
		tlv[2] = builder->tag - 256;
	}
}

bool ie_tlv_builder_set_length(struct ie_tlv_builder *builder,
					unsigned int new_len)
{
	unsigned int new_pos = builder->pos + TLV_HEADER_LEN + new_len;

	if (builder->tag >= 256)
		new_pos += 1;

	if (new_pos > builder->max)
		return false;

	if (builder->parent)
		ie_tlv_builder_set_length(builder->parent, new_pos);

	builder->len = new_len;

	return true;
}

bool ie_tlv_builder_next(struct ie_tlv_builder *builder, unsigned int new_tag)
{
	if (new_tag > 0x1ff)
		return false;

	if (builder->tag != 0xffff) {
		ie_tlv_builder_write_header(builder);
		builder->pos += TLV_HEADER_LEN + builder->tlv[builder->pos + 1];
	}

	builder->tag = new_tag;

	return ie_tlv_builder_set_length(builder, 0);
}

unsigned char *ie_tlv_builder_get_data(struct ie_tlv_builder *builder)
{
	return builder->tlv + TLV_HEADER_LEN + builder->pos +
		(builder->tag >= 256 ? 1 : 0);
}

bool ie_tlv_builder_set_data(struct ie_tlv_builder *builder,
				const void *data, size_t len)
{
	if (!ie_tlv_builder_set_length(builder, len))
		return false;

	memcpy(ie_tlv_builder_get_data(builder), data, len);

	return true;
}

bool ie_tlv_builder_recurse(struct ie_tlv_builder *builder,
					struct ie_tlv_builder *recurse)
{
	unsigned char *end = builder->buf + builder->max;
	unsigned char *data = ie_tlv_builder_get_data(builder);

	if (!ie_tlv_builder_init_recurse(recurse, data, end - data))
		return false;

	recurse->parent = builder;

	return true;
}

unsigned char *ie_tlv_builder_finalize(struct ie_tlv_builder *builder,
					size_t *out_len)
{
	unsigned int len = 0;

	if (builder->tag != 0xffff) {
		ie_tlv_builder_write_header(builder);

		len = builder->pos + TLV_HEADER_LEN +
			builder->tlv[builder->pos + 1];
	}

	if (out_len)
		*out_len = len;

	return builder->tlv;
}

/*
 * Converts RSN cipher suite into an unsigned integer suitable to be used
 * by nl80211.  The enumeration is the same as found in crypto.h
 *
 * If the suite value is invalid, this function returns 0.
 */
uint32_t ie_rsn_cipher_suite_to_cipher(enum ie_rsn_cipher_suite suite)
{
	switch (suite) {
	case IE_RSN_CIPHER_SUITE_CCMP:
		return CRYPTO_CIPHER_CCMP;
	case IE_RSN_CIPHER_SUITE_TKIP:
		return CRYPTO_CIPHER_TKIP;
	case IE_RSN_CIPHER_SUITE_WEP40:
		return CRYPTO_CIPHER_WEP40;
	case IE_RSN_CIPHER_SUITE_WEP104:
		return CRYPTO_CIPHER_WEP104;
	case IE_RSN_CIPHER_SUITE_BIP_CMAC:
		return CRYPTO_CIPHER_BIP_CMAC;
	case IE_RSN_CIPHER_SUITE_GCMP:
		return CRYPTO_CIPHER_GCMP;
	case IE_RSN_CIPHER_SUITE_GCMP_256:
		return CRYPTO_CIPHER_GCMP_256;
	case IE_RSN_CIPHER_SUITE_CCMP_256:
		return CRYPTO_CIPHER_CCMP_256;
	case IE_RSN_CIPHER_SUITE_BIP_GMAC:
		return CRYPTO_CIPHER_BIP_GMAC;
	case IE_RSN_CIPHER_SUITE_BIP_GMAC_256:
		return CRYPTO_CIPHER_BIP_GMAC_256;
	case IE_RSN_CIPHER_SUITE_BIP_CMAC_256:
		return CRYPTO_CIPHER_BIP_CMAC_256;
	default:
		return 0;
	}
}

const char *ie_rsn_cipher_suite_to_string(enum ie_rsn_cipher_suite suite)
{
	switch (suite) {
	case IE_RSN_CIPHER_SUITE_CCMP:
		return "CCMP-128";
	case IE_RSN_CIPHER_SUITE_TKIP:
		return "TKIP";
	case IE_RSN_CIPHER_SUITE_WEP40:
		return "WEP-40";
	case IE_RSN_CIPHER_SUITE_WEP104:
		return "WEP-104";
	case IE_RSN_CIPHER_SUITE_BIP_CMAC:
		return "BIP-CMAC-128";
	case IE_RSN_CIPHER_SUITE_GCMP:
		return "GCMP-128";
	case IE_RSN_CIPHER_SUITE_GCMP_256:
		return "GCMP-256";
	case IE_RSN_CIPHER_SUITE_CCMP_256:
		return "CCMP-256";
	case IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC:
		return "NO-TRAFFIC";
	case IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER:
		break;
	case IE_RSN_CIPHER_SUITE_BIP_GMAC:
		return "BIP-GMAC-128";
	case IE_RSN_CIPHER_SUITE_BIP_GMAC_256:
		return "BIP-GMAC-256";
	case IE_RSN_CIPHER_SUITE_BIP_CMAC_256:
		return "BIP-CMAC-256";
	}

	return NULL;
}

uint32_t ie_rsn_akm_suite_to_akm(enum ie_rsn_akm_suite akm)
{
	switch (akm) {
	case IE_RSN_AKM_SUITE_8021X:
		return CRYPTO_AKM_8021X;
	case IE_RSN_AKM_SUITE_PSK:
		return CRYPTO_AKM_PSK;
	case IE_RSN_AKM_SUITE_FT_OVER_8021X:
		return CRYPTO_AKM_FT_OVER_8021X;
	case IE_RSN_AKM_SUITE_FT_USING_PSK:
		return CRYPTO_AKM_FT_USING_PSK;
	case IE_RSN_AKM_SUITE_8021X_SHA256:
		return CRYPTO_AKM_8021X_SHA256;
	case IE_RSN_AKM_SUITE_PSK_SHA256:
		return CRYPTO_AKM_PSK_SHA256;
	case IE_RSN_AKM_SUITE_TDLS:
		return CRYPTO_AKM_TDLS;
	case IE_RSN_AKM_SUITE_SAE_SHA256:
		return CRYPTO_AKM_SAE_SHA256;
	case IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256:
		return CRYPTO_AKM_FT_OVER_SAE_SHA256;
	case IE_RSN_AKM_SUITE_AP_PEER_KEY_SHA256:
		return CRYPTO_AKM_AP_PEER_KEY_SHA256;
	case IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA256:
		return CRYPTO_AKM_8021X_SUITE_B_SHA256;
	case IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA384:
		return CRYPTO_AKM_8021X_SUITE_B_SHA384;
	case IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384:
		return CRYPTO_AKM_FT_OVER_8021X_SHA384;
	case IE_RSN_AKM_SUITE_FILS_SHA256:
		return CRYPTO_AKM_FILS_SHA256;
	case IE_RSN_AKM_SUITE_FILS_SHA384:
		return CRYPTO_AKM_FILS_SHA384;
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256:
		return CRYPTO_AKM_FT_OVER_FILS_SHA256;
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384:
		return CRYPTO_AKM_FT_OVER_FILS_SHA384;
	case IE_RSN_AKM_SUITE_OWE:
		return CRYPTO_AKM_OWE;
	case IE_RSN_AKM_SUITE_OSEN:
		return CRYPTO_AKM_OSEN;
	}

	return 0;
}

/* 802.11, Section 8.4.2.27.2 */
static bool ie_parse_cipher_suite(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	/*
	 * Compare the OUI to the ones we know.  OUI Format is found in
	 * Figure 8-187 of 802.11
	 */
	if (!memcmp(data, ieee_oui, 3)) {
		/* Suite type from Table 8-99 */
		switch (data[3]) {
		case 0:
			*out = IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER;
			return true;
		case 1:
			*out = IE_RSN_CIPHER_SUITE_WEP40;
			return true;
		case 2:
			*out = IE_RSN_CIPHER_SUITE_TKIP;
			return true;
		case 4:
			*out = IE_RSN_CIPHER_SUITE_CCMP;
			return true;
		case 5:
			*out = IE_RSN_CIPHER_SUITE_WEP104;
			return true;
		case 6:
			*out = IE_RSN_CIPHER_SUITE_BIP_CMAC;
			return true;
		case 7:
			*out = IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC;
			return true;
		case 8:
			*out = IE_RSN_CIPHER_SUITE_GCMP;
			return true;
		case 9:
			*out = IE_RSN_CIPHER_SUITE_GCMP_256;
			return true;
		case 10:
			*out = IE_RSN_CIPHER_SUITE_CCMP_256;
			return true;
		case 11:
			*out = IE_RSN_CIPHER_SUITE_BIP_GMAC;
			return true;
		case 12:
			*out = IE_RSN_CIPHER_SUITE_BIP_GMAC_256;
			return true;
		case 13:
			*out = IE_RSN_CIPHER_SUITE_BIP_CMAC_256;
			return true;
		default:
			return false;
		}
	}

	return false;
}

/* 802.11, Section 8.4.2.27.2 */
static int ie_parse_rsn_akm_suite(const uint8_t *data,
					enum ie_rsn_akm_suite *out)
{
	/*
	 * Compare the OUI to the ones we know.  OUI Format is found in
	 * Figure 8-187 of 802.11
	 */
	if (!memcmp(data, ieee_oui, 3)) {
		/* Suite type from Table 8-101 */
		switch (data[3]) {
		case 0:
			return -EINVAL;
		case 1:
			*out = IE_RSN_AKM_SUITE_8021X;
			return 0;
		case 2:
			*out = IE_RSN_AKM_SUITE_PSK;
			return 0;
		case 3:
			*out = IE_RSN_AKM_SUITE_FT_OVER_8021X;
			return 0;
		case 4:
			*out = IE_RSN_AKM_SUITE_FT_USING_PSK;
			return 0;
		case 5:
			*out = IE_RSN_AKM_SUITE_8021X_SHA256;
			return 0;
		case 6:
			*out = IE_RSN_AKM_SUITE_PSK_SHA256;
			return 0;
		case 7:
			*out = IE_RSN_AKM_SUITE_TDLS;
			return 0;
		case 8:
			*out = IE_RSN_AKM_SUITE_SAE_SHA256;
			return 0;
		case 9:
			*out = IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256;
			return 0;
		case 10:
			*out = IE_RSN_AKM_SUITE_AP_PEER_KEY_SHA256;
			return 0;
		case 11:
			*out = IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA256;
			return 0;
		case 12:
			*out = IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA384;
			return 0;
		case 13:
			*out = IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384;
			return 0;
		case 14:
			*out = IE_RSN_AKM_SUITE_FILS_SHA256;
			return 0;
		case 15:
			*out = IE_RSN_AKM_SUITE_FILS_SHA384;
			return 0;
		case 16:
			*out = IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256;
			return 0;
		case 17:
			*out = IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384;
			return 0;
		case 18:
			*out = IE_RSN_AKM_SUITE_OWE;
			return 0;
		default:
			return -ENOENT;
		}
	}

	return -ENOENT;
}

static int ie_parse_osen_akm_suite(const uint8_t *data,
					enum ie_rsn_akm_suite *out)
{
	if (memcmp(data, wifi_alliance_oui, 3))
		return -ENOENT;

	if (data[3] != 1)
		return -ENOENT;

	*out = IE_RSN_AKM_SUITE_OSEN;

	return 0;
}

static bool ie_parse_group_cipher(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	enum ie_rsn_cipher_suite tmp;

	bool r = ie_parse_cipher_suite(data, &tmp);

	if (!r)
		return r;

	switch (tmp) {
	case IE_RSN_CIPHER_SUITE_CCMP:
	case IE_RSN_CIPHER_SUITE_TKIP:
	case IE_RSN_CIPHER_SUITE_WEP104:
	case IE_RSN_CIPHER_SUITE_WEP40:
	case IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC:
	case IE_RSN_CIPHER_SUITE_GCMP:
	case IE_RSN_CIPHER_SUITE_GCMP_256:
	case IE_RSN_CIPHER_SUITE_CCMP_256:
		break;
	default:
		return false;
	}

	*out = tmp;
	return true;
}

static int ie_parse_pairwise_cipher(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	enum ie_rsn_cipher_suite tmp;
	bool r = ie_parse_cipher_suite(data, &tmp);

	if (!r)
		return -ENOENT;

	switch (tmp) {
	case IE_RSN_CIPHER_SUITE_CCMP:
	case IE_RSN_CIPHER_SUITE_TKIP:
	case IE_RSN_CIPHER_SUITE_WEP104:
	case IE_RSN_CIPHER_SUITE_WEP40:
	case IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER:
	case IE_RSN_CIPHER_SUITE_GCMP:
	case IE_RSN_CIPHER_SUITE_GCMP_256:
	case IE_RSN_CIPHER_SUITE_CCMP_256:
		break;
	default:
		return -ERANGE;
	}

	*out = tmp;
	return 0;
}

static bool ie_parse_group_management_cipher(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	enum ie_rsn_cipher_suite tmp;

	bool r = ie_parse_cipher_suite(data, &tmp);

	if (!r)
		return r;

	switch (tmp) {
	case IE_RSN_CIPHER_SUITE_BIP_CMAC:
	case IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC:
	case IE_RSN_CIPHER_SUITE_BIP_GMAC:
	case IE_RSN_CIPHER_SUITE_BIP_GMAC_256:
	case IE_RSN_CIPHER_SUITE_BIP_CMAC_256:
		break;
	default:
		return false;
	}

	*out = tmp;
	return true;
}

#define RSNE_ADVANCE(data, len, step)	\
	data += step;			\
	len -= step;			\
					\
	if (len == 0)			\
		goto done		\

static int parse_ciphers(const uint8_t *data, size_t len,
			int (*akm_parse)(const uint8_t *data,
						enum ie_rsn_akm_suite *out),
			struct ie_rsn_info *out_info)
{
	uint16_t count;
	uint16_t i;

	/* Parse Group Cipher Suite field */
	if (len < 4)
		return -EBADMSG;

	if (!ie_parse_group_cipher(data, &out_info->group_cipher))
		return -ERANGE;

	RSNE_ADVANCE(data, len, 4);

	/* Parse Pairwise Cipher Suite Count field */
	if (len < 2)
		return -EBADMSG;

	count = l_get_le16(data);

	/*
	 * The spec doesn't seem to explicitly say what to do in this case,
	 * so we assume this situation is invalid.
	 */
	if (count == 0)
		return -EINVAL;

	data += 2;
	len -= 2;

	if (len < 4 * count)
		return -EBADMSG;

	/* Parse Pairwise Cipher Suite List field */
	for (i = 0, out_info->pairwise_ciphers = 0; i < count; i++) {
		enum ie_rsn_cipher_suite suite;
		int r = ie_parse_pairwise_cipher(data + i * 4, &suite);

		if (r == -ENOENT) /* Skip unknown */
			continue;
		else if (r < 0)
			return r;

		out_info->pairwise_ciphers |= suite;
	}

	RSNE_ADVANCE(data, len, count * 4);

	/* Parse AKM Suite Count field */
	if (len < 2)
		return -EBADMSG;

	count = l_get_le16(data);
	if (count == 0)
		return -EINVAL;

	data += 2;
	len -= 2;

	if (len < 4 * count)
		return -EBADMSG;

	/* Parse AKM Suite List field */
	for (i = 0, out_info->akm_suites = 0; i < count; i++) {
		enum ie_rsn_akm_suite suite;
		int ret;

		ret = akm_parse(data + i * 4, &suite);
		switch (ret) {
		case 0:
			out_info->akm_suites |= suite;
			break;
		case -ENOENT:
			/* Skip unknown or vendor specific AKMs */
			break;
		default:
			return -EBADMSG;
		}
	}

	RSNE_ADVANCE(data, len, count * 4);

	if (len < 2)
		return -EBADMSG;

	out_info->preauthentication = test_bit(data, 0);
	out_info->no_pairwise = test_bit(data, 1);
	out_info->ptksa_replay_counter = bit_field(data[0], 2, 2);
	out_info->gtksa_replay_counter = bit_field(data[0], 4, 2);
	out_info->mfpr = test_bit(data, 6);
	out_info->mfpc = test_bit(data, 7);
	out_info->peerkey_enabled = test_bit(data + 1, 1);
	out_info->spp_a_msdu_capable = test_bit(data + 1, 2);
	out_info->spp_a_msdu_required = test_bit(data + 1, 3);
	out_info->pbac = test_bit(data + 1, 4);
	out_info->extended_key_id = test_bit(data + 1, 5);
	out_info->ocvc = test_bit(data + 1, 6);

	/*
	 * BIP-default group management cipher suite in an RSNA with
	 * management frame protection enabled
	 */
	if (out_info->mfpc)
		out_info->group_management_cipher =
						IE_RSN_CIPHER_SUITE_BIP_CMAC;

	RSNE_ADVANCE(data, len, 2);

	/* Parse PMKID Count field */
	if (len < 2)
		return -EBADMSG;

	out_info->num_pmkids = l_get_le16(data);
	RSNE_ADVANCE(data, len, 2);

	if (out_info->num_pmkids > 0) {
		if (len < 16 * out_info->num_pmkids)
			return -EBADMSG;

		/*
		 * Parse PMKID List field.
		 *
		 * We simply assign the pointer to the PMKIDs to the structure.
		 * The PMKIDs are fixed size, 16 bytes each.
		 */
		out_info->pmkids = data;
		RSNE_ADVANCE(data, len, out_info->num_pmkids * 16);
	}

	/* Parse Group Management Cipher Suite field */
	if (len < 4)
		return -EBADMSG;

	if (!ie_parse_group_management_cipher(data,
					&out_info->group_management_cipher))
		return -ERANGE;

	RSNE_ADVANCE(data, len, 4);

	return -EBADMSG;

done:
	return 0;
}

int ie_parse_rsne(struct ie_tlv_iter *iter, struct ie_rsn_info *out_info)
{
	const uint8_t *data = iter->data;
	size_t len = iter->len;
	uint16_t version;
	struct ie_rsn_info info;

	memset(&info, 0, sizeof(info));
	info.group_cipher = IE_RSN_CIPHER_SUITE_CCMP;
	info.pairwise_ciphers = IE_RSN_CIPHER_SUITE_CCMP;
	info.akm_suites = IE_RSN_AKM_SUITE_8021X;

	/* Parse Version field */
	if (len < 2)
		return -EMSGSIZE;

	version = l_get_le16(data);
	if (version != 0x01)
		return -EBADMSG;

	RSNE_ADVANCE(data, len, 2);

	if (parse_ciphers(data, len, ie_parse_rsn_akm_suite, &info) < 0)
		return -EBADMSG;

done:
	if (out_info)
		memcpy(out_info, &info, sizeof(info));

	return 0;
}

int ie_parse_rsne_from_data(const uint8_t *data, size_t len,
				struct ie_rsn_info *info)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_RSN)
		return -EPROTOTYPE;

	return ie_parse_rsne(&iter, info);
}

int ie_parse_osen(struct ie_tlv_iter *iter, struct ie_rsn_info *out_info)
{
	const uint8_t *data = iter->data;
	size_t len = iter->len;
	struct ie_rsn_info info;

	if (ie_tlv_iter_get_tag(iter) != IE_TYPE_VENDOR_SPECIFIC)
		return -EPROTOTYPE;

	if (!is_ie_wfa_ie(iter->data, iter->len, IE_WFA_OI_OSEN))
		return -EPROTOTYPE;

	memset(&info, 0, sizeof(info));
	info.group_cipher = IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC;
	info.pairwise_ciphers = IE_RSN_CIPHER_SUITE_CCMP;
	info.akm_suites = IE_RSN_AKM_SUITE_8021X;

	RSNE_ADVANCE(data, len, 4);

	if (parse_ciphers(data, len, ie_parse_osen_akm_suite, &info) < 0)
		return -EBADMSG;

done:
	if (out_info)
		memcpy(out_info, &info, sizeof(info));

	return 0;
}

int ie_parse_osen_from_data(const uint8_t *data, size_t len,
				struct ie_rsn_info *info)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	return ie_parse_osen(&iter, info);
}

/*
 * 802.11, Section 8.4.2.27.2
 * 802.11i, Section 7.3.2.25.1 and WPA_80211_v3_1 Section 2.1
 */
static bool ie_build_cipher_suite(uint8_t *data, const uint8_t *oui,
					const enum ie_rsn_cipher_suite suite)
{
	uint8_t selector;

	switch (suite) {
	case IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER:
		selector = 0;
		goto done;
	case IE_RSN_CIPHER_SUITE_WEP40:
		selector = 1;
		goto done;
	case IE_RSN_CIPHER_SUITE_TKIP:
		selector = 2;
		goto done;
	case IE_RSN_CIPHER_SUITE_CCMP:
		selector = 4;
		goto done;
	case IE_RSN_CIPHER_SUITE_WEP104:
		selector = 5;
		goto done;
	case IE_RSN_CIPHER_SUITE_BIP_CMAC:
		selector = 6;
		goto done;
	case IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC:
		selector = 7;
		goto done;
	case IE_RSN_CIPHER_SUITE_GCMP:
		selector = 8;
		goto done;
	case IE_RSN_CIPHER_SUITE_GCMP_256:
		selector = 9;
		goto done;
	case IE_RSN_CIPHER_SUITE_CCMP_256:
		selector = 10;
		goto done;
	case IE_RSN_CIPHER_SUITE_BIP_GMAC:
		selector = 11;
		goto done;
	case IE_RSN_CIPHER_SUITE_BIP_GMAC_256:
		selector = 12;
		goto done;
	case IE_RSN_CIPHER_SUITE_BIP_CMAC_256:
		selector = 13;
		goto done;
	}

	return false;
done:
	memcpy(data, oui, 3);
	data[3] = selector;
	return true;
}

#define RETURN_AKM(data, oui, id)		\
	do {					\
		memcpy((data), (oui), 3);	\
		(data)[3] = (id);		\
		return true;			\
	} while (0)

/* 802.11-2016, Section 9.4.2.25.3 */
static bool ie_build_rsn_akm_suite(uint8_t *data, enum ie_rsn_akm_suite suite)
{
	switch (suite) {
	case IE_RSN_AKM_SUITE_8021X:
		RETURN_AKM(data, ieee_oui, 1);
	case IE_RSN_AKM_SUITE_PSK:
		RETURN_AKM(data, ieee_oui, 2);
	case IE_RSN_AKM_SUITE_FT_OVER_8021X:
		RETURN_AKM(data, ieee_oui, 3);
	case IE_RSN_AKM_SUITE_FT_USING_PSK:
		RETURN_AKM(data, ieee_oui, 4);
	case IE_RSN_AKM_SUITE_8021X_SHA256:
		RETURN_AKM(data, ieee_oui, 5);
	case IE_RSN_AKM_SUITE_PSK_SHA256:
		RETURN_AKM(data, ieee_oui, 6);
	case IE_RSN_AKM_SUITE_TDLS:
		RETURN_AKM(data, ieee_oui, 7);
	case IE_RSN_AKM_SUITE_SAE_SHA256:
		RETURN_AKM(data, ieee_oui, 8);
	case IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256:
		RETURN_AKM(data, ieee_oui, 9);
	case IE_RSN_AKM_SUITE_AP_PEER_KEY_SHA256:
		RETURN_AKM(data, ieee_oui, 10);
	case IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA256:
		RETURN_AKM(data, ieee_oui, 11);
	case IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA384:
		RETURN_AKM(data, ieee_oui, 12);
	case IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384:
		RETURN_AKM(data, ieee_oui, 13);
	case IE_RSN_AKM_SUITE_FILS_SHA256:
		RETURN_AKM(data, ieee_oui, 14);
	case IE_RSN_AKM_SUITE_FILS_SHA384:
		RETURN_AKM(data, ieee_oui, 15);
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256:
		RETURN_AKM(data, ieee_oui, 16);
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384:
		RETURN_AKM(data, ieee_oui, 17);
	case IE_RSN_AKM_SUITE_OWE:
		RETURN_AKM(data, ieee_oui, 18);
	case IE_RSN_AKM_SUITE_OSEN:
		RETURN_AKM(data, wifi_alliance_oui, 1);
	}

	return false;
}

/* 802.11i, Section 7.3.2.25.2 and WPA_80211_v3_1 Section 2.1 */
static bool ie_build_wpa_akm_suite(uint8_t *data, enum ie_rsn_akm_suite suite)
{
	switch (suite) {
	case IE_RSN_AKM_SUITE_8021X:
		RETURN_AKM(data, microsoft_oui, 1);
	case IE_RSN_AKM_SUITE_PSK:
		RETURN_AKM(data, microsoft_oui, 2);
	default:
		break;
	}

	return false;
}

static int build_ciphers_common(const struct ie_rsn_info *info, uint8_t *to,
				uint8_t max_len, bool force_group_mgmt_cipher)
{
	/* These are the only valid pairwise suites */
	static enum ie_rsn_cipher_suite pairwise_suites[] = {
		IE_RSN_CIPHER_SUITE_CCMP,
		IE_RSN_CIPHER_SUITE_TKIP,
		IE_RSN_CIPHER_SUITE_WEP104,
		IE_RSN_CIPHER_SUITE_WEP40,
		IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER,
		IE_RSN_CIPHER_SUITE_GCMP,
		IE_RSN_CIPHER_SUITE_GCMP_256,
		IE_RSN_CIPHER_SUITE_CCMP_256,
	};
	unsigned int pos = 0;
	unsigned int i;
	uint8_t *countptr;
	uint16_t count;
	enum ie_rsn_akm_suite akm_suite;

	/* Group Data Cipher Suite */
	if (!ie_build_cipher_suite(to + pos, ieee_oui, info->group_cipher))
		return -EINVAL;

	pos += 4;

	/* Save position for Pairwise Cipher Suite Count field */
	countptr = to + pos;
	pos += 2;

	for (i = 0, count = 0; i < L_ARRAY_SIZE(pairwise_suites); i++) {
		enum ie_rsn_cipher_suite suite = pairwise_suites[i];

		if (!(info->pairwise_ciphers & suite))
			continue;

		if (pos + 4 > max_len)
			return -EBADMSG;

		if (!ie_build_cipher_suite(to + pos, ieee_oui, suite))
			return -EINVAL;

		pos += 4;
		count += 1;
	}

	l_put_le16(count, countptr);

	/* Save position for AKM Suite Count field */
	countptr = to + pos;
	pos += 2;

	for (count = 0, akm_suite = IE_RSN_AKM_SUITE_8021X;
			akm_suite <= IE_RSN_AKM_SUITE_OSEN;
				akm_suite <<= 1) {
		if (!(info->akm_suites & akm_suite))
			continue;

		if (pos + 4 > max_len)
			return -EBADMSG;

		if (!ie_build_rsn_akm_suite(to + pos, akm_suite))
			return -EINVAL;

		pos += 4;
		count += 1;
	}

	l_put_le16(count, countptr);

	/* Bits 0 - 7 of RSNE Capabilities field */
	to[pos] = 0;

	if (info->preauthentication)
		to[pos] |= 0x1;

	if (info->no_pairwise)
		to[pos] |= 0x2;

	to[pos] |= info->ptksa_replay_counter << 2;
	to[pos] |= info->gtksa_replay_counter << 4;

	if (info->mfpr)
		to[pos] |= 0x40;

	if (info->mfpc)
		to[pos] |= 0x80;

	pos += 1;

	/* Bits 8 - 15 of RSNE Capabilities field */
	to[pos] = 0;

	if (info->peerkey_enabled)
		to[pos] |= 0x2;

	if (info->spp_a_msdu_capable)
		to[pos] |= 0x4;

	if (info->spp_a_msdu_required)
		to[pos] |= 0x8;

	if (info->pbac)
		to[pos] |= 0x10;

	if (info->extended_key_id)
		to[pos] |= 0x20;

	if (info->ocvc)
		to[pos] |= 0x40;

	pos += 1;

	/* Short hand the generated RSNE if possible */
	if (info->num_pmkids == 0 && !force_group_mgmt_cipher) {
		/* No Group Management Cipher Suite */
		if (to[pos - 2] == 0 && to[pos - 1] == 0)
			/*
			 * The RSN Capabilities bytes are in theory optional,
			 * but some APs don't seem to like us not including
			 * them in the RSN element.  Also wireshark has a
			 * bug and complains of a malformed element if these
			 * bytes are not included.
			 */
			goto done;
		else if (!info->mfpc)
			goto done;
		else if (info->group_management_cipher ==
				IE_RSN_CIPHER_SUITE_BIP_CMAC)
			goto done;
	}

	/* PMKID Count */
	l_put_le16(info->num_pmkids, to + pos);
	pos += 2;

	if (pos + info->num_pmkids * 16 > max_len)
		return -EINVAL;

	/* PMKID List */
	if (info->num_pmkids) {
		memcpy(to + pos, info->pmkids, 16 * info->num_pmkids);
		pos += 16 * info->num_pmkids;
	}

	if (!force_group_mgmt_cipher && !info->mfpc)
		goto done;

	if (!force_group_mgmt_cipher && info->group_management_cipher ==
					IE_RSN_CIPHER_SUITE_BIP_CMAC)
		goto done;

	/* Group Management Cipher Suite */
	if (!ie_build_cipher_suite(to + pos, ieee_oui,
					info->group_management_cipher))
		return -EINVAL;

	pos += 4;

done:
	return pos;
}

/*
 * Generate an RSNE IE based on the information found in info.
 * The to array must be 256 bytes in size
 *
 * In theory it is possible to generate 257 byte IE RSNs (1 byte for IE Type,
 * 1 byte for Length and 255 bytes of data) but we don't support this
 * possibility.
 */
bool ie_build_rsne(const struct ie_rsn_info *info, uint8_t *to)
{
	unsigned int pos;
	int ret;

	to[0] = IE_TYPE_RSN;

	/* Version field, always 1 */
	pos = 2;
	l_put_le16(1, to + pos);
	pos += 2;

	ret = build_ciphers_common(info, to + 4, 252, false);
	if (ret < 0)
		return false;

	pos += ret;

	to[1] = pos - 2;

	return true;
}

bool ie_rsne_is_wpa3_personal(const struct ie_rsn_info *info)
{
	bool is_transition = info->akm_suites & IE_RSN_AKM_SUITE_PSK;
	/*
	 * WPA3 Specification, Version 2
	 *
	 * Section 2.2 WPA3-Personal only Mode:
	 * 1. An AP shall enable at least AKM suite selector 00-0F-AC:8 in
	 * the BSS
	 * 3.  An AP shall not enable AKM suite selector: 00-0F-AC:2, 00-0F-AC:6
	 * 5. an AP shall set MFPC to 1, MFPR to 1
	 *
	 * Section 2.3 WPA3-Personal transition Mode:
	 * 1. an AP shall enable at least AKM suite selectors 00-0F-AC:2 and
	 * 00-0F-AC:8 in the BSS
	 * 3. an AP should enable AKM suite selector: 00-0F-AC:6
	 * 5. an AP shall set MFPC to 1, MFPR to 0
	 */
	if (!(info->akm_suites & IE_RSN_AKM_SUITE_SAE_SHA256))
		return false;

	if (!info->mfpc)
		return false;

	return is_transition || info->mfpr;
}

bool ie_build_osen(const struct ie_rsn_info *info, uint8_t *to)
{
	unsigned int pos;
	int ret;

	to[0] = IE_TYPE_VENDOR_SPECIFIC;
	pos = 2;
	memcpy(to + pos, wifi_alliance_oui, 3);
	pos += 3;
	to[pos++] = 0x12;

	ret = build_ciphers_common(info, to + 6, 250, true);
	if (ret < 0)
		return false;

	pos += ret;

	to[1] = pos - 2;

	return true;
}

/* 802.11i-2004, Section 7.3.2.25.1 and WPA_80211_v3_1 Section 2.1 */
static bool ie_parse_wpa_cipher_suite(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	/*
	 * Compare the OUI to the ones we know.  OUI Format is found in
	 * Figure 8-187 of 802.11
	 */
	if (!memcmp(data, microsoft_oui, 3)) {
		/* Suite type from 802.11i-2004, Table 20da */
		switch (data[3]) {
		case 0:
			*out = IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER;
			return true;
		case 1:
			*out = IE_RSN_CIPHER_SUITE_WEP40;
			return true;
		case 2:
			*out = IE_RSN_CIPHER_SUITE_TKIP;
			return true;
		case 4:
			*out = IE_RSN_CIPHER_SUITE_CCMP;
			return true;
		case 5:
			*out = IE_RSN_CIPHER_SUITE_WEP104;
			return true;
		default:
			return false;
		}
	}

	return false;
}

/* 802.11i-2004, Section 7.3.2.25.2 and WPA_80211_v3_1 Section 2.1 */
static bool ie_parse_wpa_akm_suite(const uint8_t *data,
					enum ie_rsn_akm_suite *out)
{
	/*
	 * Compare the OUI to the ones we know.  OUI Format is found in
	 * Figure 8-187 of 802.11
	 */
	if (!memcmp(data, microsoft_oui, 3)) {
		/* Suite type from 802.11i-2004, Table 20dc */
		switch (data[3]) {
		case 1:
			*out = IE_RSN_AKM_SUITE_8021X;
			return true;
		case 2:
			*out = IE_RSN_AKM_SUITE_PSK;
			return true;
		default:
			return false;
		}
	}

	return false;
}

static bool ie_parse_wpa_group_cipher(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	enum ie_rsn_cipher_suite tmp;

	bool r = ie_parse_wpa_cipher_suite(data, &tmp);

	if (!r)
		return r;

	switch (tmp) {
	case IE_RSN_CIPHER_SUITE_CCMP:
	case IE_RSN_CIPHER_SUITE_TKIP:
	case IE_RSN_CIPHER_SUITE_WEP104:
	case IE_RSN_CIPHER_SUITE_WEP40:
		break;
	default:
		return false;
	}

	*out = tmp;
	return true;
}

static bool ie_parse_wpa_pairwise_cipher(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	enum ie_rsn_cipher_suite tmp;

	bool r = ie_parse_wpa_cipher_suite(data, &tmp);

	if (!r)
		return r;

	switch (tmp) {
	case IE_RSN_CIPHER_SUITE_CCMP:
	case IE_RSN_CIPHER_SUITE_TKIP:
	case IE_RSN_CIPHER_SUITE_WEP104:
	case IE_RSN_CIPHER_SUITE_WEP40:
	/* TODO : not sure about GROUP_CIPHER */
		break;
	default:
		return false;
	}

	*out = tmp;
	return true;
}

bool is_ie_wfa_ie(const uint8_t *data, uint8_t len, uint8_t oi_type)
{
	if (!data)
		return false;

	if (oi_type == IE_WFA_OI_OSEN && len < 22)
		return false;
	else if (oi_type == IE_WFA_OI_HS20_INDICATION && len != 5 && len != 7)
		return false;
	else if (oi_type == IE_WFA_OI_OWE_TRANSITION && len < 12)
		return false;
	else if (len < 4) /* OI not handled, but at least check length */
		return false;

	if (!memcmp(data, wifi_alliance_oui, 3) && data[3] == oi_type)
		return true;

	return false;
}

bool is_ie_wpa_ie(const uint8_t *data, uint8_t len)
{
	if (!data || len < 6)
		return false;

	if ((!memcmp(data, microsoft_oui, 3) && data[3] == 1 &&
						l_get_le16(data + 4) == 1))
		return true;

	return false;
}

int ie_parse_wpa(struct ie_tlv_iter *iter, struct ie_rsn_info *out_info)
{
	const uint8_t *data = iter->data;
	size_t len = iter->len;
	struct ie_rsn_info info;
	uint16_t count;
	uint16_t i;

	if (!is_ie_wpa_ie(iter->data, iter->len))
		return -EINVAL;

	memset(&info, 0, sizeof(info));
	info.group_cipher = IE_RSN_CIPHER_SUITE_TKIP;
	info.pairwise_ciphers = IE_RSN_CIPHER_SUITE_TKIP;
	info.akm_suites = IE_RSN_AKM_SUITE_PSK;

	RSNE_ADVANCE(data, len, 6);

	/* Parse Group Cipher Suite field */
	if (len < 4)
		return -EBADMSG;

	if (!ie_parse_wpa_group_cipher(data, &info.group_cipher))
		return -ERANGE;

	RSNE_ADVANCE(data, len, 4);

	/* Parse Pairwise Cipher Suite Count field */
	if (len < 2)
		return -EBADMSG;

	count = l_get_le16(data);

	/*
	 * The spec doesn't seem to explicitly say what to do in this case,
	 * so we assume this situation is invalid.
	 */
	if (count == 0)
		return -EINVAL;

	data += 2;
	len -= 2;

	if (len < 4 * count)
		return -EBADMSG;

	/* Parse Pairwise Cipher Suite List field */
	for (i = 0, info.pairwise_ciphers = 0; i < count; i++) {
		enum ie_rsn_cipher_suite suite;

		if (!ie_parse_wpa_pairwise_cipher(data + i * 4, &suite))
			return -ERANGE;

		info.pairwise_ciphers |= suite;
	}

	RSNE_ADVANCE(data, len, count * 4);

	/* Parse AKM Suite Count field */
	if (len < 2)
		return -EBADMSG;

	count = l_get_le16(data);
	if (count == 0)
		return -EINVAL;

	data += 2;
	len -= 2;

	if (len < 4 * count)
		return -EBADMSG;

	/* Parse AKM Suite List field */
	for (i = 0, info.akm_suites = 0; i < count; i++) {
		enum ie_rsn_akm_suite suite;

		if (!ie_parse_wpa_akm_suite(data + i * 4, &suite))
			return -ERANGE;

		info.akm_suites |= suite;
	}

	RSNE_ADVANCE(data, len, count * 4);

	if (len < 2)
		return -EBADMSG;

	out_info->preauthentication = test_bit(data, 0);
	out_info->no_pairwise = test_bit(data, 1);
	out_info->ptksa_replay_counter = bit_field(data[0], 2, 2);
	out_info->gtksa_replay_counter = bit_field(data[0], 4, 2);

	RSNE_ADVANCE(data, len, 2);

	l_warn("Received WPA element with extra trailing bytes -"
		" which will be ignored");
	return 0;

done:
	/*
	 * 802.11i, Section 7.3.2.25.1
	 * Use of CCMP as the group cipher suite with TKIP as the
	 * pairwise cipher suite shall not be supported.
	 */
	if (info.group_cipher & IE_RSN_CIPHER_SUITE_CCMP &&
			info.pairwise_ciphers & IE_RSN_CIPHER_SUITE_TKIP)
		return -EBADMSG;

	if (out_info)
		memcpy(out_info, &info, sizeof(info));

	return 0;
}

int ie_parse_wpa_from_data(const uint8_t *data, size_t len,
						struct ie_rsn_info *info)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
		return -EPROTOTYPE;

	return ie_parse_wpa(&iter, info);
}

/*
 * Generate an WPA IE based on the information found in info.
 * The to array must be minimum of 19 bytes in size
 */
bool ie_build_wpa(const struct ie_rsn_info *info, uint8_t *to)
{
	/* These are the only valid pairwise suites */
	static enum ie_rsn_cipher_suite pairwise_suites[] = {
		IE_RSN_CIPHER_SUITE_CCMP,
		IE_RSN_CIPHER_SUITE_TKIP,
		IE_RSN_CIPHER_SUITE_WEP104,
		IE_RSN_CIPHER_SUITE_WEP40,
		/* TODO: not sure about USE_GROUP_CIPHER,*/
	};
	/* These are the only valid AKM suites */
	static enum ie_rsn_akm_suite akm_suites[] = {
		IE_RSN_AKM_SUITE_8021X,
		IE_RSN_AKM_SUITE_PSK,
	};
	unsigned int pos;
	unsigned int i;
	uint8_t *countptr;
	uint16_t count;

	/*
	 * 802.11i, Section 7.3.2.25.1
	 * Use of CCMP as the group cipher suite with TKIP as the
	 * pairwise cipher suite shall not be supported.
	 */
	if (info->group_cipher == IE_RSN_CIPHER_SUITE_CCMP &&
			info->pairwise_ciphers & IE_RSN_CIPHER_SUITE_TKIP)
		return false;

	to[0] = IE_TYPE_VENDOR_SPECIFIC;

	/* Vendor OUI and Type */
	pos = 2;
	memcpy(to + pos, microsoft_oui, 3);
	pos += 3;
	to[pos] = 1; /* OUI type 1 means WPA element */
	pos++;

	/* Version field, always 1 */
	l_put_le16(1, to + pos);
	pos += 2;

	/* Group Data Cipher Suite */
	if (!ie_build_cipher_suite(to + pos, microsoft_oui,
							info->group_cipher))
		return false;

	pos += 4;

	/* Save position for Pairwise Cipher Suite Count field */
	countptr = to + pos;
	pos += 2;

	for (i = 0, count = 0; i < L_ARRAY_SIZE(pairwise_suites); i++) {
		enum ie_rsn_cipher_suite suite = pairwise_suites[i];

		if (!(info->pairwise_ciphers & suite))
			continue;

		if (!ie_build_cipher_suite(to + pos, microsoft_oui, suite))
			return false;

		pos += 4;
		count += 1;
	}

	l_put_le16(count, countptr);

	/* Save position for AKM Suite Count field */
	countptr = to + pos;
	pos += 2;

	for (i = 0, count = 0; i < L_ARRAY_SIZE(akm_suites); i++) {
		enum ie_rsn_akm_suite suite = akm_suites[i];

		if (!(info->akm_suites & suite))
			continue;

		if (!ie_build_wpa_akm_suite(to + pos, suite))
			return false;

		pos += 4;
		count += 1;
	}

	l_put_le16(count, countptr);

	to[1] = pos - 2;

	return true;
}

int ie_parse_bss_load(struct ie_tlv_iter *iter, uint16_t *out_sta_count,
			uint8_t *out_channel_utilization,
			uint16_t *out_admission_capacity)
{
	const uint8_t *data;

	if (ie_tlv_iter_get_length(iter) != 5)
		return -EINVAL;

	data = ie_tlv_iter_get_data(iter);

	if (out_sta_count)
		*out_sta_count = data[0] | data[1] << 8;

	if (out_channel_utilization)
		*out_channel_utilization = data[2];

	if (out_admission_capacity)
		*out_admission_capacity = data[3] | data[4] << 8;

	return 0;
}

int ie_parse_bss_load_from_data(const uint8_t *data, uint8_t len,
				uint16_t *out_sta_count,
				uint8_t *out_channel_utilization,
				uint16_t *out_admission_capacity)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_BSS_LOAD)
		return -EPROTOTYPE;

	return ie_parse_bss_load(&iter, out_sta_count,
			out_channel_utilization, out_admission_capacity);
}

int ie_parse_mobility_domain(struct ie_tlv_iter *iter, uint16_t *mdid,
				bool *ft_over_ds, bool *resource_req)
{
	const uint8_t *data;

	if (ie_tlv_iter_get_length(iter) != 3)
		return -EINVAL;

	data = ie_tlv_iter_get_data(iter);

	if (mdid)
		*mdid = l_get_le16(data);

	if (ft_over_ds)
		*ft_over_ds = (data[2] & 0x01) > 0;

	if (resource_req)
		*resource_req = (data[2] & 0x02) > 0;

	return 0;
}

int ie_parse_mobility_domain_from_data(const uint8_t *data, uint8_t len,
				uint16_t *mdid,
				bool *ft_over_ds, bool *resource_req)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_MOBILITY_DOMAIN)
		return -EPROTOTYPE;

	return ie_parse_mobility_domain(&iter, mdid, ft_over_ds, resource_req);
}

bool ie_build_mobility_domain(uint16_t mdid, bool ft_over_ds, bool resource_req,
				uint8_t *to)
{
	*to++ = IE_TYPE_MOBILITY_DOMAIN;

	*to++ = 3;

	l_put_le16(mdid, to);
	to[2] =
		(ft_over_ds ? 0x01 : 0) |
		(resource_req ? 0x02 : 0);

	return true;
}

int ie_parse_fast_bss_transition(struct ie_tlv_iter *iter, uint32_t mic_len,
					struct ie_ft_info *info)
{
	const uint8_t *data;
	uint8_t len, subelem_id, subelem_len;

	len = ie_tlv_iter_get_length(iter);
	if (len < 66 + mic_len)
		return -EINVAL;

	data = ie_tlv_iter_get_data(iter);

	memset(info, 0, sizeof(*info));

	info->rsnxe_used = test_bit(data, 0);
	info->mic_element_count = data[1];

	memcpy(info->mic, data + 2, mic_len);

	memcpy(info->anonce, data + mic_len + 2, 32);

	memcpy(info->snonce, data + mic_len + 34, 32);

	len -= 66 + mic_len;
	data += 66 + mic_len;

	while (len >= 2) {
		subelem_id = *data++;
		subelem_len = *data++;

		switch (subelem_id) {
		case 1:
			if (subelem_len != 6)
				return -EINVAL;

			memcpy(info->r1khid, data, 6);
			info->r1khid_present = true;

			break;

		case 2:
			if (subelem_len < 35 || subelem_len > 51)
				return -EINVAL;

			info->gtk_key_id = bit_field(data[0], 0, 2);
			info->gtk_len = data[2];

			/*
			 * Check Wrapped Key field length is Key Length plus
			 * padding (0 - 7 bytes) plus 8 bytes for AES key wrap.
			 */
			if (align_len(info->gtk_len, 8) + 8 != subelem_len - 11)
				return -EINVAL;

			memcpy(info->gtk_rsc, data + 3, 8);
			memcpy(info->gtk, data + 11, subelem_len - 11);

			break;
		case 3:

			if (subelem_len < 1 || subelem_len > 48)
				return -EINVAL;

			memcpy(info->r0khid, data, subelem_len);
			info->r0khid_len = subelem_len;

			break;

		case 4:
			if (subelem_len != 33)
				return -EINVAL;

			info->igtk_key_id = l_get_le16(data);
			memcpy(info->igtk_ipn, data + 2, 6);
			info->igtk_len = data[8];

			if (info->igtk_len > 16)
				return -EINVAL;

			memcpy(info->igtk, data + 9, subelem_len - 9);

			break;
		}

		data += subelem_len;
		len -= subelem_len + 2;
	}

	if (len)
		return -EINVAL;

	return 0;
}

int ie_parse_fast_bss_transition_from_data(const uint8_t *data, uint8_t len,
						uint32_t mic_len,
						struct ie_ft_info *info)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_FAST_BSS_TRANSITION)
		return -EPROTOTYPE;

	return ie_parse_fast_bss_transition(&iter, mic_len, info);
}

bool ie_build_fast_bss_transition(const struct ie_ft_info *info,
					uint32_t mic_len, uint8_t *to)
{
	uint8_t *len;

	*to++ = IE_TYPE_FAST_BSS_TRANSITION;

	len = to++;
	*len = (mic_len == 16) ? 82 : 90;

	to[0] = 0x00;
	to[1] = info->mic_element_count;

	memcpy(to + 2, info->mic, mic_len);

	memcpy(to + mic_len + 2, info->anonce, 32);

	memcpy(to + mic_len + 34, info->snonce, 32);

	to += (mic_len == 16) ? 82 : 90;

	if (info->r1khid_present) {
		to[0] = 1;
		to[1] = 6;
		memcpy(to + 2, info->r1khid, 6);
		to += 8;
		*len += 8;
	}

	L_WARN_ON(info->gtk_len); /* Not implemented */

	if (info->r0khid_len) {
		to[0] = 3;
		to[1] = info->r0khid_len;
		memcpy(to + 2, info->r0khid, info->r0khid_len);
		to += 2 + info->r0khid_len;
		*len += 2 + info->r0khid_len;
	}

	L_WARN_ON(info->igtk_len); /* Not implemented */

	if (info->oci_present) {
		to[0] = 5;
		to[1] = 3;
		memcpy(to + 2, info->oci, sizeof(info->oci));
		*len += 5;
	}

	return true;
}

enum nr_subelem_id {
	NR_SUBELEM_ID_TSF_INFO			= 1,
	NR_SUBELEM_ID_CONDENSED_COUNTRY_STR	= 2,
	NR_SUBELEM_ID_BSS_TRANSITION_PREF	= 3,
	NR_SUBELEM_ID_BSS_TERMINATION_DURATION	= 4,
	NR_SUBELEM_ID_BEARING			= 5,
	NR_SUBELEM_ID_WIDE_BW_CHANNEL		= 6,
	/* Remaining defined subelements use the IE_TYPE_* ID values */
};

int ie_parse_neighbor_report(struct ie_tlv_iter *iter,
				struct ie_neighbor_report_info *info)
{
	unsigned int len = ie_tlv_iter_get_length(iter);
	const uint8_t *data = ie_tlv_iter_get_data(iter);
	struct ie_tlv_iter opt_iter;

	if (len < 13)
		return -EINVAL;

	memset(info, 0, sizeof(*info));

	memcpy(info->addr, data + 0, 6);

	info->ht = test_bit(data + 8, 3);
	info->md = test_bit(data + 8, 2);
	info->immediate_block_ack = test_bit(data + 8, 1);
	info->delayed_block_ack = test_bit(data + 8, 0);
	info->rm = test_bit(data + 9, 7);
	info->apsd = test_bit(data + 9, 6);
	info->qos = test_bit(data + 9, 5);
	info->spectrum_mgmt = test_bit(data + 9, 4);
	info->key_scope = test_bit(data + 9, 3);
	info->security = test_bit(data + 9, 2);
	info->reachable = bit_field(data[9], 0, 2);

	info->oper_class = data[10];

	info->channel_num = data[11];

	info->phy_type = data[12];

	ie_tlv_iter_init(&opt_iter, data + 13, len - 13);

	while (ie_tlv_iter_next(&opt_iter)) {
		if (ie_tlv_iter_get_tag(&opt_iter) !=
				NR_SUBELEM_ID_BSS_TRANSITION_PREF)
			continue;

		if (ie_tlv_iter_get_length(&opt_iter) != 1)
			continue;

		info->bss_transition_pref = ie_tlv_iter_get_data(&opt_iter)[0];
		info->bss_transition_pref_present = true;
	}

	return 0;
}

int ie_parse_roaming_consortium(struct ie_tlv_iter *iter, size_t *num_anqp_out,
				const uint8_t **oi1_out, size_t *oi1_len_out,
				const uint8_t **oi2_out, size_t *oi2_len_out,
				const uint8_t **oi3_out, size_t *oi3_len_out)
{
	unsigned int len = ie_tlv_iter_get_length(iter);
	const uint8_t *data = ie_tlv_iter_get_data(iter);
	size_t num_anqp;
	size_t oi1_len;
	size_t oi2_len;
	size_t oi3_len;

	if (len < 4)
		return -EINVAL;

	num_anqp = l_get_u8(data);
	oi1_len = bit_field(l_get_u8(data + 1), 0, 4);
	oi2_len = bit_field(l_get_u8(data + 1), 4, 4);
	oi3_len = len - (2 + oi1_len + oi2_len);

	if (!oi1_len)
		return -EINVAL;

	if (len < oi1_len + oi2_len + oi3_len + 2)
		return -EINVAL;

	if (num_anqp_out)
		*num_anqp_out = num_anqp;

	if (oi1_out)
		*oi1_out = data + 2;

	if (oi1_len_out)
		*oi1_len_out = oi1_len;

	/* OI2/3 are optional, explicitly set to NULL if not included */
	if (oi2_len) {
		if (oi2_out)
			*oi2_out = data + 2 + oi1_len;

		if (oi2_len_out)
			*oi2_len_out = oi2_len;
	} else if (oi2_out)
		*oi2_out = NULL;

	if (oi3_len) {
		if (oi3_out)
			*oi3_out = data + 2 + oi1_len + oi2_len;

		if (oi3_len_out)
			*oi3_len_out = oi3_len;
	} else if (oi3_out)
		*oi3_out = NULL;

	return 0;
}

int ie_parse_roaming_consortium_from_data(const uint8_t *data, size_t len,
				size_t *num_anqp_out, const uint8_t **oi1_out,
				size_t *oi1_len_out, const uint8_t **oi2_out,
				size_t *oi2_len_out, const uint8_t **oi3_out,
				size_t *oi3_len_out)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_ROAMING_CONSORTIUM)
		return -EPROTOTYPE;

	return ie_parse_roaming_consortium(&iter, num_anqp_out, oi1_out,
						oi1_len_out, oi2_out,
						oi2_len_out, oi3_out,
						oi3_len_out);
}

int ie_build_roaming_consortium(const uint8_t *rc, size_t rc_len, uint8_t *to)
{
	*to++ = IE_TYPE_VENDOR_SPECIFIC;

	*to++ = rc_len + 4;

	memcpy(to, wifi_alliance_oui, 3);
	to += 3;

	*to++ = 0x1d;

	memcpy(to, rc, rc_len);

	return 0;
}

int ie_parse_hs20_indication(struct ie_tlv_iter *iter, uint8_t *version_out,
				uint16_t *pps_mo_id_out, uint8_t *domain_id_out,
				bool *dgaf_disable_out)
{
	unsigned int len = ie_tlv_iter_get_length(iter);
	const uint8_t *data = ie_tlv_iter_get_data(iter);
	uint8_t hs20_config;
	bool pps_mo_present, domain_id_present;

	if (!is_ie_wfa_ie(data, iter->len, IE_WFA_OI_HS20_INDICATION))
		return -EPROTOTYPE;

	hs20_config = l_get_u8(data + 4);

	pps_mo_present = test_bit(&hs20_config, 1);
	domain_id_present = test_bit(&hs20_config, 2);

	/*
	 * Hotspot 2.0 Spec - Section 3.1.1
	 *
	 * "Either the PPS MO ID field or the ANQP Domain ID field (these
	 * are mutually exclusive fields) is included in the HS2.0 Indication
	 * element"
	 */
	if (pps_mo_present && domain_id_present)
		return -EPROTOTYPE;

	if (dgaf_disable_out)
		*dgaf_disable_out = test_bit(&hs20_config, 0);

	if (version_out)
		*version_out = bit_field(hs20_config, 4, 4);

	if (pps_mo_id_out)
		*pps_mo_id_out = 0;

	if (domain_id_out)
		*domain_id_out = 0;

	/* No PPS MO ID or Domain ID */
	if (len == 5)
		return 0;

	/* we know from is_ie_wfa_ie that the length must be 7 */
	if (pps_mo_present) {
		if (pps_mo_id_out)
			*pps_mo_id_out = l_get_u16(data + 5);
	} else if (domain_id_present) {
		if (domain_id_out)
			*domain_id_out = l_get_u16(data + 5);
	}

	return 0;
}

int ie_parse_hs20_indication_from_data(const uint8_t *data, size_t len,
					uint8_t *version, uint16_t *pps_mo_id,
					uint8_t *domain_id, bool *dgaf_disable)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
		return -EPROTOTYPE;

	return ie_parse_hs20_indication(&iter, version, pps_mo_id, domain_id,
						dgaf_disable);
}

/*
 * Only use version for building as this is meant for the (Re)Association IE.
 * In this case DGAF is always disabled, Domain ID should not be present, and
 * this device was not configured with PerProviderSubscription MO.
 */
int ie_build_hs20_indication(uint8_t version, uint8_t *to)
{
	if (version > 2)
		return -EINVAL;

	*to++ = IE_TYPE_VENDOR_SPECIFIC;
	*to++ = 5;

	memcpy(to, wifi_alliance_oui, 3);
	to += 3;

	*to++ = IE_WFA_OI_HS20_INDICATION;

	*to++ = (version << 4) & 0xf0;

	return 0;
}

bool ie_rsnxe_capable(const uint8_t *rsnxe, unsigned int bit)
{
	unsigned int field_len;

	if (!rsnxe)
		return false;

	if (rsnxe[1] == 0)
		return false;

	field_len = bit_field(rsnxe[2], 0, 4);
	if (field_len + 1 != rsnxe[1])
		return false;

	if ((bit / 8) > field_len)
		return false;

	return test_bit(rsnxe + 2, bit);
}

/* 802.11ai-2016 Tables 9-589r, 9-262d, 9-262e */
enum ie_fils_ip_addr_req_ctrl_bits {
	IE_FILS_IP_ADDR_REQ_CTRL_IPV4_MASK = 3 << 0,
	IE_FILS_IP_ADDR_REQ_CTRL_IPV4_NONE = 0 << 0,
	IE_FILS_IP_ADDR_REQ_CTRL_IPV4_NEW = 2 << 0,
	IE_FILS_IP_ADDR_REQ_CTRL_IPV4_SPECIFIC = 3 << 0,
	IE_FILS_IP_ADDR_REQ_CTRL_IPV6_MASK = 3 << 2,
	IE_FILS_IP_ADDR_REQ_CTRL_IPV6_NONE = 0 << 2,
	IE_FILS_IP_ADDR_REQ_CTRL_IPV6_NEW = 2 << 2,
	IE_FILS_IP_ADDR_REQ_CTRL_IPV6_SPECIFIC = 3 << 2,
	IE_FILS_IP_ADDR_REQ_CTRL_DNS = 1 << 4,
};

/* 802.11ai-2016 Table 9-262f */
enum ie_fils_ip_addr_resp_ctrl_bits {
	IE_FILS_IP_ADDR_RESP_CTRL_IP_PENDING = 1 << 0,
	IE_FILS_IP_ADDR_RESP_CTRL_IPV4_ASSIGNED = 1 << 1,
	IE_FILS_IP_ADDR_RESP_CTRL_IPV4_GW_INCLUDED = 1 << 2,
	IE_FILS_IP_ADDR_RESP_CTRL_IPV6_ASSIGNED = 1 << 3,
	IE_FILS_IP_ADDR_RESP_CTRL_IPV6_GW_INCLUDED = 1 << 4,
	IE_FILS_IP_ADDR_RESP_CTRL_IPV4_LIFETIME_INCLUDED = 1 << 5,
	IE_FILS_IP_ADDR_RESP_CTRL_IPV6_LIFETIME_INCLUDED = 1 << 6,
};

/* 802.11ai-2016 Table 9-262h */
enum ie_fils_ip_addr_resp_dns_ctrl_bits {
	IE_FILS_IP_ADDR_RESP_DNS_CTRL_IPV4_DNS_INCLUDED = 1 << 0,
	IE_FILS_IP_ADDR_RESP_DNS_CTRL_IPV6_DNS_INCLUDED = 1 << 1,
	IE_FILS_IP_ADDR_RESP_DNS_CTRL_IPV4_DNS_MAC_INCLUDED = 1 << 2,
	IE_FILS_IP_ADDR_RESP_DNS_CTRL_IPV6_DNS_MAC_INCLUDED = 1 << 3,
};

int ie_parse_fils_ip_addr_request(struct ie_tlv_iter *iter,
				struct ie_fils_ip_addr_request_info *out)
{
	unsigned int len = ie_tlv_iter_get_length(iter);
	const uint8_t *data = ie_tlv_iter_get_data(iter);
	struct ie_fils_ip_addr_request_info info = {};
	bool ipv4_specific_addr = false;
	bool ipv6_specific_addr = false;

	if (len < 1)
		return -EMSGSIZE;

	if (L_IN_SET(data[0] & IE_FILS_IP_ADDR_REQ_CTRL_IPV4_MASK,
			IE_FILS_IP_ADDR_REQ_CTRL_IPV4_NEW,
			IE_FILS_IP_ADDR_REQ_CTRL_IPV4_SPECIFIC)) {
		info.ipv4 = true;
		ipv4_specific_addr =
			(data[0] & IE_FILS_IP_ADDR_REQ_CTRL_IPV4_MASK) ==
			IE_FILS_IP_ADDR_REQ_CTRL_IPV4_SPECIFIC;
	} else if ((data[0] & IE_FILS_IP_ADDR_REQ_CTRL_IPV4_MASK) !=
			IE_FILS_IP_ADDR_REQ_CTRL_IPV4_NONE)
		return -EINVAL;

	if (L_IN_SET(data[0] & IE_FILS_IP_ADDR_REQ_CTRL_IPV6_MASK,
			IE_FILS_IP_ADDR_REQ_CTRL_IPV6_NEW,
			IE_FILS_IP_ADDR_REQ_CTRL_IPV6_SPECIFIC)) {
		info.ipv6 = true;
		ipv6_specific_addr =
			(data[0] & IE_FILS_IP_ADDR_REQ_CTRL_IPV6_MASK) ==
			IE_FILS_IP_ADDR_REQ_CTRL_IPV6_SPECIFIC;
	} else if ((data[0] & IE_FILS_IP_ADDR_REQ_CTRL_IPV6_MASK) !=
			IE_FILS_IP_ADDR_REQ_CTRL_IPV6_NONE)
		return -EINVAL;

	info.dns = !!(*data++ & IE_FILS_IP_ADDR_REQ_CTRL_DNS);

	if (len < 1 + (ipv4_specific_addr ? 4u : 0u) +
			(ipv6_specific_addr ? 16u : 0u))
		return -EMSGSIZE;

	if (ipv4_specific_addr) {
		info.ipv4_requested_addr = l_get_u32(data);
		data += 4;

		if (!info.ipv4_requested_addr)
			return -EINVAL;
	}

	if (ipv6_specific_addr) {
		memcpy(info.ipv6_requested_addr, data, 16);
		data += 16;

		if (l_memeqzero(info.ipv6_requested_addr, 16))
			return -EINVAL;
	}

	memcpy(out, &info, sizeof(info));
	return 0;
}

void ie_build_fils_ip_addr_request(
				const struct ie_fils_ip_addr_request_info *info,
				uint8_t *to)
{
	uint8_t *len;
	uint8_t *ctrl;

	*to++ = IE_TYPE_EXTENSION;
	len = to++;
	*to++ = IE_TYPE_FILS_IP_ADDRESS & 0xff;
	ctrl = to++;

	*ctrl = info->dns ? IE_FILS_IP_ADDR_REQ_CTRL_DNS : 0;

	if (info->ipv4) {
		if (info->ipv4_requested_addr) {
			l_put_u32(info->ipv4_requested_addr, to);
			to += 4;
			*ctrl |= IE_FILS_IP_ADDR_REQ_CTRL_IPV4_SPECIFIC;
		} else
			*ctrl |= IE_FILS_IP_ADDR_REQ_CTRL_IPV4_NEW;
	}

	if (info->ipv6) {
		if (!l_memeqzero(info->ipv6_requested_addr, 16)) {
			memcpy(to, info->ipv6_requested_addr, 16);
			to += 16;
			*ctrl |= IE_FILS_IP_ADDR_REQ_CTRL_IPV6_SPECIFIC;
		} else
			*ctrl |= IE_FILS_IP_ADDR_REQ_CTRL_IPV6_NEW;
	}

	*len = to - (len + 1);
}

#define NEXT_FIELD(data, len, size) (__extension__ ({	\
	const uint8_t *_ptr = data;			\
							\
	if (len < size)					\
		return -EMSGSIZE;			\
							\
	data += size;					\
	len -= size;					\
	_ptr; }))

int ie_parse_fils_ip_addr_response(struct ie_tlv_iter *iter,
				struct ie_fils_ip_addr_response_info *out)
{
	unsigned int len = ie_tlv_iter_get_length(iter);
	const uint8_t *data = ie_tlv_iter_get_data(iter);
	struct ie_fils_ip_addr_response_info info = {};
	const uint8_t *resp_ctrl;
	const uint8_t *dns_ctrl;
	const uint8_t *ptr;

	resp_ctrl = NEXT_FIELD(data, len, 2);
	dns_ctrl = resp_ctrl + 1;

	info.response_pending =
		!!(*resp_ctrl & IE_FILS_IP_ADDR_RESP_CTRL_IP_PENDING);

	if (info.response_pending) {
		info.response_timeout =
			bit_field(*resp_ctrl, 1, 6); /* seconds */
		return 0;
	}

	if (*resp_ctrl & IE_FILS_IP_ADDR_RESP_CTRL_IPV4_ASSIGNED) {
		uint32_t netmask;

		ptr = NEXT_FIELD(data, len, 8);
		info.ipv4_addr = l_get_u32(ptr);
		netmask = l_get_be32(ptr + 4);
		info.ipv4_prefix_len = __builtin_popcount(netmask);

		if (!info.ipv4_addr || info.ipv4_prefix_len > 30 || netmask !=
				util_netmask_from_prefix(info.ipv4_prefix_len))
			return -EINVAL;
	}

	if (*resp_ctrl & IE_FILS_IP_ADDR_RESP_CTRL_IPV4_GW_INCLUDED) {
		ptr = NEXT_FIELD(data, len, 10);
		info.ipv4_gateway = l_get_u32(ptr);
		memcpy(info.ipv4_gateway_mac, ptr + 4, 6);

		/* Check gateway is on the same subnet */
		if (info.ipv4_addr &&
				!util_ip_subnet_match(info.ipv4_prefix_len,
							&info.ipv4_addr,
							&info.ipv4_gateway))
			return -EINVAL;
	}

	if (*resp_ctrl & IE_FILS_IP_ADDR_RESP_CTRL_IPV6_ASSIGNED) {
		ptr = NEXT_FIELD(data, len, 17);
		memcpy(info.ipv6_addr, ptr, 16);
		info.ipv6_prefix_len = ptr[16];

		if (l_memeqzero(info.ipv6_addr, 16) ||
				info.ipv6_prefix_len > 126)
			return -EINVAL;
	}

	if (*resp_ctrl & IE_FILS_IP_ADDR_RESP_CTRL_IPV6_GW_INCLUDED) {
		ptr = NEXT_FIELD(data, len, 22);
		memcpy(info.ipv6_gateway, ptr, 16);
		memcpy(info.ipv6_gateway_mac, ptr + 16, 6);

		/* Check gateway is on the same subnet */
		if (!l_memeqzero(info.ipv6_addr, 16) &&
				!util_ip_subnet_match(info.ipv6_prefix_len,
							info.ipv6_addr,
							info.ipv6_gateway))
			return -EINVAL;
	}

	if (*resp_ctrl & IE_FILS_IP_ADDR_RESP_CTRL_IPV4_LIFETIME_INCLUDED)
		info.ipv4_lifetime = *NEXT_FIELD(data, len, 1); /* seconds */

	if (*resp_ctrl & IE_FILS_IP_ADDR_RESP_CTRL_IPV6_LIFETIME_INCLUDED)
		info.ipv6_lifetime = *NEXT_FIELD(data, len, 1); /* seconds */

	if (*dns_ctrl & IE_FILS_IP_ADDR_RESP_DNS_CTRL_IPV4_DNS_INCLUDED) {
		info.ipv4_dns = l_get_u32(NEXT_FIELD(data, len, 4));

		if (!info.ipv4_dns)
			return -EINVAL;
	}

	if (*dns_ctrl & IE_FILS_IP_ADDR_RESP_DNS_CTRL_IPV6_DNS_INCLUDED) {
		memcpy(info.ipv6_dns, NEXT_FIELD(data, len, 16), 16);

		if (l_memeqzero(info.ipv6_dns, 16))
			return -EINVAL;
	}

	if (*dns_ctrl & IE_FILS_IP_ADDR_RESP_DNS_CTRL_IPV4_DNS_MAC_INCLUDED)
		memcpy(info.ipv4_dns_mac, NEXT_FIELD(data, len, 6), 6);

	if (*dns_ctrl & IE_FILS_IP_ADDR_RESP_DNS_CTRL_IPV6_DNS_MAC_INCLUDED)
		memcpy(info.ipv6_dns_mac, NEXT_FIELD(data, len, 6), 6);

	memcpy(out, &info, sizeof(info));
	return 0;
}

void ie_build_fils_ip_addr_response(
			const struct ie_fils_ip_addr_response_info *info,
			uint8_t *to)
{
	uint8_t *len;
	uint8_t *resp_ctrl;
	uint8_t *dns_ctrl;

	*to++ = IE_TYPE_EXTENSION;
	len = to++;
	*to++ = IE_TYPE_FILS_IP_ADDRESS & 0xff;
	resp_ctrl = to++;
	dns_ctrl = to++;

	*resp_ctrl = 0;
	*dns_ctrl = 0;

	if (info->response_pending) {
		*resp_ctrl |= IE_FILS_IP_ADDR_RESP_CTRL_IP_PENDING;
		*resp_ctrl |= info->response_timeout << 1;
		goto done;
	}

	if (info->ipv4_addr) {
		uint32_t netmask =
			util_netmask_from_prefix(info->ipv4_prefix_len);

		*resp_ctrl |= IE_FILS_IP_ADDR_RESP_CTRL_IPV4_ASSIGNED;

		l_put_u32(info->ipv4_addr, to);
		l_put_u32(htonl(netmask), to + 4);
		to += 8;
	}

	if (info->ipv4_gateway) {
		*resp_ctrl |= IE_FILS_IP_ADDR_RESP_CTRL_IPV4_GW_INCLUDED;

		l_put_u32(info->ipv4_gateway, to);
		memcpy(to + 4, info->ipv4_gateway_mac, 6);
		to += 10;
	}

	if (!l_memeqzero(info->ipv6_addr, 16)) {
		*resp_ctrl |= IE_FILS_IP_ADDR_RESP_CTRL_IPV6_ASSIGNED;

		memcpy(to, info->ipv6_addr, 16);
		to[16] = info->ipv6_prefix_len;
		to += 17;
	}

	if (!l_memeqzero(info->ipv6_gateway, 16)) {
		*resp_ctrl |= IE_FILS_IP_ADDR_RESP_CTRL_IPV6_GW_INCLUDED;

		memcpy(to, info->ipv6_gateway, 16);
		memcpy(to + 16, info->ipv6_gateway_mac, 6);
		to += 22;
	}

	if (info->ipv4_lifetime) {
		*resp_ctrl |= IE_FILS_IP_ADDR_RESP_CTRL_IPV4_LIFETIME_INCLUDED;

		*to++ = info->ipv4_lifetime;
	}

	if (info->ipv6_lifetime) {
		*resp_ctrl |= IE_FILS_IP_ADDR_RESP_CTRL_IPV6_LIFETIME_INCLUDED;

		*to++ = info->ipv6_lifetime;
	}

	if (info->ipv4_dns) {
		*dns_ctrl |= IE_FILS_IP_ADDR_RESP_DNS_CTRL_IPV4_DNS_INCLUDED;

		l_put_u32(info->ipv4_dns, to);
		to += 4;
	}

	if (!l_memeqzero(info->ipv6_dns, 16)) {
		*dns_ctrl |= IE_FILS_IP_ADDR_RESP_DNS_CTRL_IPV6_DNS_INCLUDED;

		memcpy(to, info->ipv6_dns, 16);
		to += 16;
	}

	if (!l_memeqzero(info->ipv4_dns_mac, 6)) {
		*dns_ctrl |=
			IE_FILS_IP_ADDR_RESP_DNS_CTRL_IPV4_DNS_MAC_INCLUDED;

		memcpy(to, info->ipv4_dns_mac, 6);
		to += 6;
	}

	if (!l_memeqzero(info->ipv6_dns_mac, 6)) {
		*dns_ctrl |=
			IE_FILS_IP_ADDR_RESP_DNS_CTRL_IPV6_DNS_MAC_INCLUDED;

		memcpy(to, info->ipv6_dns_mac, 6);
		to += 6;
	}

done:
	*len = to - (len + 1);
}

/*
 * Parse Network Cost IE according to:
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nct/88f0cdf4-cdf2-4455-b849-4abf1e5c11ac
 */
int ie_parse_network_cost(const void *data, size_t len,
				uint16_t *level, uint16_t *flags)
{
	const uint8_t *ie = data;

	if (len < 10 || ie[0] != IE_TYPE_VENDOR_SPECIFIC || ie[1] != 8)
		return -ENOMSG;

	if (memcmp(ie + 2, microsoft_oui, 3) || ie[5] != 0x11)
		return -ENOMSG;

	*level = l_get_le16(ie + 6);
	*flags = l_get_le16(ie + 8);
	return 0;
}

int ie_parse_owe_transition(const void *data, size_t len,
				struct ie_owe_transition_info *info)
{
	const uint8_t *ie = data;
	const uint8_t *bssid;
	const uint8_t *ssid;
	uint8_t oper_class = 0;
	uint8_t channel = 0;
	size_t slen;

	if (len < 14 || ie[0] != IE_TYPE_VENDOR_SPECIFIC)
		return -ENOMSG;

	if (!is_ie_wfa_ie(ie + 2, len - 2, IE_WFA_OI_OWE_TRANSITION))
		return -ENOMSG;

	slen = l_get_u8(ie + 12);
	if (slen > 32)
		return -ENOMSG;

	/*
	 * WFA OWE Specification 2.3.1
	 *
	 * "Band Info and Channel Info are optional fields. If configured,
	 * both fields shall be included in an OWE Transition Mode element"
	 */
	if (len != slen + 13 && len != slen + 15)
		return -ENOMSG;

	bssid = ie + 6;
	ssid = ie + 13;

	if (len == slen + 15) {
		oper_class = l_get_u8(ie + 13 + slen);
		channel = l_get_u8(ie + 14 + slen);
	}

	memcpy(info->bssid, bssid, 6);
	memcpy(info->ssid, ssid, slen);
	info->ssid_len = slen;
	info->oper_class = oper_class;
	info->channel = channel;

	return 0;
}

int ie_parse_oci(const void *data, size_t len, const uint8_t **oci)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_length(&iter) != 3)
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_OCI)
		return -EPROTOTYPE;

	*oci = ie_tlv_iter_get_data(&iter);

	return 0;
}

/*
 * Checks the supported width set (Table 9-322b) meets the following
 * requirements:
 *  - B0 and bits B1/B2/B3 are mutually exclusive.
 *  - B2 is only set if B1 is set
 *  - B3 is only set if B2 is set (and in turn, B1 is set)
 *  - The IE length supports B2 and B3 MCS sets
 */
bool ie_validate_he_capabilities(const void *data, size_t len)
{
	uint8_t width_set;
	const uint8_t *ptr = data;
	bool freq_2_4;
	bool width_40_80;
	bool width_160;
	bool width_80p80;

	if (len < 22)
		return false;

	width_set = bit_field((ptr + 7)[0], 1, 7);

	/* B0 indicates support for 40MHz, but only in 2.4GHz band */
	freq_2_4 = test_bit(&width_set, 0);

	/* B1 indicates support for 40/80MHz */
	width_40_80 = test_bit(&width_set, 1);

	if (width_40_80 && freq_2_4)
		return false;

	/* B2 indicates support for 160MHz MCS table */
	width_160 = test_bit(&width_set, 2);

	/* Ensure B1 is set, not B0, and the length includes this MCS table */
	if (width_160 && (!width_40_80 || freq_2_4 || len < 26))
		return false;

	/* B3 indicates support for 80+80Mhz MCS table */
	width_80p80 = test_bit(&width_set, 3);

	/* Ensure B2 is set, not B0, and the length includes this MCS table */
	if (width_80p80 && (!width_160 || freq_2_4 || len < 30))
		return false;

	return true;
}
