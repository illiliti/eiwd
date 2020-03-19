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

#include <ell/ell.h>

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
			unsigned int *out_len)
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
	case IE_RSN_CIPHER_SUITE_BIP:
		return CRYPTO_CIPHER_BIP;
	default:
		return 0;
	}
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
			*out = IE_RSN_CIPHER_SUITE_BIP;
			return true;
		case 7:
			*out = IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC;
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
		break;
	default:
		return false;
	}

	*out = tmp;
	return true;
}

static bool ie_parse_pairwise_cipher(const uint8_t *data,
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
	case IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER:
		break;
	default:
		return false;
	}

	*out = tmp;
	return true;
}

static bool ie_parse_group_management_cipher(const uint8_t *data,
					enum ie_rsn_cipher_suite *out)
{
	enum ie_rsn_cipher_suite tmp;

	bool r = ie_parse_cipher_suite(data, &tmp);

	if (!r)
		return r;

	switch (tmp) {
	case IE_RSN_CIPHER_SUITE_BIP:
	case IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC:
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

		if (!ie_parse_pairwise_cipher(data + i * 4, &suite))
			return -ERANGE;

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

	out_info->preauthentication = util_is_bit_set(data[0], 0);
	out_info->no_pairwise = util_is_bit_set(data[0], 1);
	out_info->ptksa_replay_counter = util_bit_field(data[0], 2, 2);
	out_info->gtksa_replay_counter = util_bit_field(data[0], 4, 2);
	out_info->mfpr = util_is_bit_set(data[0], 6);
	out_info->mfpc = util_is_bit_set(data[0], 7);
	out_info->peerkey_enabled = util_is_bit_set(data[1], 1);
	out_info->spp_a_msdu_capable = util_is_bit_set(data[1], 2);
	out_info->spp_a_msdu_required = util_is_bit_set(data[1], 3);
	out_info->pbac = util_is_bit_set(data[1], 4);
	out_info->extended_key_id = util_is_bit_set(data[1], 5);

	/*
	 * BIP—default group management cipher suite in an RSNA with
	 * management frame protection enabled
	 */
	if (out_info->mfpc)
		out_info->group_management_cipher = IE_RSN_CIPHER_SUITE_BIP;

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
	switch (suite) {
	case IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER:
		memcpy(data, oui, 3);
		data[3] = 0;
		return true;
	case IE_RSN_CIPHER_SUITE_WEP40:
		memcpy(data, oui, 3);
		data[3] = 1;
		return true;
	case IE_RSN_CIPHER_SUITE_TKIP:
		memcpy(data, oui, 3);
		data[3] = 2;
		return true;
	case IE_RSN_CIPHER_SUITE_CCMP:
		memcpy(data, oui, 3);
		data[3] = 4;
		return true;
	case IE_RSN_CIPHER_SUITE_WEP104:
		memcpy(data, oui, 3);
		data[3] = 5;
		return true;
	case IE_RSN_CIPHER_SUITE_BIP:
		memcpy(data, oui, 3);
		data[3] = 6;
		return true;
	case IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC:
		memcpy(data, oui, 3);
		data[3] = 7;
		return true;
	}

	return false;
}

#define RETURN_AKM(data, oui, id)	\
	memcpy((data), (oui), 3);	\
	(data)[3] = (id);		\
	return true;

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

	akm_suite = IE_RSN_AKM_SUITE_8021X;
	count = 0;

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
				IE_RSN_CIPHER_SUITE_BIP)
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
							IE_RSN_CIPHER_SUITE_BIP)
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

	out_info->preauthentication = util_is_bit_set(data[0], 0);
	out_info->no_pairwise = util_is_bit_set(data[0], 1);
	out_info->ptksa_replay_counter = util_bit_field(data[0], 2, 2);
	out_info->gtksa_replay_counter = util_bit_field(data[0], 4, 2);

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

/*
 * We have to store this mapping since basic rates don't come with a convenient
 * MCS index. Rates are stored as they are encoded in the Supported Rates IE.
 * This does not include non 802.11g data rates, e.g. 1/2/4Mbps. This data was
 * taken from 802.11 Section 17.3.10.2 and Table 10-7.
 *
 * Section 17.3.10.2 defines minimum RSSI for modulations, and Table
 * 10-7 defines reference rates for the different modulations. Together we
 * have minimum RSSI required for a given data rate.
 */
struct basic_rate_map {
	int32_t rssi;
	uint8_t rate;
};

/*
 * Rates are stored in 500Kbps increments. This is how the IE encodes the data
 * so its more convenient to match by this encoding. The actual data rate is
 * converted to Mbps after we find a match
 */
static const struct basic_rate_map rate_rssi_map[] = {
	{ -82, 12 },
	{ -81, 18 },
	{ -79, 24 },
	{ -77, 36 },
	{ -74, 48 },
	{ -70, 72 },
	{ -66, 96 },
	{ -65, 108 },
};

static int ie_parse_supported_rates(struct ie_tlv_iter *supp_rates_iter,
					struct ie_tlv_iter *ext_supp_rates_iter,
					int32_t rssi,
					uint64_t *data_rate)
{
	uint8_t max_rate = 0;
	uint8_t highest = 0;
	const uint8_t *rates;
	unsigned int len;
	unsigned int i;

	len = ie_tlv_iter_get_length(supp_rates_iter);

	if (len == 0)
		return -EINVAL;

	/* Find highest rates possible with our RSSI */
	for (i = 0; i < L_ARRAY_SIZE(rate_rssi_map); i++) {
		const struct basic_rate_map *map = &rate_rssi_map[i];

		if (rssi < map->rssi)
			break;

		max_rate = map->rate;
	}

	/* Find highest rate in Supported Rates IE */
	rates = ie_tlv_iter_get_data(supp_rates_iter);

	for (i = 0; i < len; i++) {
		uint8_t r = rates[i] & 0x7f;

		if (r <= max_rate && r > highest)
			highest = r;
	}

	/* Find highest rate in Extended Supported Rates IE */
	if (ext_supp_rates_iter) {
		len = ie_tlv_iter_get_length(ext_supp_rates_iter);
		rates = ie_tlv_iter_get_data(ext_supp_rates_iter);

		for (i = 0; i < len; i++) {
			uint8_t r = rates[i] & 0x7f;

			if (r <= max_rate && r > highest)
				highest = r;
		}
	}

	*data_rate = (highest / 2) * 1000000;

	return 0;
}

int ie_parse_supported_rates_from_data(const uint8_t *supp_rates_ie,
					uint8_t supp_rates_len,
					const uint8_t *ext_supp_rates_ie,
					uint8_t ext_supp_rates_len,
					int32_t rssi, uint64_t *data_rate)
{
	struct ie_tlv_iter supp_rates_iter;
	struct ie_tlv_iter ext_supp_rates_iter;

	if (supp_rates_ie) {
		ie_tlv_iter_init(&supp_rates_iter, supp_rates_ie,
					supp_rates_len);

		if (!ie_tlv_iter_next(&supp_rates_iter))
			return -EMSGSIZE;

		if (ie_tlv_iter_get_tag(&supp_rates_iter) !=
						IE_TYPE_SUPPORTED_RATES)
			return -EPROTOTYPE;
	}

	if (ext_supp_rates_ie) {
		ie_tlv_iter_init(&ext_supp_rates_iter, ext_supp_rates_ie,
					ext_supp_rates_len);

		if (!ie_tlv_iter_next(&ext_supp_rates_iter))
			return -EMSGSIZE;

		if (ie_tlv_iter_get_tag(&ext_supp_rates_iter) !=
					IE_TYPE_EXTENDED_SUPPORTED_RATES)
			return -EPROTOTYPE;
	}

	return ie_parse_supported_rates(
			(supp_rates_ie) ? &supp_rates_iter : NULL,
			(ext_supp_rates_ie) ? &ext_supp_rates_iter : NULL,
			rssi, data_rate);
}

enum ht_vht_channel_width {
	HT_VHT_CHANNEL_WIDTH_20MHZ = 0,
	HT_VHT_CHANNEL_WIDTH_40MHZ,
	HT_VHT_CHANNEL_WIDTH_80MHZ,
	HT_VHT_CHANNEL_WIDTH_160MHZ,
};

/*
 * Base RSSI values for 20MHz (both HT and VHT) channel. These values can be
 * used to calculate the minimum RSSI values for all other channel widths. HT
 * MCS indexes are grouped into ranges of 8 (per spatial stream) where VHT are
 * grouped in chunks of 10. This just means HT will not use the last two
 * index's of this array.
 */
static const int32_t ht_vht_base_rssi[] = {
	-82, -79, -77, -74, -70, -66, -65, -64, -59, -57
};

struct ht_vht_rate {
	uint64_t rate;
	uint64_t sgi_rate;
};

static const struct ht_vht_rate ht_vht_rates[] = {
	[HT_VHT_CHANNEL_WIDTH_20MHZ] = {	.rate = 6500000,
						.sgi_rate = 7200000 },
	[HT_VHT_CHANNEL_WIDTH_40MHZ] = {	.rate = 13500000,
						.sgi_rate = 15000000 },
	[HT_VHT_CHANNEL_WIDTH_80MHZ] = {	.rate = 29300000,
						.sgi_rate = 32500000 },
	[HT_VHT_CHANNEL_WIDTH_160MHZ] = {	.rate = 58500000,
						.sgi_rate = 65000000 },
};

/*
 * Both HT and VHT rates are calculated in the same fashion. The only difference
 * is a relative MCS index is used for HT since, for each NSS, the formula
 * is the same with relative index's. This is why this is called with index % 8
 * for HT, but not VHT.
 */
static bool calculate_ht_vht_data_rate(uint8_t index,
					enum ht_vht_channel_width width,
					int32_t rssi, uint8_t nss, bool sgi,
					uint64_t *data_rate)
{
	const struct ht_vht_rate *rate = &ht_vht_rates[width];
	int32_t width_adjust = width * 3;

	if (rssi < ht_vht_base_rssi[index] + width_adjust)
		return false;

	if (sgi)
		*data_rate = rate->sgi_rate;
	else
		*data_rate = rate->rate;

	/* adjust base for spatial streams */
	*data_rate *= nss;

	/*
	 * As with HT, the VHT rates multiplier jumps up
	 * by 2 after MCS index 4
	 */
	if (index < 4)
		*data_rate *= index + 1;
	else
		*data_rate *= index + 3;

	return true;
}

static int ie_parse_ht_capability(struct ie_tlv_iter *iter, int32_t rssi,
				uint64_t *data_rate)
{
	unsigned int len;
	const uint8_t *data;
	uint8_t ht_cap;
	int i;
	uint64_t highest_rate = 0;
	bool support_40mhz;
	bool short_gi_20mhz;
	bool short_gi_40mhz;

	len = ie_tlv_iter_get_length(iter);

	if (len < 26)
		return -EINVAL;

	if (ie_tlv_iter_get_tag(iter) != IE_TYPE_HT_CAPABILITIES)
		return -EINVAL;

	data = ie_tlv_iter_get_data(iter);

	/* Parse out channel width set and short GI */
	ht_cap = l_get_u8(data++);

	support_40mhz = util_is_bit_set(ht_cap, 1);
	short_gi_20mhz = util_is_bit_set(ht_cap, 5);
	short_gi_40mhz = util_is_bit_set(ht_cap, 6);

	data += 2;

	/*
	 * TODO: Support MCS values 32 - 76
	 *
	 * The MCS values > 31 do not follow the same pattern since they use
	 * unequal modulation per spatial stream. These higher MCS values
	 * actually don't follow a pattern at all, since each stream can have a
	 * different modulation a higher MCS value does not mean higher
	 * throughput. For this reason these MCS indexes are left out.
	 */
	for (i = 31; i >= 0; i--) {
		uint64_t drate;
		uint8_t byte = i / 8;
		uint8_t bit = i % 8;

		if (!util_is_bit_set(data[byte], bit))
			continue;

		if (!support_40mhz)
			goto check_20;

		if (calculate_ht_vht_data_rate(i % 8,
						HT_VHT_CHANNEL_WIDTH_40MHZ,
						rssi, (i / 8) + 1,
						short_gi_40mhz, &drate)) {
			*data_rate = drate;
			return 0;
		}

check_20:
		if (!calculate_ht_vht_data_rate(i % 8,
						HT_VHT_CHANNEL_WIDTH_20MHZ,
						rssi, (i / 8) + 1,
						short_gi_20mhz, &drate))
			continue;

		if (!support_40mhz) {
			*data_rate = drate;
			return 0;
		}

		if (drate > highest_rate)
			highest_rate = drate;
	}

	if (!highest_rate)
		return -ENOTSUP;

	*data_rate = highest_rate;

	return 0;
}

static int ie_parse_ht_capability_from_data(const uint8_t *data, uint8_t len,
				int32_t rssi, uint64_t *data_rate)
{
	struct ie_tlv_iter iter;
	uint8_t tag;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	tag = ie_tlv_iter_get_tag(&iter);

	if (tag != IE_TYPE_HT_CAPABILITIES)
		return -EPROTOTYPE;

	return ie_parse_ht_capability(&iter, rssi, data_rate);
}

/*
 * IEEE 802.11 - Table 9-250
 *
 * For simplicity, we are ignoring the Extended BSS BW support, per NOTE 11:
 *
 * NOTE 11—A receiving STA in which dot11VHTExtendedNSSCapable is false will
 * ignore the Extended NSS BW Support subfield and effectively evaluate this
 * table only at the entries where Extended NSS BW Support is 0.
 *
 * This also allows us to group the 160/80+80 widths together, since they are
 * the same when Extended NSS BW is zero.
 */
static const uint8_t vht_width_map[3][4] = {
	[0] = { 1, 1, 1, 0 },
	[1] = { 1, 1, 1, 1 },
	[2] = { 1, 1, 1, 1 },
};

static int ie_parse_vht_capability(struct ie_tlv_iter *vht_iter,
				struct ie_tlv_iter *ht_iter, int32_t rssi,
				uint64_t *data_rate)
{
	int width;
	int mcs;
	unsigned int nss;
	unsigned int len;
	const uint8_t *data;
	uint8_t channel_width_set;
	uint8_t rx_mcs_map[2];
	uint8_t tx_mcs_map[2];
	unsigned int max_rx_mcs = 0;
	unsigned int rx_nss = 1;
	unsigned int max_tx_mcs = 0;
	unsigned int tx_nss = 1;
	uint8_t ht_cap;
	bool short_gi_20mhz;
	bool short_gi_40mhz;
	bool short_gi_80mhz;
	bool short_gi_160mhz;
	uint64_t highest_rate = 0;

	/* grab the short GI bits from the HT IE */
	len = ie_tlv_iter_get_length(ht_iter);

	if (len != 26)
		return -EINVAL;

	data = ie_tlv_iter_get_data(ht_iter);

	ht_cap = l_get_u8(data);

	short_gi_20mhz = util_is_bit_set(ht_cap, 5);
	short_gi_40mhz = util_is_bit_set(ht_cap, 6);

	/* now move onto VHT */
	len = ie_tlv_iter_get_length(vht_iter);

	if (len != 12)
		return -EINVAL;

	data = ie_tlv_iter_get_data(vht_iter);

	channel_width_set = util_bit_field(*data, 2, 2);
	short_gi_80mhz = util_bit_field(*data, 5, 1);
	short_gi_160mhz = util_bit_field(*data, 6, 1);

	data += 4;

	rx_mcs_map[0] = *data++;
	rx_mcs_map[1] = *data++;

	data += 2;

	tx_mcs_map[0] = *data++;
	tx_mcs_map[1] = *data++;

	/* NSS->MCS map values are grouped in 2-bit values */
	for (mcs = 15; mcs >= 0; mcs -= 2) {
		uint8_t rx_val = util_bit_field(rx_mcs_map[mcs / 8],
							mcs % 8, 2);
		uint8_t tx_val = util_bit_field(tx_mcs_map[mcs / 8],
							mcs % 8, 2);

		/*
		 * 0 indicates support for MCS 0-7
		 * 1 indicates support for MCS 0-8
		 * 2 indicates support for MCS 0-9
		 *
		 * Therefore 7 + rx/tx_val gives us our max MCS index.
		 */
		if (!max_rx_mcs && rx_val < 3) {
			max_rx_mcs = 7 + rx_val;
			rx_nss = (mcs / 2) + 1;
		}

		if (!max_tx_mcs && tx_val < 3) {
			max_tx_mcs = 7 + tx_val;
			tx_nss = (mcs / 2) + 1;
		}

		if (max_rx_mcs && max_tx_mcs)
			break;
	}

	if (!max_rx_mcs && !max_tx_mcs)
		return -EINVAL;

	/*
	 * Now, using channel width, MCS index, and NSS we can determine the
	 * theoretical maximum data rate. We iterate through all possible
	 * combinations (width, MCS, NSS), saving the highest data rate we find.
	 *
	 * We could calculate a maximum data rate separately for TX/RX, but
	 * since this is only used for BSS ranking, the minimum between the
	 * two should be good enough.
	 */
	for (width = sizeof(vht_width_map[0]) - 1; width >= 0; width--) {
		bool sgi = false;

		if (!vht_width_map[channel_width_set][width])
			continue;

		/*
		 * Consolidate short GI support into a single boolean, dependent
		 * on the channel width for this iteration.
		 */
		switch (width) {
		case HT_VHT_CHANNEL_WIDTH_20MHZ:
			sgi = short_gi_20mhz;
			break;
		case HT_VHT_CHANNEL_WIDTH_40MHZ:
			sgi = short_gi_40mhz;
			break;
		case HT_VHT_CHANNEL_WIDTH_80MHZ:
			sgi = short_gi_80mhz;
			break;
		case HT_VHT_CHANNEL_WIDTH_160MHZ:
			sgi = short_gi_160mhz;
			break;
		}

		for (nss = minsize(rx_nss, tx_nss); nss > 0; nss--) {
			/* NSS > 4 does not apply to 20/40MHz */
			if (width <= HT_VHT_CHANNEL_WIDTH_40MHZ && nss > 4)
				continue;

			for (mcs = minsize(max_rx_mcs, max_tx_mcs);
						mcs >= 0; mcs--) {
				uint64_t drate;

				if (!calculate_ht_vht_data_rate(mcs, width,
							rssi, nss, sgi, &drate))
					continue;

				if (drate > highest_rate)
					highest_rate = drate;

				/* Lower MCS index will only have lower rates */
				goto next_chanwidth;
			}
		}
next_chanwidth: ; /* empty statement */
	}

	if (highest_rate == 0)
		return -ENOTSUP;

	*data_rate = highest_rate;

	return 0;
}

static int ie_parse_vht_capability_from_data(const uint8_t *vht_ie,
					size_t vht_len, const uint8_t *ht_ie,
					size_t ht_len, int32_t rssi,
					uint64_t *data_rate)
{
	struct ie_tlv_iter vht_iter;
	struct ie_tlv_iter ht_iter;
	uint8_t tag;

	ie_tlv_iter_init(&vht_iter, vht_ie, vht_len);

	if (!ie_tlv_iter_next(&vht_iter))
		return -EMSGSIZE;

	tag = ie_tlv_iter_get_tag(&vht_iter);

	if (tag != IE_TYPE_VHT_CAPABILITIES)
		return -EPROTOTYPE;

	ie_tlv_iter_init(&ht_iter, ht_ie, ht_len);

	if (!ie_tlv_iter_next(&ht_iter))
		return -EMSGSIZE;

	tag = ie_tlv_iter_get_tag(&ht_iter);

	if (tag != IE_TYPE_HT_CAPABILITIES)
		return -EPROTOTYPE;

	return ie_parse_vht_capability(&vht_iter, &ht_iter, rssi, data_rate);
}

/*
 * Calculates the theoretical maximum data rates out of the provided
 * supported rates IE, HT IE, and VHT IE. All 3 parsing functions are allowed
 * to return -ENOTSUP, which indicates that a data rate was not found given
 * the provided data. This is not fatal, it most likely means our RSSI was too
 * low.
 */
int ie_parse_data_rates(const uint8_t *supp_rates_ie,
			const uint8_t *ext_supp_rates_ie,
			const uint8_t *ht_ie,
			const uint8_t *vht_ie,
			int32_t rssi,
			uint64_t *data_rate)
{
	int ret = -ENOTSUP;
	uint64_t rate = 0;

	/* An RSSI this low will not yield any rate results */
	if (rssi < -82)
		return -ENOTSUP;

	if (ht_ie && vht_ie) {
		ret = ie_parse_vht_capability_from_data(vht_ie, IE_LEN(vht_ie),
							ht_ie, IE_LEN(ht_ie),
							rssi, &rate);
		if (ret == 0)
			goto done;
	}

	if (ht_ie) {
		ret = ie_parse_ht_capability_from_data(ht_ie, IE_LEN(ht_ie),
						rssi, &rate);
		if (ret == 0)
			goto done;
	}

	if (supp_rates_ie || ext_supp_rates_ie) {
		ret = ie_parse_supported_rates_from_data(supp_rates_ie,
						IE_LEN(supp_rates_ie),
						ext_supp_rates_ie,
						IE_LEN(supp_rates_ie),
						rssi, &rate);
		if (ret == 0)
			goto done;
	}

	return ret;

done:
	*data_rate = rate;

	return 0;
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

			info->gtk_key_id = util_bit_field(data[0], 0, 2);
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

	info->ht = util_is_bit_set(data[8], 3);
	info->md = util_is_bit_set(data[8], 2);
	info->immediate_block_ack = util_is_bit_set(data[8], 1);
	info->delayed_block_ack = util_is_bit_set(data[8], 0);
	info->rm = util_is_bit_set(data[9], 7);
	info->apsd = util_is_bit_set(data[9], 6);
	info->qos = util_is_bit_set(data[9], 5);
	info->spectrum_mgmt = util_is_bit_set(data[9], 4);
	info->key_scope = util_is_bit_set(data[9], 3);
	info->security = util_is_bit_set(data[9], 2);
	info->reachable = util_bit_field(data[9], 0, 2);

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
	oi1_len = util_bit_field(l_get_u8(data + 1), 0, 4);
	oi2_len = util_bit_field(l_get_u8(data + 1), 4, 4);
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
				uint16_t *pps_mo_id_out, uint8_t *domain_id_out)
{
	unsigned int len = ie_tlv_iter_get_length(iter);
	const uint8_t *data = ie_tlv_iter_get_data(iter);
	uint8_t hs20_config;
	bool pps_mo_present, domain_id_present;

	if (!is_ie_wfa_ie(data, iter->len, IE_WFA_OI_HS20_INDICATION))
		return -EPROTOTYPE;

	hs20_config = l_get_u8(data + 4);

	pps_mo_present = util_is_bit_set(hs20_config, 1);
	domain_id_present = util_is_bit_set(hs20_config, 2);

	/*
	 * Hotspot 2.0 Spec - Section 3.1.1
	 *
	 * "Either the PPS MO ID field or the ANQP Domain ID field (these
	 * are mutually exclusive fields) is included in the HS2.0 Indication
	 * element"
	 */
	if (pps_mo_present && domain_id_present)
		return -EPROTOTYPE;

	if (version_out)
		*version_out = util_bit_field(hs20_config, 4, 4);

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
					uint8_t *domain_id)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, len);

	if (!ie_tlv_iter_next(&iter))
		return -EMSGSIZE;

	if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
		return -EPROTOTYPE;

	return ie_parse_hs20_indication(&iter, version, pps_mo_id, domain_id);
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
