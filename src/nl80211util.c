/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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
#include <linux/if_ether.h>
#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/nl80211util.h"
#include "src/band.h"
#include "src/ie.h"
#include "src/handshake.h"
#include "src/util.h"

typedef bool (*attr_handler)(const void *data, uint16_t len, void *o);
typedef attr_handler (*handler_for_type)(int type);

static bool extract_ifindex(const void *data, uint16_t len, void *o)
{
	uint32_t *out = o;

	if (len != 4)
		return false;

	/* ifindex cannot be 0 */
	if (l_get_u32(data) == 0)
		return false;

	*out = l_get_u32(data);
	return true;
}

static bool extract_name(const void *data, uint16_t len, void *o)
{
	const char **out = o;

	if (len < 1)
		return false;

	if (!memchr(data + 1, 0, len - 1))
		return false;

	*out = data;
	return true;
}

static bool extract_2_chars(const void *data, uint16_t len, void *o)
{
	char *out = o;
	const char *in = data;

	if (len != 3 || in[2] != 0)
		return false;

	out[0] = in[0];
	out[1] = in[1];
	return true;
}

static bool extract_mac(const void *data, uint16_t len, void *o)
{
	const uint8_t **out = o;

	if (len != 6)
		return false;

	*out = data;
	return true;
}

static bool extract_uint64(const void *data, uint16_t len, void *o)
{
	uint64_t *out = o;

	if (len != 8)
		return false;

	*out = l_get_u64(data);
	return true;
}

static bool extract_uint32(const void *data, uint16_t len, void *o)
{
	uint32_t *out = o;

	if (len != 4)
		return false;

	*out = l_get_u32(data);
	return true;
}

static bool extract_flag(const void *data, uint16_t len, void *o)
{
	if (len != 0)
		return false;

	return true;
}

static bool extract_iovec(const void *data, uint16_t len, void *o)
{
	struct iovec *iov = o;

	iov->iov_base = (void *) data;
	iov->iov_len = len;

	return true;
}

static bool extract_nested(const void *data, uint16_t len, void *o)
{
	const struct l_genl_attr *outer = data;
	struct l_genl_attr *nested = o;

	return l_genl_attr_recurse(outer, nested);
}

static bool extract_u8(const void *data, uint16_t len, void *o)
{
	uint8_t *out = o;

	if (len != 1)
		return false;

	*out = l_get_u8(data);
	return true;
}

static attr_handler handler_for_nl80211(int type)
{
	switch (type) {
	case NL80211_ATTR_IFINDEX:
		return extract_ifindex;
	case NL80211_ATTR_WIPHY:
	case NL80211_ATTR_IFTYPE:
	case NL80211_ATTR_KEY_TYPE:
	case NL80211_ATTR_SCAN_FLAGS:
		return extract_uint32;
	case NL80211_ATTR_WDEV:
	case NL80211_ATTR_COOKIE:
		return extract_uint64;
	case NL80211_ATTR_IFNAME:
	case NL80211_ATTR_WIPHY_NAME:
		return extract_name;
	case NL80211_ATTR_REG_ALPHA2:
		return extract_2_chars;
	case NL80211_ATTR_MAC:
		return extract_mac;
	case NL80211_ATTR_ACK:
		return extract_flag;
	case NL80211_ATTR_WIPHY_FREQ:
	case NL80211_ATTR_WIPHY_FREQ_OFFSET:
	case NL80211_ATTR_WIPHY_CHANNEL_TYPE:
	case NL80211_ATTR_CHANNEL_WIDTH:
	case NL80211_ATTR_CENTER_FREQ1:
	case NL80211_ATTR_CENTER_FREQ2:
		return extract_uint32;
	case NL80211_ATTR_FRAME:
		return extract_iovec;
	case NL80211_ATTR_WIPHY_BANDS:
	case NL80211_ATTR_SURVEY_INFO:
	case NL80211_ATTR_KEY:
		return extract_nested;
	case NL80211_ATTR_KEY_IDX:
		return extract_u8;
	default:
		break;
	}

	return NULL;
}

static attr_handler handler_for_survey_info(int type)
{
	switch (type) {
	case NL80211_SURVEY_INFO_NOISE:
		return extract_u8;
	case NL80211_SURVEY_INFO_FREQUENCY:
		return extract_uint32;
	default:
		break;
	}

	return NULL;
}

static attr_handler handler_for_key(int type)
{
	switch (type) {
	case NL80211_KEY_SEQ:
		return extract_iovec;
	default:
		break;
	}

	return NULL;
}

struct attr_entry {
	uint16_t type;
	void *data;
	attr_handler handler;
	bool present : 1;
};

static int parse_attrs(struct l_genl_attr *attr, handler_for_type handler,
			int tag, va_list args)
{
	struct l_queue *entries;
	const struct l_queue_entry *e;
	struct attr_entry *entry;
	uint16_t type;
	uint16_t len;
	const void *data;
	int ret;

	entries = l_queue_new();
	ret = -ENOSYS;

	while (tag != NL80211_ATTR_UNSPEC) {
		entry = l_new(struct attr_entry, 1);

		entry->type = tag;
		entry->data = va_arg(args, void *);
		entry->handler = handler(tag);
		l_queue_push_tail(entries, entry);

		if (!entry->handler)
			goto done;

		tag = va_arg(args, enum nl80211_attrs);
	}

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		for (e = l_queue_get_entries(entries); e; e = e->next) {
			entry = e->data;

			if (entry->type == type)
				break;
		}

		if (!e)
			continue;

		if (entry->present) {
			ret = -EALREADY;
			goto done;
		}

		/* For nested attributes use the outer attribute as data */
		if (entry->handler == extract_nested)
			data = attr;

		if (!entry->handler(data, len, entry->data)) {
			ret = -EINVAL;
			goto done;
		}

		entry->present = true;
	}

	ret = -ENOENT;

	for (e = l_queue_get_entries(entries); e; e = e->next) {
		entry = e->data;

		if (entry->handler == extract_flag) {
			*(bool *) entry->data = entry->present;
			continue;
		}

		if (entry->present)
			continue;

		goto done;
	}

	ret = 0;

done:
	l_queue_destroy(entries, l_free);
	return ret;
}

int nl80211_parse_attrs(struct l_genl_msg *msg, int tag, ...)
{
	struct l_genl_attr attr;
	va_list args;
	int ret;

	if (!l_genl_attr_init(&attr, msg))
		return -EINVAL;

	va_start(args, tag);

	ret = parse_attrs(&attr, handler_for_nl80211, tag, args);

	va_end(args);

	return ret;
}

int nl80211_parse_nested(struct l_genl_attr *attr, int type, int tag, ...)
{
	handler_for_type handler;
	va_list args;
	int ret;

	switch (type) {
	case NL80211_ATTR_SURVEY_INFO:
		handler = handler_for_survey_info;
		break;
	case NL80211_ATTR_KEY:
		handler = handler_for_key;
		break;
	default:
		return -ENOTSUP;
	}

	va_start(args, tag);

	ret = parse_attrs(attr, handler, tag, args);

	va_end(args);

	return ret;
}

struct l_genl_msg *nl80211_build_deauthenticate(uint32_t ifindex,
						const uint8_t addr[static 6],
						uint16_t reason_code)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_DEAUTHENTICATE, 128);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);

	return msg;
}

struct l_genl_msg *nl80211_build_disconnect(uint32_t ifindex,
							uint16_t reason_code)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_DISCONNECT, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);

	return msg;
}

struct l_genl_msg *nl80211_build_del_station(uint32_t ifindex,
						const uint8_t addr[static 6],
						uint16_t reason_code,
						uint8_t subtype)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_DEL_STATION, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MGMT_SUBTYPE, 1, &subtype);
	l_genl_msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);

	return msg;
}

struct l_genl_msg *nl80211_build_new_key_group(uint32_t ifindex, uint32_t cipher,
					uint8_t key_id, const uint8_t *key,
					size_t key_len, const uint8_t *ctr,
					size_t ctr_len, const uint8_t *addr)
{
	struct l_genl_msg *msg;
	uint32_t type = NL80211_KEYTYPE_GROUP;

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_KEY, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);

	if (addr)
		l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY);
	l_genl_msg_append_attr(msg, NL80211_KEY_DATA, key_len, key);
	l_genl_msg_append_attr(msg, NL80211_KEY_CIPHER, 4, &cipher);
	l_genl_msg_append_attr(msg, NL80211_KEY_IDX, 1, &key_id);

	if (ctr)
		l_genl_msg_append_attr(msg, NL80211_KEY_SEQ, ctr_len, ctr);

	l_genl_msg_append_attr(msg, NL80211_KEY_TYPE, 4, &type);
	l_genl_msg_enter_nested(msg, NL80211_KEY_DEFAULT_TYPES);
	l_genl_msg_append_attr(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST,
					0, NULL);
	l_genl_msg_leave_nested(msg);
	l_genl_msg_leave_nested(msg);

	return msg;
}

struct l_genl_msg *nl80211_build_new_key_pairwise(uint32_t ifindex,
						uint32_t cipher,
						const uint8_t addr[static 6],
						const uint8_t *tk,
						size_t tk_len,
						uint8_t key_id)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_KEY, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_DATA, tk_len, tk);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_CIPHER, 4, &cipher);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);

	return msg;
}

struct l_genl_msg *nl80211_build_new_rx_key_pairwise(uint32_t ifindex,
						uint32_t cipher,
						const uint8_t addr[static 6],
						const uint8_t *tk,
						size_t tk_len,
						uint8_t key_id)
{
	uint8_t key_mode = NL80211_KEY_NO_TX;
	uint32_t key_type = NL80211_KEYTYPE_PAIRWISE;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_KEY, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY);

	l_genl_msg_append_attr(msg, NL80211_KEY_DATA, tk_len, tk);
	l_genl_msg_append_attr(msg, NL80211_KEY_CIPHER, 4, &cipher);
	l_genl_msg_append_attr(msg, NL80211_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_KEY_MODE, 1, &key_mode);
	l_genl_msg_append_attr(msg, NL80211_KEY_TYPE, 4, &key_type);

	l_genl_msg_leave_nested(msg);

	return msg;
}

struct l_genl_msg *nl80211_build_rekey_offload(uint32_t ifindex,
						const uint8_t *kek,
						const uint8_t *kck,
						uint64_t replay_ctr)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_REKEY_OFFLOAD, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_REKEY_DATA);
	l_genl_msg_append_attr(msg, NL80211_REKEY_DATA_KEK,
					NL80211_KEK_LEN, kek);
	l_genl_msg_append_attr(msg, NL80211_REKEY_DATA_KCK,
					NL80211_KCK_LEN, kck);
	l_genl_msg_append_attr(msg, NL80211_REKEY_DATA_REPLAY_CTR,
			NL80211_REPLAY_CTR_LEN, &replay_ctr);

	l_genl_msg_leave_nested(msg);

	return msg;
}

static struct l_genl_msg *nl80211_build_set_station(uint32_t ifindex,
					const uint8_t *addr,
					struct nl80211_sta_flag_update *flags)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_STATION, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_FLAGS2,
				sizeof(struct nl80211_sta_flag_update), flags);

	return msg;
}

struct l_genl_msg *nl80211_build_set_station_authorized(uint32_t ifindex,
							const uint8_t *addr)
{
	struct nl80211_sta_flag_update flags = {
		.mask = (1 << NL80211_STA_FLAG_AUTHORIZED),
		.set = (1 << NL80211_STA_FLAG_AUTHORIZED),
	};

	return nl80211_build_set_station(ifindex, addr, &flags);
}

struct l_genl_msg *nl80211_build_set_station_associated(uint32_t ifindex,
							const uint8_t *addr)
{
	struct nl80211_sta_flag_update flags = {
		.mask = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
			(1 << NL80211_STA_FLAG_ASSOCIATED),
		.set = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
			(1 << NL80211_STA_FLAG_ASSOCIATED),
	};

	return nl80211_build_set_station(ifindex, addr, &flags);
}

struct l_genl_msg *nl80211_build_set_station_unauthorized(uint32_t ifindex,
							const uint8_t *addr)
{
	struct nl80211_sta_flag_update flags = {
		.mask = (1 << NL80211_STA_FLAG_AUTHORIZED),
		.set = 0,
	};

	return nl80211_build_set_station(ifindex, addr, &flags);
}

struct l_genl_msg *nl80211_build_set_key(uint32_t ifindex, uint8_t key_index)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_KEY, 128);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY);
	l_genl_msg_append_attr(msg, NL80211_KEY_IDX, 1, &key_index);
	l_genl_msg_append_attr(msg, NL80211_KEY_DEFAULT, 0, NULL);
	l_genl_msg_enter_nested(msg, NL80211_KEY_DEFAULT_TYPES);
	l_genl_msg_append_attr(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST,
				0, NULL);
	l_genl_msg_leave_nested(msg);
	l_genl_msg_leave_nested(msg);

	return msg;
}

struct l_genl_msg *nl80211_build_get_key(uint32_t ifindex, uint8_t key_index)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_GET_KEY, 128);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_index);

	return msg;
}

const void *nl80211_parse_get_key_seq(struct l_genl_msg *msg)
{
	struct l_genl_attr nested;
	struct iovec iov;

	if (l_genl_msg_get_error(msg) < 0 ||
			nl80211_parse_attrs(msg, NL80211_ATTR_KEY, &nested,
						NL80211_ATTR_UNSPEC) < 0) {
		l_error("GET_KEY failed for the GTK: %i",
			l_genl_msg_get_error(msg));
		return NULL;
	}

	if (nl80211_parse_nested(&nested, NL80211_ATTR_KEY, NL80211_KEY_SEQ,
					&iov, NL80211_ATTR_UNSPEC)) {
		l_error("Can't recurse into ATTR_KEY in GET_KEY reply");
		return NULL;
	}

	if (iov.iov_len != 6) {
		l_error("KEY_SEQ length != 6 in GET_KEY reply");
		return NULL;
	}

	return iov.iov_base;
}

struct l_genl_msg *nl80211_build_cmd_frame(uint32_t ifindex,
						uint16_t frame_type,
						const uint8_t *addr,
						const uint8_t *to,
						uint32_t freq,
						struct iovec *iov,
						size_t iov_len)
{
	struct l_genl_msg *msg;
	struct iovec iovs[iov_len + 1];
	uint8_t hdr[24];

	memset(hdr, 0, 24);

	l_put_le16(frame_type, hdr + 0);
	memcpy(hdr + 4, to, 6);
	memcpy(hdr + 10, addr, 6);
	memcpy(hdr + 16, to, 6);

	iovs[0].iov_base = hdr;
	iovs[0].iov_len = sizeof(hdr);
	memcpy(iovs + 1, iov, sizeof(*iov) * iov_len);

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME, 128 + 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &freq);
	l_genl_msg_append_attrv(msg, NL80211_ATTR_FRAME, iovs, iov_len + 1);

	return msg;
}

int nl80211_parse_chandef(struct l_genl_msg *msg, struct band_chandef *out)
{
	struct band_chandef t;

	if (nl80211_parse_attrs(msg,
			NL80211_ATTR_WIPHY_FREQ, &t.frequency,
			NL80211_ATTR_CHANNEL_WIDTH, &t.channel_width,
			NL80211_ATTR_CENTER_FREQ1, &t.center1_frequency,
			NL80211_ATTR_UNSPEC) < 0)
		return -ENOENT;

	t.center2_frequency = 0;

	/* Try to parse CENTER_FREQ2, but it is given only for 80P80 */
	if (t.channel_width == NL80211_CHAN_WIDTH_80P80 &&
			nl80211_parse_attrs(msg,
				NL80211_ATTR_CENTER_FREQ2, &t.center2_frequency,
				NL80211_ATTR_UNSPEC) < 0)
		return -ENOENT;

	memcpy(out, &t, sizeof(t));
	return 0;
}

int nl80211_parse_supported_frequencies(struct l_genl_attr *band_freqs,
					struct scan_freq_set *supported_list,
					struct band_freq_attrs *list,
					size_t num_channels)
{
	uint16_t type, len;
	const void *data;
	struct l_genl_attr attr;
	struct l_genl_attr nested;
	uint8_t channel;

	if (!l_genl_attr_recurse(band_freqs, &nested))
		return -EBADMSG;

	while (l_genl_attr_next(&nested, NULL, NULL, NULL)) {
		uint32_t freq = 0;
		struct band_freq_attrs freq_attr = { 0 };

		if (!l_genl_attr_recurse(&nested, &attr))
			continue;

		while (l_genl_attr_next(&attr, &type, &len, &data)) {
			switch (type) {
			case NL80211_FREQUENCY_ATTR_FREQ:
				freq = *((uint32_t *) data);
				freq_attr.supported = true;
				break;
			case NL80211_FREQUENCY_ATTR_DISABLED:
				freq_attr.disabled = true;
				break;
			case NL80211_FREQUENCY_ATTR_NO_IR:
				freq_attr.no_ir = true;
				break;
			case NL80211_FREQUENCY_ATTR_NO_HT40_MINUS:
				freq_attr.no_ht40_minus = true;
				break;
			case NL80211_FREQUENCY_ATTR_NO_HT40_PLUS:
				freq_attr.no_ht40_plus = true;
				break;
			case NL80211_FREQUENCY_ATTR_NO_80MHZ:
				freq_attr.no_80mhz = true;
				break;
			case NL80211_FREQUENCY_ATTR_NO_160MHZ:
				freq_attr.no_160mhz = true;
				break;
			case NL80211_FREQUENCY_ATTR_NO_HE:
				freq_attr.no_he = true;
				break;
			case NL80211_FREQUENCY_ATTR_MAX_TX_POWER:
				freq_attr.tx_power = *((uint32_t *) data) / 100;
				break;
			}
		}

		if (!freq)
			continue;

		channel = band_freq_to_channel(freq, NULL);
		if (!channel)
			continue;

		if (L_WARN_ON(channel > num_channels))
			continue;

		if (supported_list)
			scan_freq_set_add(supported_list, freq);

		list[channel] = freq_attr;
	}

	return 0;
}

void nl80211_append_rsn_attributes(struct l_genl_msg *msg,
						struct handshake_state *hs)
{
	uint32_t nl_cipher;
	uint32_t nl_akm;
	uint32_t wpa_version;

	nl_cipher = ie_rsn_cipher_suite_to_cipher(hs->pairwise_cipher);
	L_WARN_ON(!nl_cipher);
	l_genl_msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
					4, &nl_cipher);

	nl_cipher = ie_rsn_cipher_suite_to_cipher(hs->group_cipher);
	L_WARN_ON(!nl_cipher);
	l_genl_msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITE_GROUP,
					4, &nl_cipher);

	if (hs->mfp) {
		uint32_t use_mfp = NL80211_MFP_REQUIRED;

		l_genl_msg_append_attr(msg, NL80211_ATTR_USE_MFP, 4, &use_mfp);
	}

	nl_akm = ie_rsn_akm_suite_to_akm(hs->akm_suite);
	L_WARN_ON(!nl_akm);
	l_genl_msg_append_attr(msg, NL80211_ATTR_AKM_SUITES, 4, &nl_akm);

	if (IE_AKM_IS_SAE(hs->akm_suite))
		wpa_version = NL80211_WPA_VERSION_3;
	else if (hs->wpa_ie)
		wpa_version = NL80211_WPA_VERSION_1;
	else
		wpa_version = NL80211_WPA_VERSION_2;

	l_genl_msg_append_attr(msg, NL80211_ATTR_WPA_VERSIONS,
						4, &wpa_version);
}
