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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <fnmatch.h>
#include <unistd.h>
#include <string.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/missing.h"
#include "src/iwd.h"
#include "src/module.h"
#include "src/ie.h"
#include "src/crypto.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/dbus.h"
#include "src/rfkill.h"
#include "src/wiphy.h"
#include "src/storage.h"
#include "src/util.h"
#include "src/common.h"
#include "src/watchlist.h"
#include "src/nl80211util.h"

#define EXT_CAP_LEN 10

static struct l_genl_family *nl80211 = NULL;
static struct l_hwdb *hwdb;
static char **whitelist_filter;
static char **blacklist_filter;
static int mac_randomize_bytes = 6;

struct wiphy {
	uint32_t id;
	char name[20];
	uint8_t permanent_addr[ETH_ALEN];
	uint32_t feature_flags;
	uint8_t ext_features[(NUM_NL80211_EXT_FEATURES + 7) / 8];
	uint8_t max_num_ssids_per_scan;
	uint32_t max_roc_duration;
	uint16_t max_scan_ie_len;
	uint16_t supported_iftypes;
	uint16_t supported_ciphers;
	struct scan_freq_set *supported_freqs;
	char *model_str;
	char *vendor_str;
	char *driver_str;
	struct watchlist state_watches;
	uint8_t extended_capabilities[EXT_CAP_LEN + 2]; /* max bitmap size + IE header */
	uint8_t *iftype_extended_capabilities[NUM_NL80211_IFTYPES];
	uint8_t *supported_rates[NUM_NL80211_BANDS];
	uint8_t rm_enabled_capabilities[7]; /* 5 size max + header */

	bool support_scheduled_scan:1;
	bool support_rekey_offload:1;
	bool support_adhoc_rsn:1;
	bool support_qos_set_map:1;
	bool soft_rfkill : 1;
	bool hard_rfkill : 1;
	bool offchannel_tx_ok : 1;
	bool blacklisted : 1;
	bool registered : 1;
};

static struct l_queue *wiphy_list = NULL;

enum ie_rsn_cipher_suite wiphy_select_cipher(struct wiphy *wiphy, uint16_t mask)
{
	if (mask == IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC)
		return IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC;

	mask &= wiphy->supported_ciphers;

	/* CCMP is our first choice, TKIP second */
	if (mask & IE_RSN_CIPHER_SUITE_CCMP)
		return IE_RSN_CIPHER_SUITE_CCMP;

	if (mask & IE_RSN_CIPHER_SUITE_TKIP)
		return IE_RSN_CIPHER_SUITE_TKIP;

	if (mask & IE_RSN_CIPHER_SUITE_BIP)
		return IE_RSN_CIPHER_SUITE_BIP;

	return 0;
}

enum ie_rsn_akm_suite wiphy_select_akm(struct wiphy *wiphy,
					struct scan_bss *bss,
					bool fils_capable_hint)
{
	struct ie_rsn_info info;
	enum security security;

	memset(&info, 0, sizeof(info));
	scan_bss_get_rsn_info(bss, &info);

	security = security_determine(bss->capability, &info);

	/*
	 * If FT is available, use FT authentication to keep the door open
	 * for fast transitions.  Otherwise use SHA256 version if present.
	 */
	if (security == SECURITY_8021X) {
		if (wiphy_has_feature(wiphy, NL80211_EXT_FEATURE_FILS_STA) &&
				fils_capable_hint) {
			if ((info.akm_suites &
					IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384) &&
					bss->rsne && bss->mde_present)
				return IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384;

			if ((info.akm_suites &
					IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256) &&
					bss->rsne && bss->mde_present)
				return IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256;

			if (info.akm_suites & IE_RSN_AKM_SUITE_FILS_SHA384)
				return IE_RSN_AKM_SUITE_FILS_SHA384;

			if (info.akm_suites & IE_RSN_AKM_SUITE_FILS_SHA256)
				return IE_RSN_AKM_SUITE_FILS_SHA256;
		}

		if ((info.akm_suites & IE_RSN_AKM_SUITE_FT_OVER_8021X) &&
				bss->rsne && bss->mde_present)
			return IE_RSN_AKM_SUITE_FT_OVER_8021X;

		if (info.akm_suites & IE_RSN_AKM_SUITE_8021X_SHA256)
			return IE_RSN_AKM_SUITE_8021X_SHA256;

		if (info.akm_suites & IE_RSN_AKM_SUITE_8021X)
			return IE_RSN_AKM_SUITE_8021X;
	} else if (security == SECURITY_PSK) {
		/*
		 * Prefer connecting to SAE/WPA3 network, but only if SAE is
		 * supported, we are MFP capable, and the AP has set the MFPR
		 * bit. If any of these conditions are not met, we can fallback
		 * to WPA2 (if the AKM is present).
		 */
		if (wiphy->supported_ciphers & IE_RSN_CIPHER_SUITE_BIP &&
				wiphy_has_feature(wiphy, NL80211_FEATURE_SAE) &&
				info.mfpr) {
			if (info.akm_suites &
					IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256)
				return IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256;

			if (info.akm_suites & IE_RSN_AKM_SUITE_SAE_SHA256)
				return IE_RSN_AKM_SUITE_SAE_SHA256;
		}

		if ((info.akm_suites & IE_RSN_AKM_SUITE_FT_USING_PSK) &&
				bss->rsne && bss->mde_present)
			return IE_RSN_AKM_SUITE_FT_USING_PSK;

		if (info.akm_suites & IE_RSN_AKM_SUITE_PSK_SHA256)
			return IE_RSN_AKM_SUITE_PSK_SHA256;

		if (info.akm_suites & IE_RSN_AKM_SUITE_PSK)
			return IE_RSN_AKM_SUITE_PSK;
	} else if (security == SECURITY_NONE) {
		if (info.akm_suites & IE_RSN_AKM_SUITE_OWE)
			return IE_RSN_AKM_SUITE_OWE;
	}

	return 0;
}

static struct wiphy *wiphy_new(uint32_t id)
{
	struct wiphy *wiphy = l_new(struct wiphy, 1);

	wiphy->id = id;
	wiphy->supported_freqs = scan_freq_set_new();
	watchlist_init(&wiphy->state_watches, NULL);
	wiphy->extended_capabilities[0] = IE_TYPE_EXTENDED_CAPABILITIES;
	wiphy->extended_capabilities[1] = EXT_CAP_LEN;

	return wiphy;
}

static void wiphy_free(void *data)
{
	struct wiphy *wiphy = data;
	uint32_t i;

	l_debug("Freeing wiphy %s[%u]", wiphy->name, wiphy->id);

	for (i = 0; i < NUM_NL80211_IFTYPES; i++)
		l_free(wiphy->iftype_extended_capabilities[i]);

	for (i = 0; i < NUM_NL80211_BANDS; i++)
		l_free(wiphy->supported_rates[i]);

	scan_freq_set_free(wiphy->supported_freqs);
	watchlist_destroy(&wiphy->state_watches);
	l_free(wiphy->model_str);
	l_free(wiphy->vendor_str);
	l_free(wiphy->driver_str);
	l_free(wiphy);
}

static bool wiphy_match(const void *a, const void *b)
{
	const struct wiphy *wiphy = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return (wiphy->id == id);
}

struct wiphy *wiphy_find(int wiphy_id)
{
	return l_queue_find(wiphy_list, wiphy_match, L_UINT_TO_PTR(wiphy_id));
}

bool wiphy_is_blacklisted(const struct wiphy *wiphy)
{
	return wiphy->blacklisted;
}

static bool wiphy_is_managed(const char *phy)
{
	char *pattern;
	unsigned int i;

	if (!whitelist_filter)
		goto check_blacklist;

	for (i = 0; (pattern = whitelist_filter[i]); i++) {
		if (fnmatch(pattern, phy, 0) != 0)
			continue;

		goto check_blacklist;
	}

	l_debug("whitelist filtered phy: %s", phy);
	return false;

check_blacklist:
	if (!blacklist_filter)
		return true;

	for (i = 0; (pattern = blacklist_filter[i]); i++) {
		if (fnmatch(pattern, phy, 0) == 0) {
			l_debug("blacklist filtered ifname: %s", phy);
			return false;
		}
	}

	return true;
}

const char *wiphy_get_path(struct wiphy *wiphy)
{
	static char path[256];

	L_WARN_ON(snprintf(path, sizeof(path), "%s/%d", IWD_BASE_PATH,
				wiphy->id) >= (int) sizeof(path));
	path[sizeof(path) - 1] = '\0';

	return path;
}

uint32_t wiphy_get_id(struct wiphy *wiphy)
{
	return wiphy->id;
}

uint32_t wiphy_get_supported_bands(struct wiphy *wiphy)
{
	if (!wiphy->supported_freqs)
		return 0;

	return scan_freq_set_get_bands(wiphy->supported_freqs);
}

const struct scan_freq_set *wiphy_get_supported_freqs(
						const struct wiphy *wiphy)
{
	return wiphy->supported_freqs;
}

bool wiphy_can_connect(struct wiphy *wiphy, struct scan_bss *bss)
{
	struct ie_rsn_info rsn_info;
	int r;

	memset(&rsn_info, 0, sizeof(rsn_info));
	r = scan_bss_get_rsn_info(bss, &rsn_info);

	if (r == 0) {
		if (!wiphy_select_cipher(wiphy, rsn_info.pairwise_ciphers))
			return false;

		if (!wiphy_select_cipher(wiphy, rsn_info.group_cipher))
			return false;

		if (rsn_info.mfpr && !wiphy_select_cipher(wiphy,
					rsn_info.group_management_cipher))
			return false;

		/*
		 * if the AP ONLY supports SAE/WPA3, then we can only connect
		 * if the wiphy feature is supported. Otherwise the AP may list
		 * SAE as one of the AKM's but also support PSK (hybrid). In
		 * this case we still want to allow a connection even if SAE
		 * is not supported.
		 */
		if (IE_AKM_IS_SAE(rsn_info.akm_suites) &&
				!wiphy_has_feature(wiphy, NL80211_FEATURE_SAE))
			return false;
	} else if (r != -ENOENT)
		return false;

	return true;
}

bool wiphy_has_feature(struct wiphy *wiphy, uint32_t feature)
{
	return wiphy->feature_flags & feature;
}

bool wiphy_can_randomize_mac_addr(struct wiphy *wiphy)
{
	return wiphy_has_feature(wiphy, NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR);
}

bool wiphy_rrm_capable(struct wiphy *wiphy)
{
	if (wiphy_has_feature(wiphy,
				NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES) &&
			wiphy_has_feature(wiphy, NL80211_FEATURE_QUIET))
		return true;

	if (wiphy_has_ext_feature(wiphy, NL80211_EXT_FEATURE_RRM))
		return true;

	return false;
}

bool wiphy_has_ext_feature(struct wiphy *wiphy, uint32_t feature)
{
	return feature < sizeof(wiphy->ext_features) * 8 &&
		util_is_bit_set(wiphy->ext_features[feature >> 3], feature & 7);
}

uint8_t wiphy_get_max_num_ssids_per_scan(struct wiphy *wiphy)
{
	return wiphy->max_num_ssids_per_scan;
}

uint16_t wiphy_get_max_scan_ie_len(struct wiphy *wiphy)
{
	return wiphy->max_scan_ie_len;
}

uint32_t wiphy_get_max_roc_duration(struct wiphy *wiphy)
{
	return wiphy->max_roc_duration;
}

bool wiphy_supports_adhoc_rsn(struct wiphy *wiphy)
{
	return wiphy->support_adhoc_rsn;
}

bool wiphy_can_offchannel_tx(struct wiphy *wiphy)
{
	return wiphy->offchannel_tx_ok;
}

bool wiphy_supports_qos_set_map(struct wiphy *wiphy)
{
	return wiphy->support_qos_set_map;
}

const char *wiphy_get_driver(struct wiphy *wiphy)
{
	return wiphy->driver_str;
}

const char *wiphy_get_name(struct wiphy *wiphy)
{
	return wiphy->name;
}

const uint8_t *wiphy_get_permanent_address(struct wiphy *wiphy)
{
	return wiphy->permanent_addr;
}

const uint8_t *wiphy_get_extended_capabilities(struct wiphy *wiphy,
							uint32_t iftype)
{
	if (wiphy->iftype_extended_capabilities[iftype])
		return wiphy->iftype_extended_capabilities[iftype];

	return wiphy->extended_capabilities;
}

const uint8_t *wiphy_get_rm_enabled_capabilities(struct wiphy *wiphy)
{
	if (!wiphy_rrm_capable(wiphy))
		return NULL;

	return wiphy->rm_enabled_capabilities;
}

static void wiphy_address_constrain(struct wiphy *wiphy, uint8_t addr[static 6])
{
	switch (mac_randomize_bytes) {
	case 6:
		/* Set the locally administered bit */
		addr[0] |= 0x2;

		/* Reset multicast bit */
		addr[0] &= 0xfe;
		break;
	case 3:
		memcpy(addr, wiphy->permanent_addr, 3);
		break;
	}

	/*
	 * Constrain the last NIC byte to 0x00 .. 0xfe, otherwise we might be
	 * able to generate an address of 0xff 0xff 0xff which might be
	 * interpreted as a vendor broadcast.  Similarly, 0x00 0x00 0x00 is
	 * also not valid
	 */
	addr[5] &= 0xfe;
	if (util_mem_is_zero(addr + 3, 3))
		addr[5] = 0x01;
}

void wiphy_generate_random_address(struct wiphy *wiphy, uint8_t addr[static 6])
{
	switch (mac_randomize_bytes) {
	case 6:
		l_getrandom(addr, 6);
		break;
	case 3:
		l_getrandom(addr + 3, 3);
		break;
	}

	wiphy_address_constrain(wiphy, addr);
}

void wiphy_generate_address_from_ssid(struct wiphy *wiphy, const char *ssid,
					uint8_t addr[static 6])
{
	struct l_checksum *sha = l_checksum_new(L_CHECKSUM_SHA256);

	l_checksum_update(sha, ssid, strlen(ssid));
	l_checksum_update(sha, wiphy->permanent_addr,
				sizeof(wiphy->permanent_addr));
	l_checksum_get_digest(sha, addr, mac_randomize_bytes);

	l_checksum_free(sha);

	wiphy_address_constrain(wiphy, addr);
}

bool wiphy_constrain_freq_set(const struct wiphy *wiphy,
						struct scan_freq_set *set)
{
	scan_freq_set_constrain(set, wiphy->supported_freqs);

	if (!scan_freq_set_get_bands(set))
		/* The set is empty. */
		return false;

	return true;
}

static char **wiphy_get_supported_iftypes(struct wiphy *wiphy, uint16_t mask)
{
	uint16_t supported_mask = wiphy->supported_iftypes & mask;
	char **ret = l_new(char *, __builtin_popcount(supported_mask) + 1);
	unsigned int i;
	unsigned int j;

	for (j = 0, i = 0; i < sizeof(supported_mask) * 8; i++) {
		const char *str;

		if (!(supported_mask & (1 << i)))
			continue;

		str = dbus_iftype_to_string(i + 1);
		if (str)
			ret[j++] = l_strdup(str);
	}

	return ret;
}

bool wiphy_supports_iftype(struct wiphy *wiphy, uint32_t iftype)
{
	if (iftype > sizeof(wiphy->supported_iftypes) * 8)
		return false;

	return wiphy->supported_iftypes & (1 << (iftype - 1));
}

const uint8_t *wiphy_get_supported_rates(struct wiphy *wiphy, unsigned int band,
						unsigned int *out_num)
{
	if (band >= L_ARRAY_SIZE(wiphy->supported_rates))
		return NULL;

	if (out_num)
		*out_num =
			(uint8_t *) rawmemchr(wiphy->supported_rates[band], 0) -
			wiphy->supported_rates[band];

	return wiphy->supported_rates[band];
}

uint32_t wiphy_state_watch_add(struct wiphy *wiphy,
				wiphy_state_watch_func_t func,
				void *user_data, wiphy_destroy_func_t destroy)
{
	return watchlist_add(&wiphy->state_watches, func, user_data, destroy);
}

bool wiphy_state_watch_remove(struct wiphy *wiphy, uint32_t id)
{
	return watchlist_remove(&wiphy->state_watches, id);
}

static void wiphy_print_basic_info(struct wiphy *wiphy)
{
	uint32_t bands;
	char buf[1024];

	l_info("Wiphy: %d, Name: %s", wiphy->id, wiphy->name);
	l_info("\tPermanent Address: "MAC, MAC_STR(wiphy->permanent_addr));

	bands = scan_freq_set_get_bands(wiphy->supported_freqs);

	if (bands) {
		int len = 0;

		len += sprintf(buf + len, "\tBands:");

		if (bands & SCAN_BAND_2_4_GHZ)
			len += sprintf(buf + len, " 2.4 GHz");

		if (bands & SCAN_BAND_5_GHZ)
			len += sprintf(buf + len, " 5 GHz");

		l_info("%s", buf);
	}

	if (wiphy->supported_ciphers) {
		int len = 0;

		len += sprintf(buf + len, "\tCiphers:");

		if (wiphy->supported_ciphers & IE_RSN_CIPHER_SUITE_CCMP)
			len += sprintf(buf + len, " CCMP");

		if (wiphy->supported_ciphers & IE_RSN_CIPHER_SUITE_TKIP)
			len += sprintf(buf + len, " TKIP");

		if (wiphy->supported_ciphers & IE_RSN_CIPHER_SUITE_BIP)
			len += sprintf(buf + len, " BIP");

		l_info("%s", buf);
	}

	if (wiphy->supported_iftypes) {
		char **iftypes = wiphy_get_supported_iftypes(wiphy, ~0);
		char *joined = l_strjoinv(iftypes, ' ');

		l_info("\tSupported iftypes: %s", joined);

		l_free(joined);
		l_strfreev(iftypes);
	}
}

static void parse_supported_commands(struct wiphy *wiphy,
						struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		uint32_t cmd = *(uint32_t *)data;

		switch (cmd) {
		case NL80211_CMD_START_SCHED_SCAN:
			wiphy->support_scheduled_scan = true;
			break;
		case NL80211_CMD_SET_REKEY_OFFLOAD:
			wiphy->support_rekey_offload = true;
			break;
		case NL80211_CMD_SET_QOS_MAP:
			wiphy->support_qos_set_map = true;
			break;
		}
	}
}

static void parse_supported_ciphers(struct wiphy *wiphy, const void *data,
						uint16_t len)
{
	while (len >= 4) {
		uint32_t cipher = *(uint32_t *)data;

		switch (cipher) {
		case CRYPTO_CIPHER_CCMP:
			wiphy->supported_ciphers |= IE_RSN_CIPHER_SUITE_CCMP;
			break;
		case CRYPTO_CIPHER_TKIP:
			wiphy->supported_ciphers |= IE_RSN_CIPHER_SUITE_TKIP;
			break;
		case CRYPTO_CIPHER_WEP40:
			wiphy->supported_ciphers |= IE_RSN_CIPHER_SUITE_WEP40;
			break;
		case CRYPTO_CIPHER_WEP104:
			wiphy->supported_ciphers |= IE_RSN_CIPHER_SUITE_WEP104;
			break;
		case CRYPTO_CIPHER_BIP:
			wiphy->supported_ciphers |= IE_RSN_CIPHER_SUITE_BIP;
			break;
		default:	/* TODO: Support other ciphers */
			break;
		}

		len -= 4;
		data += 4;
	}
}

static void parse_supported_frequencies(struct wiphy *wiphy,
						struct l_genl_attr *freqs)
{
	uint16_t type, len;
	const void *data;
	struct l_genl_attr attr;

	l_debug("");

	while (l_genl_attr_next(freqs, NULL, NULL, NULL)) {
		if (!l_genl_attr_recurse(freqs, &attr))
			continue;

		while (l_genl_attr_next(&attr, &type, &len, &data)) {
			uint32_t u32;

			switch (type) {
			case NL80211_FREQUENCY_ATTR_FREQ:
				u32 = *((uint32_t *) data);
				scan_freq_set_add(wiphy->supported_freqs, u32);
				break;
			}
		}
	}
}

static uint8_t *parse_supported_rates(struct l_genl_attr *attr)
{
	uint16_t type;
	uint16_t len;
	const void *data;
	struct l_genl_attr nested;
	int count = 0;
	uint8_t *ret;

	if (!l_genl_attr_recurse(attr, &nested))
		return NULL;

	while (l_genl_attr_next(&nested, NULL, NULL, NULL))
		count++;

	if (!l_genl_attr_recurse(attr, &nested))
		return NULL;

	ret = l_malloc(count + 1);
	ret[count] = 0;

	count = 0;

	while (l_genl_attr_next(&nested, NULL, NULL, NULL)) {
		struct l_genl_attr nested2;

		if (!l_genl_attr_recurse(&nested, &nested2)) {
			l_free(ret);
			return NULL;
		}

		while (l_genl_attr_next(&nested2, &type, &len, &data)) {
			if (type != NL80211_BITRATE_ATTR_RATE || len != 4)
				continue;

			/*
			 * Convert from the 100kb/s units reported by the
			 * kernel to the 500kb/s used in 802.11 IEs.
			 */
			ret[count++] = *(const uint32_t *) data / 5;
		}
	}

	return ret;
}

static void parse_supported_bands(struct wiphy *wiphy,
						struct l_genl_attr *bands)
{
	uint16_t type;
	struct l_genl_attr attr;

	l_debug("");

	while (l_genl_attr_next(bands, &type, NULL, NULL)) {
		enum nl80211_band band = type;

		if (band != NL80211_BAND_2GHZ && band != NL80211_BAND_5GHZ)
			continue;

		if (!l_genl_attr_recurse(bands, &attr))
			continue;

		while (l_genl_attr_next(&attr, &type, NULL, NULL)) {
			struct l_genl_attr freqs;

			switch (type) {
			case NL80211_BAND_ATTR_FREQS:
				if (!l_genl_attr_recurse(&attr, &freqs))
					continue;

				parse_supported_frequencies(wiphy, &freqs);
				break;

			case NL80211_BAND_ATTR_RATES:
				if (wiphy->supported_rates[band])
					continue;

				wiphy->supported_rates[band] =
					parse_supported_rates(&attr);
				break;
			}
		}
	}
}

static void parse_supported_iftypes(struct wiphy *wiphy,
						struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		/*
		 * NL80211_IFTYPE_UNSPECIFIED can be ignored, so we start
		 * at the first bit
		 */
		if (type > sizeof(wiphy->supported_iftypes) * 8) {
			l_warn("unsupported iftype: %u", type);
			continue;
		}

		wiphy->supported_iftypes |= 1 << (type - 1);
	}
}

static void parse_iftype_extended_capabilities(struct wiphy *wiphy,
						struct l_genl_attr *attr)
{
	uint16_t type;
	uint16_t len;
	const void *data;
	struct l_genl_attr nested;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		uint32_t iftype;

		if (!l_genl_attr_recurse(attr, &nested))
			continue;

		if (!l_genl_attr_next(&nested, &type, &len, &data))
			continue;

		if (type != NL80211_ATTR_IFTYPE)
			continue;

		iftype = l_get_u32(data);

		if (!l_genl_attr_next(&nested, &type, &len, &data))
			continue;

		if (type != NL80211_ATTR_EXT_CAPA)
			continue;

		wiphy->iftype_extended_capabilities[iftype] =
					l_new(uint8_t, EXT_CAP_LEN + 2);
		wiphy->iftype_extended_capabilities[iftype][0] =
					IE_TYPE_EXTENDED_CAPABILITIES;
		wiphy->iftype_extended_capabilities[iftype][1] =
					EXT_CAP_LEN;
		memcpy(wiphy->iftype_extended_capabilities[iftype] + 2,
				data, minsize(len, EXT_CAP_LEN));
	}
}

static void wiphy_parse_attributes(struct wiphy *wiphy,
					struct l_genl_msg *msg)
{
	struct l_genl_attr attr;
	struct l_genl_attr nested;
	uint16_t type, len;
	const void *data;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_FEATURE_FLAGS:
			if (len != sizeof(uint32_t))
				l_warn("Invalid feature flags attribute");
			else
				wiphy->feature_flags = *((uint32_t *) data);

			break;
		case NL80211_ATTR_EXT_FEATURES:
			if (len > sizeof(wiphy->ext_features))
				len = sizeof(wiphy->ext_features);

			memcpy(wiphy->ext_features, data, len);
			break;
		case NL80211_ATTR_SUPPORTED_COMMANDS:
			if (l_genl_attr_recurse(&attr, &nested))
				parse_supported_commands(wiphy, &nested);

			break;
		case NL80211_ATTR_CIPHER_SUITES:
			parse_supported_ciphers(wiphy, data, len);
			break;
		case NL80211_ATTR_WIPHY_BANDS:
			if (l_genl_attr_recurse(&attr, &nested))
				parse_supported_bands(wiphy, &nested);

			break;
		case NL80211_ATTR_MAX_NUM_SCAN_SSIDS:
			if (len != sizeof(uint8_t))
				l_warn("Invalid MAX_NUM_SCAN_SSIDS attribute");
			else
				wiphy->max_num_ssids_per_scan =
							*((uint8_t *) data);
			break;
		case NL80211_ATTR_MAX_SCAN_IE_LEN:
			if (len != sizeof(uint16_t))
				l_warn("Invalid MAX_SCAN_IE_LEN attribute");
			else
				wiphy->max_scan_ie_len = *((uint16_t *) data);
			break;
		case NL80211_ATTR_SUPPORT_IBSS_RSN:
			wiphy->support_adhoc_rsn = true;
			break;
		case NL80211_ATTR_SUPPORTED_IFTYPES:
			if (l_genl_attr_recurse(&attr, &nested))
				parse_supported_iftypes(wiphy, &nested);
			break;
		case NL80211_ATTR_OFFCHANNEL_TX_OK:
			wiphy->offchannel_tx_ok = true;
			break;
		case NL80211_ATTR_EXT_CAPA:
			memcpy(wiphy->extended_capabilities + 2,
				data, minsize(EXT_CAP_LEN, len));
			break;
		case NL80211_ATTR_IFTYPE_EXT_CAPA:
			if (!l_genl_attr_recurse(&attr, &nested))
				break;

			parse_iftype_extended_capabilities(wiphy, &nested);
			break;
		case NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION:
			if (len != 4)
				l_warn("Invalid MAX_ROC_DURATION attribute");
			else
				wiphy->max_roc_duration = *((uint32_t *) data);
			break;
		}
	}
}

static bool wiphy_get_driver_name(struct wiphy *wiphy)
{
	L_AUTO_FREE_VAR(char *, driver_link) = NULL;
	char driver_path[256];
	ssize_t len;

	driver_link = l_strdup_printf("/sys/class/ieee80211/%s/device/driver",
					wiphy->name);
	len = readlink(driver_link, driver_path, sizeof(driver_path) - 1);

	if (len == -1) {
		l_error("Can't read %s: %s", driver_link, strerror(errno));
		return false;
	}

	driver_path[len] = '\0';
	wiphy->driver_str = l_strdup(basename(driver_path));
	return true;
}

static int wiphy_get_permanent_addr_from_sysfs(struct wiphy *wiphy)
{
	char addr[32];
	ssize_t len;

	len = read_file(addr, sizeof(addr),
				"/sys/class/ieee80211/%s/macaddress",
				wiphy->name);
	if (len != 18) {
		if (len < 0)
			return -errno;
		return -EINVAL;
	}

	/* Sysfs appends a \n at the end, strip it */
	addr[17] = '\0';

	if (!util_string_to_address(addr, wiphy->permanent_addr))
		return -EINVAL;

	return 0;
}

static void wiphy_register(struct wiphy *wiphy)
{
	struct l_dbus *dbus = dbus_get_bus();

	wiphy->soft_rfkill = rfkill_get_soft_state(wiphy->id);
	wiphy->hard_rfkill = rfkill_get_hard_state(wiphy->id);

	if (hwdb) {
		char modalias[128];
		ssize_t len;
		struct l_hwdb_entry *entries = NULL, *kv;

		len = read_file(modalias, sizeof(modalias) - 1,
				"/sys/class/ieee80211/%s/device/modalias",
				wiphy->name);

		if (len > 0) {
			modalias[len] = '\0';
			entries = l_hwdb_lookup(hwdb, "%s", modalias);
		}

		for (kv = entries; kv; kv = kv->next) {
			if (!strcmp(kv->key, "ID_MODEL_FROM_DATABASE")) {
				if (wiphy->model_str)
					continue;

				wiphy->model_str = l_strdup(kv->value);
			}

			if (!strcmp(kv->key, "ID_VENDOR_FROM_DATABASE")) {
				if (wiphy->vendor_str)
					continue;

				wiphy->vendor_str = l_strdup(kv->value);
			}
		}

		l_hwdb_lookup_free(entries);
	}

	wiphy_get_driver_name(wiphy);

	if (!l_dbus_object_add_interface(dbus, wiphy_get_path(wiphy),
					IWD_WIPHY_INTERFACE, wiphy))
		l_info("Unable to add the %s interface to %s",
				IWD_WIPHY_INTERFACE, wiphy_get_path(wiphy));

	if (!l_dbus_object_add_interface(dbus, wiphy_get_path(wiphy),
					L_DBUS_INTERFACE_PROPERTIES, NULL))
		l_info("Unable to add the %s interface to %s",
				L_DBUS_INTERFACE_PROPERTIES,
				wiphy_get_path(wiphy));

	wiphy->registered = true;
}

struct wiphy *wiphy_create(uint32_t wiphy_id, const char *name)
{
	struct wiphy *wiphy;

	wiphy = wiphy_new(wiphy_id);
	l_strlcpy(wiphy->name, name, sizeof(wiphy->name));
	l_queue_push_head(wiphy_list, wiphy);

	if (!wiphy_is_managed(name))
		wiphy->blacklisted = true;

	return wiphy;
}

void wiphy_update_from_genl(struct wiphy *wiphy, struct l_genl_msg *msg)
{
	if (wiphy->blacklisted)
		return;

	l_debug("");

	wiphy_parse_attributes(wiphy, msg);
}

void wiphy_update_name(struct wiphy *wiphy, const char *name)
{
	bool updated = false;

	if (strncmp(wiphy->name, name, sizeof(wiphy->name))) {
		l_strlcpy(wiphy->name, name, sizeof(wiphy->name));
		updated = true;
	}

	if (updated && wiphy->registered) {
		struct l_dbus *dbus = dbus_get_bus();

		l_dbus_property_changed(dbus, wiphy_get_path(wiphy),
					IWD_WIPHY_INTERFACE, "Name");
	}
}

static void wiphy_set_station_capability_bits(struct wiphy *wiphy)
{
	uint8_t *ext_capa;
	bool anqp_disabled;

	/* No per-type capabilities exist for station, just copy the global */
	if (!wiphy->iftype_extended_capabilities[NL80211_IFTYPE_STATION]) {
		wiphy->iftype_extended_capabilities[NL80211_IFTYPE_STATION] =
					l_new(uint8_t, EXT_CAP_LEN + 2);

		memcpy(wiphy->iftype_extended_capabilities[
						NL80211_IFTYPE_STATION],
						wiphy->extended_capabilities,
						EXT_CAP_LEN + 2);
	}

	ext_capa = wiphy->iftype_extended_capabilities[NL80211_IFTYPE_STATION];

	if (!l_settings_get_bool(iwd_get_config(), "General", "DisableANQP",
				&anqp_disabled))
		anqp_disabled = true;

	/* Set BSS Transition Management */
	util_set_bit(ext_capa + 2, 19);

	/* Set Interworking */
	if (!anqp_disabled)
		util_set_bit(ext_capa + 2, 31);

	/* Set QoS Map */
	if (wiphy->support_qos_set_map)
		util_set_bit(ext_capa + 2, 32);

	/* Set FILS */
	util_set_bit(ext_capa + 2, 72);
}

static void wiphy_setup_rm_enabled_capabilities(struct wiphy *wiphy)
{
	/* Nothing to do */
	if (!wiphy_rrm_capable(wiphy))
		return;

	wiphy->rm_enabled_capabilities[0] = IE_TYPE_RM_ENABLED_CAPABILITIES;
	wiphy->rm_enabled_capabilities[1] = 5;
	/* Bits: Passive (4), Active (5), and Beacon Table (6) capabilities */
	wiphy->rm_enabled_capabilities[2] = 0x70;

	/*
	 * TODO: Support at least Link Measurement if TX_POWER_INSERTION is
	 * available
	 */
}

void wiphy_create_complete(struct wiphy *wiphy)
{
	wiphy_register(wiphy);

	if (util_mem_is_zero(wiphy->permanent_addr, 6)) {
		int err = wiphy_get_permanent_addr_from_sysfs(wiphy);

		if (err < 0)
			l_error("Can't read sysfs maccaddr for %s: %s",
					wiphy->name, strerror(-err));
	}

	wiphy_set_station_capability_bits(wiphy);
	wiphy_setup_rm_enabled_capabilities(wiphy);

	wiphy_print_basic_info(wiphy);
}

bool wiphy_destroy(struct wiphy *wiphy)
{
	l_debug("");

	if (!l_queue_remove(wiphy_list, wiphy))
		return false;

	if (wiphy->registered)
		l_dbus_unregister_object(dbus_get_bus(), wiphy_get_path(wiphy));

	wiphy_free(wiphy);
	return true;
}

static void wiphy_rfkill_cb(unsigned int wiphy_id, bool soft, bool hard,
				void *user_data)
{
	struct wiphy *wiphy = wiphy_find(wiphy_id);
	struct l_dbus *dbus = dbus_get_bus();
	bool old_powered, new_powered;
	enum wiphy_state_watch_event event;

	if (!wiphy)
		return;

	old_powered = !wiphy->soft_rfkill && !wiphy->hard_rfkill;

	wiphy->soft_rfkill = soft;
	wiphy->hard_rfkill = hard;

	new_powered = !wiphy->soft_rfkill && !wiphy->hard_rfkill;

	if (old_powered == new_powered)
		return;

	event = new_powered ? WIPHY_STATE_WATCH_EVENT_POWERED :
				WIPHY_STATE_WATCH_EVENT_RFKILLED;
	WATCHLIST_NOTIFY(&wiphy->state_watches, wiphy_state_watch_func_t,
				wiphy, event);

	l_dbus_property_changed(dbus, wiphy_get_path(wiphy),
					IWD_WIPHY_INTERFACE, "Powered");
}

static bool wiphy_property_get_powered(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct wiphy *wiphy = user_data;
	bool value = !wiphy->soft_rfkill && !wiphy->hard_rfkill;

	l_dbus_message_builder_append_basic(builder, 'b', &value);

	return true;
}

static struct l_dbus_message *wiphy_property_set_powered(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct wiphy *wiphy = user_data;
	bool old_powered, new_powered;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &new_powered))
		return dbus_error_invalid_args(message);

	old_powered = !wiphy->soft_rfkill && !wiphy->hard_rfkill;

	if (old_powered == new_powered)
		goto done;

	if (wiphy->hard_rfkill)
		return dbus_error_not_available(message);

	if (!rfkill_set_soft_state(wiphy->id, !new_powered))
		return dbus_error_failed(message);

done:
	complete(dbus, message, NULL);

	return NULL;
}

static bool wiphy_property_get_model(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct wiphy *wiphy = user_data;

	if (!wiphy->model_str)
		return false;

	l_dbus_message_builder_append_basic(builder, 's', wiphy->model_str);

	return true;
}

static bool wiphy_property_get_vendor(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct wiphy *wiphy = user_data;

	if (!wiphy->vendor_str)
		return false;

	l_dbus_message_builder_append_basic(builder, 's', wiphy->vendor_str);

	return true;
}

static bool wiphy_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct wiphy *wiphy = user_data;
	char buf[20];

	if (l_utf8_validate(wiphy->name, strlen(wiphy->name), NULL)) {
		l_dbus_message_builder_append_basic(builder, 's', wiphy->name);
		return true;
	}

	/*
	 * In the highly unlikely scenario that the wiphy name is not utf8,
	 * we simply use the canonical name phy<index>.  The kernel guarantees
	 * that this name cannot be taken by any other wiphy, so this should
	 * be safe enough.
	 */
	sprintf(buf, "phy%d", wiphy->id);
	l_dbus_message_builder_append_basic(builder, 's', buf);

	return true;
}

#define WIPHY_MODE_MASK	( \
	(1 << (NL80211_IFTYPE_STATION - 1)) | \
	(1 << (NL80211_IFTYPE_AP - 1)) | \
	(1 << (NL80211_IFTYPE_ADHOC - 1)))

static bool wiphy_property_get_supported_modes(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct wiphy *wiphy = user_data;
	unsigned int j = 0;
	char **iftypes = wiphy_get_supported_iftypes(wiphy, WIPHY_MODE_MASK);

	l_dbus_message_builder_enter_array(builder, "s");

	while (iftypes[j])
		l_dbus_message_builder_append_basic(builder, 's', iftypes[j++]);

	l_dbus_message_builder_leave_array(builder);
	l_strfreev(iftypes);

	return true;
}

static void setup_wiphy_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, "Powered", 0, "b",
					wiphy_property_get_powered,
					wiphy_property_set_powered);
	l_dbus_interface_property(interface, "Model", 0, "s",
					wiphy_property_get_model, NULL);
	l_dbus_interface_property(interface, "Vendor", 0, "s",
					wiphy_property_get_vendor, NULL);
	l_dbus_interface_property(interface, "Name", 0, "s",
					wiphy_property_get_name, NULL);
	l_dbus_interface_property(interface, "SupportedModes", 0, "as",
					wiphy_property_get_supported_modes,
					NULL);
}

static int wiphy_init(void)
{
	struct l_genl *genl = iwd_get_genl();
	const struct l_settings *config = iwd_get_config();
	const char *whitelist = iwd_get_phy_whitelist();
	const char *blacklist = iwd_get_phy_blacklist();
	const char *s;

	nl80211 = l_genl_family_new(genl, NL80211_GENL_NAME);

	/*
	 * This is an extra sanity check so that no memory is leaked
	 * in case the generic netlink handling gets confused.
	 */
	if (wiphy_list) {
		l_warn("Destroying existing list of wiphy devices");
		l_queue_destroy(wiphy_list, NULL);
	}

	wiphy_list = l_queue_new();

	rfkill_watch_add(wiphy_rfkill_cb, NULL);

	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_WIPHY_INTERFACE,
					setup_wiphy_interface,
					NULL, false))
		l_error("Unable to register the %s interface",
				IWD_WIPHY_INTERFACE);

	hwdb = l_hwdb_new_default();

	if (whitelist)
		whitelist_filter = l_strsplit(whitelist, ',');

	if (blacklist)
		blacklist_filter = l_strsplit(blacklist, ',');

	s = l_settings_get_value(config, "General",
						"AddressRandomizationRange");
	if (s) {
		if (!strcmp(s, "nic"))
			mac_randomize_bytes = 3;
		else if (!strcmp(s, "full"))
			mac_randomize_bytes = 6;
		else
			l_warn("Invalid [General].AddressRandomizationRange"
				" value: %s", s);
	}

	return 0;
}

static void wiphy_exit(void)
{
	l_strfreev(whitelist_filter);
	l_strfreev(blacklist_filter);

	l_queue_destroy(wiphy_list, wiphy_free);
	wiphy_list = NULL;

	l_genl_family_free(nl80211);
	nl80211 = NULL;
	mac_randomize_bytes = 6;

	l_dbus_unregister_interface(dbus_get_bus(), IWD_WIPHY_INTERFACE);

	l_hwdb_unref(hwdb);
}

IWD_MODULE(wiphy, wiphy_init, wiphy_exit);
IWD_MODULE_DEPENDS(wiphy, rfkill);
