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
#include <limits.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "ell/useful.h"
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
#include "src/nl80211cmd.h"
#include "src/band.h"

#define EXT_CAP_LEN 10

static struct l_genl_family *nl80211 = NULL;
static struct l_hwdb *hwdb;
static char **whitelist_filter;
static char **blacklist_filter;
static int mac_randomize_bytes = 6;
static char regdom_country[2];
static uint32_t work_ids;
static unsigned int wiphy_dump_id;

enum driver_flag {
	DEFAULT_IF = 0x1,
	FORCE_PAE = 0x2,
};

struct driver_info {
	const char *prefix;
	unsigned int flags;
};

/*
 * The out-of-tree rtl88x2bu crashes the kernel hard if default interface is
 * destroyed.  It seems many other drivers are built from the same source code
 * so we set the DEFAULT_IF flag for all of them.  Unfortunately there are
 * in-tree drivers that also match these names and may be fine.
 */
static const struct driver_info driver_infos[] = {
	{ "rtl81*",          DEFAULT_IF },
	{ "rtl87*",          DEFAULT_IF },
	{ "rtl88*",          DEFAULT_IF },
	{ "rtw_*",           DEFAULT_IF },
	{ "brcmfmac",        DEFAULT_IF },
	{ "bcmsdh_sdmmc",    DEFAULT_IF },
};

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
	struct scan_freq_set *disabled_freqs;
	struct scan_freq_set *pending_freqs;
	struct band *band_2g;
	struct band *band_5g;
	struct band *band_6g;
	char *model_str;
	char *vendor_str;
	char *driver_str;
	const struct driver_info *driver_info;
	struct watchlist state_watches;
	uint8_t extended_capabilities[EXT_CAP_LEN + 2]; /* max bitmap size + IE header */
	uint8_t *iftype_extended_capabilities[NUM_NL80211_IFTYPES];
	uint8_t rm_enabled_capabilities[7]; /* 5 size max + header */
	struct l_genl_family *nl80211;
	char regdom_country[2];
	/* Work queue for this radio */
	struct l_queue *work;
	bool work_in_callback;
	unsigned int get_reg_id;
	unsigned int dump_id;

	bool support_scheduled_scan:1;
	bool support_rekey_offload:1;
	bool support_adhoc_rsn:1;
	bool support_qos_set_map:1;
	bool support_cmds_auth_assoc:1;
	bool support_fw_roam:1;
	bool soft_rfkill : 1;
	bool hard_rfkill : 1;
	bool offchannel_tx_ok : 1;
	bool blacklisted : 1;
	bool registered : 1;
	bool self_managed : 1;
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

static bool wiphy_can_connect_sae(struct wiphy *wiphy)
{
	/*
	 * WPA3 Specification version 3, Section 2.2:
	 * A STA shall not enable WEP and TKIP
	 */
	if (!(wiphy->supported_ciphers & IE_RSN_CIPHER_SUITE_CCMP)) {
		l_debug("HW not CCMP capable, can't use SAE");
		return false;
	}

	/*
	 * WPA3 Specification version 3, Section 2.3:
	 * A STA shall negotiate PMF when associating to an AP using SAE
	 */
	if (!(wiphy->supported_ciphers & IE_RSN_CIPHER_SUITE_BIP)) {
		l_debug("HW not MFP capable, can't use SAE");
		return false;
	}

	/*
	 * SAE support in the kernel is a complete mess in that there are 3
	 * different ways the hardware can support SAE:
	 *
	 * 1. Cards which allow SAE in userspace, meaning they support both
	 *    CMD_AUTHENTICATE and CMD_ASSOCIATE as well as advertise support
	 *    for FEATURE_SAE (SoftMAC).
	 *
	 * 2. Cards which allow SAE to be offloaded to hardware. These cards
	 *    do not support AUTH/ASSOC commands, do not advertise FEATURE_SAE,
	 *    but advertise support for EXT_FEATURE_SAE_OFFLOAD. With these
	 *    cards the entire SAE protocol as well as the subsequent 4-way
	 *    handshake are all done in the driver/firmware (fullMAC).
	 *
	 * 3. TODO: Cards which allow SAE in userspace via CMD_EXTERNAL_AUTH.
	 *    These cards do not support AUTH/ASSOC commands but do implement
	 *    CMD_EXTERNAL_AUTH which is supposed to allow userspace to
	 *    generate Authenticate frames as it would for case (1). As it
	 *    stands today only one driver actually uses CMD_EXTERNAL_AUTH and
	 *    for now IWD will not allow connections to SAE networks using this
	 *    mechanism.
	 */

	if (wiphy_has_feature(wiphy, NL80211_FEATURE_SAE)) {
		/* Case (1) */
		if (wiphy->support_cmds_auth_assoc)
			return true;

		/*
		 * Case (3)
		 *
		 * TODO: No support for CMD_EXTERNAL_AUTH yet.
		 */
		return false;
	}

	/* Case (2) */
	if (wiphy_has_ext_feature(wiphy,
				NL80211_EXT_FEATURE_SAE_OFFLOAD))
		return true;

	return false;
}

enum ie_rsn_akm_suite wiphy_select_akm(struct wiphy *wiphy,
					const struct scan_bss *bss,
					enum security security,
					const struct ie_rsn_info *info,
					bool fils_capable_hint)
{
	bool psk_offload = wiphy_has_ext_feature(wiphy,
				NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK);

	/*
	 * If FT is available, use FT authentication to keep the door open
	 * for fast transitions.  Otherwise use SHA256 version if present.
	 */
	if (security == SECURITY_8021X) {
		if (wiphy_has_feature(wiphy, NL80211_EXT_FEATURE_FILS_STA) &&
				fils_capable_hint) {
			if ((info->akm_suites &
					IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384) &&
					bss->rsne && bss->mde_present)
				return IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384;

			if ((info->akm_suites &
					IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256) &&
					bss->rsne && bss->mde_present)
				return IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256;

			if (info->akm_suites & IE_RSN_AKM_SUITE_FILS_SHA384)
				return IE_RSN_AKM_SUITE_FILS_SHA384;

			if (info->akm_suites & IE_RSN_AKM_SUITE_FILS_SHA256)
				return IE_RSN_AKM_SUITE_FILS_SHA256;
		}

		if ((info->akm_suites & IE_RSN_AKM_SUITE_FT_OVER_8021X) &&
				bss->rsne && bss->mde_present &&
				wiphy->support_cmds_auth_assoc)
			return IE_RSN_AKM_SUITE_FT_OVER_8021X;

		if (info->akm_suites & IE_RSN_AKM_SUITE_8021X_SHA256)
			return IE_RSN_AKM_SUITE_8021X_SHA256;

		if (info->akm_suites & IE_RSN_AKM_SUITE_8021X)
			return IE_RSN_AKM_SUITE_8021X;
	} else if (security == SECURITY_PSK) {
		/*
		 * Prefer connecting to SAE/WPA3 network, but only if SAE is
		 * supported, we are MFP capable, and the AP has set the
		 * MFPR/MFPC bits correctly. If any of these conditions are not
		 * met, we can fallback to WPA2 (if the AKM is present).
		 */
		if (ie_rsne_is_wpa3_personal(info)) {
			l_debug("Network is WPA3-Personal...");

			if (!wiphy_can_connect_sae(wiphy))
				goto wpa2_personal;

			if (info->akm_suites &
					IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256)
				return IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256;

			if (info->akm_suites & IE_RSN_AKM_SUITE_SAE_SHA256)
				return IE_RSN_AKM_SUITE_SAE_SHA256;
		}

wpa2_personal:
		/*
		 * Allow FT if either Auth/Assoc is supported OR if the card
		 * supports PSK offload. Without Auth/Assoc, PSK offload is the
		 * only mechanism to allow FT on these cards.
		 */
		if ((info->akm_suites & IE_RSN_AKM_SUITE_FT_USING_PSK) &&
					bss->rsne && bss->mde_present) {
			if (wiphy->support_cmds_auth_assoc ||
					(psk_offload && wiphy->support_fw_roam))
				return IE_RSN_AKM_SUITE_FT_USING_PSK;
		}

		if (info->akm_suites & IE_RSN_AKM_SUITE_PSK_SHA256)
			return IE_RSN_AKM_SUITE_PSK_SHA256;

		if (info->akm_suites & IE_RSN_AKM_SUITE_PSK)
			return IE_RSN_AKM_SUITE_PSK;
	} else if (security == SECURITY_NONE) {
		if (info->akm_suites & IE_RSN_AKM_SUITE_OWE)
			return IE_RSN_AKM_SUITE_OWE;
	}

	return 0;
}

static struct wiphy *wiphy_new(uint32_t id)
{
	struct wiphy *wiphy = l_new(struct wiphy, 1);

	wiphy->id = id;
	wiphy->supported_freqs = scan_freq_set_new();
	wiphy->disabled_freqs = scan_freq_set_new();
	watchlist_init(&wiphy->state_watches, NULL);
	wiphy->extended_capabilities[0] = IE_TYPE_EXTENDED_CAPABILITIES;
	wiphy->extended_capabilities[1] = EXT_CAP_LEN;

	return wiphy;
}

static void destroy_work(void *user_data)
{
	struct wiphy_radio_work_item *work = user_data;

	if (work->ops && work->ops->destroy)
		work->ops->destroy(work);
}

static void wiphy_free(void *data)
{
	struct wiphy *wiphy = data;
	uint32_t i;

	l_debug("Freeing wiphy %s[%u]", wiphy->name, wiphy->id);

	if (wiphy->dump_id)
		l_genl_family_cancel(nl80211, wiphy->dump_id);

	if (wiphy->get_reg_id)
		l_genl_family_cancel(nl80211, wiphy->get_reg_id);

	for (i = 0; i < NUM_NL80211_IFTYPES; i++)
		l_free(wiphy->iftype_extended_capabilities[i]);

	if (wiphy->band_2g) {
		band_free(wiphy->band_2g);
		wiphy->band_2g = NULL;
	}

	if (wiphy->band_5g) {
		band_free(wiphy->band_5g);
		wiphy->band_5g = NULL;
	}

	if (wiphy->band_6g) {
		band_free(wiphy->band_6g);
		wiphy->band_6g = NULL;
	}

	scan_freq_set_free(wiphy->supported_freqs);
	scan_freq_set_free(wiphy->disabled_freqs);
	watchlist_destroy(&wiphy->state_watches);
	l_free(wiphy->model_str);
	l_free(wiphy->vendor_str);
	l_free(wiphy->driver_str);
	l_genl_family_free(wiphy->nl80211);
	l_queue_destroy(wiphy->work, destroy_work);
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
	uint32_t bands = 0;

	if (wiphy->band_2g)
		bands |= BAND_FREQ_2_4_GHZ;

	if (wiphy->band_5g)
		bands |= BAND_FREQ_5_GHZ;

	if (wiphy->band_6g)
		bands |= BAND_FREQ_6_GHZ;

	return bands;
}

const struct scan_freq_set *wiphy_get_supported_freqs(
						const struct wiphy *wiphy)
{
	return wiphy->supported_freqs;
}

const struct scan_freq_set *wiphy_get_disabled_freqs(const struct wiphy *wiphy)
{
	return wiphy->disabled_freqs;
}

bool wiphy_can_transition_disable(struct wiphy *wiphy)
{
	/*
	 * WPA3 Specification version 3, Section 2.2:
	 * A STA shall not enable WEP and TKIP
	 */
	if (!(wiphy->supported_ciphers & IE_RSN_CIPHER_SUITE_CCMP))
		return false;

	if (!(wiphy->supported_ciphers & IE_RSN_CIPHER_SUITE_BIP))
		return false;

	return true;
}

/* Catch all for the offload features */
bool wiphy_can_offload(struct wiphy *wiphy)
{
	return wiphy_has_ext_feature(wiphy,
				NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK) ||
		wiphy_has_ext_feature(wiphy,
				NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X) ||
		wiphy_has_ext_feature(wiphy, NL80211_EXT_FEATURE_SAE_OFFLOAD);
}

bool wiphy_supports_ext_key_id(struct wiphy *wiphy)
{
	return wiphy_has_ext_feature(wiphy, NL80211_EXT_FEATURE_EXT_KEY_ID);
}

bool wiphy_supports_cmds_auth_assoc(struct wiphy *wiphy)
{
	return wiphy->support_cmds_auth_assoc;
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
		test_bit(wiphy->ext_features, feature);
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

bool wiphy_supports_firmware_roam(struct wiphy *wiphy)
{
	return wiphy->support_fw_roam;
}

const char *wiphy_get_driver(struct wiphy *wiphy)
{
	return wiphy->driver_str;
}

const char *wiphy_get_name(struct wiphy *wiphy)
{
	return wiphy->name;
}

bool wiphy_uses_default_if(struct wiphy *wiphy)
{
	if (!wiphy_get_driver(wiphy))
		return true;

	if (wiphy->driver_info &&
			wiphy->driver_info->flags & DEFAULT_IF)
		return true;

	return false;
}

bool wiphy_control_port_enabled(struct wiphy *wiphy)
{
	const struct l_settings *settings = iwd_get_config();
	bool enabled;

	if (wiphy->driver_info &&
			wiphy->driver_info->flags & FORCE_PAE) {
		l_info("Not using Control Port due to driver quirks: %s",
				wiphy_get_driver(wiphy));
		return false;
	}

	if (!wiphy_has_ext_feature(wiphy,
			NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211))
		return false;

	if (!l_settings_get_bool(settings, "General",
					"ControlPortOverNL80211", &enabled))
		enabled = true;

	return enabled;
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

bool wiphy_get_rsnxe(const struct wiphy *wiphy, uint8_t *buf, size_t len)
{
	if (len < 3)
		return false;

	buf[0] = IE_TYPE_RSNX;
	buf[1] = 1;

	/*
	 * Lower 4 bits of the first octet:
	 * The length of the Extended RSN Capabilities field, in octets,
	 * minus 1, i.e., n - 1.
	 */
	buf[2] = 0;

	/* No other bits set for now */

	return true;
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
	if (l_memeqzero(addr + 3, 3))
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
	scan_freq_set_subtract(set, wiphy->disabled_freqs);

	if (!scan_freq_set_get_bands(set))
		/* The set is empty. */
		return false;

	return true;
}

static char **wiphy_iftype_mask_to_str(uint16_t mask)
{
	char **ret = l_new(char *, __builtin_popcount(mask) + 1);
	unsigned int i;
	unsigned int j;

	for (j = 0, i = 0; i < sizeof(mask) * 8; i++) {
		const char *str;

		if (!(mask & (1 << i)))
			continue;

		str = netdev_iftype_to_string(i + 1);
		if (str)
			ret[j++] = l_strdup(str);
	}

	return ret;
}

static char **wiphy_get_supported_iftypes(struct wiphy *wiphy, uint16_t mask)
{
	return wiphy_iftype_mask_to_str(wiphy->supported_iftypes & mask);
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
	struct band *bandp;

	switch (band) {
	case NL80211_BAND_2GHZ:
		bandp = wiphy->band_2g;
		break;
	case NL80211_BAND_5GHZ:
		bandp = wiphy->band_5g;
		break;
	case NL80211_BAND_6GHZ:
		bandp = wiphy->band_6g;
		break;
	default:
		return NULL;
	}

	if (!bandp)
		return NULL;

	if (out_num)
		*out_num = bandp->supported_rates_len;

	return bandp->supported_rates;
}

void wiphy_get_reg_domain_country(struct wiphy *wiphy, char *out)
{
	char *country = wiphy->regdom_country;

	if (!country[0])
		/* Wiphy uses the global regulatory domain */
		country = regdom_country;

	out[0] = country[0];
	out[1] = country[1];
}

bool wiphy_country_is_unknown(struct wiphy *wiphy)
{
	char cc[2];

	wiphy_get_reg_domain_country(wiphy, cc);

	/*
	 * Treat OO and XX as an unknown country. Additional codes could be
	 * added here if needed. The purpose of this is to know if we can
	 * expect the disabled frequency list to be updated once a country is
	 * known.
	 */
	return ((cc[0] == 'O' && cc[1] == 'O') ||
			(cc[0] == 'X' && cc[1] == 'X'));
}

int wiphy_estimate_data_rate(struct wiphy *wiphy,
				const void *ies, uint16_t ies_len,
				const struct scan_bss *bss,
				uint64_t *out_data_rate)
{
	struct ie_tlv_iter iter;
	const void *supported_rates = NULL;
	const void *ext_supported_rates = NULL;
	const void *vht_capabilities = NULL;
	const void *vht_operation = NULL;
	const void *ht_capabilities = NULL;
	const void *ht_operation = NULL;
	const void *he_capabilities = NULL;
	const struct band *bandp;
	enum band_freq band;

	if (band_freq_to_channel(bss->frequency, &band) == 0)
		return -ENOTSUP;

	switch (band) {
	case BAND_FREQ_2_4_GHZ:
		bandp = wiphy->band_2g;
		break;
	case BAND_FREQ_5_GHZ:
		bandp = wiphy->band_5g;
		break;
	case BAND_FREQ_6_GHZ:
		bandp = wiphy->band_6g;
		break;
	default:
		return -ENOTSUP;
	}

	ie_tlv_iter_init(&iter, ies, ies_len);

	while (ie_tlv_iter_next(&iter)) {
		uint16_t tag = ie_tlv_iter_get_tag(&iter);

		switch (tag) {
		case IE_TYPE_SUPPORTED_RATES:
			if (iter.len > 8)
				return -EBADMSG;

			supported_rates = iter.data - 2;
			break;
		case IE_TYPE_EXTENDED_SUPPORTED_RATES:
			ext_supported_rates = iter.data - 2;
			break;
		case IE_TYPE_HT_CAPABILITIES:
			if (iter.len != 26)
				return -EBADMSG;

			ht_capabilities = iter.data - 2;
			break;
		case IE_TYPE_HT_OPERATION:
			if (iter.len != 22)
				return -EBADMSG;

			ht_operation = iter.data - 2;
			break;
		case IE_TYPE_VHT_CAPABILITIES:
			if (iter.len != 12)
				return -EBADMSG;

			vht_capabilities = iter.data - 2;
			break;
		case IE_TYPE_VHT_OPERATION:
			if (iter.len != 5)
				return -EBADMSG;

			vht_operation = iter.data - 2;
			break;
		case IE_TYPE_HE_CAPABILITIES:
			if (!ie_validate_he_capabilities(iter.data, iter.len))
				return -EBADMSG;

			he_capabilities = iter.data;
			break;
		default:
			break;
		}
	}

	if (!band_estimate_he_rx_rate(bandp, he_capabilities,
					bss->signal_strength / 100,
					out_data_rate))
		return 0;

	if (!band_estimate_vht_rx_rate(bandp, vht_capabilities, vht_operation,
					ht_capabilities, ht_operation,
					bss->signal_strength / 100,
					out_data_rate))
		return 0;

	if (!band_estimate_ht_rx_rate(bandp, ht_capabilities, ht_operation,
					bss->signal_strength / 100,
					out_data_rate))
		return 0;

	return band_estimate_nonht_rate(bandp, supported_rates,
						ext_supported_rates,
						bss->signal_strength / 100,
						out_data_rate);
}

bool wiphy_regdom_is_updating(struct wiphy *wiphy)
{
	return wiphy->pending_freqs != NULL;
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

static void wiphy_print_mcs_indexes(const uint8_t *mcs)
{
	int i;

	for (i = 0; i < 77; i++) {
		int start;

		if (!test_bit(mcs, i))
			continue;

		start = i;

		while (i < 76 && test_bit(mcs, i + 1))
			i += 1;

		if (start != i)
			l_info("\t\t\t%d-%d", start, i);
		else
			l_info("\t\t\t%d", start);
	}
}

static void wiphy_print_mcs_info(const uint8_t *mcs_map,
						const char *prefix,
						uint8_t value0,
						uint8_t value1,
						uint8_t value2)
{
	int i;

	for (i = 14; i >= 0; i -= 2) {
		uint8_t value;
		int mcs = bit_field(mcs_map[i / 8], i % 8, 2);

		if (mcs == 0x3)
			continue;

		switch (mcs) {
		case 0:
			value = value0;
			break;
		case 1:
			value = value1;
			break;
		case 2:
			value = value2;
			break;
		}

		l_info("\t\t\tMax %s MCS: 0-%d for NSS: %d", prefix,
			value, i / 2 + 1);
		return;
	}
}

static void wiphy_print_he_capabilities(struct band *band,
				const struct band_he_capabilities *he_cap)
{
	_auto_(l_strv_free) char **iftypes = NULL;
	_auto_(l_free) char *joined = NULL;
	uint8_t width_set = bit_field(he_cap->he_phy_capa[0], 1, 7);

	iftypes = wiphy_iftype_mask_to_str(he_cap->iftypes);
	joined = l_strjoinv(iftypes, ' ');

	l_info("\t\t\tInterface Types: %s", joined);

	switch (band->freq) {
	case BAND_FREQ_2_4_GHZ:
		wiphy_print_mcs_info(he_cap->he_mcs_set,
					"HE RX <= 80MHz", 7, 9, 11);
		wiphy_print_mcs_info(he_cap->he_mcs_set + 2,
					"HE TX <= 80MHz", 7, 9, 11);
		break;
	case BAND_FREQ_5_GHZ:
	case BAND_FREQ_6_GHZ:
		wiphy_print_mcs_info(he_cap->he_mcs_set,
					"HE RX <= 80MHz", 7, 9, 11);
		wiphy_print_mcs_info(he_cap->he_mcs_set + 2,
					"HE TX <= 80MHz", 7, 9, 11);

		if (test_bit(&width_set, 2)) {
			wiphy_print_mcs_info(he_cap->he_mcs_set + 4,
					"HE RX <= 160MHz", 7, 9, 11);
			wiphy_print_mcs_info(he_cap->he_mcs_set + 6,
					"HE TX <= 160MHz", 7, 9, 11);
		}

		if (test_bit(&width_set, 3)) {
			wiphy_print_mcs_info(he_cap->he_mcs_set + 8,
					"HE RX <= 80+80MHz", 7, 9, 11);
			wiphy_print_mcs_info(he_cap->he_mcs_set + 10,
					"HE TX <= 80+80MHz", 7, 9, 11);
		}

		break;
	}
}

static void wiphy_print_band_info(struct band *band, const char *name)
{
	int i;

	l_info("\t%s:", name);
	l_info("\t\tBitrates (non-HT):");

	for (i = 0; i < band->supported_rates_len; i++)
		l_info("\t\t\t%2d.%d Mbps", band->supported_rates[i] / 2,
					band->supported_rates[i] % 2 * 5);

	if (band->ht_supported) {
		uint8_t max_nss = bit_field(band->ht_mcs_set[12], 2, 2) + 1;

		l_info("\t\tHT Capabilities:");

		if (test_bit(band->ht_capabilities, 1))
			l_info("\t\t\tHT40");
		else
			l_info("\t\t\tHT20");

		if (test_bit(band->ht_capabilities, 5))
			l_info("\t\t\tShort GI for 20Mhz");

		if (test_bit(band->ht_capabilities, 6))
			l_info("\t\t\tShort GI for 40Mhz");

		l_info("\t\tHT RX MCS indexes:");
		wiphy_print_mcs_indexes(band->ht_mcs_set);

		if (test_bit(band->ht_mcs_set, 96)) {
			if (test_bit(band->ht_mcs_set, 97))
				l_info("\t\tHT TX MCS differ, max NSS: %d",
					max_nss);
		} else
			l_info("\t\tHT TX MCS set undefined");
	}

	if (band->vht_supported) {
		l_info("\t\tVHT Capabilities:");

		switch (bit_field(band->vht_capabilities[0], 2, 2)) {
		case 1:
			l_info("\t\t\t160 Mhz operation");
			break;
		case 2:
			l_info("\t\t\t160 Mhz, 80+80 Mhz operation");
			break;
		}

		if (test_bit(band->vht_capabilities, 5))
			l_info("\t\t\tShort GI for 80Mhz");

		if (test_bit(band->vht_capabilities, 6))
			l_info("\t\t\tShort GI for 160 and 80 + 80 Mhz");

		wiphy_print_mcs_info(band->vht_mcs_set, "RX", 7, 8, 9);
		wiphy_print_mcs_info(band->vht_mcs_set + 4, "TX", 7, 8, 9);
	}

	if (band->he_capabilities) {
		const struct l_queue_entry *entry;

		l_info("\t\tHE Capabilities");

		for (entry = l_queue_get_entries(band->he_capabilities);
						entry; entry = entry->next) {
			const struct band_he_capabilities *he_cap = entry->data;

			wiphy_print_he_capabilities(band, he_cap);
		}

	}
}

static void wiphy_print_basic_info(struct wiphy *wiphy)
{
	char buf[1024];

	l_info("Wiphy: %d, Name: %s", wiphy->id, wiphy->name);
	l_info("\tPermanent Address: "MAC, MAC_STR(wiphy->permanent_addr));

	if (wiphy->band_2g)
		wiphy_print_band_info(wiphy->band_2g, "2.4Ghz Band");

	if (wiphy->band_5g)
		wiphy_print_band_info(wiphy->band_5g, "5Ghz Band");

	if (wiphy->band_6g)
		wiphy_print_band_info(wiphy->band_6g, "6GHz Band");

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
	bool auth = false;
	bool assoc = false;

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
		case NL80211_CMD_AUTHENTICATE:
			auth = true;
			break;
		case NL80211_CMD_ASSOCIATE:
			assoc = true;
			break;
		}
	}

	if (auth && assoc)
		wiphy->support_cmds_auth_assoc = true;
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

static int parse_supported_rates(struct l_genl_attr *attr, struct band *band)
{
	uint16_t type;
	uint16_t len;
	const void *data;
	struct l_genl_attr nested;
	int count = 0;

	if (!l_genl_attr_recurse(attr, &nested))
		return -EBADMSG;

	while (l_genl_attr_next(&nested, NULL, NULL, NULL)) {
		struct l_genl_attr nested2;

		if (!l_genl_attr_recurse(&nested, &nested2))
			return -EBADMSG;

		while (l_genl_attr_next(&nested2, &type, &len, &data)) {
			uint32_t rate;

			if (type != NL80211_BITRATE_ATTR_RATE || len != 4)
				continue;

			rate = l_get_u32(data);

			if (rate % 5)
				continue;

			/*
			 * Convert from the 100kb/s units reported by the
			 * kernel to the 500kb/s used in 802.11 IEs.
			 */
			rate /= 5;

			/*
			 * Rates past 120 seem to be used for other purposes,
			 * BSS Membership Selector (HT/VHT), etc
			 */
			if (rate > 120)
				continue;

			band->supported_rates[count++] = rate;
		}
	}

	band->supported_rates_len = count;

	return 0;
}

static struct band *band_new_from_message(struct l_genl_attr *band)
{
	uint16_t type;
	struct l_genl_attr nested;
	uint16_t count = 0;
	struct band *ret;
	size_t toalloc;

	/* First find the number of supported rates */
	while (l_genl_attr_next(band, &type, NULL, NULL)) {
		switch (type) {
		case NL80211_BAND_ATTR_RATES:
			if (!l_genl_attr_recurse(band, &nested))
				return NULL;

			while (l_genl_attr_next(&nested, NULL, NULL, NULL))
				count++;
		}
	}

	toalloc = sizeof(struct band) + count * sizeof(uint8_t);
	ret = l_malloc(toalloc);
	memset(ret, 0, toalloc);

#if __GNUC__ == 11 && __GNUC_MINOR__ == 2
_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Warray-bounds\"")
#endif
	memset(ret->vht_mcs_set, 0xff, sizeof(ret->vht_mcs_set));
#if __GNUC__ == 11 && __GNUC_MINOR__ == 2
_Pragma("GCC diagnostic pop")
#endif

	return ret;
}

static uint32_t get_iftypes(struct l_genl_attr *iftypes)
{
	uint16_t type;
	uint16_t len;
	uint32_t types = 0;

	while (l_genl_attr_next(iftypes, &type, &len, NULL)) {
		if (len != 0)
			continue;

		types |= (1 << (type - 1));
	}

	return types;
}

static void parse_iftype_attrs(struct band *band, struct l_genl_attr *types)
{
	uint16_t type;
	uint16_t len;
	const void *data;
	unsigned int count = 0;
	struct band_he_capabilities *he_cap =
					l_new(struct band_he_capabilities, 1);

	while (l_genl_attr_next(types, &type, &len, &data)) {
		struct l_genl_attr iftypes;

		switch (type) {
		case NL80211_BAND_IFTYPE_ATTR_IFTYPES:
			if (!l_genl_attr_recurse(types, &iftypes))
				goto parse_error;

			he_cap->iftypes = get_iftypes(&iftypes);
			break;
		case NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY:
			if (len > sizeof(he_cap->he_phy_capa))
				continue;

			memcpy(he_cap->he_phy_capa, data, len);
			count++;
			break;
		case NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET:
			if (len > sizeof(he_cap->he_mcs_set))
				continue;

			memcpy(he_cap->he_mcs_set, data, len);
			count++;
			break;
		default:
			break;
		}
	}

	/*
	 * Since the capabilities element indicates what values are present in
	 * the MCS set ensure both values are parsed
	 */
	if (count != 2 || !he_cap->iftypes)
		goto parse_error;

	if (!band->he_capabilities)
		band->he_capabilities = l_queue_new();

	l_queue_push_head(band->he_capabilities, he_cap);

	return;

parse_error:
	l_free(he_cap);
}

static void parse_band_iftype_data(struct band *band, struct l_genl_attr *ifdata)
{
	while (l_genl_attr_next(ifdata, NULL, NULL, NULL)) {
		struct l_genl_attr types;

		if (!l_genl_attr_recurse(ifdata, &types))
			continue;

		parse_iftype_attrs(band, &types);
	}
}

static void parse_supported_bands(struct wiphy *wiphy,
						struct l_genl_attr *bands)
{
	uint16_t type;
	uint16_t len;
	const void *data;
	struct l_genl_attr attr;

	while (l_genl_attr_next(bands, &type, NULL, NULL)) {
		struct band **bandp;
		struct band *band;
		enum band_freq freq;

		switch (type) {
		case NL80211_BAND_2GHZ:
			bandp = &wiphy->band_2g;
			freq = BAND_FREQ_2_4_GHZ;
			break;
		case NL80211_BAND_5GHZ:
			bandp = &wiphy->band_5g;
			freq = BAND_FREQ_5_GHZ;
			break;
		case NL80211_BAND_6GHZ:
			bandp = &wiphy->band_6g;
			freq = BAND_FREQ_6_GHZ;
			break;
		default:
			continue;
		}

		if (!l_genl_attr_recurse(bands, &attr))
			continue;

		if (*bandp == NULL) {
			band = band_new_from_message(&attr);
			if (!band)
				continue;

			band->freq = freq;

			/* Reset iter to beginning */
			if (!l_genl_attr_recurse(bands, &attr)) {
				band_free(band);
				continue;
			}
		} else
			band = *bandp;


		while (l_genl_attr_next(&attr, &type, &len, &data)) {
			struct l_genl_attr nested;

			switch (type) {
			case NL80211_BAND_ATTR_FREQS:
				nl80211_parse_supported_frequencies(&attr,
							wiphy->supported_freqs,
							wiphy->disabled_freqs);
				break;

			case NL80211_BAND_ATTR_RATES:
				if (parse_supported_rates(&attr, band) < 0) {
					band_free(band);
					continue;
				}

				break;
			case NL80211_BAND_ATTR_VHT_MCS_SET:
				if (L_WARN_ON(len != sizeof(band->vht_mcs_set)))
					continue;

				memcpy(band->vht_mcs_set, data, len);
				band->vht_supported = true;
				break;
			case NL80211_BAND_ATTR_VHT_CAPA:
				if (L_WARN_ON(len !=
						sizeof(band->vht_capabilities)))
					continue;

				memcpy(band->vht_capabilities, data, len);
				band->vht_supported = true;
				break;
			case NL80211_BAND_ATTR_HT_MCS_SET:
				if (L_WARN_ON(len != sizeof(band->ht_mcs_set)))
					continue;

				memcpy(band->ht_mcs_set, data, len);
				band->ht_supported = true;
				break;
			case NL80211_BAND_ATTR_HT_CAPA:
				if (L_WARN_ON(len !=
						sizeof(band->ht_capabilities)))
					continue;

				memcpy(band->ht_capabilities, data, len);
				band->ht_supported = true;
				break;
			case NL80211_BAND_ATTR_IFTYPE_DATA:
				if (!l_genl_attr_recurse(&attr, &nested))
					continue;

				parse_band_iftype_data(band, &nested);
				break;
			}
		}

		if (*bandp == NULL)
			*bandp = band;
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
		case NL80211_ATTR_ROAM_SUPPORT:
			wiphy->support_fw_roam = true;
			break;
		case NL80211_ATTR_WIPHY_SELF_MANAGED_REG:
			wiphy->self_managed = true;
			break;
		}
	}
}

static bool wiphy_get_driver_name(struct wiphy *wiphy)
{
	L_AUTO_FREE_VAR(char *, driver_link) = NULL;
	char driver_path[256];
	ssize_t len;
	unsigned int i;

	driver_link = l_strdup_printf("/sys/class/ieee80211/%s/device/driver",
					wiphy->name);
	len = readlink(driver_link, driver_path, sizeof(driver_path) - 1);

	if (len == -1) {
		l_error("Can't read %s: %s", driver_link, strerror(errno));
		return false;
	}

	driver_path[len] = '\0';
	wiphy->driver_str = l_strdup(basename(driver_path));

	for (i = 0; i < L_ARRAY_SIZE(driver_infos); i++)
		if (!fnmatch(driver_infos[i].prefix, wiphy->driver_str, 0))
			wiphy->driver_info = &driver_infos[i];

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
	struct l_genl *genl = iwd_get_genl();

	wiphy = wiphy_new(wiphy_id);
	l_strlcpy(wiphy->name, name, sizeof(wiphy->name));
	wiphy->nl80211 = l_genl_family_new(genl, NL80211_GENL_NAME);
	l_queue_push_head(wiphy_list, wiphy);

	if (!wiphy_is_managed(name))
		wiphy->blacklisted = true;

	wiphy->work = l_queue_new();

	return wiphy;
}

void wiphy_update_from_genl(struct wiphy *wiphy, struct l_genl_msg *msg)
{
	if (wiphy->blacklisted)
		return;

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
	set_bit(ext_capa + 2, 19);

	/* Set Interworking */
	if (!anqp_disabled)
		set_bit(ext_capa + 2, 31);

	/* Set QoS Map */
	if (wiphy->support_qos_set_map)
		set_bit(ext_capa + 2, 32);

	/* Set FILS */
	set_bit(ext_capa + 2, 72);
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

static void wiphy_dump_done(void *user_data)
{
	struct wiphy *wiphy = user_data;
	const struct l_queue_entry *e;

	/* This dump was canceled due to another dump */
	if ((wiphy && !wiphy->dump_id) || (!wiphy && !wiphy_dump_id))
		return;

	if (wiphy) {
		wiphy->dump_id = 0;
		scan_freq_set_free(wiphy->disabled_freqs);
		wiphy->disabled_freqs = wiphy->pending_freqs;
		wiphy->pending_freqs = NULL;

		WATCHLIST_NOTIFY(&wiphy->state_watches,
				wiphy_state_watch_func_t, wiphy,
				WIPHY_STATE_WATCH_EVENT_REGDOM_DONE);

		return;
	}

	wiphy_dump_id = 0;

	for (e = l_queue_get_entries(wiphy_list); e; e = e->next) {
		wiphy = e->data;

		if (!wiphy->pending_freqs || wiphy->self_managed)
			continue;

		scan_freq_set_free(wiphy->disabled_freqs);
		wiphy->disabled_freqs = wiphy->pending_freqs;
		wiphy->pending_freqs = NULL;

		WATCHLIST_NOTIFY(&wiphy->state_watches,
				wiphy_state_watch_func_t, wiphy,
				WIPHY_STATE_WATCH_EVENT_REGDOM_DONE);
	}
}

/* We are dumping wiphy(s) due to a regulatory change */
static void wiphy_dump_callback(struct l_genl_msg *msg,
						void *user_data)
{
	struct wiphy *wiphy;
	uint32_t id;
	struct l_genl_attr bands;
	struct l_genl_attr attr;
	uint16_t type;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_WIPHY, &id,
					NL80211_ATTR_WIPHY_BANDS, &bands,
					NL80211_ATTR_UNSPEC) < 0)
		return;

	wiphy = wiphy_find(id);
	if (L_WARN_ON(!wiphy))
		return;

	while (l_genl_attr_next(&bands, NULL, NULL, NULL)) {
		if (!l_genl_attr_recurse(&bands, &attr))
			return;

		while (l_genl_attr_next(&attr, &type, NULL, NULL)) {
			if (type != NL80211_BAND_ATTR_FREQS)
				continue;

			nl80211_parse_supported_frequencies(&attr, NULL,
							wiphy->pending_freqs);
		}
	}
}

static bool wiphy_cancel_last_dump(struct wiphy *wiphy)
{
	const struct l_queue_entry *e;
	unsigned int id = 0;

	/*
	 * Zero command ID to signal that wiphy_dump_done doesn't need to do
	 * anything. For a self-managed wiphy just free/NULL pending_freqs. For
	 * a global dump each wiphy needs to be checked and dealt with.
	 */
	if (wiphy && wiphy->dump_id) {
		id = wiphy->dump_id;
		wiphy->dump_id = 0;

		scan_freq_set_free(wiphy->pending_freqs);
		wiphy->pending_freqs = NULL;
	} else if (!wiphy && wiphy_dump_id) {
		id = wiphy_dump_id;
		wiphy_dump_id = 0;

		for (e = l_queue_get_entries(wiphy_list); e; e = e->next) {
			struct wiphy *w = e->data;

			if (!w->pending_freqs || w->self_managed)
				continue;

			scan_freq_set_free(w->pending_freqs);
			w->pending_freqs = NULL;
		}
	}

	if (id) {
		l_debug("Canceling pending regdom wiphy dump (%s)",
					wiphy ? wiphy->name : "global");

		l_genl_family_cancel(nl80211, id);
	}

	return id != 0;
}

static void wiphy_dump_after_regdom(struct wiphy *wiphy)
{
	const struct l_queue_entry *e;
	struct l_genl_msg *msg;
	unsigned int id;
	bool no_start_event;

	msg = l_genl_msg_new_sized(NL80211_CMD_GET_WIPHY, 128);

	if (wiphy)
		l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY, 4, &wiphy->id);

	l_genl_msg_append_attr(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP, 0, NULL);
	id = l_genl_family_dump(nl80211, msg, wiphy_dump_callback,
						wiphy, wiphy_dump_done);
	if (!id) {
		l_error("Wiphy information dump failed");
		l_genl_msg_unref(msg);
		return;
	}

	/*
	 * Another update while dumping wiphy. This next dump should supercede
	 * the first and not result in a DONE event until this new dump is
	 * finished. This is because the disabled frequencies are in an unknown
	 * state and could cause incorrect behavior by any watchers.
	 */
	no_start_event = wiphy_cancel_last_dump(wiphy);

	/* Limited dump so just emit the event for this wiphy */
	if (wiphy) {
		wiphy->dump_id = id;
		wiphy->pending_freqs = scan_freq_set_new();

		if (no_start_event)
			return;

		WATCHLIST_NOTIFY(&wiphy->state_watches,
				wiphy_state_watch_func_t, wiphy,
				WIPHY_STATE_WATCH_EVENT_REGDOM_STARTED);
		return;
	}

	wiphy_dump_id = id;

	/* Otherwise for a global regdom change notify for all wiphy's */
	for (e = l_queue_get_entries(wiphy_list); e; e = e->next) {
		struct wiphy *w = e->data;

		if (w->self_managed)
			continue;

		w->pending_freqs = scan_freq_set_new();

		if (no_start_event)
			continue;

		WATCHLIST_NOTIFY(&w->state_watches, wiphy_state_watch_func_t,
				w, WIPHY_STATE_WATCH_EVENT_REGDOM_STARTED);
	}
}

static bool wiphy_update_reg_domain(struct wiphy *wiphy, bool global,
					struct l_genl_msg *msg)
{
	char out_country[2];
	char *orig;

	/*
	 * Write the new country code or XX if the reg domain is not a
	 * country domain.
	 */
	if (nl80211_parse_attrs(msg, NL80211_ATTR_REG_ALPHA2, out_country,
				NL80211_ATTR_UNSPEC) < 0)
		out_country[0] = out_country[1] = 'X';

	if (global)
		/*
		 * Leave @wiphy->regdom_country as all zeros to mean that it
		 * uses the global @regdom_country, i.e. is not self-managed.
		 *
		 * Even if we're called because we queried a new wiphy's
		 * reg domain, use the value we received here to update our
		 * global @regdom_country in case this is the first opportunity
		 * we have to update it -- possibly because this is the first
		 * wiphy created (that is not self-managed anyway) and we
		 * haven't received any REG_CHANGE events yet.
		 */
		orig = regdom_country;

	else
		orig = wiphy->regdom_country;

	/*
	 * The kernel seems to send regdom updates even if the country didn't
	 * change. Skip these as there is no reason to re-dump.
	 */
	if (orig[0] == out_country[0] && orig[1] == out_country[1])
		return false;

	l_debug("New reg domain country code for %s is %c%c",
		global ? "(global)" : wiphy->name,
		out_country[0], out_country[1]);

	orig[0] = out_country[0];
	orig[1] = out_country[1];

	return true;
}

static void wiphy_get_reg_cb(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy *wiphy = user_data;
	uint32_t tmp;
	bool global;

	wiphy->get_reg_id = 0;

	/*
	 * NL80211_CMD_GET_REG contains an NL80211_ATTR_WIPHY iff the wiphy
	 * uses a self-managed regulatory domain.
	 */
	global = nl80211_parse_attrs(msg, NL80211_ATTR_WIPHY, &tmp,
				NL80211_ATTR_UNSPEC) < 0;

	wiphy_update_reg_domain(wiphy, global, msg);
}

static void wiphy_get_reg_domain(struct wiphy *wiphy)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new(NL80211_CMD_GET_REG);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY, 4, &wiphy->id);

	wiphy->get_reg_id = l_genl_family_send(wiphy->nl80211, msg,
						wiphy_get_reg_cb, wiphy, NULL);
	if (!wiphy->get_reg_id) {
		l_error("Error sending NL80211_CMD_GET_REG for %s", wiphy->name);
		l_genl_msg_unref(msg);
	}
}

void wiphy_create_complete(struct wiphy *wiphy)
{
	wiphy_register(wiphy);

	if (l_memeqzero(wiphy->permanent_addr, 6)) {
		int err = wiphy_get_permanent_addr_from_sysfs(wiphy);

		if (err < 0)
			l_error("Can't read sysfs maccaddr for %s: %s",
					wiphy->name, strerror(-err));
	}

	wiphy_set_station_capability_bits(wiphy);
	wiphy_setup_rm_enabled_capabilities(wiphy);
	wiphy_get_reg_domain(wiphy);

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

static void wiphy_reg_notify(struct l_genl_msg *msg, void *user_data)
{
	uint8_t cmd = l_genl_msg_get_command(msg);
	struct wiphy *wiphy = NULL;
	uint32_t wiphy_id;

	l_debug("Notification of command %s(%u)",
		nl80211cmd_to_string(cmd), cmd);

	switch (cmd) {
	case NL80211_CMD_REG_CHANGE:
		if (!wiphy_update_reg_domain(NULL, true, msg))
			return;
		break;
	case NL80211_CMD_WIPHY_REG_CHANGE:
		if (nl80211_parse_attrs(msg, NL80211_ATTR_WIPHY, &wiphy_id,
					NL80211_ATTR_UNSPEC) < 0)
			return;

		wiphy = wiphy_find(wiphy_id);
		if (!wiphy)
			return;

		if (!wiphy_update_reg_domain(wiphy, false, msg))
			return;

		break;
	default:
		return;
	}

	wiphy_dump_after_regdom(wiphy);
}

static void wiphy_radio_work_next(struct wiphy *wiphy)
{
	struct wiphy_radio_work_item *work;
	bool done;

	work = l_queue_peek_head(wiphy->work);
	if (!work)
		return;

	/*
	 * Ensures no other work item will get inserted before this one while
	 * the work is being done.
	 */
	work->priority = INT_MIN;

	l_debug("Starting work item %u", work->id);

	wiphy->work_in_callback = true;
	done = work->ops->do_work(work);
	wiphy->work_in_callback = false;

	if (done) {
		work->id = 0;

		l_queue_remove(wiphy->work, work);

		wiphy->work_in_callback = true;
		destroy_work(work);
		wiphy->work_in_callback = false;

		wiphy_radio_work_next(wiphy);
	}
}

static int insert_by_priority(const void *a, const void *b, void *user_data)
{
	const struct wiphy_radio_work_item *new = a;
	const struct wiphy_radio_work_item *work = b;

	if (work->priority <= new->priority)
		return 1;

	return -1;
}

uint32_t wiphy_radio_work_insert(struct wiphy *wiphy,
				struct wiphy_radio_work_item *item,
				int priority,
				const struct wiphy_radio_work_item_ops *ops)
{
	item->priority = priority;
	item->ops = ops;
	item->id = ++work_ids;

	l_debug("Inserting work item %u", item->id);

	l_queue_insert(wiphy->work, item, insert_by_priority, NULL);

	if (l_queue_length(wiphy->work) == 1 && !wiphy->work_in_callback)
		wiphy_radio_work_next(wiphy);

	return item->id;
}

static bool match_id(const void *a, const void *b)
{
	const struct wiphy_radio_work_item *item = a;

	if (item->id == L_PTR_TO_UINT(b))
		return true;

	return false;
}

void wiphy_radio_work_done(struct wiphy *wiphy, uint32_t id)
{
	struct wiphy_radio_work_item *item;
	bool next = false;

	item = l_queue_peek_head(wiphy->work);
	if (!item)
		return;

	if (item->id == id) {
		next = true;
		l_queue_pop_head(wiphy->work);
	} else
		item = l_queue_remove_if(wiphy->work, match_id,
						L_UINT_TO_PTR(id));
	if (!item)
		return;

	l_debug("Work item %u done", id);

	item->id = 0;

	wiphy->work_in_callback = true;
	destroy_work(item);
	wiphy->work_in_callback = false;

	if (next)
		wiphy_radio_work_next(wiphy);
}

int wiphy_radio_work_is_running(struct wiphy *wiphy, uint32_t id)
{
	struct wiphy_radio_work_item *item = l_queue_find(wiphy->work, match_id,
							L_UINT_TO_PTR(id));
	if (!item)
		return -ENOENT;

	return item == l_queue_peek_head(wiphy->work) ? 1 : 0;
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

	if (!l_genl_family_register(nl80211, NL80211_MULTICAST_GROUP_REG,
					wiphy_reg_notify, NULL, NULL))
		l_error("Registering for regulatory notifications failed");

	return 0;
}

static void wiphy_exit(void)
{
	l_strfreev(whitelist_filter);
	l_strfreev(blacklist_filter);

	if (wiphy_dump_id) {
		l_genl_family_cancel(nl80211, wiphy_dump_id);
		wiphy_dump_id = 0;
	}

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
