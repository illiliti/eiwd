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

#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <alloca.h>
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "ell/useful.h"

#include "src/missing.h"
#include "src/module.h"
#include "src/ie.h"
#include "src/crypto.h"
#include "src/iwd.h"
#include "src/common.h"
#include "src/storage.h"
#include "src/scan.h"
#include "src/dbus.h"
#include "src/agent.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/station.h"
#include "src/eap.h"
#include "src/knownnetworks.h"
#include "src/network.h"
#include "src/blacklist.h"
#include "src/util.h"
#include "src/erp.h"
#include "src/handshake.h"
#include "src/band.h"

#define SAE_PT_SETTING "SAE-PT-Group%u"

static uint32_t known_networks_watch;
static uint32_t event_watch;

struct network {
	char ssid[33];
	enum security security;
	char *object_path;
	struct station *station;
	struct network_info *info;
	unsigned char *psk;
	char *passphrase;
	char *password_identifier;
	struct l_ecc_point *sae_pt_19; /* SAE PT for Group 19 */
	struct l_ecc_point *sae_pt_20; /* SAE PT for Group 20 */
	unsigned int agent_request;
	struct l_queue *bss_list;
	struct l_settings *settings;
	struct l_queue *secrets;
	struct l_queue *blacklist; /* temporary blacklist for BSS's */
	uint8_t hessid[6];
	char **nai_realms;
	uint8_t *rc_ie;
	bool sync_settings:1;  /* should settings be synced on connect? */
	bool ask_passphrase:1; /* Whether we should force-ask agent */
	bool is_hs20:1;
	bool anqp_pending:1;	/* Set if there is a pending ANQP request */
	bool owe_hidden_pending:1;
	bool provisioning_hidden:1;
	uint8_t transition_disable; /* Temporary cache until info is set */
	bool have_transition_disable:1;
	bool force_default_ecc_group:1;
	int rank;
	/* Holds DBus Connect() message if it comes in before ANQP finishes */
	struct l_dbus_message *connect_after_anqp;
	struct l_dbus_message *connect_after_owe_hidden;
};

static bool network_settings_load(struct network *network)
{
	if (network->settings)
		return true;

	if (network->info)
		network->settings = network_info_open_settings(network->info);

	return network->settings != NULL;
}

static void network_reset_psk(struct network *network)
{
	if (network->psk)
		explicit_bzero(network->psk, 32);

	l_free(network->psk);
	network->psk = NULL;
}

static void network_reset_passphrase(struct network *network)
{
	if (network->passphrase) {
		explicit_bzero(network->passphrase,
				strlen(network->passphrase));
		l_free(network->passphrase);
		network->passphrase = NULL;
	}

	if (network->password_identifier) {
		explicit_bzero(network->password_identifier,
				strlen(network->password_identifier));
		l_free(network->password_identifier);
		network->password_identifier = NULL;
	}

	if (network->sae_pt_19) {
		l_ecc_point_free(network->sae_pt_19);
		network->sae_pt_19 = NULL;
	}

	if (network->sae_pt_20) {
		l_ecc_point_free(network->sae_pt_20);
		network->sae_pt_20 = NULL;
	}
}

static void network_settings_close(struct network *network)
{
	if (!network->settings)
		return;

	network_reset_psk(network);
	network_reset_passphrase(network);

	l_settings_free(network->settings);
	network->settings = NULL;
}

static bool network_secret_check_cacheable(void *data, void *user_data)
{
	struct eap_secret_info *secret = data;

	if (secret->cache_policy == EAP_CACHE_NEVER) {
		eap_secret_info_free(secret);
		return true;
	}

	return false;
}

void network_connected(struct network *network)
{
	enum security security = network_get_security(network);
	const char *ssid = network_get_ssid(network);
	int err;

	if (!network->info) {
		/*
		 * This is an open network seen for the first time:
		 *
		 * Write a settings file to keep track of the
		 * last connected time.  This will also make iwd autoconnect
		 * to this network in the future.
		 */
		if (!network->settings)
			network->settings = l_settings_new();

		storage_network_sync(security, ssid, network->settings);
	} else {
		err = network_info_touch(network->info);
		if (err < 0)
			l_error("Error %i touching network config", err);

		/* Syncs frequencies of already known network*/
		known_network_frequency_sync(network->info);
	}

	l_queue_foreach_remove(network->secrets,
				network_secret_check_cacheable, network);

	l_queue_clear(network->blacklist, NULL);

	network->provisioning_hidden = false;
}

void network_disconnected(struct network *network)
{
	network_settings_close(network);

	l_queue_clear(network->blacklist, NULL);

	if (network->provisioning_hidden)
		station_hide_network(network->station, network);
}

/* First 64 entries calculated by 1 / pow(n, 0.3) for n >= 1 */
static const double rankmod_table[] = {
	1.0000000000, 0.8122523964, 0.7192230933, 0.6597539554,
	0.6170338627, 0.5841906811, 0.5577898253, 0.5358867313,
	0.5172818580, 0.5011872336, 0.4870596972, 0.4745102806,
	0.4632516708, 0.4530661223, 0.4437850034, 0.4352752816,
	0.4274303178, 0.4201634287, 0.4134032816, 0.4070905315,
	0.4011753236, 0.3956154062, 0.3903746872, 0.3854221125,
	0.3807307877, 0.3762772797, 0.3720410580, 0.3680040435,
	0.3641502401, 0.3604654325, 0.3569369365, 0.3535533906,
	0.3503045821, 0.3471812999, 0.3441752105, 0.3412787518,
	0.3384850430, 0.3357878061, 0.3331812996, 0.3306602598,
	0.3282198502, 0.3258556179, 0.3235634544, 0.3213395618,
	0.3191804229, 0.3170827751, 0.3150435863, 0.3130600345,
	0.3111294892, 0.3092494947, 0.3074177553, 0.3056321221,
	0.3038905808, 0.3021912409, 0.3005323264, 0.2989121662,
	0.2973291870, 0.2957819051, 0.2942689208, 0.2927889114,
	0.2913406263, 0.2899228820, 0.2885345572, 0.2871745887,
};

bool network_rankmod(const struct network *network, double *rankmod)
{
	struct network_info *info = network->info;
	int n;
	int nmax;

	/*
	 * Current policy is that only networks successfully connected
	 * to at least once are autoconnectable.  Known Networks that
	 * we have never connected to are not.
	 */
	if (!info || !info->config.connected_time)
		return false;

	n = known_network_offset(network->info);
	if (n < 0)
		return false;

	nmax = L_ARRAY_SIZE(rankmod_table);

	if (n >= nmax)
		n = nmax - 1;

	*rankmod = rankmod_table[n];

	return true;
}

struct network *network_create(struct station *station, const char *ssid,
				enum security security)
{
	struct network *network;

	network = l_new(struct network, 1);
	network->station = station;
	strcpy(network->ssid, ssid);
	network->security = security;

	network->info = known_networks_find(ssid, security);
	if (network->info) {
		network->info->seen_count++;
		if (network->info->config.ecc_group ==
						KNOWN_NETWORK_ECC_GROUP_DEFAULT)
			network->force_default_ecc_group = true;
	}

	network->bss_list = l_queue_new();
	network->blacklist = l_queue_new();

	return network;
}

const char *network_get_ssid(const struct network *network)
{
	return network->ssid;
}

const char *network_get_path(const struct network *network)
{
	return network->object_path;
}

enum security network_get_security(const struct network *network)
{
	return network->security;
}

static const uint8_t *network_get_psk(struct network *network)
{
	int r;

	if (network->psk)
		return network->psk;

	network->psk = l_malloc(32);

	if ((r = crypto_psk_from_passphrase(network->passphrase,
					(unsigned char *)network->ssid,
					strlen(network->ssid),
					network->psk)) < 0) {
		l_free(network->psk);
		network->psk = NULL;
		l_error("PSK generation failed: %s.", strerror(-r));
	} else
		network->sync_settings = true;

	return network->psk;
}

static struct l_ecc_point *network_generate_sae_pt(struct network *network,
							unsigned int group)
{
	struct l_ecc_point *pt;

	l_debug("Generating PT for Group %u", group);

	pt = crypto_derive_sae_pt_ecc(group, network->ssid,
						network->passphrase,
						network->password_identifier);
	if (!pt)
		l_warn("SAE PT generation for Group %u failed", group);

	return pt;
}

static bool __network_set_passphrase(struct network *network,
							const char *passphrase)
{
	if (!passphrase || !crypto_passphrase_is_valid(passphrase))
		return false;

	network_reset_passphrase(network);
	network->passphrase = l_strdup(passphrase);

	network->sae_pt_19 = network_generate_sae_pt(network, 19);
	network->sae_pt_20 = network_generate_sae_pt(network, 20);

	network->sync_settings = true;

	return true;
}

bool network_set_passphrase(struct network *network, const char *passphrase)
{
	if (network_get_security(network) != SECURITY_PSK)
		return false;

	if (!network_settings_load(network))
		network->settings = l_settings_new();

	return __network_set_passphrase(network, passphrase);
}

bool network_set_psk(struct network *network, const uint8_t *psk)
{
	if (network_get_security(network) != SECURITY_PSK)
		return false;

	if (!network_settings_load(network))
		network->settings = l_settings_new();

	network_reset_psk(network);
	network->psk = l_memdup(psk, 32);
	return true;
}

int network_set_transition_disable(struct network *network,
					const uint8_t *td, size_t len)
{
	struct network_info *info = network->info;
	/* We only recognize bits 0, 2, 3 */
	uint8_t supported_bitmask = 0x0d;

	if (len < 1)
		return -EBADMSG;

	network->have_transition_disable = true;
	network->transition_disable = td[0] & supported_bitmask;

	if (info && info->config.have_transition_disable &&
			info->config.transition_disable ==
					network->transition_disable)
		return 0;

	network->sync_settings = true;

	return 0;
}

int network_get_signal_strength(const struct network *network)
{
	struct scan_bss *best_bss = l_queue_peek_head(network->bss_list);

	return best_bss->signal_strength;
}

struct l_settings *network_get_settings(const struct network *network)
{
	return network->settings;
}

struct station *network_get_station(const struct network *network)
{
	return network->station;
}

static bool network_set_8021x_secrets(struct network *network)
{
	const struct l_queue_entry *entry;

	if (!network->settings)
		return false;

	for (entry = l_queue_get_entries(network->secrets); entry;
			entry = entry->next) {
		struct eap_secret_info *secret = entry->data;
		char *setting;

		switch (secret->type) {
		case EAP_SECRET_LOCAL_PKEY_PASSPHRASE:
		case EAP_SECRET_REMOTE_PASSWORD:
			if (!l_settings_set_string(network->settings,
							"Security", secret->id,
							secret->value))
				return false;
			break;

		case EAP_SECRET_REMOTE_USER_PASSWORD:
			if (!l_settings_set_string(network->settings,
							"Security", secret->id,
							secret->value))
				return false;

			if (secret->id2)
				setting = secret->id2;
			else {
				setting = alloca(strlen(secret->id) + 10);
				sprintf(setting, "%s-Password", secret->id);
			}

			if (!l_settings_set_string(network->settings,
							"Security", setting,
							secret->value + 1 +
							strlen(secret->value)))
				return false;

			break;
		}
	}

	return true;
}

static int network_set_handshake_secrets_psk(struct network *network,
						struct handshake_state *hs)
{
	/* SAE will generate/set the PMK */
	if (IE_AKM_IS_SAE(hs->akm_suite)) {
		if (!network->passphrase)
			return -ENOKEY;

		handshake_state_set_passphrase(hs, network->passphrase);

		if (network->password_identifier)
			handshake_state_set_password_identifier(hs,
						network->password_identifier);

		if (ie_rsnxe_capable(hs->authenticator_rsnxe,
							IE_RSNX_SAE_H2E)) {
			l_debug("Authenticator is SAE H2E capable");
			handshake_state_add_ecc_sae_pt(hs, network->sae_pt_19);
			handshake_state_add_ecc_sae_pt(hs, network->sae_pt_20);
		}
	} else {
		const uint8_t *psk = network_get_psk(network);

		if (!psk)
			return -ENOKEY;

		handshake_state_set_pmk(hs, psk, 32);
	}

	return 0;
}

int network_handshake_setup(struct network *network, struct scan_bss *bss,
						struct handshake_state *hs)
{
	struct station *station = network->station;
	struct wiphy *wiphy = station_get_wiphy(station);
	struct l_settings *settings = network->settings;
	const struct l_settings *config = iwd_get_config();
	struct network_info *info = network->info;
	uint32_t eapol_proto_version;
	uint8_t new_addr[ETH_ALEN];
	int r;
	const char *str;

	switch (network->security) {
	case SECURITY_PSK:
		/* Check the BSS password ID settings match our configuration */
		if (bss->sae_pw_id_exclusive && !network->password_identifier) {
			l_error("[Security].PasswordIdentifier is not set but "
				"BSS requires SAE password identifiers");
			return -ENOKEY;
		}

		if (!bss->sae_pw_id_used && network->password_identifier) {
			l_error("[Security].PasswordIdentifier set but BSS "
				"does not not use password identifiers");
			return -ENOKEY;
		}

		r = network_set_handshake_secrets_psk(network, hs);
		if (r < 0)
			return r;

		break;
	case SECURITY_8021X:
		handshake_state_set_8021x_config(hs, settings);
		break;
	case SECURITY_NONE:
		break;
	case SECURITY_WEP:
		return -ENOTSUP;
	}

	handshake_state_set_ssid(hs, bss->ssid, bss->ssid_len);

	if (settings && l_settings_get_uint(settings, "EAPoL",
						"ProtocolVersion",
						&eapol_proto_version)) {
		if (eapol_proto_version > 3) {
			l_warn("Invalid ProtocolVersion value - should be 0-3");
			eapol_proto_version = 0;
		}

		if (eapol_proto_version)
			l_debug("Overriding EAPoL protocol version to: %u",
					eapol_proto_version);

		handshake_state_set_protocol_version(hs, eapol_proto_version);
	}

	hs->force_default_ecc_group = network->force_default_ecc_group;

	/*
	 * The randomization options in the provisioning file are dependent on
	 * main.conf: [General].AddressRandomization=network. Any other value
	 * should disqualify the three network-specific settings below.
	 */
	str = l_settings_get_value(config, "General", "AddressRandomization");
	if (!(str && !strcmp(str, "network")))
		return 0;

	/*
	 * We have three possible options here:
	 * 1. per-network MAC generation (default, no option in network config)
	 * 2. per-network full MAC randomization
	 * 3. per-network MAC override
	 */
	if (info && info->config.override_addr)
		handshake_state_set_supplicant_address(hs,
							info->config.sta_addr);
	else if (info && info->config.always_random_addr) {
		wiphy_generate_random_address(wiphy, new_addr);
		handshake_state_set_supplicant_address(hs, new_addr);
	}

	return 0;
}

static int network_settings_load_pt_ecc(struct network *network,
					unsigned int group,
					struct l_ecc_point **out_pt)
{
	_auto_(l_free) char *key = l_strdup_printf(SAE_PT_SETTING, group);
	size_t pt_len;
	_auto_(l_free) uint8_t *pt = l_settings_get_bytes(network->settings,
						"Security", key, &pt_len);
	const struct l_ecc_curve *curve = l_ecc_curve_from_ike_group((group));

	if (!curve)
		return -EINVAL;

	if (!pt)
		goto generate;

	if (pt_len != l_ecc_curve_get_scalar_bytes(curve) * 2)
		goto bad_format;

	*out_pt = l_ecc_point_from_data(curve, L_ECC_POINT_TYPE_FULL,
								pt, pt_len);
	if (*out_pt)
		return 0;

bad_format:
	l_error("%s profile: invalid %s format", network->ssid, key);

generate:
	if (!network->passphrase)
		return -ENOKEY;

	*out_pt = network_generate_sae_pt(network, group);
	if (*out_pt)
		return 1;

	return -EIO;
}

static inline bool __bss_is_sae(const struct scan_bss *bss,
						const struct ie_rsn_info *rsn)
{
	if (rsn->akm_suites & IE_RSN_AKM_SUITE_SAE_SHA256)
		return true;

	return false;
}

static bool bss_is_sae(const struct scan_bss *bss)
{
	struct ie_rsn_info rsn;

	memset(&rsn, 0, sizeof(rsn));
	scan_bss_get_rsn_info(bss, &rsn);

	return __bss_is_sae(bss, &rsn);
}

static int network_load_psk(struct network *network, struct scan_bss *bss)
{
	/*
	 * A legacy psk file may only contain the PreSharedKey entry. For SAE
	 * networks the raw Passphrase is required. So in this case where
	 * the psk is found but no Passphrase, we ask the agent.  The psk file
	 * will then be re-written to contain the raw passphrase.
	 */
	bool is_sae = bss_is_sae(bss);
	const char *ssid = network_get_ssid(network);
	enum security security = network_get_security(network);
	size_t psk_len;
	_auto_(l_free) uint8_t *psk =
			l_settings_get_bytes(network->settings, "Security",
						"PreSharedKey", &psk_len);
	_auto_(l_free) char *passphrase =
			l_settings_get_string(network->settings,
						"Security", "Passphrase");
	_auto_(l_free) char *password_id =
			l_settings_get_string(network->settings, "Security",
						"PasswordIdentifier");
	_auto_(l_free) char *path =
		storage_get_network_file_path(security, ssid);

	if (psk && psk_len != 32) {
		l_error("%s: invalid PreSharedKey format", path);
		l_free(psk);
		psk = NULL;
		psk_len = 0;
	}

	/* PSK can be generated from the passphrase but not the other way */
	if (!psk || is_sae) {
		if (!passphrase)
			return -ENOKEY;

		if (!crypto_passphrase_is_valid(passphrase)) {
			l_error("%s: invalid Passphrase format", path);
			return -ENOKEY;
		}
	}

	network_reset_passphrase(network);
	network_reset_psk(network);
	network->passphrase = l_steal_ptr(passphrase);
	network->password_identifier = l_steal_ptr(password_id);

	if (network_settings_load_pt_ecc(network, 19, &network->sae_pt_19) > 0)
		network->sync_settings = true;

	if (network_settings_load_pt_ecc(network, 20, &network->sae_pt_20) > 0)
		network->sync_settings = true;

	network->psk = l_steal_ptr(psk);

	return 0;
}

static void network_settings_save_sae_pt_ecc(struct l_settings *settings,
						struct l_ecc_point *pt)
{
	const struct l_ecc_curve *curve = l_ecc_point_get_curve(pt);
	unsigned int group = l_ecc_curve_get_ike_group(curve);
	_auto_(l_free) char *key = l_strdup_printf(SAE_PT_SETTING, group);
	uint8_t buf[256];
	ssize_t len;

	len = l_ecc_point_get_data(pt, buf, sizeof(buf));
	if (len < 0) {
		l_warn("Unable to serialize '%s'", key);
		return;
	}

	l_settings_set_bytes(settings, "Security", key, buf, len);
}

static void network_settings_save(struct network *network,
						struct l_settings *settings)
{
	if (network->have_transition_disable) {
		char *modes[4];
		unsigned int i = 0;

		l_settings_set_bool(settings, NET_TRANSITION_DISABLE, true);

		if (test_bit(&network->transition_disable, 0))
			modes[i++] = "personal";

		if (test_bit(&network->transition_disable, 2))
			modes[i++] = "enterprise";

		if (test_bit(&network->transition_disable, 3))
			modes[i++] = "open";

		modes[i] = NULL;

		l_settings_set_string_list(settings,
					NET_TRANSITION_DISABLE_MODES,
					modes, ' ');
	}

	if (network->security != SECURITY_PSK)
		return;

	/* We only update the [Security] bits here, wipe the group first */
	l_settings_remove_group(settings, "Security");

	if (network->psk)
		l_settings_set_bytes(settings, "Security", "PreSharedKey",
					network->psk, 32);

	if (network->passphrase)
		l_settings_set_string(settings, "Security", "Passphrase",
					network->passphrase);

	if (network->password_identifier)
		l_settings_set_string(settings, "Security",
					"PasswordIdentifier",
					network->password_identifier);

	if (network->sae_pt_19)
		network_settings_save_sae_pt_ecc(settings, network->sae_pt_19);

	if (network->sae_pt_20)
		network_settings_save_sae_pt_ecc(settings, network->sae_pt_20);
}

void network_sync_settings(struct network *network)
{
	struct network_info *info = network->info;

	if (!network->sync_settings)
		return;

	l_debug("");

	network->sync_settings = false;

	/*
	 * Re-open the settings from Disk, in case they were updated
	 * since we last opened them.
	 */
	if (network->info) {
		struct l_settings *fs_settings = info->ops->open(info);

		if (L_WARN_ON(!fs_settings))
			return;

		network_settings_save(network, fs_settings);
		info->ops->sync(info, fs_settings);
		l_settings_free(fs_settings);
		return;
	}

	network_settings_save(network, network->settings);
	storage_network_sync(network->security, network->ssid,
				network->settings);
}

const struct network_info *network_get_info(const struct network *network)
{
	return network->info;
}

void network_set_info(struct network *network, struct network_info *info)
{
	if (info) {
		network->info = info;
		network->info->seen_count++;

		network_update_known_frequencies(network);
	} else {
		network->info->seen_count--;
		network->info = NULL;
	}

	l_dbus_property_changed(dbus_get_bus(), network_get_path(network),
					IWD_NETWORK_INTERFACE, "KnownNetwork");
}

void network_set_force_default_ecc_group(struct network *network)
{
	/* No network info, likely a failed OWE connection */
	if (!network->info) {
		network->force_default_ecc_group = true;
		return;
	}

	/* Profile explicitly wants to try the most secure group */
	if (network->info->config.ecc_group ==
					KNOWN_NETWORK_ECC_GROUP_MOST_SECURE)
		return;

	l_debug("Forcing default group for %s", network->ssid);

	network->force_default_ecc_group = true;
	network->info->config.ecc_group = KNOWN_NETWORK_ECC_GROUP_DEFAULT;
}

bool network_get_force_default_ecc_group(struct network *network)
{
	if (!network->info)
		return network->force_default_ecc_group;

	if (network->info->config.ecc_group == KNOWN_NETWORK_ECC_GROUP_DEFAULT)
		return true;

	return false;
}

int network_can_connect_bss(struct network *network, const struct scan_bss *bss)
{
	struct station *station = network->station;
	struct wiphy *wiphy = station_get_wiphy(station);
	enum security security = network_get_security(network);
	struct network_info *info = network->info;
	struct network_config *config = info ? &info->config : NULL;
	bool can_transition_disable = wiphy_can_transition_disable(wiphy);
	struct ie_rsn_info rsn;
	enum band_freq band;
	int ret;

	switch (security) {
	case SECURITY_NONE:
	case SECURITY_PSK:
	case SECURITY_8021X:
		break;
	default:
		return -ENOSYS;
	}

	if (!band_freq_to_channel(bss->frequency, &band))
		return -ENOTSUP;

	memset(&rsn, 0, sizeof(rsn));
	ret = scan_bss_get_rsn_info(bss, &rsn);
	if (ret < 0) {
		/*
		 * WPA3 Specification Version 3, Section 8
		 * Transition Disable implies PMF, no TKIP, yet
		 * Bit 3 is specified as 'Open system authentication without
		 * encryption'.
		 *
		 * We assume the spec means us to check bit 3 here
		 */
		if (ret == -ENOENT && security == SECURITY_NONE) {
			/*
			 * 802.11ax 12.12.2 - STA shall not use Open System
			 * authentication without encryption
			 */
			if (band == BAND_FREQ_6_GHZ)
				return -EPERM;

			if (!config)
				return 0;

			if (!config->have_transition_disable ||
					!test_bit(&config->transition_disable,
							3))
				return 0;

			if (!can_transition_disable) {
				l_debug("HW not capable of Transition Disable");
				return 0;
			}
		}

		return ret;
	}

	if (!config || !config->have_transition_disable) {
		if (band == BAND_FREQ_6_GHZ)
			goto mfp_no_tkip;

		goto no_transition_disable;
	}

	if (!can_transition_disable) {
		if (band == BAND_FREQ_6_GHZ)
			return -EPERM;

		l_debug("HW not capable of Transition Disable, skip");
		goto no_transition_disable;
	}

	/* WPA3-Personal */
	if (test_bit(&config->transition_disable, 0)) {
		rsn.akm_suites &= ~IE_RSN_AKM_SUITE_PSK;
		rsn.akm_suites &= ~IE_RSN_AKM_SUITE_PSK_SHA256;
		rsn.akm_suites &= ~IE_RSN_AKM_SUITE_FT_USING_PSK;
	}

	/* WPA3-Enterprise */
	if (test_bit(&config->transition_disable, 2))
		rsn.akm_suites &= ~IE_RSN_AKM_SUITE_8021X;

	/* Enhanced Open */
	if (test_bit(&config->transition_disable, 3)) {
		if (!(rsn.akm_suites & IE_RSN_AKM_SUITE_OWE))
			return -EPERM;
	}

mfp_no_tkip:
	/*
	 * WPA3 Specification, v3, Section 8:
	 * - Disable use of WEP and TKIP
	 * - Disallow association without negotiation of PMF
	 */
	rsn.pairwise_ciphers &= ~IE_RSN_CIPHER_SUITE_TKIP;

	if (!rsn.group_management_cipher)
		return -EPERM;

	rsn.mfpr = true;

	/* 802.11ax Section 12.12.2 */
	if (band == BAND_FREQ_6_GHZ) {
		/* STA shall not use the following cipher suite selectors */
		rsn.pairwise_ciphers &= ~IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER;

		/* Basically the STA must use OWE, SAE, or 8021x */
		if (!IE_AKM_IS_SAE(rsn.akm_suites) &&
				!IE_AKM_IS_8021X(rsn.akm_suites) &&
				(!(rsn.akm_suites & IE_RSN_AKM_SUITE_OWE)))
			return -EPERM;
	}

no_transition_disable:
	if (!wiphy_select_cipher(wiphy, rsn.pairwise_ciphers))
		return -ENOTSUP;

	if (!wiphy_select_cipher(wiphy, rsn.group_cipher))
		return -ENOTSUP;

	if (rsn.mfpr && !wiphy_select_cipher(wiphy,
				rsn.group_management_cipher))
		return -EPERM;

	if (!wiphy_select_akm(wiphy, bss, security, &rsn, false))
		return -ENOTSUP;

	return 0;
}

int network_autoconnect(struct network *network, struct scan_bss *bss)
{
	struct station *station = network->station;
	enum security security = network_get_security(network);
	struct network_info *info = network->info;
	struct network_config *config;
	int ret;

	/* already waiting for an agent request, connect in progress */
	if (network->agent_request)
		return -EALREADY;

	if (network->ask_passphrase)
		return -ENOKEY;

	if (!info)
		return -ENOENT;

	config = &info->config;

	if (!config->is_autoconnectable)
		return -EPERM;

	if (!network_settings_load(network))
		return -ENOKEY;

	switch (security) {
	case SECURITY_PSK:
		ret = network_load_psk(network, bss);
		if (ret < 0)
			goto close_settings;

		break;
	case SECURITY_8021X:
	{
		struct l_queue *missing_secrets = NULL;

		ret = eap_check_settings(network->settings, network->secrets,
					"EAP-", true, &missing_secrets);
		if (ret < 0)
			goto close_settings;

		ret = -ENOKEY;
		if (!l_queue_isempty(missing_secrets)) {
			l_queue_destroy(missing_secrets, eap_secret_info_free);
			goto close_settings;
		}

		if (!network_set_8021x_secrets(network))
			goto close_settings;

		break;
	}

	case SECURITY_NONE:
		break;
	default:
		return -ENOTSUP;
	}

	return __station_connect_network(station, network, bss,
						STATION_STATE_CONNECTING_AUTO);

close_settings:
	network_settings_close(network);
	return ret;
}

void network_connect_failed(struct network *network, bool in_handshake)
{
	/*
	 * Connection failed during the handshake phase.  If PSK try asking
	 * for the passphrase once more
	 */
	if (network_get_security(network) == SECURITY_PSK && in_handshake) {
		network->sync_settings = false;
		network->ask_passphrase = true;
	}

	l_queue_destroy(network->secrets, eap_secret_info_free);
	network->secrets = NULL;
}

static bool hotspot_info_matches(struct network *network,
					const struct network_info *info)
{
	struct scan_bss *bss;

	if (!network->is_hs20 || !info->is_hotspot)
		return false;

	bss = network_bss_select(network, true);

	if (network_info_match_hessid(info, bss->hessid))
		return true;

	if (network_info_match_roaming_consortium(info, bss->rc_ie,
							bss->rc_ie[1] + 2,
							NULL))
		return true;

	return false;
}

static bool match_hotspot_network(const struct network_info *info,
					void *user_data)
{
	struct network *network = user_data;

	if (!hotspot_info_matches(network, info))
		return false;

	network_set_info(network, (struct network_info *) info);

	return true;
}

bool network_update_known_frequencies(struct network *network)
{
	const struct l_queue_entry *e;
	struct l_queue *reversed;

	if (!network->info)
		return false;

	reversed = l_queue_new();

	for (e = l_queue_get_entries(network->bss_list); e; e = e->next) {
		struct scan_bss *bss = e->data;

		l_queue_push_head(reversed, bss);
	}

	for (e = l_queue_get_entries(reversed); e; e = e->next) {
		struct scan_bss *bss = e->data;

		known_network_add_frequency(network->info, bss->frequency);
	}

	l_queue_destroy(reversed, NULL);

	return true;
}

const char *__network_path_append_bss(const char *network_path,
					const struct scan_bss *bss)
{
	static char path[256];

	snprintf(path, sizeof(path), "%s/%02x%02x%02x%02x%02x%02x",
			network_path, MAC_STR(bss->addr));

	return path;
}

const char *network_bss_get_path(const struct network *network,
						const struct scan_bss *bss)
{
	return __network_path_append_bss(network->object_path, bss);
}

void network_bss_start_update(struct network *network)
{
	l_queue_destroy(network->bss_list, NULL);
	network->bss_list = l_queue_new();
}

bool network_bss_add(struct network *network, struct scan_bss *bss)
{
	if (!l_queue_insert(network->bss_list, bss, scan_bss_rank_compare,
									NULL))
		return false;

	l_dbus_property_changed(dbus_get_bus(), network->object_path,
				IWD_NETWORK_INTERFACE, "ExtendedServiceSet");

	/* Done if BSS is not HS20 or we already have network_info set */
	if (!bss->hs20_capable)
		return true;

	network->is_hs20 = true;

	if (network->info)
		return true;

	/* Set the network_info to a matching hotspot entry, if found */
	known_networks_foreach(match_hotspot_network, network);

	return true;
}

static bool match_addr(const void *a, const void *b)
{
	const struct scan_bss *bss = a;

	return memcmp(bss->addr, b, 6) == 0;
}

/*
 * Replaces an old scan_bss (if exists) in the bss list with a new bss object.
 * Note this BSS is *not* freed and must be by the caller. scan_bss objects are
 * shared between network/station but station technically owns them.
 */
bool network_bss_update(struct network *network, struct scan_bss *bss)
{
	l_queue_remove_if(network->bss_list, match_addr, bss->addr);

	l_queue_insert(network->bss_list, bss, scan_bss_rank_compare, NULL);

	/* Sync frequency for already known networks */
	if (network->info) {
		known_network_add_frequency(network->info, bss->frequency);
		known_network_frequency_sync(network->info);
	}

	return true;
}

bool network_bss_list_isempty(struct network *network)
{
	return l_queue_isempty(network->bss_list);
}

struct scan_bss *network_bss_list_pop(struct network *network)
{
	return l_queue_pop_head(network->bss_list);
}

struct scan_bss *network_bss_find_by_addr(struct network *network,
						const uint8_t *addr)
{
	return l_queue_find(network->bss_list, match_addr, addr);
}

static bool match_bss(const void *a, const void *b)
{
	return a == b;
}

struct erp_cache_entry *network_get_erp_cache(struct network *network)
{
	struct erp_cache_entry *cache;
	struct l_settings *settings;
	char *check_id;
	const char *identity;
	bool ret;

	settings = network_get_settings(network);
	if (!settings)
		return NULL;

	check_id = l_settings_get_string(settings, "Security", "EAP-Identity");
	if (!check_id)
		return NULL;

	cache = erp_cache_get(network_get_ssid(network));
	if (!cache) {
		l_free(check_id);
		return NULL;
	}

	identity = erp_cache_entry_get_identity(cache);

	ret = strcmp(check_id, identity) == 0;

	l_free(check_id);

	/*
	 * The settings file must have change out from under us. In this
	 * case we want to remove the ERP entry because it is no longer
	 * valid.
	 */
	if (!ret) {
		erp_cache_put(cache);
		erp_cache_remove(identity);
		return NULL;
	}

	return cache;
}

const struct l_queue_entry *network_bss_list_get_entries(
						const struct network *network)
{
	return l_queue_get_entries(network->bss_list);
}

struct scan_bss *network_bss_select(struct network *network,
						bool fallback_to_blacklist)
{
	struct l_queue *bss_list = network->bss_list;
	const struct l_queue_entry *bss_entry;
	struct scan_bss *candidate = NULL;

	for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
			bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;
		int ret = network_can_connect_bss(network, bss);

		if (ret == -ENOSYS)
			return NULL;
		else if (ret < 0)
			continue;

		/*
		 * We only want to record the first (best) candidate. In case
		 * all our BSS's are blacklisted but we still want to connect
		 * we want to hold only this first candidate
		 */
		if (!candidate)
			candidate = bss;

		/* OWE Transition BSS */
		if (bss->owe_trans) {
			/* Don't want to connect to the Open BSS if possible */
			if (!bss->rsne)
				continue;

			/* Candidate is not OWE, set this as new candidate */
			if (!(candidate->owe_trans && candidate->rsne))
				candidate = bss;
		}

		/* check if temporarily blacklisted */
		if (l_queue_find(network->blacklist, match_bss, bss))
			continue;

		if (!blacklist_contains_bss(bss->addr))
			return bss;
	}

	/*
	 * No BSS was found, but if we are falling back to blacklisted BSS's we
	 * can just use the first connectable candidate found above.
	 */
	if (fallback_to_blacklist)
		return candidate;

	return NULL;
}

static void passphrase_callback(enum agent_result result,
				const char *passphrase,
				struct l_dbus_message *message,
				void *user_data)
{
	struct network *network = user_data;
	struct station *station = network->station;
	struct scan_bss *bss;

	l_debug("result %d", result);

	network->agent_request = 0;

	/*
	 * agent will release its reference to message after invoking this
	 * callback.  So if we want this message, we need to take a reference
	 * to it
	 */
	l_dbus_message_ref(message);

	if (result != AGENT_RESULT_OK) {
		dbus_pending_reply(&message, dbus_error_aborted(message));
		goto err;
	}

	bss = network_bss_select(network, true);

	/* Did all good BSSes go away while we waited */
	if (!bss) {
		dbus_pending_reply(&message, dbus_error_failed(message));
		goto err;
	}

	network_reset_psk(network);

	if (!__network_set_passphrase(network, passphrase)) {
		dbus_pending_reply(&message,
				dbus_error_invalid_format(message));
		goto err;
	}

	station_connect_network(station, network, bss, message);
	l_dbus_message_unref(message);
	return;

err:
	network_settings_close(network);

	if (network->provisioning_hidden)
		station_hide_network(station, network);
}

static struct l_dbus_message *network_connect_psk(struct network *network,
					struct scan_bss *bss,
					struct l_dbus_message *message)
{
	struct station *station = network->station;

	if (!network_settings_load(network)) {
		network->settings = l_settings_new();
		network->ask_passphrase = true;
	} else if (!network->ask_passphrase)
		network->ask_passphrase =
			network_load_psk(network, bss) < 0;

	l_debug("ask_passphrase: %s",
		network->ask_passphrase ? "true" : "false");

	if (network->ask_passphrase) {
		network->ask_passphrase = false;

		network->agent_request =
			agent_request_passphrase(network->object_path,
						passphrase_callback,
						message, network, NULL);

		if (!network->agent_request)
			return dbus_error_no_agent(message);
	} else
		station_connect_network(station, network, bss, message);

	return NULL;
}

struct eap_secret_request {
	struct network *network;
	struct eap_secret_info *secret;
	struct l_queue *pending_secrets;
	void (*callback)(enum agent_result result,
				struct l_dbus_message *message,
				struct eap_secret_request *req);
};

static void eap_secret_request_free(void *data)
{
	struct eap_secret_request *req = data;

	eap_secret_info_free(req->secret);
	l_queue_destroy(req->pending_secrets, eap_secret_info_free);
	l_free(req);
}

static bool eap_secret_info_match_local(const void *a, const void *b)
{
	const struct eap_secret_info *info = a;

	return info->type == EAP_SECRET_LOCAL_PKEY_PASSPHRASE;
}

static void eap_password_callback(enum agent_result result, const char *value,
					struct l_dbus_message *message,
					void *user_data)
{
	struct eap_secret_request *req = user_data;

	req->network->agent_request = 0;

	if (value) {
		if (strlen(value) < IWD_MAX_PASSWORD_LEN)
			req->secret->value = l_strdup(value);
		else {
			l_error("EAP password too long");
			result = AGENT_RESULT_FAILED;
		}
	}

	req->callback(result, message, req);
}

static void eap_user_password_callback(enum agent_result result,
					const char *user, const char *passwd,
					struct l_dbus_message *message,
					void *user_data)
{
	struct eap_secret_request *req = user_data;

	req->network->agent_request = 0;

	if (user && passwd) {
		size_t len1 = strlen(user) + 1;
		size_t len2 = strlen(passwd) + 1;

		if (len2 > IWD_MAX_PASSWORD_LEN) {
			l_error("EAP password too long");
			result = AGENT_RESULT_FAILED;
			goto done;
		}

		req->secret->value = l_malloc(len1 + len2);
		memcpy(req->secret->value, user, len1);
		memcpy(req->secret->value + len1, passwd, len2);
	}

done:
	req->callback(result, message, req);
}

static bool eap_send_agent_req(struct network *network,
				struct l_queue *pending_secrets,
				struct l_dbus_message *message,
				void *callback)
{
	struct eap_secret_request *req;
	struct eap_secret_info *info;

	/*
	 * Request the locally-verifiable data first, i.e.
	 * the private key encryption passphrases so that we don't bother
	 * asking for any other data if these passphrases turn out to
	 * be wrong.
	 */
	info = l_queue_remove_if(pending_secrets, eap_secret_info_match_local,
					NULL);

	if (!info)
		info = l_queue_pop_head(pending_secrets);

	req = l_new(struct eap_secret_request, 1);
	req->network = network;
	req->secret = info;
	req->pending_secrets = pending_secrets;
	req->callback = callback;

	switch (info->type) {
	case EAP_SECRET_LOCAL_PKEY_PASSPHRASE:
		network->agent_request = agent_request_pkey_passphrase(
						network->object_path,
						eap_password_callback,
						message, req,
						eap_secret_request_free);
		break;
	case EAP_SECRET_REMOTE_PASSWORD:
		network->agent_request = agent_request_user_password(
						network->object_path,
						info->parameter,
						eap_password_callback,
						message, req,
						eap_secret_request_free);
		break;
	case EAP_SECRET_REMOTE_USER_PASSWORD:
		network->agent_request = agent_request_user_name_password(
						network->object_path,
						eap_user_password_callback,
						message, req,
						eap_secret_request_free);
		break;
	}

	if (network->agent_request)
		return true;

	eap_secret_request_free(req);
	return false;
}

static struct l_dbus_message *network_connect_8021x(struct network *network,
						struct scan_bss *bss,
						struct l_dbus_message *message);

static void eap_secret_done(enum agent_result result,
				struct l_dbus_message *message,
				struct eap_secret_request *req)
{
	struct network *network = req->network;
	struct eap_secret_info *secret = req->secret;
	struct l_queue *pending = req->pending_secrets;
	struct scan_bss *bss;

	l_debug("result %d", result);

	/*
	 * Agent will release its reference to message after invoking this
	 * callback.  So if we want this message, we need to take a reference
	 * to it.
	 */
	l_dbus_message_ref(message);

	if (result != AGENT_RESULT_OK) {
		dbus_pending_reply(&message, dbus_error_aborted(message));
		goto err;
	}

	bss = network_bss_select(network, true);

	/* Did all good BSSes go away while we waited */
	if (!bss) {
		dbus_pending_reply(&message, dbus_error_failed(message));
		goto err;
	}

	if (!network->secrets)
		network->secrets = l_queue_new();

	l_queue_push_tail(network->secrets, secret);

	req->secret = NULL;

	/*
	 * If we have any other missing secrets in the queue, send the
	 * next request immediately unless we've just received a passphrase
	 * for a local private key.  In that case we will first call
	 * network_connect_8021x to have it validate the new passphrase.
	 */
	if (secret->type == EAP_SECRET_LOCAL_PKEY_PASSPHRASE ||
			l_queue_isempty(req->pending_secrets)) {
		struct l_dbus_message *reply;

		reply = network_connect_8021x(network, bss, message);
		if (reply)
			dbus_pending_reply(&message, reply);
		else
			l_dbus_message_unref(message);

		return;
	}

	req->pending_secrets = NULL;

	if (eap_send_agent_req(network, pending, message,
				eap_secret_done)) {
		l_dbus_message_unref(message);
		return;
	}

	dbus_pending_reply(&message, dbus_error_no_agent(message));
err:
	network_settings_close(network);
}

static struct l_dbus_message *network_connect_8021x(struct network *network,
						struct scan_bss *bss,
						struct l_dbus_message *message)
{
	struct station *station = network->station;
	int r;
	struct l_queue *missing_secrets = NULL;
	struct l_dbus_message *reply;

	l_debug("");

	r = eap_check_settings(network->settings, network->secrets, "EAP-",
				true, &missing_secrets);
	if (r) {
		if (r == -EUNATCH)
			reply = dbus_error_not_available(message);
		else if (r == -ENOTSUP)
			reply = dbus_error_not_supported(message);
		else if (r == -EACCES)
			reply = dbus_error_failed(message);
		else
			reply = dbus_error_not_configured(message);

		goto error;
	}

	l_debug("supplied %u secrets, %u more needed for EAP",
		l_queue_length(network->secrets),
		l_queue_length(missing_secrets));

	if (l_queue_isempty(missing_secrets)) {
		if (!network_set_8021x_secrets(network)) {
			reply = dbus_error_failed(message);

			goto error;
		}

		station_connect_network(station, network, bss, message);

		return NULL;
	}

	if (eap_send_agent_req(network, missing_secrets, message,
				eap_secret_done))
		return NULL;

	reply = dbus_error_no_agent(message);

error:
	network_settings_close(network);

	l_queue_destroy(network->secrets, eap_secret_info_free);
	network->secrets = NULL;

	return reply;
}

struct l_dbus_message *__network_connect(struct network *network,
						struct scan_bss *bss,
						struct l_dbus_message *message)
{
	struct station *station = network->station;

	switch (network_get_security(network)) {
	case SECURITY_PSK:
		return network_connect_psk(network, bss, message);
	case SECURITY_NONE:
		if (network->connect_after_owe_hidden)
			return dbus_error_busy(message);

		/* Save message and connect after OWE hidden scan is done */
		if (network->owe_hidden_pending) {
			network->connect_after_owe_hidden =
						l_dbus_message_ref(message);
			l_debug("Pending OWE hidden scan, delaying connect");
			return NULL;
		}

		station_connect_network(station, network, bss, message);
		return NULL;
	case SECURITY_8021X:
		if (network->connect_after_anqp)
			return dbus_error_busy(message);

		/*
		 * If there is an ongoing ANQP request we must wait for that to
		 * finish. Save the message and wait for the ANQP watch to
		 * fire
		 */
		if (network->anqp_pending) {
			network->connect_after_anqp =
						l_dbus_message_ref(message);
			l_debug("Pending ANQP request, delaying connect to %s",
						network->ssid);
			return NULL;
		}

		if (!network_settings_load(network))
			return dbus_error_not_configured(message);

		return network_connect_8021x(network, bss, message);
	default:
		return dbus_error_not_supported(message);
	}
}

static struct l_dbus_message *network_connect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct network *network = user_data;
	struct station *station = network->station;
	struct scan_bss *bss;

	l_debug("");

	if (network == station_get_connected_network(station))
		/*
		 * The requested network is already connected, return success.
		 */
		return l_dbus_message_new_method_return(message);

	if (network->agent_request)
		return dbus_error_busy(message);

	/*
	 * Select the best BSS to use at this time.  If we have to query the
	 * agent this may not be the final choice because BSS visibility can
	 * change while we wait for the agent.
	 */
	bss = network_bss_select(network, true);

	/* None of the BSSes is compatible with our stack */
	if (!bss)
		return dbus_error_not_supported(message);

	return __network_connect(network, bss, message);
}

/*
 * Returns an error message in case an error occurs.  Otherwise this function
 * returns NULL and takes a reference to message.  Callers should unref
 * their copy in this case
 */
struct l_dbus_message *network_connect_new_hidden_network(
						struct network *network,
						struct l_dbus_message *message)
{
	struct station *station = network->station;
	struct scan_bss *bss;

	l_debug("");

	if (network->agent_request)
		return dbus_error_busy(message);

	/*
	 * This is not a Known Network.  If connection succeeds, either
	 * network_sync_settings or network_connected will save this network
	 * as hidden and trigger an update to the hidden networks count.
	 */

	bss = network_bss_select(network, true);
	/* This should never happened for the hidden networks. */
	if (!bss)
		return dbus_error_not_supported(message);

	network->settings = l_settings_new();
	l_settings_set_bool(network->settings, NET_HIDDEN, true);

	switch (network_get_security(network)) {
	case SECURITY_PSK:
		network->provisioning_hidden = true;
		return network_connect_psk(network, bss, message);
	case SECURITY_NONE:
		network->provisioning_hidden = true;
		station_connect_network(station, network, bss, message);
		return NULL;
	default:
		break;
	}

	return dbus_error_not_supported(message);
}

void network_blacklist_add(struct network *network, struct scan_bss *bss)
{
	l_queue_push_head(network->blacklist, bss);
}

static bool network_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network *network = user_data;

	l_dbus_message_builder_append_basic(builder, 's',
						network_get_ssid(network));
	return true;
}

static bool network_property_is_connected(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network *network = user_data;
	struct station *station = network->station;
	bool connected;

	connected = station_get_connected_network(station) == network;
	l_dbus_message_builder_append_basic(builder, 'b', &connected);
	return true;
}

static bool network_property_get_device(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network *network = user_data;
	struct station *station = network->station;
	struct netdev *netdev = station_get_netdev(station);

	l_dbus_message_builder_append_basic(builder, 'o',
						netdev_get_path(netdev));

	return true;
}

static bool network_property_get_type(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)

{
	struct network *network = user_data;
	enum security security = network_get_security(network);

	l_dbus_message_builder_append_basic(builder, 's',
						security_to_str(security));

	return true;
}

static bool network_property_get_known_network(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network *network = user_data;

	if (!network->info)
		return false;

	l_dbus_message_builder_append_basic(builder, 'o',
					network_info_get_path(network->info));

	return true;
}

static bool network_property_get_extended_service_set(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network *network = user_data;
	const struct l_queue_entry *e;

	l_dbus_message_builder_enter_array(builder, "o");

	for (e = l_queue_get_entries(network->bss_list); e; e = e->next) {
		struct scan_bss *bss = e->data;
		const char *path = network_bss_get_path(network, bss);

		l_dbus_message_builder_append_basic(builder, 'o', path);
	}

	l_dbus_message_builder_leave_array(builder);

	return true;
}

bool network_register(struct network *network, const char *path)
{
	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
					IWD_NETWORK_INTERFACE, network)) {
		l_info("Unable to register %s interface",
						IWD_NETWORK_INTERFACE);
		return false;
	}

	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
					L_DBUS_INTERFACE_PROPERTIES, network))
		l_info("Unable to register %s interface",
						L_DBUS_INTERFACE_PROPERTIES);

	network->object_path = l_strdup(path);

	return true;
}

static void network_unregister(struct network *network, int reason)
{
	struct l_dbus *dbus = dbus_get_bus();

	if (network->connect_after_anqp)
		dbus_pending_reply(&network->connect_after_anqp,
			dbus_error_aborted(network->connect_after_anqp));

	if (network->connect_after_owe_hidden)
		dbus_pending_reply(&network->connect_after_owe_hidden,
			dbus_error_aborted(network->connect_after_owe_hidden));

	agent_request_cancel(network->agent_request, reason);
	network_settings_close(network);

	l_dbus_unregister_object(dbus, network->object_path);

	l_free(network->object_path);
	network->object_path = NULL;
}

void network_remove(struct network *network, int reason)
{
	if (network->object_path)
		network_unregister(network, reason);

	l_queue_destroy(network->secrets, eap_secret_info_free);
	network->secrets = NULL;

	if (network->info)
		network->info->seen_count -= 1;

	l_queue_destroy(network->bss_list, NULL);
	l_queue_destroy(network->blacklist, NULL);

	if (network->nai_realms)
		l_strv_free(network->nai_realms);

	if (network->rc_ie)
		l_free(network->rc_ie);

	l_free(network);
}

int network_rank_compare(const void *a, const void *b, void *user)
{
	const struct network *new_network = a;
	const struct network *network = b;

	return (network->rank > new_network->rank) ? 1 : -1;
}

void network_rank_update(struct network *network, bool connected)
{
	static const double RANK_RSNE_FACTOR = 1.2;
	static const double RANK_WPA_FACTOR = 1.0;
	static const double RANK_OPEN_FACTOR = 0.5;
	static const double RANK_NO_PRIVACY_FACTOR = 0.5;
	/*
	 * Theoretically there may be difference between the BSS selection
	 * here and in network_bss_select but those should be rare cases.
	 */
	struct scan_bss *best_bss = l_queue_peek_head(network->bss_list);
	struct network_info *info = network->info;

	/*
	 * The rank should separate networks into four groups that use
	 * non-overlapping ranges for:
	 *   - current connected network,
	 *   - other networks we've connected to before,
	 *   - networks with preprovisioned settings file that we haven't
	 *     used yet,
	 *   - other networks.
	 *
	 * Within the 2nd group the last connection time is the main factor,
	 * for the other two groups it's the BSS rank - mainly signal strength.
	 */
	if (connected) {
		network->rank = INT_MAX;
		return;
	}

	if (!info) { /* Not known, assign negative rank */
		network->rank = (int) best_bss->rank - USHRT_MAX;
		return;
	}

	if (info->config.connected_time != 0) {
		int n = known_network_offset(info);

		L_WARN_ON(n < 0);

		if (n >= (int) L_ARRAY_SIZE(rankmod_table))
			n = L_ARRAY_SIZE(rankmod_table) - 1;

		network->rank = rankmod_table[n] * best_bss->rank + USHRT_MAX;
	} else
		network->rank = best_bss->rank;

	/*
	 * Prefer RSNE first, WPA second.  Open networks are much less
	 * desirable.
	 */
	if (best_bss->rsne)
		network->rank *= RANK_RSNE_FACTOR;
	else if (best_bss->wpa)
		network->rank *= RANK_WPA_FACTOR;
	else
		network->rank *= RANK_OPEN_FACTOR;

	/* We prefer networks with CAP PRIVACY */
	if (!(best_bss->capability & IE_BSS_CAP_PRIVACY))
		network->rank *= RANK_NO_PRIVACY_FACTOR;
}

static void network_unset_hotspot(struct network *network, void *user_data)
{
	struct network_info *info = user_data;

	if (network->info != info)
		return;

	network_set_info(network, NULL);

	l_queue_destroy(network->secrets, eap_secret_info_free);
	network->secrets = NULL;
}

static void emit_known_network_removed(struct station *station, void *user_data)
{
	struct network_info *info = user_data;
	bool was_hidden = info->config.is_hidden;
	struct network *connected_network;
	struct network *network = NULL;

	/* Clear network info, as this network is no longer known */
	if (info->is_hotspot)
		station_network_foreach(station, network_unset_hotspot, info);
	else {
		network = station_network_find(station, info->ssid, info->type);
		if (!network)
			return;

		network_set_info(network, NULL);

		l_queue_destroy(network->secrets, eap_secret_info_free);
		network->secrets = NULL;
	}

	connected_network = station_get_connected_network(station);
	if (connected_network && connected_network->info == NULL)
		station_disconnect(station);

	if (network && was_hidden)
		station_hide_network(station, network);
}

static void network_update_hotspot(struct network *network, void *user_data)
{
	struct network_info *info = user_data;

	match_hotspot_network(info, network);
}

static void match_known_network(struct station *station, void *user_data)
{
	struct network_info *info = user_data;
	struct network *network;

	if (!info->is_hotspot) {
		network = station_network_find(station, info->ssid, info->type);
		if (!network)
			return;

		network_set_info(network, info);
		return;
	}

	/* This is a new hotspot network */
	station_network_foreach(station, network_update_hotspot, info);
}

static void known_networks_changed(enum known_networks_event event,
					const struct network_info *info,
					void *user_data)
{
	switch (event) {
	case KNOWN_NETWORKS_EVENT_ADDED:
		station_foreach(match_known_network, (void *) info);

		/* Syncs frequencies of newly known network */
		known_network_frequency_sync((struct network_info *)info);
		break;
	case KNOWN_NETWORKS_EVENT_REMOVED:
		station_foreach(emit_known_network_removed, (void *) info);
		break;
	case KNOWN_NETWORKS_EVENT_UPDATED:
		break;
	}
}

static void event_watch_changed(enum station_event state,
				struct network *network, void *user_data)
{
	struct l_dbus_message *reply;

	switch (state) {
	case STATION_EVENT_ANQP_STARTED:
		network->anqp_pending = true;
		break;
	case STATION_EVENT_ANQP_FINISHED:
		network->anqp_pending = false;

		if (!network->connect_after_anqp)
			return;

		l_debug("ANQP complete, resuming connect to %s", network->ssid);

		if (!network_settings_load(network)) {
			reply = dbus_error_not_configured(
						network->connect_after_anqp);
			dbus_pending_reply(&network->connect_after_anqp, reply);
			return;
		}

		reply = network_connect_8021x(network,
					network_bss_select(network, true),
					network->connect_after_anqp);

		if (reply)
			l_dbus_send(dbus_get_bus(), reply);

		l_dbus_message_unref(network->connect_after_anqp);
		network->connect_after_anqp = NULL;

		break;
	case STATION_EVENT_OWE_HIDDEN_STARTED:
		network->owe_hidden_pending = true;
		break;
	case STATION_EVENT_OWE_HIDDEN_FINISHED:
		network->owe_hidden_pending = false;

		if (!network->connect_after_owe_hidden)
			return;

		station_connect_network(network->station, network,
					network_bss_select(network, true),
					network->connect_after_owe_hidden);

		l_dbus_message_unref(network->connect_after_owe_hidden);
		network->connect_after_owe_hidden = NULL;

		break;
	}
}

static void setup_network_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Connect", 0,
				network_connect,
				"", "");

	l_dbus_interface_property(interface, "Name", 0, "s",
					network_property_get_name, NULL);

	l_dbus_interface_property(interface, "Connected", 0, "b",
					network_property_is_connected,
					NULL);

	l_dbus_interface_property(interface, "Device", 0, "o",
					network_property_get_device, NULL);

	l_dbus_interface_property(interface, "Type", 0, "s",
					network_property_get_type, NULL);

	l_dbus_interface_property(interface, "KnownNetwork", 0, "o",
				network_property_get_known_network, NULL);

	l_dbus_interface_property(interface, "ExtendedServiceSet", 0, "ao",
				network_property_get_extended_service_set, NULL);
}

static bool network_bss_property_get_address(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct scan_bss *bss = user_data;

	l_dbus_message_builder_append_basic(builder, 's',
					util_address_to_string(bss->addr));
	return true;
}

static void setup_bss_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, "Address", 0, "s",
					network_bss_property_get_address, NULL);
}

static int network_init(void)
{
	if (!l_dbus_register_interface(dbus_get_bus(), IWD_NETWORK_INTERFACE,
					setup_network_interface, NULL, false))
		l_error("Unable to register %s interface",
						IWD_NETWORK_INTERFACE);

	if (!l_dbus_register_interface(dbus_get_bus(), IWD_BSS_INTERFACE,
					setup_bss_interface, NULL, false))
		l_error("Unable to register %s interface",
						IWD_BSS_INTERFACE);

	known_networks_watch =
		known_networks_watch_add(known_networks_changed, NULL, NULL);

	event_watch = station_add_event_watch(event_watch_changed, NULL, NULL);

	return 0;
}

static void network_exit(void)
{
	known_networks_watch_remove(known_networks_watch);
	known_networks_watch = 0;

	station_remove_event_watch(event_watch);
	event_watch = 0;

	l_dbus_unregister_interface(dbus_get_bus(), IWD_NETWORK_INTERFACE);
	l_dbus_unregister_interface(dbus_get_bus(), IWD_BSS_INTERFACE);
}

IWD_MODULE(network, network_init, network_exit)
IWD_MODULE_DEPENDS(network, known_networks)
