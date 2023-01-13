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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <limits.h>
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "ell/useful.h"
#include "src/util.h"
#include "src/iwd.h"
#include "src/module.h"
#include "src/common.h"
#include "src/watchlist.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/dbus.h"
#include "src/wiphy.h"
#include "src/network.h"
#include "src/knownnetworks.h"
#include "src/ie.h"
#include "src/handshake.h"
#include "src/station.h"
#include "src/blacklist.h"
#include "src/mpdu.h"
#include "src/erp.h"
#include "src/netconfig.h"
#include "src/anqp.h"
#include "src/anqputil.h"
#include "src/diagnostic.h"
#include "src/frame-xchg.h"
#include "src/sysfs.h"
#include "src/band.h"
#include "src/ft.h"
#include "src/eap.h"
#include "src/eap-tls-common.h"
#include "src/storage.h"

static struct l_queue *station_list;
static uint32_t netdev_watch;
static uint32_t mfp_setting;
static uint32_t roam_retry_interval;
static bool anqp_disabled;
static bool supports_arp_evict_nocarrier;
static bool supports_ndisc_evict_nocarrier;
static struct watchlist event_watches;
static uint32_t known_networks_watch;

struct station {
	enum station_state state;
	struct watchlist state_watches;
	struct scan_bss *connected_bss;
	struct network *connected_network;
	struct scan_bss *connect_pending_bss;
	struct network *connect_pending_network;
	struct l_queue *autoconnect_list;
	struct l_queue *bss_list;
	struct l_queue *hidden_bss_list_sorted;
	struct l_hashmap *networks;
	struct l_queue *networks_sorted;
	struct l_dbus_message *connect_pending;
	struct l_dbus_message *hidden_pending;
	struct l_dbus_message *disconnect_pending;
	struct l_dbus_message *scan_pending;
	struct l_dbus_message *get_station_pending;
	struct signal_agent *signal_agent;
	uint32_t dbus_scan_id;
	uint32_t quick_scan_id;
	uint32_t hidden_network_scan_id;
	struct l_queue *owe_hidden_scan_ids;

	/* Roaming related members */
	struct timespec roam_min_time;
	struct l_timeout *roam_trigger_timeout;
	uint32_t roam_scan_id;
	uint8_t preauth_bssid[6];

	struct wiphy *wiphy;
	struct netdev *netdev;

	struct l_queue *anqp_pending;

	struct netconfig *netconfig;

	/* Set of frequencies to scan first when attempting a roam */
	struct scan_freq_set *roam_freqs;
	struct l_queue *roam_bss_list;

	/* Frequencies split into subsets by priority */
	struct scan_freq_set *scan_freqs_order[3];
	unsigned int dbus_scan_subset_idx;

	uint32_t wiphy_watch;

	struct wiphy_radio_work_item ft_work;

	bool preparing_roam : 1;
	bool roam_scan_full : 1;
	bool signal_low : 1;
	bool ap_directed_roaming : 1;
	bool scanning : 1;
	bool autoconnect : 1;
	bool autoconnect_can_start : 1;
};

struct anqp_entry {
	struct station *station;
	struct network *network;
	uint32_t pending;
};

/*
 * Used as entries for the roam list since holding scan_bss pointers directly
 * from station->bss_list is not 100% safe due to the possibility of the
 * hardware scanning and overwriting station->bss_list.
 */
struct roam_bss {
	uint8_t addr[6];
	uint16_t rank;
	int32_t signal_strength;
};

static struct roam_bss *roam_bss_from_scan_bss(const struct scan_bss *bss)
{
	struct roam_bss *rbss = l_new(struct roam_bss, 1);

	memcpy(rbss->addr, bss->addr, 6);
	rbss->rank = bss->rank;
	rbss->signal_strength = bss->signal_strength;

	return rbss;
}

static int roam_bss_rank_compare(const void *a, const void *b, void *user_data)
{
	const struct roam_bss *new_bss = a, *bss = b;

	if (bss->rank == new_bss->rank)
		return (bss->signal_strength >
					new_bss->signal_strength) ? 1 : -1;

	return (bss->rank > new_bss->rank) ? 1 : -1;
}

struct wiphy *station_get_wiphy(struct station *station)
{
	return station->wiphy;
}

struct netdev *station_get_netdev(struct station *station)
{
	return station->netdev;
}

struct network *station_get_connected_network(struct station *station)
{
	return station->connected_network;
}

bool station_is_busy(struct station *station)
{
	return station->state != STATION_STATE_DISCONNECTED &&
			station->state != STATION_STATE_AUTOCONNECT_FULL &&
			station->state != STATION_STATE_AUTOCONNECT_QUICK;
}

static bool station_is_autoconnecting(struct station *station)
{
	return station->state == STATION_STATE_AUTOCONNECT_FULL ||
			station->state == STATION_STATE_AUTOCONNECT_QUICK;
}

static bool station_is_roaming(struct station *station)
{
	return station->state == STATION_STATE_ROAMING ||
			station->state == STATION_STATE_FT_ROAMING ||
			station->state == STATION_STATE_FW_ROAMING;
}

static bool station_debug_event(struct station *station, const char *name)
{
	struct l_dbus_message *signal;

	if (!iwd_is_developer_mode())
		return true;

	l_debug("StationDebug.Event(%s)", name);

	signal = l_dbus_message_new_signal(dbus_get_bus(),
					netdev_get_path(station->netdev),
					IWD_STATION_DEBUG_INTERFACE, "Event");

	l_dbus_message_set_arguments(signal, "sav", name, 0);

	return l_dbus_send(dbus_get_bus(), signal) != 0;
}

static void station_property_set_scanning(struct station *station,
								bool scanning)
{
	if (station->scanning == scanning)
		return;

	station->scanning = scanning;

	l_dbus_property_changed(dbus_get_bus(),
				netdev_get_path(station->netdev),
					IWD_STATION_INTERFACE, "Scanning");
}

static void station_enter_state(struct station *station,
						enum station_state state);

static void network_add_foreach(struct network *network, void *user_data)
{
	struct station *station = user_data;

	l_queue_insert(station->autoconnect_list, network,
				network_rank_compare, NULL);
}

static int station_autoconnect_next(struct station *station)
{
	struct network *network;
	int r;

	if (!station->autoconnect_list)
		return -ENOENT;

	while ((network = l_queue_pop_head(station->autoconnect_list))) {
		const char *ssid = network_get_ssid(network);
		struct scan_bss *bss = network_bss_select(network, false);

		l_debug("autoconnect: Trying SSID: %s", ssid);

		if (!bss) {
			l_debug("autoconnect: No suitable BSSes found");
			continue;
		}

		l_debug("autoconnect: '%s' freq: %u, rank: %u, strength: %i",
			util_address_to_string(bss->addr),
			bss->frequency, bss->rank,
			bss->signal_strength);

		r = network_autoconnect(network, bss);
		if (!r) {
			station_enter_state(station,
						STATION_STATE_CONNECTING_AUTO);

			if (station->quick_scan_id) {
				scan_cancel(netdev_get_wdev_id(station->netdev),
						station->quick_scan_id);
				station->quick_scan_id = 0;
				station_property_set_scanning(station, false);
			}

			return 0;
		}

		l_debug("autoconnect: network_autoconnect: %s (%d)",
							strerror(-r), r);
	}

	return -ENOENT;
}

static void station_autoconnect_start(struct station *station)
{
	if (!station->autoconnect_can_start)
		return;

	if (!station_is_autoconnecting(station))
		return;

	if (!l_queue_isempty(station->anqp_pending))
		return;

	if (!l_queue_isempty(station->owe_hidden_scan_ids))
		return;

	if (L_WARN_ON(station->autoconnect_list))
		l_queue_destroy(station->autoconnect_list, NULL);

	l_debug("");

	station->autoconnect_list = l_queue_new();
	station_network_foreach(station, network_add_foreach, station);
	station_autoconnect_next(station);
	station->autoconnect_can_start = false;
}

static void bss_free(void *data)
{
	struct scan_bss *bss = data;

	scan_bss_free(bss);
}

static void network_free(void *data)
{
	struct network *network = data;

	network_remove(network, -ESHUTDOWN);
}

static bool process_network(const void *key, void *data, void *user_data)
{
	struct network *network = data;
	struct station *station = user_data;

	if (!network_bss_list_isempty(network)) {
		bool connected = network == station->connected_network;

		/* Build the network list ordered by rank */
		network_rank_update(network, connected);

		l_queue_insert(station->networks_sorted, network,
				network_rank_compare, NULL);

		return false;
	}

	/* Drop networks that have no more BSSs in range */
	l_debug("No remaining BSSs for SSID: %s -- Removing network",
			network_get_ssid(network));
	network_remove(network, -ERANGE);

	return true;
}

static const char *iwd_network_get_path(struct station *station,
					const char *ssid,
					enum security security)
{
	static char path[256];
	unsigned int pos, i;

	pos = snprintf(path, sizeof(path), "%s/",
					netdev_get_path(station->netdev));

	for (i = 0; ssid[i] && pos < sizeof(path); i++)
		pos += snprintf(path + pos, sizeof(path) - pos, "%02x",
								ssid[i]);

	snprintf(path + pos, sizeof(path) - pos, "_%s",
				security_to_str(security));

	return path;
}

struct network *station_network_find(struct station *station, const char *ssid,
					enum security security)
{
	const char *path = iwd_network_get_path(station, ssid, security);

	return l_hashmap_lookup(station->networks, path);
}

static int bss_signal_strength_compare(const void *a, const void *b, void *user)
{
	const struct scan_bss *new_bss = a;
	const struct scan_bss *bss = b;

	return (bss->signal_strength > new_bss->signal_strength) ? 1 : -1;
}

/*
 * Returns the network object the BSS was added to or NULL if ignored.
 */
static struct network *station_add_seen_bss(struct station *station,
						struct scan_bss *bss)
{
	struct network *network;
	enum security security;
	const char *path;
	char ssid[33];
	uint32_t kbps100 = DIV_ROUND_CLOSEST(bss->data_rate, 100000);

	l_debug("Processing BSS '%s' with SSID: %s, freq: %u, rank: %u, "
			"strength: %i, data_rate: %u.%u",
			util_address_to_string(bss->addr),
			util_ssid_to_utf8(bss->ssid_len, bss->ssid),
			bss->frequency, bss->rank, bss->signal_strength,
			kbps100 / 10, kbps100 % 10);

	if (util_ssid_is_hidden(bss->ssid_len, bss->ssid)) {
		l_debug("BSS has hidden SSID");

		l_queue_insert(station->hidden_bss_list_sorted, bss,
					bss_signal_strength_compare, NULL);
		return NULL;
	}

	memcpy(ssid, bss->ssid, bss->ssid_len);
	ssid[bss->ssid_len] = '\0';

	if (!(bss->capability & IE_BSS_CAP_ESS)) {
		l_debug("Ignoring non-ESS BSS \"%s\"", ssid);
		return NULL;
	}

	if (scan_bss_get_security(bss, &security) < 0)
		return NULL;

	/* Hidden OWE transition network */
	if (security == SECURITY_NONE && bss->rsne && bss->owe_trans) {
		struct ie_owe_transition_info *info = bss->owe_trans;
		/*
		 * WiFi Alliance OWE Specification v1.1 - Section 2.2.1:
		 *
		 * "2. An OWE AP shall use two different SSIDs, one for OWE
		 *     and one for Open"
		 *
		 * "4. The OWE BSS shall include the OWE Transition Mode element
		 *     in all Beacon and Probe Response frames to encapsulate
		 *     the BSSID and SSID of the Open BSS"
		 *
		 * Meaning the hidden SSID should not match the SSID in the
		 * hidden network's OWE IE. Might as well restrict BSSID as well
		 * to be safe.
		 *
		 * In addition this SSID must be a valid utf8 string otherwise
		 * we could not look up the network. Note that this is not true
		 * for the open BSS IE, it can be non-utf8.
		 */
		if (!util_ssid_is_utf8(info->ssid_len, info->ssid))
			return NULL;

		if (!memcmp(info->ssid, bss->ssid, bss->ssid_len))
			return NULL;

		if (!memcmp(info->bssid, bss->addr, 6))
			return NULL;

		memcpy(ssid, info->ssid, info->ssid_len);
		ssid[info->ssid_len] = '\0';

		l_debug("Found hidden OWE network, using %s for network lookup",
				ssid);
	}

	path = iwd_network_get_path(station, ssid, security);

	network = l_hashmap_lookup(station->networks, path);
	if (!network) {
		network = network_create(station, ssid, security);

		if (!network_register(network, path)) {
			network_remove(network, -EINVAL);
			return NULL;
		}

		l_hashmap_insert(station->networks,
					network_get_path(network), network);
		l_debug("Added new Network \"%s\" security %s",
			network_get_ssid(network), security_to_str(security));
	}

	network_bss_add(network, bss);

	return network;
}

static bool bss_match(const void *a, const void *b)
{
	const struct scan_bss *bss_a = a;
	const struct scan_bss *bss_b = b;

	if (memcmp(bss_a->addr, bss_b->addr, sizeof(bss_a->addr)))
		return false;

	if (bss_a->ssid_len != bss_b->ssid_len)
		return false;

	return !memcmp(bss_a->ssid, bss_b->ssid, bss_a->ssid_len);
}

struct bss_expiration_data {
	struct scan_bss *connected_bss;
	uint64_t now;
	const struct scan_freq_set *freqs;
};

#define SCAN_RESULT_BSS_RETENTION_TIME (30 * 1000000)

static bool bss_free_if_expired(void *data, void *user_data)
{
	struct scan_bss *bss = data;
	struct bss_expiration_data *expiration_data = user_data;

	if (bss == expiration_data->connected_bss)
		/* Do not expire the currently connected BSS. */
		return false;

	/* Keep any BSSes that are not on the frequency list */
	if (!scan_freq_set_contains(expiration_data->freqs, bss->frequency))
		return false;

	if (l_time_before(expiration_data->now,
			bss->time_stamp + SCAN_RESULT_BSS_RETENTION_TIME))
		return false;

	bss_free(bss);

	return true;
}

static void station_bss_list_remove_expired_bsses(struct station *station,
					const struct scan_freq_set *freqs)
{
	struct bss_expiration_data data = {
		.now = l_time_now(),
		.connected_bss = station->connected_bss,
		.freqs = freqs,
	};

	l_queue_foreach_remove(station->bss_list, bss_free_if_expired, &data);
}

struct nai_search {
	struct network *network;
	const char **realms;
};

static bool match_nai_realms(const struct network_info *info, void *user_data)
{
	struct nai_search *search = user_data;

	if (!network_info_match_nai_realm(info, search->realms))
		return false;

	network_set_info(search->network, (struct network_info *) info);

	return true;
}

static bool match_pending(const void *a, const void *b)
{
	const struct anqp_entry *entry = a;

	return entry->pending != 0;
}

static void remove_anqp(void *data)
{
	struct anqp_entry *entry = data;

	if (entry->pending)
		anqp_cancel(entry->pending);

	l_free(entry);
}

static bool anqp_entry_foreach(void *data, void *user_data)
{
	struct anqp_entry *e = data;

	WATCHLIST_NOTIFY(&event_watches, station_event_watch_func_t,
				STATION_EVENT_ANQP_FINISHED, e->network);

	remove_anqp(e);

	return true;
}

static void station_anqp_response_cb(enum anqp_result result,
					const void *anqp, size_t anqp_len,
					void *user_data)
{
	struct anqp_entry *entry = user_data;
	struct station *station = entry->station;
	struct network *network = entry->network;
	struct anqp_iter iter;
	uint16_t id;
	uint16_t len;
	const void *data;
	char **realms = NULL;
	struct nai_search search;

	l_debug("");

	if (result != ANQP_SUCCESS) {
		/* TODO: try next BSS */
		goto request_done;
	}

	anqp_iter_init(&iter, anqp, anqp_len);

	while (anqp_iter_next(&iter, &id, &len, &data)) {
		switch (id) {
		case ANQP_NAI_REALM:
			if (realms)
				break;

			realms = anqp_parse_nai_realms(data, len);
			if (!realms)
				goto request_done;

			break;
		default:
			continue;
		}
	}

	if (!realms)
		goto request_done;

	search.network = network;
	search.realms = (const char **)realms;

	known_networks_foreach(match_nai_realms, &search);

	l_strv_free(realms);

request_done:
	entry->pending = 0;

	/* Return if there are other pending requests */
	if (l_queue_find(station->anqp_pending, match_pending, NULL))
		return;

	/* Notify all watchers now that every ANQP request has finished */
	l_queue_foreach_remove(station->anqp_pending, anqp_entry_foreach, NULL);

	station_autoconnect_start(station);
}

static bool station_start_anqp(struct station *station, struct network *network,
					struct scan_bss *bss)
{
	uint8_t anqp[256];
	uint8_t *ptr = anqp;
	struct anqp_entry *entry;

	if (!bss->hs20_capable)
		return false;

	/* Network already has ANQP data/HESSID */
	if (network_get_info(network))
		return false;

	if (anqp_disabled) {
		l_debug("Not querying AP for ANQP data (disabled)");
		return false;
	}

	entry = l_new(struct anqp_entry, 1);
	entry->station = station;
	entry->network = network;

	l_put_le16(ANQP_QUERY_LIST, ptr);
	ptr += 2;
	l_put_le16(2, ptr);
	ptr += 2;
	l_put_le16(ANQP_NAI_REALM, ptr);
	ptr += 2;
	l_put_le16(ANQP_VENDOR_SPECIFIC, ptr);
	ptr += 2;
	/* vendor length */
	l_put_le16(7, ptr);
	ptr += 2;
	*ptr++ = 0x50;
	*ptr++ = 0x6f;
	*ptr++ = 0x9a;
	*ptr++ = 0x11; /* HS20 ANQP Element type */
	*ptr++ = ANQP_HS20_QUERY_LIST;
	*ptr++ = 0; /* reserved */
	*ptr++ = ANQP_HS20_OSU_PROVIDERS_NAI_LIST;

	/*
	 * TODO: Additional roaming consortiums can be queried if indicated
	 * by the roaming consortium IE. The IE contains up to the first 3, and
	 * these are checked in hs20_find_settings_file.
	 */

	entry->pending = anqp_request(netdev_get_wdev_id(station->netdev),
				netdev_get_address(station->netdev), bss, anqp,
				ptr - anqp, station_anqp_response_cb,
				entry, NULL);
	if (!entry->pending) {
		l_free(entry);
		return false;
	}

	l_queue_push_head(station->anqp_pending, entry);

	WATCHLIST_NOTIFY(&event_watches, station_event_watch_func_t,
				STATION_EVENT_ANQP_STARTED, network);
	return true;
}

static bool network_has_open_pair(struct network *network, struct scan_bss *owe)
{
	const struct l_queue_entry *entry;
	struct ie_owe_transition_info *owe_info = owe->owe_trans;

	for (entry = network_bss_list_get_entries(network); entry;
				entry = entry->next) {
		struct scan_bss *open = entry->data;
		struct ie_owe_transition_info *open_info = open->owe_trans;

		/* AP does not advertise owe transition */
		if (!open_info)
			continue;

		/*
		 * Check if this is an Open/Hidden pair:
		 *
		 * Open SSID equals the SSID in OWE IE
		 * Open BSSID equals the BSSID in OWE IE
		 *
		 * OWE SSID equals the SSID in Open IE
		 * OWE BSSID equals the BSSID in Open IE
		 */
		if (open->ssid_len == owe_info->ssid_len &&
				open_info->ssid_len == owe->ssid_len &&
				!memcmp(open->ssid, owe_info->ssid,
					open->ssid_len) &&
				!memcmp(open_info->ssid, owe->ssid,
					owe->ssid_len) &&
				!memcmp(open->addr, owe_info->bssid, 6) &&
				!memcmp(open_info->bssid, owe->addr, 6))
			return true;
	}

	return false;
}

static bool station_owe_transition_results(int err, struct l_queue *bss_list,
					const struct scan_freq_set *freqs,
					void *userdata)
{
	struct network *network = userdata;
	struct station *station = network_get_station(network);
	struct scan_bss *bss;

	station_property_set_scanning(station, false);

	if (err)
		goto done;

	while ((bss = l_queue_pop_head(bss_list))) {
		/*
		 * Don't handle the open BSS, hidden BSS, BSS with no OWE
		 * Transition IE, or an IE with a non-utf8 SSID
		 */
		if (!bss->rsne || !bss->owe_trans ||
				util_ssid_is_hidden(bss->ssid_len, bss->ssid) ||
				!util_ssid_is_utf8(bss->owe_trans->ssid_len,
							bss->owe_trans->ssid))
			goto free;

		/* Check if we have an open BSS that matches */
		if (!network_has_open_pair(network, bss))
			goto free;

		l_debug("Adding OWE transition network "MAC" to %s",
				MAC_STR(bss->addr), network_get_ssid(network));

		l_queue_push_tail(station->bss_list, bss);
		network_bss_add(network, bss);

		continue;

free:
		scan_bss_free(bss);
	}

	l_queue_destroy(bss_list, NULL);

done:
	l_queue_pop_head(station->owe_hidden_scan_ids);

	WATCHLIST_NOTIFY(&event_watches, station_event_watch_func_t,
				STATION_EVENT_OWE_HIDDEN_FINISHED, network);

	station_autoconnect_start(station);

	return err == 0;
}

static void station_owe_transition_triggered(int err, void *user_data)
{
	struct network *network = user_data;
	struct station *station = network_get_station(network);

	if (err < 0) {
		l_debug("OWE transition scan trigger failed: %i", err);

		l_queue_pop_head(station->owe_hidden_scan_ids);

		WATCHLIST_NOTIFY(&event_watches, station_event_watch_func_t,
				STATION_EVENT_OWE_HIDDEN_FINISHED, network);

		return;
	}

	l_debug("OWE transition scan triggered");

	station_property_set_scanning(station, true);
}

static void foreach_add_owe_scan(struct network *network, void *data)
{
	struct station *station = data;
	const struct l_queue_entry *entry;
	struct l_queue *list = NULL;
	uint32_t id;

	if (network_get_security(network) != SECURITY_NONE)
		return;

	for (entry = network_bss_list_get_entries(network); entry;
				entry = entry->next) {
		struct scan_bss *open = entry->data;

		if (!open->owe_trans)
			continue;

		/* only want the open networks with WFA OWE IE */
		if (open->rsne)
			continue;

		/* BSS already in network object */
		if (network_bss_find_by_addr(network, open->owe_trans->bssid))
			continue;

		if (!list)
			list = l_queue_new();

		l_queue_push_tail(list, open);
	}

	if (!list)
		return;

	id = scan_owe_hidden(netdev_get_wdev_id(station->netdev), list,
				station_owe_transition_triggered,
				station_owe_transition_results, network, NULL);

	l_queue_destroy(list, NULL);

	if (!id)
		return;

	if (!station->owe_hidden_scan_ids)
		station->owe_hidden_scan_ids = l_queue_new();

	l_queue_push_tail(station->owe_hidden_scan_ids, L_UINT_TO_PTR(id));

	WATCHLIST_NOTIFY(&event_watches, station_event_watch_func_t,
				STATION_EVENT_OWE_HIDDEN_STARTED, network);
}

static void station_process_owe_transition_networks(struct station *station)
{
	station_network_foreach(station, foreach_add_owe_scan, station);
}

static bool bss_free_if_ssid_not_utf8(void *data, void *user_data)
{
	struct scan_bss *bss = data;

	if (util_ssid_is_hidden(bss->ssid_len, bss->ssid))
		return false;

	if (util_ssid_is_utf8(bss->ssid_len, bss->ssid))
		return false;

	l_debug("Dropping scan_bss '%s', with non-utf8 SSID",
			util_address_to_string(bss->addr));
	bss_free(bss);
	return true;
}

/*
 * Used when scan results were obtained; either from scan running
 * inside station module or scans running in other state machines, e.g. wsc
 */
void station_set_scan_results(struct station *station,
					struct l_queue *new_bss_list,
					const struct scan_freq_set *freqs,
					bool trigger_autoconnect)
{
	const struct l_queue_entry *bss_entry;
	struct network *network;

	l_queue_foreach_remove(new_bss_list, bss_free_if_ssid_not_utf8, NULL);

	while ((network = l_queue_pop_head(station->networks_sorted)))
		network_bss_list_clear(network);

	l_queue_clear(station->hidden_bss_list_sorted, NULL);

	l_queue_destroy(station->autoconnect_list, NULL);
	station->autoconnect_list = NULL;

	station_bss_list_remove_expired_bsses(station, freqs);

	for (bss_entry = l_queue_get_entries(station->bss_list); bss_entry;
						bss_entry = bss_entry->next) {
		struct scan_bss *old_bss = bss_entry->data;
		struct scan_bss *new_bss;

		new_bss = l_queue_find(new_bss_list, bss_match, old_bss);
		if (new_bss) {
			if (old_bss == station->connected_bss)
				station->connected_bss = new_bss;

			bss_free(old_bss);

			continue;
		}

		if (old_bss == station->connected_bss) {
			l_warn("Connected BSS not in scan results");
			station->connected_bss->rank = 0;
		}

		l_queue_push_tail(new_bss_list, old_bss);
	}

	l_queue_destroy(station->bss_list, NULL);

	for (bss_entry = l_queue_get_entries(new_bss_list); bss_entry;
						bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;
		struct network *network = station_add_seen_bss(station, bss);

		if (!network)
			continue;

		/* Cached BSS entry, this should have been processed already */
		if (!scan_freq_set_contains(freqs, bss->frequency))
			continue;

		station_start_anqp(station, network, bss);
	}

	station->bss_list = new_bss_list;

	l_hashmap_foreach_remove(station->networks, process_network, station);

	station->autoconnect_can_start = trigger_autoconnect;
	station_autoconnect_start(station);
}

static void station_reconnect(struct station *station);

static void station_handshake_event(struct handshake_state *hs,
					enum handshake_event event,
					void *user_data, ...)
{
	struct station *station = user_data;
	struct network *network = station->connected_network;
	va_list args;

	va_start(args, user_data);

	switch (event) {
	case HANDSHAKE_EVENT_STARTED:
		l_debug("Handshaking");
		break;
	case HANDSHAKE_EVENT_SETTING_KEYS:
		l_debug("Setting keys");

		/* If we got here, then our settings work.  Update if needed */
		network_sync_settings(network);
		break;
	case HANDSHAKE_EVENT_FAILED:
		netdev_handshake_failed(hs, va_arg(args, int));
		break;
	case HANDSHAKE_EVENT_REKEY_FAILED:
		l_warn("Unable to securely rekey on this hw/kernel...");
		station_reconnect(station);
		break;
	case HANDSHAKE_EVENT_TRANSITION_DISABLE:
	{
		const uint8_t *td = va_arg(args, const uint8_t *);
		size_t len = va_arg(args, size_t);

		network_set_transition_disable(network, td, len);
		break;
	}
	case HANDSHAKE_EVENT_COMPLETE:
	case HANDSHAKE_EVENT_SETTING_KEYS_FAILED:
	case HANDSHAKE_EVENT_EAP_NOTIFY:
	case HANDSHAKE_EVENT_P2P_IP_REQUEST:
	case HANDSHAKE_EVENT_REKEY_COMPLETE:
		/*
		 * currently we don't care about any other events. The
		 * netdev_connect_cb will notify us when the connection is
		 * complete.
		 */
		break;
	}

	va_end(args);
}

static int station_build_handshake_rsn(struct handshake_state *hs,
					struct wiphy *wiphy,
					struct network *network,
					struct scan_bss *bss)
{
	const struct l_settings *settings = iwd_get_config();
	enum security security = network_get_security(network);
	bool add_mde = false;
	struct erp_cache_entry *erp_cache = NULL;
	struct ie_rsn_info bss_info;
	uint8_t rsne_buf[256];
	struct ie_rsn_info info;
	uint8_t *ap_ie;
	bool disable_ocv;
	enum band_freq band;

	memset(&info, 0, sizeof(info));

	if (!band_freq_to_channel(bss->frequency, &band))
		goto not_supported;

	memset(&bss_info, 0, sizeof(bss_info));
	scan_bss_get_rsn_info(bss, &bss_info);

	if (bss_info.akm_suites & (IE_RSN_AKM_SUITE_FILS_SHA256 |
				IE_RSN_AKM_SUITE_FILS_SHA384))
		hs->support_fils = true;

	/*
	 * If this network 8021x we might have a set of cached EAP keys. If so
	 * wiphy may select FILS if supported by the AP.
	 */
	if (security == SECURITY_8021X && hs->support_fils)
		erp_cache = network_get_erp_cache(network);

	info.akm_suites = wiphy_select_akm(wiphy, bss, security,
						&bss_info, erp_cache != NULL);

	/*
	 * Special case for OWE. With OWE we still need to build up the
	 * handshake object with AKM/cipher info since OWE does the full 4-way
	 * handshake. But if this is a non-OWE open network, we can skip this.
	 */
	if (security == SECURITY_NONE &&
			!(info.akm_suites & IE_RSN_AKM_SUITE_OWE))
		goto open_network;

	if (!info.akm_suites)
		goto not_supported;

	info.pairwise_ciphers = wiphy_select_cipher(wiphy,
					bss_info.pairwise_ciphers);
	info.group_cipher = wiphy_select_cipher(wiphy,
					bss_info.group_cipher);

	if (!info.pairwise_ciphers || !info.group_cipher)
		goto not_supported;

	/* Management frame protection is explicitly off for OSEN */
	if (info.akm_suites & IE_RSN_AKM_SUITE_OSEN) {
		info.group_management_cipher =
					IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC;
		goto build_ie;
	}

	switch (mfp_setting) {
	case 0:
		if (band != BAND_FREQ_6_GHZ)
			break;

		l_error("MFP turned off by [General].ManagementFrameProtection,"
				" 6GHz frequencies are disabled");
		goto not_supported;
	case 1:
		info.group_management_cipher =
			wiphy_select_cipher(wiphy,
				bss_info.group_management_cipher);
		info.mfpc = info.group_management_cipher != 0;

		if (band != BAND_FREQ_6_GHZ)
			break;

		if (!info.mfpc)
			goto not_supported;

		/*
		 * 802.11ax Section 12.12.2
		 * The STA shall use management frame protection
		 * (MFPR=1) when using RSN.
		 */
		info.mfpr = true;

		break;
	case 2:
		info.group_management_cipher =
			wiphy_select_cipher(wiphy,
				bss_info.group_management_cipher);

		/*
		 * MFP required on our side, but AP doesn't support MFP
		 * or cipher mismatch
		 */
		if (info.group_management_cipher == 0)
			goto not_supported;

		info.mfpc = true;
		info.mfpr = true;
		break;
	}

	if (bss_info.mfpr && !info.mfpc)
		goto not_supported;

build_ie:
	if (!l_settings_get_bool(settings, "General", "DisableOCV",
					&disable_ocv))
		disable_ocv = false;

	/*
	 * Obviously do not enable OCV if explicitly disabled or no AP support.
	 *
	 * Not obviously hostapd rejects OCV support if MFPC is not enabled.
	 * This is not really specified by the spec, but we have to work around
	 * this limitation.
	 *
	 * Another limitation is full mac cards. With limited testing it was
	 * seen that they do not include the OCI in the 4-way handshake yet
	 * still advertise the capability. Because of this OCV is disabled if
	 * any offload features are detected (since IWD prefers to use offload).
	 *
	 * TODO: For now OCV is disabled if the network is FT capable. This is
	 *       being done until support in the kernel is added to
	 *       automatically include the OCI element for the association
	 *       request.
	 */
	info.ocvc = !disable_ocv && bss_info.ocvc && info.mfpc &&
			!wiphy_can_offload(wiphy) &&
			!IE_AKM_IS_FT(info.akm_suites);

	/*
	 * IEEE 802.11-2020 9.4.2.24.4 states extended key IDs can only be used
	 * with CCMP/GCMP cipher suites. We also only enable support if the AP
	 * also indicates support.
	 */
	if (wiphy_supports_ext_key_id(wiphy) && bss_info.extended_key_id &&
			IE_CIPHER_IS_GCMP_CCMP(info.pairwise_ciphers))
		info.extended_key_id = true;

	/* RSN takes priority */
	if (bss->rsne) {
		ap_ie = bss->rsne;
		ie_build_rsne(&info, rsne_buf);
	} else if (bss->wpa) {
		ap_ie = bss->wpa;
		ie_build_wpa(&info, rsne_buf);
	} else if (bss->osen) {
		ap_ie = bss->osen;
		ie_build_osen(&info, rsne_buf);
	} else
		goto not_supported;

	if (!handshake_state_set_authenticator_ie(hs, ap_ie))
		goto not_supported;

	if (!handshake_state_set_supplicant_ie(hs, rsne_buf))
		goto not_supported;

	if (IE_AKM_IS_FT(info.akm_suites))
		add_mde = true;

	/*
	 * If FILS was chosen, the ERP cache has been verified to exist. Take
	 * a reference now so it remains valid (in case of expiration) until
	 * FILS starts.
	 */
	if (IE_AKM_IS_FILS(hs->akm_suite))
		hs->erp_cache = erp_cache;
	else if (erp_cache)
		erp_cache_put(erp_cache);

open_network:
	if (security == SECURITY_NONE)
		/* Perform FT association if available */
		add_mde = bss->mde_present;

	if (add_mde) {
		uint8_t mde[5];

		/* The MDE advertised by the BSS must be passed verbatim */
		mde[0] = IE_TYPE_MOBILITY_DOMAIN;
		mde[1] = 3;
		memcpy(mde + 2, bss->mde, 3);

		handshake_state_set_mde(hs, mde);
	}

	return 0;

not_supported:
	if (erp_cache)
		erp_cache_put(erp_cache);

	return -ENOTSUP;
}

static struct handshake_state *station_handshake_setup(struct station *station,
							struct network *network,
							struct scan_bss *bss)
{
	struct wiphy *wiphy = station->wiphy;
	const struct network_info *info = network_get_info(network);
	struct handshake_state *hs;
	const struct iovec *vendor_ies;
	size_t iov_elems = 0;
	struct ie_fils_ip_addr_request_info fils_ip_req;

	hs = netdev_handshake_state_new(station->netdev);

	handshake_state_set_event_func(hs, station_handshake_event, station);

	if (station_build_handshake_rsn(hs, wiphy, network, bss) < 0)
		goto not_supported;

	handshake_state_set_authenticator_rsnxe(hs, bss->rsnxe);

	if (network_handshake_setup(network, bss, hs) < 0)
		goto not_supported;

	vendor_ies = network_info_get_extra_ies(info, bss, &iov_elems);
	handshake_state_set_vendor_ies(hs, vendor_ies, iov_elems);

	/*
	 * It can't hurt to try the FILS IP Address Assigment independent of
	 * which auth-proto is actually used.
	 */
	if (station->netconfig && netconfig_get_fils_ip_req(station->netconfig,
								&fils_ip_req)) {
		hs->fils_ip_req_ie = l_malloc(32);
		ie_build_fils_ip_addr_request(&fils_ip_req, hs->fils_ip_req_ie);
	}

	return hs;

not_supported:
	handshake_state_free(hs);
	return NULL;
}

static bool new_scan_results(int err, struct l_queue *bss_list,
				const struct scan_freq_set *freqs,
				void *userdata)
{
	struct station *station = userdata;

	station_property_set_scanning(station, false);

	if (err)
		return false;

	station_set_scan_results(station, bss_list, freqs, false);

	station_process_owe_transition_networks(station);

	station->autoconnect_can_start = true;
	station_autoconnect_start(station);

	return true;
}

static void periodic_scan_trigger(int err, void *user_data)
{
	struct station *station = user_data;

	station_property_set_scanning(station, true);
}

static void periodic_scan_stop(struct station *station)
{
	uint64_t id = netdev_get_wdev_id(station->netdev);

	if (scan_periodic_stop(id))
		station_property_set_scanning(station, false);
}

static bool station_needs_hidden_network_scan(struct station *station)
{
	if (!known_networks_has_hidden())
		return false;

	if (station_is_autoconnecting(station))
		return true;

	return !l_queue_isempty(station->hidden_bss_list_sorted);
}

static uint32_t station_scan_trigger(struct station *station,
					struct scan_freq_set *freqs,
					scan_trigger_func_t triggered,
					scan_notify_func_t notify,
					scan_destroy_func_t destroy)
{
	uint64_t id = netdev_get_wdev_id(station->netdev);
	struct scan_parameters params;

	memset(&params, 0, sizeof(params));
	params.flush = true;
	params.freqs = freqs;

	if (wiphy_can_randomize_mac_addr(station->wiphy) ||
			station->connected_bss ||
				station_needs_hidden_network_scan(station)) {
		/* If we're connected, HW cannot randomize our MAC */
		if (!station->connected_bss)
			params.randomize_mac_addr_hint = true;

		return scan_active_full(id, &params, triggered, notify,
					station, destroy);
	}

	return scan_passive_full(id, &params, triggered, notify,
					station, destroy);
}

static bool station_quick_scan_results(int err, struct l_queue *bss_list,
					const struct scan_freq_set *freqs,
					void *userdata)
{
	struct station *station = userdata;

	station_property_set_scanning(station, false);

	if (err)
		goto done;

	station_set_scan_results(station, bss_list, freqs, false);

	station_process_owe_transition_networks(station);

	station->autoconnect_can_start = true;
	station_autoconnect_start(station);

done:
	if (station->state == STATION_STATE_AUTOCONNECT_QUICK)
		/*
		 * If we're still in AUTOCONNECT_QUICK state, then autoconnect
		 * failed to find any candidates. Transition to AUTOCONNECT_FULL
		 */
		station_enter_state(station, STATION_STATE_AUTOCONNECT_FULL);

	return err == 0;
}

static void station_quick_scan_triggered(int err, void *user_data)
{
	struct station *station = user_data;

	if (err < 0) {
		l_debug("Quick scan trigger failed: %i", err);

		station_enter_state(station, STATION_STATE_AUTOCONNECT_FULL);

		return;
	}

	l_debug("Quick scan triggered for %s",
					netdev_get_name(station->netdev));

	station_property_set_scanning(station, true);
}

static void station_quick_scan_destroy(void *userdata)
{
	struct station *station = userdata;

	station->quick_scan_id = 0;
}

static int station_quick_scan_trigger(struct station *station)
{
	_auto_(scan_freq_set_free) struct scan_freq_set *known_freq_set = NULL;
	bool known_6ghz;

	if (wiphy_regdom_is_updating(station->wiphy)) {
		l_debug("regdom is updating, delaying quick scan");
		return -EAGAIN;
	}

	known_freq_set = known_networks_get_recent_frequencies(5);
	if (!known_freq_set)
		return -ENODATA;

	known_6ghz = scan_freq_set_get_bands(known_freq_set) & BAND_FREQ_6_GHZ;

	/*
	 * This means IWD has previously connected to a 6GHz AP before, but now
	 * the regulatory domain disallows 6GHz likely caused by a reboot, the
	 * firmware going down, or a regulatory update. The only way to
	 * re-enable 6GHz is to get enough beacons via scanning for the firmware
	 * to set the regulatory domain. A quick scan is very unlikely to do
	 * this since its so limited, so return an error which will fall back to
	 * full autoconnect.
	 */
	if (wiphy_get_supported_bands(station->wiphy) & BAND_FREQ_6_GHZ &&
			wiphy_band_is_disabled(station->wiphy,
						BAND_FREQ_6_GHZ) &&
			wiphy_country_is_unknown(station->wiphy) &&
			known_6ghz)
		return -ENOTSUP;

	if (!wiphy_constrain_freq_set(station->wiphy, known_freq_set)) {
		return -ENOTSUP;
	}

	station->quick_scan_id = station_scan_trigger(station,
						known_freq_set,
						station_quick_scan_triggered,
						station_quick_scan_results,
						station_quick_scan_destroy);
	if (!station->quick_scan_id)
		return -EIO;

	return 0;
}

static const char *station_state_to_string(enum station_state state)
{
	switch (state) {
	case STATION_STATE_DISCONNECTED:
		return "disconnected";
	case STATION_STATE_AUTOCONNECT_QUICK:
		return "autoconnect_quick";
	case STATION_STATE_AUTOCONNECT_FULL:
		return "autoconnect_full";
	case STATION_STATE_CONNECTING:
		return "connecting";
	case STATION_STATE_CONNECTING_AUTO:
		return "connecting (auto)";
	case STATION_STATE_CONNECTED:
		return "connected";
	case STATION_STATE_DISCONNECTING:
		return "disconnecting";
	case STATION_STATE_ROAMING:
		return "roaming";
	case STATION_STATE_FT_ROAMING:
		return "ft-roaming";
	case STATION_STATE_FW_ROAMING:
		return "fw-roaming";
	}

	return "invalid";
}

static void station_set_evict_nocarrier(struct station *station, bool value)
{
	char *v = value ? "1" : "0";

	if (supports_arp_evict_nocarrier)
		sysfs_write_ipv4_setting(netdev_get_name(station->netdev),
					"arp_evict_nocarrier", v);

	if (supports_ndisc_evict_nocarrier)
		sysfs_write_ipv6_setting(netdev_get_name(station->netdev),
					"ndisc_evict_nocarrier", v);
}

/*
 * Handles dropping ARP (IPv4) and neighbor advertisements (IPv6) settings.
 */
static void station_set_drop_neighbor_discovery(struct station *station,
						bool value)
{
	char *v = value ? "1" : "0";

	sysfs_write_ipv4_setting(netdev_get_name(station->netdev),
				"drop_gratuitous_arp", v);
	sysfs_write_ipv6_setting(netdev_get_name(station->netdev),
				"drop_unsolicited_na", v);
}

static void station_set_drop_unicast_l2_multicast(struct station *station,
							bool value)
{
	char *v = value ? "1" : "0";

	sysfs_write_ipv4_setting(netdev_get_name(station->netdev),
				"drop_unicast_in_l2_multicast", v);
	sysfs_write_ipv6_setting(netdev_get_name(station->netdev),
				"drop_unicast_in_l2_multicast", v);
}

static void station_signal_agent_notify(struct station *station);

static void station_enter_state(struct station *station,
						enum station_state state)
{
	uint64_t id = netdev_get_wdev_id(station->netdev);
	struct l_dbus *dbus = dbus_get_bus();
	bool disconnected;
	int ret;

	l_debug("Old State: %s, new state: %s",
			station_state_to_string(station->state),
			station_state_to_string(state));

	disconnected = !station_is_busy(station);

	if ((disconnected && state > STATION_STATE_AUTOCONNECT_FULL) ||
			(!disconnected && state != station->state))
		l_dbus_property_changed(dbus, netdev_get_path(station->netdev),
					IWD_STATION_INTERFACE, "State");

	station->state = state;

	switch (state) {
	case STATION_STATE_AUTOCONNECT_QUICK:
		ret = station_quick_scan_trigger(station);
		if (ret == 0 || ret == -EAGAIN)
			break;

		station->state = STATION_STATE_AUTOCONNECT_FULL;
		/* Fall through */
	case STATION_STATE_AUTOCONNECT_FULL:
		scan_periodic_start(id, periodic_scan_trigger,
					new_scan_results, station);
		break;
	case STATION_STATE_CONNECTING:
	case STATION_STATE_CONNECTING_AUTO:
		/* Refresh the ordered network list */
		network_rank_update(station->connected_network, true);
		l_queue_remove(station->networks_sorted,
					station->connected_network);
		l_queue_insert(station->networks_sorted,
					station->connected_network,
					network_rank_compare, NULL);

		l_dbus_property_changed(dbus, netdev_get_path(station->netdev),
				IWD_STATION_INTERFACE, "ConnectedNetwork");
		l_dbus_property_changed(dbus,
				network_get_path(station->connected_network),
				IWD_NETWORK_INTERFACE, "Connected");

		if (station->signal_agent)
			station_signal_agent_notify(station);

		periodic_scan_stop(station);
		break;
	case STATION_STATE_CONNECTED:
		l_dbus_object_add_interface(dbus,
					netdev_get_path(station->netdev),
					IWD_STATION_DIAGNOSTIC_INTERFACE,
					station);
		periodic_scan_stop(station);

		station_set_evict_nocarrier(station, true);

		/*
		 * Hotspot Specification 2.0 - Section 6.5
		 *
		 * " - Shall drop all received {gratuitous ARP, unsolicited
		 *     Neighbor Advertisement} messages when the Proxy ARP field
		 *     is set to 1 in the Extended Capabilities element of the
		 *     serving AP.
		 *
		 *   - When the serving AP transmits frames containing an HS2.0
		 *     Indication element in which the value of the DGAF Disable
		 *     bit subfield is set to 0, the mobile device should
		 *     discard all received unicast IP packets that were
		 *     decrypted using the GTK"
		 */
		if (station->connected_bss->proxy_arp)
			station_set_drop_neighbor_discovery(station, true);
		if (station->connected_bss->hs20_dgaf_disable)
			station_set_drop_unicast_l2_multicast(station, true);

		break;
	case STATION_STATE_DISCONNECTED:
		periodic_scan_stop(station);

		station_set_evict_nocarrier(station, true);
		station_set_drop_neighbor_discovery(station, false);
		station_set_drop_unicast_l2_multicast(station, false);
		break;
	case STATION_STATE_DISCONNECTING:
		break;
	case STATION_STATE_ROAMING:
	case STATION_STATE_FT_ROAMING:
	case STATION_STATE_FW_ROAMING:
		station_set_evict_nocarrier(station, false);
		break;
	}

	WATCHLIST_NOTIFY(&station->state_watches,
				station_state_watch_func_t, station->state);
}

enum station_state station_get_state(struct station *station)
{
	return station->state;
}

uint32_t station_add_state_watch(struct station *station,
					station_state_watch_func_t func,
					void *user_data,
					station_destroy_func_t destroy)
{
	return watchlist_add(&station->state_watches, func, user_data, destroy);
}

bool station_remove_state_watch(struct station *station, uint32_t id)
{
	return watchlist_remove(&station->state_watches, id);
}

uint32_t station_add_event_watch(station_event_watch_func_t func,
				void *user_data,
				station_destroy_func_t destroy)
{
	return watchlist_add(&event_watches, func, user_data, destroy);
}

void station_remove_event_watch(uint32_t id)
{
	watchlist_remove(&event_watches, id);
}

bool station_set_autoconnect(struct station *station, bool autoconnect)
{
	if (station->autoconnect == autoconnect)
		return true;

	station->autoconnect = autoconnect;

	if (station->state == STATION_STATE_DISCONNECTED && autoconnect)
		station_enter_state(station, STATION_STATE_AUTOCONNECT_QUICK);

	if (station_is_autoconnecting(station) && !autoconnect)
		station_enter_state(station, STATION_STATE_DISCONNECTED);

	if (iwd_is_developer_mode())
		l_dbus_property_changed(dbus_get_bus(),
				netdev_get_path(station->netdev),
				IWD_STATION_DEBUG_INTERFACE, "AutoConnect");

	return true;
}

static void station_roam_state_clear(struct station *station)
{
	l_debug("%u", netdev_get_ifindex(station->netdev));

	l_timeout_remove(station->roam_trigger_timeout);
	station->roam_trigger_timeout = NULL;
	station->preparing_roam = false;
	station->roam_scan_full = false;
	station->signal_low = false;
	station->roam_min_time.tv_sec = 0;

	if (station->roam_scan_id)
		scan_cancel(netdev_get_wdev_id(station->netdev),
						station->roam_scan_id);

	if (station->roam_freqs) {
		scan_freq_set_free(station->roam_freqs);
		station->roam_freqs = NULL;
	}

	l_queue_clear(station->roam_bss_list, l_free);

	ft_clear_authentications(netdev_get_ifindex(station->netdev));
}

static void station_reset_connection_state(struct station *station)
{
	struct network *network = station->connected_network;
	struct l_dbus *dbus = dbus_get_bus();

	l_debug("%u", netdev_get_ifindex(station->netdev));

	if (!network)
		return;

	station_roam_state_clear(station);

	if (station->netconfig)
		netconfig_reset(station->netconfig);

	/* Refresh the ordered network list */
	network_rank_update(station->connected_network, false);
	l_queue_remove(station->networks_sorted, station->connected_network);
	l_queue_insert(station->networks_sorted, station->connected_network,
				network_rank_compare, NULL);

	station->connected_bss = NULL;
	station->connected_network = NULL;

	l_dbus_property_changed(dbus, netdev_get_path(station->netdev),
				IWD_STATION_INTERFACE, "ConnectedNetwork");
	l_dbus_property_changed(dbus, network_get_path(network),
				IWD_NETWORK_INTERFACE, "Connected");
	l_dbus_object_remove_interface(dbus, netdev_get_path(station->netdev),
				IWD_STATION_DIAGNOSTIC_INTERFACE);

	/*
	 * Perform this step last since calling network_disconnected() might
	 * result in the removal of the network (for example if provisioning
	 * a new hidden network fails with an incorrect pasword).
	 */
	if (station->state == STATION_STATE_CONNECTED ||
			station->state == STATION_STATE_CONNECTING ||
			station->state == STATION_STATE_CONNECTING_AUTO ||
			station_is_roaming(station))
		network_disconnected(network);
}

static void station_disassociated(struct station *station)
{
	l_debug("%u", netdev_get_ifindex(station->netdev));

	station_reset_connection_state(station);

	station_enter_state(station, STATION_STATE_DISCONNECTED);

	if (station->autoconnect)
		station_enter_state(station, STATION_STATE_AUTOCONNECT_QUICK);
}

static void station_roam_timeout_rearm(struct station *station, int seconds);
static int station_roam_scan(struct station *station,
				struct scan_freq_set *freq_set);

static uint32_t station_freq_from_neighbor_report(const uint8_t *country,
		struct ie_neighbor_report_info *info, enum band_freq *out_band)
{
	enum band_freq band;
	uint32_t freq;

	if (info->oper_class == 0) {
		/*
		 * Some Cisco APs report all operating class values as 0
		 * in the Neighbor Report Responses.  Work around this by
		 * using the most likely operating class for the channel
		 * number as the 2.4GHz and 5GHz bands happen to mostly
		 * use channels in two disjoint ranges.
		 */
		if (info->channel_num >= 1 && info->channel_num <= 14)
			band = BAND_FREQ_2_4_GHZ;
		else if (info->channel_num >= 36 && info->channel_num <= 169)
			band = BAND_FREQ_5_GHZ;
		else {
			l_debug("Ignored: 0 oper class with an unusual "
				"channel number");

			return 0;
		}
	} else {
		band = band_oper_class_to_band(country, info->oper_class);
		if (!band) {
			l_debug("Ignored: unsupported oper class");

			return 0;
		}
	}

	freq = band_channel_to_freq(info->channel_num, band);
	if (!freq) {
		l_debug("Ignored: unsupported channel");

		return 0;
	}

	if (out_band)
		*out_band = band;

	return freq;
}

static void parse_neighbor_report(struct station *station,
					const uint8_t *reports,
					size_t reports_len,
					struct scan_freq_set **set)
{
	struct ie_tlv_iter iter;
	int count_md = 0, count_no_md = 0;
	struct scan_freq_set *freq_set_md, *freq_set_no_md;
	uint32_t current_freq = 0;
	struct handshake_state *hs = netdev_get_handshake(station->netdev);

	freq_set_md = scan_freq_set_new();
	freq_set_no_md = scan_freq_set_new();

	ie_tlv_iter_init(&iter, reports, reports_len);

	/* First see if any of the reports contain the MD bit set */
	while (ie_tlv_iter_next(&iter)) {
		struct ie_neighbor_report_info info;
		uint32_t freq;
		enum band_freq band;
		const uint8_t *cc = NULL;
		const struct band_freq_attrs *attr;

		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_NEIGHBOR_REPORT)
			continue;

		if (ie_parse_neighbor_report(&iter, &info) < 0)
			continue;

		l_debug("Neighbor report received for %s: ch %i "
				"(oper class %i), %s",
				util_address_to_string(info.addr),
				(int) info.channel_num, (int) info.oper_class,
				info.md ? "MD set" : "MD not set");

		if (station->connected_bss->cc_present)
			cc = station->connected_bss->cc;

		freq = station_freq_from_neighbor_report(cc, &info, &band);
		if (!freq)
			continue;

		/* Skip if the band is not supported */
		if (!(band & wiphy_get_supported_bands(station->wiphy)))
			continue;

		/* Skip if frequency is not supported or disabled */
		attr = wiphy_get_frequency_info(station->wiphy, freq);
		if (!attr || attr->disabled)
			continue;

		if (!memcmp(info.addr,
				station->connected_bss->addr, ETH_ALEN)) {
			/*
			 * If this report is for the current AP, don't add
			 * it to any of the lists yet.  We will need to scan
			 * its channel because it may still be the best ranked
			 * or the only visible AP.
			 */
			current_freq = freq;

			continue;
		}

		/* Add the frequency to one of the lists */
		if (info.md && hs->mde) {
			scan_freq_set_add(freq_set_md, freq);

			count_md += 1;
		} else {
			scan_freq_set_add(freq_set_no_md, freq);

			count_no_md += 1;
		}
	}

	if (!current_freq)
		current_freq = station->connected_bss->frequency;

	/*
	 * If there are neighbor reports with the MD bit set then the bit
	 * is probably valid so scan only the frequencies of the neighbors
	 * with that bit set, which will allow us to use Fast Transition.
	 * Some APs, such as those based on hostapd do not set the MD bit
	 * even if the neighbor is within the MD.
	 *
	 * In any case we only select the frequencies here and will check
	 * the IEs in the scan results as the authoritative information
	 * on whether we can use Fast Transition, and rank BSSes based on
	 * that.
	 *
	 * TODO: possibly save the neighbors from outside the MD and if
	 * none of the ones in the MD end up working, try a non-FT
	 * transition to those neighbors.  We should be using a
	 * blacklisting mechanism (for both initial connection and
	 * transitions) so that cound_md would not count the
	 * BSSes already used and when it goes down to 0 we'd
	 * automatically fall back to the non-FT candidates and then to
	 * full scan.
	 */
	if (count_md) {
		scan_freq_set_add(freq_set_md, current_freq);
		*set = freq_set_md;
		scan_freq_set_free(freq_set_no_md);
	} else if (count_no_md) {
		scan_freq_set_add(freq_set_no_md, current_freq);
		*set = freq_set_no_md;
		scan_freq_set_free(freq_set_md);
	} else {
		scan_freq_set_free(freq_set_no_md);
		scan_freq_set_free(freq_set_md);
		*set = NULL;
	}
}

static void station_early_neighbor_report_cb(struct netdev *netdev, int err,
						const uint8_t *reports,
						size_t reports_len,
						void *user_data)
{
	struct station *station = user_data;

	if (err == -ENODEV)
		return;

	l_debug("ifindex: %u, error: %d(%s)",
			netdev_get_ifindex(station->netdev),
			err, err < 0 ? strerror(-err) : "");

	if (!reports || err)
		return;

	parse_neighbor_report(station, reports, reports_len,
				&station->roam_freqs);
}

static bool station_can_fast_transition(struct handshake_state *hs,
					struct scan_bss *bss)
{
	uint16_t mdid;

	if (!hs->mde)
		return false;

	if (ie_parse_mobility_domain_from_data(hs->mde, hs->mde[1] + 2,
						&mdid, NULL, NULL) < 0)
		return false;

	if (!(bss->mde_present && l_get_le16(bss->mde) == mdid))
		return false;

	if (hs->supplicant_ie != NULL) {
		struct ie_rsn_info rsn_info;

		if (!IE_AKM_IS_FT(hs->akm_suite))
			return false;

		if (scan_bss_get_rsn_info(bss, &rsn_info) < 0)
			return false;

		if (!IE_AKM_IS_FT(rsn_info.akm_suites))
			return false;
	}

	return true;
}

static void station_roamed(struct station *station)
{
	station->roam_scan_full = false;

	/*
	 * Schedule another roaming attempt in case the signal continues to
	 * remain low. A subsequent high signal notification will cancel it.
	 */
	if (station->signal_low)
		station_roam_timeout_rearm(station, roam_retry_interval);

	if (station->netconfig)
		netconfig_reconfigure(station->netconfig,
					!supports_arp_evict_nocarrier);

	if (station->roam_freqs) {
		scan_freq_set_free(station->roam_freqs);
		station->roam_freqs = NULL;
	}

	if (station->connected_bss->cap_rm_neighbor_report) {
		if (netdev_neighbor_report_req(station->netdev,
					station_early_neighbor_report_cb) < 0)
			l_warn("Could not request neighbor report");
	}

	l_queue_clear(station->roam_bss_list, l_free);

	station_enter_state(station, STATION_STATE_CONNECTED);
}

static void station_roam_retry(struct station *station)
{
	/*
	 * If we're still connected to the old BSS, only clear preparing_roam
	 * and reattempt in 60 seconds if signal level is still low at that
	 * time.
	 */
	station->preparing_roam = false;
	station->roam_scan_full = false;
	station->ap_directed_roaming = false;

	if (station->signal_low)
		station_roam_timeout_rearm(station, roam_retry_interval);
}

static void station_roam_failed(struct station *station)
{
	l_debug("%u", netdev_get_ifindex(station->netdev));

	l_queue_clear(station->roam_bss_list, l_free);

	/*
	 * If we attempted a reassociation or a fast transition, and ended up
	 * here then we are now disconnected.
	 */
	if (station_is_roaming(station)) {
		station_disassociated(station);
		return;
	}

	/*
	 * We were told by the AP to roam, but failed.  Try ourselves or
	 * wait for the AP to tell us to roam again
	 */
	if (station->ap_directed_roaming)
		goto delayed_retry;

	/*
	 * If we tried a limited scan, failed and the signal is still low,
	 * repeat with a full scan right away
	 */
	if (station->signal_low && !station->roam_scan_full) {
		/*
		 * Since we're re-using roam_scan_id, explicitly cancel
		 * the scan here, so that the destroy callback is not called
		 * after the return of this function
		 */
		scan_cancel(netdev_get_wdev_id(station->netdev),
						station->roam_scan_id);

		if (!station_roam_scan(station, NULL))
			return;
	}

delayed_retry:
	station_roam_retry(station);
}

static void station_disconnect_on_error_cb(struct netdev *netdev, bool success,
					void *user_data)
{
	struct station *station = user_data;
	bool continue_autoconnect;

	station_enter_state(station, STATION_STATE_DISCONNECTED);

	continue_autoconnect = station->state == STATION_STATE_CONNECTING_AUTO;

	if (continue_autoconnect) {
		if (station_autoconnect_next(station) < 0) {
			l_debug("Nothing left on autoconnect list");
			station_enter_state(station,
					STATION_STATE_AUTOCONNECT_FULL);
		}

		return;
	}

	if (station->autoconnect)
		station_enter_state(station, STATION_STATE_AUTOCONNECT_QUICK);
}

static void station_netconfig_event_handler(enum netconfig_event event,
							void *user_data)
{
	struct station *station = user_data;

	switch (event) {
	case NETCONFIG_EVENT_CONNECTED:
		station_enter_state(station, STATION_STATE_CONNECTED);
		break;
	case NETCONFIG_EVENT_FAILED:
		if (station->connect_pending) {
			struct l_dbus_message *reply = dbus_error_failed(
						station->connect_pending);

			dbus_pending_reply(&station->connect_pending, reply);
		}

		if (L_IN_SET(station->state, STATION_STATE_CONNECTING,
				STATION_STATE_CONNECTING_AUTO))
			network_connect_failed(station->connected_network,
						false);

		netdev_disconnect(station->netdev,
					station_disconnect_on_error_cb,
					station);
		station_reset_connection_state(station);

		station_enter_state(station, STATION_STATE_DISCONNECTING);
		break;
	default:
		l_error("station: Unsupported netconfig event: %d.", event);
		break;
	}
}

static void station_reassociate_cb(struct netdev *netdev,
					enum netdev_result result,
					void *event_data,
					void *user_data)
{
	struct station *station = user_data;

	l_debug("%u, result: %d", netdev_get_ifindex(station->netdev), result);

	if (station->state != STATION_STATE_ROAMING)
		return;

	if (result == NETDEV_RESULT_OK)
		station_roamed(station);
	else
		station_roam_failed(station);
}

static void station_netdev_event(struct netdev *netdev, enum netdev_event event,
					void *event_data, void *user_data);

static int station_transition_reassociate(struct station *station,
						struct scan_bss *bss,
						struct handshake_state *new_hs)
{
	int ret;

	ret = netdev_reassociate(station->netdev, bss, station->connected_bss,
				new_hs, station_netdev_event,
				station_reassociate_cb, station);
	if (ret < 0)
		return ret;

	station->connected_bss = bss;
	station->preparing_roam = false;
	station_enter_state(station, STATION_STATE_ROAMING);

	return 0;
}

static bool bss_match_bssid(const void *a, const void *b)
{
	const struct scan_bss *bss = a;
	const uint8_t *bssid = b;

	return !memcmp(bss->addr, bssid, sizeof(bss->addr));
}

static void station_preauthenticate_cb(struct netdev *netdev,
					enum netdev_result result,
					const uint8_t *pmk, void *user_data)
{
	struct station *station = user_data;
	struct network *connected = station->connected_network;
	struct scan_bss *bss;
	struct handshake_state *new_hs;

	l_debug("%u, result: %d", netdev_get_ifindex(station->netdev), result);

	if (!station->preparing_roam || result == NETDEV_RESULT_ABORTED)
		return;

	bss = network_bss_find_by_addr(station->connected_network,
						station->preauth_bssid);
	if (!bss) {
		l_error("Roam target BSS not found");
		station_roam_failed(station);
		return;
	}

	new_hs = station_handshake_setup(station, connected, bss);
	if (!new_hs) {
		l_error("station_handshake_setup failed");

		station_roam_failed(station);
		return;
	}

	if (result == NETDEV_RESULT_OK) {
		uint8_t pmkid[16];
		uint8_t rsne_buf[300];
		struct ie_rsn_info rsn_info;

		handshake_state_set_pmk(new_hs, pmk, 32);
		handshake_state_set_authenticator_address(new_hs,
					station->preauth_bssid);
		handshake_state_set_supplicant_address(new_hs,
					netdev_get_address(station->netdev));

		/*
		 * Rebuild the RSNE to include the negotiated PMKID.  Note
		 * supplicant_ie can't be a WPA IE here, including because
		 * the WPA IE doesn't have a capabilities field and
		 * target_rsne->preauthentication would have been false in
		 * station_transition_start.
		 */
		ie_parse_rsne_from_data(new_hs->supplicant_ie,
					new_hs->supplicant_ie[1] + 2,
					&rsn_info);

		handshake_state_get_pmkid(new_hs, pmkid);

		rsn_info.num_pmkids = 1;
		rsn_info.pmkids = pmkid;

		ie_build_rsne(&rsn_info, rsne_buf);
		handshake_state_set_supplicant_ie(new_hs, rsne_buf);
	}

	if (station_transition_reassociate(station, bss, new_hs) < 0) {
		handshake_state_free(new_hs);
		station_roam_failed(station);
	}
}

static void station_transition_start(struct station *station);

static bool station_ft_work_ready(struct wiphy_radio_work_item *item)
{
	struct station *station = l_container_of(item, struct station, ft_work);
	struct roam_bss *rbss = l_queue_pop_head(station->roam_bss_list);
	struct scan_bss *bss = network_bss_find_by_addr(
					station->connected_network, rbss->addr);
	int ret;

	l_free(rbss);

	/* Very unlikely, but the BSS could have gone away */
	if (!bss)
		goto try_next;

	ret = ft_associate(netdev_get_ifindex(station->netdev), bss->addr);
	if (ret == -ENOENT) {
		station_debug_event(station, "ft-roam-failed");
try_next:
		station_transition_start(station);
		return true;
	} else if (ret < 0)
		goto assoc_failed;

	station->connected_bss = bss;
	station->preparing_roam = false;
	station_enter_state(station, STATION_STATE_FT_ROAMING);

	return true;

assoc_failed:
	station_roam_failed(station);
	return true;
}

static const struct wiphy_radio_work_item_ops ft_work_ops = {
	.do_work = station_ft_work_ready,
};

static bool station_fast_transition(struct station *station,
					struct scan_bss *bss)
{
	struct handshake_state *hs = netdev_get_handshake(station->netdev);
	struct network *connected = station->connected_network;
	const struct network_info *info = network_get_info(connected);
	const struct iovec *vendor_ies;
	size_t iov_elems = 0;

	/* Rebuild handshake RSN for target AP */
	if (station_build_handshake_rsn(hs, station->wiphy,
				station->connected_network, bss) < 0)
		return false;

	/* Reset the vendor_ies in case they're different */
	vendor_ies = network_info_get_extra_ies(info, bss, &iov_elems);
	handshake_state_set_vendor_ies(hs, vendor_ies, iov_elems);

	/* Both ft_action/ft_authenticate will gate the associate work item */
	if ((hs->mde[4] & 1))
		ft_action(netdev_get_ifindex(station->netdev),
				station->connected_bss->frequency, bss);
	else
		ft_authenticate(netdev_get_ifindex(station->netdev), bss);

	wiphy_radio_work_insert(station->wiphy, &station->ft_work,
				WIPHY_WORK_PRIORITY_CONNECT, &ft_work_ops);

	return true;
}

static bool station_try_next_transition(struct station *station,
					struct scan_bss *bss)
{
	struct handshake_state *hs = netdev_get_handshake(station->netdev);
	struct network *connected = station->connected_network;
	enum security security = network_get_security(connected);
	struct handshake_state *new_hs;
	struct ie_rsn_info cur_rsne, target_rsne;

	l_debug("%u, target %s", netdev_get_ifindex(station->netdev),
			util_address_to_string(bss->addr));

	/* Reset AP roam flag, at this point the roaming behaves the same */
	station->ap_directed_roaming = false;

	/* Can we use Fast Transition? */
	if (station_can_fast_transition(hs, bss))
		return station_fast_transition(station, bss);

	/* Non-FT transition */

	/*
	 * FT not available, we can try preauthentication if available.
	 * 802.11-2012 section 11.5.9.2:
	 * "A STA shall not use preauthentication within the same mobility
	 * domain if AKM suite type 00-0F-AC:3 or 00-0F-AC:4 is used in
	 * the current association."
	 */
	if (security == SECURITY_8021X &&
			scan_bss_get_rsn_info(station->connected_bss,
						&cur_rsne) >= 0 &&
			scan_bss_get_rsn_info(bss, &target_rsne) >= 0 &&
			cur_rsne.preauthentication &&
			target_rsne.preauthentication) {
		/*
		 * Both the current and the target AP support
		 * pre-authentication and we're using 8021x authentication so
		 * attempt to pre-authenticate and reassociate afterwards.
		 * If the pre-authentication fails or times out we simply
		 * won't supply any PMKID when reassociating.
		 * Remain in the preparing_roam state.
		 */
		memcpy(station->preauth_bssid, bss->addr, ETH_ALEN);

		if (netdev_preauthenticate(station->netdev, bss,
						station_preauthenticate_cb,
						station) >= 0)
			return true;
	}

	new_hs = station_handshake_setup(station, connected, bss);
	if (!new_hs) {
		l_error("station_handshake_setup failed in reassociation");
		return false;
	}

	if (station_transition_reassociate(station, bss, new_hs) < 0) {
		handshake_state_free(new_hs);
		return false;
	}

	return true;
}

static void station_transition_start(struct station *station)
{
	struct roam_bss *rbss;
	bool roaming = false;

	/*
	 * For each failed attempt pop the BSS leaving the head of the queue
	 * with the current roam candidate.
	 */
	while ((rbss = l_queue_peek_head(station->roam_bss_list))) {
		struct scan_bss *bss = network_bss_find_by_addr(
					station->connected_network, rbss->addr);

		roaming = station_try_next_transition(station, bss);
		if (roaming)
			break;

		l_queue_pop_head(station->roam_bss_list);
		l_free(rbss);
	}

	if (!roaming)
		station_roam_failed(station);
}

static void station_roam_scan_triggered(int err, void *user_data)
{
	struct station *station = user_data;

	if (err) {
		station_roam_failed(station);
		return;
	}

	station_debug_event(station, "roam-scan-triggered");

	/*
	 * Do not update the Scanning property as we won't be updating the
	 * list of networks.
	 */
}

static void station_update_roam_bss(struct station *station,
					struct scan_bss *bss)
{
	struct network *network = station->connected_network;
	struct scan_bss *old =
		l_queue_remove_if(station->bss_list, bss_match, bss);

	network_bss_update(network, bss);
	l_queue_push_tail(station->bss_list, bss);

	if (old)
		scan_bss_free(old);
}

static bool station_roam_scan_notify(int err, struct l_queue *bss_list,
					const struct scan_freq_set *freqs,
					void *userdata)
{
	struct station *station = userdata;
	struct network *network = station->connected_network;
	struct handshake_state *hs = netdev_get_handshake(station->netdev);
	struct scan_bss *current_bss = station->connected_bss;
	struct scan_bss *bss;
	double cur_bss_rank = 0.0;
	static const double RANK_FT_FACTOR = 1.3;
	uint16_t mdid;
	enum security orig_security, security;

	if (err) {
		station_roam_failed(station);
		return false;
	}

	/*
	 * Do not call station_set_scan_results because this may have been
	 * a partial scan.  We could at most update the current networks' BSS
	 * list in its station->networks entry.
	 */

	orig_security = network_get_security(network);

	if (hs->mde)
		ie_parse_mobility_domain_from_data(hs->mde, hs->mde[1] + 2,
							&mdid, NULL, NULL);

	/*
	 * Find the current BSS rank, use the updated result if it exists. If
	 * this is an AP roam keep the current rank as zero to force the roam
	 * to occur.
	 */
	bss = l_queue_find(bss_list, bss_match_bssid, current_bss->addr);
	if (bss && !station->ap_directed_roaming) {
		cur_bss_rank = bss->rank;

		if (hs->mde && bss->mde_present && l_get_le16(bss->mde) == mdid)
			cur_bss_rank *= RANK_FT_FACTOR;
	}

	/*
	 * BSSes in the bss_list come already ranked with their initial
	 * association preference rank value.  We only need to add preference
	 * for BSSes that are within the FT Mobility Domain so as to favor
	 * Fast Roaming, if it is supported.
	 */
	l_debug("Current BSS '%s' with SSID: %s",
		util_address_to_string(current_bss->addr),
		util_ssid_to_utf8(current_bss->ssid_len, current_bss->ssid));

	while ((bss = l_queue_pop_head(bss_list))) {
		double rank;
		uint32_t kbps100 = DIV_ROUND_CLOSEST(bss->data_rate, 100000);
		struct roam_bss *rbss;

		l_debug("Processing BSS '%s' with SSID: %s, freq: %u, rank: %u,"
				" strength: %i, data_rate: %u.%u",
				util_address_to_string(bss->addr),
				util_ssid_to_utf8(bss->ssid_len, bss->ssid),
				bss->frequency, bss->rank, bss->signal_strength,
				kbps100 / 10, kbps100 % 10);

		/* Skip the BSS we are connected to */
		if (!memcmp(bss->addr, station->connected_bss->addr, 6))
			goto next;

		/* Skip result if it is not part of the ESS */
		if (bss->ssid_len != hs->ssid_len ||
				memcmp(bss->ssid, hs->ssid, hs->ssid_len))
			goto next;

		if (scan_bss_get_security(bss, &security) < 0)
			goto next;

		if (security != orig_security)
			goto next;

		if (network_can_connect_bss(network, bss) < 0)
			goto next;

		if (blacklist_contains_bss(bss->addr))
			goto next;

		rank = bss->rank;

		if (hs->mde && bss->mde_present && l_get_le16(bss->mde) == mdid)
			rank *= RANK_FT_FACTOR;

		if (rank <= cur_bss_rank)
			goto next;

		/*
		 * We need to update/add any potential roam candidate so
		 * station/network know it exists.
		 */
		station_update_roam_bss(station, bss);

		rbss = roam_bss_from_scan_bss(bss);

		l_queue_insert(station->roam_bss_list, rbss,
				roam_bss_rank_compare, NULL);

		continue;

next:
		scan_bss_free(bss);
	}

	l_queue_destroy(bss_list, NULL);

	/* See if we have anywhere to roam to */
	if (l_queue_isempty(station->roam_bss_list)) {
		station_debug_event(station, "no-roam-candidates");
		goto fail;
	}

	station_transition_start(station);

	return true;

fail:
	station_roam_failed(station);

	return true;
}

static void station_roam_scan_destroy(void *userdata)
{
	struct station *station = userdata;

	station->roam_scan_id = 0;
}

static int station_roam_scan(struct station *station,
				struct scan_freq_set *freq_set)
{
	struct scan_parameters params = { .freqs = freq_set, .flush = true };

	l_debug("ifindex: %u", netdev_get_ifindex(station->netdev));

	if (station->connected_network) {
		const char *ssid = network_get_ssid(station->connected_network);
		/* Use direct probe request */
		params.ssid = (const uint8_t *)ssid;
		params.ssid_len = strlen(ssid);
	}

	if (!freq_set)
		station->roam_scan_full = true;

	station->roam_scan_id =
		scan_active_full(netdev_get_wdev_id(station->netdev), &params,
					station_roam_scan_triggered,
					station_roam_scan_notify, station,
					station_roam_scan_destroy);

	if (!station->roam_scan_id)
		return -EIO;

	return 0;
}

static int station_roam_scan_known_freqs(struct station *station)
{
	const struct network_info *info = network_get_info(
						station->connected_network);
	struct scan_freq_set *freqs = network_info_get_roam_frequencies(info,
					station->connected_bss->frequency, 5);
	int r = -ENODATA;

	if (!freqs)
		return r;

	if (!wiphy_constrain_freq_set(station->wiphy, freqs))
		goto free_set;

	r = station_roam_scan(station, freqs);

free_set:
	scan_freq_set_free(freqs);
	return r;
}

static void station_neighbor_report_cb(struct netdev *netdev, int err,
					const uint8_t *reports,
					size_t reports_len, void *user_data)
{
	struct station *station = user_data;
	struct scan_freq_set *freq_set;
	int r;

	if (err == -ENODEV)
		return;

	l_debug("ifindex: %u, error: %d(%s)",
			netdev_get_ifindex(station->netdev),
			err, err < 0 ? strerror(-err) : "");

	/*
	 * Check if we're still attempting to roam -- if dbus Disconnect
	 * had been called in the meantime we just abort the attempt.
	 */
	if (!station->preparing_roam || err == -ENODEV)
		return;

	if (!reports || err) {
		r = station_roam_scan_known_freqs(station);

		if (r == -ENODATA)
			l_debug("no neighbor report results or known freqs");

		if (r < 0)
			station_roam_failed(station);

		return;
	}

	parse_neighbor_report(station, reports, reports_len, &freq_set);

	r = station_roam_scan(station, freq_set);

	if (freq_set)
		scan_freq_set_free(freq_set);

	if (r < 0)
		station_roam_failed(station);
}

static void station_start_roam(struct station *station)
{
	int r;

	station->preparing_roam = true;

	/*
	 * If current BSS supports Neighbor Reports, narrow the scan down
	 * to channels occupied by known neighbors in the ESS. If no neighbor
	 * report was obtained upon connection, request one now. This isn't
	 * 100% reliable as the neighbor lists are not required to be
	 * complete or current.  It is likely still better than doing a
	 * full scan.  10.11.10.1: "A neighbor report may not be exhaustive
	 * either by choice, or due to the fact that there may be neighbor
	 * APs not known to the AP."
	 */
	if (station->roam_freqs) {
		if (station_roam_scan(station, station->roam_freqs) == 0) {
			l_debug("Using cached neighbor report for roam");
			return;
		}
	} else if (station->connected_bss->cap_rm_neighbor_report) {
		if (netdev_neighbor_report_req(station->netdev,
					station_neighbor_report_cb) == 0) {
			l_debug("Requesting neighbor report for roam");
			return;
		}
	}

	r = station_roam_scan_known_freqs(station);
	if (r == -ENODATA)
		l_debug("No neighbor report or known frequencies, roam failed");

	if (r < 0)
		station_roam_failed(station);
}

static bool station_cannot_roam(struct station *station)
{
	const struct l_settings *config = iwd_get_config();
	bool disabled;

	/*
	 * Disable roaming with hardware that can roam automatically. Note this
	 * is now required for recent kernels which have CQM event support on
	 * this type of hardware (e.g. brcmfmac).
	 */
	if (wiphy_supports_firmware_roam(station->wiphy))
		return true;

	if (!l_settings_get_bool(config, "Scan", "DisableRoamingScan",
								&disabled))
		disabled = false;

	return disabled || station->preparing_roam ||
				station->state == STATION_STATE_ROAMING ||
				station->state == STATION_STATE_FT_ROAMING;
}

static void station_roam_trigger_cb(struct l_timeout *timeout, void *user_data)
{
	struct station *station = user_data;

	l_debug("%u", netdev_get_ifindex(station->netdev));

	l_timeout_remove(station->roam_trigger_timeout);
	station->roam_trigger_timeout = NULL;

	if (station_cannot_roam(station))
		return;

	station_start_roam(station);
}

static void station_roam_timeout_rearm(struct station *station, int seconds)
{
	struct timespec now, min_timeout;

	clock_gettime(CLOCK_MONOTONIC, &now);

	min_timeout = now;
	min_timeout.tv_sec += seconds;

	if (station->roam_min_time.tv_sec < min_timeout.tv_sec ||
			(station->roam_min_time.tv_sec == min_timeout.tv_sec &&
			 station->roam_min_time.tv_nsec < min_timeout.tv_nsec))
		station->roam_min_time = min_timeout;

	seconds = station->roam_min_time.tv_sec - now.tv_sec +
		(station->roam_min_time.tv_nsec > now.tv_nsec ? 1 : 0);

	station->roam_trigger_timeout =
		l_timeout_create(seconds, station_roam_trigger_cb,
								station, NULL);
}

#define WNM_REQUEST_MODE_PREFERRED_CANDIDATE_LIST	(1 << 0)
#define WNM_REQUEST_MODE_DISASSOCIATION_IMMINENT	(1 << 2)
#define WNM_REQUEST_MODE_TERMINATION_IMMINENT		(1 << 3)
#define WNM_REQUEST_MODE_ESS_DISASSOCIATION_IMMINENT	(1 << 4)

static void station_ap_directed_roam(struct station *station,
					const struct mmpdu_header *hdr,
					const void *body, size_t body_len)
{
	uint32_t pos = 0;
	uint8_t req_mode;
	uint16_t dtimer;
	uint8_t valid_interval;

	l_debug("ifindex: %u", netdev_get_ifindex(station->netdev));

	if (station_cannot_roam(station))
		return;

	if (station->state != STATION_STATE_CONNECTED) {
		l_debug("roam: unexpected AP directed roam -- ignore");
		return;
	}

	/*
	 * Sanitize the frame to check that it is from our current AP.
	 *
	 * 802.11-2020 Section 9.3.3.1 about Address2:
	 * "If the STA is an AP with dot11MultiBSSDImplemented set to false,
	 * then this address is the BSSID."
	 *
	 * Address3:
	 * "If the STA is an AP or PCP, the Address 3 field is the same as the
	 * Address 2 field."
	 *
	 * For now check that Address2 & Address3 is the same as the connected
	 * BSS address.
	 */
	if (memcmp(hdr->address_2, station->connected_bss, ETH_ALEN) ||
			memcmp(hdr->address_2, hdr->address_3, ETH_ALEN)) {
		l_debug("roam: AP directed roam not from our AP -- ignore");
		return;
	}

	if (body_len < 7)
		goto format_error;

	/*
	 * First two bytes are checked by the frame watch (WNM category and
	 * WNM action). The third is the dialog token which is not relevant
	 * because we did not send a BSS transition query -- so skip these
	 * first three bytes.
	 */
	pos += 3;

	req_mode = l_get_u8(body + pos);
	pos++;

	/*
	 * TODO: Disassociation timer and validity interval are currently not
	 * used since the BSS transition request is being handled immediately.
	 */
	dtimer = l_get_le16(body + pos);
	pos += 2;
	valid_interval = l_get_u8(body + pos);
	pos++;

	l_debug("roam: BSS transition received from AP: " MAC", "
			"Disassociation Time: %u, "
			"Validity interval: %u, Address3: " MAC,
			MAC_STR(hdr->address_2),
			dtimer, valid_interval,
			MAC_STR(hdr->address_3));

	/*
	 * The ap_directed_roaming flag forces IWD to roam if there are any
	 * candidates, even if they are worse than the current BSS. This isn't
	 * always a good idea since we may be associated to the best BSS. Where
	 * this does matter is if the AP indicates its going down or will be
	 * disassociating us. If either of these bits are set, set the
	 * ap_directed_roaming flag. Otherwise still try roaming but don't
	 * treat it any different than a normal roam.
	 */
	if (req_mode & (WNM_REQUEST_MODE_DISASSOCIATION_IMMINENT |
			WNM_REQUEST_MODE_TERMINATION_IMMINENT |
			WNM_REQUEST_MODE_ESS_DISASSOCIATION_IMMINENT))
		station->ap_directed_roaming = true;

	if (req_mode & WNM_REQUEST_MODE_TERMINATION_IMMINENT) {
		if (pos + 12 > body_len)
			goto format_error;

		pos += 12;
	}

	if (req_mode & WNM_REQUEST_MODE_ESS_DISASSOCIATION_IMMINENT) {
		uint8_t url_len;

		if (pos + 1 > body_len)
			goto format_error;

		url_len = l_get_u8(body + pos);
		pos++;

		if (pos + url_len > body_len)
			goto format_error;

		pos += url_len;
	}

	station->preparing_roam = true;

	l_timeout_remove(station->roam_trigger_timeout);
	station->roam_trigger_timeout = NULL;

	if (req_mode & WNM_REQUEST_MODE_PREFERRED_CANDIDATE_LIST) {
		l_debug("roam: AP sent a preferred candidate list");
		station_neighbor_report_cb(station->netdev, 0, body + pos,
				body_len - pos, station);
	} else {
		l_debug("roam: AP did not include a preferred candidate list");
		if (station_roam_scan(station, NULL) < 0)
			station_roam_failed(station);
	}

	return;

format_error:
	l_debug("bad AP roam frame formatting");
}

static void station_low_rssi(struct station *station)
{
	if (station->signal_low)
		return;

	station->signal_low = true;

	if (station_cannot_roam(station))
		return;

	/* Set a 5-second initial timeout */
	station_roam_timeout_rearm(station, 5);
}

static void station_ok_rssi(struct station *station)
{
	l_timeout_remove(station->roam_trigger_timeout);
	station->roam_trigger_timeout = NULL;

	station->signal_low = false;
	station->roam_min_time.tv_sec = 0;
}

static void station_event_roamed(struct station *station, struct scan_bss *new)
{
	struct scan_bss *stale;

	network_bss_update(station->connected_network, new);

	/* Remove new BSS if it exists in past scan results */
	stale = l_queue_remove_if(station->bss_list, bss_match, new);
	if (stale)
		scan_bss_free(stale);

	station->connected_bss = new;

	l_queue_insert(station->bss_list, new, scan_bss_rank_compare, NULL);

	station_roamed(station);
}

static void station_event_channel_switched(struct station *station,
						const uint32_t freq)
{
	struct network *network = station->connected_network;

	station->connected_bss->frequency = freq;

	network_bss_update(network, station->connected_bss);
}

static bool station_try_next_bss(struct station *station)
{
	struct scan_bss *next;
	int ret;

	next = network_bss_select(station->connected_network, false);

	if (!next)
		return false;

	ret = __station_connect_network(station, station->connected_network,
						next);
	if (ret < 0)
		return false;

	l_debug("Attempting to connect to next BSS "MAC, MAC_STR(next->addr));

	return true;
}

static bool station_retry_owe_default_group(struct station *station)
{
	/*
	 * Shouldn't ever get here with classic open networks so its safe to
	 * assume if the security is none this is an OWE network.
	 */
	if (network_get_security(station->connected_network) != SECURITY_NONE)
		return false;

	/* If we already forced group 19, allow the BSS to be blacklisted */
	if (network_get_force_default_owe_group(station->connected_network))
		return false;

	l_warn("Failed to connect to OWE BSS "MAC" possibly because the AP is "
		"incorrectly deriving the PTK, this AP should be fixed. "
		"Retrying with group 19 as a workaround",
		MAC_STR(station->connected_bss->addr));

	network_set_force_default_owe_group(station->connected_network);

	return true;
}

static bool station_retry_with_reason(struct station *station,
					uint16_t reason_code)
{
	/*
	 * We don't want to cause a retry and blacklist if the password was
	 * incorrect. Otherwise we would just continue to fail.
	 *
	 * Other reason codes can be added here if its decided we want to
	 * fail in those cases.
	 */
	switch (reason_code) {
	case MMPDU_REASON_CODE_PREV_AUTH_NOT_VALID:
		if (station_retry_owe_default_group(station))
			goto try_next;
		/* fall through */
	case MMPDU_REASON_CODE_IEEE8021X_FAILED:
		return false;
	default:
		break;
	}

	blacklist_add_bss(station->connected_bss->addr);

try_next:
	return station_try_next_bss(station);
}

/* A bit more concise for trying to fit these into 80 characters */
#define IS_TEMPORARY_STATUS(code) \
	((code) == MMPDU_STATUS_CODE_DENIED_UNSUFFICIENT_BANDWIDTH || \
	(code) == MMPDU_STATUS_CODE_DENIED_POOR_CHAN_CONDITIONS || \
	(code) == MMPDU_STATUS_CODE_REJECTED_WITH_SUGG_BSS_TRANS || \
	(code) == MMPDU_STATUS_CODE_DENIED_NO_MORE_STAS)

static bool station_retry_with_status(struct station *station,
					uint16_t status_code)
{
	/*
	 * Certain Auth/Assoc failures should not cause a timeout blacklist.
	 * In these cases we want to only temporarily blacklist the BSS until
	 * the connection is complete.
	 *
	 * TODO: The WITH_SUGG_BSS_TRANS case should also include a neighbor
	 *       report IE in the frame. This would allow us to target a
	 *       specific BSS on our next attempt. There is currently no way to
	 *       obtain that IE, but this should be done in the future.
	 */
	if (IS_TEMPORARY_STATUS(status_code))
		network_blacklist_add(station->connected_network,
						station->connected_bss);
	else
		blacklist_add_bss(station->connected_bss->addr);

	return station_try_next_bss(station);
}

static void station_connect_ok(struct station *station)
{
	struct handshake_state *hs = netdev_get_handshake(station->netdev);

	l_debug("");

	if (station->connect_pending) {
		struct l_dbus_message *reply =
			l_dbus_message_new_method_return(
						station->connect_pending);
		dbus_pending_reply(&station->connect_pending, reply);
	}

	/*
	 * Get a neighbor report now so future roams can avoid waiting for
	 * a report at that time
	 */
	if (station->connected_bss->cap_rm_neighbor_report) {
		if (netdev_neighbor_report_req(station->netdev,
					station_early_neighbor_report_cb) < 0)
			l_warn("Could not request neighbor report");
	}

	network_connected(station->connected_network);

	if (station->netconfig) {
		if (hs->fils_ip_req_ie && hs->fils_ip_resp_ie) {
			struct ie_fils_ip_addr_response_info info;
			struct ie_tlv_iter iter;
			int r;

			ie_tlv_iter_init(&iter, hs->fils_ip_resp_ie,
						hs->fils_ip_resp_ie[1] + 2);
			if (!L_WARN_ON(unlikely(!ie_tlv_iter_next(&iter))))
				r = ie_parse_fils_ip_addr_response(&iter,
									&info);
			else
				r = -ENOMSG;

			if (r != 0)
				l_debug("Error parsing the FILS IP Address "
					"Assignment response: %s (%i)",
					strerror(-r), -r);
			else if (info.response_pending &&
					info.response_timeout)
				l_debug("FILS IP Address Assignment response "
					"is pending (unsupported)");
			else if (info.response_pending)
				l_debug("FILS IP Address Assignment failed");
			else {
				l_debug("FILS IP Address Assignment response "
					"OK");
				netconfig_handle_fils_ip_resp(
							station->netconfig,
							&info);
			}
		}

		if (L_WARN_ON(!netconfig_configure(station->netconfig,
						station_netconfig_event_handler,
						station)))
			return;
	} else
		station_enter_state(station, STATION_STATE_CONNECTED);
}

static void station_connect_cb(struct netdev *netdev, enum netdev_result result,
					void *event_data, void *user_data)
{
	struct station *station = user_data;
	bool continue_autoconnect;

	l_debug("%u, result: %d", netdev_get_ifindex(station->netdev), result);

	switch (result) {
	case NETDEV_RESULT_OK:
		blacklist_remove_bss(station->connected_bss->addr);
		station_connect_ok(station);
		return;
	case NETDEV_RESULT_HANDSHAKE_FAILED:
		/* reason code in this case */
		if (station_retry_with_reason(station, l_get_u16(event_data)))
			return;

		break;
	case NETDEV_RESULT_AUTHENTICATION_FAILED:
	case NETDEV_RESULT_ASSOCIATION_FAILED:
		/* status code in this case */
		if (station_retry_with_status(station, l_get_u16(event_data)))
			return;

		break;
	default:
		break;
	}

	if (station->connect_pending) {
		struct l_dbus_message *reply;

		if (result == NETDEV_RESULT_ABORTED)
			reply = dbus_error_aborted(station->connect_pending);
		else
			reply = dbus_error_failed(station->connect_pending);

		dbus_pending_reply(&station->connect_pending, reply);
	}

	if (result == NETDEV_RESULT_ABORTED)
		return;

	continue_autoconnect = station->state == STATION_STATE_CONNECTING_AUTO;

	if (station->state == STATION_STATE_CONNECTING) {
		bool during_eapol = result == NETDEV_RESULT_HANDSHAKE_FAILED;
		network_connect_failed(station->connected_network,
								during_eapol);
	}

	station_reset_connection_state(station);
	station_enter_state(station, STATION_STATE_DISCONNECTED);

	if (continue_autoconnect) {
		if (station_autoconnect_next(station) < 0) {
			l_debug("Nothing left on autoconnect list");
			station_enter_state(station,
					STATION_STATE_AUTOCONNECT_FULL);
		}

		return;
	}

	if (station->autoconnect)
		station_enter_state(station, STATION_STATE_AUTOCONNECT_QUICK);
}

static void station_disconnect_event(struct station *station, void *event_data)
{
	l_debug("%u", netdev_get_ifindex(station->netdev));

	/*
	 * If we're connecting, AP deauthenticated us, most likely because
	 * we provided the wrong password or otherwise failed authentication
	 * during the handshaking phase.  Treat this as a connection failure
	 */
	switch (station->state) {
	case STATION_STATE_CONNECTING:
	case STATION_STATE_CONNECTING_AUTO:
		station_connect_cb(station->netdev,
					NETDEV_RESULT_HANDSHAKE_FAILED,
					event_data, station);
		return;
	case STATION_STATE_CONNECTED:
	case STATION_STATE_FT_ROAMING:
	case STATION_STATE_FW_ROAMING:
		station_disassociated(station);
		return;
	default:
		break;
	}

	l_warn("Unexpected disconnect event");
}

#define STATION_PKT_LOSS_THRESHOLD 10

static void station_packets_lost(struct station *station, uint32_t num_pkts)
{
	l_debug("Packets lost event: %u", num_pkts);

	if (num_pkts < STATION_PKT_LOSS_THRESHOLD)
		return;

	if (station_cannot_roam(station))
		return;

	station_debug_event(station, "packet-loss-roam");

	station_start_roam(station);
}

static void station_netdev_event(struct netdev *netdev, enum netdev_event event,
					void *event_data, void *user_data)
{
	struct station *station = user_data;

	switch (event) {
	case NETDEV_EVENT_AUTHENTICATING:
		l_debug("Authenticating");
		break;
	case NETDEV_EVENT_ASSOCIATING:
		l_debug("Associating");
		break;
	case NETDEV_EVENT_DISCONNECT_BY_AP:
	case NETDEV_EVENT_DISCONNECT_BY_SME:
		station_disconnect_event(station, event_data);
		break;
	case NETDEV_EVENT_RSSI_THRESHOLD_LOW:
		station_low_rssi(station);
		break;
	case NETDEV_EVENT_RSSI_THRESHOLD_HIGH:
		station_ok_rssi(station);
		break;
	case NETDEV_EVENT_RSSI_LEVEL_NOTIFY:
		if (station->signal_agent)
			station_signal_agent_notify(station);
		break;
	case NETDEV_EVENT_ROAMING:
		station_enter_state(station, STATION_STATE_FW_ROAMING);
		break;
	case NETDEV_EVENT_ROAMED:
		station_event_roamed(station, (struct scan_bss *) event_data);
		break;
	case NETDEV_EVENT_CHANNEL_SWITCHED:
		station_event_channel_switched(station, l_get_u32(event_data));
		break;
	case NETDEV_EVENT_PACKET_LOSS_NOTIFY:
		station_packets_lost(station, l_get_u32(event_data));
		break;
	case NETDEV_EVENT_FT_ROAMED:
		if (L_WARN_ON(station->state != STATION_STATE_FT_ROAMING))
			return;

		station_roamed(station);
		break;
	}
}

int __station_connect_network(struct station *station, struct network *network,
				struct scan_bss *bss)
{
	struct handshake_state *hs;
	int r;

	if (station->netconfig && !netconfig_load_settings(
					station->netconfig,
					network_get_settings(network)))
		return -EINVAL;

	hs = station_handshake_setup(station, network, bss);
	if (!hs)
		return -ENOTSUP;

	r = netdev_connect(station->netdev, bss, hs, NULL, 0,
				station_netdev_event,
				station_connect_cb, station);
	if (r < 0) {
		handshake_state_free(hs);
		return r;
	}

	l_debug("connecting to BSS "MAC, MAC_STR(bss->addr));

	station->connected_bss = bss;
	station->connected_network = network;

	return 0;
}

static void station_disconnect_onconnect_cb(struct netdev *netdev, bool success,
					void *user_data)
{
	struct station *station = user_data;
	int err;

	station_enter_state(station, STATION_STATE_DISCONNECTED);

	err = __station_connect_network(station,
					station->connect_pending_network,
					station->connect_pending_bss);

	station->connect_pending_network = NULL;
	station->connect_pending_bss = NULL;

	if (err < 0) {
		dbus_pending_reply(&station->connect_pending,
					dbus_error_from_errno(err,
						station->connect_pending));
		return;
	}

	station_enter_state(station, STATION_STATE_CONNECTING);
}

static void station_disconnect_onconnect(struct station *station,
					struct network *network,
					struct scan_bss *bss,
					struct l_dbus_message *message)
{
	if (netdev_disconnect(station->netdev, station_disconnect_onconnect_cb,
								station) < 0) {
		l_dbus_send(dbus_get_bus(),
					dbus_error_from_errno(-EIO, message));
		return;
	}

	station_reset_connection_state(station);

	station_enter_state(station, STATION_STATE_DISCONNECTING);

	station->connect_pending_network = network;
	station->connect_pending_bss = bss;

	station->connect_pending = l_dbus_message_ref(message);
}

void station_connect_network(struct station *station, struct network *network,
				struct scan_bss *bss,
				struct l_dbus_message *message)
{
	struct l_dbus *dbus = dbus_get_bus();
	int err;

	/*
	 * If a hidden scan is not completed, station_is_busy would not
	 * indicate anything is going on so we need to cancel the scan and
	 * fail the connection now.
	 */
	if (station->hidden_network_scan_id) {
		scan_cancel(netdev_get_wdev_id(station->netdev),
				station->hidden_network_scan_id);

		dbus_pending_reply(&station->hidden_pending,
				dbus_error_failed(station->hidden_pending));
	}

	if (station->quick_scan_id) {
		scan_cancel(netdev_get_wdev_id(station->netdev),
				station->quick_scan_id);
		station->quick_scan_id = 0;
		station_property_set_scanning(station, false);
	}

	if (station_is_busy(station)) {
		station_disconnect_onconnect(station, network, bss, message);

		return;
	}

	err = __station_connect_network(station, network, bss);
	if (err < 0)
		goto error;

	station_enter_state(station, STATION_STATE_CONNECTING);

	station->connect_pending = l_dbus_message_ref(message);

	station_set_autoconnect(station, true);

	return;

error:
	l_dbus_send(dbus, dbus_error_from_errno(err, message));
}

static void station_hidden_network_scan_triggered(int err, void *user_data)
{
	struct station *station = user_data;

	l_debug("");

	if (!err)
		return;

	dbus_pending_reply(&station->hidden_pending,
				dbus_error_failed(station->hidden_pending));
}

static bool station_hidden_network_scan_results(int err,
					struct l_queue *bss_list,
					const struct scan_freq_set *freqs,
					void *userdata)
{
	struct station *station = userdata;
	struct network *network_psk;
	struct network *network_open;
	const char *ssid;
	uint8_t ssid_len;
	struct l_dbus_message *msg;
	struct l_dbus_message *error;
	struct scan_bss *bss;

	l_debug("");

	msg = station->hidden_pending;
	station->hidden_pending = NULL;
	/* Zero this now so station_connect_network knows the scan is done */
	station->hidden_network_scan_id = 0;

	if (err) {
		dbus_pending_reply(&msg, dbus_error_failed(msg));
		return false;
	}

	if (!l_dbus_message_get_arguments(msg, "s", &ssid)) {
		dbus_pending_reply(&msg, dbus_error_invalid_args(msg));
		return false;
	}

	ssid_len = strlen(ssid);

	while ((bss = l_queue_pop_head(bss_list))) {
		if (bss->ssid_len != ssid_len ||
					memcmp(bss->ssid, ssid, ssid_len))
			goto next;

		if (bss->owe_trans)
			goto next;

		/*
		 * Override time_stamp so that this entry is removed on
		 * the next scan
		 */
		bss->time_stamp = 0;

		if (station_add_seen_bss(station, bss)) {
			l_queue_push_tail(station->bss_list, bss);

			continue;
		}

next:
		scan_bss_free(bss);
	}

	l_queue_destroy(bss_list, NULL);

	network_psk = station_network_find(station, ssid, SECURITY_PSK);
	network_open = station_network_find(station, ssid, SECURITY_NONE);

	if (!network_psk && !network_open) {
		dbus_pending_reply(&msg, dbus_error_not_found(msg));
		return true;
	}

	if (network_psk && network_open) {
		station_hide_network(station, network_psk);
		station_hide_network(station, network_open);
		dbus_pending_reply(&msg, dbus_error_service_set_overlap(msg));
		return true;
	}

	error = network_connect_new_hidden_network(network_psk ?: network_open,
							msg);

	if (error)
		dbus_pending_reply(&msg, error);
	else
		l_dbus_message_unref(msg);

	return true;
}

static void station_hidden_network_scan_destroy(void *userdata)
{
	struct station *station = userdata;

	station->hidden_network_scan_id = 0;
}

static struct l_dbus_message *station_dbus_connect_hidden_network(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	uint64_t id = netdev_get_wdev_id(station->netdev);
	struct scan_parameters params = {
		.flush = true,
		.randomize_mac_addr_hint = false,
	};
	const char *ssid;
	struct network *network;

	l_debug("");

	if (station->hidden_pending)
		return dbus_error_busy(message);

	if (!l_dbus_message_get_arguments(message, "s", &ssid))
		return dbus_error_invalid_args(message);

	if (strlen(ssid) > 32)
		return dbus_error_invalid_args(message);

	if (known_networks_find(ssid, SECURITY_PSK) ||
			known_networks_find(ssid, SECURITY_NONE))
		return dbus_error_already_provisioned(message);

	network = station_network_find(station, ssid, SECURITY_PSK);
	if (!network)
		network = station_network_find(station, ssid, SECURITY_NONE);

	/*
	 * This checks for a corner case where the hidden network was already
	 * found and is in our scan results, but the initial connection failed.
	 * For example, the password was given incorrectly.  In this case the
	 * entry will also be found on the hidden bss list.
	 */
	if (network) {
		const struct l_queue_entry *entry =
			l_queue_get_entries(station->hidden_bss_list_sorted);
		struct scan_bss *target = network_bss_select(network, true);

		/* Treat OWE transition networks special */
		if (target->owe_trans)
			goto not_hidden;

		for (; entry; entry = entry->next) {
			struct scan_bss *bss = entry->data;

			if (!scan_bss_addr_eq(target, bss))
				continue;

			/* We can skip the scan and try to connect right away */
			return network_connect_new_hidden_network(network,
								message);
		}

not_hidden:
		return dbus_error_not_hidden(message);
	}

	params.ssid = (const uint8_t *)ssid;
	params.ssid_len = strlen(ssid);

	/* HW cannot randomize our MAC if connected */
	if (!station->connected_bss)
		params.randomize_mac_addr_hint = true;

	station->hidden_network_scan_id = scan_active_full(id, &params,
				station_hidden_network_scan_triggered,
				station_hidden_network_scan_results,
				station, station_hidden_network_scan_destroy);
	if (!station->hidden_network_scan_id)
		return dbus_error_failed(message);

	station->hidden_pending = l_dbus_message_ref(message);

	return NULL;
}

static void station_disconnect_reconnect_cb(struct netdev *netdev, bool success,
					void *user_data)
{
	struct station *station = user_data;

	if (__station_connect_network(station, station->connected_network,
					station->connected_bss) < 0)
		station_disassociated(station);
}

static void station_reconnect(struct station *station)
{
	/*
	 * Rather than doing 4 or so state changes, lets just go into
	 * roaming for the duration of this reconnect.
	 */
	station_enter_state(station, STATION_STATE_ROAMING);

	netdev_disconnect(station->netdev, station_disconnect_reconnect_cb,
				station);
}

static void station_disconnect_cb(struct netdev *netdev, bool success,
					void *user_data)
{
	struct station *station = user_data;

	l_debug("%u, success: %d",
			netdev_get_ifindex(station->netdev), success);

	if (station->disconnect_pending) {
		struct l_dbus_message *reply;

		if (success) {
			reply = l_dbus_message_new_method_return(
						station->disconnect_pending);
			l_dbus_message_set_arguments(reply, "");
		} else
			reply = dbus_error_failed(station->disconnect_pending);

		dbus_pending_reply(&station->disconnect_pending, reply);
	}

	station_enter_state(station, STATION_STATE_DISCONNECTED);

	if (station->autoconnect)
		station_enter_state(station, STATION_STATE_AUTOCONNECT_QUICK);
}

int station_disconnect(struct station *station)
{
	if (station->state == STATION_STATE_DISCONNECTING)
		return -EBUSY;

	if (!station->connected_bss)
		return -ENOTCONN;

	/*
	 * If the disconnect somehow fails we won't know if we're still
	 * connected so we may as well indicate now that we're no longer
	 * connected.
	 */
	station_reset_connection_state(station);

	station_enter_state(station, STATION_STATE_DISCONNECTING);

	if (netdev_disconnect(station->netdev,
					station_disconnect_cb, station) < 0)
		return -EIO;

	return 0;
}

static struct l_dbus_message *station_dbus_disconnect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	int result;

	l_debug("");

	/*
	 * Disconnect was triggered by the user, don't autoconnect. Wait for
	 * the user's explicit instructions to scan and connect to the network
	 */
	station_set_autoconnect(station, false);

	if (station->hidden_network_scan_id) {
		scan_cancel(netdev_get_wdev_id(station->netdev),
				station->hidden_network_scan_id);
		dbus_pending_reply(&station->hidden_pending,
				dbus_error_aborted(station->hidden_pending));

		return l_dbus_message_new_method_return(message);
	}

	if (!station_is_busy(station))
		return l_dbus_message_new_method_return(message);

	result = station_disconnect(station);
	if (result < 0)
		return dbus_error_from_errno(result, message);

	station->disconnect_pending = l_dbus_message_ref(message);

	return NULL;
}

static struct l_dbus_message *station_dbus_get_networks(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	struct l_dbus_message *reply =
				l_dbus_message_new_method_return(message);
	struct l_dbus_message_builder *builder =
				l_dbus_message_builder_new(reply);
	struct l_queue *sorted = station->networks_sorted;
	const struct l_queue_entry *entry;

	l_dbus_message_builder_enter_array(builder, "(on)");

	for (entry = l_queue_get_entries(sorted); entry; entry = entry->next) {
		const struct network *network = entry->data;
		int16_t signal_strength = network_get_signal_strength(network);

		l_dbus_message_builder_enter_struct(builder, "on");
		l_dbus_message_builder_append_basic(builder, 'o',
						network_get_path(network));
		l_dbus_message_builder_append_basic(builder, 'n',
							&signal_strength);
		l_dbus_message_builder_leave_struct(builder);
	}

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static struct l_dbus_message *station_dbus_get_hidden_access_points(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	struct l_dbus_message *reply =
				l_dbus_message_new_method_return(message);
	struct l_dbus_message_builder *builder =
				l_dbus_message_builder_new(reply);
	const struct l_queue_entry *entry;

	l_dbus_message_builder_enter_array(builder, "(sns)");

	for (entry = l_queue_get_entries(station->hidden_bss_list_sorted);
						entry; entry = entry->next) {
		struct scan_bss *bss = entry->data;
		int16_t signal_strength = bss->signal_strength;
		enum security security;

		if (scan_bss_get_security(bss, &security) < 0)
			continue;

		l_dbus_message_builder_enter_struct(builder, "sns");
		l_dbus_message_builder_append_basic(builder, 's',
					util_address_to_string(bss->addr));
		l_dbus_message_builder_append_basic(builder, 'n',
							&signal_strength);
		l_dbus_message_builder_append_basic(builder, 's',
						security_to_str(security));
		l_dbus_message_builder_leave_struct(builder);
	}

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static void station_dbus_scan_done(struct station *station,
							bool try_autoconnect)
{
	station->dbus_scan_id = 0;
	station_property_set_scanning(station, false);

	station_process_owe_transition_networks(station);

	if (try_autoconnect) {
		station->autoconnect_can_start = true;
		station_autoconnect_start(station);
	}
}

static void station_dbus_scan_triggered(int err, void *user_data)
{
	struct station *station = user_data;
	struct l_dbus_message *reply;

	l_debug("station_scan_triggered: %i", err);

	if (err < 0) {
		if (station->scan_pending) {
			reply = dbus_error_from_errno(err,
							station->scan_pending);
			dbus_pending_reply(&station->scan_pending, reply);
		}

		station_dbus_scan_done(station, true);
		return;
	}

	l_debug("Scan triggered for %s subset %i",
		netdev_get_name(station->netdev),
		station->dbus_scan_subset_idx);

	if (station->scan_pending) {
		reply = l_dbus_message_new_method_return(station->scan_pending);
		l_dbus_message_set_arguments(reply, "");
		dbus_pending_reply(&station->scan_pending, reply);
	}

	station_property_set_scanning(station, true);
}

static bool station_dbus_scan_subset(struct station *station);

static bool station_dbus_scan_results(int err, struct l_queue *bss_list,
					const struct scan_freq_set *freqs,
					void *userdata)
{
	struct station *station = userdata;
	unsigned int next_idx = station->dbus_scan_subset_idx + 1;
	bool last_subset;

	if (err) {
		station_dbus_scan_done(station, true);
		return false;
	}

	last_subset = next_idx >= L_ARRAY_SIZE(station->scan_freqs_order) ||
		station->scan_freqs_order[next_idx] == NULL;
	station->dbus_scan_subset_idx = next_idx;

	station_set_scan_results(station, bss_list, freqs, false);

	if (last_subset || !station_dbus_scan_subset(station))
		station_dbus_scan_done(station, true);

	return true;
}

static bool station_dbus_scan_subset(struct station *station)
{
	unsigned int idx = station->dbus_scan_subset_idx;

	station->dbus_scan_id = station_scan_trigger(station,
						station->scan_freqs_order[idx],
						station_dbus_scan_triggered,
						station_dbus_scan_results,
						NULL);

	return station->dbus_scan_id != 0;
}

static struct l_dbus_message *station_dbus_scan(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;

	l_debug("Scan called from DBus");

	if (station->dbus_scan_id)
		return dbus_error_busy(message);

	if (station->state == STATION_STATE_CONNECTING ||
			station->state == STATION_STATE_CONNECTING_AUTO)
		return dbus_error_busy(message);

	station->dbus_scan_subset_idx = 0;

	if (!station_dbus_scan_subset(station))
		return dbus_error_failed(message);

	station->scan_pending = l_dbus_message_ref(message);

	return NULL;
}

struct signal_agent {
	char *owner;
	char *path;
	unsigned int disconnect_watch;
};

static void station_signal_agent_notify(struct station *station)
{
	struct signal_agent *agent = station->signal_agent;
	struct netdev *netdev = station->netdev;
	const char *device_path = netdev_get_path(netdev);
	uint8_t level = netdev_get_rssi_level_idx(netdev);

	struct l_dbus_message *msg;

	msg = l_dbus_message_new_method_call(dbus_get_bus(),
						agent->owner, agent->path,
						IWD_SIGNAL_AGENT_INTERFACE,
						"Changed");
	l_dbus_message_set_arguments(msg, "oy", device_path, level);
	l_dbus_message_set_no_reply(msg, true);

	l_dbus_send(dbus_get_bus(), msg);
}

static void station_signal_agent_release(struct signal_agent *agent,
						const char *device_path)
{
	struct l_dbus_message *msg;

	msg = l_dbus_message_new_method_call(dbus_get_bus(),
						agent->owner, agent->path,
						IWD_SIGNAL_AGENT_INTERFACE,
						"Release");
	l_dbus_message_set_arguments(msg, "o", device_path);
	l_dbus_message_set_no_reply(msg, true);

	l_dbus_send(dbus_get_bus(), msg);
}

static void signal_agent_free(void *data)
{
	struct signal_agent *agent = data;

	l_free(agent->owner);
	l_free(agent->path);
	l_dbus_remove_watch(dbus_get_bus(), agent->disconnect_watch);
	l_free(agent);
}

static void signal_agent_disconnect(struct l_dbus *dbus, void *user_data)
{
	struct station *station = user_data;

	l_debug("signal_agent %s disconnected", station->signal_agent->owner);

	l_idle_oneshot(signal_agent_free, station->signal_agent, NULL);
	station->signal_agent = NULL;

	netdev_set_rssi_report_levels(station->netdev, NULL, 0);
}

static struct l_dbus_message *station_dbus_signal_agent_register(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	const char *path, *sender;
	struct l_dbus_message *reply;
	struct l_dbus_message_iter level_iter;
	int8_t levels[16];
	int err;
	int16_t val;
	size_t count = 0;

	if (station->signal_agent)
		return dbus_error_already_exists(message);

	l_debug("signal agent register called");

	if (!l_dbus_message_get_arguments(message, "oan", &path, &level_iter))
		return dbus_error_invalid_args(message);

	while (l_dbus_message_iter_next_entry(&level_iter, &val)) {
		if (count >= L_ARRAY_SIZE(levels) || val > 127 || val < -127)
			return dbus_error_invalid_args(message);

		levels[count++] = val;
	}

	if (count < 1)
		return dbus_error_invalid_args(message);

	err = netdev_set_rssi_report_levels(station->netdev, levels, count);
	if (err == -ENOTSUP)
		return dbus_error_not_supported(message);
	else if (err < 0)
		return dbus_error_failed(message);

	sender = l_dbus_message_get_sender(message);

	station->signal_agent = l_new(struct signal_agent, 1);
	station->signal_agent->owner = l_strdup(sender);
	station->signal_agent->path = l_strdup(path);
	station->signal_agent->disconnect_watch =
		l_dbus_add_disconnect_watch(dbus, sender,
						signal_agent_disconnect,
						station, NULL);

	l_debug("agent %s path %s", sender, path);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_send(dbus, reply);

	if (station->connected_network)
		station_signal_agent_notify(station);

	return NULL;
}

static struct l_dbus_message *station_dbus_signal_agent_unregister(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	const char *path, *sender;

	if (!station->signal_agent)
		return dbus_error_failed(message);

	l_debug("signal agent unregister");

	if (!l_dbus_message_get_arguments(message, "o", &path))
		return dbus_error_invalid_args(message);

	if (strcmp(station->signal_agent->path, path))
		return dbus_error_not_found(message);

	sender = l_dbus_message_get_sender(message);

	if (strcmp(station->signal_agent->owner, sender))
		return dbus_error_not_found(message);

	signal_agent_free(station->signal_agent);
	station->signal_agent = NULL;

	netdev_set_rssi_report_levels(station->netdev, NULL, 0);

	return l_dbus_message_new_method_return(message);
}

static bool station_property_get_connected_network(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct station *station = user_data;

	if (!station->connected_network)
		return false;

	l_dbus_message_builder_append_basic(builder, 'o',
				network_get_path(station->connected_network));

	return true;
}

static bool station_property_get_scanning(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct station *station = user_data;
	bool scanning = station->scanning;

	l_dbus_message_builder_append_basic(builder, 'b', &scanning);

	return true;
}

static bool station_property_get_state(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct station *station = user_data;
	const char *statestr = "invalid";

	switch (station->state) {
	case STATION_STATE_AUTOCONNECT_QUICK:
	case STATION_STATE_AUTOCONNECT_FULL:
	case STATION_STATE_DISCONNECTED:
		statestr = "disconnected";
		break;
	case STATION_STATE_CONNECTING:
	case STATION_STATE_CONNECTING_AUTO:
		statestr = "connecting";
		break;
	case STATION_STATE_CONNECTED:
		statestr = "connected";
		break;
	case STATION_STATE_DISCONNECTING:
		statestr = "disconnecting";
		break;
	case STATION_STATE_ROAMING:
	case STATION_STATE_FT_ROAMING:
	case STATION_STATE_FW_ROAMING:
		statestr = "roaming";
		break;
	}

	l_dbus_message_builder_append_basic(builder, 's', statestr);
	return true;
}

void station_foreach(station_foreach_func_t func, void *user_data)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(station_list); entry;
					entry = entry->next) {
		struct station *station = entry->data;

		func(station, user_data);
	}
}

struct station *station_find(uint32_t ifindex)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(station_list); entry;
				entry = entry->next) {
		struct station *station = entry->data;

		if (netdev_get_ifindex(station->netdev) == ifindex)
			return station;
	}

	return NULL;
}

struct network_foreach_data {
	station_network_foreach_func_t func;
	void *user_data;
};

static void network_foreach(const void *key, void *value, void *user_data)
{
	struct network_foreach_data *data = user_data;
	struct network *network = value;

	data->func(network, data->user_data);
}

void station_network_foreach(struct station *station,
				station_network_foreach_func_t func,
				void *user_data)
{
	struct network_foreach_data data = {
		.func = func,
		.user_data = user_data,
	};

	l_hashmap_foreach(station->networks, network_foreach, &data);
}

struct l_queue *station_get_bss_list(struct station *station)
{
	return station->bss_list;
}

struct scan_bss *station_get_connected_bss(struct station *station)
{
	return station->connected_bss;
}

int station_hide_network(struct station *station, struct network *network)
{
	const char *path = network_get_path(network);
	struct scan_bss *bss;

	l_debug("%s", path);

	if (station->connected_network == network)
		return -EBUSY;

	if (!l_hashmap_lookup(station->networks, path))
		return -ENOENT;

	l_queue_remove(station->networks_sorted, network);
	l_hashmap_remove(station->networks, path);

	while ((bss = network_bss_list_pop(network))) {
		memset(bss->ssid, 0, bss->ssid_len);
		l_queue_remove_if(station->hidden_bss_list_sorted,
					bss_match_bssid, bss->addr);
		l_queue_insert(station->hidden_bss_list_sorted, bss,
					bss_signal_strength_compare, NULL);
	}

	network_remove(network, -ESRCH);

	return 0;
}

static void station_add_one_freq(uint32_t freq, void *user_data)
{
	struct station *station = user_data;

	if (freq > 3000)
		scan_freq_set_add(station->scan_freqs_order[1], freq);
	else if (!scan_freq_set_contains(station->scan_freqs_order[0], freq))
		scan_freq_set_add(station->scan_freqs_order[2], freq);
}

static void station_fill_scan_freq_subsets(struct station *station)
{
	const struct scan_freq_set *supported =
		wiphy_get_supported_freqs(station->wiphy);

	/*
	 * Scan the 2.4GHz "social channels" first, 5GHz second, if supported,
	 * all other 2.4GHz channels last.  To be refined as needed.
	 */
	station->scan_freqs_order[0] = scan_freq_set_new();
	scan_freq_set_add(station->scan_freqs_order[0], 2412);
	scan_freq_set_add(station->scan_freqs_order[0], 2437);
	scan_freq_set_add(station->scan_freqs_order[0], 2462);

	station->scan_freqs_order[1] = scan_freq_set_new();
	station->scan_freqs_order[2] = scan_freq_set_new();
	scan_freq_set_foreach(supported, station_add_one_freq, station);

	if (scan_freq_set_isempty(station->scan_freqs_order[1])) {
		scan_freq_set_free(station->scan_freqs_order[1]);
		station->scan_freqs_order[1] = station->scan_freqs_order[2];
		station->scan_freqs_order[2] = NULL;
	}
}

static void station_wiphy_watch(struct wiphy *wiphy,
				enum wiphy_state_watch_event event,
				void *user_data)
{
	struct station *station = user_data;
	int ret;

	if (event != WIPHY_STATE_WATCH_EVENT_REGDOM_DONE)
		return;

	/*
	 * The only state that requires special handling is for
	 * quick scans since the previous quick scan was delayed until
	 * the regulatory domain updated. Try again in case 6Ghz is now
	 * unlocked (unlikely), or advance to full autoconnect. Just in
	 * case this update came during a quick scan, ignore it.
	 */
	if (station->state != STATION_STATE_AUTOCONNECT_QUICK ||
			station->quick_scan_id)
		return;

	ret = station_quick_scan_trigger(station);
	if (!ret)
		return;

	L_WARN_ON(ret == -EAGAIN);
	station_enter_state(station, STATION_STATE_AUTOCONNECT_FULL);
}

static struct station *station_create(struct netdev *netdev)
{
	struct station *station;
	struct l_dbus *dbus = dbus_get_bus();
	bool autoconnect = true;

	station = l_new(struct station, 1);
	watchlist_init(&station->state_watches, NULL);

	station->bss_list = l_queue_new();
	station->hidden_bss_list_sorted = l_queue_new();
	station->networks = l_hashmap_new();
	l_hashmap_set_hash_function(station->networks, l_str_hash);
	l_hashmap_set_compare_function(station->networks,
				(l_hashmap_compare_func_t) strcmp);
	station->networks_sorted = l_queue_new();

	station->wiphy = netdev_get_wiphy(netdev);
	station->netdev = netdev;

	station->wiphy_watch = wiphy_state_watch_add(station->wiphy,
							station_wiphy_watch,
							station, NULL);

	l_queue_push_head(station_list, station);

	l_dbus_object_add_interface(dbus, netdev_get_path(netdev),
					IWD_STATION_INTERFACE, station);

	if (netconfig_enabled())
		station->netconfig = netconfig_new(netdev_get_ifindex(netdev));

	station->anqp_pending = l_queue_new();

	station_fill_scan_freq_subsets(station);

	if (iwd_is_developer_mode()) {
		l_dbus_object_add_interface(dbus,
					netdev_get_path(station->netdev),
					IWD_STATION_DEBUG_INTERFACE,
					station);
		autoconnect = false;
	}

	station_set_autoconnect(station, autoconnect);

	station->roam_bss_list = l_queue_new();

	return station;
}

static void station_free(struct station *station)
{
	l_debug("");

	if (!l_queue_remove(station_list, station))
		return;

	l_dbus_object_remove_interface(dbus_get_bus(),
					netdev_get_path(station->netdev),
					IWD_STATION_DIAGNOSTIC_INTERFACE);
	if (iwd_is_developer_mode())
		l_dbus_object_remove_interface(dbus_get_bus(),
					netdev_get_path(station->netdev),
					IWD_STATION_DEBUG_INTERFACE);

	if (station->netconfig) {
		netconfig_destroy(station->netconfig);
		station->netconfig = NULL;
	}

	periodic_scan_stop(station);

	if (station->signal_agent) {
		station_signal_agent_release(station->signal_agent,
					netdev_get_path(station->netdev));
		signal_agent_free(station->signal_agent);
	}

	if (station->connect_pending)
		dbus_pending_reply(&station->connect_pending,
				dbus_error_aborted(station->connect_pending));

	if (station->hidden_pending)
		dbus_pending_reply(&station->hidden_pending,
				dbus_error_aborted(station->hidden_pending));

	if (station->disconnect_pending)
		dbus_pending_reply(&station->disconnect_pending,
			dbus_error_aborted(station->disconnect_pending));

	if (station->scan_pending)
		dbus_pending_reply(&station->scan_pending,
			dbus_error_aborted(station->scan_pending));

	if (station->dbus_scan_id)
		scan_cancel(netdev_get_wdev_id(station->netdev),
				station->dbus_scan_id);

	if (station->quick_scan_id)
		scan_cancel(netdev_get_wdev_id(station->netdev),
				station->quick_scan_id);

	if (station->hidden_network_scan_id)
		scan_cancel(netdev_get_wdev_id(station->netdev),
				station->hidden_network_scan_id);

	if (station->owe_hidden_scan_ids) {
		void *ptr;

		while ((ptr = l_queue_pop_head(station->owe_hidden_scan_ids)))
			scan_cancel(netdev_get_wdev_id(station->netdev),
					L_PTR_TO_UINT(ptr));

		l_queue_destroy(station->owe_hidden_scan_ids, NULL);
	}

	station_roam_state_clear(station);

	l_queue_destroy(station->networks_sorted, NULL);
	l_hashmap_destroy(station->networks, network_free);
	l_queue_destroy(station->bss_list, bss_free);
	l_queue_destroy(station->hidden_bss_list_sorted, NULL);
	l_queue_destroy(station->autoconnect_list, NULL);

	watchlist_destroy(&station->state_watches);

	l_queue_destroy(station->anqp_pending, remove_anqp);

	scan_freq_set_free(station->scan_freqs_order[0]);
	scan_freq_set_free(station->scan_freqs_order[1]);

	if (station->scan_freqs_order[2])
		scan_freq_set_free(station->scan_freqs_order[2]);

	wiphy_state_watch_remove(station->wiphy, station->wiphy_watch);

	l_queue_destroy(station->roam_bss_list, l_free);

	l_free(station);
}

static void station_setup_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "ConnectHiddenNetwork", 0,
				station_dbus_connect_hidden_network,
				"", "s", "name");
	l_dbus_interface_method(interface, "Disconnect", 0,
				station_dbus_disconnect, "", "");
	l_dbus_interface_method(interface, "GetOrderedNetworks", 0,
				station_dbus_get_networks, "a(on)", "",
				"networks");
	l_dbus_interface_method(interface, "GetHiddenAccessPoints", 0,
				station_dbus_get_hidden_access_points,
				"a(sns)", "",
				"accesspoints");
	l_dbus_interface_method(interface, "Scan", 0,
				station_dbus_scan, "", "");
	l_dbus_interface_method(interface, "RegisterSignalLevelAgent", 0,
				station_dbus_signal_agent_register,
				"", "oan", "path", "levels");
	l_dbus_interface_method(interface, "UnregisterSignalLevelAgent", 0,
				station_dbus_signal_agent_unregister,
				"", "o", "path");

	l_dbus_interface_property(interface, "ConnectedNetwork", 0, "o",
					station_property_get_connected_network,
					NULL);
	l_dbus_interface_property(interface, "Scanning", 0, "b",
					station_property_get_scanning, NULL);
	l_dbus_interface_property(interface, "State", 0, "s",
					station_property_get_state, NULL);
}

static void station_destroy_interface(void *user_data)
{
	struct station *station = user_data;

	station_free(station);
}

static void station_get_diagnostic_cb(
				const struct diagnostic_station_info *info,
				void *user_data)
{
	struct station *station = user_data;
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;
	struct handshake_state *hs = netdev_get_handshake(station->netdev);

	if (!info) {
		reply = dbus_error_aborted(station->get_station_pending);
		goto done;
	}

	reply = l_dbus_message_new_method_return(station->get_station_pending);

	builder = l_dbus_message_builder_new(reply);

	l_dbus_message_builder_enter_array(builder, "{sv}");

	dbus_append_dict_basic(builder, "ConnectedBss", 's',
					util_address_to_string(info->addr));
	dbus_append_dict_basic(builder, "Frequency", 'u',
				&station->connected_bss->frequency);
	dbus_append_dict_basic(builder, "Security", 's',
				diagnostic_akm_suite_to_security(hs->akm_suite,
								hs->wpa_ie));

	if (hs->pairwise_cipher) {
		const char *str;

		if (hs->pairwise_cipher ==
				IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER)
			str = ie_rsn_cipher_suite_to_string(hs->group_cipher);
		else
			str = ie_rsn_cipher_suite_to_string(
							hs->pairwise_cipher);

		if (str)
			dbus_append_dict_basic(builder, "PairwiseCipher",
						's', str);
	}

	diagnostic_info_to_dict(info, builder);

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

done:
	dbus_pending_reply(&station->get_station_pending, reply);
}

static void station_get_diagnostic_destroy(void *user_data)
{
	struct station *station = user_data;
	struct l_dbus_message *reply;

	if (station->get_station_pending) {
		reply = dbus_error_aborted(station->get_station_pending);
		dbus_pending_reply(&station->get_station_pending, reply);
	}
}

static struct l_dbus_message *station_get_diagnostics(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	int ret;

	if (station->get_station_pending)
		return dbus_error_busy(message);

	ret = netdev_get_current_station(station->netdev,
				station_get_diagnostic_cb, station,
				station_get_diagnostic_destroy);
	if (ret < 0)
		return dbus_error_from_errno(ret, message);

	station->get_station_pending = l_dbus_message_ref(message);

	return NULL;
}

struct station_roam_data {
	struct station *station;
	struct l_dbus_message *pending;
	uint8_t bssid[6];
};

static void station_force_roam_scan_triggered(int err, void *user_data)
{
	struct station_roam_data *data = user_data;
	struct station *station = data->station;

	if (err)
		station_roam_failed(station);
}

static bool station_force_roam_scan_notify(int err, struct l_queue *bss_list,
					const struct scan_freq_set *freqs,
					void *user_data)
{
	struct station_roam_data *data = user_data;
	struct station *station = data->station;
	struct scan_bss *target;
	struct l_dbus_message *reply;

	if (err) {
		reply = dbus_error_from_errno(err, data->pending);
		goto reply;
	}

	target = l_queue_remove_if(bss_list, bss_match_bssid, data->bssid);
	if (!target) {
		reply = dbus_error_not_found(data->pending);
		goto reply;
	}

	l_debug("Attempting forced roam to BSS "MAC, MAC_STR(target->addr));

	/* The various roam routines expect this to be set from scanning */
	station->preparing_roam = true;
	l_queue_push_tail(station->roam_bss_list,
				roam_bss_from_scan_bss(target));

	station_update_roam_bss(station, target);

	station_transition_start(station);

	reply = l_dbus_message_new_method_return(data->pending);

reply:
	dbus_pending_reply(&data->pending, reply);

	return false;
}

static void station_force_roam_scan_destroy(void *user_data)
{
	struct station_roam_data *data = user_data;

	data->station->roam_scan_id = 0;

	if (data->pending)
		l_dbus_message_unref(data->pending);

	l_free(data);
}

static struct l_dbus_message *station_force_roam(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	struct scan_bss *target;
	struct l_dbus_message_iter iter;
	uint8_t *mac;
	uint32_t mac_len;
	struct scan_parameters params = { 0 };
	struct scan_freq_set *freqs = NULL;
	struct station_roam_data *data;

	if (!l_dbus_message_get_arguments(message, "ay", &iter))
		goto invalid_args;

	if (!l_dbus_message_iter_get_fixed_array(&iter, &mac, &mac_len))
		goto invalid_args;

	if (mac_len != 6)
		return dbus_error_invalid_args(message);

	if (!station->connected_network)
		return dbus_error_not_connected(message);

	target = network_bss_find_by_addr(station->connected_network, mac);
	if (!target)
		goto full_scan;

	if (target && target == station->connected_bss)
		return dbus_error_already_exists(message);

	if (station->connected_bss->ssid_len != target->ssid_len)
		goto invalid_args;

	if (memcmp(station->connected_bss->ssid, target->ssid,
				target->ssid_len))
		goto invalid_args;

	/*
	 * Always scan before a roam to ensure the kernel has the BSS in its
	 * cache. If we already see the BSS only scan that frequency
	 */
	freqs = scan_freq_set_new();
	scan_freq_set_add(freqs, target->frequency);

	params.freqs = freqs;

full_scan:
	params.flush = true;

	data = l_new(struct station_roam_data, 1);
	data->station = station;
	data->pending = l_dbus_message_ref(message);
	memcpy(data->bssid, mac, 6);

	station->roam_scan_id = scan_active_full(
					netdev_get_wdev_id(station->netdev),
					&params,
					station_force_roam_scan_triggered,
					station_force_roam_scan_notify, data,
					station_force_roam_scan_destroy);

	if (freqs)
		scan_freq_set_free(freqs);

	if (!station->roam_scan_id) {
		l_free(data);
		return dbus_error_failed(message);
	}

	if (freqs)
		l_debug("Scanning on %u for BSS "MAC, target->frequency,
			MAC_STR(mac));
	else
		l_debug("Full scan for BSS "MAC, MAC_STR(mac));

	return NULL;

invalid_args:
	return dbus_error_invalid_args(message);
}

static struct network *station_find_network_from_bss(struct station *station,
						struct scan_bss *bss)
{
	enum security security;
	char ssid[33];

	memcpy(ssid, bss->ssid, bss->ssid_len);
	ssid[bss->ssid_len] = '\0';

	if (scan_bss_get_security(bss, &security) < 0)
		return NULL;

	return station_network_find(station, ssid, security);
}

static void station_setup_diagnostic_interface(
					struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "GetDiagnostics", 0,
				station_get_diagnostics, "a{sv}", "",
				"diagnostics");
}

static void station_destroy_diagnostic_interface(void *user_data)
{
}

static struct l_dbus_message *station_force_connect_bssid(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	struct l_queue *bss_list;
	struct scan_bss *target;
	struct network *network;
	struct l_dbus_message_iter iter;
	uint8_t *mac;
	uint32_t mac_len;

	if (!l_dbus_message_get_arguments(message, "ay", &iter))
		goto invalid_args;

	if (!l_dbus_message_iter_get_fixed_array(&iter, &mac, &mac_len))
		goto invalid_args;

	if (mac_len != 6)
		return dbus_error_invalid_args(message);

	bss_list = station_get_bss_list(station);

	target = l_queue_find(bss_list, bss_match_bssid, mac);
	if (!target)
		return dbus_error_invalid_args(message);

	if (util_ssid_is_hidden(target->ssid_len, target->ssid))
		return dbus_error_not_found(message);

	network = station_find_network_from_bss(station, target);
	if (!network)
		return dbus_error_invalid_args(message);

	l_debug("Attempting forced connection to BSS "MAC, MAC_STR(mac));

	return __network_connect(network, target, message);

invalid_args:
	return dbus_error_invalid_args(message);
}

static void station_debug_scan_triggered(int err, void *user_data)
{
	struct station *station = user_data;
	struct l_dbus_message *reply;

	if (err < 0) {
		if (station->scan_pending) {
			reply = dbus_error_from_errno(err,
							station->scan_pending);
			dbus_pending_reply(&station->scan_pending, reply);
		}

		station_dbus_scan_done(station, false);
		return;
	}

	l_debug("debug scan triggered for %s",
			netdev_get_name(station->netdev));

	if (station->scan_pending) {
		reply = l_dbus_message_new_method_return(station->scan_pending);
		l_dbus_message_set_arguments(reply, "");
		dbus_pending_reply(&station->scan_pending, reply);
	}

	station_property_set_scanning(station, true);
}

static bool station_debug_scan_results(int err, struct l_queue *bss_list,
					const struct scan_freq_set *freqs,
					void *userdata)
{
	struct station *station = userdata;

	if (err) {
		station_dbus_scan_done(station, false);
		return false;
	}

	station_set_scan_results(station, bss_list, freqs, false);
	station_dbus_scan_done(station, false);

	return true;
}

static struct l_dbus_message *station_debug_scan(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	struct l_dbus_message_iter iter;
	uint16_t *freqs;
	uint32_t freqs_len;
	struct scan_freq_set *freq_set;
	unsigned int i;

	if (station->dbus_scan_id)
		return dbus_error_busy(message);

	if (station->state == STATION_STATE_CONNECTING ||
			station->state == STATION_STATE_CONNECTING_AUTO)
		return dbus_error_busy(message);

	if (!l_dbus_message_get_arguments(message, "aq", &iter))
		goto invalid_args;

	if (!l_dbus_message_iter_get_fixed_array(&iter, &freqs, &freqs_len))
		goto invalid_args;

	freq_set = scan_freq_set_new();

	for (i = 0; i < freqs_len; i++) {
		if (scan_freq_set_contains(freq_set, (uint32_t)freqs[i]))
			continue;

		if (!scan_freq_set_add(freq_set, (uint32_t)freqs[i])) {
			scan_freq_set_free(freq_set);
			goto invalid_args;
		}

		l_debug("added frequency %u", freqs[i]);
	}

	station->dbus_scan_id = station_scan_trigger(station, freq_set,
						station_debug_scan_triggered,
						station_debug_scan_results,
						NULL);

	scan_freq_set_free(freq_set);

	if (!station->dbus_scan_id)
		goto failed;

	station->scan_pending = l_dbus_message_ref(message);

	return NULL;

failed:
	return dbus_error_failed(message);
invalid_args:
	return dbus_error_invalid_args(message);
}

static bool station_property_get_autoconnect(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct station *station = user_data;
	bool autoconnect;

	autoconnect = station->autoconnect;

	l_dbus_message_builder_append_basic(builder, 'b', &autoconnect);

	return true;
}

static struct l_dbus_message *station_property_set_autoconnect(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct station *station = user_data;
	bool autoconnect;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &autoconnect))
		return dbus_error_invalid_args(message);

	l_debug("Setting autoconnect %s", autoconnect ? "true" : "false");

	station_set_autoconnect(station, autoconnect);

	return l_dbus_message_new_method_return(message);
}

static void station_append_byte_array(struct l_dbus_message_builder *builder,
					const char *name,
					const uint8_t *bytes, size_t len)
{
	size_t i;

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', name);
	l_dbus_message_builder_enter_variant(builder, "ay");
	l_dbus_message_builder_enter_array(builder, "y");

	for (i = 0; i < len; i++)
		l_dbus_message_builder_append_basic(builder, 'y', &bytes[i]);

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);
}

static void station_append_bss_list(struct l_dbus_message_builder *builder,
					const struct l_queue_entry *entry)
{
	for (; entry; entry = entry->next) {
		struct scan_bss *bss = entry->data;
		int32_t rssi = bss->signal_strength / 100;

		l_dbus_message_builder_enter_array(builder, "{sv}");

		dbus_append_dict_basic(builder, "Frequency", 'u',
						&bss->frequency);
		dbus_append_dict_basic(builder, "RSSI", 'i',
						&rssi);
		dbus_append_dict_basic(builder, "Rank", 'q', &bss->rank);

		dbus_append_dict_basic(builder, "Address", 's',
					util_address_to_string(bss->addr));

		station_append_byte_array(builder, "MDE", bss->mde, 3);

		l_dbus_message_builder_leave_array(builder);
	}
}

static struct l_dbus_message *station_debug_get_networks(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct station *station = user_data;
	struct l_dbus_message *reply =
				l_dbus_message_new_method_return(message);
	struct l_dbus_message_builder *builder =
				l_dbus_message_builder_new(reply);
	const struct l_queue_entry *entry;

	l_dbus_message_builder_enter_array(builder, "{oaa{sv}}");

	if (l_queue_isempty(station->networks_sorted))
		goto done;

	for (entry = l_queue_get_entries(station->networks_sorted); entry;
							entry = entry->next) {
		const struct network *network = entry->data;

		l_dbus_message_builder_enter_dict(builder, "oaa{sv}");
		l_dbus_message_builder_append_basic(builder, 'o',
						network_get_path(network));
		l_dbus_message_builder_enter_array(builder, "a{sv}");

		station_append_bss_list(builder,
					network_bss_list_get_entries(network));

		l_dbus_message_builder_leave_array(builder);
		l_dbus_message_builder_leave_dict(builder);
	}

done:
	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static void station_setup_debug_interface(
					struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "ConnectBssid", 0,
					station_force_connect_bssid, "", "ay",
					"mac");
	l_dbus_interface_method(interface, "Roam", 0,
					station_force_roam, "", "ay", "mac");

	l_dbus_interface_method(interface, "Scan", 0,
					station_debug_scan, "", "aq",
					"frequencies");
	l_dbus_interface_method(interface, "GetNetworks", 0,
				station_debug_get_networks, "a{oaa{sv}}", "",
				"networks");

	l_dbus_interface_signal(interface, "Event", 0, "sav", "name", "data");

	l_dbus_interface_property(interface, "AutoConnect", 0, "b",
					station_property_get_autoconnect,
					station_property_set_autoconnect);
}

static void ap_roam_frame_event(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	uint32_t ifindex = L_PTR_TO_UINT(user_data);
	struct station *station = station_find(ifindex);

	if (!station)
		return;

	station_ap_directed_roam(station, hdr, body, body_len);
}

static void add_frame_watches(struct netdev *netdev)
{
	static const uint8_t action_ap_roam_prefix[2] = { 0x0a, 0x07 };

	/*
	 * register for AP roam transition watch
	 */
	frame_watch_add(netdev_get_wdev_id(netdev), 0, 0x00d0,
			action_ap_roam_prefix, sizeof(action_ap_roam_prefix),
			ap_roam_frame_event,
			L_UINT_TO_PTR(netdev_get_ifindex(netdev)), NULL);
}

static void station_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_NEW:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_STATION) {
			add_frame_watches(netdev);

			if (netdev_get_is_up(netdev))
				station_create(netdev);
		}
		break;
	case NETDEV_WATCH_EVENT_UP:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_STATION)
			station_create(netdev);

		break;
	case NETDEV_WATCH_EVENT_DOWN:
	case NETDEV_WATCH_EVENT_DEL:
		l_dbus_object_remove_interface(dbus_get_bus(),
						netdev_get_path(netdev),
						IWD_STATION_INTERFACE);
		break;
	case NETDEV_WATCH_EVENT_IFTYPE_CHANGE:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_STATION)
			add_frame_watches(netdev);

		break;
	default:
		break;
	}
}

static void station_known_networks_changed(enum known_networks_event event,
						const struct network_info *info,
						void *user_data)
{
	_auto_(l_free) char *network_id = NULL;

	if (event != KNOWN_NETWORKS_EVENT_REMOVED)
		return;

	if (info->type != SECURITY_8021X)
		return;

	network_id = l_util_hexstring(info->ssid, strlen(info->ssid));
	eap_tls_forget_peer(network_id);
}

static int station_init(void)
{
	station_list = l_queue_new();
	netdev_watch = netdev_watch_add(station_netdev_watch, NULL, NULL);
	l_dbus_register_interface(dbus_get_bus(), IWD_STATION_INTERFACE,
					station_setup_interface,
					station_destroy_interface, false);
	l_dbus_register_interface(dbus_get_bus(),
					IWD_STATION_DIAGNOSTIC_INTERFACE,
					station_setup_diagnostic_interface,
					station_destroy_diagnostic_interface,
					false);
	if (iwd_is_developer_mode())
		l_dbus_register_interface(dbus_get_bus(),
					IWD_STATION_DEBUG_INTERFACE,
					station_setup_debug_interface,
					NULL,
					false);

	if (!l_settings_get_uint(iwd_get_config(), "General",
					"ManagementFrameProtection",
					&mfp_setting))
		mfp_setting = 1;

	if (mfp_setting > 2) {
		l_error("Invalid [General].ManagementFrameProtection value: %d,"
				" using default of 1", mfp_setting);
		mfp_setting = 1;
	}

	if (!l_settings_get_uint(iwd_get_config(), "General",
				"RoamRetryInterval",
				&roam_retry_interval))
		roam_retry_interval = 60;

	if (roam_retry_interval > INT_MAX)
		roam_retry_interval = INT_MAX;

	if (!l_settings_get_bool(iwd_get_config(), "General", "DisableANQP",
				&anqp_disabled))
		anqp_disabled = true;

	if (!netconfig_enabled())
		l_info("station: Network configuration is disabled.");

	supports_arp_evict_nocarrier = sysfs_supports_ipv4_setting("all",
						"arp_evict_nocarrier");
	supports_ndisc_evict_nocarrier = sysfs_supports_ipv6_setting("all",
						"ndisc_evict_nocarrier");

	watchlist_init(&event_watches, NULL);

	eap_tls_set_session_cache_ops(storage_eap_tls_cache_load,
					storage_eap_tls_cache_sync);
	known_networks_watch = known_networks_watch_add(
						station_known_networks_changed,
						NULL, NULL);

	return 0;
}

static void station_exit(void)
{
	l_dbus_unregister_interface(dbus_get_bus(),
					IWD_STATION_DIAGNOSTIC_INTERFACE);
	if (iwd_is_developer_mode())
		l_dbus_unregister_interface(dbus_get_bus(),
					IWD_STATION_DEBUG_INTERFACE);
	l_dbus_unregister_interface(dbus_get_bus(), IWD_STATION_INTERFACE);
	netdev_watch_remove(netdev_watch);
	l_queue_destroy(station_list, NULL);
	station_list = NULL;
	watchlist_destroy(&event_watches);
	known_networks_watch_remove(known_networks_watch);
	known_networks_watch = 0;
}

IWD_MODULE(station, station_init, station_exit)
IWD_MODULE_DEPENDS(station, known_networks)
IWD_MODULE_DEPENDS(station, netdev);
IWD_MODULE_DEPENDS(station, netconfig);
IWD_MODULE_DEPENDS(station, frame_xchg);
IWD_MODULE_DEPENDS(station, wiphy);
