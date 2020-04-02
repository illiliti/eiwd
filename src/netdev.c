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

#include <stdlib.h>
#include <alloca.h>
#include <stdio.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <sys/socket.h>
#include <errno.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/module.h"
#include "src/wiphy.h"
#include "src/ie.h"
#include "src/mpdu.h"
#include "src/eapol.h"
#include "src/handshake.h"
#include "src/crypto.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/ft.h"
#include "src/util.h"
#include "src/watchlist.h"
#include "src/sae.h"
#include "src/nl80211util.h"
#include "src/nl80211cmd.h"
#include "src/owe.h"
#include "src/fils.h"
#include "src/auth-proto.h"
#include "src/frame-xchg.h"

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

static uint32_t unicast_watch;

struct netdev_handshake_state {
	struct handshake_state super;
	uint32_t pairwise_new_key_cmd_id;
	uint32_t group_new_key_cmd_id;
	uint32_t group_management_new_key_cmd_id;
	uint32_t set_station_cmd_id;
	bool ptk_installed;
	bool gtk_installed;
	bool igtk_installed;
	bool complete;
	struct netdev *netdev;
};

struct netdev {
	uint32_t index;
	uint64_t wdev_id;
	char name[IFNAMSIZ];
	uint32_t type;
	uint8_t addr[ETH_ALEN];
	struct wiphy *wiphy;
	unsigned int ifi_flags;
	uint32_t frequency;
	uint32_t prev_frequency;

	netdev_event_func_t event_filter;
	netdev_connect_cb_t connect_cb;
	netdev_disconnect_cb_t disconnect_cb;
	netdev_neighbor_report_cb_t neighbor_report_cb;
	netdev_command_cb_t adhoc_cb;
	void *user_data;
	struct eapol_sm *sm;
	struct sae_sm *sae_sm;
	struct auth_proto *ap;
	struct handshake_state *handshake;
	uint32_t connect_cmd_id;
	uint32_t disconnect_cmd_id;
	uint32_t join_adhoc_cmd_id;
	uint32_t leave_adhoc_cmd_id;
	uint32_t set_interface_cmd_id;
	uint32_t rekey_offload_cmd_id;
	uint32_t qos_map_cmd_id;
	uint32_t mac_change_cmd_id;
	enum netdev_result result;
	uint16_t last_code; /* reason or status, depending on result */
	struct l_timeout *neighbor_report_timeout;
	struct l_timeout *sa_query_timeout;
	struct l_timeout *group_handshake_timeout;
	struct l_timeout *gas_timeout;
	uint16_t sa_query_id;
	uint8_t prev_bssid[ETH_ALEN];
	uint8_t prev_snonce[32];
	int8_t rssi_levels[16];
	uint8_t rssi_levels_num;
	uint8_t cur_rssi_level_idx;
	int8_t cur_rssi;
	struct l_timeout *rssi_poll_timeout;
	uint32_t rssi_poll_cmd_id;
	uint8_t set_mac_once[6];

	uint32_t set_powered_cmd_id;
	netdev_command_cb_t set_powered_cb;
	void *set_powered_user_data;
	netdev_destroy_func_t set_powered_destroy;

	struct watchlist station_watches;

	struct l_io *pae_io;  /* for drivers without EAPoL over NL80211 */

	bool connected : 1;
	bool operational : 1;
	bool rekey_offload_support : 1;
	bool pae_over_nl80211 : 1;
	bool in_ft : 1;
	bool cur_rssi_low : 1;
	bool use_4addr : 1;
	bool ignore_connect_event : 1;
	bool expect_connect_failure : 1;
	bool aborting : 1;
	bool events_ready : 1;
};

struct netdev_preauth_state {
	netdev_preauthenticate_cb_t cb;
	void *user_data;
	struct netdev *netdev;
};

struct netdev_watch {
	uint32_t id;
	netdev_watch_func_t callback;
	void *user_data;
};

static struct l_netlink *rtnl = NULL;
static struct l_genl_family *nl80211;
static struct l_queue *netdev_list;
static struct watchlist netdev_watches;
static bool pae_over_nl80211;
static bool mac_per_ssid;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

/* Cancels ongoing GTK/IGTK related commands (if any) */
static void netdev_handshake_state_cancel_rekey(
					struct netdev_handshake_state *nhs)
{
	if (nhs->group_new_key_cmd_id) {
		l_genl_family_cancel(nl80211, nhs->group_new_key_cmd_id);
		nhs->group_new_key_cmd_id = 0;
	}

	if (nhs->group_management_new_key_cmd_id) {
		l_genl_family_cancel(nl80211,
					nhs->group_management_new_key_cmd_id);
		nhs->group_management_new_key_cmd_id = 0;
	}
}

static void netdev_handshake_state_cancel_all(
					struct netdev_handshake_state *nhs)
{
	if (nhs->pairwise_new_key_cmd_id) {
		l_genl_family_cancel(nl80211, nhs->pairwise_new_key_cmd_id);
		nhs->pairwise_new_key_cmd_id = 0;
	}

	netdev_handshake_state_cancel_rekey(nhs);

	if (nhs->set_station_cmd_id) {
		l_genl_family_cancel(nl80211, nhs->set_station_cmd_id);
		nhs->set_station_cmd_id = 0;
	}
}

static void netdev_handshake_state_free(struct handshake_state *hs)
{
	struct netdev_handshake_state *nhs =
		l_container_of(hs, struct netdev_handshake_state, super);

	netdev_handshake_state_cancel_all(nhs);
	l_free(nhs);
}

struct handshake_state *netdev_handshake_state_new(struct netdev *netdev)
{
	struct netdev_handshake_state *nhs;

	nhs = l_new(struct netdev_handshake_state, 1);

	nhs->super.ifindex = netdev->index;
	nhs->super.free = netdev_handshake_state_free;

	nhs->netdev = netdev;
	/*
	 * Since GTK/IGTK are optional (NO_GROUP_TRAFFIC), we set them as
	 * 'installed' upon initialization. If/When the gtk/igtk callback is
	 * called they will get set to false until we have received a successful
	 * callback from nl80211. From these callbacks we can check that all
	 * the keys have been installed, and only then trigger the handshake
	 * complete callback.
	 */
	nhs->gtk_installed = true;
	nhs->igtk_installed = true;

	return &nhs->super;
}

struct wiphy *netdev_get_wiphy(struct netdev *netdev)
{
	return netdev->wiphy;
}

const uint8_t *netdev_get_address(struct netdev *netdev)
{
	return netdev->addr;
}

uint32_t netdev_get_ifindex(struct netdev *netdev)
{
	return netdev->index;
}

uint64_t netdev_get_wdev_id(struct netdev *netdev)
{
	return netdev->wdev_id;
}

enum netdev_iftype netdev_get_iftype(struct netdev *netdev)
{
	switch (netdev->type) {
	case NL80211_IFTYPE_STATION:
		return NETDEV_IFTYPE_STATION;
	case NL80211_IFTYPE_AP:
		return NETDEV_IFTYPE_AP;
	case NL80211_IFTYPE_ADHOC:
		return NETDEV_IFTYPE_ADHOC;
	case NL80211_IFTYPE_P2P_CLIENT:
		return NETDEV_IFTYPE_P2P_CLIENT;
	case NL80211_IFTYPE_P2P_GO:
		return NETDEV_IFTYPE_P2P_GO;
	default:
		/* can't really do much here */
		l_error("unknown iftype %u", netdev->type);
		return NETDEV_IFTYPE_STATION;
	}
}

const char *netdev_get_name(struct netdev *netdev)
{
	return netdev->name;
}

bool netdev_get_is_up(struct netdev *netdev)
{
	bool powered = (netdev->ifi_flags & IFF_UP) != 0;

	/*
	 * If we are in the middle of changing the MAC we are in somewhat of a
	 * no mans land. Technically the iface may be down, but since we are
	 * not emitting any netdev DOWN events we want netdev_get_is_up to
	 * reflect the same state. Once MAC changing finishes any pending
	 * DOWN events will be emitted.
	 */
	if (netdev->mac_change_cmd_id && !powered)
		return true;

	return powered;
}

struct handshake_state *netdev_get_handshake(struct netdev *netdev)
{
	return netdev->handshake;
}

const char *netdev_get_path(struct netdev *netdev)
{
	static char path[256];

	L_WARN_ON(snprintf(path, sizeof(path), "%s/%u",
				wiphy_get_path(netdev->wiphy),
				netdev->index) >= (int) sizeof(path));
	path[sizeof(path) - 1] = '\0';

	return path;
}

static void netdev_set_powered_result(int error, uint16_t type,
					const void *data,
					uint32_t len, void *user_data)
{
	struct netdev *netdev = user_data;

	if (netdev->set_powered_cb)
		netdev->set_powered_cb(netdev, error,
						netdev->set_powered_user_data);

	netdev->set_powered_cb = NULL;
}

static void netdev_set_powered_destroy(void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->set_powered_cmd_id = 0;

	if (netdev->set_powered_destroy)
		netdev->set_powered_destroy(netdev->set_powered_user_data);

	netdev->set_powered_destroy = NULL;
	netdev->set_powered_user_data = NULL;
}

int netdev_set_powered(struct netdev *netdev, bool powered,
			netdev_command_cb_t callback, void *user_data,
			netdev_destroy_func_t destroy)
{
	if (netdev->set_powered_cmd_id ||
			netdev->set_interface_cmd_id)
		return -EBUSY;

	netdev->set_powered_cmd_id =
		l_rtnl_set_powered(rtnl, netdev->index, powered,
					netdev_set_powered_result, netdev,
					netdev_set_powered_destroy);
	if (!netdev->set_powered_cmd_id)
		return -EIO;

	netdev->set_powered_cb = callback;
	netdev->set_powered_user_data = user_data;
	netdev->set_powered_destroy = destroy;

	return 0;
}

static void netdev_set_rssi_level_idx(struct netdev *netdev)
{
	uint8_t new_level;

	for (new_level = 0; new_level < netdev->rssi_levels_num; new_level++)
		if (netdev->cur_rssi >= netdev->rssi_levels[new_level])
			break;

	netdev->cur_rssi_level_idx = new_level;
}

static void netdev_rssi_poll_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_attr attr, nested;
	uint16_t type, len;
	const void *data;
	bool found;
	uint8_t prev_rssi_level_idx = netdev->cur_rssi_level_idx;

	netdev->rssi_poll_cmd_id = 0;

	if (!l_genl_attr_init(&attr, msg))
		goto done;

	found = false;
	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		if (type != NL80211_ATTR_STA_INFO)
			continue;

		found = true;
		break;
	}

	if (!found || !l_genl_attr_recurse(&attr, &nested))
		goto done;

	found = false;
	while (l_genl_attr_next(&nested, &type, &len, &data)) {
		if (type != NL80211_STA_INFO_SIGNAL_AVG)
			continue;

		if (len != 1)
			continue;

		found = true;
		netdev->cur_rssi = *(const int8_t *) data;
		break;
	}

	if (!found)
		goto done;

	/*
	 * Note we don't have to handle LOW_SIGNAL_THRESHOLD here.  The
	 * CQM single threshold RSSI monitoring should work even if the
	 * kernel driver doesn't support multiple thresholds.  So the
	 * polling only handles the client-supplied threshold list.
	 */
	netdev_set_rssi_level_idx(netdev);
	if (netdev->cur_rssi_level_idx != prev_rssi_level_idx)
		netdev->event_filter(netdev, NETDEV_EVENT_RSSI_LEVEL_NOTIFY,
					&netdev->cur_rssi_level_idx,
					netdev->user_data);

done:
	/* Rearm timer */
	l_timeout_modify(netdev->rssi_poll_timeout, 6);
}

static void netdev_rssi_poll(struct l_timeout *timeout, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_GET_STATION, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN,
							netdev->handshake->aa);

	netdev->rssi_poll_cmd_id = l_genl_family_send(nl80211, msg,
							netdev_rssi_poll_cb,
							netdev, NULL);
}

/* To be called whenever operational or rssi_levels_num are updated */
static void netdev_rssi_polling_update(struct netdev *netdev)
{
	if (wiphy_has_ext_feature(netdev->wiphy,
					NL80211_EXT_FEATURE_CQM_RSSI_LIST))
		return;

	if (netdev->operational && netdev->rssi_levels_num > 0) {
		if (netdev->rssi_poll_timeout)
			return;

		netdev->rssi_poll_timeout =
			l_timeout_create(1, netdev_rssi_poll, netdev, NULL);
	} else {
		if (!netdev->rssi_poll_timeout)
			return;

		l_timeout_remove(netdev->rssi_poll_timeout);
		netdev->rssi_poll_timeout = NULL;

		if (netdev->rssi_poll_cmd_id) {
			l_genl_family_cancel(nl80211, netdev->rssi_poll_cmd_id);
			netdev->rssi_poll_cmd_id = 0;
		}
	}
}

static void netdev_preauth_destroy(void *data)
{
	struct netdev_preauth_state *state = data;

	if (state->cb)
		state->cb(state->netdev, NETDEV_RESULT_ABORTED, NULL,
				state->user_data);

	l_free(state);
}

static void netdev_connect_free(struct netdev *netdev)
{
	if (netdev->sm) {
		eapol_sm_free(netdev->sm);
		netdev->sm = NULL;
	}

	if (netdev->ap) {
		auth_proto_free(netdev->ap);
		netdev->ap = NULL;
	}

	eapol_preauth_cancel(netdev->index);

	if (netdev->handshake) {
		handshake_state_free(netdev->handshake);
		netdev->handshake = NULL;
	}

	if (netdev->neighbor_report_cb) {
		netdev->neighbor_report_cb(netdev, -ENOTCONN, NULL, 0,
						netdev->user_data);
		netdev->neighbor_report_cb = NULL;
		l_timeout_remove(netdev->neighbor_report_timeout);
	}

	if (netdev->sa_query_timeout) {
		l_timeout_remove(netdev->sa_query_timeout);
		netdev->sa_query_timeout = NULL;
	}

	if (netdev->group_handshake_timeout) {
		l_timeout_remove(netdev->group_handshake_timeout);
		netdev->group_handshake_timeout = NULL;
	}

	netdev->operational = false;
	netdev->connected = false;
	netdev->connect_cb = NULL;
	netdev->event_filter = NULL;
	netdev->user_data = NULL;
	netdev->result = NETDEV_RESULT_OK;
	netdev->last_code = 0;
	netdev->in_ft = false;
	netdev->ignore_connect_event = false;
	netdev->expect_connect_failure = false;

	netdev_rssi_polling_update(netdev);

	if (netdev->connect_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->connect_cmd_id);
		netdev->connect_cmd_id = 0;
	} else if (netdev->disconnect_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->disconnect_cmd_id);
		netdev->disconnect_cmd_id = 0;
	}
}

static void netdev_connect_failed(struct netdev *netdev,
					enum netdev_result result,
					uint16_t status_or_reason)
{
	netdev_connect_cb_t connect_cb = netdev->connect_cb;
	netdev_event_func_t event_filter = netdev->event_filter;
	void *connect_data = netdev->user_data;

	netdev->disconnect_cmd_id = 0;

	/* Done this way to allow re-entrant netdev_connect calls */
	netdev_connect_free(netdev);

	if (connect_cb)
		connect_cb(netdev, result, &status_or_reason, connect_data);
	else if (event_filter)
		event_filter(netdev, NETDEV_EVENT_DISCONNECT_BY_SME,
				&status_or_reason,
				connect_data);
}

static void netdev_disconnect_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	netdev_connect_failed(netdev, netdev->result, netdev->last_code);
}

static void netdev_free(void *data)
{
	struct netdev *netdev = data;

	l_debug("Freeing netdev %s[%d]", netdev->name, netdev->index);

	if (netdev->neighbor_report_cb) {
		netdev->neighbor_report_cb(netdev, -ENODEV, NULL, 0,
						netdev->user_data);
		netdev->neighbor_report_cb = NULL;
		l_timeout_remove(netdev->neighbor_report_timeout);
	}

	if (netdev->connected)
		netdev_connect_free(netdev);
	else if (netdev->disconnect_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->disconnect_cmd_id);
		netdev->disconnect_cmd_id = 0;

		if (netdev->disconnect_cb)
			netdev->disconnect_cb(netdev, true, netdev->user_data);

		netdev->disconnect_cb = NULL;
		netdev->user_data = NULL;
	}

	if (netdev->join_adhoc_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->join_adhoc_cmd_id);
		netdev->join_adhoc_cmd_id = 0;
	}

	if (netdev->leave_adhoc_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->leave_adhoc_cmd_id);
		netdev->leave_adhoc_cmd_id = 0;
	}

	if (netdev->set_powered_cmd_id) {
		l_netlink_cancel(rtnl, netdev->set_powered_cmd_id);
		netdev->set_powered_cmd_id = 0;
	}

	if (netdev->rekey_offload_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->rekey_offload_cmd_id);
		netdev->rekey_offload_cmd_id = 0;
	}

	if (netdev->qos_map_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->qos_map_cmd_id);
		netdev->qos_map_cmd_id = 0;
	}

	if (netdev->mac_change_cmd_id) {
		l_netlink_cancel(rtnl, netdev->mac_change_cmd_id);
		netdev->mac_change_cmd_id = 0;
	}

	if (netdev->events_ready)
		WATCHLIST_NOTIFY(&netdev_watches, netdev_watch_func_t,
					netdev, NETDEV_WATCH_EVENT_DEL);

	scan_wdev_remove(netdev->wdev_id);

	watchlist_destroy(&netdev->station_watches);

	l_io_destroy(netdev->pae_io);

	l_free(netdev);
}

static void netdev_shutdown_one(void *data, void *user_data)
{
	struct netdev *netdev = data;

	if (netdev_get_is_up(netdev))
		l_rtnl_set_powered(rtnl, netdev->index, false,
					NULL, NULL, NULL);
}

static bool netdev_match(const void *a, const void *b)
{
	const struct netdev *netdev = a;
	uint32_t ifindex = L_PTR_TO_UINT(b);

	return (netdev->index == ifindex);
}

struct netdev *netdev_find(int ifindex)
{
	return l_queue_find(netdev_list, netdev_match, L_UINT_TO_PTR(ifindex));
}

static void netdev_lost_beacon(struct netdev *netdev)
{
	if (!netdev->connected)
		return;

	if (netdev->event_filter)
		netdev->event_filter(netdev, NETDEV_EVENT_LOST_BEACON, NULL,
							netdev->user_data);
}

/* Threshold RSSI for roaming to trigger, configurable in main.conf */
static int LOW_SIGNAL_THRESHOLD;

static void netdev_cqm_event_rssi_threshold(struct netdev *netdev,
						uint32_t rssi_event)
{
	int event;

	if (!netdev->connected)
		return;

	if (rssi_event != NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW &&
			rssi_event != NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH)
		return;

	if (!netdev->event_filter)
		return;

	netdev->cur_rssi_low =
		(rssi_event == NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW);
	event = netdev->cur_rssi_low ? NETDEV_EVENT_RSSI_THRESHOLD_LOW :
		NETDEV_EVENT_RSSI_THRESHOLD_HIGH;

	netdev->event_filter(netdev, event, NULL, netdev->user_data);
}

static void netdev_rssi_level_init(struct netdev *netdev)
{
	if (netdev->connected && netdev->rssi_levels_num)
		netdev_set_rssi_level_idx(netdev);
}

static void netdev_cqm_event_rssi_value(struct netdev *netdev, int rssi_val)
{
	bool new_rssi_low;
	uint8_t prev_rssi_level_idx = netdev->cur_rssi_level_idx;

	if (!netdev->connected)
		return;

	if (rssi_val > 127)
		rssi_val = 127;
	else if (rssi_val < -127)
		rssi_val = -127;

	netdev->cur_rssi = rssi_val;

	if (!netdev->event_filter)
		return;

	new_rssi_low = rssi_val < LOW_SIGNAL_THRESHOLD;
	if (netdev->cur_rssi_low != new_rssi_low) {
		int event = new_rssi_low ?
			NETDEV_EVENT_RSSI_THRESHOLD_LOW :
			NETDEV_EVENT_RSSI_THRESHOLD_HIGH;

		netdev->cur_rssi_low = new_rssi_low;
		netdev->event_filter(netdev, event, NULL, netdev->user_data);
	}

	if (!netdev->rssi_levels_num)
		return;

	netdev_set_rssi_level_idx(netdev);
	if (netdev->cur_rssi_level_idx != prev_rssi_level_idx)
		netdev->event_filter(netdev, NETDEV_EVENT_RSSI_LEVEL_NOTIFY,
					&netdev->cur_rssi_level_idx,
					netdev->user_data);
}

static void netdev_cqm_event(struct l_genl_msg *msg, struct netdev *netdev)
{
	struct l_genl_attr attr;
	struct l_genl_attr nested;
	uint16_t type, len;
	const void *data;
	uint32_t *rssi_event = NULL;
	int32_t *rssi_val = NULL;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_CQM:
			if (!l_genl_attr_recurse(&attr, &nested))
				return;

			while (l_genl_attr_next(&nested, &type, &len, &data)) {
				switch (type) {
				case NL80211_ATTR_CQM_BEACON_LOSS_EVENT:
					netdev_lost_beacon(netdev);
					break;

				case NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT:
					if (len != 4)
						continue;

					rssi_event = (uint32_t *) data;
					break;

				case NL80211_ATTR_CQM_RSSI_LEVEL:
					if (len != 4)
						continue;

					rssi_val = (int32_t *) data;
					break;
				}
			}

			break;
		}
	}

	if (rssi_event) {
		if (rssi_val)
			netdev_cqm_event_rssi_value(netdev, *rssi_val);
		else
			netdev_cqm_event_rssi_threshold(netdev, *rssi_event);
	}
}

static void netdev_rekey_offload_event(struct l_genl_msg *msg,
					struct netdev *netdev)
{
	struct l_genl_attr attr;
	struct l_genl_attr nested;
	uint16_t type, len;
	const void *data;
	uint64_t replay_ctr;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		if (type != NL80211_ATTR_REKEY_DATA)
			continue;

		if (!l_genl_attr_recurse(&attr, &nested))
			return;

		while (l_genl_attr_next(&nested, &type, &len, &data)) {
			if (type != NL80211_REKEY_DATA_REPLAY_CTR)
				continue;

			if (len != sizeof(uint64_t)) {
				l_warn("Invalid replay_ctr");
				return;
			}

			replay_ctr = *((uint64_t *) data);
			__eapol_update_replay_counter(netdev->index,
							netdev->addr,
							netdev->handshake->aa,
							replay_ctr);
			return;
		}
	}
}

static void netdev_disconnect_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint16_t reason_code = 0;
	bool disconnect_by_ap = false;
	netdev_event_func_t event_filter;
	void *event_data;

	l_debug("");

	if (!netdev->connected || netdev->disconnect_cmd_id > 0 ||
			netdev->in_ft)
		return;

	if (!l_genl_attr_init(&attr, msg)) {
		l_error("attr init failed");
		return;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_REASON_CODE:
			if (len != sizeof(uint16_t))
				l_warn("Invalid reason code attribute");
			else
				reason_code = *((uint16_t *) data);

			break;

		case NL80211_ATTR_DISCONNECTED_BY_AP:
			disconnect_by_ap = true;
			break;
		}
	}

	l_info("Received Deauthentication event, reason: %hu, from_ap: %s",
			reason_code, disconnect_by_ap ? "true" : "false");

	event_filter = netdev->event_filter;
	event_data = netdev->user_data;
	netdev_connect_free(netdev);

	if (!event_filter)
		return;

	if (disconnect_by_ap)
		event_filter(netdev, NETDEV_EVENT_DISCONNECT_BY_AP,
						&reason_code, event_data);
	else
		event_filter(netdev, NETDEV_EVENT_DISCONNECT_BY_SME,
						&reason_code, event_data);
}

static void netdev_cmd_disconnect_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	void *disconnect_data;
	netdev_disconnect_cb_t disconnect_cb;
	bool r;

	netdev->disconnect_cmd_id = 0;
	netdev->aborting = false;

	if (!netdev->disconnect_cb) {
		netdev->user_data = NULL;
		return;
	}

	disconnect_data = netdev->user_data;
	disconnect_cb = netdev->disconnect_cb;
	netdev->user_data = NULL;
	netdev->disconnect_cb = NULL;

	if (l_genl_msg_get_error(msg) < 0)
		r = false;
	else
		r = true;

	disconnect_cb(netdev, r, disconnect_data);
}

static struct l_genl_msg *netdev_build_cmd_disconnect(struct netdev *netdev,
							uint16_t reason_code)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_DISCONNECT, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);

	return msg;
}

static void netdev_deauthenticate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	l_debug("");
}

static struct l_genl_msg *netdev_build_cmd_deauthenticate(struct netdev *netdev,
							uint16_t reason_code)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_DEAUTHENTICATE, 128);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN,
							netdev->handshake->aa);

	return msg;
}

static struct l_genl_msg *netdev_build_cmd_del_station(struct netdev *netdev,
							const uint8_t *sta,
							uint16_t reason_code,
							bool disassociate)
{
	struct l_genl_msg *msg;
	uint8_t subtype = disassociate ?
			MPDU_MANAGEMENT_SUBTYPE_DISASSOCIATION :
			MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION;

	msg = l_genl_msg_new_sized(NL80211_CMD_DEL_STATION, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MGMT_SUBTYPE, 1, &subtype);
	l_genl_msg_append_attr(msg, NL80211_ATTR_REASON_CODE, 2, &reason_code);

	return msg;
}

static void netdev_del_sta_cb(struct l_genl_msg *msg, void *user_data)
{
	int err = l_genl_msg_get_error(msg);
	const char *ext_error;

	if (err >= 0)
		return;

	ext_error = l_genl_msg_get_extended_error(msg);
	l_error("DEL_STATION failed: %s",
			ext_error ? ext_error : strerror(-err));
}

int netdev_del_station(struct netdev *netdev, const uint8_t *sta,
			uint16_t reason_code, bool disassociate)
{
	struct l_genl_msg *msg;

	msg = netdev_build_cmd_del_station(netdev, sta, reason_code,
						disassociate);

	if (!l_genl_family_send(nl80211, msg, netdev_del_sta_cb, NULL, NULL))
		return -EIO;

	return 0;
}

static void netdev_operstate_cb(int error, uint16_t type,
					const void *data,
					uint32_t len, void *user_data)
{
	if (!error)
		return;

	l_debug("netdev: %u, error: %s", L_PTR_TO_UINT(user_data),
							strerror(-error));
}

static void netdev_connect_ok(struct netdev *netdev)
{
	l_rtnl_set_linkmode_and_operstate(rtnl, netdev->index,
					IF_LINK_MODE_DORMANT, IF_OPER_UP,
					netdev_operstate_cb,
					L_UINT_TO_PTR(netdev->index), NULL);

	netdev->operational = true;

	if (netdev->connect_cb) {
		netdev->connect_cb(netdev, NETDEV_RESULT_OK, NULL,
					netdev->user_data);
		netdev->connect_cb = NULL;
	}

	netdev_rssi_polling_update(netdev);
}

static void netdev_setting_keys_failed(struct netdev_handshake_state *nhs,
						int err)
{
	struct netdev *netdev = nhs->netdev;
	struct l_genl_msg *msg;

	/*
	 * Something went wrong with our sequence:
	 * 1. new_key(ptk)
	 * 2. new_key(gtk) [optional]
	 * 3. new_key(igtk) [optional]
	 * 4. rekey offload [optional]
	 * 5. set_station
	 *
	 * Cancel all pending commands, then de-authenticate
	 */
	netdev_handshake_state_cancel_all(nhs);

	if (netdev->rekey_offload_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->rekey_offload_cmd_id);
		netdev->rekey_offload_cmd_id = 0;
	}

	if (netdev->group_handshake_timeout) {
		l_timeout_remove(netdev->group_handshake_timeout);
		netdev->group_handshake_timeout = NULL;
	}

	netdev->result = NETDEV_RESULT_KEY_SETTING_FAILED;
	handshake_event(&nhs->super, HANDSHAKE_EVENT_SETTING_KEYS_FAILED, &err);

	switch (netdev->type) {
	case NL80211_IFTYPE_STATION:
		msg = netdev_build_cmd_disconnect(netdev,
						MMPDU_REASON_CODE_UNSPECIFIED);
		netdev->disconnect_cmd_id = l_genl_family_send(nl80211, msg,
							netdev_disconnect_cb,
							netdev, NULL);
		break;
	case NL80211_IFTYPE_AP:
		msg = netdev_build_cmd_del_station(netdev, nhs->super.spa,
				MMPDU_REASON_CODE_UNSPECIFIED, false);
		if (!l_genl_family_send(nl80211, msg, NULL, NULL, NULL))
			l_error("error sending DEL_STATION");
	}
}

static void try_handshake_complete(struct netdev_handshake_state *nhs)
{
	if (nhs->ptk_installed && nhs->gtk_installed && nhs->igtk_installed &&
			!nhs->complete) {
		nhs->complete = true;
		handshake_event(&nhs->super, HANDSHAKE_EVENT_COMPLETE);

		netdev_connect_ok(nhs->netdev);
	}
}

static void netdev_set_station_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev_handshake_state *nhs = user_data;
	struct netdev *netdev = nhs->netdev;
	int err;

	nhs->set_station_cmd_id = 0;
	nhs->ptk_installed = true;

	if (netdev->type == NL80211_IFTYPE_STATION && !netdev->connected)
		return;

	err = l_genl_msg_get_error(msg);
	if (err == -EOPNOTSUPP || err == -ENOTSUPP)
		goto done;

	if (err < 0) {
		const char *ext_error = l_genl_msg_get_extended_error(msg);

		l_error("Set Station failed for ifindex %d:%s", netdev->index,
				ext_error ? ext_error : strerror(-err));

		netdev_setting_keys_failed(nhs, err);
		return;
	}

done:
	try_handshake_complete(nhs);
}

static void netdev_new_group_key_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev_handshake_state *nhs = data;
	struct netdev *netdev = nhs->netdev;
	int err = l_genl_msg_get_error(msg);

	nhs->group_new_key_cmd_id = 0;

	if (err < 0) {
		const char *ext_error = l_genl_msg_get_extended_error(msg);

		l_error("New Key for Group Key failed for ifindex: %d:%s",
				netdev->index,
				ext_error ? ext_error : strerror(-err));

		netdev_setting_keys_failed(nhs, err);
		return;
	}

	nhs->gtk_installed = true;
	try_handshake_complete(nhs);
}

static void netdev_new_group_management_key_cb(struct l_genl_msg *msg,
					void *data)
{
	struct netdev_handshake_state *nhs = data;
	struct netdev *netdev = nhs->netdev;
	int err = l_genl_msg_get_error(msg);

	nhs->group_management_new_key_cmd_id = 0;

	if (err < 0) {
		const char *ext_error = l_genl_msg_get_extended_error(msg);

		l_error("New Key for Group Mgmt failed for ifindex: %d:%s",
				netdev->index,
				ext_error ? ext_error : strerror(-err));

		netdev_setting_keys_failed(nhs, err);
		return;
	}

	nhs->igtk_installed = true;
	try_handshake_complete(nhs);
}

static bool netdev_copy_tk(uint8_t *tk_buf, const uint8_t *tk,
				uint32_t cipher, bool authenticator)
{
	switch (cipher) {
	case CRYPTO_CIPHER_CCMP:
		/*
		 * 802.11-2016 12.8.3 Mapping PTK to CCMP keys:
		 * "A STA shall use the temporal key as the CCMP key
		 * for MPDUs between the two communicating STAs."
		 */
		memcpy(tk_buf, tk, 16);
		break;
	case CRYPTO_CIPHER_TKIP:
		/*
		 * 802.11-2016 12.8.1 Mapping PTK to TKIP keys:
		 * "A STA shall use bits 0-127 of the temporal key as its
		 * input to the TKIP Phase 1 and Phase 2 mixing functions.
		 *
		 * A STA shall use bits 128-191 of the temporal key as
		 * the michael key for MSDUs from the Authenticator's STA
		 * to the Supplicant's STA.
		 *
		 * A STA shall use bits 192-255 of the temporal key as
		 * the michael key for MSDUs from the Supplicant's STA
		 * to the Authenticator's STA."
		 */
		if (authenticator) {
			memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_ENCR_KEY,
					tk, 16);
			memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_TX_MIC_KEY,
					tk + 16, 8);
			memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_RX_MIC_KEY,
					tk + 24, 8);
		} else {
			memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_ENCR_KEY,
					tk, 16);
			memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_RX_MIC_KEY,
					tk + 16, 8);
			memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_TX_MIC_KEY,
					tk + 24, 8);
		}
		break;
	default:
		l_error("Unexpected cipher: %x", cipher);
		return false;
	}

	return true;
}

static const uint8_t *netdev_choose_key_address(
					struct netdev_handshake_state *nhs)
{
	return (nhs->super.authenticator) ? nhs->super.spa : nhs->super.aa;
}

static void netdev_set_gtk(struct handshake_state *hs, uint16_t key_index,
				const uint8_t *gtk, uint8_t gtk_len,
				const uint8_t *rsc, uint8_t rsc_len,
				uint32_t cipher)
{
	struct netdev_handshake_state *nhs =
		l_container_of(hs, struct netdev_handshake_state, super);
	struct netdev *netdev = nhs->netdev;
	uint8_t gtk_buf[32];
	struct l_genl_msg *msg;
	const uint8_t *addr = (netdev->type == NL80211_IFTYPE_ADHOC) ?
				nhs->super.aa : NULL;

	nhs->gtk_installed = false;

	l_debug("%d", netdev->index);

	if (crypto_cipher_key_len(cipher) != gtk_len) {
		l_error("Unexpected key length: %d", gtk_len);
		netdev_setting_keys_failed(nhs, -ERANGE);
		return;
	}

	if (!netdev_copy_tk(gtk_buf, gtk, cipher, false)) {
		netdev_setting_keys_failed(nhs, -ENOENT);
		return;
	}

	if (hs->wait_for_gtk) {
		l_timeout_remove(netdev->group_handshake_timeout);
		netdev->group_handshake_timeout = NULL;
	}

	msg = nl80211_build_new_key_group(netdev->index, cipher, key_index,
					gtk_buf, gtk_len, rsc, rsc_len, addr);

	nhs->group_new_key_cmd_id =
		l_genl_family_send(nl80211, msg, netdev_new_group_key_cb,
						nhs, NULL);

	if (nhs->group_new_key_cmd_id > 0)
		return;

	l_genl_msg_unref(msg);
	netdev_setting_keys_failed(nhs, -EIO);
}

static void netdev_set_igtk(struct handshake_state *hs, uint16_t key_index,
				const uint8_t *igtk, uint8_t igtk_len,
				const uint8_t *ipn, uint8_t ipn_len,
				uint32_t cipher)
{
	struct netdev_handshake_state *nhs =
		l_container_of(hs, struct netdev_handshake_state, super);
	uint8_t igtk_buf[16];
	struct netdev *netdev = nhs->netdev;
	struct l_genl_msg *msg;

	nhs->igtk_installed = false;

	l_debug("%d", netdev->index);

	if (crypto_cipher_key_len(cipher) != igtk_len) {
		l_error("Unexpected key length: %d", igtk_len);
		netdev_setting_keys_failed(nhs, -ERANGE);
		return;
	}

	switch (cipher) {
	case CRYPTO_CIPHER_BIP:
		memcpy(igtk_buf, igtk, 16);
		break;
	default:
		l_error("Unexpected cipher: %x", cipher);
		netdev_setting_keys_failed(nhs, -ENOENT);
		return;
	}

	if (key_index == 0x0400 || key_index == 0x0500) {
		l_warn("Received an invalid IGTK key index (%04hx)"
				" that is likely in"
				" big endian format.  Trying to fix and"
				" proceed anyway", key_index);
		key_index = bswap_16(key_index);
	}

	msg = nl80211_build_new_key_group(netdev->index, cipher, key_index,
					igtk_buf, igtk_len, ipn, ipn_len, NULL);

	nhs->group_management_new_key_cmd_id =
			l_genl_family_send(nl80211, msg,
				netdev_new_group_management_key_cb,
				nhs, NULL);

	if (nhs->group_management_new_key_cmd_id > 0)
		return;

	l_genl_msg_unref(msg);
	netdev_setting_keys_failed(nhs, -EIO);
}

static void netdev_new_pairwise_key_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev_handshake_state *nhs = data;
	struct netdev *netdev = nhs->netdev;
	const uint8_t *addr = netdev_choose_key_address(nhs);
	int err = l_genl_msg_get_error(msg);

	nhs->pairwise_new_key_cmd_id = 0;

	if (err < 0) {
		const char *ext_error = l_genl_msg_get_extended_error(msg);

		l_error("New Key for Pairwise Key failed for ifindex: %d:%s",
				netdev->index,
				ext_error ? ext_error : strerror(-err));
		goto error;
	}

	/*
	 * Set the AUTHORIZED flag using a SET_STATION command even if
	 * we're already operational, it will not hurt during re-keying
	 * and is necessary after an FT.
	 */
	msg = nl80211_build_set_station_authorized(netdev->index, addr);

	nhs->set_station_cmd_id =
		l_genl_family_send(nl80211, msg, netdev_set_station_cb,
					nhs, NULL);
	if (nhs->set_station_cmd_id > 0)
		return;

	l_genl_msg_unref(msg);
	err = -EIO;
error:
	netdev_setting_keys_failed(nhs, err);
}

static struct l_genl_msg *netdev_build_cmd_new_key_pairwise(
							struct netdev *netdev,
							uint32_t cipher,
							const uint8_t *aa,
							const uint8_t *tk,
							size_t tk_len)
{
	uint8_t key_id = 0;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_KEY, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_DATA, tk_len, tk);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_CIPHER, 4, &cipher);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, aa);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);

	return msg;
}

static void netdev_group_timeout_cb(struct l_timeout *timeout, void *user_data)
{
	struct netdev_handshake_state *nhs = user_data;

	/*
	 * There was a problem with the ptk, this should have triggered a key
	 * setting failure event already.
	 */
	if (!nhs->ptk_installed)
		return;

	/*
	 * If this happens, we never completed the group handshake. We can still
	 * complete the connection, but we will not have group traffic.
	 */
	l_warn("completing connection with no group traffic on ifindex %d",
			nhs->netdev->index);

	nhs->complete = true;
	handshake_event(&nhs->super, HANDSHAKE_EVENT_COMPLETE);

	netdev_connect_ok(nhs->netdev);
}

static void netdev_set_tk(struct handshake_state *hs,
				const uint8_t *tk, uint32_t cipher)
{
	struct netdev_handshake_state *nhs =
		l_container_of(hs, struct netdev_handshake_state, super);
	uint8_t tk_buf[32];
	struct netdev *netdev = nhs->netdev;
	struct l_genl_msg *msg;
	const uint8_t *addr = netdev_choose_key_address(nhs);
	int err;

	/*
	 * WPA1 does the group handshake after the 4-way finishes so we can't
	 * rely on the gtk/igtk being set immediately after the ptk. Since
	 * 'gtk_installed' is initially set to true (to handle NO_GROUP_TRAFFIC)
	 * we must set it false so we don't notify that the connection was
	 * successful until we get the gtk/igtk callbacks. Note that we do not
	 * need to set igtk_installed false because the igtk could not happen at
	 * all.
	 */
	if (hs->wait_for_gtk) {
		nhs->gtk_installed = false;

		netdev->group_handshake_timeout = l_timeout_create(2,
					netdev_group_timeout_cb, nhs, NULL);
	}

	/*
	 * 802.11 Section 4.10.4.3:
	 * Because in an IBSS there are two 4-way handshakes between
	 * any two Supplicants and Authenticators, the pairwise key used
	 * between any two STAs is from the 4-way handshake initiated
	 * by the STA Authenticator with the higher MAC address...
	 */
	if (netdev->type == NL80211_IFTYPE_ADHOC &&
			memcmp(nhs->super.aa, nhs->super.spa, 6) < 0) {
		nhs->ptk_installed = true;
		try_handshake_complete(nhs);
		return;
	}

	l_debug("%d", netdev->index);

	err = -ENOENT;
	if (!netdev_copy_tk(tk_buf, tk, cipher, false))
		goto invalid_key;

	msg = netdev_build_cmd_new_key_pairwise(netdev, cipher, addr, tk_buf,
						crypto_cipher_key_len(cipher));
	nhs->pairwise_new_key_cmd_id =
		l_genl_family_send(nl80211, msg, netdev_new_pairwise_key_cb,
						nhs, NULL);
	if (nhs->pairwise_new_key_cmd_id > 0)
		return;

	err = -EIO;
	l_genl_msg_unref(msg);
invalid_key:
	netdev_setting_keys_failed(nhs, err);
}

void netdev_handshake_failed(struct handshake_state *hs, uint16_t reason_code)
{
	struct netdev_handshake_state *nhs =
		l_container_of(hs, struct netdev_handshake_state, super);
	struct netdev *netdev = nhs->netdev;
	struct l_genl_msg *msg;

	l_error("4-Way handshake failed for ifindex: %d, reason: %u",
				netdev->index, reason_code);

	netdev->sm = NULL;

	netdev->result = NETDEV_RESULT_HANDSHAKE_FAILED;
	netdev->last_code = reason_code;

	switch (netdev->type) {
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_P2P_CLIENT:
		msg = netdev_build_cmd_disconnect(netdev, reason_code);
		netdev->disconnect_cmd_id = l_genl_family_send(nl80211, msg,
							netdev_disconnect_cb,
							netdev, NULL);
		break;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_P2P_GO:
		msg = netdev_build_cmd_del_station(netdev, nhs->super.spa,
				reason_code, false);
		if (!l_genl_family_send(nl80211, msg, NULL, NULL, NULL))
			l_error("error sending DEL_STATION");
	}
}

static void hardware_rekey_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev *netdev = data;
	int err;

	netdev->rekey_offload_cmd_id = 0;

	err = l_genl_msg_get_error(msg);
	if (err < 0) {
		if (err == -EOPNOTSUPP) {
			l_error("hardware_rekey not supported");
			netdev->rekey_offload_support = false;
		}

		/*
		 * TODO: Ignore all other errors for now, until WoWLAN is
		 * supported properly
		 */
	}
}

static struct l_genl_msg *netdev_build_cmd_replay_counter(struct netdev *netdev,
							const uint8_t *kek,
							const uint8_t *kck,
							uint64_t replay_ctr)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_REKEY_OFFLOAD, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);

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

static void netdev_set_rekey_offload(uint32_t ifindex,
					const uint8_t *kek,
					const uint8_t *kck,
					uint64_t replay_counter,
					void *user_data)
{
	struct netdev *netdev;
	struct l_genl_msg *msg;

	netdev = netdev_find(ifindex);
	if (!netdev)
		return;

	if (netdev->type != NL80211_IFTYPE_STATION)
		return;

	if (!netdev->rekey_offload_support)
		return;

	l_debug("%d", netdev->index);
	msg = netdev_build_cmd_replay_counter(netdev, kek, kck, replay_counter);
	netdev->rekey_offload_cmd_id = l_genl_family_send(nl80211, msg,
							hardware_rekey_cb,
							netdev, NULL);
}

static void netdev_qos_map_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	int err = l_genl_msg_get_error(msg);
	const char *ext_error;

	netdev->qos_map_cmd_id = 0;

	if (err >= 0)
		return;

	ext_error = l_genl_msg_get_extended_error(msg);
	l_error("Couuld not set QoS Map in kernel: %s",
			ext_error ? ext_error : strerror(-err));
}

/*
 * TODO: Fix this in the kernel:
 *
 * The QoS Map is really of no use to IWD. The kernel requires it to map QoS
 * network values properly to what it puts into the IP header. The way we have
 * to let the kernel know is to receive the IE, then give it right back...
 *
 * The kernel/driver/firmware *could* simply obtain this information as the
 * frame comes in and not require userspace to forward it back... but that's a
 * battle for another day.
 */
static void netdev_send_qos_map_set(struct netdev *netdev,
					const uint8_t *qos_set, size_t qos_len)
{
	struct l_genl_msg *msg;

	if (!wiphy_supports_qos_set_map(netdev->wiphy)) {
		l_warn("AP sent QoS Map, but capability was not advertised!");
		return;
	}

	/*
	 * Since this IE comes in on either a management frame or during
	 * Association response we could have potentially already set this.
	 */
	if (netdev->qos_map_cmd_id)
		return;

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_QOS_MAP, 128 + qos_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_QOS_MAP, qos_len, qos_set);

	netdev->qos_map_cmd_id = l_genl_family_send(nl80211, msg,
						netdev_qos_map_cb,
						netdev, NULL);
}

static void netdev_connect_event(struct l_genl_msg *msg, struct netdev *netdev)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint16_t *status_code = NULL;
	const uint8_t *ies = NULL;
	size_t ies_len = 0;
	struct ie_tlv_iter iter;
	const uint8_t *resp_ies = NULL;
	size_t resp_ies_len;

	l_debug("");

	if (netdev->aborting)
		return;

	if (netdev->ignore_connect_event)
		return;

	if (!netdev->connected) {
		l_warn("Unexpected connection related event -- "
				"is another supplicant running?");
		return;
	}

	if (!l_genl_attr_init(&attr, msg)) {
		l_debug("attr init failed");
		goto error;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_TIMED_OUT:
			l_warn("authentication timed out");
			goto error;
		case NL80211_ATTR_STATUS_CODE:
			if (len == sizeof(uint16_t))
				status_code = data;
			break;
		case NL80211_ATTR_REQ_IE:
			ies = data;
			ies_len = len;
			break;
		case NL80211_ATTR_RESP_IE:
			resp_ies = data;
			resp_ies_len = len;
			break;
		}
	}

	if (netdev->expect_connect_failure) {
		/*
		 * The kernel may think we are connected when we are actually
		 * expecting a failure here, e.g. if Authenticate/Associate had
		 * previously failed. If so we need to deauth to let the kernel
		 * know.
		 */
		if (status_code && *status_code == 0)
			goto deauth;
		else
			goto error;
	}

	/* AP Rejected the authenticate / associate */
	if (!status_code || *status_code != 0)
		goto error;

	if (!ies)
		goto process_resp_ies;
	/*
	 * The driver may have modified the IEs we passed to CMD_CONNECT
	 * before sending them out, the actual IE sent is reflected in the
	 * ATTR_REQ_IE sequence.  These are the values EAPoL will need to use.
	 */
	ie_tlv_iter_init(&iter, ies, ies_len);

	while (ie_tlv_iter_next(&iter)) {
		data = ie_tlv_iter_get_data(&iter);

		switch (ie_tlv_iter_get_tag(&iter)) {
		case IE_TYPE_RSN:
			handshake_state_set_supplicant_ie(netdev->handshake,
								data - 2);
			break;
		case IE_TYPE_VENDOR_SPECIFIC:
			if (!is_ie_wpa_ie(data, ie_tlv_iter_get_length(&iter)))
				break;

			handshake_state_set_supplicant_ie(netdev->handshake,
								data - 2);
			break;
		case IE_TYPE_MOBILITY_DOMAIN:
			handshake_state_set_mde(netdev->handshake, data - 2);
			break;
		}
	}

process_resp_ies:
	if (resp_ies) {
		const uint8_t *fte = NULL;
		const uint8_t *qos_set = NULL;
		size_t qos_len = 0;
		struct ie_ft_info ft_info;

		ie_tlv_iter_init(&iter, resp_ies, resp_ies_len);

		while (ie_tlv_iter_next(&iter)) {
			data = ie_tlv_iter_get_data(&iter);

			switch (ie_tlv_iter_get_tag(&iter)) {
			case IE_TYPE_FAST_BSS_TRANSITION:
				fte = data - 2;
				break;
			case IE_TYPE_QOS_MAP_SET:
				qos_set = data;
				qos_len = ie_tlv_iter_get_length(&iter);
				break;
			}
		}

		/* FILS handles its own FT key derivation */
		if (fte && !(netdev->handshake->akm_suite &
				(IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256 |
				IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384))) {
			uint32_t kck_len =
				handshake_state_get_kck_len(netdev->handshake);
			/*
			 * If we are here, then most likely we have a FullMac
			 * hw performing initial mobility association.  We need
			 * to set the FTE element or the handshake will fail
			 * The firmware accepted the FTE element, so do not
			 * sanitize the contents and just assume they're okay.
			 */
			if (ie_parse_fast_bss_transition_from_data(fte,
					fte[1] + 2, kck_len, &ft_info) >= 0) {
				handshake_state_set_fte(netdev->handshake, fte);
				handshake_state_set_kh_ids(netdev->handshake,
							ft_info.r0khid,
							ft_info.r0khid_len,
							ft_info.r1khid);
			} else {
				l_info("CMD_CONNECT Succeeded, but parsing FTE"
					" failed.  Expect handshake failure");
			}
		}

		if (qos_set)
			netdev_send_qos_map_set(netdev, qos_set, qos_len);
	}

	if (netdev->sm) {
		/*
		 * Start processing EAPoL frames now that the state machine
		 * has all the input data even in FT mode.
		 */
		if (!eapol_start(netdev->sm))
			goto error;

		return;
	}

	netdev_connect_ok(netdev);

	return;

error:
	netdev_connect_failed(netdev, NETDEV_RESULT_ASSOCIATION_FAILED,
			(status_code) ? *status_code :
			MMPDU_STATUS_CODE_UNSPECIFIED);
	return;

deauth:
	msg = netdev_build_cmd_deauthenticate(netdev,
						MMPDU_REASON_CODE_UNSPECIFIED);
	netdev->disconnect_cmd_id = l_genl_family_send(nl80211,
							msg,
							netdev_disconnect_cb,
							netdev, NULL);
}

static unsigned int ie_rsn_akm_suite_to_nl80211(enum ie_rsn_akm_suite akm)
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

static struct l_genl_msg *netdev_build_cmd_associate_common(
							struct netdev *netdev)
{
	struct handshake_state *hs = netdev->handshake;
	bool is_rsn = hs->supplicant_ie != NULL;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_ASSOCIATE, 600);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4,
							&netdev->frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, hs->aa);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SSID, hs->ssid_len, hs->ssid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SOCKET_OWNER, 0, NULL);

	if (is_rsn) {
		uint32_t nl_cipher;
		uint32_t nl_akm;
		uint32_t wpa_version;

		l_genl_msg_append_attr(msg, NL80211_ATTR_CONTROL_PORT, 0, NULL);

		if (netdev->pae_over_nl80211)
			l_genl_msg_append_attr(msg,
					NL80211_ATTR_CONTROL_PORT_OVER_NL80211,
					0, NULL);

		if (hs->pairwise_cipher == IE_RSN_CIPHER_SUITE_CCMP)
			nl_cipher = CRYPTO_CIPHER_CCMP;
		else
			nl_cipher = CRYPTO_CIPHER_TKIP;

		l_genl_msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
					4, &nl_cipher);

		if (hs->group_cipher == IE_RSN_CIPHER_SUITE_CCMP)
			nl_cipher = CRYPTO_CIPHER_CCMP;
		else
			nl_cipher = CRYPTO_CIPHER_TKIP;

		l_genl_msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITE_GROUP,
					4, &nl_cipher);

		if (hs->mfp) {
			uint32_t use_mfp = NL80211_MFP_REQUIRED;
			l_genl_msg_append_attr(msg, NL80211_ATTR_USE_MFP,
								4, &use_mfp);
		}

		nl_akm = ie_rsn_akm_suite_to_nl80211(hs->akm_suite);
		if (nl_akm)
			l_genl_msg_append_attr(msg, NL80211_ATTR_AKM_SUITES,
							4, &nl_akm);

		if (hs->wpa_ie)
			wpa_version = NL80211_WPA_VERSION_1;
		else
			wpa_version = NL80211_WPA_VERSION_2;

		l_genl_msg_append_attr(msg, NL80211_ATTR_WPA_VERSIONS,
						4, &wpa_version);
	}

	return msg;
}

static void netdev_cmd_ft_reassociate_cb(struct l_genl_msg *msg,
						void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->connect_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		struct l_genl_msg *cmd_deauth;

		netdev->result = NETDEV_RESULT_ASSOCIATION_FAILED;
		netdev->last_code = MMPDU_STATUS_CODE_UNSPECIFIED;
		cmd_deauth = netdev_build_cmd_deauthenticate(netdev,
						MMPDU_REASON_CODE_UNSPECIFIED);
		netdev->disconnect_cmd_id = l_genl_family_send(nl80211,
							cmd_deauth,
							netdev_disconnect_cb,
							netdev, NULL);
	}
}

static void netdev_authenticate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint8_t *frame = NULL;
	size_t frame_len = 0;
	int ret;
	uint16_t status_code = MMPDU_STATUS_CODE_UNSPECIFIED;

	l_debug("");

	if (netdev->aborting)
		return;

	if (!netdev->connected) {
		l_warn("Unexpected connection related event -- "
				"is another supplicant running?");
		return;
	}

	/*
	 * During Fast Transition we use the authenticate event to start the
	 * reassociation step because the FTE necessary before we can build
	 * the FT Associate command is included in the attached frame and is
	 * not available in the Authenticate command callback.
	 */
	if (!netdev->ap)
		return;

	if (!l_genl_attr_init(&attr, msg)) {
		l_debug("attr init failed");

		goto auth_error;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_TIMED_OUT:
			l_warn("authentication timed out");

			if (auth_proto_auth_timeout(netdev->ap))
				return;

			goto auth_error;

		case NL80211_ATTR_FRAME:
			if (frame)
				goto auth_error;

			frame = data;
			frame_len = len;
			break;
		}
	}

	if (!frame)
		goto auth_error;

	if (netdev->ap) {
		ret = auth_proto_rx_authenticate(netdev->ap, frame, frame_len);
		if (ret == 0 || ret == -EAGAIN)
			return;
		else if (ret > 0)
			status_code = (uint16_t)ret;

		goto auth_error;
	} else
		goto auth_error;

	return;

auth_error:
	netdev_connect_failed(netdev, NETDEV_RESULT_AUTHENTICATION_FAILED,
				status_code);
}

static void netdev_associate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	size_t frame_len = 0;
	const uint8_t *frame = NULL;
	uint16_t status_code = MMPDU_STATUS_CODE_UNSPECIFIED;
	int ret;

	l_debug("");

	if (!netdev->connected || netdev->aborting)
		return;

	if (!netdev->ap)
		return;

	if (!l_genl_attr_init(&attr, msg)) {
		l_debug("attr init failed");
		return;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_TIMED_OUT:
			l_warn("association timed out");

			if (auth_proto_assoc_timeout(netdev->ap))
				return;

			goto assoc_failed;

		case NL80211_ATTR_FRAME:
			frame = data;
			frame_len = len;

			break;
		}
	}

	if (!frame)
		goto assoc_failed;

	if (netdev->ap) {
		ret = auth_proto_rx_associate(netdev->ap, frame, frame_len);
		if (ret == 0) {
			auth_proto_free(netdev->ap);
			netdev->ap = NULL;

			netdev->sm = eapol_sm_new(netdev->handshake);
			eapol_register(netdev->sm);

			/* Just in case this was a retry */
			netdev->ignore_connect_event = false;

			/*
			 * If in FT we need to prevent the 4-way handshake from
			 * happening, and instead just wait for rekeys
			 */
			if (netdev->in_ft) {
				eapol_sm_set_require_handshake(netdev->sm,
								false);
				netdev->in_ft = false;
			}

			return;
		} else if (ret == -EAGAIN) {
			/*
			 * Here to support OWE retries. OWE will retry
			 * internally, but a connect even will still be emitted.
			 */
			netdev->ignore_connect_event = true;
			return;
		} else if (ret > 0)
			status_code = (uint16_t)ret;

		goto assoc_failed;
	}

	return;

assoc_failed:
	netdev->result = NETDEV_RESULT_ASSOCIATION_FAILED;
	netdev->last_code = status_code;
	netdev->expect_connect_failure = true;
}

static void netdev_cmd_connect_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->connect_cmd_id = 0;

	/* Wait for connect event */
	if (l_genl_msg_get_error(msg) >= 0) {
		netdev->connected = true;

		if (netdev->event_filter)
			netdev->event_filter(netdev,
						NETDEV_EVENT_ASSOCIATING,
						NULL,
						netdev->user_data);

		/*
		 * We register the eapol state machine here, in case the PAE
		 * socket receives EAPoL packets before the nl80211 socket
		 * receives the connected event.  The logical sequence of
		 * events can be reversed (e.g. connect_event, then PAE data)
		 * due to scheduling
		 */
		if (netdev->sm)
			eapol_register(netdev->sm);

		return;
	}

	netdev_connect_failed(netdev, NETDEV_RESULT_ASSOCIATION_FAILED,
				MMPDU_STATUS_CODE_UNSPECIFIED);
}

static struct l_genl_msg *netdev_build_cmd_authenticate(struct netdev *netdev,
							uint32_t auth_type,
							const uint8_t *addr)
{
	struct handshake_state *hs = netdev->handshake;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_AUTHENTICATE, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ,
						4, &netdev->frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SSID, hs->ssid_len, hs->ssid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IE, hs->supplicant_ie[1] + 2,
					hs->supplicant_ie);

	return msg;
}

static void netdev_auth_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("Error sending CMD_AUTHENTICATE");

		netdev_connect_failed(netdev,
					NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
		return;
	}
}

static void netdev_assoc_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("Error sending CMD_ASSOCIATE");

		netdev_connect_failed(netdev, NETDEV_RESULT_ASSOCIATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
	}
}

static void netdev_sae_tx_authenticate(const uint8_t *body,
					size_t body_len, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	msg = netdev_build_cmd_authenticate(netdev, NL80211_AUTHTYPE_SAE,
						netdev->handshake->aa);

	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_DATA, body_len, body);

	if (!l_genl_family_send(nl80211, msg, netdev_auth_cb, netdev, NULL)) {
		l_genl_msg_unref(msg);
		netdev_connect_failed(netdev,
					NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
	}
}

static void netdev_sae_tx_associate(void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;
	struct iovec iov[2];
	int iov_elems = 0;

	msg = netdev_build_cmd_associate_common(netdev);

	iov[iov_elems].iov_base = netdev->handshake->supplicant_ie;
	iov[iov_elems].iov_len = netdev->handshake->supplicant_ie[1] + 2;
	iov_elems++;

	if (netdev->handshake->mde) {
		iov[iov_elems].iov_base = netdev->handshake->mde;
		iov[iov_elems].iov_len = netdev->handshake->mde[1] + 2;
		iov_elems++;
	}

	l_genl_msg_append_attrv(msg, NL80211_ATTR_IE, iov, iov_elems);

	if (!l_genl_family_send(nl80211, msg, netdev_assoc_cb, netdev, NULL)) {
		l_genl_msg_unref(msg);
		netdev_connect_failed(netdev, NETDEV_RESULT_ASSOCIATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
	}
}

static void netdev_owe_tx_authenticate(void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	msg = netdev_build_cmd_authenticate(netdev,
						NL80211_AUTHTYPE_OPEN_SYSTEM,
						netdev->handshake->aa);

	if (!l_genl_family_send(nl80211, msg, netdev_auth_cb,
							netdev, NULL)) {
		l_genl_msg_unref(msg);
		netdev_connect_failed(netdev,
					NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
	}
}

static void netdev_owe_tx_associate(struct iovec *ie_iov, size_t iov_len,
					void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	msg = netdev_build_cmd_associate_common(netdev);

	l_genl_msg_append_attrv(msg, NL80211_ATTR_IE, ie_iov, iov_len);

	if (!l_genl_family_send(nl80211, msg, netdev_assoc_cb,
							netdev, NULL)) {
		l_genl_msg_unref(msg);
		netdev_connect_failed(netdev, NETDEV_RESULT_ASSOCIATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
	}
}

static void netdev_fils_tx_authenticate(const uint8_t *body,
					size_t body_len,
					void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	msg = netdev_build_cmd_authenticate(netdev, NL80211_AUTHTYPE_FILS_SK,
						netdev->handshake->aa);

	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_DATA, body_len, body);

	if (!l_genl_family_send(nl80211, msg, netdev_auth_cb,
							netdev, NULL)) {
		l_genl_msg_unref(msg);
		netdev_connect_failed(netdev,
					NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
	}
}

static void netdev_fils_tx_associate(struct iovec *iov, size_t iov_len,
					const uint8_t *kek, size_t kek_len,
					const uint8_t *nonces, size_t nonces_len,
					void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	msg = netdev_build_cmd_associate_common(netdev);

	l_genl_msg_append_attrv(msg, NL80211_ATTR_IE, iov, iov_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_FILS_KEK, kek_len, kek);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FILS_NONCES, nonces_len, nonces);

	if (!l_genl_family_send(nl80211, msg, netdev_assoc_cb,
							netdev, NULL)) {
		l_genl_msg_unref(msg);
		netdev_connect_failed(netdev, NETDEV_RESULT_ASSOCIATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
	}
}

static struct l_genl_msg *netdev_build_cmd_connect(struct netdev *netdev,
						struct scan_bss *bss,
						struct handshake_state *hs,
						const uint8_t *prev_bssid,
						const struct iovec *vendor_ies,
						size_t num_vendor_ies)
{
	uint32_t auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;
	struct l_genl_msg *msg;
	struct iovec iov[4 + num_vendor_ies];
	int iov_elems = 0;
	bool is_rsn = hs->supplicant_ie != NULL;
	const uint8_t *extended_capabilities;
	const uint8_t *rm_enabled_capabilities;

	msg = l_genl_msg_new_sized(NL80211_CMD_CONNECT, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ,
						4, &bss->frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, bss->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SSID,
						bss->ssid_len, bss->ssid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);

	if (prev_bssid)
		l_genl_msg_append_attr(msg, NL80211_ATTR_PREV_BSSID, ETH_ALEN,
						prev_bssid);

	if (bss->capability & IE_BSS_CAP_PRIVACY)
		l_genl_msg_append_attr(msg, NL80211_ATTR_PRIVACY, 0, NULL);

	l_genl_msg_append_attr(msg, NL80211_ATTR_SOCKET_OWNER, 0, NULL);

	if (is_rsn) {
		uint32_t nl_cipher;
		uint32_t nl_akm;
		uint32_t wpa_version;

		if (hs->pairwise_cipher == IE_RSN_CIPHER_SUITE_CCMP)
			nl_cipher = CRYPTO_CIPHER_CCMP;
		else
			nl_cipher = CRYPTO_CIPHER_TKIP;

		l_genl_msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
					4, &nl_cipher);

		if (hs->group_cipher == IE_RSN_CIPHER_SUITE_CCMP)
			nl_cipher = CRYPTO_CIPHER_CCMP;
		else
			nl_cipher = CRYPTO_CIPHER_TKIP;

		l_genl_msg_append_attr(msg, NL80211_ATTR_CIPHER_SUITE_GROUP,
					4, &nl_cipher);

		if (hs->mfp) {
			uint32_t use_mfp = NL80211_MFP_REQUIRED;
			l_genl_msg_append_attr(msg, NL80211_ATTR_USE_MFP,
								4, &use_mfp);
		}

		nl_akm = ie_rsn_akm_suite_to_nl80211(hs->akm_suite);
		if (nl_akm)
			l_genl_msg_append_attr(msg, NL80211_ATTR_AKM_SUITES,
							4, &nl_akm);

		if (hs->wpa_ie)
			wpa_version = NL80211_WPA_VERSION_1;
		else
			wpa_version = NL80211_WPA_VERSION_2;

		l_genl_msg_append_attr(msg, NL80211_ATTR_WPA_VERSIONS,
						4, &wpa_version);

		l_genl_msg_append_attr(msg, NL80211_ATTR_CONTROL_PORT, 0, NULL);

		iov[iov_elems].iov_base = (void *) hs->supplicant_ie;
		iov[iov_elems].iov_len = hs->supplicant_ie[1] + 2;
		iov_elems += 1;
	}

	if (netdev->pae_over_nl80211)
		l_genl_msg_append_attr(msg,
				NL80211_ATTR_CONTROL_PORT_OVER_NL80211,
				0, NULL);

	rm_enabled_capabilities =
			wiphy_get_rm_enabled_capabilities(netdev->wiphy);
	if (rm_enabled_capabilities && bss->capability & IE_BSS_CAP_RM) {
		iov[iov_elems].iov_base = (void *) rm_enabled_capabilities;
		iov[iov_elems].iov_len = rm_enabled_capabilities[1] + 2;
		iov_elems += 1;

		l_genl_msg_append_attr(msg, NL80211_ATTR_USE_RRM, 0, NULL);
	}

	if (hs->mde) {
		iov[iov_elems].iov_base = (void *) hs->mde;
		iov[iov_elems].iov_len = hs->mde[1] + 2;
		iov_elems += 1;
	}

	/*
	 * This element should be added after MDE
	 * See 802.11-2016, Section 9.3.3.6
	 */
	extended_capabilities = wiphy_get_extended_capabilities(netdev->wiphy,
								netdev->type);
	iov[iov_elems].iov_base = (void *) extended_capabilities;
	iov[iov_elems].iov_len = extended_capabilities[1] + 2;
	iov_elems += 1;

	if (vendor_ies) {
		memcpy(iov + iov_elems, vendor_ies,
					sizeof(*vendor_ies) * num_vendor_ies);
		iov_elems += num_vendor_ies;
	}

	if (iov_elems)
		l_genl_msg_append_attrv(msg, NL80211_ATTR_IE, iov, iov_elems);

	return msg;
}

struct rtnl_data {
	struct netdev *netdev;
	struct l_genl_msg *cmd_connect;
	uint8_t addr[ETH_ALEN];
	int ref;
};

static int netdev_begin_connection(struct netdev *netdev,
					struct l_genl_msg *cmd_connect)
{
	if (cmd_connect) {
		netdev->connect_cmd_id = l_genl_family_send(nl80211,
					cmd_connect, netdev_cmd_connect_cb,
					netdev, NULL);

		if (!netdev->connect_cmd_id) {
			l_genl_msg_unref(cmd_connect);
			return -EIO;
		}
	}

	handshake_state_set_supplicant_address(netdev->handshake, netdev->addr);

	/* set connected since the auth protocols cannot do so internally */
	if (netdev->ap && auth_proto_start(netdev->ap))
		netdev->connected = true;

	return 0;
}

static void netdev_mac_change_failed(struct netdev *netdev,
					struct rtnl_data *req, int error)
{
	l_error("Error setting mac address on %d: %s", netdev->index,
			strerror(-error));

	/*
	 * If the interface is down and we failed to up it we need to notify
	 * any watchers since we have been skipping the notification while
	 * mac_change_cmd_id was set.
	 */
	if (!netdev_get_is_up(netdev)) {
		l_genl_msg_unref(req->cmd_connect);

		WATCHLIST_NOTIFY(&netdev_watches, netdev_watch_func_t,
				netdev, NETDEV_WATCH_EVENT_DOWN);

		goto failed;
	} else {
		/*
		 * If the interface is up we can still try and connect. This
		 * is a very rare case and most likely will never happen.
		 */
		l_info("Interface still up after failing to change the MAC, "
			"continuing with connection");
		if (netdev_begin_connection(netdev, req->cmd_connect) < 0)
			goto failed;

		return;
	}

failed:
	netdev_connect_failed(netdev, NETDEV_RESULT_ABORTED,
				MMPDU_STATUS_CODE_UNSPECIFIED);
}

static void netdev_mac_destroy(void *user_data)
{
	struct rtnl_data *req = user_data;

	req->ref--;

	/* still pending requests? */
	if (req->ref)
		return;

	l_free(req);
}

static void netdev_mac_power_up_cb(int error, uint16_t type,
					const void *data, uint32_t len,
					void *user_data)
{
	struct rtnl_data *req = user_data;
	struct netdev *netdev = req->netdev;

	netdev->mac_change_cmd_id = 0;

	if (error) {
		l_error("Error taking interface %u up for per-network MAC "
			"generation: %s", netdev->index, strerror(-error));
		netdev_mac_change_failed(netdev, req, error);
		return;
	}

	/*
	 * Pick up where we left off in netdev_connect_commmon.
	 */
	if (netdev_begin_connection(netdev, req->cmd_connect) < 0) {
		l_error("Failed to connect after changing MAC");
		netdev_connect_failed(netdev, NETDEV_RESULT_ASSOCIATION_FAILED,
				MMPDU_STATUS_CODE_UNSPECIFIED);
	}
}

static void netdev_mac_power_down_cb(int error, uint16_t type,
					const void *data, uint32_t len,
					void *user_data)
{
	struct rtnl_data *req = user_data;
	struct netdev *netdev = req->netdev;

	netdev->mac_change_cmd_id = 0;

	if (error) {
		l_error("Error taking interface %u down for per-network MAC "
			"generation: %s", netdev->index, strerror(-error));
		netdev_mac_change_failed(netdev, req, error);
		return;
	}

	l_debug("Setting generated address on ifindex: %d to: "MAC,
					netdev->index, MAC_STR(req->addr));
	netdev->mac_change_cmd_id = l_rtnl_set_mac(rtnl, netdev->index,
					req->addr, true,
					netdev_mac_power_up_cb, req,
					netdev_mac_destroy);
	if (!netdev->mac_change_cmd_id) {
		netdev_mac_change_failed(netdev, req, -EIO);
		return;
	}

	req->ref++;
}

/*
 * TODO: There are some potential race conditions that are being ignored. There
 *       is nothing that IWD itself can do to solve these, they require kernel
 *       changes:
 *
 * 1. A perfectly timed ifdown could be ignored. If an external process
 *    brings down an interface just before calling this function we would only
 *    get a single newlink event since there is no state change doing a second
 *    ifdown (nor an error from the kernel). This newlink event would be ignored
 *    since IWD thinks its from our own doing. This would result in IWD changing
 *    the MAC and bringing the interface back up which would look very strange
 *    and unexpected to someone who just tried to ifdown an interface.
 *
 * 2. A perfectly timed ifup could result in a failed connection. If an external
 *    process ifup's just after IWD ifdown's but before changing the MAC this
 *    would cause the MAC change to fail. This failure would result in a failed
 *    connection.
 *
 * Returns 0 if a MAC change procedure was started.
 * Returns -EALREADY if the requested MAC matched our current MAC
 * Returns -EIO if there was an IO error when powering down
 */
static int netdev_start_powered_mac_change(struct netdev *netdev,
					struct scan_bss *bss,
					struct l_genl_msg *cmd_connect)
{
	struct rtnl_data *req;
	uint8_t new_addr[6];

	/* No address set in handshake, use per-network MAC generation */
	if (util_mem_is_zero(netdev->handshake->spa, ETH_ALEN))
		wiphy_generate_address_from_ssid(netdev->wiphy,
						(const char *)bss->ssid,
						new_addr);
	else
		memcpy(new_addr, netdev->handshake->spa, ETH_ALEN);

	/*
	 * MAC has already been changed previously, no need to again
	 */
	if (!memcmp(new_addr, netdev->addr, sizeof(new_addr)))
		return -EALREADY;

	req = l_new(struct rtnl_data, 1);
	req->netdev = netdev;
	/* This message will need to be unreffed upon any error */
	req->cmd_connect = cmd_connect;
	req->ref++;
	memcpy(req->addr, new_addr, sizeof(req->addr));

	netdev->mac_change_cmd_id = l_rtnl_set_powered(rtnl, netdev->index,
					false, netdev_mac_power_down_cb,
					req, netdev_mac_destroy);

	if (!netdev->mac_change_cmd_id) {
		l_genl_msg_unref(req->cmd_connect);
		l_free(req);

		return -EIO;
	}

	return 0;
}

static int netdev_connect_common(struct netdev *netdev,
					struct l_genl_msg *cmd_connect,
					struct scan_bss *bss,
					struct handshake_state *hs,
					struct eapol_sm *sm,
					netdev_event_func_t event_filter,
					netdev_connect_cb_t cb, void *user_data)
{
	netdev->event_filter = event_filter;
	netdev->connect_cb = cb;
	netdev->user_data = user_data;
	netdev->handshake = hs;
	netdev->sm = sm;
	netdev->frequency = bss->frequency;
	netdev->cur_rssi_low = false; /* Gets updated on the 1st CQM event */
	netdev->cur_rssi = bss->signal_strength / 100;
	netdev_rssi_level_init(netdev);

	handshake_state_set_authenticator_address(hs, bss->addr);

	if (!wiphy_has_ext_feature(netdev->wiphy,
					NL80211_EXT_FEATURE_CAN_REPLACE_PTK0))
		handshake_state_set_no_rekey(hs, true);

	if (mac_per_ssid) {
		int ret = netdev_start_powered_mac_change(netdev, bss,
								cmd_connect);
		if (ret != -EALREADY)
			return ret;
	}

	return netdev_begin_connection(netdev, cmd_connect);
}

int netdev_connect(struct netdev *netdev, struct scan_bss *bss,
				struct handshake_state *hs,
				const struct iovec *vendor_ies,
				size_t num_vendor_ies,
				netdev_event_func_t event_filter,
				netdev_connect_cb_t cb, void *user_data)
{
	struct l_genl_msg *cmd_connect = NULL;
	struct eapol_sm *sm = NULL;
	bool is_rsn = hs->supplicant_ie != NULL;

	if (netdev->type != NL80211_IFTYPE_STATION &&
			netdev->type != NL80211_IFTYPE_P2P_CLIENT)
		return -ENOTSUP;

	if (netdev->connected || netdev->connect_cmd_id)
		return -EISCONN;

	switch (hs->akm_suite) {
	case IE_RSN_AKM_SUITE_SAE_SHA256:
	case IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256:
		netdev->ap = sae_sm_new(hs, netdev_sae_tx_authenticate,
						netdev_sae_tx_associate,
						netdev);
		break;
	case IE_RSN_AKM_SUITE_OWE:
		netdev->ap = owe_sm_new(hs, netdev_owe_tx_authenticate,
						netdev_owe_tx_associate,
						netdev);
		break;
	case IE_RSN_AKM_SUITE_FILS_SHA256:
	case IE_RSN_AKM_SUITE_FILS_SHA384:
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256:
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384:
		netdev->ap = fils_sm_new(hs, netdev_fils_tx_authenticate,
						netdev_fils_tx_associate,
						netdev);
		break;
	default:
		cmd_connect = netdev_build_cmd_connect(netdev, bss, hs,
					NULL, vendor_ies, num_vendor_ies);

		if (!cmd_connect)
			return -EINVAL;

		if (is_rsn || hs->settings_8021x)
			sm = eapol_sm_new(hs);
	}

	return netdev_connect_common(netdev, cmd_connect, bss, hs, sm,
						event_filter, cb, user_data);
}

int netdev_disconnect(struct netdev *netdev,
				netdev_disconnect_cb_t cb, void *user_data)
{
	struct l_genl_msg *disconnect;

	if (netdev->type != NL80211_IFTYPE_STATION &&
			netdev->type != NL80211_IFTYPE_P2P_CLIENT)
		return -ENOTSUP;

	if (!netdev->connected)
		return -ENOTCONN;

	if (netdev->disconnect_cmd_id)
		return -EINPROGRESS;

	/* Only perform this if we haven't successfully fully associated yet */
	if (!netdev->operational) {
		if (netdev->connect_cmd_id) {
			l_genl_family_cancel(nl80211, netdev->connect_cmd_id);
			netdev->connect_cmd_id = 0;
		}

		netdev_connect_failed(netdev, NETDEV_RESULT_ABORTED,
					MMPDU_REASON_CODE_UNSPECIFIED);
	} else {
		netdev_connect_free(netdev);
	}

	disconnect = netdev_build_cmd_disconnect(netdev,
					MMPDU_REASON_CODE_DEAUTH_LEAVING);
	netdev->disconnect_cmd_id = l_genl_family_send(nl80211, disconnect,
				netdev_cmd_disconnect_cb, netdev, NULL);

	if (!netdev->disconnect_cmd_id) {
		l_genl_msg_unref(disconnect);
		return -EIO;
	}

	netdev->disconnect_cb = cb;
	netdev->user_data = user_data;
	netdev->aborting = true;

	return 0;
}

int netdev_reassociate(struct netdev *netdev, struct scan_bss *target_bss,
			struct scan_bss *orig_bss, struct handshake_state *hs,
			netdev_event_func_t event_filter,
			netdev_connect_cb_t cb, void *user_data)
{
	struct l_genl_msg *cmd_connect;
	struct netdev_handshake_state;
	struct handshake_state *old_hs;
	struct eapol_sm *sm = NULL, *old_sm;
	bool is_rsn = hs->supplicant_ie != NULL;
	int err;

	cmd_connect = netdev_build_cmd_connect(netdev, target_bss, hs,
						orig_bss->addr, NULL, 0);
	if (!cmd_connect)
		return -EINVAL;

	if (is_rsn)
		sm = eapol_sm_new(hs);

	old_sm = netdev->sm;
	old_hs = netdev->handshake;

	err = netdev_connect_common(netdev, cmd_connect, target_bss, hs, sm,
					event_filter, cb, user_data);
	if (err < 0)
		return err;

	memcpy(netdev->prev_bssid, orig_bss->addr, ETH_ALEN);

	netdev->operational = false;

	netdev_rssi_polling_update(netdev);

	if (old_sm)
		eapol_sm_free(old_sm);

	if (old_hs)
		handshake_state_free(old_hs);

	return err;
}

static void netdev_join_adhoc_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->join_adhoc_cmd_id = 0;

	if (netdev->adhoc_cb)
		netdev->adhoc_cb(netdev, l_genl_msg_get_error(msg),
				netdev->user_data);
}

int netdev_join_adhoc(struct netdev *netdev, const char *ssid,
			struct iovec *extra_ie, size_t extra_ie_elems,
			bool control_port, netdev_command_cb_t cb,
			void *user_data)
{
	struct l_genl_msg *cmd;
	uint32_t ifindex = netdev->index;
	uint32_t ch_freq = scan_channel_to_freq(6, SCAN_BAND_2_4_GHZ);
	uint32_t ch_type = NL80211_CHAN_HT20;

	if (netdev->type != NL80211_IFTYPE_ADHOC) {
		l_error("iftype is invalid for adhoc: %u",
				netdev_get_iftype(netdev));
		return -ENOTSUP;
	}

	if (netdev->join_adhoc_cmd_id || netdev->leave_adhoc_cmd_id)
		return -EBUSY;

	netdev->adhoc_cb = cb;
	netdev->user_data = user_data;

	cmd = l_genl_msg_new_sized(NL80211_CMD_JOIN_IBSS, 128);

	l_genl_msg_append_attr(cmd, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_SSID, strlen(ssid), ssid);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_WIPHY_FREQ, 4, &ch_freq);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_WIPHY_CHANNEL_TYPE, 4,
			&ch_type);
	l_genl_msg_append_attrv(cmd, NL80211_ATTR_IE, extra_ie, extra_ie_elems);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_SOCKET_OWNER, 0, NULL);

	if (control_port) {
		l_genl_msg_append_attr(cmd, NL80211_ATTR_CONTROL_PORT, 0, NULL);

		if (netdev->pae_over_nl80211)
			l_genl_msg_append_attr(cmd,
					NL80211_ATTR_CONTROL_PORT_OVER_NL80211,
					0, NULL);
	}

	netdev->join_adhoc_cmd_id = l_genl_family_send(nl80211, cmd,
			netdev_join_adhoc_cb, netdev, NULL);

	if (!netdev->join_adhoc_cmd_id) {
		netdev->adhoc_cb = NULL;
		netdev->user_data = NULL;
		return -EIO;
	}

	return 0;
}

static void netdev_leave_adhoc_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->leave_adhoc_cmd_id = 0;

	if (netdev->adhoc_cb)
		netdev->adhoc_cb(netdev, l_genl_msg_get_error(msg),
				netdev->user_data);

	netdev->adhoc_cb = NULL;
}

int netdev_leave_adhoc(struct netdev *netdev, netdev_command_cb_t cb,
			void *user_data)
{
	struct l_genl_msg *cmd;

	if (netdev->type != NL80211_IFTYPE_ADHOC) {
		l_error("iftype is invalid for adhoc: %u",
				netdev_get_iftype(netdev));
		return -ENOTSUP;
	}

	if (netdev->join_adhoc_cmd_id || netdev->leave_adhoc_cmd_id)
		return -EBUSY;

	netdev->adhoc_cb = cb;
	netdev->user_data = user_data;

	cmd = l_genl_msg_new_sized(NL80211_CMD_LEAVE_IBSS, 64);

	l_genl_msg_append_attr(cmd, NL80211_ATTR_IFINDEX, 4, &netdev->index);

	netdev->leave_adhoc_cmd_id = l_genl_family_send(nl80211, cmd,
						netdev_leave_adhoc_cb, netdev,
						NULL);

	if (!netdev->leave_adhoc_cmd_id)
		return -EIO;

	return 0;
}

static uint32_t netdev_send_action_framev(struct netdev *netdev,
					const uint8_t *to,
					struct iovec *iov, size_t iov_len,
					uint32_t freq,
					l_genl_msg_func_t callback)
{
	uint32_t id;
	struct l_genl_msg *msg = nl80211_build_cmd_frame(netdev->index,
								netdev->addr,
								to, freq,
								iov, iov_len);

	id = l_genl_family_send(nl80211, msg, callback, netdev, NULL);

	if (!id)
		l_genl_msg_unref(msg);

	return id;
}

static uint32_t netdev_send_action_frame(struct netdev *netdev,
					const uint8_t *to,
					const uint8_t *body, size_t body_len,
					uint32_t freq,
					l_genl_msg_func_t callback)
{
	struct iovec iov[1];

	iov[0].iov_base = (void *)body;
	iov[0].iov_len = body_len;

	return netdev_send_action_framev(netdev, to, iov, 1, freq, callback);
}

/*
 * Build an FT Authentication Request frame according to 12.5.2 / 12.5.4:
 * RSN or non-RSN Over-the-air FT Protocol, with the IE contents
 * according to 12.8.2: FT authentication sequence: contents of first message.
 */
static struct l_genl_msg *netdev_build_cmd_ft_authenticate(
					struct netdev *netdev,
					const struct handshake_state *hs)
{
	uint32_t auth_type = NL80211_AUTHTYPE_FT;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_AUTHENTICATE, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ,
						4, &netdev->frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, hs->aa);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SSID, hs->ssid_len, hs->ssid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);

	return msg;

}

static void netdev_cmd_authenticate_ft_cb(struct l_genl_msg *msg,
						void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->connect_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0)
		netdev_connect_failed(netdev,
					NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
}

static void netdev_ft_tx_authenticate(struct iovec *iov,
					size_t iov_len, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *cmd_authenticate;

	cmd_authenticate = netdev_build_cmd_ft_authenticate(netdev,
							netdev->handshake);
	if (!cmd_authenticate)
		goto restore_snonce;

	l_genl_msg_append_attrv(cmd_authenticate, NL80211_ATTR_IE, iov,
					iov_len);

	netdev->connect_cmd_id = l_genl_family_send(nl80211,
						cmd_authenticate,
						netdev_cmd_authenticate_ft_cb,
						netdev, NULL);
	if (!netdev->connect_cmd_id) {
		l_genl_msg_unref(cmd_authenticate);
		goto restore_snonce;
	}

	return;

restore_snonce:
	memcpy(netdev->handshake->snonce, netdev->prev_snonce, 32);

	netdev_connect_failed(netdev, NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
}

static void netdev_ft_tx_associate(struct iovec *ie_iov, size_t iov_len,
					void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	msg = netdev_build_cmd_associate_common(netdev);

	l_genl_msg_append_attr(msg, NL80211_ATTR_PREV_BSSID, ETH_ALEN,
				netdev->prev_bssid);
	l_genl_msg_append_attrv(msg, NL80211_ATTR_IE, ie_iov, iov_len);

	netdev->connect_cmd_id = l_genl_family_send(nl80211, msg,
						netdev_cmd_ft_reassociate_cb,
						netdev, NULL);
	if (!netdev->connect_cmd_id) {
		l_genl_msg_unref(msg);

		netdev_connect_failed(netdev, NETDEV_RESULT_ASSOCIATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
		return;
	}
}

static void netdev_ft_request_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("Could not send CMD_FRAME");
		netdev_connect_failed(netdev,
					NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
	}
}

static void netdev_ft_response_frame_event(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	int ret;
	uint16_t status_code = MMPDU_STATUS_CODE_UNSPECIFIED;
	struct netdev *netdev = user_data;

	if (!netdev->ap || !netdev->in_ft)
		return;

	ret = auth_proto_rx_authenticate(netdev->ap, body, body_len);
	if (ret < 0)
		goto ft_error;
	else if (ret > 0) {
		status_code = (uint16_t)ret;
		goto ft_error;
	}

	return;

ft_error:
	netdev_connect_failed(netdev, NETDEV_RESULT_AUTHENTICATION_FAILED,
				status_code);
	return;
}

static void netdev_qos_map_frame_event(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	struct netdev *netdev = user_data;

	/* No point telling the kernel */
	if (!netdev->connected)
		return;

	if (memcmp(netdev->handshake->aa, hdr->address_2, ETH_ALEN))
		return;

	if (body_len < 5)
		return;

	if (l_get_u8(body + 2) != IE_TYPE_QOS_MAP_SET)
		return;

	netdev_send_qos_map_set(netdev, body + 4, body_len - 4);
}

static void netdev_ft_over_ds_tx_authenticate(struct iovec *iov,
					size_t iov_len, void *user_data)
{
	struct netdev *netdev = user_data;
	uint8_t ft_req[14];
	struct handshake_state *hs = netdev->handshake;
	struct iovec iovs[iov_len + 1];

	ft_req[0] = 6; /* FT category */
	ft_req[1] = 1; /* FT Request action */
	memcpy(ft_req + 2, netdev->addr, 6);
	memcpy(ft_req + 8, hs->aa, 6);

	iovs[0].iov_base = ft_req;
	iovs[0].iov_len = sizeof(ft_req);
	memcpy(iovs + 1, iov, sizeof(*iov) * iov_len);

	netdev_send_action_framev(netdev, netdev->prev_bssid, iovs, iov_len + 1,
					netdev->prev_frequency,
					netdev_ft_request_cb);
}

static int fast_transition(struct netdev *netdev, struct scan_bss *target_bss,
				bool over_air,
				netdev_connect_cb_t cb)
{
	struct netdev_handshake_state *nhs;
	int err = -EINVAL;

	if (!netdev->operational)
		return -ENOTCONN;

	if (!netdev->handshake->mde || !target_bss->mde_present ||
			l_get_le16(netdev->handshake->mde + 2) !=
			l_get_le16(target_bss->mde))
		return -EINVAL;

	/*
	 * We reuse the handshake_state object and reset what's needed.
	 * Could also create a new object and copy most of the state but
	 * we would end up doing more work.
	 */
	memcpy(netdev->prev_bssid, netdev->handshake->aa, ETH_ALEN);
	memcpy(netdev->prev_snonce, netdev->handshake->snonce, 32);

	handshake_state_new_snonce(netdev->handshake);

	netdev->prev_frequency = netdev->frequency;
	netdev->frequency = target_bss->frequency;

	handshake_state_set_authenticator_address(netdev->handshake,
							target_bss->addr);

	if (target_bss->rsne)
		handshake_state_set_authenticator_ie(netdev->handshake,
							target_bss->rsne);
	memcpy(netdev->handshake->mde + 2, target_bss->mde, 3);

	netdev->operational = false;
	netdev->in_ft = true;
	netdev->connect_cb = cb;

	/*
	 * Cancel commands that could be running because of EAPoL activity
	 * like re-keying, this way the callbacks for those commands don't
	 * have to check if failures resulted from the transition.
	 */
	nhs = l_container_of(netdev->handshake,
				struct netdev_handshake_state, super);

	/* reset key states just as we do in initialization */
	nhs->complete = false;
	nhs->ptk_installed = false;
	nhs->gtk_installed = true;
	nhs->igtk_installed = true;

	if (nhs->group_new_key_cmd_id) {
		l_genl_family_cancel(nl80211, nhs->group_new_key_cmd_id);
		nhs->group_new_key_cmd_id = 0;
	}

	if (nhs->group_management_new_key_cmd_id) {
		l_genl_family_cancel(nl80211,
			nhs->group_management_new_key_cmd_id);
		nhs->group_management_new_key_cmd_id = 0;
	}

	if (netdev->rekey_offload_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->rekey_offload_cmd_id);
		netdev->rekey_offload_cmd_id = 0;
	}

	netdev_rssi_polling_update(netdev);

	if (netdev->sm) {
		eapol_sm_free(netdev->sm);
		netdev->sm = NULL;
	}

	if (over_air)
		netdev->ap = ft_over_air_sm_new(netdev->handshake,
					netdev_ft_tx_authenticate,
					netdev_ft_tx_associate, netdev);
	else
		netdev->ap = ft_over_ds_sm_new(netdev->handshake,
					netdev_ft_over_ds_tx_authenticate,
					netdev_ft_tx_associate, netdev);

	if (!auth_proto_start(netdev->ap))
		goto restore_snonce;

	return 0;

restore_snonce:
	memcpy(netdev->handshake->snonce, netdev->prev_snonce, 32);

	return err;
}

int netdev_fast_transition(struct netdev *netdev, struct scan_bss *target_bss,
				netdev_connect_cb_t cb)
{
	return fast_transition(netdev, target_bss, true, cb);
}

int netdev_fast_transition_over_ds(struct netdev *netdev,
					struct scan_bss *target_bss,
					netdev_connect_cb_t cb)
{
	return fast_transition(netdev, target_bss, false, cb);
}

static void netdev_preauth_cb(const uint8_t *pmk, void *user_data)
{
	struct netdev_preauth_state *preauth = user_data;
	netdev_preauthenticate_cb_t cb = preauth->cb;

	preauth->cb = NULL;

	cb(preauth->netdev,
		pmk ? NETDEV_RESULT_OK : NETDEV_RESULT_HANDSHAKE_FAILED,
		pmk, preauth->user_data);
}

int netdev_preauthenticate(struct netdev *netdev, struct scan_bss *target_bss,
				netdev_preauthenticate_cb_t cb, void *user_data)
{
	struct netdev_preauth_state *preauth;

	if (!netdev->operational)
		return -ENOTCONN;

	preauth = l_new(struct netdev_preauth_state, 1);

	if (!eapol_preauth_start(target_bss->addr, netdev->handshake,
					netdev_preauth_cb, preauth,
					netdev_preauth_destroy)) {
		l_free(preauth);

		return -EIO;
	}

	preauth->cb = cb;
	preauth->user_data = user_data;
	preauth->netdev = netdev;

	return 0;
}

static void netdev_neighbor_report_req_cb(struct l_genl_msg *msg,
						void *user_data)
{
	struct netdev *netdev = user_data;

	if (!netdev->neighbor_report_cb)
		return;

	if (l_genl_msg_get_error(msg) < 0) {
		netdev->neighbor_report_cb(netdev, l_genl_msg_get_error(msg),
						NULL, 0, netdev->user_data);

		netdev->neighbor_report_cb = NULL;

		l_timeout_remove(netdev->neighbor_report_timeout);
	}
}

static void netdev_neighbor_report_timeout(struct l_timeout *timeout,
						void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->neighbor_report_cb(netdev, -ETIMEDOUT, NULL, 0,
					netdev->user_data);

	netdev->neighbor_report_cb = NULL;

	l_timeout_remove(netdev->neighbor_report_timeout);
}

int netdev_neighbor_report_req(struct netdev *netdev,
				netdev_neighbor_report_cb_t cb)
{
	const uint8_t action_frame[] = {
		0x05, /* Category: Radio Measurement */
		0x04, /* Radio Measurement Action: Neighbor Report Request */
		0x01, /* Dialog Token: a non-zero value (unused) */
	};

	if (netdev->neighbor_report_cb || !netdev->connected)
		return -EBUSY;

	if (!netdev_send_action_frame(netdev, netdev->handshake->aa,
					action_frame, sizeof(action_frame),
					netdev->frequency,
					netdev_neighbor_report_req_cb))
		return -EIO;

	netdev->neighbor_report_cb = cb;

	/* Set a 3-second timeout */
	netdev->neighbor_report_timeout =
		l_timeout_create(3, netdev_neighbor_report_timeout,
					netdev, NULL);

	return 0;
}

static void netdev_neighbor_report_frame_event(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	struct netdev *netdev = user_data;

	if (body_len < 3) {
		l_debug("Neighbor Report frame too short");
		return;
	}

	if (!netdev->neighbor_report_cb)
		return;

	/*
	 * Don't use the dialog token (byte 3), return the first Neighbor
	 * Report Response received.
	 *
	 * Byte 1 is 0x05 for Radio Measurement, byte 2 is 0x05 for
	 * Neighbor Report.
	 */

	netdev->neighbor_report_cb(netdev, 0, body + 3, body_len - 3,
					netdev->user_data);
	netdev->neighbor_report_cb = NULL;

	l_timeout_remove(netdev->neighbor_report_timeout);
}

static void netdev_sa_query_resp_cb(struct l_genl_msg *msg, void *user_data)
{
	int err = l_genl_msg_get_error(msg);
	const char *ext_error;

	if (err >= 0)
		return;

	ext_error = l_genl_msg_get_extended_error(msg);
	l_debug("error sending SA Query request: %s",
			ext_error ? ext_error : strerror(-err));
}

static void netdev_sa_query_req_frame_event(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	uint8_t sa_resp[4];
	uint16_t transaction;
	struct netdev *netdev = user_data;

	if (body_len < 4) {
		l_debug("SA Query request too short");
		return;
	}

	if (!netdev->connected)
		return;

	/* only care about SA Queries from our connected AP */
	if (memcmp(hdr->address_2, netdev->handshake->aa, 6))
		return;

	transaction = l_get_u16(body + 2);

	sa_resp[0] = 0x08;	/* SA Query */
	sa_resp[1] = 0x01;	/* Response */
	memcpy(sa_resp + 2, &transaction, 2);

	l_info("received SA Query request from "MAC", transaction=%u",
			MAC_STR(hdr->address_2), transaction);

	if (!netdev_send_action_frame(netdev, netdev->handshake->aa,
			sa_resp, sizeof(sa_resp),
			netdev->frequency,
			netdev_sa_query_resp_cb)) {
		l_error("error sending SA Query response");
		return;
	}
}

static void netdev_sa_query_resp_frame_event(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	struct netdev *netdev = user_data;

	if (body_len < 4) {
		l_debug("SA Query frame too short");
		return;
	}

	l_debug("SA Query src="MAC" dest="MAC" bssid="MAC" transaction=%u",
			MAC_STR(hdr->address_2), MAC_STR(hdr->address_1),
			MAC_STR(hdr->address_3), l_get_u16(body + 2));

	if (!netdev->sa_query_timeout) {
		l_debug("no SA Query request sent");
		return;
	}

	/* check if this is from our connected BSS */
	if (memcmp(hdr->address_2, netdev->handshake->aa, 6)) {
		l_debug("received SA Query from non-connected AP");
		return;
	}

	if (memcmp(body + 2, &netdev->sa_query_id, 2)) {
		l_debug("SA Query transaction ID's did not match");
		return;
	}

	l_info("SA Query response from connected BSS received, "
			"keeping the connection active");

	l_timeout_remove(netdev->sa_query_timeout);
	netdev->sa_query_timeout = NULL;
}

static void netdev_sa_query_req_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	int err = l_genl_msg_get_error(msg);
	const char *ext_error;

	if (err >= 0)
		return;

	ext_error = l_genl_msg_get_extended_error(msg);
	l_debug("error sending SA Query request: %s",
			ext_error ? ext_error : strerror(-err));

	l_timeout_remove(netdev->sa_query_timeout);
	netdev->sa_query_timeout = NULL;
}

static void netdev_sa_query_timeout(struct l_timeout *timeout,
		void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	l_info("SA Query timed out, connection is invalid.  Disconnecting...");

	l_timeout_remove(netdev->sa_query_timeout);
	netdev->sa_query_timeout = NULL;

	msg = netdev_build_cmd_disconnect(netdev,
			MMPDU_REASON_CODE_PREV_AUTH_NOT_VALID);
	netdev->disconnect_cmd_id = l_genl_family_send(nl80211, msg,
			netdev_disconnect_cb, netdev, NULL);
}

static void netdev_unprot_disconnect_event(struct l_genl_msg *msg,
		struct netdev *netdev)
{
	const struct mmpdu_header *hdr = NULL;
	struct l_genl_attr attr;
	uint16_t type;
	uint16_t len;
	const void *data;
	uint8_t action_frame[4];
	uint8_t reason_code;

	if (!netdev->connected)
		return;

	/* ignore excessive disassociate requests */
	if (netdev->sa_query_timeout)
		return;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_FRAME:
			hdr = mpdu_validate(data, len);
			break;
		}
	}

	/* check that ATTR_FRAME was actually included */
	if (!hdr)
		return;

	/* get reason code, first byte of frame */
	reason_code = l_get_u8(mmpdu_body(hdr));

	l_info("disconnect event, src="MAC" dest="MAC" bssid="MAC" reason=%u",
			MAC_STR(hdr->address_2), MAC_STR(hdr->address_1),
			MAC_STR(hdr->address_3), reason_code);

	if (memcmp(hdr->address_2, netdev->handshake->aa, 6)) {
		l_debug("received invalid disassociate frame");
		return;
	}

	if (reason_code != MMPDU_REASON_CODE_CLASS2_FRAME_FROM_NONAUTH_STA &&
			reason_code !=
			MMPDU_REASON_CODE_CLASS3_FRAME_FROM_NONASSOC_STA) {
		l_debug("invalid reason code %u", reason_code);
		return;
	}

	action_frame[0] = 0x08; /* Category: SA Query */
	action_frame[1] = 0x00; /* SA Query Action: Request */

	/* Transaction ID */
	l_getrandom(action_frame + 2, 2);

	if (!netdev_send_action_frame(netdev, netdev->handshake->aa,
			action_frame, sizeof(action_frame),
			netdev->frequency,
			netdev_sa_query_req_cb)) {
		l_error("error sending SA Query action frame");
		return;
	}

	netdev->sa_query_id = l_get_u16(action_frame + 2);
	netdev->sa_query_timeout = l_timeout_create(3,
			netdev_sa_query_timeout, netdev, NULL);
}

static void netdev_station_event(struct l_genl_msg *msg,
					struct netdev *netdev, bool added)
{
	struct l_genl_attr attr;
	uint16_t type;
	uint16_t len;
	const void *data;
	const uint8_t *mac = NULL;

	if (netdev_get_iftype(netdev) != NETDEV_IFTYPE_ADHOC)
		return;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_MAC:
			mac = data;
			break;
		}
	}

	if (!mac) {
		l_error("%s station event did not include MAC attribute",
				added ? "new" : "del");
		return;
	}

	WATCHLIST_NOTIFY(&netdev->station_watches,
			netdev_station_watch_func_t, netdev, mac, added);
}

static void netdev_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = NULL;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	l_debug("MLME notification %s(%u)", nl80211cmd_to_string(cmd), cmd);

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface index attribute");
				return;
			}

			netdev = netdev_find(*((uint32_t *) data));
			break;
		}
	}

	if (!netdev)
		return;

	switch (cmd) {
	case NL80211_CMD_AUTHENTICATE:
		netdev_authenticate_event(msg, netdev);
		break;
	case NL80211_CMD_DEAUTHENTICATE:
		netdev_deauthenticate_event(msg, netdev);
		break;
	case NL80211_CMD_ASSOCIATE:
		netdev_associate_event(msg, netdev);
		break;
	case NL80211_CMD_CONNECT:
		netdev_connect_event(msg, netdev);
		break;
	case NL80211_CMD_DISCONNECT:
		netdev_disconnect_event(msg, netdev);
		break;
	case NL80211_CMD_NOTIFY_CQM:
		netdev_cqm_event(msg, netdev);
		break;
	case NL80211_CMD_SET_REKEY_OFFLOAD:
		netdev_rekey_offload_event(msg, netdev);
		break;
	case NL80211_CMD_UNPROT_DEAUTHENTICATE:
	case NL80211_CMD_UNPROT_DISASSOCIATE:
		netdev_unprot_disconnect_event(msg, netdev);
		break;
	case NL80211_CMD_NEW_STATION:
		netdev_station_event(msg, netdev, true);
		break;
	case NL80211_CMD_DEL_STATION:
		netdev_station_event(msg, netdev, false);
		break;
	}
}

static void netdev_pae_destroy(void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->pae_io = NULL;
}

static bool netdev_pae_read(struct l_io *io, void *user_data)
{
	int fd = l_io_get_fd(io);
	struct sockaddr_ll sll;
	socklen_t sll_len;
	ssize_t bytes;
	uint8_t frame[IEEE80211_MAX_DATA_LEN];

	memset(&sll, 0, sizeof(sll));
	sll_len = sizeof(sll);

	bytes = recvfrom(fd, frame, sizeof(frame), 0,
				(struct sockaddr *) &sll, &sll_len);
	if (bytes <= 0) {
		l_error("EAPoL read socket: %s", strerror(errno));
		return false;
	}

	if (sll.sll_halen != ETH_ALEN)
		return true;

	__eapol_rx_packet(sll.sll_ifindex, sll.sll_addr,
				ntohs(sll.sll_protocol), frame, bytes, false);

	return true;
}

static void netdev_control_port_frame_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	struct l_genl_attr attr;
	uint16_t type;
	uint16_t len;
	const void *data;
	const uint8_t *frame = NULL;
	uint16_t frame_len = 0;
	const uint8_t *src = NULL;
	uint16_t proto = 0;
	bool unencrypted = false;

	l_debug("");

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_FRAME:
			if (frame)
				return;

			frame = data;
			frame_len = len;
			break;
		case NL80211_ATTR_MAC:
			if (src)
				return;

			src = data;
			break;
		case NL80211_ATTR_CONTROL_PORT_ETHERTYPE:
			if (len != sizeof(proto))
				return;

			proto = *((const uint16_t *) data);
			break;
		case NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT:
			unencrypted = true;
			break;
		}
	}

	if (!src || !frame || !proto)
		return;

	__eapol_rx_packet(netdev->index, src, proto,
						frame, frame_len, unencrypted);
}

static struct l_genl_msg *netdev_build_control_port_frame(struct netdev *netdev,
							const uint8_t *to,
							uint16_t proto,
							bool unencrypted,
							const void *body,
							size_t body_len)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_CONTROL_PORT_FRAME,
							128 + body_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME, body_len, body);
	l_genl_msg_append_attr(msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, 2,
				&proto);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, to);

	if (unencrypted)
		l_genl_msg_append_attr(msg,
				NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT, 0, NULL);

	return msg;
}

static void netdev_control_port_frame_cb(struct l_genl_msg *msg,
							void *user_data)
{
	int err = l_genl_msg_get_error(msg);
	const char *ext_error;

	if (err >= 0)
		return;

	ext_error = l_genl_msg_get_extended_error(msg);
	l_error("CMD_CONTROL_PORT failed: %s",
			ext_error ? ext_error : strerror(-err));
}

static int netdev_control_port_write_pae(struct netdev *netdev,
						const uint8_t *dest,
						uint16_t proto,
						const struct eapol_frame *ef,
						bool noencrypt)
{
	int fd = l_io_get_fd(netdev->pae_io);
	struct sockaddr_ll sll;
	size_t frame_size = sizeof(struct eapol_header) +
					L_BE16_TO_CPU(ef->header.packet_len);
	ssize_t r;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = netdev->index;
	sll.sll_protocol = htons(proto);
	sll.sll_halen = ETH_ALEN;
	memcpy(sll.sll_addr, dest, ETH_ALEN);

	r = sendto(fd, ef, frame_size, 0,
			(struct sockaddr *) &sll, sizeof(sll));
	if (r < 0)
		l_error("EAPoL write socket: %s", strerror(errno));

	return r;
}

static int netdev_control_port_frame(uint32_t ifindex,
					const uint8_t *dest, uint16_t proto,
					const struct eapol_frame *ef,
					bool noencrypt,
					void *user_data)
{
	struct l_genl_msg *msg;
	struct netdev *netdev;
	size_t frame_size;

	netdev = netdev_find(ifindex);
	if (!netdev)
		return -ENOENT;

	frame_size = sizeof(struct eapol_header) +
			L_BE16_TO_CPU(ef->header.packet_len);

	if (!netdev->pae_over_nl80211)
		return netdev_control_port_write_pae(netdev, dest, proto,
							ef, noencrypt);

	msg = netdev_build_control_port_frame(netdev, dest, proto, noencrypt,
						ef, frame_size);
	if (!msg)
		return -ENOMEM;

	if (!l_genl_family_send(nl80211, msg, netdev_control_port_frame_cb,
				netdev, NULL)) {
		l_genl_msg_unref(msg);
		return -EINVAL;
	}

	return 0;
}

static void netdev_unicast_notify(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = NULL;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);
	if (!cmd)
		return;

	l_debug("Unicast notification %u", cmd);

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface index attribute");
				return;
			}

			netdev = netdev_find(*((uint32_t *) data));
			break;
		}
	}

	if (!netdev)
		return;

	switch (cmd) {
	case NL80211_CMD_CONTROL_PORT_FRAME:
		netdev_control_port_frame_event(msg, netdev);
		break;
	}
}

static struct l_genl_msg *netdev_build_cmd_cqm_rssi_update(
							struct netdev *netdev,
							const int8_t *levels,
							size_t levels_num)
{
	struct l_genl_msg *msg;
	uint32_t hyst = 5;
	int thold_count;
	int32_t thold_list[levels_num + 2];

	if (levels_num == 0) {
		thold_list[0] = LOW_SIGNAL_THRESHOLD;
		thold_count = 1;
	} else {
		/*
		 * Build the list of all the threshold values we care about:
		 *  - the low/high level threshold,
		 *  - the value ranges requested by
		 *    netdev_set_rssi_report_levels
		 */
		unsigned int i;
		bool low_sig_added = false;

		thold_count = 0;
		for (i = 0; i < levels_num; i++) {
			int32_t val = levels[levels_num - i - 1];

			if (i && thold_list[thold_count - 1] >= val)
				return NULL;

			if (val >= LOW_SIGNAL_THRESHOLD && !low_sig_added) {
				thold_list[thold_count++] =
					LOW_SIGNAL_THRESHOLD;
				low_sig_added = true;

				/* Duplicate values are not allowed */
				if (val == LOW_SIGNAL_THRESHOLD)
					continue;
			}

			thold_list[thold_count++] = val;
		}
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_CQM, 32 + thold_count * 4);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_enter_nested(msg, NL80211_ATTR_CQM);
	l_genl_msg_append_attr(msg, NL80211_ATTR_CQM_RSSI_THOLD,
				thold_count * 4, thold_list);
	l_genl_msg_append_attr(msg, NL80211_ATTR_CQM_RSSI_HYST, 4, &hyst);
	l_genl_msg_leave_nested(msg);

	return msg;
}

static void netdev_cmd_set_cqm_cb(struct l_genl_msg *msg, void *user_data)
{
	int err = l_genl_msg_get_error(msg);
	const char *ext_error;

	if (err >= 0)
		return;

	ext_error = l_genl_msg_get_extended_error(msg);
	l_error("CMD_SET_CQM failed: %s",
			ext_error ? ext_error : strerror(-err));
}

int netdev_set_rssi_report_levels(struct netdev *netdev, const int8_t *levels,
					size_t levels_num)
{
	struct l_genl_msg *cmd_set_cqm;

	l_debug("ifindex: %d, num_levels: %zu", netdev->index, levels_num);

	if (levels_num > L_ARRAY_SIZE(netdev->rssi_levels))
		return -ENOSPC;

	if (!wiphy_has_ext_feature(netdev->wiphy,
					NL80211_EXT_FEATURE_CQM_RSSI_LIST))
		goto done;

	cmd_set_cqm = netdev_build_cmd_cqm_rssi_update(netdev, levels,
							levels_num);
	if (!cmd_set_cqm)
		return -EINVAL;

	if (!l_genl_family_send(nl80211, cmd_set_cqm, netdev_cmd_set_cqm_cb,
				NULL, NULL)) {
		l_genl_msg_unref(cmd_set_cqm);
		return -EIO;
	}

done:
	if (levels_num)
		memcpy(netdev->rssi_levels, levels, levels_num);

	netdev->rssi_levels_num = levels_num;
	netdev_rssi_level_init(netdev);

	netdev_rssi_polling_update(netdev);

	return 0;
}

static int netdev_cqm_rssi_update(struct netdev *netdev)
{
	struct l_genl_msg *msg;

	l_debug("");

	if (!wiphy_has_ext_feature(netdev->wiphy,
					NL80211_EXT_FEATURE_CQM_RSSI_LIST))
		return 0;

	msg = netdev_build_cmd_cqm_rssi_update(netdev, netdev->rssi_levels,
						netdev->rssi_levels_num);
	if (!msg)
		return -EINVAL;

	if (!l_genl_family_send(nl80211, msg, netdev_cmd_set_cqm_cb,
				NULL, NULL)) {
		l_genl_msg_unref(msg);
		return -EIO;
	}

	return 0;
}

static struct l_genl_msg *netdev_build_cmd_set_interface(struct netdev *netdev,
							uint32_t iftype)
{
	struct l_genl_msg *msg =
		l_genl_msg_new_sized(NL80211_CMD_SET_INTERFACE, 32);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFTYPE, 4, &iftype);

	return msg;
}

struct netdev_set_iftype_request {
	netdev_command_cb_t cb;
	void *user_data;
	netdev_destroy_func_t destroy;
	uint32_t pending_type;
	uint32_t ref;
	struct netdev *netdev;
	bool bring_up;
};

static void netdev_set_iftype_request_destroy(void *user_data)
{
	struct netdev_set_iftype_request *req = user_data;
	struct netdev *netdev = req->netdev;

	req->ref--;
	if (req->ref)
		return;

	netdev->set_powered_cmd_id = 0;
	netdev->set_interface_cmd_id = 0;

	if (req->destroy)
		req->destroy(req->user_data);

	l_free(req);
}

static void netdev_set_iftype_up_cb(int error, uint16_t type,
					const void *data,
					uint32_t len, void *user_data)
{
	struct netdev_set_iftype_request *req = user_data;
	struct netdev *netdev = req->netdev;

	if (req->cb)
		req->cb(netdev, error, req->user_data);
}

static void netdev_set_iftype_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev_set_iftype_request *req = user_data;
	struct netdev *netdev = req->netdev;
	int error = l_genl_msg_get_error(msg);

	if (error != 0)
		goto done;

	netdev->type = req->pending_type;

	/* Set RSSI threshold for CQM notifications */
	if (netdev->type == NL80211_IFTYPE_STATION)
		netdev_cqm_rssi_update(netdev);

	/* If the netdev was down originally, we're done */
	if (!req->bring_up)
		goto done;

	netdev->set_powered_cmd_id =
			l_rtnl_set_powered(rtnl, netdev->index, true,
					netdev_set_iftype_up_cb, req,
					netdev_set_iftype_request_destroy);
	if (!netdev->set_powered_cmd_id) {
		error = -EIO;
		goto done;
	}

	req->ref++;
	netdev->set_interface_cmd_id = 0;
	return;

done:
	if (req->cb)
		req->cb(netdev, error, req->user_data);
}

static void netdev_set_iftype_down_cb(int error, uint16_t type,
					const void *data,
					uint32_t len, void *user_data)
{
	struct netdev_set_iftype_request *req = user_data;
	struct netdev *netdev = req->netdev;
	struct l_genl_msg *msg;

	if (error != 0)
		goto error;

	msg = netdev_build_cmd_set_interface(netdev, req->pending_type);
	netdev->set_interface_cmd_id =
		l_genl_family_send(nl80211, msg, netdev_set_iftype_cb, req,
					netdev_set_iftype_request_destroy);
	if (!netdev->set_interface_cmd_id) {
		l_genl_msg_unref(msg);
		error = -EIO;
		goto error;
	}

	req->ref++;
	netdev->set_powered_cmd_id = 0;
	return;

error:
	if (req->cb)
		req->cb(netdev, error, req->user_data);
}

int netdev_set_iftype(struct netdev *netdev, enum netdev_iftype type,
			netdev_command_cb_t cb, void *user_data,
			netdev_destroy_func_t destroy)
{
	uint32_t iftype;
	struct netdev_set_iftype_request *req;

	switch (type) {
	case NETDEV_IFTYPE_AP:
		iftype = NL80211_IFTYPE_AP;
		break;
	case NETDEV_IFTYPE_ADHOC:
		iftype = NL80211_IFTYPE_ADHOC;
		break;
	case NETDEV_IFTYPE_STATION:
		iftype = NL80211_IFTYPE_STATION;
		break;
	default:
		l_error("unsupported iftype %u", type);
		return -EINVAL;
	}

	if (netdev->set_powered_cmd_id ||
			netdev->set_interface_cmd_id)
		return -EBUSY;

	req = l_new(struct netdev_set_iftype_request, 1);
	req->cb = cb;
	req->user_data = user_data;
	req->destroy = destroy;
	req->pending_type = iftype;
	req->netdev = netdev;
	req->ref = 1;
	req->bring_up = netdev_get_is_up(netdev);

	if (!req->bring_up) {
		struct l_genl_msg *msg =
			netdev_build_cmd_set_interface(netdev, iftype);

		netdev->set_interface_cmd_id =
			l_genl_family_send(nl80211, msg,
					netdev_set_iftype_cb, req,
					netdev_set_iftype_request_destroy);
		if (netdev->set_interface_cmd_id)
			return 0;

		l_genl_msg_unref(msg);
	} else {
		netdev->set_powered_cmd_id =
			l_rtnl_set_powered(rtnl, netdev->index, false,
					netdev_set_iftype_down_cb, req,
					netdev_set_iftype_request_destroy);
		if (netdev->set_powered_cmd_id)
			return 0;
	}

	l_free(req);
	return -EIO;
}

static void netdev_bridge_port_event(const struct ifinfomsg *ifi, int bytes,
					bool added)
{
	struct netdev *netdev;
	struct rtattr *attr;
	uint32_t master = 0;

	netdev = netdev_find(ifi->ifi_index);
	if (!netdev)
		return;

	for (attr = IFLA_RTA(ifi); RTA_OK(attr, bytes);
			attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFLA_MASTER:
			memcpy(&master, RTA_DATA(attr), sizeof(master));
			break;
		}
	}

	l_debug("netdev: %d %s bridge: %d", ifi->ifi_index,
		(added ? "added to" : "removed from"), master);
}

struct set_4addr_cb_data {
	struct netdev *netdev;
	bool value;
	netdev_command_cb_t callback;
	void *user_data;
	netdev_destroy_func_t destroy;
};

static void netdev_set_4addr_cb(struct l_genl_msg *msg, void *user_data)
{
	struct set_4addr_cb_data *cb_data = user_data;
	int error = l_genl_msg_get_error(msg);

	if (!cb_data)
		return;

	/* cache the value that has just been set */
	if (!error)
		cb_data->netdev->use_4addr = cb_data->value;

	cb_data->callback(cb_data->netdev, error, cb_data->user_data);
}

static void netdev_set_4addr_destroy(void *user_data)
{
	struct set_4addr_cb_data *cb_data = user_data;

	if (!cb_data)
		return;

	if (cb_data->destroy)
		cb_data->destroy(cb_data->user_data);

	l_free(cb_data);
}

int netdev_set_4addr(struct netdev *netdev, bool use_4addr,
			netdev_command_cb_t cb, void *user_data,
			netdev_destroy_func_t destroy)
{
	struct set_4addr_cb_data *cb_data = NULL;
	uint8_t attr_4addr = (use_4addr ? 1 : 0);
	struct l_genl_msg *msg;

	l_debug("netdev: %d use_4addr: %d", netdev->index, use_4addr);

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_INTERFACE, 32);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_4ADDR, 1, &attr_4addr);

	if (cb) {
		cb_data = l_new(struct set_4addr_cb_data, 1);
		cb_data->netdev = netdev;
		cb_data->value = use_4addr;
		cb_data->callback = cb;
		cb_data->user_data = user_data;
		cb_data->destroy = destroy;
	}

	if (!l_genl_family_send(nl80211, msg, netdev_set_4addr_cb, cb_data,
				netdev_set_4addr_destroy)) {
		l_error("CMD_SET_INTERFACE (4addr) failed");

		l_genl_msg_unref(msg);
		l_free(cb_data);

		return -EIO;
	}

	return 0;
}

bool netdev_get_4addr(struct netdev *netdev)
{
	return netdev->use_4addr;
}

static void netdev_newlink_notify(const struct ifinfomsg *ifi, int bytes)
{
	struct netdev *netdev;
	bool old_up, new_up;
	char old_name[IFNAMSIZ];
	uint8_t old_addr[ETH_ALEN];
	struct rtattr *attr;

	if (ifi->ifi_family == AF_BRIDGE) {
		netdev_bridge_port_event(ifi, bytes, true);
		return;
	}

	netdev = netdev_find(ifi->ifi_index);
	if (!netdev)
		return;

	old_up = netdev_get_is_up(netdev);
	strcpy(old_name, netdev->name);
	memcpy(old_addr, netdev->addr, ETH_ALEN);

	netdev->ifi_flags = ifi->ifi_flags;

	for (attr = IFLA_RTA(ifi); RTA_OK(attr, bytes);
			attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFLA_IFNAME:
			strcpy(netdev->name, RTA_DATA(attr));
			break;
		case IFLA_ADDRESS:
			if (RTA_PAYLOAD(attr) < ETH_ALEN)
				break;

			memcpy(netdev->addr, RTA_DATA(attr), ETH_ALEN);
			break;
		}
	}

	if (!netdev->events_ready) /* Did we send NETDEV_WATCH_EVENT_NEW yet? */
		return;

	new_up = netdev_get_is_up(netdev);

	/*
	 * If mac_change_cmd_id is set we are in the process of changing the
	 * MAC address and this event is a result of powering down/up. In this
	 * case we do not want to emit a netdev DOWN/UP event as this would
	 * cause other modules to behave as such. We do, however, want to emit
	 * address changes so other modules get the new MAC address updated.
	 */
	if (old_up != new_up && !netdev->mac_change_cmd_id)
		WATCHLIST_NOTIFY(&netdev_watches, netdev_watch_func_t,
				netdev, new_up ? NETDEV_WATCH_EVENT_UP :
						NETDEV_WATCH_EVENT_DOWN);

	if (strcmp(old_name, netdev->name))
		WATCHLIST_NOTIFY(&netdev_watches, netdev_watch_func_t,
				netdev, NETDEV_WATCH_EVENT_NAME_CHANGE);

	if (memcmp(old_addr, netdev->addr, ETH_ALEN))
		WATCHLIST_NOTIFY(&netdev_watches, netdev_watch_func_t,
				netdev, NETDEV_WATCH_EVENT_ADDRESS_CHANGE);
}

static void netdev_dellink_notify(const struct ifinfomsg *ifi, int bytes)
{
	struct netdev *netdev;

	if (ifi->ifi_family == AF_BRIDGE) {
		netdev_bridge_port_event(ifi, bytes, false);
		return;
	}

	netdev = l_queue_remove_if(netdev_list, netdev_match,
						L_UINT_TO_PTR(ifi->ifi_index));
	if (!netdev)
		return;

	netdev_free(netdev);
}

static void netdev_initial_up_cb(int error, uint16_t type, const void *data,
					uint32_t len, void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->set_powered_cmd_id = 0;

	if (!error)
		netdev->ifi_flags |= IFF_UP;
	else {
		l_error("Error bringing interface %i up: %s", netdev->index,
			strerror(-error));

		if (error != -ERFKILL)
			return;
	}

	l_rtnl_set_linkmode_and_operstate(rtnl, netdev->index,
					IF_LINK_MODE_DORMANT, IF_OPER_DOWN,
					netdev_operstate_cb,
					L_UINT_TO_PTR(netdev->index), NULL);

	/*
	 * we don't know the initial status of the 4addr property on this
	 * netdev, therefore we set it to zero by default.
	 */
	netdev_set_4addr(netdev, netdev->use_4addr, NULL, NULL, NULL);

	l_debug("Interface %i initialized", netdev->index);

	scan_wdev_add(netdev->wdev_id);

	WATCHLIST_NOTIFY(&netdev_watches, netdev_watch_func_t,
				netdev, NETDEV_WATCH_EVENT_NEW);
	netdev->events_ready = true;
}

static bool netdev_check_set_mac(struct netdev *netdev)
{
	if (util_mem_is_zero(netdev->set_mac_once, 6))
		return false;

	l_debug("Setting initial address on ifindex: %d to: " MAC,
		netdev->index, MAC_STR(netdev->set_mac_once));
	netdev->set_powered_cmd_id =
		l_rtnl_set_mac(rtnl, netdev->index, netdev->set_mac_once, true,
				netdev_initial_up_cb, netdev, NULL);
	memset(netdev->set_mac_once, 0, 6);
	return true;
}

static void netdev_initial_down_cb(int error, uint16_t type, const void *data,
					uint32_t len, void *user_data)
{
	struct netdev *netdev = user_data;

	if (!error)
		netdev->ifi_flags &= ~IFF_UP;
	else {
		l_error("Error taking interface %i down: %s", netdev->index,
			strerror(-error));

		netdev->set_powered_cmd_id = 0;
		return;
	}

	if (netdev_check_set_mac(netdev))
		return;

	netdev->set_powered_cmd_id =
		l_rtnl_set_powered(rtnl, netdev->index, true,
					netdev_initial_up_cb, netdev, NULL);
}

static void netdev_getlink_cb(int error, uint16_t type, const void *data,
			uint32_t len, void *user_data)
{
	const struct ifinfomsg *ifi = data;
	unsigned int bytes;
	struct netdev *netdev;
	l_netlink_command_func_t cb;
	bool powered;

	if (error != 0) {
		l_error("RTM_GETLINK error %i: %s", error, strerror(-error));
		return;
	}

	if (ifi->ifi_type != ARPHRD_ETHER || type != RTM_NEWLINK) {
		l_debug("Non-ethernet address or not newlink message -- "
			"ifi_type: %i, type: %i", ifi->ifi_type, type);
		return;
	}

	netdev = netdev_find(ifi->ifi_index);
	if (!netdev)
		return;

	bytes = len - NLMSG_ALIGN(sizeof(struct ifinfomsg));

	netdev_newlink_notify(ifi, bytes);

	/*
	 * If the interface is UP, reset it to ensure a clean state.
	 * Otherwise, if we need to set a random mac, do so.  If not, just
	 * bring the interface UP.
	 */
	powered = netdev_get_is_up(netdev);

	if (!powered && netdev_check_set_mac(netdev))
		return;

	cb = powered ? netdev_initial_down_cb : netdev_initial_up_cb;

	netdev->set_powered_cmd_id =
		l_rtnl_set_powered(rtnl, ifi->ifi_index, !powered, cb, netdev,
					NULL);
}

static struct l_io *pae_open(uint32_t ifindex)
{
	/*
	 * BPF filter to match skb->dev->type == 1 (ARPHRD_ETHER) and
	 * match skb->protocol == 0x888e (PAE) or 0x88c7 (preauthentication).
	 */
	struct sock_filter pae_filter[] = {
		{ 0x20,  0,  0, 0xfffff008 },	/* ld #ifidx		*/
		{ 0x15,  0,  6, 0x00000000 },	/* jne #0, drop		*/
		{ 0x28,  0,  0, 0xfffff01c },	/* ldh #hatype		*/
		{ 0x15,  0,  4, 0x00000001 },	/* jne #1, drop		*/
		{ 0x28,  0,  0, 0xfffff000 },	/* ldh #proto		*/
		{ 0x15,  1,  0, 0x0000888e },	/* je  #0x888e, keep	*/
		{ 0x15,  0,  1, 0x000088c7 },	/* jne #0x88c7, drop	*/
		{ 0x06,  0,  0, 0xffffffff },	/* keep: ret #-1	*/
		{ 0x06,  0,  0, 0000000000 },	/* drop: ret #0		*/
	};

	const struct sock_fprog pae_fprog = {
		.len = L_ARRAY_SIZE(pae_filter),
		.filter = pae_filter
	};

	struct l_io *io;
	int fd;

	fd = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
							htons(ETH_P_ALL));
	if (fd < 0)
		return NULL;

	/*
	 * Here we modify the k value in the BPF program above to match the
	 * given ifindex.  We do it this way instead of using bind to attach
	 * to a specific interface index to avoid having to re-open the fd
	 * whenever the device is powered down / up
	 */

	pae_filter[1].k = ifindex;

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
					&pae_fprog, sizeof(pae_fprog)) < 0)
		goto error;

	io = l_io_new(fd);
	l_io_set_close_on_destroy(io, true);

	return io;

error:
	close(fd);
	return NULL;
}

struct netdev *netdev_create_from_genl(struct l_genl_msg *msg,
					const uint8_t *set_mac)
{
	const char *ifname;
	const uint8_t *ifaddr;
	uint32_t ifindex;
	uint32_t iftype;
	uint64_t wdev;
	uint32_t wiphy_id;
	struct netdev *netdev;
	struct wiphy *wiphy = NULL;
	struct ifinfomsg *rtmmsg;
	size_t bufsize;
	const uint8_t action_neighbor_report_prefix[2] = { 0x05, 0x05 };
	const uint8_t action_sa_query_resp_prefix[2] = { 0x08, 0x01 };
	const uint8_t action_sa_query_req_prefix[2] = { 0x08, 0x00 };
	const uint8_t action_ft_response_prefix[] =  { 0x06, 0x02 };
	const uint8_t action_qos_map_prefix[] = { 0x01, 0x04 };
	struct l_io *pae_io = NULL;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_IFINDEX, &ifindex,
					NL80211_ATTR_WDEV, &wdev,
					NL80211_ATTR_IFNAME, &ifname,
					NL80211_ATTR_WIPHY, &wiphy_id,
					NL80211_ATTR_IFTYPE, &iftype,
					NL80211_ATTR_MAC, &ifaddr,
					NL80211_ATTR_UNSPEC) < 0) {
		l_warn("Required attributes missing");
		return NULL;
	}

	wiphy = wiphy_find(wiphy_id);
	if (!wiphy) {
		l_warn("No wiphy: %d", wiphy_id);
		return NULL;
	}

	if (netdev_find(ifindex)) {
		l_debug("Skipping duplicate netdev %s[%d]", ifname, ifindex);
		return NULL;
	}

	if (!wiphy_has_ext_feature(wiphy,
			NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211) ||
			!pae_over_nl80211) {
		pae_io = pae_open(ifindex);
		if (!pae_io) {
			l_error("Unable to open PAE interface");
			return NULL;
		}
	}

	netdev = l_new(struct netdev, 1);
	netdev->index = ifindex;
	netdev->wdev_id = wdev;
	netdev->type = iftype;
	netdev->rekey_offload_support = true;
	memcpy(netdev->addr, ifaddr, sizeof(netdev->addr));
	l_strlcpy(netdev->name, ifname, IFNAMSIZ);
	netdev->wiphy = wiphy;
	netdev->pae_over_nl80211 = pae_io == NULL;

	if (set_mac)
		memcpy(netdev->set_mac_once, set_mac, 6);

	if (pae_io) {
		netdev->pae_io = pae_io;
		l_io_set_read_handler(netdev->pae_io, netdev_pae_read, netdev,
							netdev_pae_destroy);
	}

	watchlist_init(&netdev->station_watches, NULL);

	l_queue_push_tail(netdev_list, netdev);

	l_debug("Created interface %s[%d %" PRIx64 "]", netdev->name,
		netdev->index, netdev->wdev_id);

	/* Query interface flags */
	bufsize = NLMSG_ALIGN(sizeof(struct ifinfomsg));
	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->ifi_family = AF_UNSPEC;
	rtmmsg->ifi_index = ifindex;

	l_netlink_send(rtnl, RTM_GETLINK, 0, rtmmsg, bufsize,
					netdev_getlink_cb, NULL, NULL);

	l_free(rtmmsg);

	/* Subscribe to Management -> Action -> RM -> Neighbor Report frames */
	frame_watch_add(wdev, 0, 0x00d0, action_neighbor_report_prefix,
			sizeof(action_neighbor_report_prefix),
			netdev_neighbor_report_frame_event, netdev, NULL);

	frame_watch_add(wdev, 0, 0x00d0, action_sa_query_resp_prefix,
			sizeof(action_sa_query_resp_prefix),
			netdev_sa_query_resp_frame_event, netdev, NULL);

	frame_watch_add(wdev, 0, 0x00d0, action_sa_query_req_prefix,
			sizeof(action_sa_query_req_prefix),
			netdev_sa_query_req_frame_event, netdev, NULL);

	frame_watch_add(wdev, 0, 0x00d0, action_ft_response_prefix,
			sizeof(action_ft_response_prefix),
			netdev_ft_response_frame_event, netdev, NULL);

	if (wiphy_supports_qos_set_map(netdev->wiphy))
		frame_watch_add(wdev, 0, 0x00d0, action_qos_map_prefix,
				sizeof(action_qos_map_prefix),
				netdev_qos_map_frame_event, netdev, NULL);

	/* Set RSSI threshold for CQM notifications */
	if (netdev->type == NL80211_IFTYPE_STATION)
		netdev_cqm_rssi_update(netdev);

	return netdev;
}

bool netdev_destroy(struct netdev *netdev)
{
	if (!l_queue_remove(netdev_list, netdev))
		return false;

	netdev_free(netdev);
	return true;
}

static void netdev_link_notify(uint16_t type, const void *data, uint32_t len,
							void *user_data)
{
	const struct ifinfomsg *ifi = data;
	unsigned int bytes;

	if (ifi->ifi_type != ARPHRD_ETHER)
		return;

	l_debug("event %u on ifindex %u", type, ifi->ifi_index);

	bytes = len - NLMSG_ALIGN(sizeof(struct ifinfomsg));

	switch (type) {
	case RTM_NEWLINK:
		netdev_newlink_notify(ifi, bytes);
		break;
	case RTM_DELLINK:
		netdev_dellink_notify(ifi, bytes);
		break;
	}
}

uint32_t netdev_station_watch_add(struct netdev *netdev,
			netdev_station_watch_func_t func, void *user_data)
{
	return watchlist_add(&netdev->station_watches, func, user_data, NULL);
}

bool netdev_station_watch_remove(struct netdev *netdev, uint32_t id)
{
	return watchlist_remove(&netdev->station_watches, id);
}

uint32_t netdev_watch_add(netdev_watch_func_t func,
				void *user_data, netdev_destroy_func_t destroy)
{
	return watchlist_add(&netdev_watches, func, user_data, destroy);
}

bool netdev_watch_remove(uint32_t id)
{
	return watchlist_remove(&netdev_watches, id);
}

static int netdev_init(void)
{
	struct l_genl *genl = iwd_get_genl();
	const struct l_settings *settings = iwd_get_config();
	const char *rand_addr_str;

	if (rtnl)
		return -EALREADY;

	l_debug("Opening route netlink socket");

	rtnl = l_netlink_new(NETLINK_ROUTE);
	if (!rtnl) {
		l_error("Failed to open route netlink socket");
		return -EIO;
	}

	if (getenv("IWD_RTNL_DEBUG"))
		l_netlink_set_debug(rtnl, do_debug, "[RTNL] ", NULL);

	if (!l_netlink_register(rtnl, RTNLGRP_LINK,
				netdev_link_notify, NULL, NULL)) {
		l_error("Failed to register for RTNL link notifications");
		goto fail_netlink;
	}

	nl80211 = l_genl_family_new(genl, NL80211_GENL_NAME);
	if (!nl80211) {
		l_error("Failed to obtain nl80211");
		goto fail_netlink;
	}

	if (!l_settings_get_int(settings, "General", "RoamThreshold",
					&LOW_SIGNAL_THRESHOLD))
		LOW_SIGNAL_THRESHOLD = -70;

	if (!l_settings_get_bool(settings, "General", "ControlPortOverNL80211",
					&pae_over_nl80211))
		pae_over_nl80211 = true;

	rand_addr_str = l_settings_get_value(settings, "General",
						"AddressRandomization");
	if (rand_addr_str && !strcmp(rand_addr_str, "network"))
		mac_per_ssid = true;

	watchlist_init(&netdev_watches, NULL);
	netdev_list = l_queue_new();

	__handshake_set_install_tk_func(netdev_set_tk);
	__handshake_set_install_gtk_func(netdev_set_gtk);
	__handshake_set_install_igtk_func(netdev_set_igtk);

	__eapol_set_rekey_offload_func(netdev_set_rekey_offload);
	__eapol_set_tx_packet_func(netdev_control_port_frame);

	unicast_watch = l_genl_add_unicast_watch(genl, NL80211_GENL_NAME,
						netdev_unicast_notify,
						NULL, NULL);
	if (!unicast_watch)
		l_error("Registering for unicast notification failed");

	if (!l_genl_family_register(nl80211, "mlme", netdev_mlme_notify,
								NULL, NULL))
		l_error("Registering for MLME notification failed");

	return 0;

fail_netlink:
	l_netlink_destroy(rtnl);
	rtnl = NULL;

	return -EIO;
}

static void netdev_exit(void)
{
	struct l_genl *genl = iwd_get_genl();

	if (!rtnl)
		return;

	l_genl_remove_unicast_watch(genl, unicast_watch);

	watchlist_destroy(&netdev_watches);

	l_genl_family_free(nl80211);
	nl80211 = NULL;

	l_debug("Closing route netlink socket");
	l_netlink_destroy(rtnl);
	rtnl = NULL;
}

void netdev_shutdown(void)
{
	if (!rtnl)
		return;

	l_queue_foreach(netdev_list, netdev_shutdown_one, NULL);

	l_queue_destroy(netdev_list, netdev_free);
	netdev_list = NULL;
}

IWD_MODULE(netdev, netdev_init, netdev_exit);
IWD_MODULE_DEPENDS(netdev, eapol);
