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

#include "ell/useful.h"

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
#include "src/diagnostic.h"
#include "src/band.h"

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

enum connection_type {
	CONNECTION_TYPE_SOFTMAC,
	CONNECTION_TYPE_FULLMAC,
	CONNECTION_TYPE_SAE_OFFLOAD,
	CONNECTION_TYPE_PSK_OFFLOAD,
	CONNECTION_TYPE_8021X_OFFLOAD,
};

static uint32_t unicast_watch;

struct netdev_handshake_state {
	struct handshake_state super;
	uint32_t pairwise_new_key_cmd_id;
	uint32_t group_new_key_cmd_id;
	uint32_t group_management_new_key_cmd_id;
	uint32_t set_station_cmd_id;
	uint32_t set_pmk_cmd_id;
	uint32_t pairwise_set_key_tx_cmd_id;
	bool ptk_installed;
	bool gtk_installed;
	bool igtk_installed;
	bool complete;
	struct netdev *netdev;
	enum connection_type type;
};

struct netdev_ext_key_info {
	uint16_t proto;
	bool noencrypt;
	struct eapol_frame frame[];
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

	netdev_event_func_t event_filter;
	netdev_connect_cb_t connect_cb;
	netdev_disconnect_cb_t disconnect_cb;
	netdev_neighbor_report_cb_t neighbor_report_cb;
	netdev_command_cb_t adhoc_cb;
	void *user_data;
	struct eapol_sm *sm;
	struct auth_proto *ap;
	struct owe_sm *owe_sm;
	struct handshake_state *handshake;
	uint32_t connect_cmd_id;
	uint32_t disconnect_cmd_id;
	uint32_t join_adhoc_cmd_id;
	uint32_t leave_adhoc_cmd_id;
	uint32_t set_interface_cmd_id;
	uint32_t rekey_offload_cmd_id;
	uint32_t qos_map_cmd_id;
	uint32_t mac_change_cmd_id;
	uint32_t get_oci_cmd_id;
	uint32_t get_link_cmd_id;
	uint32_t power_save_cmd_id;
	enum netdev_result result;
	uint16_t last_code; /* reason or status, depending on result */
	struct l_timeout *neighbor_report_timeout;
	struct l_timeout *sa_query_timeout;
	struct l_timeout *sa_query_delay;
	struct l_timeout *group_handshake_timeout;
	uint16_t sa_query_id;
	int8_t rssi_levels[16];
	uint8_t rssi_levels_num;
	uint8_t cur_rssi_level_idx;
	int8_t cur_rssi;
	struct l_timeout *rssi_poll_timeout;
	uint32_t rssi_poll_cmd_id;
	uint8_t set_mac_once[6];

	struct scan_bss *fw_roam_bss;

	uint32_t set_powered_cmd_id;
	netdev_command_cb_t set_powered_cb;
	void *set_powered_user_data;
	netdev_destroy_func_t set_powered_destroy;

	uint32_t get_station_cmd_id;
	netdev_get_station_cb_t get_station_cb;
	void *get_station_data;
	netdev_destroy_func_t get_station_destroy;

	struct l_idle *disconnect_idle;

	struct watchlist station_watches;

	struct l_io *pae_io;  /* for drivers without EAPoL over NL80211 */

	struct l_genl_msg *connect_cmd;
	struct l_genl_msg *auth_cmd;
	struct wiphy_radio_work_item work;

	struct netdev_ext_key_info *ext_key_info;

	bool connected : 1;
	bool associated : 1;
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
	bool retry_auth : 1;
	bool in_reassoc : 1;
	bool privacy : 1;
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
static bool mac_per_ssid;

static unsigned int iov_ie_append(struct iovec *iov,
					unsigned int n_iov, unsigned int c,
					const uint8_t *ie, size_t len)
{
	if (L_WARN_ON(c >= n_iov))
		return n_iov;

	if (!ie)
		return c;

	iov[c].iov_base = (void *) ie;
	iov[c].iov_len = len;

	return c + 1u;
}

const char *netdev_iftype_to_string(uint32_t iftype)
{
	switch (iftype) {
	case NL80211_IFTYPE_ADHOC:
		return "ad-hoc";
	case NL80211_IFTYPE_STATION:
		return "station";
	case NL80211_IFTYPE_AP:
		return "ap";
	case NL80211_IFTYPE_P2P_CLIENT:
		return "p2p-client";
	case NL80211_IFTYPE_P2P_GO:
		return "p2p-go";
	case NL80211_IFTYPE_P2P_DEVICE:
		return "p2p-device";
	default:
		break;
	}

	return NULL;
}

static inline bool is_offload(struct handshake_state *hs)
{
	struct netdev_handshake_state *nhs =
		l_container_of(hs, struct netdev_handshake_state, super);

	if (!nhs)
		return false;

	switch (nhs->type) {
	case CONNECTION_TYPE_SOFTMAC:
	case CONNECTION_TYPE_FULLMAC:
	/*
	 * 8021x offload does not quite fit into the same category of PSK
	 * offload. First the netdev_connect_event comes prior to EAP meaning
	 * the handshake is not done at this point. In addition it still
	 * requires EAP take place in userspace meaning IWD needs an eapol_sm.
	 * Because of this, and our prior use of 'is_offload', it does not fit
	 * into the same category and will need to be handled specially.
	 */
	case CONNECTION_TYPE_8021X_OFFLOAD:
		return false;
	case CONNECTION_TYPE_SAE_OFFLOAD:
	case CONNECTION_TYPE_PSK_OFFLOAD:
		return true;
	}

	return false;
}

static unsigned int netdev_populate_common_ies(struct netdev *netdev,
					struct handshake_state *hs,
					struct l_genl_msg *msg,
					struct iovec *iov,
					unsigned int n_iov,
					unsigned int c_iov)
{
	const uint8_t *extended_capabilities;
	const uint8_t *rm_enabled_capabilities;

	extended_capabilities = wiphy_get_extended_capabilities(netdev->wiphy,
								netdev->type);
	c_iov = iov_ie_append(iov, n_iov, c_iov, extended_capabilities,
				IE_LEN(extended_capabilities));

	rm_enabled_capabilities =
		wiphy_get_rm_enabled_capabilities(netdev->wiphy);
	c_iov = iov_ie_append(iov, n_iov, c_iov, rm_enabled_capabilities,
				IE_LEN(rm_enabled_capabilities));

	if (rm_enabled_capabilities)
		l_genl_msg_append_attr(msg, NL80211_ATTR_USE_RRM, 0, NULL);

	c_iov = iov_ie_append(iov, n_iov, c_iov,
				hs->vendor_ies, hs->vendor_ies_len);

	c_iov = iov_ie_append(iov, n_iov, c_iov, hs->fils_ip_req_ie,
				IE_LEN(hs->fils_ip_req_ie));

	return c_iov;
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

	if (nhs->set_pmk_cmd_id) {
		l_genl_family_cancel(nl80211, nhs->set_pmk_cmd_id);
		nhs->set_pmk_cmd_id = 0;
	}

	if (nhs->pairwise_set_key_tx_cmd_id) {
		l_genl_family_cancel(nl80211, nhs->pairwise_set_key_tx_cmd_id);
		nhs->pairwise_set_key_tx_cmd_id = 0;
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
	return netdev->type;
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

uint8_t netdev_get_rssi_level_idx(struct netdev *netdev)
{
	return netdev->cur_rssi_level_idx;
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

static bool netdev_parse_bitrate(struct l_genl_attr *attr,
					enum diagnostic_mcs_type *type_out,
					uint32_t *rate_out,
					uint8_t *mcs_out)
{
	uint16_t type, len;
	const void *data;
	uint32_t rate = 0;
	uint8_t mcs = 0;
	enum diagnostic_mcs_type mcs_type = DIAGNOSTIC_MCS_TYPE_NONE;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_RATE_INFO_BITRATE32:
			if (len != 4)
				return false;

			rate = l_get_u32(data);

			break;

		case NL80211_RATE_INFO_MCS:
			if (len != 1)
				return false;

			mcs = l_get_u8(data);
			mcs_type = DIAGNOSTIC_MCS_TYPE_HT;

			break;

		case NL80211_RATE_INFO_VHT_MCS:
			if (len != 1)
				return false;

			mcs = l_get_u8(data);
			mcs_type = DIAGNOSTIC_MCS_TYPE_VHT;

			break;

		case NL80211_RATE_INFO_HE_MCS:
			if (len != 1)
				return false;

			mcs = l_get_u8(data);
			mcs_type = DIAGNOSTIC_MCS_TYPE_HE;

			break;
		}
	}

	if (!rate)
		return false;

	*type_out = mcs_type;
	*rate_out = rate;

	if (mcs_type != DIAGNOSTIC_MCS_TYPE_NONE)
		*mcs_out = mcs;

	return true;
}

static bool netdev_parse_sta_info(struct l_genl_attr *attr,
					struct diagnostic_station_info *info)
{
	uint16_t type, len;
	const void *data;
	struct l_genl_attr nested;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_STA_INFO_SIGNAL:
			if (len != 1)
				return false;

			info->cur_rssi = *(const int8_t *) data;
			info->have_cur_rssi = true;

			break;
		case NL80211_STA_INFO_SIGNAL_AVG:
			if (len != 1)
				return false;

			info->avg_rssi = *(const int8_t *) data;
			info->have_avg_rssi = true;

			break;
		case NL80211_STA_INFO_RX_BITRATE:
			if (!l_genl_attr_recurse(attr, &nested))
				return false;

			if (!netdev_parse_bitrate(&nested, &info->rx_mcs_type,
							&info->rx_bitrate,
							&info->rx_mcs))
				return false;

			info->have_rx_bitrate = true;

			if (info->rx_mcs_type != DIAGNOSTIC_MCS_TYPE_NONE)
				info->have_rx_mcs = true;

			break;

		case NL80211_STA_INFO_TX_BITRATE:
			if (!l_genl_attr_recurse(attr, &nested))
				return false;

			if (!netdev_parse_bitrate(&nested, &info->tx_mcs_type,
							&info->tx_bitrate,
							&info->tx_mcs))
				return false;

			info->have_tx_bitrate = true;

			if (info->tx_mcs_type != DIAGNOSTIC_MCS_TYPE_NONE)
				info->have_tx_mcs = true;

			break;

		case NL80211_STA_INFO_EXPECTED_THROUGHPUT:
			if (len != 4)
				return false;

			info->expected_throughput = l_get_u32(data);
			info->have_expected_throughput = true;

			break;
		}
	}

	return true;
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
	struct diagnostic_station_info info;
	uint8_t prev_rssi_level_idx = netdev->cur_rssi_level_idx;

	netdev->rssi_poll_cmd_id = 0;

	if (!l_genl_attr_init(&attr, msg))
		goto done;

	found = false;
	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		if (type != NL80211_ATTR_STA_INFO)
			continue;

		if (!l_genl_attr_recurse(&attr, &nested))
			goto done;

		if (!netdev_parse_sta_info(&nested, &info))
			goto done;

		found = true;
		break;
	}

	if (!found || !info.have_cur_rssi)
		goto done;

	netdev->cur_rssi = info.cur_rssi;

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
	if (netdev->work.id)
		wiphy_radio_work_done(netdev->wiphy, netdev->work.id);

	if (netdev->sm) {
		eapol_sm_free(netdev->sm);
		netdev->sm = NULL;
	}

	if (netdev->ap) {
		auth_proto_free(netdev->ap);
		netdev->ap = NULL;
	}

	if (netdev->owe_sm) {
		owe_sm_free(netdev->owe_sm);
		netdev->owe_sm = NULL;
	}

	eapol_preauth_cancel(netdev->index);

	if (netdev->handshake) {
		handshake_state_free(netdev->handshake);
		netdev->handshake = NULL;
	}

	if (netdev->ext_key_info) {
		l_free(netdev->ext_key_info);
		netdev->ext_key_info = NULL;
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

	if (netdev->sa_query_delay) {
		l_timeout_remove(netdev->sa_query_delay);
		netdev->sa_query_delay = NULL;
	}

	if (netdev->group_handshake_timeout) {
		l_timeout_remove(netdev->group_handshake_timeout);
		netdev->group_handshake_timeout = NULL;
	}

	netdev->associated = false;
	netdev->operational = false;
	netdev->connected = false;
	netdev->connect_cb = NULL;
	netdev->event_filter = NULL;
	netdev->user_data = NULL;
	netdev->result = NETDEV_RESULT_OK;
	netdev->last_code = 0;
	netdev->in_ft = false;
	netdev->in_reassoc = false;
	netdev->ignore_connect_event = false;
	netdev->expect_connect_failure = false;
	netdev->cur_rssi_low = false;
	netdev->privacy = false;

	if (netdev->connect_cmd) {
		l_genl_msg_unref(netdev->connect_cmd);
		netdev->connect_cmd = NULL;
	}

	netdev_rssi_polling_update(netdev);

	if (netdev->connect_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->connect_cmd_id);
		netdev->connect_cmd_id = 0;
	} else if (netdev->disconnect_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->disconnect_cmd_id);
		netdev->disconnect_cmd_id = 0;
	}

	if (netdev->get_oci_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->get_oci_cmd_id);
		netdev->get_oci_cmd_id = 0;
	}
}

static void netdev_connect_failed(struct netdev *netdev,
					enum netdev_result result,
					uint16_t status_or_reason)
{
	netdev_connect_cb_t connect_cb = netdev->connect_cb;
	void *connect_data = netdev->user_data;

	/* Done this way to allow re-entrant netdev_connect calls */
	netdev_connect_free(netdev);

	if (connect_cb)
		connect_cb(netdev, result, &status_or_reason, connect_data);
}

static void netdev_connect_failed_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->disconnect_cmd_id = 0;
	netdev_connect_failed(netdev, netdev->result, netdev->last_code);
}

static void netdev_send_and_fail_connection(struct netdev *netdev,
						enum netdev_result result,
						uint16_t status_code,
						struct l_genl_msg *msg)
{
	netdev->result = result;
	netdev->last_code = status_code;

	netdev->disconnect_cmd_id =
		l_genl_family_send(nl80211, msg, netdev_connect_failed_cb,
					netdev, NULL);
}

static void netdev_disconnect_and_fail_connection(struct netdev *netdev,
						enum netdev_result result,
						uint16_t status_code)
{
	struct l_genl_msg *msg = nl80211_build_disconnect(netdev->index,
						MMPDU_REASON_CODE_UNSPECIFIED);

	netdev_send_and_fail_connection(netdev, result, status_code, msg);
}

static void netdev_deauth_and_fail_connection(struct netdev *netdev,
						enum netdev_result result,
						uint16_t status_code)
{
	struct l_genl_msg *msg = nl80211_build_deauthenticate(netdev->index,
						netdev->handshake->aa,
						MMPDU_REASON_CODE_UNSPECIFIED);

	netdev_send_and_fail_connection(netdev, result, status_code, msg);
}

/*
 * If we have a connection callback pending, either through netdev_connect
 * or netdev_reassociate, then invoke that callback with the @result and
 * @status_or_reason.  Otherwise, invoke the event callback with the @event
 * and @status_or_reason.
 *
 * This is useful for situations where handshaking or setting keys somehow
 * fails (perhaps due to rekeying), or if the device is removed / brought
 * down when keys are being set as a result of a rekey
 */
static void netdev_disconnected(struct netdev *netdev,
					enum netdev_result result,
					enum netdev_event event,
					uint16_t status_or_reason)
{
	netdev_event_func_t event_filter = netdev->event_filter;
	void *event_data = netdev->user_data;

	if (netdev->connect_cb) {
		netdev_connect_failed(netdev, result, status_or_reason);
		return;
	}

	netdev_connect_free(netdev);

	if (event_filter)
		event_filter(netdev, event, &status_or_reason, event_data);
}

static void netdev_disconnect_by_sme_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->disconnect_cmd_id = 0;
	netdev_disconnected(netdev, netdev->result,
			NETDEV_EVENT_DISCONNECT_BY_SME, netdev->last_code);
}

static void netdev_disconnect_by_sme(struct netdev *netdev,
					enum netdev_result result,
					uint16_t reason_code)
{
	struct l_genl_msg *msg = nl80211_build_disconnect(netdev->index,
								reason_code);

	netdev->result = result;
	netdev->last_code = reason_code;

	netdev->disconnect_cmd_id = l_genl_family_send(nl80211, msg,
						netdev_disconnect_by_sme_cb,
						netdev, NULL);
}

static void netdev_free(void *data)
{
	struct netdev *netdev = data;

	l_debug("Freeing netdev %s[%d]", netdev->name, netdev->index);

	netdev->ifi_flags &= ~IFF_UP;

	if (netdev->events_ready)
		WATCHLIST_NOTIFY(&netdev_watches, netdev_watch_func_t,
					netdev, NETDEV_WATCH_EVENT_DEL);

	if (netdev->neighbor_report_cb) {
		netdev->neighbor_report_cb(netdev, -ENODEV, NULL, 0,
						netdev->user_data);
		netdev->neighbor_report_cb = NULL;
		l_timeout_remove(netdev->neighbor_report_timeout);
	}

	if (netdev->connected || netdev->connect_cmd_id || netdev->work.id)
		netdev_connect_free(netdev);

	if (netdev->disconnect_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->disconnect_cmd_id);
		netdev->disconnect_cmd_id = 0;

		if (netdev->disconnect_cb)
			netdev->disconnect_cb(netdev, true, netdev->user_data);

		netdev->disconnect_cb = NULL;
		netdev->user_data = NULL;
	}

	if (netdev->disconnect_idle) {
		l_idle_remove(netdev->disconnect_idle);
		netdev->disconnect_idle = NULL;
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

	if (netdev->get_station_cmd_id) {
		l_genl_family_cancel(nl80211, netdev->get_station_cmd_id);
		netdev->get_station_cmd_id = 0;
	}

	if (netdev->fw_roam_bss)
		scan_bss_free(netdev->fw_roam_bss);

	if (netdev->get_link_cmd_id) {
		l_netlink_cancel(rtnl, netdev->get_link_cmd_id);
		netdev->get_link_cmd_id = 0;
	}

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

/* Threshold RSSI for roaming to trigger, configurable in main.conf */
static int LOW_SIGNAL_THRESHOLD;
static int LOW_SIGNAL_THRESHOLD_5GHZ;

static void netdev_cqm_event_rssi_threshold(struct netdev *netdev,
						uint32_t rssi_event)
{
	int event;

	if (!netdev->operational)
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

static void netdev_cqm_event_rssi_value(struct netdev *netdev, int rssi_val)
{
	bool new_rssi_low;
	uint8_t prev_rssi_level_idx = netdev->cur_rssi_level_idx;
	int threshold = netdev->frequency > 4000 ? LOW_SIGNAL_THRESHOLD_5GHZ :
						LOW_SIGNAL_THRESHOLD;

	if (!netdev->connected)
		return;

	if (rssi_val > 127)
		rssi_val = 127;
	else if (rssi_val < -127)
		rssi_val = -127;

	netdev->cur_rssi = rssi_val;

	if (!netdev->event_filter)
		return;

	new_rssi_low = rssi_val < threshold;
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
	uint32_t *pkt_event = NULL;
	bool beacon_loss = false;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_CQM:
			if (!l_genl_attr_recurse(&attr, &nested))
				return;

			while (l_genl_attr_next(&nested, &type, &len, &data)) {
				switch (type) {
				case NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT:
					if (len != 4)
						continue;

					rssi_event = (uint32_t *) data;
					break;

				case NL80211_ATTR_CQM_PKT_LOSS_EVENT:
					if (len != 4)
						continue;

					pkt_event = (uint32_t *) data;
					break;

				case NL80211_ATTR_CQM_BEACON_LOSS_EVENT:
					beacon_loss = true;
					break;

				case NL80211_ATTR_CQM_RSSI_LEVEL:
					if (len != 4)
						continue;

					rssi_val = (int32_t *) data;
					break;
				default:
					l_debug("Unknown CQM event: %d", type);
				}
			}

			break;
		}
	}

	if (rssi_event) {
		if (rssi_val) {
			l_debug("Signal change event (above=%d signal=%d)",
							*rssi_event, *rssi_val);
			netdev_cqm_event_rssi_value(netdev, *rssi_val);
		} else {
			l_debug("Signal change event (above=%d)", *rssi_event);
			netdev_cqm_event_rssi_threshold(netdev, *rssi_event);
		}
	} else if (pkt_event && netdev->event_filter)
		netdev->event_filter(netdev, NETDEV_EVENT_PACKET_LOSS_NOTIFY,
					pkt_event, netdev->user_data);
	else if (beacon_loss && netdev->event_filter)
		netdev->event_filter(netdev, NETDEV_EVENT_BEACON_LOSS_NOTIFY,
					NULL, netdev->user_data);
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

	if (!netdev->connected || netdev->disconnect_cmd_id > 0)
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

	/*
	 * Only ignore this event if issued by the kernel since this is
	 * normal when using CMD_AUTH/ASSOC.
	 */
	if (!disconnect_by_ap && (netdev->in_ft || netdev->in_reassoc))
		return;

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

static void netdev_deauthenticate_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const struct mmpdu_header *hdr = NULL;
	const struct mmpdu_deauthentication *deauth;
	uint16_t reason_code;

	l_debug("");

	/*
	 * If we got to the association phase, process the connect event
	 * instead
	 */
	if (!netdev->connected || netdev->associated)
		return;

	/*
	 * Handle the bizarre case of AP accepting authentication, then
	 * deauthenticating immediately afterwards
	 */

	if (L_WARN_ON(!l_genl_attr_init(&attr, msg)))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_FRAME:
			hdr = mpdu_validate(data, len);
			break;
		}
	}

	if (L_WARN_ON(!hdr))
		return;

	/* Ignore any locally generated frames */
	if (!memcmp(hdr->address_2, netdev->addr, sizeof(netdev->addr)))
		return;

	deauth = mmpdu_body(hdr);
	reason_code = L_LE16_TO_CPU(deauth->reason_code);

	l_info("deauth event, src="MAC" dest="MAC" bssid="MAC" reason=%u",
			MAC_STR(hdr->address_2), MAC_STR(hdr->address_1),
			MAC_STR(hdr->address_3), reason_code);

	netdev_connect_failed(netdev, NETDEV_RESULT_AUTHENTICATION_FAILED,
					reason_code);
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
	l_debug("");

	l_rtnl_set_linkmode_and_operstate(rtnl, netdev->index,
					IF_LINK_MODE_DORMANT, IF_OPER_UP,
					netdev_operstate_cb,
					L_UINT_TO_PTR(netdev->index), NULL);

	netdev->operational = true;

	if (netdev->fw_roam_bss) {
		if (netdev->event_filter)
			netdev->event_filter(netdev, NETDEV_EVENT_ROAMED,
						netdev->fw_roam_bss,
						netdev->user_data);
		else
			scan_bss_free(netdev->fw_roam_bss);

		netdev->fw_roam_bss = NULL;
	} else if (netdev->connect_cb) {
		netdev->connect_cb(netdev, NETDEV_RESULT_OK, NULL,
					netdev->user_data);
		netdev->connect_cb = NULL;
		netdev->in_ft = false;
	} else
		l_warn("Connection event without a connect callback!");

	netdev_rssi_polling_update(netdev);

	if (netdev->work.id)
		wiphy_radio_work_done(netdev->wiphy, netdev->work.id);
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

	switch (netdev->type) {
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_P2P_CLIENT:
		/*
		 * If we failed due to the netdev being brought down,
		 * just abort the connection and do not try to send a
		 * CMD_DISCONNECT
		 */
		if (err == -ENETDOWN) {
			netdev_disconnected(netdev, NETDEV_RESULT_ABORTED,
					NETDEV_EVENT_DISCONNECT_BY_SME,
					MMPDU_STATUS_CODE_UNSPECIFIED);
			return;
		}

		netdev_disconnect_by_sme(netdev,
					NETDEV_RESULT_KEY_SETTING_FAILED,
					MMPDU_REASON_CODE_UNSPECIFIED);
		break;
	case NL80211_IFTYPE_AP:
		if (err == -ENETDOWN)
			return;

		msg = nl80211_build_del_station(netdev->index,
				nhs->super.spa, MMPDU_REASON_CODE_UNSPECIFIED,
				MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION);
		if (!l_genl_family_send(nl80211, msg, NULL, NULL, NULL))
			l_error("error sending DEL_STATION");

		break;
	}

	handshake_event(&nhs->super, HANDSHAKE_EVENT_SETTING_KEYS_FAILED, &err);
}

static void try_handshake_complete(struct netdev_handshake_state *nhs)
{
	l_debug("ptk_installed: %u, gtk_installed: %u, igtk_installed: %u",
			nhs->ptk_installed,
			nhs->gtk_installed,
			nhs->igtk_installed);

	if (nhs->ptk_installed && nhs->gtk_installed && nhs->igtk_installed) {
		l_debug("nhs->complete: %u", nhs->complete);

		if (nhs->complete) {
			handshake_event(&nhs->super,
					HANDSHAKE_EVENT_REKEY_COMPLETE);
			return;
		}

		nhs->complete = true;

		l_debug("Invoking handshake_event()");

		if (handshake_event(&nhs->super, HANDSHAKE_EVENT_COMPLETE))
			return;

		if (nhs->netdev->type == NL80211_IFTYPE_STATION ||
				nhs->netdev->type == NL80211_IFTYPE_P2P_CLIENT)
			netdev_connect_ok(nhs->netdev);
	}
}

static void netdev_set_station_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev_handshake_state *nhs = user_data;
	struct netdev *netdev = nhs->netdev;
	int err;

	l_debug("");

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

	l_debug("ifindex: %u, err: %d", netdev->index, err);
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

	l_debug("ifindex: %u, err: %d", netdev->index, err);
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
	case CRYPTO_CIPHER_GCMP:
	case CRYPTO_CIPHER_GCMP_256:
	case CRYPTO_CIPHER_CCMP_256:
		/*
		 * 802.11-2020 12.8.3 Mapping PTK to CCMP keys:
		 * "A STA shall use the temporal key as the CCMP key
		 * for MPDUs between the two communicating STAs."
		 *
		 * Similar verbiage in 12.8.8
		 */
		memcpy(tk_buf, tk, crypto_cipher_key_len(cipher));
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

	l_debug("ifindex=%d key_idx=%u", netdev->index, key_index);

	if (crypto_cipher_key_len(cipher) != gtk_len) {
		l_error("Unexpected key length: %d", gtk_len);
		netdev_setting_keys_failed(nhs, -ERANGE);
		return;
	}

	if (!netdev_copy_tk(gtk_buf, gtk, cipher, hs->authenticator)) {
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
	uint8_t igtk_buf[32];
	struct netdev *netdev = nhs->netdev;
	struct l_genl_msg *msg;

	nhs->igtk_installed = false;

	l_debug("ifindex=%d key_idx=%u", netdev->index, key_index);

	if (crypto_cipher_key_len(cipher) != igtk_len) {
		l_error("Unexpected key length: %d", igtk_len);
		netdev_setting_keys_failed(nhs, -ERANGE);
		return;
	}

	switch (cipher) {
	case CRYPTO_CIPHER_BIP_CMAC:
	case CRYPTO_CIPHER_BIP_GMAC:
	case CRYPTO_CIPHER_BIP_GMAC_256:
	case CRYPTO_CIPHER_BIP_CMAC_256:
		memcpy(igtk_buf, igtk, igtk_len);
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

static struct l_genl_msg *netdev_build_cmd_set_key_tx(struct netdev *netdev)
{
	uint8_t key_mode = NL80211_KEY_SET_TX;
	struct l_genl_msg *msg = l_genl_msg_new_sized(NL80211_CMD_SET_KEY, 512);

	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN,
					netdev->handshake->aa);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);

	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY);
	l_genl_msg_append_attr(msg, NL80211_KEY_IDX, 1,
				&netdev->handshake->active_tk_index);
	l_genl_msg_append_attr(msg, NL80211_KEY_MODE, 1, &key_mode);
	l_genl_msg_leave_nested(msg);

	return msg;
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

static int netdev_set_key_tx(struct netdev *netdev)
{
	struct netdev_handshake_state *nhs = l_container_of(netdev->handshake,
					struct netdev_handshake_state, super);
	struct l_genl_msg *msg = netdev_build_cmd_set_key_tx(netdev);

	nhs->pairwise_set_key_tx_cmd_id = l_genl_family_send(nl80211, msg,
						netdev_new_pairwise_key_cb,
						nhs, NULL);
	if (nhs->pairwise_set_key_tx_cmd_id > 0)
		return 0;

	l_genl_msg_unref(msg);

	return -EIO;
}

static void netdev_new_rx_pairwise_key_cb(struct l_genl_msg *msg, void *data)
{
	struct netdev_handshake_state *nhs = data;
	struct netdev *netdev = nhs->netdev;
	struct netdev_ext_key_info *info = netdev->ext_key_info;
	int err = l_genl_msg_get_error(msg);

	nhs->pairwise_new_key_cmd_id = 0;

	if (err < 0) {
		const char *ext_error = l_genl_msg_get_extended_error(msg);

		l_error("New Key for RX Pairwise Key failed for ifindex: %d:%s",
				netdev->index,
				ext_error ? ext_error : strerror(-err));
		goto error;
	}

	if (!info)
		return;

	err = netdev_control_port_write_pae(netdev, nhs->super.aa, info->proto,
						info->frame, info->noencrypt);
	l_free(netdev->ext_key_info);
	netdev->ext_key_info = NULL;

	if (err < 0)
		goto error;

	err = netdev_set_key_tx(netdev);
	if (err < 0)
		goto error;

	return;

error:
	netdev_setting_keys_failed(nhs, err);
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

	if (handshake_event(&nhs->super, HANDSHAKE_EVENT_COMPLETE))
		return;

	netdev_connect_ok(nhs->netdev);
}

static void netdev_set_tk(struct handshake_state *hs, uint8_t key_index,
				const uint8_t *tk, uint32_t cipher)
{
	struct netdev_handshake_state *nhs =
		l_container_of(hs, struct netdev_handshake_state, super);
	uint8_t tk_buf[32];
	struct netdev *netdev = nhs->netdev;
	struct l_genl_msg *msg;
	const uint8_t *addr = netdev_choose_key_address(nhs);
	int err;

	nhs->ptk_installed = false;

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

	l_debug("ifindex=%d key_idx=%u", netdev->index, key_index);

	err = -ENOENT;
	if (!netdev_copy_tk(tk_buf, tk, cipher, hs->authenticator))
		goto invalid_key;

	msg = nl80211_build_new_key_pairwise(netdev->index, cipher, addr,
					tk_buf, crypto_cipher_key_len(cipher),
					key_index);
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

static void netdev_set_ext_tk(struct handshake_state *hs, uint8_t key_idx,
				const uint8_t *tk, uint32_t cipher,
				const struct eapol_frame *step4, uint16_t proto,
				bool noencrypt)
{
	struct netdev_handshake_state *nhs =
		l_container_of(hs, struct netdev_handshake_state, super);
	uint8_t tk_buf[32];
	struct netdev *netdev = nhs->netdev;
	struct l_genl_msg *msg;
	const uint8_t *addr = netdev_choose_key_address(nhs);
	int err;
	size_t frame_size = sizeof(struct eapol_header) +
				L_BE16_TO_CPU(step4->header.packet_len);

	err = -ENOENT;
	if (!netdev_copy_tk(tk_buf, tk, cipher, hs->authenticator))
		goto error;

	msg = nl80211_build_new_rx_key_pairwise(netdev->index, cipher, addr,
					tk_buf, crypto_cipher_key_len(cipher),
					hs->active_tk_index);
	nhs->pairwise_new_key_cmd_id =
		l_genl_family_send(nl80211, msg, netdev_new_rx_pairwise_key_cb,
						nhs, NULL);

	if (!nhs->pairwise_new_key_cmd_id)
		goto io_error;

	/*
	 * Without control port we cannot guarantee the order that messages go
	 * out and must wait for NEW_KEY to call back before sending message 4
	 */
	if (!netdev->pae_over_nl80211) {
		netdev->ext_key_info = l_malloc(
					sizeof(struct netdev_ext_key_info) +
					frame_size);
		memcpy(netdev->ext_key_info->frame, step4, frame_size);
		netdev->ext_key_info->proto = proto;
		netdev->ext_key_info->noencrypt = noencrypt;
		return;
	}

	/*
	 * Otherwise, order of messages will be guaranteed. Therefore we can
	 * send send message 4, and set the TK to TX (below) without waiting for
	 * any callbacks
	 */
	err = netdev_control_port_frame(netdev->index, netdev->handshake->aa,
					proto, step4, noencrypt, NULL);
	if (err < 0)
		goto error;

	/* Then toggle to RX + TX */
	err = netdev_set_key_tx(netdev);
	if (err < 0)
		goto error;

	return;

io_error:
	err = -EIO;
	l_genl_msg_unref(msg);

error:
	netdev_setting_keys_failed(nhs, err);
}

static void netdev_set_pmk_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev_handshake_state *nhs = user_data;
	struct netdev *netdev = nhs->netdev;
	int err = l_genl_msg_get_error(msg);

	nhs->set_pmk_cmd_id = 0;

	if (err < 0) {
		l_error("Error with SET_PMK/SET_STATION");
		netdev_setting_keys_failed(nhs, err);
		return;
	}

	if (handshake_event(netdev->handshake, HANDSHAKE_EVENT_SETTING_KEYS))
		return;

	netdev_connect_ok(netdev);
}

static void netdev_set_pmk(struct handshake_state *hs, const uint8_t *pmk,
				size_t pmk_len)
{
	struct l_genl_msg *msg;
	struct netdev_handshake_state *nhs = l_container_of(hs,
				struct netdev_handshake_state, super);
	struct netdev *netdev = nhs->netdev;

	/* Only relevent for 8021x offload */
	if (nhs->type != CONNECTION_TYPE_8021X_OFFLOAD)
		return;

	msg = l_genl_msg_new(NL80211_CMD_SET_PMK);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, netdev->handshake->aa);
	l_genl_msg_append_attr(msg, NL80211_ATTR_PMK,
				netdev->handshake->pmk_len,
				netdev->handshake->pmk);

	nhs->set_pmk_cmd_id = l_genl_family_send(nl80211, msg,
							netdev_set_pmk_cb,
							nhs, NULL);
	if (!nhs->set_pmk_cmd_id) {
		l_error("Failed to set SET_PMK");
		netdev_setting_keys_failed(nhs, -EIO);
		return;
	}
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

	switch (netdev->type) {
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_P2P_CLIENT:
		netdev_disconnect_by_sme(netdev, NETDEV_RESULT_HANDSHAKE_FAILED,
						reason_code);
		break;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_P2P_GO:
		msg = nl80211_build_del_station(netdev->index, nhs->super.spa,
				reason_code,
				MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION);
		if (!l_genl_family_send(nl80211, msg, NULL, NULL, NULL))
			l_error("error sending DEL_STATION");
	}

	if (netdev->work.id)
		wiphy_radio_work_done(netdev->wiphy, netdev->work.id);
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
	msg = nl80211_build_rekey_offload(ifindex, kek, kck, replay_counter);
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

static void netdev_get_oci_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	int err = l_genl_msg_get_error(msg);
	_auto_(l_free) struct band_chandef *chandef =
						l_new(struct band_chandef, 1);

	netdev->get_oci_cmd_id = 0;

	if (err < 0) {
		const char *ext_error = l_genl_msg_get_extended_error(msg);

		l_error("Could not get OCI info: %s",
				ext_error ? ext_error : strerror(-err));
		goto done;
	}

	if (nl80211_parse_chandef(msg, chandef) < 0) {
		l_debug("Couldn't parse operating channel info.");
		goto done;
	}

	l_debug("Obtained OCI: freq: %u, width: %u, center1: %u, center2: %u",
			chandef->frequency, chandef->channel_width,
			chandef->center1_frequency, chandef->center2_frequency);

	handshake_state_set_chandef(netdev->handshake, l_steal_ptr(chandef));

done:
	if (netdev->ap) {
		/*
		 * Cant do much here. IWD assumes every kernel/driver supports
		 * this. There is no way of detecting support either.
		 */
		if (L_WARN_ON(err < 0))
			netdev_connect_failed(netdev,
					NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
		else
			auth_proto_rx_oci(netdev->ap);

		return;
	}

	L_WARN_ON(!eapol_start(netdev->sm));
}

static int netdev_get_oci(void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg =
			l_genl_msg_new_sized(NL80211_CMD_GET_INTERFACE, 64);

	l_debug("");

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);

	netdev->get_oci_cmd_id = l_genl_family_send(nl80211, msg,
						netdev_get_oci_cb, netdev,
						NULL);
	if (!netdev->get_oci_cmd_id) {
		l_genl_msg_unref(msg);
		return -EIO;
	}

	return 0;
}

static void parse_request_ies(struct netdev *netdev, const uint8_t *ies,
				size_t ies_len)
{
	struct ie_tlv_iter iter;
	const void *data;
	const uint8_t *rsnxe = NULL;

	l_debug("");

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
		case IE_TYPE_RSNX:
			if (!rsnxe)
				rsnxe = data - 2;
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

	/* RSNXE element might be omitted when FTing */
	handshake_state_set_supplicant_rsnxe(netdev->handshake, rsnxe);
}

static void netdev_driver_connected(struct netdev *netdev)
{
	netdev->connected = true;

	if (netdev->event_filter)
		netdev->event_filter(netdev, NETDEV_EVENT_ASSOCIATING, NULL,
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
}

static struct l_genl_msg *netdev_build_cmd_connect(struct netdev *netdev,
						struct handshake_state *hs,
						const uint8_t *prev_bssid)
{
	struct netdev_handshake_state *nhs =
		l_container_of(hs, struct netdev_handshake_state, super);
	uint32_t auth_type = IE_AKM_IS_SAE(hs->akm_suite) ?
					NL80211_AUTHTYPE_SAE :
					NL80211_AUTHTYPE_OPEN_SYSTEM;
	enum mpdu_management_subtype subtype = prev_bssid ?
				MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_REQUEST :
				MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST;
	struct l_genl_msg *msg;
	struct iovec iov[64];
	unsigned int n_iov = L_ARRAY_SIZE(iov);
	unsigned int c_iov = 0;
	bool is_rsn = hs->supplicant_ie != NULL;
	uint8_t owe_dh_ie[5 + L_ECC_SCALAR_MAX_BYTES];
	size_t dh_ie_len;

	msg = l_genl_msg_new_sized(NL80211_CMD_CONNECT, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ,
							4, &netdev->frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, hs->aa);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SSID, hs->ssid_len, hs->ssid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);

	switch (nhs->type) {
	case CONNECTION_TYPE_SOFTMAC:
	case CONNECTION_TYPE_FULLMAC:
		break;
	case CONNECTION_TYPE_SAE_OFFLOAD:
		l_genl_msg_append_attr(msg, NL80211_ATTR_SAE_PASSWORD,
					strlen(hs->passphrase), hs->passphrase);
		break;
	case CONNECTION_TYPE_PSK_OFFLOAD:
		l_genl_msg_append_attr(msg, NL80211_ATTR_PMK, 32, hs->pmk);
		break;
	case CONNECTION_TYPE_8021X_OFFLOAD:
		l_genl_msg_append_attr(msg, NL80211_ATTR_WANT_1X_4WAY_HS,
					0, NULL);
	}

	if (prev_bssid)
		l_genl_msg_append_attr(msg, NL80211_ATTR_PREV_BSSID, ETH_ALEN,
						prev_bssid);

	if (netdev->privacy)
		l_genl_msg_append_attr(msg, NL80211_ATTR_PRIVACY, 0, NULL);

	l_genl_msg_append_attr(msg, NL80211_ATTR_SOCKET_OWNER, 0, NULL);

	if (is_rsn) {
		nl80211_append_rsn_attributes(msg, hs);
		c_iov = iov_ie_append(iov, n_iov, c_iov, hs->supplicant_ie,
					IE_LEN(hs->supplicant_ie));
	}

	if (is_rsn || hs->settings_8021x) {
		l_genl_msg_append_attr(msg, NL80211_ATTR_CONTROL_PORT,
						0, NULL);

		if (netdev->pae_over_nl80211)
			l_genl_msg_append_attr(msg,
					NL80211_ATTR_CONTROL_PORT_OVER_NL80211,
					0, NULL);
	}

	if (netdev->owe_sm) {
		owe_build_dh_ie(netdev->owe_sm, owe_dh_ie, &dh_ie_len);
		c_iov = iov_ie_append(iov, n_iov, c_iov, owe_dh_ie, dh_ie_len);
	}

	c_iov = iov_ie_append(iov, n_iov, c_iov, hs->mde, IE_LEN(hs->mde));
	c_iov = netdev_populate_common_ies(netdev, hs, msg, iov, n_iov, c_iov);

	mpdu_sort_ies(subtype, iov, c_iov);

	if (c_iov)
		l_genl_msg_append_attrv(msg, NL80211_ATTR_IE, iov, c_iov);

	return msg;
}

static void netdev_cmd_connect_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->connect_cmd_id = 0;

	if (l_genl_msg_get_error(msg) >= 0) {
		/*
		 * connected should be false if the connect event hasn't come
		 * in yet.  i.e. the CMD_CONNECT ack arrived first (typical).
		 * Mark the connection as 'connected'
		 */
		if (!netdev->connected)
			netdev_driver_connected(netdev);

		return;
	}

	netdev_connect_failed(netdev, NETDEV_RESULT_ASSOCIATION_FAILED,
				MMPDU_STATUS_CODE_UNSPECIFIED);
}

static bool netdev_retry_owe(struct netdev *netdev)
{
	struct l_genl_msg *connect_cmd;

	if (!owe_next_group(netdev->owe_sm))
		return false;

	connect_cmd = netdev_build_cmd_connect(netdev, netdev->handshake, NULL);

	netdev->connect_cmd_id = l_genl_family_send(nl80211, connect_cmd,
						netdev_cmd_connect_cb, netdev,
						NULL);

	if (netdev->connect_cmd_id > 0)
		return true;

	l_genl_msg_unref(connect_cmd);
	return false;
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
	size_t resp_ies_len = 0;
	struct handshake_state *hs = netdev->handshake;
	bool timeout = false;
	uint32_t timeout_reason = 0;

	l_debug("");

	if (netdev->aborting)
		return;

	if (netdev->ignore_connect_event)
		return;

	l_debug("aborting and ignore_connect_event not set, proceed");

	/* Work around mwifiex which sends a Connect Event prior to the Ack */
	if (netdev->connect_cmd_id)
		netdev_driver_connected(netdev);

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
			timeout = true;
			break;
		case NL80211_ATTR_TIMEOUT_REASON:
			if (len != 4)
				break;

			timeout_reason = l_get_u32(data);
			break;
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

	if (timeout) {
		l_warn("connect event timed out, reason=%u", timeout_reason);
		goto error;
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

	l_debug("expect_connect_failure not set, proceed");

	if (netdev->owe_sm && status_code && *status_code ==
				MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP) {
		if (!netdev_retry_owe(netdev))
			goto error;

		return;
	}

	/* AP Rejected the authenticate / associate */
	if (!status_code || *status_code != 0)
		goto error;

	if (!ies)
		goto process_resp_ies;

	parse_request_ies(netdev, ies, ies_len);

process_resp_ies:
	if (resp_ies) {
		const uint8_t *fte = NULL;
		const uint8_t *qos_set = NULL;
		const uint8_t *owe_dh = NULL;
		size_t owe_dh_len = 0;
		size_t qos_len = 0;
		struct ie_ft_info ft_info;
		struct ie_rsn_info info;
		bool owe_akm_found = false;

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
			case IE_TYPE_FILS_IP_ADDRESS:
				if (hs->fils_ip_resp_ie) {
					l_debug("Duplicate response FILS IP "
						"Address Assignment IE");
					l_free(hs->fils_ip_resp_ie);
				}

				hs->fils_ip_resp_ie = l_memdup(data - 3,
					ie_tlv_iter_get_length(&iter) + 3);
				break;
			case IE_TYPE_OWE_DH_PARAM:
				if (!netdev->owe_sm)
					continue;

				owe_dh = data;
				owe_dh_len = ie_tlv_iter_get_length(&iter);

				break;

			case IE_TYPE_RSN:
				if (!netdev->owe_sm)
					continue;

				if (ie_parse_rsne(&iter, &info) < 0) {
					l_error("could not parse RSN IE");
					goto deauth;
				}

				/*
				 * RFC 8110 Section 4.2
				 * An AP agreeing to do OWE MUST include the
				 * OWE AKM in the RSN element portion of the
				 * 802.11 association response.
				 */
				if (info.akm_suites != IE_RSN_AKM_SUITE_OWE) {
					l_error("OWE AKM not included");
					goto deauth;
				}

				owe_akm_found = true;

				break;
			}
		}

		if (netdev->owe_sm) {
			if (!owe_dh) {
				l_error("OWE DH element not found");
				goto deauth;
			}

			if (!owe_akm_found)
				l_warn("OWE AKM was not included in the RSNE. "
					"This AP is out of spec!");

			if (L_WARN_ON(owe_process_dh_ie(netdev->owe_sm, owe_dh,
							owe_dh_len) != 0))
				goto deauth;

			owe_sm_free(netdev->owe_sm);
			netdev->owe_sm = NULL;
		}

		if (fte) {
			uint32_t kck_len =
				handshake_state_get_kck_len(hs);
			/*
			 * If we are here, then most likely we have a FullMac
			 * hw performing initial mobility association.  We need
			 * to set the FTE element or the handshake will fail
			 * The firmware accepted the FTE element, so do not
			 * sanitize the contents and just assume they're okay.
			 */
			if (ie_parse_fast_bss_transition_from_data(fte,
					fte[1] + 2, kck_len, &ft_info) >= 0) {
				handshake_state_set_authenticator_fte(hs, fte);
				handshake_state_set_kh_ids(hs,
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

	l_debug("Request / Response IEs parsed");

	if (netdev->sm) {
		if (!hs->chandef) {
			if (netdev_get_oci(netdev) < 0)
				goto deauth;
		} else if (!eapol_start(netdev->sm))
			goto deauth;

		return;
	}

	/* Allow station to sync the PSK to disk */
	if (is_offload(hs) && handshake_event(hs, HANDSHAKE_EVENT_SETTING_KEYS))
		return;

	netdev_connect_ok(netdev);
	return;

error:
	netdev_connect_failed(netdev, NETDEV_RESULT_ASSOCIATION_FAILED,
			(status_code) ? *status_code :
			MMPDU_STATUS_CODE_UNSPECIFIED);
	return;

deauth:
	netdev_disconnect_and_fail_connection(netdev,
					NETDEV_RESULT_ASSOCIATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
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

	if (is_rsn)
		nl80211_append_rsn_attributes(msg, hs);

	if (is_rsn || hs->settings_8021x) {
		l_genl_msg_append_attr(msg, NL80211_ATTR_CONTROL_PORT,
						0, NULL);

		if (netdev->pae_over_nl80211)
			l_genl_msg_append_attr(msg,
					NL80211_ATTR_CONTROL_PORT_OVER_NL80211,
					0, NULL);
	}

	return msg;
}

static void netdev_cmd_ft_reassociate_cb(struct l_genl_msg *msg,
						void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->connect_cmd_id = 0;

	if (l_genl_msg_get_error(msg) >= 0)
		return;

	netdev_deauth_and_fail_connection(netdev,
					NETDEV_RESULT_ASSOCIATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
}

static bool kernel_will_retry_auth(uint16_t status_code,
					uint16_t alg, uint16_t trans)
{
	/*
	 * Kernel keeps re-trying auth frames until told to stop
	 * when authentication succeeds and under certain SAE-related
	 * circumstances.  Detect these cases.
	 */

	if (status_code == 0)
		return true;

	if (alg != MMPDU_AUTH_ALGO_SAE)
		return false;

	if (status_code == MMPDU_STATUS_CODE_ANTI_CLOGGING_TOKEN_REQ)
		return true;

	if (trans == 1 && (status_code == MMPDU_STATUS_CODE_SAE_PK ||
			status_code == MMPDU_STATUS_CODE_SAE_HASH_TO_ELEMENT))
		return true;

	return false;
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
			l_warn("authentication event timed out");

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

	if (L_WARN_ON(!frame))
		goto auth_error;

	if (netdev->ap) {
		const struct mmpdu_header *hdr;
		const struct mmpdu_authentication *auth;
		bool retry;

		hdr = mpdu_validate(frame, frame_len);
		if (L_WARN_ON(!hdr))
			goto auth_error;

		auth = mmpdu_body(hdr);
		status_code = L_CPU_TO_LE16(auth->status);

		ret = auth_proto_rx_authenticate(netdev->ap, frame, frame_len);

		/* We have sent another CMD_AUTHENTICATE / CMD_ASSOCIATE */
		if (ret == 0 || ret == -EAGAIN)
			return;

		retry = kernel_will_retry_auth(status_code,
				L_CPU_TO_LE16(auth->algorithm),
				L_CPU_TO_LE16(auth->transaction_sequence));

		/*
		 * Spec wants us to silently drop these frames,
		 * if the kernel will keep retrying, let it
		 */
		if ((ret == -ENOMSG || ret == -EBADMSG) && retry)
			return;

		if (ret > 0)
			status_code = (uint16_t)ret;

		/*
		 * We have encountered a fatal error, if the kernel wants
		 * to keep retrying, tell it to stop
		 */
		if (retry) {
			netdev_deauth_and_fail_connection(netdev,
					NETDEV_RESULT_ASSOCIATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
			return;
		}
	}

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
	const struct mmpdu_header *hdr;
	const struct mmpdu_association_response *assoc;

	l_debug("");

	if (!netdev->connected || netdev->aborting)
		return;

	if (!netdev->ap && !netdev->in_ft) {
		netdev->associated = true;
		netdev->in_reassoc = false;
		return;
	}

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

			/*
			 * There will be no connect event when Associate times
			 * out. The failed connection must be explicitly
			 * initiated here.
			 */
			netdev_connect_failed(netdev,
					NETDEV_RESULT_ASSOCIATION_FAILED,
					status_code);
			return;

		case NL80211_ATTR_FRAME:
			frame = data;
			frame_len = len;

			break;
		}
	}

	if (L_WARN_ON(!frame))
		goto assoc_failed;

	hdr = mpdu_validate(frame, frame_len);
	if (L_WARN_ON(!hdr))
		goto assoc_failed;

	assoc = mmpdu_body(hdr);
	status_code = L_CPU_TO_LE16(assoc->status_code);

	if (netdev->ap)
		ret = auth_proto_rx_associate(netdev->ap, frame,
							frame_len);
	else
		ret = __ft_rx_associate(netdev->index, frame,
							frame_len);
	if (ret == 0) {
		bool fils = !!(netdev->handshake->akm_suite &
				(IE_RSN_AKM_SUITE_FILS_SHA256 |
				 IE_RSN_AKM_SUITE_FILS_SHA384 |
				 IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384 |
				 IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256));

		if (netdev->ap) {
			auth_proto_free(netdev->ap);
			netdev->ap = NULL;
		}

		netdev->sm = eapol_sm_new(netdev->handshake);
		eapol_register(netdev->sm);

		/* Just in case this was a retry */
		netdev->ignore_connect_event = false;

		/*
		 * If in FT and/or FILS we don't force an initial 4-way
		 * handshake and instead just keep the EAPoL state
		 * machine for the rekeys.
		 */
		if (netdev->in_ft || fils)
			eapol_sm_set_require_handshake(netdev->sm,
							false);

		netdev->in_reassoc = false;
		netdev->associated = true;
		return;
	} else if (ret == -EAGAIN) {
		/*
		 * Here to support OWE retries. OWE will retry
		 * internally, but a connect event will still be emitted
		 */
		netdev->ignore_connect_event = true;
		return;
	} else if (ret > 0)
		status_code = (uint16_t)ret;

assoc_failed:
	netdev->result = NETDEV_RESULT_ASSOCIATION_FAILED;
	netdev->last_code = status_code;
	netdev->expect_connect_failure = true;
}

static struct l_genl_msg *netdev_build_cmd_authenticate(struct netdev *netdev,
							uint32_t auth_type)
{
	struct handshake_state *hs = netdev->handshake;
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_AUTHENTICATE, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ,
						4, &netdev->frequency);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN,
				netdev->handshake->aa);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SSID, hs->ssid_len, hs->ssid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);

	return msg;
}

static void netdev_scan_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;

	if (l_genl_msg_get_error(msg) < 0) {
		netdev_connect_failed(netdev,
					NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
		return;
	}

	netdev->retry_auth = true;
}

static void netdev_auth_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	struct handshake_state *hs = netdev->handshake;
	int err = l_genl_msg_get_error(msg);
	struct l_genl_msg *scan_msg;

	if (!err) {
		l_genl_msg_unref(netdev->auth_cmd);
		netdev->auth_cmd = NULL;
		return;
	}

	l_debug("Error during auth: %d", err);

	if (!netdev->auth_cmd || err != -ENOENT)
		goto failed;

	/* Kernel can't find the BSS in its cache, scan and retry */
	scan_msg = scan_build_trigger_scan_bss(netdev->index, netdev->wiphy,
						netdev->frequency,
						hs->ssid, hs->ssid_len);

	if (l_genl_family_send(nl80211, scan_msg,
					netdev_scan_cb, netdev, NULL) > 0)
		return;

	l_genl_msg_unref(scan_msg);
failed:
	netdev_connect_failed(netdev, NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
}

static void netdev_new_scan_results_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	if (!netdev->retry_auth)
		return;

	l_debug("");

	if (!l_genl_family_send(nl80211, netdev->auth_cmd,
					netdev_auth_cb, netdev, NULL)) {
		netdev_connect_failed(netdev,
					NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
		return;
	}

	netdev->auth_cmd = NULL;
}

static void netdev_assoc_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	int err = l_genl_msg_get_error(msg);

	if (err < 0) {
		l_error("Error sending CMD_ASSOCIATE (%d)", err);

		netdev_connect_failed(netdev, NETDEV_RESULT_ASSOCIATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
	}
}

static void netdev_sae_tx_authenticate(const uint8_t *body,
					size_t body_len, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_msg *msg;

	msg = netdev_build_cmd_authenticate(netdev, NL80211_AUTHTYPE_SAE);
	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_DATA, body_len, body);

	if (!l_genl_family_send(nl80211, msg, netdev_auth_cb, netdev, NULL)) {
		l_genl_msg_unref(msg);
		netdev_connect_failed(netdev,
					NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
		return;
	}

	/*
	 * Sometimes due to the way the scheduling works out, netdev_auth_cb
	 * is sent after the SAE Authentication reply from the AP arrives.
	 * Do not leak auth_cmd if this occurs.  Note that if auth_cmd is not
	 * NULL and we are here, there's no further reason to save off auth_cmd.
	 * This is done only if the kernel's cache lacks the BSS we are trying
	 * to communicate with.
	 */
	if (netdev->auth_cmd) {
		l_genl_msg_unref(netdev->auth_cmd);
		netdev->auth_cmd = NULL;
	} else
		netdev->auth_cmd = l_genl_msg_ref(msg);
}

static void netdev_sae_tx_associate(void *user_data)
{
	struct netdev *netdev = user_data;
	struct handshake_state *hs = netdev->handshake;
	struct l_genl_msg *msg;
	struct iovec iov[64];
	unsigned int n_iov = L_ARRAY_SIZE(iov);
	unsigned int n_used = 0;
	enum mpdu_management_subtype subtype =
				MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST;

	msg = netdev_build_cmd_associate_common(netdev);

	n_used = iov_ie_append(iov, n_iov, n_used, hs->supplicant_ie,
						IE_LEN(hs->supplicant_ie));
	n_used = iov_ie_append(iov, n_iov, n_used, hs->mde, IE_LEN(hs->mde));
	n_used = iov_ie_append(iov, n_iov, n_used, hs->supplicant_rsnxe,
					IE_LEN(hs->supplicant_rsnxe));
	n_used = netdev_populate_common_ies(netdev, hs, msg,
							iov, n_iov, n_used);
	mpdu_sort_ies(subtype, iov, n_used);

	l_genl_msg_append_attrv(msg, NL80211_ATTR_IE, iov, n_used);

	/* If doing a non-FT Reassociation */
	if (netdev->in_reassoc)
		l_genl_msg_append_attr(msg, NL80211_ATTR_PREV_BSSID, 6,
					netdev->ap->prev_bssid);

	if (!l_genl_family_send(nl80211, msg, netdev_assoc_cb, netdev, NULL)) {
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

	msg = netdev_build_cmd_authenticate(netdev, NL80211_AUTHTYPE_FILS_SK);

	l_genl_msg_append_attr(msg, NL80211_ATTR_AUTH_DATA, body_len, body);

	if (!l_genl_family_send(nl80211, msg, netdev_auth_cb,
							netdev, NULL)) {
		l_genl_msg_unref(msg);
		netdev_connect_failed(netdev,
					NETDEV_RESULT_AUTHENTICATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
		return;
	}

	/* See comment in netdev_sae_tx_authenticate */
	if (netdev->auth_cmd) {
		l_genl_msg_unref(netdev->auth_cmd);
		netdev->auth_cmd = NULL;
	} else
		netdev->auth_cmd = l_genl_msg_ref(msg);
}

static void netdev_fils_tx_associate(struct iovec *fils_iov, size_t n_fils_iov,
					const uint8_t *kek, size_t kek_len,
					const uint8_t *nonces,
					size_t nonces_len,
					void *user_data)
{
	struct netdev *netdev = user_data;
	struct handshake_state *hs = netdev->handshake;
	struct l_genl_msg *msg;
	struct iovec iov[64];
	unsigned int n_iov = L_ARRAY_SIZE(iov);
	unsigned int c_iov = 0;
	enum mpdu_management_subtype subtype =
				MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST;

	msg = netdev_build_cmd_associate_common(netdev);
	c_iov = netdev_populate_common_ies(netdev, hs, msg, iov, n_iov, c_iov);

	if (!L_WARN_ON(n_iov - c_iov < n_fils_iov)) {
		memcpy(iov + c_iov, fils_iov, sizeof(*fils_iov) * n_fils_iov);
		c_iov += n_fils_iov;
	}

	mpdu_sort_ies(subtype, iov, c_iov);

	l_genl_msg_append_attrv(msg, NL80211_ATTR_IE, iov, c_iov);

	l_genl_msg_append_attr(msg, NL80211_ATTR_FILS_KEK, kek_len, kek);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FILS_NONCES,
							nonces_len, nonces);

	/* If doing a non-FT Reassociation */
	if (netdev->in_reassoc)
		l_genl_msg_append_attr(msg, NL80211_ATTR_PREV_BSSID, 6,
					netdev->ap->prev_bssid);

	if (!l_genl_family_send(nl80211, msg, netdev_assoc_cb,
							netdev, NULL)) {
		l_genl_msg_unref(msg);
		netdev_connect_failed(netdev, NETDEV_RESULT_ASSOCIATION_FAILED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
	}
}

struct rtnl_data {
	struct netdev *netdev;
	uint8_t addr[ETH_ALEN];
	int ref;
};

static int netdev_begin_connection(struct netdev *netdev)
{
	if (netdev->connect_cmd) {
		netdev->connect_cmd_id = l_genl_family_send(nl80211,
						netdev->connect_cmd,
						netdev_cmd_connect_cb, netdev,
						NULL);

		if (!netdev->connect_cmd_id)
			goto failed;

		netdev->connect_cmd = NULL;
	}

	/*
	 * Set the supplicant address now, this may have already been done for
	 * a non-randomized address connect, but if we are randomizing we need
	 * to set it again as the address should have now changed.
	 */
	handshake_state_set_supplicant_address(netdev->handshake, netdev->addr);

	if (netdev->ap) {
		if (!auth_proto_start(netdev->ap))
			goto failed;

		/*
		 * set connected since the auth protocols cannot do
		 * so internally
		 */
		netdev->connected = true;
	}

	return 0;

failed:
	netdev_connect_failed(netdev, NETDEV_RESULT_ABORTED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
	return -EIO;
}

static void netdev_mac_change_failed(struct netdev *netdev, int error)
{
	l_error("Error setting mac address on %d: %s", netdev->index,
			strerror(-error));

	/*
	 * If the interface is down and we failed to up it we need to notify
	 * any watchers since we have been skipping the notification while
	 * mac_change_cmd_id was set.
	 */
	if (!netdev_get_is_up(netdev)) {
		WATCHLIST_NOTIFY(&netdev_watches, netdev_watch_func_t,
				netdev, NETDEV_WATCH_EVENT_DOWN);

		netdev_connect_failed(netdev, NETDEV_RESULT_ABORTED,
				MMPDU_STATUS_CODE_UNSPECIFIED);
		return;
	}

	/* If the interface is up we can still try and connect */
	l_info("Failed to change the MAC, continuing with connection");

	if (netdev_begin_connection(netdev) < 0)
		l_error("netdev_begin_connection() error in mac_change_failed");
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
		l_error("Error changing per-network MAC on interface %u: %s",
			netdev->index, strerror(-error));
		netdev_mac_change_failed(netdev, error);
		return;
	}

	/* Pick up where we left off in netdev_connect_commmon */
	if (netdev_begin_connection(netdev) < 0)
		l_error("netdev_begin_connection() error in mac_power_up_cb");
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
		netdev_mac_change_failed(netdev, error);
		return;
	}

	netdev->mac_change_cmd_id = l_rtnl_set_mac(rtnl, netdev->index,
					req->addr, true,
					netdev_mac_power_up_cb, req,
					netdev_mac_destroy);
	if (!netdev->mac_change_cmd_id) {
		netdev_mac_change_failed(netdev, -EIO);
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
static int netdev_start_powered_mac_change(struct netdev *netdev)
{
	struct rtnl_data *req;
	uint8_t new_addr[6];
	bool powered = wiphy_has_ext_feature(netdev->wiphy,
				NL80211_EXT_FEATURE_POWERED_ADDR_CHANGE);

	/* No address set in handshake, use per-network MAC generation */
	if (l_memeqzero(netdev->handshake->spa, ETH_ALEN))
		wiphy_generate_address_from_ssid(netdev->wiphy,
					netdev->handshake->ssid,
					netdev->handshake->ssid_len,
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
	req->ref++;
	memcpy(req->addr, new_addr, sizeof(req->addr));

	if (powered)
		netdev->mac_change_cmd_id = l_rtnl_set_mac(rtnl, netdev->index,
						req->addr, false,
						netdev_mac_power_up_cb, req,
						netdev_mac_destroy);
	else
		netdev->mac_change_cmd_id = l_rtnl_set_powered(rtnl,
						netdev->index, false,
						netdev_mac_power_down_cb, req,
						netdev_mac_destroy);

	if (!netdev->mac_change_cmd_id) {
		l_free(req);

		return -EIO;
	}

	l_debug("Setting generated address on ifindex: %d to: "MAC" (%s)",
					netdev->index, MAC_STR(req->addr),
					powered ? "powered" : "power-down");

	return 0;
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
	int threshold = netdev->frequency > 4000 ? LOW_SIGNAL_THRESHOLD_5GHZ :
						LOW_SIGNAL_THRESHOLD;

	if (levels_num == 0) {
		thold_list[0] = threshold;
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

			if (val >= threshold && !low_sig_added) {
				thold_list[thold_count++] = threshold;
				low_sig_added = true;

				/* Duplicate values are not allowed */
				if (val == threshold)
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

static int netdev_cqm_rssi_update(struct netdev *netdev)
{
	struct l_genl_msg *msg;

	l_debug("");

	if (!wiphy_has_ext_feature(netdev->wiphy,
					NL80211_EXT_FEATURE_CQM_RSSI_LIST))
		msg = netdev_build_cmd_cqm_rssi_update(netdev, NULL, 0);
	else
		msg = netdev_build_cmd_cqm_rssi_update(netdev,
						netdev->rssi_levels,
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

static bool netdev_connection_work_ready(struct wiphy_radio_work_item *item)
{
	struct netdev *netdev = l_container_of(item, struct netdev, work);

	netdev->retry_auth = false;

	if (mac_per_ssid) {
		int ret = netdev_start_powered_mac_change(netdev);

		if (!ret)
			return false;
		else if (ret != -EALREADY)
			goto failed;
	}

	if (netdev_begin_connection(netdev) < 0)
		return true;

	return false;

failed:
	netdev_connect_failed(netdev, NETDEV_RESULT_ABORTED,
				MMPDU_STATUS_CODE_UNSPECIFIED);

	return true;
}

static void netdev_connection_work_destroy(struct wiphy_radio_work_item *item)
{
	struct netdev *netdev = l_container_of(item, struct netdev, work);

	if (netdev->auth_cmd) {
		l_genl_msg_unref(netdev->auth_cmd);
		netdev->auth_cmd = NULL;
	}

	netdev->retry_auth = false;
}

static const struct wiphy_radio_work_item_ops connect_work_ops = {
	.do_work = netdev_connection_work_ready,
	.destroy = netdev_connection_work_destroy,
};

static int netdev_handshake_state_setup_connection_type(
						struct handshake_state *hs)
{
	struct netdev_handshake_state *nhs = l_container_of(hs,
				struct netdev_handshake_state, super);
	struct wiphy *wiphy = nhs->netdev->wiphy;
	bool softmac = wiphy_supports_cmds_auth_assoc(wiphy);
	bool canroam = wiphy_supports_firmware_roam(wiphy);

	if (hs->supplicant_ie == NULL)
		goto softmac;

	/*
	 * Sanity check that any FT AKMs are set only on softmac or on
	 * devices that support firmware roam
	 */
	if (L_WARN_ON(IE_AKM_IS_FT(hs->akm_suite) && !softmac && !canroam))
		return -ENOTSUP;

	switch (hs->akm_suite) {
	case IE_RSN_AKM_SUITE_PSK:
	case IE_RSN_AKM_SUITE_FT_USING_PSK:
	case IE_RSN_AKM_SUITE_PSK_SHA256:
		if (wiphy_has_ext_feature(wiphy,
				NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK))
			goto psk_offload;

	/* fall through */
	case IE_RSN_AKM_SUITE_OWE:
		if (softmac)
			goto softmac;

		goto fullmac;
	case IE_RSN_AKM_SUITE_8021X:
	case IE_RSN_AKM_SUITE_FT_OVER_8021X:
	case IE_RSN_AKM_SUITE_8021X_SHA256:
	case IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA256:
	case IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA384:
	case IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384:
		if (wiphy_has_ext_feature(wiphy,
				NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X))
			goto offload_1x;

		if (softmac)
			goto softmac;

		goto fullmac;
	case IE_RSN_AKM_SUITE_SAE_SHA256:
	case IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256:
		if (wiphy_has_ext_feature(wiphy,
					NL80211_EXT_FEATURE_SAE_OFFLOAD))
			goto sae_offload;

		if (softmac && wiphy_has_feature(wiphy, NL80211_FEATURE_SAE))
			goto softmac;

		return -EINVAL;
	case IE_RSN_AKM_SUITE_FILS_SHA256:
	case IE_RSN_AKM_SUITE_FILS_SHA384:
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256:
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384:
		/* FILS has no offload in any upstream driver */
		if (softmac)
			goto softmac;

		return -ENOTSUP;
	case IE_RSN_AKM_SUITE_TDLS:
	case IE_RSN_AKM_SUITE_AP_PEER_KEY_SHA256:
	case IE_RSN_AKM_SUITE_OSEN:
		return -ENOTSUP;
	}

	return -ENOTSUP;

softmac:
	nhs->type = CONNECTION_TYPE_SOFTMAC;
	return 0;
fullmac:
	nhs->type = CONNECTION_TYPE_FULLMAC;
	return 0;
sae_offload:
	nhs->type = CONNECTION_TYPE_SAE_OFFLOAD;
	return 0;
psk_offload:
	nhs->type = CONNECTION_TYPE_PSK_OFFLOAD;
	return 0;
offload_1x:
	nhs->type = CONNECTION_TYPE_8021X_OFFLOAD;
	return 0;
}

static void netdev_connect_common(struct netdev *netdev,
					const struct scan_bss *bss,
					const struct scan_bss *prev_bss,
					struct handshake_state *hs,
					netdev_event_func_t event_filter,
					netdev_connect_cb_t cb, void *user_data)
{
	struct netdev_handshake_state *nhs = l_container_of(hs,
				struct netdev_handshake_state, super);
	struct l_genl_msg *cmd_connect = NULL;
	struct eapol_sm *sm = NULL;
	bool is_rsn = hs->supplicant_ie != NULL;
	const uint8_t *prev_bssid = prev_bss ? prev_bss->addr : NULL;

	netdev->frequency = bss->frequency;
	netdev->privacy = bss->capability & IE_BSS_CAP_PRIVACY;
	handshake_state_set_authenticator_address(hs, bss->addr);

	if (!is_rsn)
		goto build_cmd_connect;

	if (nhs->type != CONNECTION_TYPE_SOFTMAC)
		goto build_cmd_connect;

	switch (hs->akm_suite) {
	case IE_RSN_AKM_SUITE_SAE_SHA256:
	case IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256:
		netdev->ap = sae_sm_new(hs, netdev_sae_tx_authenticate,
						netdev_sae_tx_associate,
						netdev);

		if (sae_sm_is_h2e(netdev->ap)) {
			uint8_t own_rsnxe[20];

			if (wiphy_get_rsnxe(netdev->wiphy,
					own_rsnxe, sizeof(own_rsnxe))) {
				set_bit(own_rsnxe + 2, IE_RSNX_SAE_H2E);
				handshake_state_set_supplicant_rsnxe(hs,
								own_rsnxe);
			}
		}

		if (bss->force_default_sae_group)
			sae_sm_set_force_group_19(netdev->ap);

		break;
	case IE_RSN_AKM_SUITE_OWE:
		netdev->owe_sm = owe_sm_new(hs);

		goto build_cmd_connect;
	case IE_RSN_AKM_SUITE_FILS_SHA256:
	case IE_RSN_AKM_SUITE_FILS_SHA384:
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256:
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384:
		netdev->ap = fils_sm_new(hs, netdev_fils_tx_authenticate,
						netdev_fils_tx_associate,
						netdev_get_oci,
						netdev);
		break;
	default:
build_cmd_connect:
		cmd_connect = netdev_build_cmd_connect(netdev, hs, prev_bssid);

		if (!is_offload(hs) && (is_rsn || hs->settings_8021x)) {
			sm = eapol_sm_new(hs);

			if (nhs->type == CONNECTION_TYPE_8021X_OFFLOAD)
				eapol_sm_set_require_handshake(sm, false);
		}
	}

	netdev->connect_cmd = cmd_connect;
	netdev->event_filter = event_filter;
	netdev->connect_cb = cb;
	netdev->user_data = user_data;
	netdev->handshake = hs;
	netdev->sm = sm;
	netdev->cur_rssi = bss->signal_strength / 100;

	if (netdev->rssi_levels_num)
		netdev_set_rssi_level_idx(netdev);

	netdev_cqm_rssi_update(netdev);

	if (!wiphy_has_ext_feature(netdev->wiphy,
					NL80211_EXT_FEATURE_CAN_REPLACE_PTK0))
		handshake_state_set_no_rekey(hs, true);

	wiphy_radio_work_insert(netdev->wiphy, &netdev->work,
				WIPHY_WORK_PRIORITY_CONNECT, &connect_work_ops);
}

int netdev_connect(struct netdev *netdev, const struct scan_bss *bss,
				struct handshake_state *hs,
				netdev_event_func_t event_filter,
				netdev_connect_cb_t cb, void *user_data)
{
	if (!(netdev->ifi_flags & IFF_UP))
		return -ENETDOWN;

	if (netdev->type != NL80211_IFTYPE_STATION &&
			netdev->type != NL80211_IFTYPE_P2P_CLIENT)
		return -ENOTSUP;

	if (netdev->connected || netdev->connect_cmd_id || netdev->work.id)
		return -EISCONN;

	if (netdev_handshake_state_setup_connection_type(hs) < 0)
		return -ENOTSUP;

	netdev_connect_common(netdev, bss, NULL, hs,
				event_filter, cb, user_data);

	return 0;
}

static void disconnect_idle(struct l_idle *idle, void *user_data)
{
	struct netdev *netdev = user_data;

	l_idle_remove(idle);
	netdev->disconnect_idle = NULL;

	netdev->disconnect_cb(netdev, true, netdev->user_data);
}

int netdev_disconnect(struct netdev *netdev,
				netdev_disconnect_cb_t cb, void *user_data)
{
	struct l_genl_msg *disconnect;
	bool send_disconnect = true;

	if (!(netdev->ifi_flags & IFF_UP))
		return -ENETDOWN;

	if (netdev->type != NL80211_IFTYPE_STATION &&
			netdev->type != NL80211_IFTYPE_P2P_CLIENT)
		return -ENOTSUP;

	if (netdev->disconnect_cmd_id)
		return -EINPROGRESS;

	/* Only perform this if we haven't successfully fully associated yet */
	if (!netdev->operational) {
		/*
		 * Three possibilities here:
		 * 1. We do not actually have a connect in progress (work.id
		 *    is zero), then we can bail out early with an error.
		 * 2. We have sent CMD_CONNECT but not fully connected. The
		 *    CMD_CONNECT needs to be canceled and a disconnect should
		 *    be sent.
		 * 3. Queued up the connect work, but haven't sent CMD_CONNECT
		 *    to the kernel. This case we do not need to send a
		 *    disconnect.
		 */
		if (!netdev->work.id)
			return -ENOTCONN;

		if (netdev->connect_cmd_id) {
			l_genl_family_cancel(nl80211, netdev->connect_cmd_id);
			netdev->connect_cmd_id = 0;
		} else if (!wiphy_radio_work_is_running(netdev->wiphy,
							netdev->work.id))
			send_disconnect = false;

		netdev_connect_failed(netdev, NETDEV_RESULT_ABORTED,
					MMPDU_REASON_CODE_UNSPECIFIED);
	} else {
		netdev_connect_free(netdev);
	}

	if (send_disconnect) {
		disconnect = nl80211_build_disconnect(netdev->index,
					MMPDU_REASON_CODE_DEAUTH_LEAVING);
		netdev->disconnect_cmd_id = l_genl_family_send(nl80211,
					disconnect, netdev_cmd_disconnect_cb,
					netdev, NULL);

		if (!netdev->disconnect_cmd_id) {
			l_genl_msg_unref(disconnect);
			return -EIO;
		}

		netdev->disconnect_cb = cb;
		netdev->user_data = user_data;
		netdev->aborting = true;
	} else if (cb) {
		netdev->disconnect_cb = cb;
		netdev->user_data = user_data;
		netdev->disconnect_idle = l_idle_create(disconnect_idle,
							netdev, NULL);
	}

	return 0;
}

int netdev_reassociate(struct netdev *netdev, const struct scan_bss *target_bss,
			const struct scan_bss *orig_bss,
			struct handshake_state *hs,
			netdev_event_func_t event_filter,
			netdev_connect_cb_t cb, void *user_data)
{
	struct handshake_state *old_hs;
	struct eapol_sm *old_sm;

	old_sm = netdev->sm;
	old_hs = netdev->handshake;

	if (netdev_handshake_state_setup_connection_type(hs) < 0)
		return -ENOTSUP;

	netdev->associated = false;
	netdev->operational = false;
	netdev->connected = false;
	netdev->in_reassoc = true;

	netdev_connect_common(netdev, target_bss, orig_bss, hs,
					event_filter, cb, user_data);

	if (netdev->ap)
		memcpy(netdev->ap->prev_bssid, orig_bss->addr, ETH_ALEN);

	netdev_rssi_polling_update(netdev);

	if (old_sm)
		eapol_sm_free(old_sm);

	if (old_hs)
		handshake_state_free(old_hs);

	return 0;
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
	uint32_t ch_freq = band_channel_to_freq(6, BAND_FREQ_2_4_GHZ);
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
					l_genl_msg_func_t callback,
					void *user_data)
{
	uint32_t id;
	struct l_genl_msg *msg = nl80211_build_cmd_frame(netdev->index,
								0x00d0,
								netdev->addr,
								to, freq,
								iov, iov_len);

	id = l_genl_family_send(nl80211, msg, callback, user_data, NULL);

	if (!id)
		l_genl_msg_unref(msg);

	return id;
}

static uint32_t netdev_send_action_frame(struct netdev *netdev,
					const uint8_t *to,
					const uint8_t *body, size_t body_len,
					uint32_t freq,
					l_genl_msg_func_t callback,
					void *user_data)
{
	struct iovec iov[1];

	iov[0].iov_base = (void *)body;
	iov[0].iov_len = body_len;

	return netdev_send_action_framev(netdev, to, iov, 1, freq, callback,
						user_data);
}

static void netdev_ft_frame_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_debug("Failed to send FT-Frame");
}

static int netdev_tx_ft_frame(uint32_t ifindex, uint16_t frame_type,
					uint32_t frequency, const uint8_t *dest,
					struct iovec *iov, size_t iov_len)
{
	struct netdev *netdev = netdev_find(ifindex);
	struct l_genl_msg *msg = nl80211_build_cmd_frame(netdev->index,
							frame_type,
							netdev->addr, dest,
							frequency,
							iov, iov_len);

	/*
	 * Even though the kernel is doing offchannel for Authentication this
	 * flag is still required otherwise the kernel gives -EBUSY.
	 */
	l_genl_msg_append_attr(msg, NL80211_ATTR_OFFCHANNEL_TX_OK, 0, NULL);

	if (!l_genl_family_send(nl80211, msg, netdev_ft_frame_cb,
				netdev, NULL)) {
		l_genl_msg_unref(msg);
		return -EIO;
	}

	return 0;
}

int netdev_ft_reassociate(struct netdev *netdev,
				const struct scan_bss *target_bss,
				const struct scan_bss *orig_bss,
				netdev_event_func_t event_filter,
				netdev_connect_cb_t cb, void *user_data)
{
	struct handshake_state *hs = netdev->handshake;
	struct netdev_handshake_state *nhs;
	struct l_genl_msg *msg;
	struct iovec iov[64];
	unsigned int n_iov = L_ARRAY_SIZE(iov);
	unsigned int c_iov = 0;
	enum mpdu_management_subtype subtype =
				MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_REQUEST;

	/*
	 * At this point there is no going back with FT so reset all the flags
	 * needed to associate with a new BSS.
	 */
	netdev->frequency = target_bss->frequency;
	netdev->handshake->active_tk_index = 0;
	netdev->associated = false;
	netdev->operational = false;
	netdev->in_ft = true;
	netdev->event_filter = event_filter;
	netdev->connect_cb = cb;
	netdev->user_data = user_data;

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
	netdev_cqm_rssi_update(netdev);

	if (netdev->sm) {
		eapol_sm_free(netdev->sm);
		netdev->sm = NULL;
	}

	msg = netdev_build_cmd_associate_common(netdev);

	c_iov = netdev_populate_common_ies(netdev, hs, msg, iov, n_iov, c_iov);

	if (hs->supplicant_ie)
		c_iov = iov_ie_append(iov, n_iov, c_iov, hs->supplicant_ie,
					IE_LEN(hs->supplicant_ie));

	if (hs->supplicant_fte)
		c_iov = iov_ie_append(iov, n_iov, c_iov, hs->supplicant_fte,
					IE_LEN(hs->supplicant_fte));

	if (hs->mde)
		c_iov = iov_ie_append(iov, n_iov, c_iov, hs->mde,
					IE_LEN(hs->mde));

	mpdu_sort_ies(subtype, iov, c_iov);

	l_genl_msg_append_attr(msg, NL80211_ATTR_PREV_BSSID, ETH_ALEN,
				orig_bss->addr);
	l_genl_msg_append_attrv(msg, NL80211_ATTR_IE, iov, c_iov);

	netdev->connect_cmd_id = l_genl_family_send(nl80211, msg,
						netdev_cmd_ft_reassociate_cb,
						netdev, NULL);
	if (!netdev->connect_cmd_id) {
		l_genl_msg_unref(msg);

		return -EIO;
	}

	return 0;
}

static void netdev_ft_response_frame_event(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	struct netdev *netdev = user_data;

	if (!netdev->connected)
		return;

	__ft_rx_action(netdev->index, (const uint8_t *)hdr,
			mmpdu_header_len(hdr) + body_len);
}

static void netdev_ft_auth_response_frame_event(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	struct netdev *netdev = user_data;

	if (!netdev->connected)
		return;

	__ft_rx_authenticate(netdev->index, (const uint8_t *)hdr,
			mmpdu_header_len(hdr) + body_len);
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

static void netdev_preauth_cb(const uint8_t *pmk, void *user_data)
{
	struct netdev_preauth_state *preauth = user_data;
	netdev_preauthenticate_cb_t cb = preauth->cb;

	preauth->cb = NULL;

	cb(preauth->netdev,
		pmk ? NETDEV_RESULT_OK : NETDEV_RESULT_HANDSHAKE_FAILED,
		pmk, preauth->user_data);
}

int netdev_preauthenticate(struct netdev *netdev,
				const struct scan_bss *target_bss,
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
					netdev_neighbor_report_req_cb,
					netdev))
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

static int netdev_build_oci(struct netdev *netdev, uint8_t *out)
{
	out[0] = IE_TYPE_EXTENSION;
	out[1] = 4;
	out[2] = IE_TYPE_OCI & 0xff;

	return oci_from_chandef(netdev->handshake->chandef, out + 3);
}

static void netdev_sa_query_timeout(struct l_timeout *timeout,
		void *user_data)
{
	struct netdev *netdev = user_data;

	l_info("SA Query timed out, connection is invalid.  Disconnecting...");

	l_timeout_remove(netdev->sa_query_timeout);
	netdev->sa_query_timeout = NULL;

	netdev_disconnect_by_sme(netdev, NETDEV_RESULT_ABORTED,
					MMPDU_REASON_CODE_PREV_AUTH_NOT_VALID);
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

static bool netdev_send_sa_query_request(struct netdev *netdev)
{
	uint8_t req[10];
	uint8_t *ptr = req;

	ptr[0] = 0x08; /* Category: SA Query */
	ptr[1] = 0x00; /* SA Query Action: Request */

	/* Transaction ID */
	l_getrandom(ptr + 2, 2);

	ptr += 4;

	if (netdev->handshake->supplicant_ocvc &&
					netdev->handshake->authenticator_ocvc) {
		if (netdev_build_oci(netdev, ptr) < 0) {
			l_debug("Could not build OCI");
			return false;
		}

		ptr += 6;
	}

	if (!netdev_send_action_frame(netdev, netdev->handshake->aa, req,
			ptr - req, netdev->frequency,
			netdev_sa_query_req_cb, netdev)) {
		l_error("error sending SA Query action frame");
		return false;
	}

	netdev->sa_query_id = l_get_u16(req + 2);
	netdev->sa_query_timeout = l_timeout_create(3,
			netdev_sa_query_timeout, netdev, NULL);

	return true;
}

static void netdev_sa_query_req_frame_event(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	uint8_t sa_resp[10];
	uint8_t *ptr = sa_resp;
	uint16_t transaction;
	const uint8_t *oci;
	struct netdev *netdev = user_data;
	bool ocvc;

	if (body_len < 4) {
		l_debug("SA Query request too short");
		return;
	}

	if (!netdev->connected)
		return;

	ocvc = netdev->handshake->supplicant_ocvc &&
					netdev->handshake->authenticator_ocvc;

	/* only care about SA Queries from our connected AP */
	if (memcmp(hdr->address_2, netdev->handshake->aa, 6))
		return;

	transaction = l_get_u16(body + 2);

	body_len -= 4;

	if (ocvc) {
		/*
		 * IEEE 802.11 Section 11.13
		 *
		 * "A STA that supports the SA Query procedure and receives an
		 * SA Query Request frame shall respond with an SA Query
		 * Response frame if none of the following are true...
		 * - OCI element is not present in the request or
		 * - Operating channel information indicated does not match the
		 *   current channel information (see 12.2.9)."
		 */
		if (ie_parse_oci(body + 4, body_len, &oci) < 0) {
			l_debug("Could not parse OCI");
			return;
		}

		if (oci_verify(oci, netdev->handshake->chandef) < 0) {
			l_debug("Could not verify OCI");
			return;
		}
	}

	ptr[0] = 0x08;	/* SA Query */
	ptr[1] = 0x01;	/* Response */
	memcpy(ptr + 2, &transaction, 2);

	ptr += 4;

	/*
	 * IEEE 802.11 Section 11.13
	 *
	 * "A STA that responds with an SA Query Response frame to a STA that
	 * indicated OCVC capability shall include OCI element in the response
	 * frame if dot11RSNAOperatingChannelValidationActivated is true"
	 */
	if (ocvc) {
		if (netdev_build_oci(netdev, ptr) < 0) {
			l_debug("Could not build OCI");
			return;
		}

		ptr += 6;
	}

	l_info("received SA Query request from "MAC", transaction=%u",
			MAC_STR(hdr->address_2), transaction);

	if (!netdev_send_action_frame(netdev, netdev->handshake->aa,
			sa_resp, ptr - sa_resp,
			netdev->frequency,
			netdev_sa_query_resp_cb, netdev)) {
		l_error("error sending SA Query response");
		return;
	}
}

static void netdev_sa_query_resp_frame_event(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	struct netdev *netdev = user_data;
	const uint8_t *ptr = body;
	const uint8_t *oci;

	if (!netdev->connected)
		return;

	if (body_len < 4) {
		l_debug("SA Query frame too short");
		return;
	}

	ptr += 2;

	l_debug("SA Query src="MAC" dest="MAC" bssid="MAC" transaction=%u",
			MAC_STR(hdr->address_2), MAC_STR(hdr->address_1),
			MAC_STR(hdr->address_3), l_get_u16(ptr));

	if (!netdev->sa_query_timeout) {
		l_debug("no SA Query request sent");
		return;
	}

	/* check if this is from our connected BSS */
	if (memcmp(hdr->address_2, netdev->handshake->aa, 6)) {
		l_debug("received SA Query from non-connected AP");
		return;
	}

	if (memcmp(ptr, &netdev->sa_query_id, 2)) {
		l_debug("SA Query transaction ID's did not match");
		return;
	}

	if (!(netdev->handshake->supplicant_ocvc &&
				netdev->handshake->authenticator_ocvc))
		goto keep_alive;

	ptr += 2;
	body_len -= 4;

	/*
	 * IEEE 802.11 Section 11.13
	 *
	 * "When a non-AP or non-PCP STA receives the SA Query Response frame
	 * from a STA that indicated OCVC capability, it shall ensure that OCI
	 * element is present in the response and the channel information in the
	 * OCI element matches current operating channel parameters
	 * (see 12.2.9). Otherwise, the receiving STA shall deem the response
	 * as invalid and discard it"
	 */
	if (ie_parse_oci(ptr, body_len, &oci) < 0) {
		l_debug("Invalid OCI element");
		return;
	}

	if (oci_verify(oci, netdev->handshake->chandef) < 0) {
		l_debug("Could not verify OCI element");
		return;
	}

keep_alive:
	l_info("SA Query response from connected BSS received, "
			"keeping the connection active");

	l_timeout_remove(netdev->sa_query_timeout);
	netdev->sa_query_timeout = NULL;
}

static void netdev_unprot_disconnect_event(struct l_genl_msg *msg,
		struct netdev *netdev)
{
	const struct mmpdu_header *hdr = NULL;
	struct l_genl_attr attr;
	uint16_t type;
	uint16_t len;
	const void *data;
	uint16_t reason_code;

	if (!netdev->connected)
		return;

	/* ignore excessive disassociate requests */
	if (netdev->sa_query_timeout) {
		l_debug("SA Query already in progress, ignoring");
		return;
	}

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

	reason_code = l_get_le16(mmpdu_body(hdr));

	l_info("unprotected disconnect event, src="MAC" dest="MAC
			 " bssid="MAC" reason=%u",
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

	netdev_send_sa_query_request(netdev);
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

static struct netdev *netdev_from_message(struct l_genl_msg *msg)
{
	uint32_t ifindex;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_IFINDEX, &ifindex,
					NL80211_ATTR_UNSPEC) < 0)
		return NULL;

	return netdev_find(ifindex);
}

static void netdev_scan_notify(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev;

	netdev = netdev_from_message(msg);
	if (!netdev)
		return;

	switch (l_genl_msg_get_command(msg)) {
	case NL80211_CMD_NEW_SCAN_RESULTS:
		netdev_new_scan_results_event(msg, netdev);
		break;
	}
}

static bool match_addr(const void *a, const void *b)
{
	const struct scan_bss *bss = a;

	return memcmp(bss->addr, b, 6) == 0;
}

static bool netdev_get_fw_scan_cb(int err, struct l_queue *bss_list,
					const struct scan_freq_set *freqs,
					void *user_data)
{
	struct netdev *netdev = user_data;
	struct scan_bss *bss = NULL;

	/*
	 * If we happened to be disconnected prior to  GET_SCAN coming back
	 * just bail out now. This disconnect should already have been handled.
	 */
	if (!netdev->connected)
		return false;

	if (err < 0) {
		l_error("Failed to get scan after roam (%d)", err);
		return false;
	}

	/*
	 * We don't actually need the entire list since we only provide
	 * station with the roamed BSS. We can remove the BSS we want and by
	 * returning false scan will keep ownership of the list.
	 */
	bss = l_queue_remove_if(bss_list, match_addr, netdev->handshake->aa);

	if (!bss) {
		l_error("Roam target BSS not found in scan results");
		return false;
	}

	netdev->fw_roam_bss = bss;

	handshake_state_set_authenticator_ie(netdev->handshake, bss->rsne);

	if (is_offload(netdev->handshake)) {
		netdev_connect_ok(netdev);
		return false;
	}

	if (netdev->sm)
		L_WARN_ON(!eapol_start(netdev->sm));

	return false;
}

/*
 * CMD_ROAM indicates that the driver has already roamed/associated with a new
 * AP. This event is nearly identical to the CMD_CONNECT event which is why
 * netdev_connect_event will handle all the parsing of IE's just as it does
 * normally.
 *
 * Using GET_SCAN we can grab all the required scan_bss data, create that object
 * and provide it to station.
 *
 * The current handshake/netdev_handshake objects are reused after being
 * reset to allow eapol to happen again without it thinking this is a re-key.
 */
static void netdev_roam_event(struct l_genl_msg *msg, struct netdev *netdev)
{
	struct netdev_handshake_state *nhs =
			l_container_of(netdev->handshake,
					struct netdev_handshake_state,
					super);
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint8_t *mac = NULL;

	l_debug("");

	netdev->operational = false;

	if (L_WARN_ON(!l_genl_attr_init(&attr, msg)))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_MAC:
			mac = data;
			break;
		case NL80211_ATTR_REQ_IE:
			parse_request_ies(netdev, data, len);
			break;
		}
	}

	if (!mac) {
		l_error("Failed to parse ATTR_MAC from CMD_ROAM");
		return;
	}

	/* Handshake completed in firmware, just get the roamed BSS */
	if (is_offload(netdev->handshake))
		goto get_fw_scan;

	/* Reset handshake state */
	nhs->complete = false;
	nhs->ptk_installed = false;
	nhs->gtk_installed = true;
	nhs->igtk_installed = true;
	netdev->handshake->ptk_complete = false;

get_fw_scan:
	handshake_state_set_authenticator_address(netdev->handshake, mac);

	if (L_WARN_ON(!scan_get_firmware_scan(netdev->wdev_id,
					netdev_get_fw_scan_cb,
					netdev, NULL)))
		return;

	if (netdev->event_filter)
		netdev->event_filter(netdev, NETDEV_EVENT_ROAMING,
					NULL, netdev->user_data);
}

static void netdev_send_sa_query_delay(struct l_timeout *timeout,
					void *user_data)
{
	struct netdev *netdev = user_data;

	netdev_send_sa_query_request(netdev);

	l_timeout_remove(netdev->sa_query_delay);
	netdev->sa_query_delay = NULL;
}

static void netdev_channel_switch_event(struct l_genl_msg *msg,
					struct netdev *netdev)
{
	_auto_(l_free) struct band_chandef *chandef = NULL;

	if (netdev->type != NL80211_IFTYPE_STATION)
		return;

	chandef = l_new(struct band_chandef, 1);

	if (nl80211_parse_chandef(msg, chandef) < 0) {
		l_debug("Couldn't parse operating channel info.");
		return;
	}

	netdev->frequency = chandef->frequency;

	l_debug("Channel switch event, frequency: %u", netdev->frequency);

	handshake_state_set_chandef(netdev->handshake, l_steal_ptr(chandef));

	/*
	 * IEEE 802.11-2020 11.9.3.2
	 * "If the STA chooses to perform the specified switch and
	 * dot11RSNAOperatingChannelValidationActivated is true and the AP has
	 * indicated OCVC capability, after switching to the new channel the STA
	 * shall wait a random delay uniformly-distributed in the range between
	 * zero and 5000us, and then initiate the SA query procedure"
	 */
	if (netdev->handshake->supplicant_ocvc &&
					netdev->handshake->authenticator_ocvc)
		netdev->sa_query_delay = l_timeout_create_ms(
						l_getrandom_uint32() % 5,
						netdev_send_sa_query_delay,
						netdev, NULL);

	if (!netdev->event_filter)
		return;

	netdev->event_filter(netdev, NETDEV_EVENT_CHANNEL_SWITCHED,
				&netdev->frequency, netdev->user_data);
}

static void netdev_michael_mic_failure(struct l_genl_msg *msg,
					struct netdev *netdev)
{
	uint8_t idx;
	uint32_t type;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_KEY_IDX, &idx,
				NL80211_ATTR_KEY_TYPE, &type,
				NL80211_ATTR_UNSPEC) < 0)
		return;

	l_debug("ifindex=%u key_idx=%u type=%u", netdev->index, idx, type);
}

static void netdev_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = NULL;
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);
	l_debug("MLME notification %s(%u)", nl80211cmd_to_string(cmd), cmd);

	netdev = netdev_from_message(msg);
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
	case NL80211_CMD_ROAM:
		netdev_roam_event(msg, netdev);
		break;
	case NL80211_CMD_CH_SWITCH_NOTIFY:
		netdev_channel_switch_event(msg, netdev);
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
	case NL80211_CMD_MICHAEL_MIC_FAILURE:
		netdev_michael_mic_failure(msg, netdev);
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

	l_debug("Unicast notification %s(%u)", nl80211cmd_to_string(cmd), cmd);

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
	netdev->rssi_levels_num = levels_num;

	if (levels_num) {
		memcpy(netdev->rssi_levels, levels, levels_num);

		if (netdev->connected)
			netdev_set_rssi_level_idx(netdev);
	}

	netdev_rssi_polling_update(netdev);

	return 0;
}

static void netdev_get_station_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	struct l_genl_attr attr, nested;
	uint16_t type, len;
	const void *data;
	struct diagnostic_station_info info;

	netdev->get_station_cmd_id = 0;

	if (!l_genl_attr_init(&attr, msg))
		goto parse_error;

	memset(&info, 0, sizeof(info));

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_STA_INFO:
			if (!l_genl_attr_recurse(&attr, &nested))
				goto parse_error;

			if (!netdev_parse_sta_info(&nested, &info))
				goto parse_error;

			break;

		case NL80211_ATTR_MAC:
			if (len != 6)
				goto parse_error;

			memcpy(info.addr, data, 6);

			break;
		}
	}

	if (netdev->get_station_cb)
		netdev->get_station_cb(&info, netdev->get_station_data);

	return;

parse_error:
	if (netdev->get_station_cb)
		netdev->get_station_cb(NULL, netdev->get_station_data);
}

static void netdev_get_station_destroy(void *user_data)
{
	struct netdev *netdev = user_data;

	netdev->get_station_cmd_id = 0;

	if (netdev->get_station_destroy)
		netdev->get_station_destroy(netdev->get_station_data);
}

int netdev_get_station(struct netdev *netdev, const uint8_t *mac,
			netdev_get_station_cb_t cb, void *user_data,
			netdev_destroy_func_t destroy)
{
	struct l_genl_msg *msg;

	if (netdev->get_station_cmd_id)
		return -EBUSY;

	msg = l_genl_msg_new_sized(NL80211_CMD_GET_STATION, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, ETH_ALEN, mac);

	netdev->get_station_cmd_id = l_genl_family_send(nl80211, msg,
						netdev_get_station_cb, netdev,
						netdev_get_station_destroy);
	if (!netdev->get_station_cmd_id) {
		l_genl_msg_unref(msg);
		return -EIO;
	}

	netdev->get_station_cb = cb;
	netdev->get_station_data = user_data;
	netdev->get_station_destroy = destroy;

	return 0;
}

int netdev_get_current_station(struct netdev *netdev,
			netdev_get_station_cb_t cb, void *user_data,
			netdev_destroy_func_t destroy)
{
	if (!netdev->handshake)
		return -ENOTCONN;

	return netdev_get_station(netdev, netdev->handshake->aa, cb,
					user_data, destroy);
}

int netdev_get_all_stations(struct netdev *netdev, netdev_get_station_cb_t cb,
				void *user_data, netdev_destroy_func_t destroy)
{
	struct l_genl_msg *msg;

	if (netdev->get_station_cmd_id)
		return -EBUSY;

	msg = l_genl_msg_new_sized(NL80211_CMD_GET_STATION, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);

	netdev->get_station_cmd_id = l_genl_family_dump(nl80211, msg,
						netdev_get_station_cb, netdev,
						netdev_get_station_destroy);
	if (!netdev->get_station_cmd_id) {
		l_genl_msg_unref(msg);
		return -EIO;
	}

	netdev->get_station_cb = cb;
	netdev->get_station_data = user_data;
	netdev->get_station_destroy = destroy;

	return 0;
}

static void netdev_add_station_frame_watches(struct netdev *netdev)
{
	static const uint8_t action_neighbor_report_prefix[2] = { 0x05, 0x05 };
	static const uint8_t action_sa_query_resp_prefix[2] = { 0x08, 0x01 };
	static const uint8_t action_sa_query_req_prefix[2] = { 0x08, 0x00 };
	static const uint8_t action_ft_response_prefix[] =  { 0x06, 0x02 };
	static const uint8_t auth_ft_response_prefix[] = { 0x02, 0x00 };
	static const uint8_t action_qos_map_prefix[] = { 0x01, 0x04 };
	uint64_t wdev = netdev->wdev_id;

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

	frame_watch_add(wdev, 0, 0x00b0, auth_ft_response_prefix,
			sizeof(auth_ft_response_prefix),
			netdev_ft_auth_response_frame_event, netdev, NULL);

	if (wiphy_supports_qos_set_map(netdev->wiphy))
		frame_watch_add(wdev, 0, 0x00d0, action_qos_map_prefix,
				sizeof(action_qos_map_prefix),
				netdev_qos_map_frame_event, netdev, NULL);
}

static void netdev_setup_interface(struct netdev *netdev)
{
	switch (netdev->type) {
	case NL80211_IFTYPE_STATION:
		netdev_add_station_frame_watches(netdev);
		break;
	default:
		break;
	}
}

static void netdev_set_interface_event(struct l_genl_msg *msg,
							struct netdev *netdev)
{
	uint32_t iftype;
	uint64_t wdev_id;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_IFTYPE, &iftype,
					NL80211_ATTR_WDEV, &wdev_id,
					NL80211_ATTR_UNSPEC) < 0)
		return;

	if (iftype == netdev->type)
		return;

	l_debug("Interface type changed from %s to %s",
			netdev_iftype_to_string(netdev->type),
			netdev_iftype_to_string(iftype));
	netdev->type = iftype;
	frame_watch_wdev_remove(wdev_id);

	netdev_setup_interface(netdev);

	WATCHLIST_NOTIFY(&netdev_watches, netdev_watch_func_t,
				netdev, NETDEV_WATCH_EVENT_IFTYPE_CHANGE);
}

static void netdev_config_notify(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev;

	netdev = netdev_from_message(msg);
	if (!netdev)
		return;

	switch (l_genl_msg_get_command(msg)) {
	case NL80211_CMD_SET_INTERFACE:
		netdev_set_interface_event(msg, netdev);
		break;
	}
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
	uint8_t *operstate = NULL;
	uint8_t *linkmode = NULL;

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
		case IFLA_OPERSTATE:
			operstate = RTA_DATA(attr);
			break;
		case IFLA_LINKMODE:
			linkmode = RTA_DATA(attr);
			break;
		}
	}

	if (!netdev->events_ready) /* Did we send NETDEV_WATCH_EVENT_NEW yet? */
		return;

	/*
	 * Sometimes the driver sends the Association / Connect event on the
	 * nl80211 interface before the driver is ready to accept IF_OPER_UP
	 * setting on the rtnl interface.  This results in our initial
	 * IF_OPER_UP setting being ignored.  In this case the driver will
	 * send a New Link event with a stale OperState.  Detect this case and
	 * try to re-set IF_OPER_UP.
	 */
	if (linkmode && *linkmode == 1 &&
			operstate && *operstate == IF_OPER_DORMANT &&
			netdev->operational) {
		l_debug("Retrying setting OperState to IF_OPER_UP");
		l_rtnl_set_linkmode_and_operstate(rtnl, netdev->index,
					IF_LINK_MODE_DORMANT, IF_OPER_UP,
					netdev_operstate_cb,
					L_UINT_TO_PTR(netdev->index), NULL);
	}

	new_up = netdev_get_is_up(netdev);

	if (!new_up)
		netdev_connect_free(netdev);

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

static void netdev_disable_ps_cb(struct l_genl_msg *msg, void *user_data)
{
	struct netdev *netdev = user_data;
	int err = l_genl_msg_get_error(msg);

	netdev->power_save_cmd_id = 0;

	/* Can't do anything about it but inform the user */
	if (err < 0)
		l_error("Failed to disable power save for ifindex %u (%s: %d)",
				netdev->index, strerror(-err), err);
	else
		l_debug("Disabled power save for ifindex %u", netdev->index);

	WATCHLIST_NOTIFY(&netdev_watches, netdev_watch_func_t,
				netdev, NETDEV_WATCH_EVENT_NEW);
	netdev->events_ready = true;
}

static bool netdev_disable_power_save(struct netdev *netdev)
{
	struct l_genl_msg *msg = l_genl_msg_new(NL80211_CMD_SET_POWER_SAVE);
	uint32_t disabled = NL80211_PS_DISABLED;

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &netdev->index);
	l_genl_msg_append_attr(msg, NL80211_ATTR_PS_STATE, 4, &disabled);

	netdev->power_save_cmd_id = l_genl_family_send(nl80211, msg,
							netdev_disable_ps_cb,
							netdev, NULL);
	if (!netdev->power_save_cmd_id) {
		l_error("Failed to send SET_POWER_SAVE (-EIO)");
		return false;
	}

	return true;
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

	if (wiphy_power_save_disabled(netdev->wiphy)) {
		/* Wait to issue EVENT_NEW until power save is disabled */
		if (netdev_disable_power_save(netdev))
			return;
	}

	WATCHLIST_NOTIFY(&netdev_watches, netdev_watch_func_t,
				netdev, NETDEV_WATCH_EVENT_NEW);
	netdev->events_ready = true;
}

static bool netdev_check_set_mac(struct netdev *netdev)
{
	if (l_memeqzero(netdev->set_mac_once, 6))
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
	struct netdev *netdev = user_data;
	const struct ifinfomsg *ifi = data;
	unsigned int bytes;
	l_netlink_command_func_t cb;
	bool powered;

	netdev->get_link_cmd_id = 0;

	if (error != 0) {
		l_error("RTM_GETLINK error %i: %s", error, strerror(-error));
		return;
	}

	if (ifi->ifi_type != ARPHRD_ETHER || type != RTM_NEWLINK) {
		l_debug("Non-ethernet address or not newlink message -- "
			"ifi_type: %i, type: %i", ifi->ifi_type, type);
		return;
	}

	if (L_WARN_ON((uint32_t)ifi->ifi_index != netdev->index))
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

static void netdev_get_link(struct netdev *netdev)
{
	struct ifinfomsg *rtmmsg;
	size_t bufsize;

	/* Query interface flags */
	bufsize = NLMSG_ALIGN(sizeof(struct ifinfomsg));
	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->ifi_family = AF_UNSPEC;
	rtmmsg->ifi_index = netdev->index;

	netdev->get_link_cmd_id = l_netlink_send(rtnl, RTM_GETLINK, 0, rtmmsg,
						bufsize, netdev_getlink_cb,
						netdev, NULL);
	L_WARN_ON(netdev->get_link_cmd_id == 0);

	l_free(rtmmsg);
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

	if (!wiphy_control_port_enabled(wiphy)) {
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

	netdev_setup_interface(netdev);

	netdev_get_link(netdev);

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

	rtnl = iwd_get_rtnl();

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

	if (!l_settings_get_int(settings, "General", "RoamThreshold5G",
					&LOW_SIGNAL_THRESHOLD_5GHZ))
		LOW_SIGNAL_THRESHOLD_5GHZ = -76;

	rand_addr_str = l_settings_get_value(settings, "General",
						"AddressRandomization");
	if (rand_addr_str && !strcmp(rand_addr_str, "network"))
		mac_per_ssid = true;

	watchlist_init(&netdev_watches, NULL);
	netdev_list = l_queue_new();

	__handshake_set_install_tk_func(netdev_set_tk);
	__handshake_set_install_gtk_func(netdev_set_gtk);
	__handshake_set_install_igtk_func(netdev_set_igtk);
	__handshake_set_install_ext_tk_func(netdev_set_ext_tk);

	__eapol_set_rekey_offload_func(netdev_set_rekey_offload);
	__eapol_set_tx_packet_func(netdev_control_port_frame);
	__eapol_set_install_pmk_func(netdev_set_pmk);

	__ft_set_tx_frame_func(netdev_tx_ft_frame);

	unicast_watch = l_genl_add_unicast_watch(genl, NL80211_GENL_NAME,
						netdev_unicast_notify,
						NULL, NULL);
	if (!unicast_watch)
		l_error("Registering for unicast notification failed");

	if (!l_genl_family_register(nl80211, "mlme", netdev_mlme_notify,
								NULL, NULL))
		l_error("Registering for MLME notification failed");

	if (!l_genl_family_register(nl80211, "scan", netdev_scan_notify,
								NULL, NULL))
		l_error("Registering for scan notifications failed");

	if (!l_genl_family_register(nl80211, "config", netdev_config_notify,
								NULL, NULL))
		l_error("Registering for config notifications failed");

	return 0;

fail_netlink:
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
	l_queue_destroy(netdev_list, netdev_free);
	netdev_list = NULL;

	l_genl_family_free(nl80211);
	nl80211 = NULL;

	rtnl = NULL;
}

void netdev_shutdown(void)
{
	struct netdev *netdev;

	if (!rtnl)
		return;

	l_queue_foreach(netdev_list, netdev_shutdown_one, NULL);

	while ((netdev = l_queue_peek_head(netdev_list))) {
		netdev_free(netdev);
		l_queue_pop_head(netdev_list);
	}
}

IWD_MODULE(netdev, netdev_init, netdev_exit);
IWD_MODULE_DEPENDS(netdev, eapol);
IWD_MODULE_DEPENDS(netdev, frame_xchg);
IWD_MODULE_DEPENDS(netdev, wiphy);
IWD_MODULE_DEPENDS(netdev, ft);
