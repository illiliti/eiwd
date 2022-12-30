/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "ell/useful.h"
#include "src/missing.h"
#include "src/iwd.h"
#include "src/module.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/crypto.h"
#include "src/ie.h"
#include "src/mpdu.h"
#include "src/util.h"
#include "src/eapol.h"
#include "src/handshake.h"
#include "src/dbus.h"
#include "src/nl80211util.h"
#include "src/frame-xchg.h"
#include "src/wscutil.h"
#include "src/eap-wsc.h"
#include "src/ip-pool.h"
#include "src/netconfig.h"
#include "src/ap.h"
#include "src/storage.h"
#include "src/diagnostic.h"
#include "src/band.h"
#include "src/common.h"

struct ap_state {
	struct netdev *netdev;
	struct l_genl_family *nl80211;
	const struct ap_ops *ops;
	ap_stopped_func_t stopped_func;
	void *user_data;

	char ssid[33];
	char passphrase[64];
	uint8_t psk[32];
	enum band_freq band;
	uint8_t channel;
	struct band_chandef chandef;
	uint8_t *authorized_macs;
	unsigned int authorized_macs_num;
	char wsc_name[33];
	struct wsc_primary_device_type wsc_primary_device_type;

	unsigned int ciphers;
	enum ie_rsn_cipher_suite group_cipher;
	uint32_t beacon_interval;
	struct l_uintset *rates;
	uint32_t start_stop_cmd_id;
	uint32_t mlme_watch;
	uint8_t gtk[CRYPTO_MAX_GTK_LEN];
	uint8_t gtk_index;
	struct l_queue *wsc_pbc_probes;
	struct l_timeout *wsc_pbc_timeout;
	uint16_t wsc_dpid;
	uint8_t wsc_uuid_r[16];

	uint16_t last_aid;
	struct l_queue *sta_states;

	struct l_dhcp_server *netconfig_dhcp;
	struct l_rtnl_address *netconfig_addr4;
	uint32_t rtnl_add_cmd;
	uint32_t rtnl_get_gateway4_mac_cmd;
	uint32_t rtnl_get_dns4_mac_cmd;
	uint8_t netconfig_gateway4_mac[6];
	uint8_t netconfig_dns4_mac[6];

	uint32_t scan_id;
	struct l_dbus_message *scan_pending;
	struct l_queue *networks;

	bool started : 1;
	bool gtk_set : 1;
	bool netconfig_set_addr4 : 1;
	bool in_event : 1;
	bool free_pending : 1;
	bool scanning : 1;
	bool supports_ht : 1;
};

struct sta_state {
	uint8_t addr[6];
	bool associated;
	bool rsna;
	uint16_t aid;
	struct mmpdu_field_capability capability;
	uint16_t listen_interval;
	struct l_uintset *rates;
	uint32_t assoc_resp_cmd_id;
	struct ap_state *ap;
	uint8_t *assoc_ies;
	size_t assoc_ies_len;
	uint8_t *assoc_rsne;
	struct eapol_sm *sm;
	struct handshake_state *hs;
	uint32_t gtk_query_cmd_id;
	struct l_idle *stop_handshake_work;
	struct l_settings *wsc_settings;
	uint8_t wsc_uuid_e[16];
	bool wsc_v2;
	struct l_dhcp_lease *ip_alloc_lease;
	bool ip_alloc_sent;

	bool ht_support : 1;
	bool ht_greenfield : 1;
};

struct ap_wsc_pbc_probe_record {
	uint8_t mac[6];
	uint8_t uuid_e[16];
	uint64_t timestamp;
};

struct ap_network {
	char ssid[33];
	int16_t signal;
	enum security security;
};

static char **global_addr4_strs;
static uint32_t netdev_watch;
static struct l_netlink *rtnl;

static bool network_match_ssid(const void *a, const void *b)
{
	const struct ap_network *network = a;
	const char *ssid = b;

	return !strcmp(network->ssid, ssid);
}

static int network_signal_compare(const void *a, const void *b, void *user)
{
	const struct ap_network *new_network = a;
	const struct ap_network *network = b;

	return (network->signal > new_network->signal) ? 1 : -1;
}

static struct ap_network *ap_network_find(struct ap_state *ap,
						struct scan_bss *bss)
{
	char ssid[33];

	memcpy(ssid, bss->ssid, bss->ssid_len);
	ssid[bss->ssid_len] = '\0';

	return l_queue_find(ap->networks, network_match_ssid, ssid);
}

static void ap_network_append(struct ap_state *ap, struct scan_bss *bss)
{
	struct ap_network *network;
	enum security security;

	if (util_ssid_is_hidden(bss->ssid_len, bss->ssid))
		return;

	network = ap_network_find(ap, bss);
	if (!network) {
		if (scan_bss_get_security(bss, &security) < 0)
			return;

		network = l_new(struct ap_network, 1);
		network->signal = bss->signal_strength;
		network->security = security;

		memcpy(network->ssid, bss->ssid, bss->ssid_len);
		network->ssid[bss->ssid_len] = '\0';

		goto insert;
	}

	if (bss->signal_strength <= network->signal)
		return;

	l_queue_remove(ap->networks, network);
	network->signal = bss->signal_strength;

insert:
	l_queue_insert(ap->networks, network, network_signal_compare, NULL);
}

static void ap_stop_handshake(struct sta_state *sta)
{
	if (sta->sm) {
		eapol_sm_free(sta->sm);
		sta->sm = NULL;
	}

	if (sta->hs) {
		handshake_state_free(sta->hs);
		sta->hs = NULL;
	}

	if (sta->wsc_settings) {
		l_settings_free(sta->wsc_settings);
		sta->wsc_settings = NULL;
	}

	if (sta->stop_handshake_work) {
		l_idle_remove(sta->stop_handshake_work);
		sta->stop_handshake_work = NULL;
	}
}

static void ap_stop_handshake_work(struct l_idle *idle, void *user_data)
{
	struct sta_state *sta = user_data;

	ap_stop_handshake(sta);
}

static void ap_sta_free(void *data)
{
	struct sta_state *sta = data;
	struct ap_state *ap = sta->ap;

	if (sta->rates)
		l_uintset_free(sta->rates);

	l_free(sta->assoc_ies);

	if (sta->assoc_resp_cmd_id)
		l_genl_family_cancel(ap->nl80211, sta->assoc_resp_cmd_id);

	if (sta->gtk_query_cmd_id)
		l_genl_family_cancel(ap->nl80211, sta->gtk_query_cmd_id);

	if (sta->ip_alloc_lease && ap->netconfig_dhcp)
		l_dhcp_server_lease_remove(ap->netconfig_dhcp,
						sta->ip_alloc_lease);

	ap_stop_handshake(sta);

	l_free(sta);
}

static void ap_reset(struct ap_state *ap)
{
	struct netdev *netdev = ap->netdev;

	explicit_bzero(ap->passphrase, sizeof(ap->passphrase));
	explicit_bzero(ap->psk, sizeof(ap->psk));

	if (ap->authorized_macs_num) {
		l_free(ap->authorized_macs);
		ap->authorized_macs_num = 0;
	}

	if (ap->mlme_watch) {
		l_genl_family_unregister(ap->nl80211, ap->mlme_watch);
		ap->mlme_watch = 0;
	}

	frame_watch_wdev_remove(netdev_get_wdev_id(netdev));

	if (ap->start_stop_cmd_id) {
		l_genl_family_cancel(ap->nl80211, ap->start_stop_cmd_id);
		ap->start_stop_cmd_id = 0;
	}

	if (ap->rtnl_add_cmd) {
		l_netlink_cancel(rtnl, ap->rtnl_add_cmd);
		ap->rtnl_add_cmd = 0;
	}

	if (ap->rtnl_get_gateway4_mac_cmd) {
		l_netlink_cancel(rtnl, ap->rtnl_get_gateway4_mac_cmd);
		ap->rtnl_get_gateway4_mac_cmd = 0;
	}

	if (ap->rtnl_get_dns4_mac_cmd) {
		l_netlink_cancel(rtnl, ap->rtnl_get_dns4_mac_cmd);
		ap->rtnl_get_dns4_mac_cmd = 0;
	}

	l_queue_destroy(l_steal_ptr(ap->sta_states), ap_sta_free);

	if (ap->rates)
		l_uintset_free(l_steal_ptr(ap->rates));

	l_queue_destroy(l_steal_ptr(ap->wsc_pbc_probes), l_free);
	l_timeout_remove(ap->wsc_pbc_timeout);

	ap->started = false;

	/* Delete IP if one was set by IWD */
	if (ap->netconfig_set_addr4) {
		l_rtnl_ifaddr_delete(rtnl, netdev_get_ifindex(netdev),
					ap->netconfig_addr4, NULL, NULL, NULL);
		ap->netconfig_set_addr4 = false;
	}

	l_rtnl_address_free(l_steal_ptr(ap->netconfig_addr4));

	if (ap->netconfig_dhcp) {
		l_dhcp_server_destroy(ap->netconfig_dhcp);
		ap->netconfig_dhcp = NULL;
	}

	if (ap->scan_id) {
		scan_cancel(netdev_get_wdev_id(ap->netdev), ap->scan_id);
		ap->scan_id = 0;
	}

	if (ap->networks) {
		l_queue_destroy(ap->networks, l_free);
		ap->networks = NULL;
	}
}

static bool ap_event_done(struct ap_state *ap, bool prev_in_event)
{
	ap->in_event = prev_in_event;

	if (!prev_in_event && ap->free_pending) {
		l_genl_family_free(ap->nl80211);
		l_free(ap);
		return true;
	}

	return ap->free_pending;
}

/*
 * Returns true if the AP is considered freed and the caller must avoid
 * accessing @ap.
 */
static bool ap_event(struct ap_state *ap, enum ap_event_type event,
			const void *event_data)
{
	bool prev = ap->in_event;

	if (ap->free_pending)
		return true;

	ap->in_event = true;
	ap->ops->handle_event(event, event_data, ap->user_data);
	return ap_event_done(ap, prev);
}

static void ap_del_station(struct sta_state *sta, uint16_t reason,
				bool disassociate)
{
	struct ap_state *ap = sta->ap;
	struct ap_event_station_removed_data event_data;
	bool send_event = false;

	netdev_del_station(ap->netdev, sta->addr, reason, disassociate);
	sta->associated = false;

	if (sta->rsna) {
		if (ap->ops->handle_event) {
			memset(&event_data, 0, sizeof(event_data));
			event_data.mac = sta->addr;
			event_data.reason = reason;
			send_event = true;
		}

		sta->rsna = false;
	}

	if (sta->assoc_resp_cmd_id) {
		l_genl_family_cancel(ap->nl80211, sta->assoc_resp_cmd_id);
		sta->assoc_resp_cmd_id = 0;
	}

	if (sta->gtk_query_cmd_id) {
		l_genl_family_cancel(ap->nl80211, sta->gtk_query_cmd_id);
		sta->gtk_query_cmd_id = 0;
	}

	ap_stop_handshake(sta);

	/*
	 * If the event handler tears the AP down, we've made sure above that
	 * a subsequent ap_sta_free(sta) has no need to access sta->ap.
	 */
	if (send_event)
		if (ap_event(ap, AP_EVENT_STATION_REMOVED, &event_data))
			return;

	/*
	 * Expire any DHCP leases owned by this client when it disconnects to
	 * make it harder for somebody to DoS the IP pool.  If the client
	 * comes back and the lease is still in the expired leases list they
	 * will get their IP back.
	 */
	if (ap->netconfig_dhcp) {
		bool prev = ap->in_event;

		/*
		 * If the LEASE_EXPIRED event in ap_dhcp_event_cb triggers an
		 * ap_free(), delay cleanup to avoid destroying the DHCP
		 * server midway through l_dhcp_server_expire_by_mac().
		 */
		ap->in_event = true;

		sta->ip_alloc_lease = NULL;
		l_dhcp_server_expire_by_mac(ap->netconfig_dhcp, sta->addr);

		ap_event_done(ap, prev);
	}
}

static bool ap_sta_match_addr(const void *a, const void *b)
{
	const struct sta_state *sta = a;

	return !memcmp(sta->addr, b, 6);
}

static void ap_remove_sta(struct sta_state *sta)
{
	if (!l_queue_remove(sta->ap->sta_states, sta)) {
		l_error("tried to remove station that doesn't exist");
		return;
	}

	ap_sta_free(sta);
}

static void ap_set_sta_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("SET_STATION failed: %i", l_genl_msg_get_error(msg));
}

static void ap_del_key_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_debug("DEL_KEY failed: %i", l_genl_msg_get_error(msg));
}

static void ap_new_rsna(struct sta_state *sta)
{
	struct ap_state *ap = sta->ap;
	struct ap_event_station_added_data event_data = {};

	l_debug("STA "MAC" authenticated", MAC_STR(sta->addr));

	sta->rsna = true;

	event_data.mac = sta->addr;
	event_data.assoc_ies = sta->assoc_ies;
	event_data.assoc_ies_len = sta->assoc_ies_len;
	ap_event(ap, AP_EVENT_STATION_ADDED, &event_data);
}

static void ap_drop_rsna(struct sta_state *sta)
{
	struct ap_state *ap = sta->ap;
	struct l_genl_msg *msg;
	uint32_t ifindex = netdev_get_ifindex(sta->ap->netdev);
	uint8_t key_id = 0;
	struct ap_event_station_removed_data event_data = {};

	sta->rsna = false;

	msg = nl80211_build_set_station_unauthorized(ifindex, sta->addr);

	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_AID, 2, &sta->aid);

	if (!l_genl_family_send(ap->nl80211, msg, ap_set_sta_cb, NULL, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Issuing SET_STATION failed");
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_DEL_KEY, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta->addr);

	if (!l_genl_family_send(ap->nl80211, msg, ap_del_key_cb, NULL, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Issuing DEL_KEY failed");
	}

	ap_stop_handshake(sta);

	event_data.mac = sta->addr;
	ap_event(ap, AP_EVENT_STATION_REMOVED, &event_data);
}

static void ap_set_rsn_info(struct ap_state *ap, struct ie_rsn_info *rsn)
{
	memset(rsn, 0, sizeof(*rsn));
	rsn->akm_suites = IE_RSN_AKM_SUITE_PSK;
	rsn->pairwise_ciphers = ap->ciphers;
	rsn->group_cipher = ap->group_cipher;
}

static void ap_wsc_exit_pbc(struct ap_state *ap)
{
	if (!ap->wsc_pbc_timeout)
		return;

	l_timeout_remove(ap->wsc_pbc_timeout);
	ap->wsc_dpid = 0;
	ap_update_beacon(ap);

	ap_event(ap, AP_EVENT_PBC_MODE_EXIT, NULL);
}

struct ap_pbc_record_expiry_data {
	uint64_t min_time;
	const uint8_t *mac;
};

static bool ap_wsc_pbc_record_expire(void *data, void *user_data)
{
	struct ap_wsc_pbc_probe_record *record = data;
	const struct ap_pbc_record_expiry_data *expiry_data = user_data;

	if (record->timestamp > expiry_data->min_time &&
			memcmp(record->mac, expiry_data->mac, 6))
		return false;

	l_free(record);
	return true;
}

#define AP_WSC_PBC_MONITOR_TIME	120
#define AP_WSC_PBC_WALK_TIME	120

static void ap_process_wsc_probe_req(struct ap_state *ap, const uint8_t *from,
					const uint8_t *wsc_data,
					size_t wsc_data_len)
{
	struct wsc_probe_request req;
	struct ap_pbc_record_expiry_data expiry_data;
	struct ap_wsc_pbc_probe_record *record;
	uint64_t now;
	bool empty;
	uint8_t first_sta_addr[6] = {};
	const struct l_queue_entry *entry;

	if (wsc_parse_probe_request(wsc_data, wsc_data_len, &req) < 0)
		return;

	if (!(req.config_methods & WSC_CONFIGURATION_METHOD_PUSH_BUTTON))
		return;

	if (req.device_password_id != WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON)
		return;

	/* Save the address of the first enrollee record */
	record = l_queue_peek_head(ap->wsc_pbc_probes);
	if (record)
		memcpy(first_sta_addr, record->mac, 6);

	now = l_time_now();

	/*
	 * Expire entries older than PBC Monitor Time.  While there also drop
	 * older entries from the same Enrollee that sent us this new Probe
	 * Request.  It's unclear whether we should also match by the UUID-E.
	 */
	expiry_data.min_time = now - AP_WSC_PBC_MONITOR_TIME * 1000000;
	expiry_data.mac = from;
	l_queue_foreach_remove(ap->wsc_pbc_probes, ap_wsc_pbc_record_expire,
				&expiry_data);

	empty = l_queue_isempty(ap->wsc_pbc_probes);

	if (!ap->wsc_pbc_probes)
		ap->wsc_pbc_probes = l_queue_new();

	/* Add new record */
	record = l_new(struct ap_wsc_pbc_probe_record, 1);
	memcpy(record->mac, from, 6);
	memcpy(record->uuid_e, req.uuid_e, sizeof(record->uuid_e));
	record->timestamp = now;
	l_queue_push_tail(ap->wsc_pbc_probes, record);

	/*
	 * If queue was non-empty and we've added one more record then we
	 * now have seen more than one PBC enrollee during the PBC Monitor
	 * Time and must exit "active PBC mode" due to "session overlap".
	 * WSC v2.0.5 Section 11.3:
	 * "Within the PBC Monitor Time, if the Registrar receives PBC
	 * probe requests from more than one Enrollee [...] then the
	 * Registrar SHALL signal a "session overlap" error.  As a result,
	 * the Registrar shall refuse to enter active PBC mode and shall
	 * also refuse to perform a PBC-based Registration Protocol
	 * exchange [...]"
	 */
	if (empty)
		return;

	if (ap->wsc_pbc_timeout) {
		l_debug("Exiting PBC mode due to Session Overlap");
		ap_wsc_exit_pbc(ap);
	}

	/*
	 * "If the Registrar is engaged in PBC Registration Protocol
	 * exchange with an Enrollee and receives a Probe Request or M1
	 * Message from another Enrollee, then the Registrar should
	 * signal a "session overlap" error".
	 *
	 * For simplicity just interrupt the handshake with that enrollee.
	 */
	for (entry = l_queue_get_entries(ap->sta_states); entry;
			entry = entry->next) {
		struct sta_state *sta = entry->data;

		if (!sta->associated || sta->assoc_rsne)
			continue;

		/*
		 * Check whether this enrollee is in PBC Registration
		 * Protocol by comparing its mac with the first (and only)
		 * record we had in ap->wsc_pbc_probes.  If we had more
		 * than one record we wouldn't have been in
		 * "active PBC mode".
		 */
		if (memcmp(sta->addr, first_sta_addr, 6) ||
				!memcmp(sta->addr, from, 6))
			continue;

		l_debug("Interrupting handshake with %s due to Session Overlap",
			util_address_to_string(sta->addr));

		if (sta->hs) {
			netdev_handshake_failed(sta->hs,
					MMPDU_REASON_CODE_DISASSOC_AP_BUSY);
			sta->sm = NULL;
		}

		ap_remove_sta(sta);
	}
}

static void ap_write_authorized_macs(struct ap_state *ap,
					size_t out_len, uint8_t *out)
{
	size_t len = ap->authorized_macs_num * 6;

	if (!len)
		return;

	if (len > out_len)
		len = out_len;

	memcpy(out, ap->authorized_macs, len);
}

static size_t ap_get_wsc_ie_len(struct ap_state *ap,
				enum mpdu_management_subtype type,
				const struct mmpdu_header *client_frame,
				size_t client_frame_len)
{
	return 256;
}

static size_t ap_write_wsc_ie(struct ap_state *ap,
				enum mpdu_management_subtype type,
				const struct mmpdu_header *client_frame,
				size_t client_frame_len,
				uint8_t *out_buf)
{
	uint8_t *wsc_data;
	size_t wsc_data_size;
	uint8_t *wsc_ie;
	size_t wsc_ie_size;
	size_t len = 0;

	/* WSC IE */
	if (type == MPDU_MANAGEMENT_SUBTYPE_PROBE_RESPONSE && client_frame) {
		const uint8_t *from = client_frame->address_2;
		struct wsc_probe_response wsc_pr = {};
		const struct mmpdu_probe_request *req =
			mmpdu_body(client_frame);
		size_t req_ies_len = (void *) client_frame + client_frame_len -
			(void *) req->ies;
		ssize_t req_wsc_data_size;

		/*
		 * Process the client Probe Request WSC IE first as it may
		 * cause us to exit "active PBC mode" and that will be
		 * immediately reflected in our Probe Response WSC IE.
		 */
		wsc_data = ie_tlv_extract_wsc_payload(req->ies, req_ies_len,
							&req_wsc_data_size);
		if (wsc_data) {
			ap_process_wsc_probe_req(ap, from, wsc_data,
							req_wsc_data_size);
			l_free(wsc_data);
		}

		wsc_pr.version2 = true;
		wsc_pr.state = WSC_STATE_CONFIGURED;

		if (ap->wsc_pbc_timeout) {
			wsc_pr.selected_registrar = true;
			wsc_pr.device_password_id = ap->wsc_dpid;
			wsc_pr.selected_reg_config_methods =
				WSC_CONFIGURATION_METHOD_PUSH_BUTTON;
		}

		wsc_pr.response_type = WSC_RESPONSE_TYPE_AP;
		memcpy(wsc_pr.uuid_e, ap->wsc_uuid_r, sizeof(wsc_pr.uuid_e));
		wsc_pr.primary_device_type = ap->wsc_primary_device_type;

		if (ap->wsc_name[0] != '\0')
			l_strlcpy(wsc_pr.device_name, ap->wsc_name,
					sizeof(wsc_pr.device_name));

		wsc_pr.config_methods =
			WSC_CONFIGURATION_METHOD_PUSH_BUTTON;

		ap_write_authorized_macs(ap, sizeof(wsc_pr.authorized_macs),
						wsc_pr.authorized_macs);
		wsc_data = wsc_build_probe_response(&wsc_pr, &wsc_data_size);
	} else if (type == MPDU_MANAGEMENT_SUBTYPE_BEACON) {
		struct wsc_beacon wsc_beacon = {};

		wsc_beacon.version2 = true;
		wsc_beacon.state = WSC_STATE_CONFIGURED;

		if (ap->wsc_pbc_timeout) {
			wsc_beacon.selected_registrar = true;
			wsc_beacon.device_password_id = ap->wsc_dpid;
			wsc_beacon.selected_reg_config_methods =
				WSC_CONFIGURATION_METHOD_PUSH_BUTTON;
		}

		ap_write_authorized_macs(ap, sizeof(wsc_beacon.authorized_macs),
						wsc_beacon.authorized_macs);
		wsc_data = wsc_build_beacon(&wsc_beacon, &wsc_data_size);
	} else if (L_IN_SET(type, MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_RESPONSE,
			MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_RESPONSE)) {
		const uint8_t *from = client_frame->address_2;
		struct wsc_association_response wsc_resp = {};
		struct sta_state *sta =
			l_queue_find(ap->sta_states, ap_sta_match_addr, from);

		if (!sta || sta->assoc_rsne)
			return 0;

		wsc_resp.response_type = WSC_RESPONSE_TYPE_AP;
		wsc_resp.version2 = sta->wsc_v2;

		wsc_data = wsc_build_association_response(&wsc_resp,
								&wsc_data_size);
	} else
		return 0;

	if (!wsc_data) {
		l_error("wsc_build_<mgmt-subtype> error (stype 0x%x)", type);
		return 0;
	}

	wsc_ie = ie_tlv_encapsulate_wsc_payload(wsc_data, wsc_data_size,
						&wsc_ie_size);
	l_free(wsc_data);

	if (!wsc_ie) {
		l_error("ie_tlv_encapsulate_wsc_payload error (stype 0x%x)",
			type);
		return 0;
	}

	memcpy(out_buf + len, wsc_ie, wsc_ie_size);
	len += wsc_ie_size;
	l_free(wsc_ie);

	return len;
}

static size_t ap_build_supported_rates(struct ap_state *ap,
					uint8_t *rates)
{
	uint32_t minr, maxr, count, r;

	minr = l_uintset_find_min(ap->rates);
	maxr = l_uintset_find_max(ap->rates);
	count = 0;
	for (r = minr; r <= maxr && count < 8; r++)
		if (l_uintset_contains(ap->rates, r)) {
			uint8_t flag = 0;

			/* Mark only the lowest rate as Basic Rate */
			if (count == 0)
				flag = 0x80;

			*rates++ = r | flag;
			count++;
		}

	return count;
}

static size_t ap_get_extra_ies_len(struct ap_state *ap,
					enum mpdu_management_subtype type,
					const struct mmpdu_header *client_frame,
					size_t client_frame_len)
{
	size_t len = 0;

	len += ap_get_wsc_ie_len(ap, type, client_frame, client_frame_len);

	if (ap->supports_ht)
		len += 26;

	if (ap->ops->get_extra_ies_len)
		len += ap->ops->get_extra_ies_len(type, client_frame,
							client_frame_len,
							ap->user_data);

	return len;
}

/* WMM Specification 2.2.2 WMM Parameter Element */
struct ap_wmm_ac_record {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t aifsn : 4;
	uint8_t acm : 1;
	uint8_t aci : 2;
	uint8_t reserved : 1;
	uint8_t ecw_min : 4;
	uint8_t ecw_max : 4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t reserved : 1;
	uint8_t aci : 2;
	uint8_t acm : 1;
	uint8_t aifsn : 4;
	uint8_t acw_max : 4;
	uint8_t acw_min : 4;
#else
#error "Please fix <asm/byteorder.h"
#endif
	__le16 txop_limit;
} __attribute__((packed));

static size_t ap_write_wmm_ies(struct ap_state *ap, uint8_t *out_buf)
{
	unsigned int i;
	struct wiphy *wiphy = netdev_get_wiphy(ap->netdev);

	/*
	 * Linux kernel requires APs include WMM Information element if
	 * supporting HT/VHT/etc.
	 *
	 * The only value we can actually get from the kernel is UAPSD. The
	 * remaining values (AC parameter records) are made up or defaults
	 * defined in the WMM spec are used.
	 */
	*out_buf++ = IE_TYPE_VENDOR_SPECIFIC;
	*out_buf++ = 24;
	memcpy(out_buf, microsoft_oui, sizeof(microsoft_oui));
	out_buf += sizeof(microsoft_oui);
	*out_buf++ = 2; /* WMM OUI Type */
	*out_buf++ = 1; /* WMM Parameter subtype */
	*out_buf++ = 1; /* WMM Version */
	*out_buf++ = wiphy_supports_uapsd(wiphy) ? 1 << 7 : 0;
	*out_buf++ = 0; /* reserved */

	for (i = 0; i < 4; i++) {
		struct ap_wmm_ac_record ac = { 0 };

		ac.aifsn = 2;
		ac.acm = 0;
		ac.aci = i;
		ac.ecw_min = 1;
		ac.ecw_max = 15;
		l_put_le16(0, &ac.txop_limit);

		memcpy(out_buf + (i * 4), &ac, sizeof(struct ap_wmm_ac_record));
	}

	return 26;
}

static size_t ap_write_extra_ies(struct ap_state *ap,
					enum mpdu_management_subtype type,
					const struct mmpdu_header *client_frame,
					size_t client_frame_len,
					uint8_t *out_buf)
{
	size_t len = 0;

	len += ap_write_wsc_ie(ap, type, client_frame, client_frame_len,
				out_buf + len);

	if (ap->supports_ht)
		len += ap_write_wmm_ies(ap, out_buf + len);

	if (ap->ops->write_extra_ies)
		len += ap->ops->write_extra_ies(type,
						client_frame, client_frame_len,
						out_buf + len, ap->user_data);

	return len;
}

static size_t ap_build_ht_capability(struct ap_state *ap, uint8_t *buf)
{
	struct wiphy *wiphy = netdev_get_wiphy(ap->netdev);
	size_t ht_capa_len;
	const uint8_t *ht_capa = wiphy_get_ht_capabilities(wiphy, ap->band,
								&ht_capa_len);

	memcpy(buf, ht_capa, ht_capa_len);

	return ht_capa_len;
}

static size_t ap_build_ht_operation(struct ap_state *ap, uint8_t *buf)
{
	const struct l_queue_entry *e;
	unsigned int non_ht = false;
	unsigned int non_greenfield = false;

	memset(buf, 0, 22);
	*buf++ = ap->channel;

	/*
	 * If 40MHz set 'Secondary Channel Offset' (bits 0-1) to above/below
	 * and set 'STA Channel Width' (bit 2) to indicate non-20Mhz.
	 */
	if (ap->chandef.channel_width == BAND_CHANDEF_WIDTH_20)
		goto check_stas;
	else if (ap->chandef.frequency < ap->chandef.center1_frequency)
		*buf |= 1 & 0x3;
	else
		*buf |= 3 & 0x3;

	*buf |= 1 << 2;

check_stas:
	for (e = l_queue_get_entries(ap->sta_states); e; e = e->next) {
		struct sta_state *sta = e->data;

		if (!sta->associated)
			continue;

		if (!sta->ht_support)
			non_ht = true;
		else if (!sta->ht_greenfield)
			non_greenfield = true;
	}

	if (non_greenfield)
		set_bit(buf, 10);

	if (non_ht)
		set_bit(buf, 12);

	/*
	 * TODO: Basic MCS set for all associated STAs
	 */

	return 22;
}

/*
 * Build a Beacon frame or a Probe Response frame's header and body until
 * the TIM IE.  Except for the optional TIM IE which is inserted by the
 * kernel when needed, our contents for both frames are the same.
 * See Beacon format in 8.3.3.2 and Probe Response format in 8.3.3.10.
 *
 * 802.11-2016, Section 9.4.2.1:
 * "The frame body components specified for many management subtypes result
 * in elements ordered by ascending values of the Element ID field and then
 * the Element ID Extension field (when present), with the exception of the
 * MIC Management element (9.4.2.55)."
 */
static size_t ap_build_beacon_pr_head(struct ap_state *ap,
					enum mpdu_management_subtype stype,
					const uint8_t *dest, uint8_t *out_buf,
					size_t out_len)
{
	struct mmpdu_header *mpdu = (void *) out_buf;
	uint16_t capability = IE_BSS_CAP_ESS | IE_BSS_CAP_PRIVACY;
	const uint8_t *bssid = netdev_get_address(ap->netdev);
	size_t len;
	struct ie_tlv_builder builder;

	memset(mpdu, 0, 36); /* Zero out header + non-IE fields */

	/* Header */
	mpdu->fc.protocol_version = 0;
	mpdu->fc.type = MPDU_TYPE_MANAGEMENT;
	mpdu->fc.subtype = stype;
	memcpy(mpdu->address_1, dest, 6);	/* DA */
	memcpy(mpdu->address_2, bssid, 6);	/* SA */
	memcpy(mpdu->address_3, bssid, 6);	/* BSSID */

	/* Body non-IE fields */
	l_put_le16(ap->beacon_interval, out_buf + 32);	/* Beacon Interval */
	l_put_le16(capability, out_buf + 34);		/* Capability Info */

	ie_tlv_builder_init(&builder, out_buf + 36, out_len - 36);

	/* SSID IE */
	ie_tlv_builder_next(&builder, IE_TYPE_SSID);
	ie_tlv_builder_set_data(&builder, ap->ssid, strlen(ap->ssid));

	/* Supported Rates IE */
	ie_tlv_builder_next(&builder, IE_TYPE_SUPPORTED_RATES);
	len = ap_build_supported_rates(ap, ie_tlv_builder_get_data(&builder));
	ie_tlv_builder_set_length(&builder, len);

	/* DSSS Parameter Set IE for DSSS, HR, ERP and HT PHY rates */
	ie_tlv_builder_next(&builder, IE_TYPE_DSSS_PARAMETER_SET);
	ie_tlv_builder_set_data(&builder, &ap->channel, 1);

	if (ap->supports_ht) {
		ie_tlv_builder_next(&builder, IE_TYPE_HT_CAPABILITIES);
		len = ap_build_ht_capability(ap,
					ie_tlv_builder_get_data(&builder));
		ie_tlv_builder_set_length(&builder, len);

		ie_tlv_builder_next(&builder, IE_TYPE_HT_OPERATION);
		len = ap_build_ht_operation(ap,
					ie_tlv_builder_get_data(&builder));
		ie_tlv_builder_set_length(&builder, len);
	}

	ie_tlv_builder_finalize(&builder, &out_len);
	return 36 + out_len;
}

static size_t ap_build_country_ie(struct ap_state *ap, uint8_t *out_buf,
					size_t buf_len)
{
	size_t len;
	size_t i;
	int spacing;
	uint8_t *pos = out_buf;
	uint8_t nchans = 1;
	struct wiphy *wiphy = netdev_get_wiphy(ap->netdev);
	const struct band_freq_attrs *last = NULL;
	const struct band_freq_attrs *list = wiphy_get_frequency_info_list(
							wiphy, ap->band, &len);

	if (!list || wiphy_country_is_unknown(wiphy))
		return 0;

	if (L_WARN_ON(buf_len < 5))
		goto no_space;

	*pos++ = IE_TYPE_COUNTRY;
	/* length not yet known */
	pos++;

	wiphy_get_reg_domain_country(wiphy, (char *)pos);
	pos += 2;
	*pos++ = ' ';

	buf_len -= 5;

	if (ap->band == BAND_FREQ_2_4_GHZ)
		spacing = 1;
	else
		spacing = 4;

	/*
	 * Construct a list of subband triplet entries. Each entry contains a
	 * starting channel and a number of channels which are spaced evenly
	 * and use the same TX power. Any deviation from this results in a new
	 * channel group.
	 *
	 * TODO: 6Ghz requires operating triplets, not subband triplets.
	 */
	for (i = 0; i < len; i++) {
		const struct band_freq_attrs *attr = &list[i];

		if (!attr->supported || attr->disabled)
			continue;

		if (!last) {
			/* Room for one complete triplet */
			if (L_WARN_ON(buf_len < 3))
				goto no_space;

			*pos++ = i;
			last = attr;
			continue;
		}

		if (spacing != attr - last ||
					attr->tx_power != last->tx_power) {
			/* finish current group */
			*pos++ = nchans;
			*pos++ = last->tx_power;
			buf_len -= 3;

			/* start a new group */
			if (L_WARN_ON(buf_len < 3))
				goto no_space;

			*pos++ = i;
			nchans = 1;
		} else
			nchans++;

		last = attr;
	}

	/* finish final group */
	*pos++ = nchans;
	*pos++ = last->tx_power;

	len = pos - out_buf - 2;

	/* Pad to even byte */
	if (len & 1) {
		if (L_WARN_ON(buf_len < 1))
			goto no_space;

		*pos++ = 0;
		len++;
	}

	out_buf[1] = len;

	return out_buf[1] + 2;

no_space:
	return 0;
}

/* Beacon / Probe Response frame portion after the TIM IE */
static size_t ap_build_beacon_pr_tail(struct ap_state *ap,
					enum mpdu_management_subtype stype,
					const struct mmpdu_header *req,
					size_t req_len, uint8_t *out_buf,
					size_t buf_len)
{
	size_t len;
	struct ie_rsn_info rsn;

	len = ap_build_country_ie(ap, out_buf, buf_len);

	/* RSNE */
	ap_set_rsn_info(ap, &rsn);
	if (!ie_build_rsne(&rsn, out_buf + len))
		return 0;
	len += 2 + out_buf[len + 1];

	len += ap_write_extra_ies(ap, stype, req, req_len, out_buf + len);
	return len;
}

static void ap_set_beacon_cb(struct l_genl_msg *msg, void *user_data)
{
	int error = l_genl_msg_get_error(msg);

	if (error < 0)
		l_error("SET_BEACON failed: %s (%i)", strerror(-error), -error);
}

void ap_update_beacon(struct ap_state *ap)
{
	struct l_genl_msg *cmd;
	uint8_t head[256];
	size_t tail_len = 256 + ap_get_extra_ies_len(ap,
						MPDU_MANAGEMENT_SUBTYPE_BEACON,
						NULL, 0);
	L_AUTO_FREE_VAR(uint8_t *, tail) = malloc(tail_len);
	size_t head_len;
	uint64_t wdev_id = netdev_get_wdev_id(ap->netdev);
	static const uint8_t bcast_addr[6] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	if (L_WARN_ON(!ap->started))
		return;

	head_len = ap_build_beacon_pr_head(ap, MPDU_MANAGEMENT_SUBTYPE_BEACON,
						bcast_addr, head, sizeof(head));
	tail_len = ap_build_beacon_pr_tail(ap, MPDU_MANAGEMENT_SUBTYPE_BEACON,
						NULL, 0, tail, tail_len);
	if (L_WARN_ON(!head_len || !tail_len))
		return;

	cmd = l_genl_msg_new_sized(NL80211_CMD_SET_BEACON,
					32 + head_len + tail_len);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_WDEV, 8, &wdev_id);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_BEACON_HEAD, head_len, head);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_BEACON_TAIL, tail_len, tail);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IE, 0, "");
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IE_PROBE_RESP, 0, "");
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IE_ASSOC_RESP, 0, "");

	if (l_genl_family_send(ap->nl80211, cmd, ap_set_beacon_cb, NULL, NULL))
		return;

	l_genl_msg_unref(cmd);
	l_error("Issuing SET_BEACON failed");
}

static uint32_t ap_send_mgmt_frame(struct ap_state *ap,
					const struct mmpdu_header *frame,
					size_t frame_len,
					frame_xchg_cb_t callback,
					void *user_data)
{
	uint32_t ch_freq = band_channel_to_freq(ap->channel, ap->band);
	uint64_t wdev_id = netdev_get_wdev_id(ap->netdev);
	struct iovec iov[2];

	iov[0].iov_base = (void *) frame;
	iov[0].iov_len = frame_len;
	iov[1].iov_base = NULL;
	return frame_xchg_start(wdev_id, iov, ch_freq, 0, 0, 0, 0,
					callback, user_data, NULL, NULL);
}

#define IP4_FROM_STR(str)						\
	(__extension__ ({						\
		struct in_addr ia;					\
		inet_pton(AF_INET, str, &ia) == 1 ? ia.s_addr : 0;	\
	}))

static void ap_start_handshake(struct sta_state *sta, bool use_eapol_start,
				const uint8_t *gtk_rsc)
{
	struct ap_state *ap = sta->ap;
	const uint8_t *own_addr = netdev_get_address(ap->netdev);
	struct ie_rsn_info rsn;
	uint8_t bss_rsne[64];

	handshake_state_set_ssid(sta->hs, (void *) ap->ssid, strlen(ap->ssid));
	handshake_state_set_authenticator_address(sta->hs, own_addr);
	handshake_state_set_supplicant_address(sta->hs, sta->addr);

	ap_set_rsn_info(ap, &rsn);
	/*
	 * Note: This assumes the length that ap_set_rsn_info() requires. If
	 * ap_set_rsn_info() changes then this will need to be updated.
	 */
	ie_build_rsne(&rsn, bss_rsne);
	handshake_state_set_authenticator_ie(sta->hs, bss_rsne);

	if (gtk_rsc)
		handshake_state_set_gtk(sta->hs, sta->ap->gtk,
					sta->ap->gtk_index, gtk_rsc);

	if (ap->netconfig_dhcp)
		sta->hs->support_ip_allocation = true;

	sta->sm = eapol_sm_new(sta->hs);
	if (!sta->sm) {
		ap_stop_handshake(sta);
		l_error("could not create sm object");
		goto error;
	}

	eapol_sm_set_listen_interval(sta->sm, sta->listen_interval);
	eapol_sm_set_use_eapol_start(sta->sm, use_eapol_start);

	eapol_register(sta->sm);
	eapol_start(sta->sm);

	return;

error:
	ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED, true);
}

static bool ap_sta_get_dhcp4_lease(struct sta_state *sta)
{
	if (sta->ip_alloc_lease)
		return true;

	if (!sta->ap->netconfig_dhcp)
		return false;

	sta->ip_alloc_lease = l_dhcp_server_discover(sta->ap->netconfig_dhcp,
							0, NULL, sta->addr);
	if (!sta->ip_alloc_lease) {
		l_error("l_dhcp_server_discover() failed, see IWD_DHCP_DEBUG "
			"output");
		return false;
	}

	return true;
}

static void ap_handshake_event(struct handshake_state *hs,
		enum handshake_event event, void *user_data, ...)
{
	struct sta_state *sta = user_data;
	struct ap_state *ap = sta->ap;
	va_list args;

	va_start(args, user_data);

	switch (event) {
	case HANDSHAKE_EVENT_COMPLETE:
		if (sta->ip_alloc_lease) {
			if (hs->support_ip_allocation)
				sta->ip_alloc_sent = true;

			/*
			 * Move the lease from offered to active state if the
			 * client has actually used it.  In any case drop our
			 * reference to the lease, the server owns the lease
			 * and if we want to keep our reference we'd need to
			 * react to relevant server events.
			 */
			if (sta->ip_alloc_sent)
				l_dhcp_server_request(ap->netconfig_dhcp,
							sta->ip_alloc_lease);

			sta->ip_alloc_lease = NULL;
		}

		ap_new_rsna(sta);
		break;
	case HANDSHAKE_EVENT_FAILED:
		netdev_handshake_failed(hs, va_arg(args, int));
		/* fall through */
	case HANDSHAKE_EVENT_SETTING_KEYS_FAILED:
		sta->sm = NULL;
		ap_remove_sta(sta);
		break;
	case HANDSHAKE_EVENT_P2P_IP_REQUEST:
	{
		char own_addr_str[INET_ADDRSTRLEN];

		if (!ap_sta_get_dhcp4_lease(sta))
			break;

		sta->hs->client_ip_addr =
			l_dhcp_lease_get_address_u32(sta->ip_alloc_lease);
		sta->hs->subnet_mask =
			l_dhcp_lease_get_netmask_u32(sta->ip_alloc_lease);
		l_rtnl_address_get_address(ap->netconfig_addr4, own_addr_str);
		sta->hs->go_ip_addr = IP4_FROM_STR(own_addr_str);
		break;
	}
	default:
		break;
	}

	va_end(args);
}

static void ap_start_rsna(struct sta_state *sta, const uint8_t *gtk_rsc)
{
	/* this handshake setup assumes PSK network */
	sta->hs = netdev_handshake_state_new(sta->ap->netdev);
	handshake_state_set_authenticator(sta->hs, true);
	handshake_state_set_event_func(sta->hs, ap_handshake_event, sta);
	handshake_state_set_supplicant_ie(sta->hs, sta->assoc_rsne);
	handshake_state_set_pmk(sta->hs, sta->ap->psk, 32);
	ap_start_handshake(sta, false, gtk_rsc);
}

static void ap_gtk_query_cb(struct l_genl_msg *msg, void *user_data)
{
	struct sta_state *sta = user_data;
	const void *gtk_rsc;
	uint8_t zero_gtk_rsc[6];

	sta->gtk_query_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0)
		goto error;

	gtk_rsc = nl80211_parse_get_key_seq(msg);
	if (!gtk_rsc) {
		memset(zero_gtk_rsc, 0, 6);
		gtk_rsc = zero_gtk_rsc;
	}

	ap_start_rsna(sta, gtk_rsc);
	return;

error:
	ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED, true);
}

static void ap_stop_handshake_schedule(struct sta_state *sta)
{
	if (sta->stop_handshake_work)
		return;

	sta->stop_handshake_work = l_idle_create(ap_stop_handshake_work,
							sta, NULL);
}

static void ap_wsc_handshake_event(struct handshake_state *hs,
		enum handshake_event event, void *user_data, ...)
{
	struct sta_state *sta = user_data;
	va_list args;
	struct ap_event_registration_success_data event_data;
	struct ap_pbc_record_expiry_data expiry_data;

	va_start(args, user_data);

	switch (event) {
	case HANDSHAKE_EVENT_FAILED:
		sta->sm = NULL;
		ap_stop_handshake_schedule(sta);
		/*
		 * Some diagrams in WSC v2.0.5 indicate we should
		 * automatically deauthenticate the Enrollee.  The text
		 * generally indicates the Enrollee may disassociate
		 * meaning that we should neither deauthenticate nor
		 * disassociate it automatically.  Some places indicate
		 * that the enrollee can send a new EAPoL-Start right away
		 * on an unsuccessful registration, we don't implement
		 * this for now.  STA remains associated but not authorized
		 * and basically has no other option than to re-associate
		 * or disassociate/deauthenticate.
		 */
		break;
	case HANDSHAKE_EVENT_EAP_NOTIFY:
		if (va_arg(args, unsigned int) != EAP_WSC_EVENT_CREDENTIAL_SENT)
			break;

		/*
		 * WSC v2.0.5 Section 11.3:
		 * "If the Registrar successfully runs the PBC method to
		 * completion with an Enrollee, that Enrollee's probe requests
		 * are removed from the Monitor Time check the next time the
		 * Registrar's PBC button is pressed."
		 */
		expiry_data.min_time = 0;
		expiry_data.mac = sta->addr;
		l_queue_foreach_remove(sta->ap->wsc_pbc_probes,
					ap_wsc_pbc_record_expire,
					&expiry_data);

		event_data.mac = sta->addr;
		ap_event(sta->ap, AP_EVENT_REGISTRATION_SUCCESS, &event_data);
		break;
	default:
		break;
	}

	va_end(args);
}

static void ap_start_eap_wsc(struct sta_state *sta)
{
	struct ap_state *ap = sta->ap;

	/*
	 * WSC v2.0.5 Section 8.2: "The AP is allowed to send
	 * EAP-Request/Identity to the station before EAPOL-Start is received
	 * if a WSC IE is included in the (re)association request and the
	 * WSC IE is version 2.0 or higher.
	 */
	bool wait_for_eapol_start = !sta->wsc_v2;

	sta->wsc_settings = l_settings_new();
	l_settings_set_string(sta->wsc_settings, "Security", "EAP-Method",
				"WSC-R");
	l_settings_set_string(sta->wsc_settings, "WSC", "EnrolleeMAC",
				util_address_to_string(sta->addr));
	l_settings_set_bytes(sta->wsc_settings, "WSC", "UUID-R",
				ap->wsc_uuid_r, 16);
	l_settings_set_bytes(sta->wsc_settings, "WSC", "UUID-E",
				sta->wsc_uuid_e, 16);
	l_settings_set_uint(sta->wsc_settings, "WSC", "RFBand",
				WSC_RF_BAND_2_4_GHZ);
	l_settings_set_uint(sta->wsc_settings, "WSC", "ConfigurationMethods",
				WSC_CONFIGURATION_METHOD_PUSH_BUTTON);
	l_settings_set_string(sta->wsc_settings, "WSC", "WPA2-SSID", ap->ssid);

	if (ap->passphrase[0])
		l_settings_set_string(sta->wsc_settings,
					"WSC", "WPA2-Passphrase",
					ap->passphrase);
	else
		l_settings_set_bytes(sta->wsc_settings,
					"WSC", "WPA2-PSK", ap->psk, 32);

	sta->hs = netdev_handshake_state_new(ap->netdev);
	handshake_state_set_authenticator(sta->hs, true);
	handshake_state_set_event_func(sta->hs, ap_wsc_handshake_event, sta);
	handshake_state_set_8021x_config(sta->hs, sta->wsc_settings);

	ap_start_handshake(sta, wait_for_eapol_start, NULL);
}

static struct l_genl_msg *ap_build_cmd_del_key(struct ap_state *ap)
{
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_DEL_KEY, 128);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_enter_nested(msg, NL80211_ATTR_KEY);
	l_genl_msg_append_attr(msg, NL80211_KEY_IDX, 1, &ap->gtk_index);
	l_genl_msg_leave_nested(msg);

	return msg;
}

static struct l_genl_msg *ap_build_cmd_new_station(struct sta_state *sta)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = netdev_get_ifindex(sta->ap->netdev);
	/*
	 * This should hopefully work both with and without
	 * NL80211_FEATURE_FULL_AP_CLIENT_STATE.
	 */
	struct nl80211_sta_flag_update flags = {
		.mask = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
			(1 << NL80211_STA_FLAG_ASSOCIATED) |
			(1 << NL80211_STA_FLAG_AUTHORIZED) |
			(1 << NL80211_STA_FLAG_MFP),
		.set = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
			(1 << NL80211_STA_FLAG_ASSOCIATED),
	};

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_STATION, 300);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_FLAGS2, 8, &flags);

	return msg;
}

static void ap_gtk_op_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0) {
		uint8_t cmd = l_genl_msg_get_command(msg);
		const char *cmd_name =
			cmd == NL80211_CMD_NEW_KEY ? "NEW_KEY" :
			cmd == NL80211_CMD_SET_KEY ? "SET_KEY" :
			"DEL_KEY";

		l_error("%s failed for the GTK: %i",
			cmd_name, l_genl_msg_get_error(msg));
	}
}

static void ap_associate_sta_cb(struct l_genl_msg *msg, void *user_data)
{
	struct sta_state *sta = user_data;
	struct ap_state *ap = sta->ap;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("NEW_STATION/SET_STATION failed: %i",
			l_genl_msg_get_error(msg));
		return;
	}

	/*
	 * WSC v2.0.5 Section 8.2:
	 * "Therefore if a WSC IE is present in the (re)association request,
	 * the AP shall engage in EAP-WSC with the station and shall not
	 * attempt any other security handshake."
	 *
	 * So no need for group traffic, skip the GTK setup below.
	 */
	if (!sta->assoc_rsne) {
		ap_start_eap_wsc(sta);
		return;
	}

	/*
	 * Set up the group key.  If this is our first STA then we have
	 * to add the new GTK to the kernel.  In theory we should be
	 * able to supply our own RSC (e.g. generated randomly) and use it
	 * immediately for our 4-Way Handshake without querying the kernel.
	 * However NL80211_CMD_NEW_KEY only lets us set the receive RSC --
	 * the Rx PN for CCMP and the Rx IV for TKIP -- and the
	 * transmit RSC always starts as all zeros.  There's effectively
	 * no way to set the Tx RSC or query the Rx RSC through nl80211.
	 * So we query the Tx RSC in both scenarios just in case some
	 * driver/hardware uses a different initial Tx RSC.
	 *
	 * Optimally we would get called back by the EAPoL state machine
	 * only when building the step 3 of 4 message to query the RSC as
	 * late as possible but that would complicate EAPoL.
	 */
	if (ap->group_cipher != IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC &&
			!ap->gtk_set) {
		enum crypto_cipher group_cipher =
			ie_rsn_cipher_suite_to_cipher(ap->group_cipher);
		int gtk_len = crypto_cipher_key_len(group_cipher);

		/*
		 * Generate our GTK.  Not following the example derivation
		 * method in 802.11-2016 section 12.7.1.4 because a simple
		 * l_getrandom is just as good.
		 */
		l_getrandom(ap->gtk, gtk_len);
		ap->gtk_index = 1;

		msg = nl80211_build_new_key_group(
						netdev_get_ifindex(ap->netdev),
						group_cipher, ap->gtk_index,
						ap->gtk, gtk_len, NULL,
						0, NULL);

		if (!l_genl_family_send(ap->nl80211, msg, ap_gtk_op_cb, NULL,
					NULL)) {
			l_genl_msg_unref(msg);
			l_error("Issuing NEW_KEY failed");
			goto error;
		}

		msg = nl80211_build_set_key(netdev_get_ifindex(ap->netdev),
						ap->gtk_index);
		if (!l_genl_family_send(ap->nl80211, msg, ap_gtk_op_cb, NULL,
					NULL)) {
			l_genl_msg_unref(msg);
			l_error("Issuing SET_KEY failed");
			goto error;
		}

		/*
		 * Set the flag now because any new associating STA will
		 * just use NL80211_CMD_GET_KEY from now.
		 */
		ap->gtk_set = true;
	}

	if (ap->group_cipher == IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC)
		ap_start_rsna(sta, NULL);
	else {
		msg = nl80211_build_get_key(netdev_get_ifindex(ap->netdev),
					ap->gtk_index);
		sta->gtk_query_cmd_id = l_genl_family_send(ap->nl80211, msg,
								ap_gtk_query_cb,
								sta, NULL);
		if (!sta->gtk_query_cmd_id) {
			l_genl_msg_unref(msg);
			l_error("Issuing GET_KEY failed");
			goto error;
		}
	}

	return;

error:
	ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED, true);
}

static void ap_associate_sta(struct ap_state *ap, struct sta_state *sta)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);

	uint8_t rates[256];
	uint32_t r, minr, maxr, count = 0;
	uint16_t capability = l_get_le16(&sta->capability);

	if (sta->associated)
		msg = nl80211_build_set_station_associated(ifindex, sta->addr);
	else
		msg = ap_build_cmd_new_station(sta);

	sta->associated = true;
	sta->rsna = false;

	minr = l_uintset_find_min(sta->rates);
	maxr = l_uintset_find_max(sta->rates);

	for (r = minr; r <= maxr; r++)
		if (l_uintset_contains(sta->rates, r))
			rates[count++] = r;

	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_AID, 2, &sta->aid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_SUPPORTED_RATES,
				count, &rates);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, 2,
				&sta->listen_interval);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_CAPABILITY, 2,
				&capability);

	if (!l_genl_family_send(ap->nl80211, msg, ap_associate_sta_cb,
								sta, NULL)) {
		l_genl_msg_unref(msg);
		if (l_genl_msg_get_command(msg) == NL80211_CMD_NEW_STATION)
			l_error("Issuing NEW_STATION failed");
		else
			l_error("Issuing SET_STATION failed");
	}
}

static bool ap_common_rates(struct l_uintset *ap_rates,
				struct l_uintset *sta_rates)
{
	uint32_t minr = l_uintset_find_min(ap_rates);

	/* Our lowest rate is a Basic Rate so must be supported */
	if (l_uintset_contains(sta_rates, minr))
		return true;

	return false;
}

static void ap_success_assoc_resp_cb(int err, void *user_data)
{
	struct sta_state *sta = user_data;
	struct ap_state *ap = sta->ap;

	sta->assoc_resp_cmd_id = 0;

	if (err) {
		if (err == -ECOMM)
			l_error("AP (Re)Association Response received no ACK");
		else
			l_error("AP (Re)Association Response not sent %s (%i)",
				strerror(-err), -err);

		/* If we were in State 3 or 4 go to back to State 2 */
		if (sta->associated)
			ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED,
					true);

		return;
	}

	/* If we were in State 2, 3 or 4 also go to State 3 */
	ap_associate_sta(ap, sta);

	l_info("AP (Re)Association Response ACK received");
}

static void ap_fail_assoc_resp_cb(int err, void *user_data)
{
	if (err == -ECOMM)
		l_error("AP (Re)Association Response with an error status "
			"received no ACK");
	else if (err)
		l_error("AP (Re)Association Response with an error status "
			"not sent: %s (%i)", strerror(-err), -err);
	else
		l_info("AP (Re)Association Response with an error status "
			"delivered OK");
}

static uint32_t ap_assoc_resp(struct ap_state *ap, struct sta_state *sta,
				const uint8_t *dest,
				enum mmpdu_reason_code status_code,
				bool reassoc, const struct mmpdu_header *req,
				size_t req_len,
				const struct ie_fils_ip_addr_request_info *
				ip_req_info, frame_xchg_cb_t callback)
{
	const uint8_t *addr = netdev_get_address(ap->netdev);
	enum mpdu_management_subtype stype = reassoc ?
		MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_RESPONSE :
		MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_RESPONSE;
	L_AUTO_FREE_VAR(uint8_t *, mpdu_buf) =
		l_malloc(256 + ap_get_extra_ies_len(ap, stype, req, req_len));
	struct mmpdu_header *mpdu = (void *) mpdu_buf;
	struct mmpdu_association_response *resp;
	size_t ies_len = 0;
	size_t len;
	uint16_t capability = IE_BSS_CAP_ESS | IE_BSS_CAP_PRIVACY;

	memset(mpdu, 0, sizeof(*mpdu));

	/* Header */
	mpdu->fc.protocol_version = 0;
	mpdu->fc.type = MPDU_TYPE_MANAGEMENT;
	mpdu->fc.subtype = stype;
	memcpy(mpdu->address_1, dest, 6);	/* DA */
	memcpy(mpdu->address_2, addr, 6);	/* SA */
	memcpy(mpdu->address_3, addr, 6);	/* BSSID */

	/* Association Response body */
	resp = (void *) mmpdu_body(mpdu);
	l_put_le16(capability, &resp->capability);
	resp->status_code = L_CPU_TO_LE16(status_code);
	resp->aid = sta ? L_CPU_TO_LE16(sta->aid | 0xc000) : 0;

	/* Supported Rates IE */
	resp->ies[ies_len++] = IE_TYPE_SUPPORTED_RATES;
	len = ap_build_supported_rates(ap, resp->ies + ies_len + 1);
	resp->ies[ies_len++] = len;
	ies_len += len;

	if (ap->supports_ht) {
		resp->ies[ies_len++] = IE_TYPE_HT_CAPABILITIES;
		len = ap_build_ht_capability(ap, resp->ies + ies_len + 1);
		resp->ies[ies_len++] = len;
		ies_len += len;

		resp->ies[ies_len++] = IE_TYPE_HT_OPERATION;
		len = ap_build_ht_operation(ap, resp->ies + ies_len + 1);
		resp->ies[ies_len++] = len;
		ies_len += len;
	}

	ies_len += ap_write_extra_ies(ap, stype, req, req_len,
					resp->ies + ies_len);

	if (ip_req_info) {
		struct ie_fils_ip_addr_response_info ip_resp_info = {};

		if (ip_req_info->ipv4 && sta && ap_sta_get_dhcp4_lease(sta)) {
			uint32_t lease_lifetime =
				l_dhcp_lease_get_lifetime(sta->ip_alloc_lease);
			uint32_t gw =
				l_dhcp_lease_get_gateway_u32(
							sta->ip_alloc_lease);
			char **lease_dns_str_list =
				l_dhcp_lease_get_dns(sta->ip_alloc_lease);

			ip_resp_info.ipv4_addr = l_dhcp_lease_get_address_u32(
							sta->ip_alloc_lease);
			ip_resp_info.ipv4_prefix_len =
				l_dhcp_lease_get_prefix_length(
							sta->ip_alloc_lease);

			if (lease_lifetime != 0xffffffff)
				ip_resp_info.ipv4_lifetime = lease_lifetime;

			if (gw) {
				ip_resp_info.ipv4_gateway = gw;
				memcpy(ip_resp_info.ipv4_gateway_mac,
					ap->netconfig_gateway4_mac, 6);
			}

			if (lease_dns_str_list && lease_dns_str_list[0]) {
				ip_resp_info.ipv4_dns =
					IP4_FROM_STR(lease_dns_str_list[0]);
				memcpy(ip_resp_info.ipv4_dns_mac,
					ap->netconfig_dns4_mac, 6);
			}

			l_strv_free(lease_dns_str_list);
			sta->ip_alloc_sent = true;
		} else if (ip_req_info->ipv4 || ip_req_info->ipv6) {
			/*
			 * 802.11ai-2016 Section 11.47.3.3: "If the AP is unable
			 * to assign an IP address in the (Re)Association
			 * Response frame, then the AP sets the IP address
			 * assignment pending flag in the IP Address Response
			 * Control field of the FILS IP Address Assignment
			 * element to 1 and sets the IP address request timeout
			 * to 0 in (Re)Association Response frame."
			 */
			ip_resp_info.response_pending = 1;
			ip_resp_info.response_timeout = 0;
		}

		ie_build_fils_ip_addr_response(&ip_resp_info,
							resp->ies + ies_len);
		ies_len += 2 + resp->ies[ies_len + 1];
	}

	return ap_send_mgmt_frame(ap, mpdu, resp->ies + ies_len - mpdu_buf,
					callback, sta);
}

static int ap_parse_supported_rates(struct ie_tlv_iter *iter,
					struct l_uintset **set)
{
	const uint8_t *rates;
	unsigned int len;
	unsigned int i;

	len = ie_tlv_iter_get_length(iter);

	if (ie_tlv_iter_get_tag(iter) == IE_TYPE_SUPPORTED_RATES && len == 0)
		return -EINVAL;

	rates = ie_tlv_iter_get_data(iter);

	if (!*set)
		*set = l_uintset_new(108);

	for (i = 0; i < len; i++) {
		if (rates[i] == 0xff)
			continue;

		l_uintset_put(*set, rates[i] & 0x7f);
	}

	return 0;
}

/*
 * This handles both the Association and Reassociation Request frames.
 * Association Request is documented in 802.11-2016 9.3.3.6 (frame format),
 * 802.11-2016 11.3.5.3 (MLME/SME) and Reassociation in 802.11-2016
 * 9.3.3.8 (frame format), 802.11-2016 11.3.5.3 (MLME/SME).
 *
 * The difference between Association and Reassociation procedures is
 * documented in 11.3.5.1 "General" but seems inconsistent with specific
 * instructions in 11.3.5.3 vs. 11.3.5.5 and 11.3.5.2 vs. 11.3.5.4.
 * According to 11.3.5.1:
 *  1. Reassociation requires the STA to be already associated in the ESS,
 *     Association doesn't.
 *  2. Unsuccessful Reassociation should not cause a state transition of
 *     the authentication state between the two STAs.
 *
 * The first requirement is not present in 11.3.5.5 which is virtually
 * identical with 11.3.5.3, but we do implement it.  Number 2 is also not
 * reflected in 11.3.5.5 where the state transitions are the same as in
 * 11.3.5.3 and 11.3.5.4 where the state transitions are the same as in
 * 11.3.5.2 including f) "If a Reassociation Response frame is received
 * with a status code other than SUCCESS [...] 1. [...] the state for
 * the AP [...] shall be set to State 2 [...]"
 *
 * For the record here are the apparent differences between 802.11-2016
 * 11.3.5.2 and 11.3.5.4 ignoring the s/Associate/Reassociate/ changes
 * and the special case of Reassociation during a Fast Transition.
 *  o Points c) and d) are switched around.
 *  o On success, the STA is disassociated from all other APs in 11.3.5.2,
 *    and from the previous AP in 11.3.5.4 c).  (Shouldn't make a
 *    difference as there seems to be no way for the STA to become
 *    associated with more than one AP)
 *  o After Association a 4-Way Handshake is always performed, after
 *    Reassociation it is only performed if STA was in State 3 according
 *    to 11.3.5.4 g).  This is not reflected in 11.3.5.5 though.
 *    Additionally 11.3.5.4 and 11.3.5.5 require the STA and AP
 *    respectively to delete current PTKSA/GTKSA/IGTKSA at the beginning
 *    of the procedure independent of the STA state so without a 4-Way
 *    Handshake the two stations end up with no encryption keys.
 *
 * The main difference between 11.3.5.3 and 11.3.5.5 is presence of p).
 */
static void ap_assoc_reassoc(struct sta_state *sta, bool reassoc,
				const struct mmpdu_field_capability *capability,
				uint16_t listen_interval,
				const uint8_t *ies, size_t ies_len,
				const struct mmpdu_header *req)
{
	struct ap_state *ap = sta->ap;
	const char *ssid = NULL;
	const uint8_t *rsn = NULL;
	size_t ssid_len = 0;
	_auto_(l_uintset_free) struct l_uintset *rates = NULL;
	struct ie_rsn_info rsn_info;
	int err;
	struct ie_tlv_iter iter;
	_auto_(l_free) uint8_t *wsc_data = NULL;
	ssize_t wsc_data_len;
	bool fils_ip_req = false;
	struct ie_fils_ip_addr_request_info fils_ip_req_info;

	if (sta->assoc_resp_cmd_id)
		return;

	if (reassoc && !sta->associated) {
		err = MMPDU_REASON_CODE_CLASS3_FRAME_FROM_NONASSOC_STA;
		goto unsupported;
	}

	wsc_data = ie_tlv_extract_wsc_payload(ies, ies_len, &wsc_data_len);

	ie_tlv_iter_init(&iter, ies, ies_len);

	while (ie_tlv_iter_next(&iter))
		switch (ie_tlv_iter_get_tag(&iter)) {
		case IE_TYPE_SSID:
			ssid = (const char *) ie_tlv_iter_get_data(&iter);
			ssid_len = ie_tlv_iter_get_length(&iter);
			break;

		case IE_TYPE_SUPPORTED_RATES:
		case IE_TYPE_EXTENDED_SUPPORTED_RATES:
			if (ap_parse_supported_rates(&iter, &rates) < 0) {
				err = MMPDU_REASON_CODE_INVALID_IE;
				goto bad_frame;
			}

			break;

		case IE_TYPE_RSN:
			/*
			 * WSC v2.0.5 Section 8.2:
			 * "Note that during the WSC association [...] the
			 * RSN IE and the WPA IE are irrelevant and shall be
			 * ignored by both the station and AP."
			 */
			if (wsc_data)
				break;

			if (ie_parse_rsne(&iter, &rsn_info) < 0) {
				err = MMPDU_REASON_CODE_INVALID_IE;
				goto bad_frame;
			}

			rsn = (const uint8_t *) ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_FILS_IP_ADDRESS:
			if (fils_ip_req || ie_parse_fils_ip_addr_request(&iter,
						&fils_ip_req_info) < 0) {
				l_debug("Can't parse FILS IP Address Assignment"
					" IE, ignoring it");
				break;
			}

			fils_ip_req = true;
			break;
		case IE_TYPE_HT_CAPABILITIES:
			if (ie_tlv_iter_get_length(&iter) != 26) {
				err = MMPDU_REASON_CODE_INVALID_IE;
				goto bad_frame;
			}

			if (test_bit(ie_tlv_iter_get_data(&iter), 4))
				sta->ht_greenfield = true;

			sta->ht_support = true;
			break;
		}

	if (!rates || !ssid || (!wsc_data && !rsn) ||
			ssid_len != strlen(ap->ssid) ||
			memcmp(ssid, ap->ssid, ssid_len)) {
		err = MMPDU_REASON_CODE_INVALID_IE;
		goto bad_frame;
	}

	if (!ap_common_rates(ap->rates, rates)) {
		err = MMPDU_REASON_CODE_UNSPECIFIED;
		goto unsupported;
	}

	/* Is the client requesting RSNA establishment or WSC registration */
	if (!rsn) {
		struct wsc_association_request wsc_req;
		struct ap_event_registration_start_data event_data;
		struct ap_wsc_pbc_probe_record *record;

		if (wsc_parse_association_request(wsc_data, wsc_data_len,
							&wsc_req) < 0) {
			err = MMPDU_REASON_CODE_INVALID_IE;
			goto bad_frame;
		}

		if (wsc_req.request_type !=
				WSC_REQUEST_TYPE_ENROLLEE_OPEN_8021X) {
			err = MMPDU_REASON_CODE_INVALID_IE;
			goto bad_frame;
		}

		if (!ap->wsc_pbc_timeout) {
			l_debug("WSC association from %s but we're not in "
				"PBC mode", util_address_to_string(sta->addr));
			err = MMPDU_REASON_CODE_UNSPECIFIED;
			goto bad_frame;
		}

		if (l_queue_isempty(ap->wsc_pbc_probes)) {
			l_debug("%s tried to register as enrollee but we "
				"don't have their Probe Request record",
				util_address_to_string(sta->addr));
			err = MMPDU_REASON_CODE_UNSPECIFIED;
			goto bad_frame;
		}

		/*
		 * For PBC, the Enrollee must have sent the only PBC Probe
		 * Request within the monitor time and walk time.
		 */
		record = l_queue_peek_head(ap->wsc_pbc_probes);
		if (memcmp(sta->addr, record->mac, 6)) {
			l_debug("Session overlap during %s's attempt to "
				"register as WSC enrollee",
				util_address_to_string(sta->addr));
			err = MMPDU_REASON_CODE_UNSPECIFIED;
			goto bad_frame;
		}

		memcpy(sta->wsc_uuid_e, record->uuid_e, 16);
		sta->wsc_v2 = wsc_req.version2;

		event_data.mac = sta->addr;
		event_data.assoc_ies = ies;
		event_data.assoc_ies_len = ies_len;

		if (ap_event(ap, AP_EVENT_REGISTRATION_START, &event_data))
			return;

		/*
		 * Since we're starting the PBC Registration Protocol
		 * we can now exit the "active PBC mode".
		 */
		ap_wsc_exit_pbc(ap);
	} else {
		if (rsn_info.mfpr && rsn_info.spp_a_msdu_required) {
			err = MMPDU_REASON_CODE_UNSPECIFIED;
			goto unsupported;
		}

		if (__builtin_popcount(rsn_info.pairwise_ciphers) != 1 ||
				!(rsn_info.pairwise_ciphers & ap->ciphers)) {
			err = MMPDU_REASON_CODE_INVALID_PAIRWISE_CIPHER;
			goto unsupported;
		}

		if (rsn_info.akm_suites != IE_RSN_AKM_SUITE_PSK) {
			err = MMPDU_REASON_CODE_INVALID_AKMP;
			goto unsupported;
		}

		if (rsn_info.group_cipher != ap->group_cipher) {
			err = MMPDU_REASON_CODE_INVALID_GROUP_CIPHER;
			goto unsupported;
		}
	}

	/* 802.11-2016 11.3.5.3 j) */
	if (sta->rsna)
		ap_drop_rsna(sta);
	else if (sta->associated)
		ap_stop_handshake(sta);

	if (!sta->associated) {
		/*
		 * Everything fine so far, assign an AID, send response.
		 * According to 802.11-2016 11.3.5.3 l) we will only go to
		 * State 3 (set sta->associated) once we receive the station's
		 * ACK or gave up on resends.
		 */
		sta->aid = ++ap->last_aid;
	}

	sta->capability = *capability;
	sta->listen_interval = listen_interval;

	if (sta->rates)
		l_uintset_free(sta->rates);

	sta->rates = l_steal_ptr(rates);

	l_free(sta->assoc_ies);

	if (rsn) {
		sta->assoc_ies = l_memdup(ies, ies_len);
		sta->assoc_ies_len = ies_len;
		sta->assoc_rsne = sta->assoc_ies + (rsn - ies);
	} else {
		sta->assoc_ies = NULL;
		sta->assoc_rsne = NULL;
	}

	sta->assoc_resp_cmd_id = ap_assoc_resp(ap, sta, sta->addr, 0, reassoc,
						req, (void *) ies + ies_len -
						(void *) req, fils_ip_req ?
						&fils_ip_req_info : NULL,
						ap_success_assoc_resp_cb);
	if (!sta->assoc_resp_cmd_id)
		l_error("Sending success (Re)Association Response failed");

	return;

unsupported:
bad_frame:
	/*
	 * TODO: MFP
	 *
	 * 802.11-2016 11.3.5.3 m)
	 * "If the ResultCode in the MLME-ASSOCIATE.response primitive is
	 * not SUCCESS and management frame protection is in use the state
	 * for the STA shall be left unchanged.  If the ResultCode is not
	 * SUCCESS and management frame protection is not in use the state
	 * for the STA shall be set to State 3 if it was State 4."
	 *
	 * For now, we need to drop the RSNA.
	 */
	if (sta->rsna)
		ap_drop_rsna(sta);
	else if (sta->associated)
		ap_stop_handshake(sta);

	if (!ap_assoc_resp(ap, sta, sta->addr, err, reassoc,
				req, (void *) ies + ies_len - (void *) req,
				NULL, ap_fail_assoc_resp_cb))
		l_error("Sending error (Re)Association Response failed");
}

/* 802.11-2016 9.3.3.6 */
static void ap_assoc_req_cb(const struct mmpdu_header *hdr, const void *body,
				size_t body_len, int rssi, void *user_data)
{
	struct ap_state *ap = user_data;
	struct sta_state *sta;
	const uint8_t *from = hdr->address_2;
	const struct mmpdu_association_request *req = body;
	const uint8_t *bssid = netdev_get_address(ap->netdev);

	l_info("AP Association Request from %s", util_address_to_string(from));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, from);
	if (!sta) {
		if (!ap_assoc_resp(ap, NULL, from,
				MMPDU_REASON_CODE_STA_REQ_ASSOC_WITHOUT_AUTH,
				false, hdr, body + body_len - (void *) hdr,
				NULL, ap_fail_assoc_resp_cb))
			l_error("Sending error Association Response failed");

		return;
	}

	ap_assoc_reassoc(sta, false, &req->capability,
				L_LE16_TO_CPU(req->listen_interval),
				req->ies, body_len - sizeof(*req), hdr);
}

/* 802.11-2016 9.3.3.8 */
static void ap_reassoc_req_cb(const struct mmpdu_header *hdr, const void *body,
				size_t body_len, int rssi, void *user_data)
{
	struct ap_state *ap = user_data;
	struct sta_state *sta;
	const uint8_t *from = hdr->address_2;
	const struct mmpdu_reassociation_request *req = body;
	const uint8_t *bssid = netdev_get_address(ap->netdev);
	int err;

	l_info("AP Reassociation Request from %s",
		util_address_to_string(from));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, from);
	if (!sta) {
		err = MMPDU_REASON_CODE_STA_REQ_ASSOC_WITHOUT_AUTH;
		goto bad_frame;
	}

	if (memcmp(req->current_ap_address, bssid, 6)) {
		err = MMPDU_REASON_CODE_UNSPECIFIED;
		goto bad_frame;
	}

	ap_assoc_reassoc(sta, true, &req->capability,
				L_LE16_TO_CPU(req->listen_interval),
				req->ies, body_len - sizeof(*req), hdr);
	return;

bad_frame:
	if (!ap_assoc_resp(ap, NULL, from, err, true,
				hdr, body + body_len - (void *) hdr,
				NULL, ap_fail_assoc_resp_cb))
		l_error("Sending error Reassociation Response failed");
}

static void ap_probe_resp_cb(int err, void *user_data)
{
	if (err == -ECOMM)
		l_error("AP Probe Response received no ACK");
	else if (err)
		l_error("AP Probe Response not sent: %s (%i)",
			strerror(-err), -err);
	else
		l_info("AP Probe Response delivered OK");
}

/*
 * Parse Probe Request according to 802.11-2016 9.3.3.10 and act according
 * to 802.11-2016 11.1.4.3
 */
static void ap_probe_req_cb(const struct mmpdu_header *hdr, const void *body,
				size_t body_len, int rssi, void *user_data)
{
	struct ap_state *ap = user_data;
	const struct mmpdu_probe_request *req = body;
	const char *ssid = NULL;
	const uint8_t *ssid_list = NULL;
	size_t ssid_len = 0, ssid_list_len = 0, len;
	uint8_t dsss_channel = 0;
	struct ie_tlv_iter iter;
	const uint8_t *bssid = netdev_get_address(ap->netdev);
	bool match = false;
	uint32_t resp_len;
	uint8_t *resp;

	l_info("AP Probe Request from %s",
		util_address_to_string(hdr->address_2));

	ie_tlv_iter_init(&iter, req->ies, body_len - sizeof(*req));

	while (ie_tlv_iter_next(&iter))
		switch (ie_tlv_iter_get_tag(&iter)) {
		case IE_TYPE_SSID:
			ssid = (const char *) ie_tlv_iter_get_data(&iter);
			ssid_len = ie_tlv_iter_get_length(&iter);
			break;

		case IE_TYPE_SSID_LIST:
			ssid_list = ie_tlv_iter_get_data(&iter);
			ssid_list_len = ie_tlv_iter_get_length(&iter);
			break;

		case IE_TYPE_DSSS_PARAMETER_SET:
			if (ie_tlv_iter_get_length(&iter) != 1)
				return;

			dsss_channel = ie_tlv_iter_get_data(&iter)[0];
			break;
		}

	/*
	 * Check if we should reply to this Probe Request according to
	 * 802.11-2016 section 11.1.4.3.2.
	 */

	if (memcmp(hdr->address_1, bssid, 6) &&
			!util_is_broadcast_address(hdr->address_1))
		return;

	if (memcmp(hdr->address_3, bssid, 6) &&
			!util_is_broadcast_address(hdr->address_3))
		return;

	if (!ssid || ssid_len == 0) /* Wildcard SSID */
		match = true;
	else if (ssid && ssid_len == strlen(ap->ssid) && /* One SSID */
			!memcmp(ssid, ap->ssid, ssid_len))
		match = true;
	else if (ssid && ssid_len == 7 && !memcmp(ssid, "DIRECT-", 7) &&
			!memcmp(ssid, ap->ssid, 7)) /* P2P wildcard */
		match = true;
	else if (ssid_list) { /* SSID List */
		ie_tlv_iter_init(&iter, ssid_list, ssid_list_len);

		while (ie_tlv_iter_next(&iter)) {
			if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_SSID)
				return;

			ssid = (const char *) ie_tlv_iter_get_data(&iter);
			ssid_len = ie_tlv_iter_get_length(&iter);

			if (ssid_len == strlen(ap->ssid) &&
					!memcmp(ssid, ap->ssid, ssid_len)) {
				match = true;
				break;
			}
		}
	}

	if (dsss_channel != 0 && dsss_channel != ap->channel)
		match = false;

	if (!match)
		return;

	resp_len = 512 + ap_get_extra_ies_len(ap,
					MPDU_MANAGEMENT_SUBTYPE_PROBE_RESPONSE,
					hdr, body + body_len - (void *) hdr);
	resp = l_new(uint8_t, resp_len);
	len = ap_build_beacon_pr_head(ap,
					MPDU_MANAGEMENT_SUBTYPE_PROBE_RESPONSE,
					hdr->address_2, resp, resp_len);
	len += ap_build_beacon_pr_tail(ap,
					MPDU_MANAGEMENT_SUBTYPE_PROBE_RESPONSE,
					hdr, body + body_len - (void *) hdr,
					resp + len, resp_len - len);

	ap_send_mgmt_frame(ap, (struct mmpdu_header *) resp, len,
				ap_probe_resp_cb, NULL);
	l_free(resp);
}

/* 802.11-2016 9.3.3.5 (frame format), 802.11-2016 11.3.5.9 (MLME/SME) */
static void ap_disassoc_cb(const struct mmpdu_header *hdr, const void *body,
				size_t body_len, int rssi, void *user_data)
{
	struct ap_state *ap = user_data;
	struct sta_state *sta;
	const struct mmpdu_disassociation *disassoc = body;
	const uint8_t *bssid = netdev_get_address(ap->netdev);

	l_info("AP Disassociation from %s, reason %i",
		util_address_to_string(hdr->address_2),
		(int) L_LE16_TO_CPU(disassoc->reason_code));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, hdr->address_2);

	if (sta && sta->assoc_resp_cmd_id) {
		l_genl_family_cancel(ap->nl80211, sta->assoc_resp_cmd_id);
		sta->assoc_resp_cmd_id = 0;
	}

	if (!sta || !sta->associated)
		return;

	ap_del_station(sta, L_LE16_TO_CPU(disassoc->reason_code), true);
}

static void ap_auth_reply_cb(int err, void *user_data)
{
	if (err == -ECOMM)
		l_error("AP Authentication frame 2 received no ACK");
	else if (err)
		l_error("AP Authentication frame 2 not sent: %s (%i)",
			strerror(-err), -err);
	else
		l_info("AP Authentication frame 2 ACKed by STA");
}

static void ap_auth_reply(struct ap_state *ap, const uint8_t *dest,
				enum mmpdu_reason_code status_code)
{
	const uint8_t *addr = netdev_get_address(ap->netdev);
	uint8_t mpdu_buf[64];
	struct mmpdu_header *mpdu = (struct mmpdu_header *) mpdu_buf;
	struct mmpdu_authentication *auth;

	memset(mpdu, 0, sizeof(*mpdu));

	/* Header */
	mpdu->fc.protocol_version = 0;
	mpdu->fc.type = MPDU_TYPE_MANAGEMENT;
	mpdu->fc.subtype = MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION;
	memcpy(mpdu->address_1, dest, 6);	/* DA */
	memcpy(mpdu->address_2, addr, 6);	/* SA */
	memcpy(mpdu->address_3, addr, 6);	/* BSSID */

	/* Authentication body */
	auth = (void *) mmpdu_body(mpdu);
	auth->algorithm = L_CPU_TO_LE16(MMPDU_AUTH_ALGO_OPEN_SYSTEM);
	auth->transaction_sequence = L_CPU_TO_LE16(2);
	auth->status = L_CPU_TO_LE16(status_code);

	ap_send_mgmt_frame(ap, mpdu, (uint8_t *) auth + 6 - mpdu_buf,
				ap_auth_reply_cb, NULL);
}

/*
 * 802.11-2016 9.3.3.12 (frame format), 802.11-2016 11.3.4.3 and
 * 802.11-2016 12.3.3.2 (MLME/SME)
 */
static void ap_auth_cb(const struct mmpdu_header *hdr, const void *body,
			size_t body_len, int rssi, void *user_data)
{
	struct ap_state *ap = user_data;
	const struct mmpdu_authentication *auth = body;
	const uint8_t *from = hdr->address_2;
	const uint8_t *bssid = netdev_get_address(ap->netdev);
	struct sta_state *sta;

	l_info("AP Authentication from %s", util_address_to_string(from));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	if (ap->authorized_macs_num) {
		unsigned int i;

		for (i = 0; i < ap->authorized_macs_num; i++)
			if (!memcmp(from, ap->authorized_macs + i * 6,
					6))
				break;

		if (i == ap->authorized_macs_num) {
			ap_auth_reply(ap, from, MMPDU_REASON_CODE_UNSPECIFIED);
			return;
		}
	}

	/* Only Open System authentication implemented here */
	if (L_LE16_TO_CPU(auth->algorithm) !=
			MMPDU_AUTH_ALGO_OPEN_SYSTEM) {
		ap_auth_reply(ap, from, MMPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	if (L_LE16_TO_CPU(auth->transaction_sequence) != 1) {
		ap_auth_reply(ap, from, MMPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, from);

	/*
	 * Figure 11-13 in 802.11-2016 11.3.2 shows a transition from
	 * States 3 / 4 to State 2 on "Successful 802.11 Authentication"
	 * however 11.3.4.2 and 11.3.4.3 clearly say the connection goes to
	 * State 2 only if it was in State 1:
	 *
	 * "c) [...] the state for the indicated STA shall be set to State 2
	 * if it was State 1; the state shall remain unchanged if it was other
	 * than State 1."
	 */
	if (sta)
		goto done;

	/*
	 * Per 12.3.3.2.3 with Open System the state change is immediate,
	 * no waiting for the response to be ACKed as with the association
	 * frames.
	 */
	sta = l_new(struct sta_state, 1);
	memcpy(sta->addr, from, 6);
	sta->ap = ap;

	if (!ap->sta_states)
		ap->sta_states = l_queue_new();

	l_queue_push_tail(ap->sta_states, sta);

	/*
	 * Nothing to do here netlink-wise as we can't receive any data
	 * frames until after association anyway.  We do need to add a
	 * timeout for the authentication and possibly the kernel could
	 * handle that if we registered the STA with NEW_STATION now (TODO)
	 */

done:
	ap_auth_reply(ap, from, 0);
}

/* 802.11-2016 9.3.3.13 (frame format), 802.11-2016 11.3.4.5 (MLME/SME) */
static void ap_deauth_cb(const struct mmpdu_header *hdr, const void *body,
				size_t body_len, int rssi, void *user_data)
{
	struct ap_state *ap = user_data;
	const struct mmpdu_deauthentication *deauth = body;
	const uint8_t *bssid = netdev_get_address(ap->netdev);

	l_info("AP Deauthentication from %s, reason %i",
		util_address_to_string(hdr->address_2),
		(int) L_LE16_TO_CPU(deauth->reason_code));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	ap_station_disconnect(ap, hdr->address_2,
				L_LE16_TO_CPU(deauth->reason_code));
}

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void ap_start_failed(struct ap_state *ap, int err)
{
	struct ap_event_start_failed_data data = { err };

	ap->in_event = true;
	ap->ops->handle_event(AP_EVENT_START_FAILED, &data, ap->user_data);
	ap_reset(ap);
	l_genl_family_free(ap->nl80211);

	l_free(ap);
}

static void ap_dhcp_event_cb(struct l_dhcp_server *server,
				enum l_dhcp_server_event event, void *user_data,
				const struct l_dhcp_lease *lease)
{
	struct ap_state *ap = user_data;

	switch (event) {
	case L_DHCP_SERVER_EVENT_NEW_LEASE:
		ap_event(ap, AP_EVENT_DHCP_NEW_LEASE, lease);
		break;

	case L_DHCP_SERVER_EVENT_LEASE_EXPIRED:
		ap_event(ap, AP_EVENT_DHCP_LEASE_EXPIRED, lease);
		break;

	default:
		break;
	}
}

static void ap_start_cb(struct l_genl_msg *msg, void *user_data)
{
	struct ap_state *ap = user_data;

	ap->start_stop_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("START_AP failed: %i", l_genl_msg_get_error(msg));
		ap_start_failed(ap, l_genl_msg_get_error(msg));
		return;
	}

	if (ap->netconfig_dhcp) {
		if (!l_dhcp_server_start(ap->netconfig_dhcp)) {
			l_error("DHCP server failed to start");
			ap_start_failed(ap, -EINVAL);
			return;
		}

		if (!l_dhcp_server_set_event_handler(ap->netconfig_dhcp,
							ap_dhcp_event_cb,
							ap, NULL)) {
			l_error("l_dhcp_server_set_event_handler failed");
			ap_start_failed(ap, -EIO);
			return;
		}
	}

	ap->started = true;
	ap_event(ap, AP_EVENT_STARTED, NULL);
}

static struct l_genl_msg *ap_build_cmd_start_ap(struct ap_state *ap)
{
	struct l_genl_msg *cmd;

	uint8_t head[256];
	size_t tail_len = 256 + ap_get_extra_ies_len(ap,
						MPDU_MANAGEMENT_SUBTYPE_BEACON,
						NULL, 0);
	L_AUTO_FREE_VAR(uint8_t *, tail) = l_malloc(tail_len);
	size_t head_len;

	uint32_t dtim_period = 3;
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);
	struct wiphy *wiphy = netdev_get_wiphy(ap->netdev);
	uint32_t hidden_ssid = NL80211_HIDDEN_SSID_NOT_IN_USE;
	unsigned int nl_ciphers_cnt = __builtin_popcount(ap->ciphers);
	uint32_t nl_ciphers[nl_ciphers_cnt];
	uint32_t group_nl_cipher =
		ie_rsn_cipher_suite_to_cipher(ap->group_cipher);
	uint32_t nl_akm = CRYPTO_AKM_PSK;
	uint32_t wpa_version = NL80211_WPA_VERSION_2;
	uint32_t auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;
	unsigned int i;

	static const uint8_t bcast_addr[6] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	static const uint8_t zero_addr[6] = { 0 };

	for (i = 0, nl_ciphers_cnt = 0; i < 8; i++)
		if (ap->ciphers & (1 << i))
			nl_ciphers[nl_ciphers_cnt++] =
				ie_rsn_cipher_suite_to_cipher(1 << i);

	head_len = ap_build_beacon_pr_head(ap, MPDU_MANAGEMENT_SUBTYPE_BEACON,
						bcast_addr, head, sizeof(head));
	tail_len = ap_build_beacon_pr_tail(ap, MPDU_MANAGEMENT_SUBTYPE_BEACON,
						NULL, 0, tail, tail_len);

	if (!head_len || !tail_len)
		return NULL;

	cmd = l_genl_msg_new_sized(NL80211_CMD_START_AP, 256 + head_len +
					tail_len + strlen(ap->ssid));

	/* SET_BEACON attrs */
	l_genl_msg_append_attr(cmd, NL80211_ATTR_BEACON_HEAD, head_len, head);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_BEACON_TAIL, tail_len, tail);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IE, 0, "");
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IE_PROBE_RESP, 0, "");
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IE_ASSOC_RESP, 0, "");

	/* START_AP attrs */
	l_genl_msg_append_attr(cmd, NL80211_ATTR_BEACON_INTERVAL, 4,
				&ap->beacon_interval);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_DTIM_PERIOD, 4, &dtim_period);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_SSID, strlen(ap->ssid),
				ap->ssid);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_HIDDEN_SSID, 4,
				&hidden_ssid);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
				nl_ciphers_cnt * 4, nl_ciphers);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_CIPHER_SUITE_GROUP, 4,
				&group_nl_cipher);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_WPA_VERSIONS, 4, &wpa_version);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_AKM_SUITES, 4, &nl_akm);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_WIPHY_FREQ, 4,
				&ap->chandef.frequency);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_CHANNEL_WIDTH, 4,
				&ap->chandef.channel_width);
	if (ap->chandef.center1_frequency)
		l_genl_msg_append_attr(cmd, NL80211_ATTR_CENTER_FREQ1, 4,
					&ap->chandef.center1_frequency);

	if (wiphy_supports_probe_resp_offload(wiphy)) {
		uint8_t probe_resp[head_len + tail_len];
		uint8_t *ptr = probe_resp;

		ptr += ap_build_beacon_pr_head(ap,
					MPDU_MANAGEMENT_SUBTYPE_PROBE_RESPONSE,
					zero_addr, ptr, sizeof(probe_resp));
		ptr += ap_build_beacon_pr_tail(ap,
					MPDU_MANAGEMENT_SUBTYPE_PROBE_RESPONSE,
					NULL, 0, ptr, sizeof(probe_resp) -
					(ptr - probe_resp));

		l_genl_msg_append_attr(cmd, NL80211_ATTR_PROBE_RESP,
					ptr - probe_resp, probe_resp);
	}

	if (wiphy_has_ext_feature(wiphy,
			NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211)) {
		l_genl_msg_append_attr(cmd, NL80211_ATTR_SOCKET_OWNER, 0, NULL);
		l_genl_msg_append_attr(cmd,
				NL80211_ATTR_CONTROL_PORT_OVER_NL80211,
				0, NULL);
	}

	return cmd;
}

static bool ap_start_send(struct ap_state *ap)
{
	struct l_genl_msg *cmd = ap_build_cmd_start_ap(ap);

	if (!cmd) {
		l_error("ap_build_cmd_start_ap failed");
		return false;
	}

	ap->start_stop_cmd_id = l_genl_family_send(ap->nl80211, cmd,
							ap_start_cb, ap, NULL);
	if (!ap->start_stop_cmd_id) {
		l_error("AP_START l_genl_family_send failed");
		l_genl_msg_unref(cmd);
		return false;
	}

	return true;
}

static void ap_ifaddr4_added_cb(int error, uint16_t type, const void *data,
				uint32_t len, void *user_data)
{
	struct ap_state *ap = user_data;

	ap->rtnl_add_cmd = 0;

	if (error) {
		l_error("Failed to set IP address");
		ap_start_failed(ap, error);
		return;
	}

	if (!ap_start_send(ap))
		ap_start_failed(ap, -EIO);
}

static bool ap_parse_new_station_ies(const void *data, uint16_t len,
					uint8_t **rsn_out,
					struct l_uintset **rates_out)
{
	struct ie_tlv_iter iter;
	uint8_t *rsn = NULL;
	struct l_uintset *rates = NULL;

	ie_tlv_iter_init(&iter, data, len);

	while (ie_tlv_iter_next(&iter)) {
		switch (ie_tlv_iter_get_tag(&iter)) {
		case IE_TYPE_RSN:
			if (rsn || ie_parse_rsne(&iter, NULL) < 0)
				goto parse_error;

			rsn = l_memdup(ie_tlv_iter_get_data(&iter) - 2,
					ie_tlv_iter_get_length(&iter) + 2);
			break;
		case IE_TYPE_EXTENDED_SUPPORTED_RATES:
			if (rates || ap_parse_supported_rates(&iter, &rates) <
					0)
				goto parse_error;

			break;
		}
	}

	*rsn_out = rsn;

	if (rates_out)
		*rates_out = rates;
	else
		l_uintset_free(rates);

	return true;

parse_error:
	if (rsn)
		l_free(rsn);

	if (rates)
		l_uintset_free(rates);

	return false;
}

static void ap_handle_new_station(struct ap_state *ap, struct l_genl_msg *msg)
{
	struct sta_state *sta;
	struct l_genl_attr attr;
	uint16_t type;
	uint16_t len;
	const void *data;
	uint8_t mac[6];
	uint8_t *assoc_rsne = NULL;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IE:
			if (assoc_rsne)
				goto cleanup;

			if (!ap_parse_new_station_ies(data, len, &assoc_rsne,
							NULL))
				return;
			break;
		case NL80211_ATTR_MAC:
			if (len != 6)
				goto cleanup;

			memcpy(mac, data, 6);
			break;
		}
	}

	if (!assoc_rsne)
		goto cleanup;

	/*
	 * Softmac's should already have a station created. The above check
	 * may also fail for softmac cards.
	 */
	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, mac);
	if (sta)
		goto cleanup;

	sta = l_new(struct sta_state, 1);
	memcpy(sta->addr, mac, 6);
	sta->ap = ap;
	sta->assoc_rsne = assoc_rsne;
	sta->aid = ++ap->last_aid;

	sta->associated = true;

	if (!ap->sta_states)
		ap->sta_states = l_queue_new();

	l_queue_push_tail(ap->sta_states, sta);

	if (ap->supports_ht)
		ap_update_beacon(ap);

	msg = nl80211_build_set_station_unauthorized(
					netdev_get_ifindex(ap->netdev), mac);

	if (!l_genl_family_send(ap->nl80211, msg, ap_associate_sta_cb,
								sta, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Issuing SET_STATION failed");
		ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED, true);
	}

	return;

cleanup:
	l_free(assoc_rsne);
}

static void ap_handle_del_station(struct ap_state *ap, struct l_genl_msg *msg)
{
	struct l_genl_attr attr;
	uint16_t type;
	uint16_t len;
	const void *data;
	uint8_t mac[6];
	uint16_t reason = MMPDU_REASON_CODE_UNSPECIFIED;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_MAC:
			if (len != 6)
				return;

			memcpy(mac, data, 6);
			break;
		case NL80211_ATTR_REASON_CODE:
			if (len != 2)
				return;

			reason = l_get_u16(data);
		}
	}

	ap_station_disconnect(ap, mac, reason);
}

static void ap_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct ap_state *ap = user_data;
	uint32_t ifindex;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_IFINDEX, &ifindex,
				NL80211_ATTR_UNSPEC) < 0 ||
			ifindex != netdev_get_ifindex(ap->netdev))
		return;

	switch (l_genl_msg_get_command(msg)) {
	case NL80211_CMD_STOP_AP:
		ap->in_event = true;

		if (ap->start_stop_cmd_id) {
			struct ap_event_start_failed_data data = { -ECANCELED };

			l_genl_family_cancel(ap->nl80211,
						ap->start_stop_cmd_id);
			ap->start_stop_cmd_id = 0;
			ap->ops->handle_event(AP_EVENT_START_FAILED, &data,
						ap->user_data);
		} else if (ap->started) {
			ap->started = false;
			ap->ops->handle_event(AP_EVENT_STOPPING, NULL,
						ap->user_data);
		}

		ap_reset(ap);
		l_genl_family_free(ap->nl80211);
		l_free(ap);
		break;
	case NL80211_CMD_NEW_STATION:
		ap_handle_new_station(ap, msg);
		break;
	case NL80211_CMD_DEL_STATION:
		ap_handle_del_station(ap, msg);
		break;
	}
}

static void ap_get_gateway4_mac_cb(int error, const uint8_t *hwaddr,
					size_t hwaddr_len, void *user_data)
{
	struct ap_state *ap = user_data;

	ap->rtnl_get_gateway4_mac_cmd = 0;

	if (error) {
		l_debug("Error: %s (%i)", strerror(-error), -error);
		return;
	}

	if (L_WARN_ON(unlikely(hwaddr_len != 6)))
		return;

	l_debug("Resolved mac to " MAC, MAC_STR(hwaddr));
	memcpy(ap->netconfig_gateway4_mac, hwaddr, 6);
}

static void ap_get_dns4_mac_cb(int error, const uint8_t *hwaddr,
					size_t hwaddr_len, void *user_data)
{
	struct ap_state *ap = user_data;

	ap->rtnl_get_dns4_mac_cmd = 0;

	if (error) {
		l_debug("Error: %s (%i)", strerror(-error), -error);
		return;
	}

	if (L_WARN_ON(unlikely(hwaddr_len != 6)))
		return;

	l_debug("Resolved mac to " MAC, MAC_STR(hwaddr));
	memcpy(ap->netconfig_dns4_mac, hwaddr, 6);
}

static void ap_query_macs(struct ap_state *ap, const char *addr_str,
				uint8_t prefix_len, const char *gateway_str,
				const char **dns_str_list)
{
	uint32_t local = IP4_FROM_STR(addr_str);
	uint32_t gateway = 0;
	uint32_t dns = 0;
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);

	/*
	 * For simplicity only check the ARP/NDP tables to see if we already
	 * have the MACs that we need.  There doesn't seem to be an API to
	 * actually resolve addresses that are not in these tables other than
	 * by triggering IP traffic to those hosts, such as a ping.  In a PC
	 * or mobile device scenario we're likely to have these MACs already,
	 * otherwise we give up as this is a pretty low-priority feature.
	 */

	if (gateway_str) {
		gateway = IP4_FROM_STR(gateway_str);
		if (L_WARN_ON(unlikely(!gateway)))
			return;

		if (gateway == local)
			memcpy(ap->netconfig_gateway4_mac,
				netdev_get_address(ap->netdev), 6);
		else {
			ap->rtnl_get_gateway4_mac_cmd =
				l_rtnl_neighbor_get_hwaddr(rtnl, ifindex,
							AF_INET, &gateway,
							ap_get_gateway4_mac_cb,
							ap, NULL);
			if (!ap->rtnl_get_gateway4_mac_cmd)
				l_debug("l_rtnl_neighbor_get_hwaddr() failed "
					"for the gateway IP");
		}
	}

	if (dns_str_list) {
		dns = IP4_FROM_STR(dns_str_list[0]);
		if (L_WARN_ON(unlikely(!dns)))
			return;

		/* TODO: can also skip query if dns == gateway */
		if (dns == local)
			memcpy(ap->netconfig_dns4_mac,
				netdev_get_address(ap->netdev), 6);
		else if (util_ip_subnet_match(prefix_len, &dns, &local)) {
			ap->rtnl_get_dns4_mac_cmd =
				l_rtnl_neighbor_get_hwaddr(rtnl, ifindex,
							AF_INET, &dns,
							ap_get_dns4_mac_cb,
							ap, NULL);
			if (!ap->rtnl_get_dns4_mac_cmd)
				l_debug("l_rtnl_neighbor_get_hwaddr() failed "
					"for the DNS IP");
		}
	}
}

#define AP_DEFAULT_IPV4_PREFIX_LEN 28

static int ap_setup_netconfig4(struct ap_state *ap, const char **addr_str_list,
				uint8_t prefix_len, const char *gateway_str,
				const char **ip_range,
				const char **dns_str_list,
				unsigned int lease_time)
{
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);
	struct l_rtnl_address *existing_addr = ip_pool_get_addr4(ifindex);
	struct l_rtnl_address *new_addr = NULL;
	int ret;
	struct in_addr ia;
	struct l_dhcp_server *dhcp = NULL;
	bool r;
	char addr_str_buf[INET_ADDRSTRLEN];

	dhcp = l_dhcp_server_new(ifindex);
	if (!dhcp) {
		l_error("Failed to create DHCP server on ifindex %u", ifindex);
		ret = -EIO;
		goto cleanup;
	}

	if (getenv("IWD_DHCP_DEBUG"))
		l_dhcp_server_set_debug(dhcp, do_debug,
					"[DHCPv4 SERV] ", NULL);

	/*
	 * The address pool specified for this AP (if any) has the priority,
	 * next is the address currently set on the interface (if any) and
	 * last is the global AP address pool (APRanges setting).
	 */
	if (addr_str_list) {
		if (!prefix_len)
			prefix_len = AP_DEFAULT_IPV4_PREFIX_LEN;

		ret = ip_pool_select_addr4(addr_str_list, prefix_len,
						&new_addr);
	} else if (existing_addr &&
			l_rtnl_address_get_prefix_length(existing_addr) <
			31) {
		if (!prefix_len)
			prefix_len = l_rtnl_address_get_prefix_length(
								existing_addr);

		if (!l_rtnl_address_get_address(existing_addr, addr_str_buf)) {
			ret = -EIO;
			goto cleanup;
		}

		new_addr = l_rtnl_address_new(addr_str_buf, prefix_len);
		ret = 0;
	} else {
		if (!prefix_len)
			prefix_len = AP_DEFAULT_IPV4_PREFIX_LEN;

		ret = ip_pool_select_addr4((const char **) global_addr4_strs,
						prefix_len, &new_addr);
	}

	if (ret)
		goto cleanup;

	ret = -EIO;

	/*
	 * l_dhcp_server_start() would retrieve the current IPv4 from
	 * the interface but set it anyway in case there are multiple
	 * addresses, saves one ioctl too.
	 */
	if (!l_rtnl_address_get_address(new_addr, addr_str_buf)) {
		l_error("l_rtnl_address_get_address failed");
		goto cleanup;
	}

	if (!l_dhcp_server_set_ip_address(dhcp, addr_str_buf)) {
		l_error("l_dhcp_server_set_ip_address failed");
		goto cleanup;
	}

	ia.s_addr = htonl(util_netmask_from_prefix(prefix_len));

	if (!l_dhcp_server_set_netmask(dhcp, inet_ntoa(ia))) {
		l_error("l_dhcp_server_set_netmask failed");
		goto cleanup;
	}

	if (gateway_str && !l_dhcp_server_set_gateway(dhcp, gateway_str)) {
		l_error("l_dhcp_server_set_gateway failed");
		goto cleanup;
	}

	if (ip_range) {
		r = l_dhcp_server_set_ip_range(dhcp, ip_range[0], ip_range[1]);
		if (!r) {
			l_error("l_dhcp_server_set_ip_range failed");
			goto cleanup;
		}
	}

	if (dns_str_list) {
		r = l_dhcp_server_set_dns(dhcp, (char **) dns_str_list);
		if (!r) {
			l_error("l_dhcp_server_set_dns failed");
			goto cleanup;
		}
	}

	if (lease_time && !l_dhcp_server_set_lease_time(dhcp, lease_time)) {
		l_error("l_dhcp_server_set_lease_time failed");
		goto cleanup;
	}

	ap->netconfig_set_addr4 = true;
	ap->netconfig_addr4 = l_steal_ptr(new_addr);
	ap->netconfig_dhcp = l_steal_ptr(dhcp);
	ret = 0;

	if (existing_addr && l_rtnl_address_get_prefix_length(existing_addr) >
			prefix_len) {
		char addr_str_buf2[INET_ADDRSTRLEN];

		if (l_rtnl_address_get_address(existing_addr, addr_str_buf2) &&
				!strcmp(addr_str_buf, addr_str_buf2))
			ap->netconfig_set_addr4 = false;
	}

	ap_query_macs(ap, addr_str_buf, prefix_len, gateway_str, dns_str_list);

cleanup:
	l_dhcp_server_destroy(dhcp);
	l_rtnl_address_free(new_addr);
	l_rtnl_address_free(existing_addr);
	return ret;
}

static int ap_load_ipv4(struct ap_state *ap, const struct l_settings *config)
{
	int ret = -EINVAL;
	char **addr_str_list = NULL;
	uint32_t static_addr = 0;
	uint8_t prefix_len = 0;
	char *gateway_str = NULL;
	char **ip_range = NULL;
	char **dns_str_list = NULL;
	unsigned int lease_time = 0;
	struct in_addr ia;

	if (!l_settings_has_group(config, "IPv4") || !netconfig_enabled())
		return 0;

	if (l_settings_has_key(config, "IPv4", "Address")) {
		addr_str_list = l_settings_get_string_list(config, "IPv4",
								"Address", ',');
		if (!addr_str_list || !*addr_str_list) {
			l_error("Can't parse the profile [IPv4].Address "
				"setting as a string list");
			goto done;
		}

		/* Check for the static IP syntax: Address=<IP> */
		if (l_strv_length(addr_str_list) == 1 &&
				inet_pton(AF_INET, *addr_str_list, &ia) == 1)
			static_addr = ntohl(ia.s_addr);
	}

	if (l_settings_has_key(config, "IPv4", "Netmask")) {
		L_AUTO_FREE_VAR(char *, netmask_str) =
			l_settings_get_string(config, "IPv4", "Netmask");

		if (inet_pton(AF_INET, netmask_str, &ia) != 1) {
			l_error("Can't parse the profile [IPv4].Netmask "
				"setting");
			goto done;
		}

		prefix_len = __builtin_popcount(ia.s_addr);

		if (ntohl(ia.s_addr) != util_netmask_from_prefix(prefix_len)) {
			l_error("Invalid profile [IPv4].Netmask value");
			goto done;
		}
	}

	if (l_settings_has_key(config, "IPv4", "Gateway")) {
		gateway_str = l_settings_get_string(config, "IPv4", "Gateway");
		if (!gateway_str) {
			l_error("Invalid profile [IPv4].Gateway value");
			goto done;
		}
	}

	if (l_settings_get_value(config, "IPv4", "IPRange")) {
		int i;
		uint32_t netmask;
		uint8_t tmp_len = prefix_len ?: AP_DEFAULT_IPV4_PREFIX_LEN;

		ip_range = l_settings_get_string_list(config, "IPv4",
							"IPRange", ',');

		if (!static_addr) {
			l_error("[IPv4].IPRange only makes sense in an AP "
				"profile if a static local address has also "
				"been specified");
			goto done;
		}

		if (!ip_range || l_strv_length(ip_range) != 2) {
			l_error("Can't parse the profile [IPv4].IPRange "
				"setting as two address strings");
			goto done;
		}

		netmask = util_netmask_from_prefix(tmp_len);

		for (i = 0; i < 2; i++) {
			struct in_addr range_addr;

			if (inet_pton(AF_INET, ip_range[i], &range_addr) != 1) {
				l_error("Can't parse address in "
					"[IPv4].IPRange[%i]", i + 1);
				goto done;
			}

			if ((static_addr ^ ntohl(range_addr.s_addr)) &
					netmask) {
				ia.s_addr = htonl(static_addr);
				l_error("[IPv4].IPRange[%i] is not in the "
					"%s/%i subnet", i + 1, inet_ntoa(ia),
					tmp_len);
				goto done;
			}
		}
	}

	if (l_settings_has_key(config, "IPv4", "DNSList")) {
		dns_str_list = l_settings_get_string_list(config, "IPv4",
								"DNSList", ',');
		if (!dns_str_list || !*dns_str_list) {
			l_error("Can't parse the profile [IPv4].DNSList "
				"setting as a string list");
			goto done;
		}
	}

	if (l_settings_has_key(config, "IPv4", "LeaseTime")) {
		if (!l_settings_get_uint(config, "IPv4", "LeaseTime",
						&lease_time) ||
				lease_time < 1) {
			l_error("Error parsing [IPv4].LeaseTime as a positive "
				"integer");
			goto done;
		}
	}

	ret = ap_setup_netconfig4(ap, (const char **) addr_str_list, prefix_len,
					gateway_str, (const char **) ip_range,
					(const char **) dns_str_list,
					lease_time);

done:
	l_strv_free(addr_str_list);
	l_free(gateway_str);
	l_strv_free(ip_range);
	l_strv_free(dns_str_list);
	return ret;
}

static bool ap_load_psk(struct ap_state *ap, const struct l_settings *config)
{
	L_AUTO_FREE_VAR(char *, passphrase) =
		l_settings_get_string(config, "Security", "Passphrase");
	int err;

	if (passphrase) {
		if (strlen(passphrase) > 63) {
			l_error("AP [Security].Passphrase must not exceed "
				"63 characters");
			return false;
		}

		strcpy(ap->passphrase, passphrase);
	}

	if (l_settings_has_key(config, "Security", "PreSharedKey")) {
		size_t psk_len;
		L_AUTO_FREE_VAR(uint8_t *, psk) = l_settings_get_bytes(config,
								"Security",
								"PreSharedKey",
								&psk_len);

		if (!psk || psk_len != 32) {
			l_error("AP [Security].PreSharedKey must be a 32-byte "
				"hexstring");
			return false;
		}

		memcpy(ap->psk, psk, 32);
		return true;
	}

	if (!passphrase) {
		l_error("AP requires at least one of [Security].PreSharedKey, "
			"[Security].Passphrase to be present");
		return false;
	}

	err = crypto_psk_from_passphrase(passphrase, (uint8_t *) ap->ssid,
						strlen(ap->ssid), ap->psk);
	if (err < 0) {
		l_error("AP couldn't generate the PSK from given "
			"[Security].Passphrase value: %s (%i)",
			strerror(-err), -err);
		return false;
	}

	return true;
}

/*
 * Note: only PTK/GTK ciphers are supported here since this is all these are
 *       used for.
 */
static enum ie_rsn_cipher_suite ap_string_to_cipher(const char *str)
{
	if (!strcmp(str, "UseGroupCipher"))
		return IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER;
	else if (!strcmp(str, "TKIP"))
		return IE_RSN_CIPHER_SUITE_TKIP;
	else if (!strcmp(str, "CCMP-128") || !strcmp(str, "CCMP"))
		return IE_RSN_CIPHER_SUITE_CCMP;
	else if (!strcmp(str, "GCMP-128") || !strcmp(str, "GCMP"))
		return IE_RSN_CIPHER_SUITE_GCMP;
	else if (!strcmp(str, "GCMP-256"))
		return IE_RSN_CIPHER_SUITE_GCMP_256;
	else if (!strcmp(str, "CCMP-256"))
		return IE_RSN_CIPHER_SUITE_CCMP_256;
	else
		return 0;
}

static char **ap_ciphers_to_strv(uint16_t ciphers)
{
	uint16_t i;
	char **list = l_strv_new();

	for (i = 0; i < 16; i++) {
		if (!(ciphers & (1 << i)))
			continue;

		list = l_strv_append(list,
					ie_rsn_cipher_suite_to_string(1 << i));
	}

	return list;
}

static bool ap_validate_band_channel(struct ap_state *ap)
{
	struct wiphy *wiphy = netdev_get_wiphy(ap->netdev);
	uint32_t freq;
	const struct band_freq_attrs *attr;

	if (!(wiphy_get_supported_bands(wiphy) & ap->band)) {
		l_error("AP hardware does not support band");
		return -EINVAL;
	}

	freq = band_channel_to_freq(ap->channel, ap->band);
	if (!freq) {
		l_error("AP invalid band (%s) and channel (%u) combination",
			(ap->band & BAND_FREQ_5_GHZ) ? "5Ghz" : "2.4GHz",
			ap->channel);
		return false;
	}

	attr = wiphy_get_frequency_info(wiphy, freq);
	if (!attr || attr->disabled) {
		l_error("AP frequency %u disabled or unsupported", freq);
		return false;
	}

	if (ap->supports_ht) {
		if (band_freq_to_ht_chandef(freq, attr, &ap->chandef) < 0) {
			/*
			 * This is unlikely ever to fail since there are no
			 * 20Mhz restrictions, but just in case fall back to
			 * non-HT.
			 */
			ap->supports_ht = false;

			l_warn("AP could not find HT chandef for frequency %u"
				" using 20Mhz no-HT", freq);

			goto no_ht;
		}
	} else {
no_ht:
		ap->chandef.frequency = freq;
		ap->chandef.channel_width = BAND_CHANDEF_WIDTH_20NOHT;
	}

	l_debug("AP using frequency %u and channel width %s",
			ap->chandef.frequency,
			band_chandef_width_to_string(
				ap->chandef.channel_width));

	return true;
}

static int ap_load_config(struct ap_state *ap, const struct l_settings *config,
				bool *out_cck_rates)
{
	struct wiphy *wiphy = netdev_get_wiphy(ap->netdev);
	size_t len;
	L_AUTO_FREE_VAR(char *, strval) = NULL;
	_auto_(l_strv_free) char **ciphers_str = NULL;
	uint16_t cipher_mask;
	int err;
	int i;

	strval = l_settings_get_string(config, "General", "SSID");
	if (L_WARN_ON(!strval))
		return -ENOMSG;

	len = strlen(strval);
	if (len < 1 || len > 32) {
		l_error("AP SSID length outside the [1, 32] range");
		return -EINVAL;
	}

	if (L_WARN_ON(!l_utf8_validate(strval, len, NULL)))
		return -EINVAL;

	strcpy(ap->ssid, strval);
	l_free(l_steal_ptr(strval));

	if (!ap_load_psk(ap, config))
		return -EINVAL;

	/*
	 * This looks at the network configuration settings in @config and
	 * relevant global settings and if it determines that netconfig is to
	 * be enabled for the AP, it both creates the DHCP server object and
	 * processes IP settings, applying the defaults where needed.
	 */
	err = ap_load_ipv4(ap, config);
	if (err)
		return err;

	if (l_settings_has_key(config, "General", "Channel")) {
		unsigned int uintval;

		if (!l_settings_get_uint(config, "General", "Channel",
						&uintval)) {
			l_error("AP Channel value unsupported");
			return -EINVAL;
		}

		ap->channel = uintval;

		/*
		 * 6GHz is not supported so we can use only a channel number to
		 * distinguish between 2.4 and 5GHz.
		 */
		if (ap->channel >= 36)
			ap->band = BAND_FREQ_5_GHZ;
		else
			ap->band = BAND_FREQ_2_4_GHZ;
	} else {
		/* TODO: Start a Get Survey to decide the channel */
		ap->channel = 6;
		ap->band = BAND_FREQ_2_4_GHZ;
	}

	ap->supports_ht = wiphy_get_ht_capabilities(wiphy, ap->band,
							NULL) != NULL;

	if (!ap_validate_band_channel(ap)) {
		l_error("AP Band and Channel combination invalid");
		return -EINVAL;
	}

	strval = l_settings_get_string(config, "WSC", "DeviceName");
	if (strval) {
		len = strlen(strval);

		if (len > 32) {
			l_error("AP WSC name length outside the [1, 32] range");
			return -EINVAL;
		}

		if (!l_utf8_validate(strval, len, NULL)) {
			l_error("AP WSC name doesn't validate as UTF-8");
			return -EINVAL;
		}

		strcpy(ap->wsc_name, strval);
		l_free(l_steal_ptr(strval));
	} else
		memcpy(ap->wsc_name, ap->ssid, 33);

	strval = l_settings_get_string(config, "WSC", "PrimaryDeviceType");
	if (strval) {
		bool ok = wsc_device_type_from_setting_str(strval,
						&ap->wsc_primary_device_type);

		if (!ok) {
			l_error("AP [WSC].PrimaryDeviceType format unknown");
			return -EINVAL;
		}

		l_free(l_steal_ptr(strval));
	} else {
		/* Make ourselves a WFA standard PC by default */
		ap->wsc_primary_device_type.category = 1;
		memcpy(ap->wsc_primary_device_type.oui, wsc_wfa_oui, 3);
		ap->wsc_primary_device_type.oui_type = 0x04;
		ap->wsc_primary_device_type.subcategory = 1;
	}

	if (l_settings_get_value(config, "WSC", "AuthorizedMACs")) {
		char **strvval;
		unsigned int i;

		strvval = l_settings_get_string_list(config, "WSC",
							"AuthorizedMACs", ',');
		if (!strvval) {
			l_error("AP Authorized MACs list format wrong");
			return -EINVAL;
		}

		ap->authorized_macs_num = l_strv_length(strvval);
		ap->authorized_macs = l_malloc(ap->authorized_macs_num * 6);

		for (i = 0; strvval[i]; i++)
			if (!util_string_to_address(strvval[i],
						ap->authorized_macs + i * 6)) {
				l_error("Bad authorized MAC format: %s",
					strvval[i]);
				l_strfreev(strvval);
				return -EINVAL;
			}

		l_strfreev(strvval);
	}

	/*
	 * Since 5GHz won't ever support only CCK rates we can ignore this
	 * setting on that band.
	 */
	if (ap->band & BAND_FREQ_5_GHZ)
		*out_cck_rates = false;
	else if (l_settings_get_value(config, "General", "NoCCKRates")) {
		bool boolval;

		if (!l_settings_get_bool(config, "General", "NoCCKRates",
						&boolval)) {
			l_error("AP [General].NoCCKRates not a valid "
				"boolean");
			return -EINVAL;
		}

		*out_cck_rates = !boolval;
	} else
		*out_cck_rates = true;

	cipher_mask = wiphy_get_supported_ciphers(wiphy, IE_GROUP_CIPHERS);

	/* If the config sets a group cipher use that directly */
	strval = l_settings_get_string(config, "Security", "GroupCipher");
	if (strval) {
		enum ie_rsn_cipher_suite cipher = ap_string_to_cipher(strval);

		if (!cipher || !(cipher & cipher_mask)) {
			l_error("Unsupported or unknown group cipher %s",
					strval);
			return -ENOTSUP;
		}

		ap->group_cipher = cipher;
		l_free(l_steal_ptr(strval));
	} else {
		/* No config override, use CCMP (or TKIP if not supported) */
		if (cipher_mask & IE_RSN_CIPHER_SUITE_CCMP)
			ap->group_cipher = IE_RSN_CIPHER_SUITE_CCMP;
		else
			ap->group_cipher = IE_RSN_CIPHER_SUITE_TKIP;
	}

	cipher_mask = wiphy_get_supported_ciphers(wiphy, IE_PAIRWISE_CIPHERS);

	ciphers_str = l_settings_get_string_list(config, "Security",
						"PairwiseCiphers", ',');
	for (i = 0; ciphers_str && ciphers_str[i]; i++) {
		enum ie_rsn_cipher_suite cipher =
					ap_string_to_cipher(ciphers_str[i]);

		/*
		 * Constrain list to only values in both supported ciphers and
		 * the cipher list provided.
		 */
		if (!cipher || !(cipher & cipher_mask)) {
			l_error("Unsupported or unknown pairwise cipher %s",
					ciphers_str[i]);
			return -ENOTSUP;
		}

		ap->ciphers |= cipher;
	}

	if (!ap->ciphers) {
		/*
		 * Default behavior if no ciphers are specified, disable TKIP
		 * for security if CCMP is available
		 */
		if (cipher_mask & IE_RSN_CIPHER_SUITE_CCMP)
			cipher_mask &= ~IE_RSN_CIPHER_SUITE_TKIP;

		ap->ciphers = cipher_mask;
	}

	return 0;
}

/*
 * Start a simple independent WPA2 AP on given netdev.
 *
 * @ops.handle_event is required and must react to AP_EVENT_START_FAILED
 * and AP_EVENT_STOPPING by forgetting the ap_state struct, which is
 * going to be freed automatically.
 * In the @config struct the [General].SSID key is required and one of
 * [Security].Passphrase and [Security].PreSharedKey must be filled in.
 * All other fields are optional.
 */
struct ap_state *ap_start(struct netdev *netdev, struct l_settings *config,
				const struct ap_ops *ops, int *err_out,
				void *user_data)
{
	struct ap_state *ap;
	struct wiphy *wiphy = netdev_get_wiphy(netdev);
	uint64_t wdev_id = netdev_get_wdev_id(netdev);
	int err;
	bool cck_rates = true;
	const uint8_t *rates;
	unsigned int num_rates;
	unsigned int i;

	if (L_WARN_ON(!config)) {
		if (err_out)
			*err_out = -EINVAL;

		return NULL;
	}

	ap = l_new(struct ap_state, 1);
	ap->nl80211 = l_genl_family_new(iwd_get_genl(), NL80211_GENL_NAME);
	ap->netdev = netdev;
	ap->ops = ops;
	ap->user_data = user_data;

	err = ap_load_config(ap, config, &cck_rates);
	if (err)
		goto error;

	err = -EINVAL;

	ap->beacon_interval = 100;
	ap->networks = l_queue_new();

	wsc_uuid_from_addr(netdev_get_address(netdev), ap->wsc_uuid_r);

	rates = wiphy_get_supported_rates(wiphy, ap->band, &num_rates);
	if (!rates)
		goto error;

	ap->rates = l_uintset_new(200);

	for (i = 0; i < num_rates; i++) {
		if (cck_rates && !L_IN_SET(rates[i], 2, 4, 11, 22))
			continue;

		l_uintset_put(ap->rates, rates[i]);
	}

	if (!frame_watch_add(wdev_id, 0, 0x0000 |
			(MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST << 4),
			NULL, 0, ap_assoc_req_cb, ap, NULL))
		goto error;

	if (!frame_watch_add(wdev_id, 0, 0x0000 |
			(MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_REQUEST << 4),
			NULL, 0, ap_reassoc_req_cb, ap, NULL))
		goto error;

	if (!wiphy_supports_probe_resp_offload(wiphy)) {
		if (!frame_watch_add(wdev_id, 0, 0x0000 |
				(MPDU_MANAGEMENT_SUBTYPE_PROBE_REQUEST << 4),
				NULL, 0, ap_probe_req_cb, ap, NULL))
			goto error;
	}

	if (!frame_watch_add(wdev_id, 0, 0x0000 |
				(MPDU_MANAGEMENT_SUBTYPE_DISASSOCIATION << 4),
				NULL, 0, ap_disassoc_cb, ap, NULL))
		goto error;

	if (!frame_watch_add(wdev_id, 0, 0x0000 |
				(MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION << 4),
				NULL, 0, ap_auth_cb, ap, NULL))
		goto error;

	if (!frame_watch_add(wdev_id, 0, 0x0000 |
				(MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION << 4),
				NULL, 0, ap_deauth_cb, ap, NULL))
		goto error;

	ap->mlme_watch = l_genl_family_register(ap->nl80211, "mlme",
						ap_mlme_notify, ap, NULL);
	if (!ap->mlme_watch)
		l_error("Registering for MLME notification failed");

	if (ap->netconfig_set_addr4) {
		ap->rtnl_add_cmd = l_rtnl_ifaddr_add(rtnl,
						netdev_get_ifindex(netdev),
						ap->netconfig_addr4,
						ap_ifaddr4_added_cb, ap, NULL);
		if (!ap->rtnl_add_cmd) {
			l_error("Failed to add the IPv4 address");
			goto error;
		}

		return ap;
	}

	if (ap_start_send(ap)) {
		if (err_out)
			*err_out = 0;

		return ap;
	}

error:
	if (err_out)
		*err_out = err;

	ap_reset(ap);
	l_genl_family_free(ap->nl80211);
	l_free(ap);
	return NULL;
}

static void ap_stop_cb(struct l_genl_msg *msg, void *user_data)
{
	struct ap_state *ap = user_data;
	int error = l_genl_msg_get_error(msg);

	ap->start_stop_cmd_id = 0;

	if (error < 0)
		l_error("STOP_AP failed: %s (%i)", strerror(-error), -error);

	if (ap->stopped_func)
		ap->stopped_func(ap->user_data);

	l_genl_family_free(ap->nl80211);
	l_free(ap);
}

static struct l_genl_msg *ap_build_cmd_stop_ap(struct ap_state *ap)
{
	struct l_genl_msg *cmd;
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);

	cmd = l_genl_msg_new_sized(NL80211_CMD_STOP_AP, 16);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IFINDEX, 4, &ifindex);

	return cmd;
}

/*
 * Schedule the running @ap to be stopped and freed.  The original
 * ops and user_data are forgotten and a new callback can be
 * provided if the caller needs to know when the interface becomes
 * free, for example for a new ap_start call.
 *
 * The user must forget @ap when @stopped_func is called.  If the
 * @user_data ends up being destroyed before that, ap_free(ap) should
 * be used to prevent @stopped_func from being called.
 * If @stopped_func is not provided, the caller must forget @ap
 * immediately.
 */
void ap_shutdown(struct ap_state *ap, ap_stopped_func_t stopped_func,
			void *user_data)
{
	struct l_genl_msg *cmd;

	if (ap->started) {
		ap->started = false;

		if (ap_event(ap, AP_EVENT_STOPPING, NULL))
			return;
	}

	ap_reset(ap);

	if (ap->gtk_set) {
		ap->gtk_set = false;

		cmd = ap_build_cmd_del_key(ap);
		if (!cmd) {
			l_error("ap_build_cmd_del_key failed");
			goto free_ap;
		}

		if (!l_genl_family_send(ap->nl80211, cmd, ap_gtk_op_cb, NULL,
					NULL)) {
			l_genl_msg_unref(cmd);
			l_error("Issuing DEL_KEY failed");
			goto free_ap;
		}
	}

	cmd = ap_build_cmd_stop_ap(ap);
	if (!cmd) {
		l_error("ap_build_cmd_stop_ap failed");
		goto free_ap;
	}

	ap->start_stop_cmd_id = l_genl_family_send(ap->nl80211, cmd, ap_stop_cb,
							ap, NULL);
	if (!ap->start_stop_cmd_id) {
		l_genl_msg_unref(cmd);
		l_error("Sending STOP_AP failed");
		goto free_ap;
	}

	ap->stopped_func = stopped_func;
	ap->user_data = user_data;
	return;

free_ap:
	if (stopped_func)
		stopped_func(user_data);

	l_genl_family_free(ap->nl80211);
	l_free(ap);
}

/* Free @ap without a graceful shutdown */
void ap_free(struct ap_state *ap)
{
	ap_reset(ap);

	if (ap->in_event) {
		ap->free_pending = true;
		return;
	}

	l_genl_family_free(ap->nl80211);
	l_free(ap);
}

bool ap_station_disconnect(struct ap_state *ap, const uint8_t *mac,
				enum mmpdu_reason_code reason)
{
	struct sta_state *sta;

	if (!ap->started)
		return false;

	sta = l_queue_remove_if(ap->sta_states, ap_sta_match_addr, mac);
	if (!sta)
		return false;

	if (ap->supports_ht)
		ap_update_beacon(ap);

	ap_del_station(sta, reason, false);
	ap_sta_free(sta);
	return true;
}

static void ap_wsc_pbc_timeout_cb(struct l_timeout *timeout, void *user_data)
{
	struct ap_state *ap = user_data;

	l_debug("PBC mode timeout");
	ap_wsc_exit_pbc(ap);
}

static void ap_wsc_pbc_timeout_destroy(void *user_data)
{
	struct ap_state *ap = user_data;

	ap->wsc_pbc_timeout = NULL;
}

bool ap_push_button(struct ap_state *ap)
{
	if (!ap->started)
		return false;

	if (l_queue_length(ap->wsc_pbc_probes) > 1) {
		l_debug("Can't start PBC mode due to Session Overlap");
		return false;
	}

	/*
	 * WSC v2.0.5 Section 11.3: "Multiple presses of the button are
	 * permitted.  If a PBC button on an Enrollee or Registrar is
	 * pressed again during Walk Time, the timers for that device are
	 * restarted at that time [...]"
	 */
	if (ap->wsc_pbc_timeout) {
		l_timeout_modify(ap->wsc_pbc_timeout, AP_WSC_PBC_WALK_TIME);
		return true;
	}

	ap->wsc_pbc_timeout = l_timeout_create(AP_WSC_PBC_WALK_TIME,
						ap_wsc_pbc_timeout_cb, ap,
						ap_wsc_pbc_timeout_destroy);
	ap->wsc_dpid = WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON;
	ap_update_beacon(ap);
	return true;
}

struct ap_if_data {
	struct netdev *netdev;
	struct ap_state *ap;
	struct l_dbus_message *pending;
};

static void ap_properties_changed(struct ap_if_data *ap_if)
{
	l_dbus_property_changed(dbus_get_bus(),
				netdev_get_path(ap_if->netdev),
				IWD_AP_INTERFACE, "Started");
	l_dbus_property_changed(dbus_get_bus(),
				netdev_get_path(ap_if->netdev),
				IWD_AP_INTERFACE, "Name");
	l_dbus_property_changed(dbus_get_bus(),
				netdev_get_path(ap_if->netdev),
				IWD_AP_INTERFACE, "Frequency");
	l_dbus_property_changed(dbus_get_bus(),
				netdev_get_path(ap_if->netdev),
				IWD_AP_INTERFACE, "PairwiseCiphers");
	l_dbus_property_changed(dbus_get_bus(),
				netdev_get_path(ap_if->netdev),
				IWD_AP_INTERFACE, "GroupCipher");
	l_dbus_property_changed(dbus_get_bus(),
				netdev_get_path(ap_if->netdev),
				IWD_AP_INTERFACE, "Scanning");
}

static void ap_if_event_func(enum ap_event_type type, const void *event_data,
				void *user_data)
{
	struct ap_if_data *ap_if = user_data;
	struct l_dbus_message *reply;

	switch (type) {
	case AP_EVENT_START_FAILED:
	{
		const struct ap_event_start_failed_data *data = event_data;

		if (L_WARN_ON(!ap_if->pending))
			break;

		reply = dbus_error_from_errno(data->error, ap_if->pending);
		dbus_pending_reply(&ap_if->pending, reply);
		ap_if->ap = NULL;
		break;
	}

	case AP_EVENT_STARTED:
		if (L_WARN_ON(!ap_if->pending))
			break;

		l_dbus_object_add_interface(dbus_get_bus(),
						netdev_get_path(ap_if->netdev),
						IWD_AP_DIAGNOSTIC_INTERFACE,
						ap_if);

		reply = l_dbus_message_new_method_return(ap_if->pending);
		dbus_pending_reply(&ap_if->pending, reply);

		ap_properties_changed(ap_if);

		l_rtnl_set_linkmode_and_operstate(rtnl,
					netdev_get_ifindex(ap_if->netdev),
					IF_LINK_MODE_DEFAULT, IF_OPER_UP,
					NULL, NULL, NULL);
		break;

	case AP_EVENT_STOPPING:
		l_dbus_object_remove_interface(dbus_get_bus(),
						netdev_get_path(ap_if->netdev),
						IWD_AP_DIAGNOSTIC_INTERFACE);

		ap_properties_changed(ap_if);

		l_rtnl_set_linkmode_and_operstate(rtnl,
					netdev_get_ifindex(ap_if->netdev),
					IF_LINK_MODE_DORMANT, IF_OPER_DOWN,
					NULL, NULL, NULL);

		if (!ap_if->pending)
			ap_if->ap = NULL;

		break;

	case AP_EVENT_STATION_ADDED:
	case AP_EVENT_STATION_REMOVED:
	case AP_EVENT_REGISTRATION_START:
	case AP_EVENT_REGISTRATION_SUCCESS:
	case AP_EVENT_PBC_MODE_EXIT:
	case AP_EVENT_DHCP_NEW_LEASE:
	case AP_EVENT_DHCP_LEASE_EXPIRED:
		/* Ignored */
		break;
	}
}

static const struct ap_ops ap_dbus_ops = {
	.handle_event = ap_if_event_func,
};

static struct l_dbus_message *ap_dbus_start(struct l_dbus *dbus,
		struct l_dbus_message *message, void *user_data)
{
	struct ap_if_data *ap_if = user_data;
	const char *ssid, *wpa2_passphrase;
	struct l_settings *config;
	int err;

	if (ap_if->ap && ap_if->ap->started)
		return dbus_error_already_exists(message);

	if (ap_if->ap || ap_if->pending)
		return dbus_error_busy(message);

	if (!l_dbus_message_get_arguments(message, "ss",
						&ssid, &wpa2_passphrase))
		return dbus_error_invalid_args(message);

	config = l_settings_new();
	l_settings_set_string(config, "General", "SSID", ssid);
	l_settings_set_string(config, "Security", "Passphrase",
				wpa2_passphrase);
	l_settings_add_group(config, "IPv4");

	ap_if->ap = ap_start(ap_if->netdev, config, &ap_dbus_ops, &err, ap_if);
	l_settings_free(config);

	if (!ap_if->ap)
		return dbus_error_from_errno(err, message);

	ap_if->pending = l_dbus_message_ref(message);
	return NULL;
}

static void ap_dbus_stop_cb(void *user_data)
{
	struct ap_if_data *ap_if = user_data;
	struct l_dbus_message *reply;

	if (L_WARN_ON(!ap_if->pending))
		return;

	reply = l_dbus_message_new_method_return(ap_if->pending);
	dbus_pending_reply(&ap_if->pending, reply);
	ap_if->ap = NULL;
}

static struct l_dbus_message *ap_dbus_stop(struct l_dbus *dbus,
		struct l_dbus_message *message, void *user_data)
{
	struct ap_if_data *ap_if = user_data;

	if (!ap_if->ap) {
		if (ap_if->pending)
			return dbus_error_busy(message);

		/* already stopped, no-op */
		return l_dbus_message_new_method_return(message);
	}

	if (ap_if->pending) {
		struct l_dbus_message *reply;

		reply = dbus_error_aborted(ap_if->pending);
		dbus_pending_reply(&ap_if->pending, reply);
	}

	ap_if->pending = l_dbus_message_ref(message);
	ap_shutdown(ap_if->ap, ap_dbus_stop_cb, ap_if);
	return NULL;
}

static struct l_dbus_message *ap_dbus_start_profile(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct ap_if_data *ap_if = user_data;
	const char *ssid;
	_auto_(l_settings_free) struct l_settings *config = NULL;
	char *config_path;
	int err;

	if (ap_if->ap && ap_if->ap->started)
		return dbus_error_already_exists(message);

	if (ap_if->ap || ap_if->pending)
		return dbus_error_busy(message);

	if (!l_dbus_message_get_arguments(message, "s", &ssid))
		return dbus_error_invalid_args(message);

	config = l_settings_new();
	config_path = storage_get_path("ap/%s.ap", ssid);
	err = l_settings_load_from_file(config, config_path) ? 0 : -EIO;
	l_free(config_path);

	if (err)
		goto error;

	/*
	 * Since [General].SSID is not an allowed setting for a profile on
	 * disk, we're free to potentially overwrite it with the SSID that
	 * the DBus user asked for.
	 */
	l_settings_set_string(config, "General", "SSID", ssid);

	ap_if->ap = ap_start(ap_if->netdev, config, &ap_dbus_ops, &err, ap_if);
	if (!ap_if->ap)
		goto error;

	ap_if->pending = l_dbus_message_ref(message);
	return NULL;

error:
	return dbus_error_from_errno(err, message);
}

static void ap_set_scanning(struct ap_state *ap, bool scanning)
{
	if (ap->scanning == scanning)
		return;

	ap->scanning = scanning;

	l_dbus_property_changed(dbus_get_bus(), netdev_get_path(ap->netdev),
					IWD_AP_INTERFACE, "Scanning");
}

static void ap_scan_triggered(int err, void *user_data)
{
	struct ap_state *ap = user_data;
	struct l_dbus_message *reply;

	if (err < 0) {
		reply = dbus_error_from_errno(err, ap->scan_pending);
		dbus_pending_reply(&ap->scan_pending, reply);
		return;
	}

	l_debug("AP scan triggered for %s", netdev_get_name(ap->netdev));

	reply = l_dbus_message_new_method_return(ap->scan_pending);
	l_dbus_message_set_arguments(reply, "");
	dbus_pending_reply(&ap->scan_pending, reply);

	ap_set_scanning(ap, true);
}

static bool ap_scan_notify(int err, struct l_queue *bss_list,
				const struct scan_freq_set *freqs,
				void *user_data)
{
	struct ap_state *ap = user_data;
	const struct l_queue_entry *bss_entry;

	ap_set_scanning(ap, false);

	/* Remove all networks, then re-populate with fresh BSS list */
	l_queue_clear(ap->networks, l_free);

	for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
						bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;

		ap_network_append(ap, bss);
	}

	l_debug("");

	return false;
}

static void ap_scan_destroy(void *user_data)
{
	struct ap_state *ap = user_data;

	ap->scan_id = 0;
}

static struct l_dbus_message *ap_dbus_scan(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct ap_if_data *ap_if = user_data;
	uint64_t wdev_id = netdev_get_wdev_id(ap_if->netdev);
	struct scan_parameters params = { 0};

	if (wiphy_has_feature(wiphy_find_by_wdev(wdev_id),
				NL80211_FEATURE_AP_SCAN))
		params.ap_scan = true;

	/*
	 * TODO: There is really nothing preventing scanning while stopped.
	 *       The only consideration would be if a scan is ongoing and the
	 *       AP is started. Queuing Start() as wiphy work may be required to
	 *       handle this case if needed. For now just limit to started APs.
	 */
	if (!ap_if->ap || !ap_if->ap->started)
		return dbus_error_not_available(message);

	if (ap_if->ap->scan_id)
		return dbus_error_busy(message);

	ap_if->ap->scan_id = scan_active_full(wdev_id, &params,
						ap_scan_triggered,
						ap_scan_notify,
						ap_if->ap, ap_scan_destroy);
	if (!ap_if->ap->scan_id)
		return dbus_error_failed(message);

	ap_if->ap->scan_pending = l_dbus_message_ref(message);

	return NULL;
}

static void dbus_append_network(struct l_dbus_message_builder *builder,
					struct ap_network *network)
{
	l_dbus_message_builder_enter_array(builder, "{sv}");
	dbus_append_dict_basic(builder, "Name", 's', network->ssid);
	dbus_append_dict_basic(builder, "SignalStrength", 'n',
					&network->signal);
	dbus_append_dict_basic(builder, "Type", 's',
					security_to_str(network->security));
	l_dbus_message_builder_leave_array(builder);
}

static struct l_dbus_message *ap_dbus_get_networks(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct ap_if_data *ap_if = user_data;
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;
	const struct l_queue_entry *entry;

	if (!ap_if->ap || !ap_if->ap->started)
		return dbus_error_not_available(message);

	reply = l_dbus_message_new_method_return(message);
	builder = l_dbus_message_builder_new(reply);

	l_dbus_message_builder_enter_array(builder, "a{sv}");

	for (entry = l_queue_get_entries(ap_if->ap->networks); entry;
							entry = entry->next) {
		struct ap_network *network = entry->data;

		dbus_append_network(builder, network);
	}

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static bool ap_dbus_property_get_started(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct ap_if_data *ap_if = user_data;
	bool started = ap_if->ap && ap_if->ap->started;

	l_dbus_message_builder_append_basic(builder, 'b', &started);

	return true;
}

static bool ap_dbus_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct ap_if_data *ap_if = user_data;

	if (!ap_if->ap || !ap_if->ap->started)
		return false;

	l_dbus_message_builder_append_basic(builder, 's',
						ap_if->ap->ssid);

	return true;
}

static bool ap_dbus_property_get_scanning(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct ap_if_data *ap_if = user_data;
	bool bval;

	if (!ap_if->ap || !ap_if->ap->started)
		return false;

	bval = ap_if->ap->scanning;

	l_dbus_message_builder_append_basic(builder, 'b', &bval);

	return true;
}

static bool ap_dbus_property_get_freq(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct ap_if_data *ap_if = user_data;
	uint32_t freq;

	if (!ap_if->ap || !ap_if->ap->started)
		return false;

	freq = band_channel_to_freq(ap_if->ap->channel, ap_if->ap->band);

	l_dbus_message_builder_append_basic(builder, 'u', &freq);

	return true;
}

static bool ap_dbus_property_get_pairwise(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct ap_if_data *ap_if = user_data;
	char **ciphers;
	size_t i;

	if (!ap_if->ap || !ap_if->ap->started)
		return false;

	ciphers = ap_ciphers_to_strv(ap_if->ap->ciphers);

	l_dbus_message_builder_enter_array(builder, "s");

	for (i = 0; ciphers[i]; i++)
		l_dbus_message_builder_append_basic(builder, 's', ciphers[i]);

	l_dbus_message_builder_leave_array(builder);

	l_strv_free(ciphers);

	return true;
}

static bool ap_dbus_property_get_group(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct ap_if_data *ap_if = user_data;
	char **cipher;

	if (!ap_if->ap || !ap_if->ap->started)
		return false;

	cipher = ap_ciphers_to_strv(ap_if->ap->group_cipher);

	/* Group cipher will only ever be a single value */
	l_dbus_message_builder_append_basic(builder, 's', cipher[0]);
	l_strv_free(cipher);

	return true;
}

static void ap_setup_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Start", 0, ap_dbus_start, "",
			"ss", "ssid", "wpa2_passphrase");
	l_dbus_interface_method(interface, "Stop", 0, ap_dbus_stop, "", "");
	l_dbus_interface_method(interface, "StartProfile", 0,
					ap_dbus_start_profile, "", "s",
					"ssid");
	l_dbus_interface_method(interface, "Scan", 0, ap_dbus_scan, "", "");
	l_dbus_interface_method(interface, "GetOrderedNetworks", 0,
					ap_dbus_get_networks, "aa{sv}",
					"", "networks");

	l_dbus_interface_property(interface, "Started", 0, "b",
					ap_dbus_property_get_started, NULL);
	l_dbus_interface_property(interface, "Name", 0, "s",
					ap_dbus_property_get_name, NULL);
	l_dbus_interface_property(interface, "Scanning", 0, "b",
					ap_dbus_property_get_scanning, NULL);
	l_dbus_interface_property(interface, "Frequency", 0, "u",
					ap_dbus_property_get_freq, NULL);
	l_dbus_interface_property(interface, "PairwiseCiphers", 0, "as",
					ap_dbus_property_get_pairwise, NULL);
	l_dbus_interface_property(interface, "GroupCipher", 0, "s",
					ap_dbus_property_get_group, NULL);
}

static void ap_destroy_interface(void *user_data)
{
	struct ap_if_data *ap_if = user_data;

	if (ap_if->pending) {
		struct l_dbus_message *reply;

		reply = dbus_error_aborted(ap_if->pending);
		dbus_pending_reply(&ap_if->pending, reply);
	}

	if (ap_if->ap)
		ap_free(ap_if->ap);

	l_free(ap_if);
}

struct diagnostic_data {
	struct l_dbus_message *pending;
	struct l_dbus_message_builder *builder;
};

static void ap_get_station_cb(const struct diagnostic_station_info *info,
				void *user_data)
{
	struct diagnostic_data *data = user_data;

	/* First station info */
	if (!data->builder) {
		struct l_dbus_message *reply =
				l_dbus_message_new_method_return(data->pending);

		data->builder = l_dbus_message_builder_new(reply);

		l_dbus_message_builder_enter_array(data->builder, "a{sv}");
	}

	l_dbus_message_builder_enter_array(data->builder, "{sv}");
	dbus_append_dict_basic(data->builder, "Address", 's',
					util_address_to_string(info->addr));

	diagnostic_info_to_dict(info, data->builder);

	l_dbus_message_builder_leave_array(data->builder);
}

static void ap_get_station_destroy(void *user_data)
{
	struct diagnostic_data *data = user_data;
	struct l_dbus_message *reply;

	if (!data->builder) {
		reply = l_dbus_message_new_method_return(data->pending);

		data->builder = l_dbus_message_builder_new(reply);

		l_dbus_message_builder_enter_array(data->builder, "a{sv}");
	}

	l_dbus_message_builder_leave_array(data->builder);
	reply = l_dbus_message_builder_finalize(data->builder);
	l_dbus_message_builder_destroy(data->builder);

	dbus_pending_reply(&data->pending, reply);

	l_free(data);
}

static struct l_dbus_message *ap_dbus_get_diagnostics(struct l_dbus *dbus,
		struct l_dbus_message *message, void *user_data)
{
	struct ap_if_data *ap_if = user_data;
	struct diagnostic_data *data;
	int ret;

	data = l_new(struct diagnostic_data, 1);
	data->pending = l_dbus_message_ref(message);

	ret = netdev_get_all_stations(ap_if->ap->netdev, ap_get_station_cb,
					data, ap_get_station_destroy);

	if (ret < 0) {
		l_dbus_message_unref(data->pending);
		l_free(data);
		return dbus_error_from_errno(ret, message);
	}

	return NULL;
}

static void ap_setup_diagnostic_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "GetDiagnostics", 0,
				ap_dbus_get_diagnostics,
				"aa{sv}", "", "diagnostic");
}

static void ap_diagnostic_interface_destroy(void *user_data)
{
}

static void ap_add_interface(struct netdev *netdev)
{
	struct ap_if_data *ap_if;

	/*
	 * TODO: Check wiphy supported channels and NL80211_ATTR_TX_FRAME_TYPES
	 */

	/* just allocate/set device, Start method will complete setup */
	ap_if = l_new(struct ap_if_data, 1);
	ap_if->netdev = netdev;

	/* setup ap dbus interface */
	l_dbus_object_add_interface(dbus_get_bus(),
			netdev_get_path(netdev), IWD_AP_INTERFACE, ap_if);
}

static void ap_remove_interface(struct netdev *netdev)
{
	l_dbus_object_remove_interface(dbus_get_bus(),
			netdev_get_path(netdev), IWD_AP_INTERFACE);
	l_dbus_object_remove_interface(dbus_get_bus(),
			netdev_get_path(netdev), IWD_AP_DIAGNOSTIC_INTERFACE);
}

static void ap_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
	case NETDEV_WATCH_EVENT_NEW:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_AP &&
				netdev_get_is_up(netdev))
			ap_add_interface(netdev);
		break;
	case NETDEV_WATCH_EVENT_DOWN:
	case NETDEV_WATCH_EVENT_DEL:
		ap_remove_interface(netdev);
		break;
	default:
		break;
	}
}

static int ap_init(void)
{
	const struct l_settings *settings = iwd_get_config();

	netdev_watch = netdev_watch_add(ap_netdev_watch, NULL, NULL);

	l_dbus_register_interface(dbus_get_bus(), IWD_AP_INTERFACE,
			ap_setup_interface, ap_destroy_interface, false);
	l_dbus_register_interface(dbus_get_bus(), IWD_AP_DIAGNOSTIC_INTERFACE,
			ap_setup_diagnostic_interface,
			ap_diagnostic_interface_destroy, false);

	/*
	 * Enable network configuration and DHCP only if
	 * [General].EnableNetworkConfiguration is true.
	 */
	if (netconfig_enabled()) {
		global_addr4_strs =
			l_settings_get_string_list(settings, "IPv4",
							"APAddressPool", ',');
		if (global_addr4_strs && !global_addr4_strs[0]) {
			l_error("Can't parse the [IPv4].APAddressPool "
					"setting as a string list");
			l_strv_free(global_addr4_strs);
			global_addr4_strs = NULL;
		}

		/* Fall back to 192.168.0.0/16 */
		if (!global_addr4_strs)
			global_addr4_strs =
				l_strv_append(NULL, "192.168.0.0/16");
	}

	rtnl = iwd_get_rtnl();

	return 0;
}

static void ap_exit(void)
{
	netdev_watch_remove(netdev_watch);
	l_dbus_unregister_interface(dbus_get_bus(), IWD_AP_INTERFACE);

	l_strv_free(global_addr4_strs);
}

IWD_MODULE(ap, ap_init, ap_exit)
IWD_MODULE_DEPENDS(ap, netdev);
