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

#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <linux/if.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/module.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/crypto.h"
#include "src/ie.h"
#include "src/util.h"
#include "src/eapol.h"
#include "src/handshake.h"
#include "src/mpdu.h"
#include "src/dbus.h"
#include "src/nl80211util.h"

struct adhoc_state {
	struct netdev *netdev;
	struct l_genl_family *nl80211;
	char *ssid;
	uint8_t pmk[32];
	struct l_queue *sta_states;
	uint32_t sta_watch_id;
	uint32_t netdev_watch_id;
	unsigned int mlme_watch;
	struct l_dbus_message *pending;
	uint32_t ciphers;
	uint32_t group_cipher;
	uint8_t gtk[CRYPTO_MAX_GTK_LEN];
	uint8_t gtk_index;
	bool started : 1;
	bool open : 1;
	bool gtk_set : 1;
};

struct sta_state {
	uint8_t addr[6];
	struct adhoc_state *adhoc;
	struct eapol_sm *sm;
	struct handshake_state *hs_sta;
	struct eapol_sm *sm_a;
	struct handshake_state *hs_auth;
	uint32_t gtk_query_cmd_id;
	bool hs_sta_done : 1;
	bool hs_auth_done : 1;
	bool authenticated : 1;
};

static uint32_t netdev_watch;

static void adhoc_sta_free(void *data)
{
	struct sta_state *sta = data;

	if (sta->adhoc->open)
		goto end;

	if (sta->gtk_query_cmd_id)
		l_genl_family_cancel(sta->adhoc->nl80211,
						sta->gtk_query_cmd_id);

	if (sta->sm)
		eapol_sm_free(sta->sm);

	if (sta->hs_sta)
		handshake_state_free(sta->hs_sta);

	if (sta->sm_a)
		eapol_sm_free(sta->sm_a);

	if (sta->hs_auth)
		handshake_state_free(sta->hs_auth);

end:
	l_free(sta);
}

static void adhoc_remove_sta(struct sta_state *sta)
{
	if (!l_queue_remove(sta->adhoc->sta_states, sta)) {
		l_error("station %p was not found", sta);
		return;
	}

	if (sta->gtk_query_cmd_id) {
		l_genl_family_cancel(sta->adhoc->nl80211,
						sta->gtk_query_cmd_id);
		sta->gtk_query_cmd_id = 0;
	}

	/* signal station has been removed */
	if (sta->authenticated) {
		l_dbus_property_changed(dbus_get_bus(),
				netdev_get_path(sta->adhoc->netdev),
				IWD_ADHOC_INTERFACE, "ConnectedPeers");
	}

	adhoc_sta_free(sta);
}

static void adhoc_reset(struct adhoc_state *adhoc)
{
	if (adhoc->pending)
		dbus_pending_reply(&adhoc->pending,
				dbus_error_aborted(adhoc->pending));

	l_free(adhoc->ssid);
	adhoc->ssid = NULL;

	netdev_station_watch_remove(adhoc->netdev, adhoc->sta_watch_id);
	adhoc->sta_watch_id = 0;

	l_queue_destroy(adhoc->sta_states, adhoc_sta_free);
	adhoc->sta_states = NULL;

	adhoc->started = false;

	l_dbus_property_changed(dbus_get_bus(), netdev_get_path(adhoc->netdev),
						IWD_ADHOC_INTERFACE, "Started");

	if (adhoc->mlme_watch)
		l_genl_family_unregister(adhoc->nl80211, adhoc->mlme_watch);
}

static void adhoc_set_rsn_info(struct adhoc_state *adhoc,
						struct ie_rsn_info *rsn)
{
	memset(rsn, 0, sizeof(*rsn));
	rsn->akm_suites = IE_RSN_AKM_SUITE_PSK;
	rsn->pairwise_ciphers = adhoc->ciphers;
	rsn->group_cipher = adhoc->group_cipher;
}

static bool ap_sta_match_addr(const void *a, const void *b)
{
	const struct sta_state *sta = a;

	return !memcmp(sta->addr, b, 6);
}

static void adhoc_operstate_cb(int error, uint16_t type,
					const void *data,
					uint32_t len, void *user_data)
{
	if (!error)
		return;

	l_debug("netdev: %u, error: %s", L_PTR_TO_UINT(user_data),
							strerror(-error));
}

static void adhoc_handshake_event(struct handshake_state *hs,
		enum handshake_event event, void *user_data, ...)
{
	struct sta_state *sta = user_data;
	struct adhoc_state *adhoc = sta->adhoc;
	va_list args;

	switch (event) {
	case HANDSHAKE_EVENT_FAILED:
		va_start(args, user_data);

		l_error("handshake failed with STA "MAC" (%d)",
						MAC_STR(sta->addr),
						va_arg(args, int));

		va_end(args);
		/*
		 * eapol frees the state machines upon handshake failure. Since
		 * this is only a failure on one of the handshakes we need to
		 * set the failing SM to NULL so it will not get double freed
		 * by adhoc_remove_sta.
		 */
		if (sta->hs_auth == hs)
			sta->sm_a = NULL;
		else
			sta->sm = NULL;

		/* fall through */
	case HANDSHAKE_EVENT_SETTING_KEYS_FAILED:
		adhoc_remove_sta(sta);

		return;
	case HANDSHAKE_EVENT_COMPLETE:
		if (sta->hs_auth == hs)
			sta->hs_auth_done = true;

		if (sta->hs_sta == hs)
			sta->hs_sta_done = true;

		if ((sta->hs_auth_done && sta->hs_sta_done) &&
				!sta->authenticated) {
			sta->authenticated = true;
			l_dbus_property_changed(dbus_get_bus(),
					netdev_get_path(adhoc->netdev),
					IWD_ADHOC_INTERFACE, "ConnectedPeers");
		}
		break;
	default:
		break;
	}
}

static struct eapol_sm *adhoc_new_sm(struct sta_state *sta, bool authenticator,
					const uint8_t *gtk_rsc)
{
	struct adhoc_state *adhoc = sta->adhoc;
	struct netdev *netdev = adhoc->netdev;
	const uint8_t *own_addr = netdev_get_address(netdev);
	struct ie_rsn_info rsn;
	uint8_t bss_rsne[24];
	struct handshake_state *hs;
	struct eapol_sm *sm;

	/* fill in only what handshake setup requires */
	adhoc_set_rsn_info(adhoc, &rsn);
	ie_build_rsne(&rsn, bss_rsne);

	hs = netdev_handshake_state_new(netdev);
	if (!hs) {
		l_error("could not create handshake object");
		return NULL;
	}

	handshake_state_set_event_func(hs, adhoc_handshake_event, sta);
	handshake_state_set_ssid(hs, (void *)adhoc->ssid, strlen(adhoc->ssid));
	/* we don't have the connecting peer rsn info, so just set ap == own */
	handshake_state_set_authenticator_ie(hs, bss_rsne);
	handshake_state_set_supplicant_ie(hs, bss_rsne);
	handshake_state_set_pmk(hs, adhoc->pmk, 32);

	if (authenticator) {
		handshake_state_set_authenticator_address(hs, own_addr);
		handshake_state_set_supplicant_address(hs, sta->addr);
		handshake_state_set_authenticator(hs, true);
	} else {
		handshake_state_set_authenticator_address(hs, sta->addr);
		handshake_state_set_supplicant_address(hs, own_addr);
	}

	if (gtk_rsc)
		handshake_state_set_gtk(hs, adhoc->gtk, adhoc->gtk_index,
					gtk_rsc);

	sm = eapol_sm_new(hs);
	if (!sm) {
		l_error("could not create sm object");
		return NULL;
	}

	eapol_sm_set_listen_interval(sm, 100);

	if (authenticator)
		sta->hs_auth = hs;
	else
		sta->hs_sta = hs;

	return sm;
}

static void adhoc_free(struct adhoc_state *adhoc)
{
	adhoc_reset(adhoc);
	l_genl_family_free(adhoc->nl80211);
	l_free(adhoc);
}

static void adhoc_start_rsna(struct sta_state *sta, const uint8_t *gtk_rsc)
{
	sta->sm_a = adhoc_new_sm(sta, true, gtk_rsc);
	if (!sta->sm_a) {
		l_error("could not create authenticator state machine");
		goto failed;
	}

	sta->sm = adhoc_new_sm(sta, false, NULL);
	if (!sta->sm) {
		l_error("could not create station state machine");
		goto failed;
	}

	eapol_register(sta->sm);
	eapol_register(sta->sm_a);

	eapol_start(sta->sm);
	eapol_start(sta->sm_a);

	return;

failed:
	adhoc_remove_sta(sta);
}

static void adhoc_gtk_op_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0) {
		uint8_t cmd = l_genl_msg_get_command(msg);
		const char *cmd_name =
			cmd == NL80211_CMD_NEW_KEY ? "NEW_KEY" : "SET_KEY";

		l_error("%s failed for the GTK: %i",
			cmd_name, l_genl_msg_get_error(msg));
	}
}

static void adhoc_gtk_query_cb(struct l_genl_msg *msg, void *user_data)
{
	struct sta_state *sta = user_data;
	const void *gtk_rsc;

	sta->gtk_query_cmd_id = 0;

	gtk_rsc = nl80211_parse_get_key_seq(msg);
	if (!gtk_rsc)
		goto error;

	adhoc_start_rsna(sta, gtk_rsc);
	return;

error:
	adhoc_remove_sta(sta);
}

static void adhoc_new_station(struct adhoc_state *adhoc, const uint8_t *mac)
{
	struct sta_state *sta;
	struct l_genl_msg *msg;

	sta = l_queue_find(adhoc->sta_states, ap_sta_match_addr, mac);
	if (sta) {
		l_warn("new station event with already connected STA");
		return;
	}

	/*
	 * Follows same logic as AP. If this is the first station we create and
	 * set a group key. Any subsequent connections will use GET_KEY for this
	 * tx GTK.
	 */
	if (adhoc->group_cipher != IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC &&
			!adhoc->gtk_set && !adhoc->open) {
		enum crypto_cipher group_cipher =
			ie_rsn_cipher_suite_to_cipher(adhoc->group_cipher);
		int gtk_len = crypto_cipher_key_len(group_cipher);

		/*
		 * Generate our GTK.  Not following the example derivation
		 * method in 802.11-2016 section 12.7.1.4 because a simple
		 * l_getrandom is just as good.
		 */
		l_getrandom(adhoc->gtk, gtk_len);
		adhoc->gtk_index = 1;

		msg = nl80211_build_new_key_group(
					netdev_get_ifindex(adhoc->netdev),
					group_cipher, adhoc->gtk_index,
					adhoc->gtk, gtk_len, NULL,
					0, NULL);

		if (!l_genl_family_send(adhoc->nl80211, msg, adhoc_gtk_op_cb,
					NULL, NULL)) {
			l_genl_msg_unref(msg);
			l_error("Issuing NEW_KEY failed");
			return;
		}

		msg = nl80211_build_set_key(netdev_get_ifindex(adhoc->netdev),
						adhoc->gtk_index);
		if (!l_genl_family_send(adhoc->nl80211, msg, adhoc_gtk_op_cb,
					NULL, NULL)) {
			l_genl_msg_unref(msg);
			l_error("Issuing SET_KEY failed");
			return;
		}

		/*
		 * Set the flag now because any new associating STA will
		 * just use NL80211_CMD_GET_KEY from now.
		 */
		adhoc->gtk_set = true;
	}

	sta = l_new(struct sta_state, 1);

	memset(sta, 0, sizeof(struct sta_state));

	memcpy(sta->addr, mac, 6);
	sta->adhoc = adhoc;

	l_queue_push_tail(adhoc->sta_states, sta);

	l_info("new Station: "MAC" adhoc=%p", MAC_STR(mac), adhoc);

	/* with open networks nothing else is required */
	if (sta->adhoc->open) {
		int ifindex = netdev_get_ifindex(adhoc->netdev);

		sta->authenticated = true;

		l_rtnl_set_linkmode_and_operstate(iwd_get_rtnl(), ifindex,
					IF_LINK_MODE_DORMANT, IF_OPER_UP,
					adhoc_operstate_cb,
					L_UINT_TO_PTR(ifindex), NULL);

		l_dbus_property_changed(dbus_get_bus(),
					netdev_get_path(adhoc->netdev),
					IWD_ADHOC_INTERFACE, "ConnectedPeers");
		return;
	}

	if (adhoc->group_cipher == IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC)
		adhoc_start_rsna(sta, NULL);
	else {
		msg = nl80211_build_get_key(netdev_get_ifindex(adhoc->netdev),
					adhoc->gtk_index);
		sta->gtk_query_cmd_id = l_genl_family_send(adhoc->nl80211, msg,
							adhoc_gtk_query_cb,
							sta, NULL);
		if (!sta->gtk_query_cmd_id) {
			l_genl_msg_unref(msg);
			l_error("Issuing GET_KEY failed");

			adhoc_remove_sta(sta);
			return;
		}
	}
}

static void adhoc_del_station(struct adhoc_state *adhoc, const uint8_t *mac)
{
	struct sta_state *sta;

	sta = l_queue_find(adhoc->sta_states, ap_sta_match_addr, mac);
	if (!sta) {
		l_warn("could not find station "MAC" in list", MAC_STR(mac));
		return;
	}

	l_debug("lost station "MAC, MAC_STR(mac));

	adhoc_remove_sta(sta);
}

static void adhoc_station_changed_cb(struct netdev *netdev,
		const uint8_t *mac, bool added, void *user_data)
{
	struct adhoc_state *adhoc = user_data;

	if (added)
		adhoc_new_station(adhoc, mac);
	else
		adhoc_del_station(adhoc, mac);
}

static void adhoc_join_cb(struct netdev *netdev, int result, void *user_data)
{
	struct adhoc_state *adhoc = user_data;
	struct l_dbus_message *reply;

	if (result < 0) {
		l_error("Failed to join adhoc network, %i", result);
		dbus_pending_reply(&adhoc->pending,
					dbus_error_failed(adhoc->pending));
		return;
	}

	l_rtnl_set_linkmode_and_operstate(iwd_get_rtnl(),
					netdev_get_ifindex(adhoc->netdev),
					IF_LINK_MODE_DEFAULT, IF_OPER_UP,
					NULL, NULL, NULL);

	adhoc->sta_watch_id = netdev_station_watch_add(netdev,
			adhoc_station_changed_cb, adhoc);

	reply = l_dbus_message_new_method_return(adhoc->pending);
	dbus_pending_reply(&adhoc->pending, reply);
}

static void adhoc_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct adhoc_state *adhoc = user_data;
	uint32_t ifindex;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_IFINDEX, &ifindex,
				NL80211_ATTR_UNSPEC) < 0 ||
			ifindex != netdev_get_ifindex(adhoc->netdev))
		return;

	switch (l_genl_msg_get_command(msg)) {
	case NL80211_CMD_JOIN_IBSS:
		/*
		 * if watch is set the join_ibss_cb has come back. This event
		 * will come in for each new STA joining the IBSS so we only
		 * want to set it once
		 */
		if (adhoc->sta_watch_id && !adhoc->started) {
			adhoc->started = true;

			l_dbus_property_changed(dbus_get_bus(),
						netdev_get_path(adhoc->netdev),
						IWD_ADHOC_INTERFACE, "Started");
		}

		break;
	}
}

static struct l_dbus_message *adhoc_dbus_start(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct adhoc_state *adhoc = user_data;
	struct netdev *netdev = adhoc->netdev;
	struct wiphy *wiphy = netdev_get_wiphy(netdev);
	const char *ssid, *wpa2_psk;
	struct ie_rsn_info rsn;
	struct iovec rsn_ie;
	uint8_t ie_elems[32];

	if (adhoc->pending)
		return dbus_error_busy(message);

	if (!l_dbus_message_get_arguments(message, "ss", &ssid, &wpa2_psk))
		return dbus_error_invalid_args(message);

	adhoc->ssid = l_strdup(ssid);
	adhoc->pending = l_dbus_message_ref(message);
	adhoc->sta_states = l_queue_new();
	adhoc->ciphers = wiphy_select_cipher(wiphy, 0xffff);
	adhoc->group_cipher = wiphy_select_cipher(wiphy, 0xffff);

	adhoc_set_rsn_info(adhoc, &rsn);
	ie_build_rsne(&rsn, ie_elems);

	rsn_ie.iov_base = ie_elems;
	rsn_ie.iov_len = ie_elems[1] + 2;

	if (crypto_psk_from_passphrase(wpa2_psk, (uint8_t *) ssid,
			strlen(ssid), adhoc->pmk))
		return dbus_error_invalid_args(message);

	if (netdev_join_adhoc(netdev, ssid, &rsn_ie, 1, true, adhoc_join_cb,
			adhoc))
		return dbus_error_invalid_args(message);

	adhoc->mlme_watch = l_genl_family_register(adhoc->nl80211, "mlme",
						adhoc_mlme_notify, adhoc, NULL);
	if (!adhoc->mlme_watch)
		return dbus_error_failed(message);

	return NULL;
}

static struct l_dbus_message *adhoc_dbus_start_open(struct l_dbus *dbus,
				struct l_dbus_message *message, void *user_data)
{
	struct adhoc_state *adhoc = user_data;
	struct netdev *netdev = adhoc->netdev;
	const char *ssid;
	struct iovec rsn_ie;
	uint8_t ie_elems[10];

	if (adhoc->pending)
		return dbus_error_busy(message);

	if (!l_dbus_message_get_arguments(message, "s", &ssid))
		return dbus_error_invalid_args(message);

	adhoc->ssid = l_strdup(ssid);
	adhoc->pending = l_dbus_message_ref(message);
	adhoc->sta_states = l_queue_new();
	adhoc->open = true;

	/* Mac/iPhone seem to require the extended capabilities field */
	memset(ie_elems, 0, sizeof(ie_elems));
	ie_elems[0] = IE_TYPE_EXTENDED_CAPABILITIES;
	ie_elems[1] = 8;

	rsn_ie.iov_base = ie_elems;
	rsn_ie.iov_len = ie_elems[1] + 2;

	if (netdev_join_adhoc(netdev, ssid, &rsn_ie, 1, false, adhoc_join_cb,
			adhoc))
		return dbus_error_invalid_args(message);

	adhoc->mlme_watch = l_genl_family_register(adhoc->nl80211, "mlme",
						adhoc_mlme_notify, adhoc, NULL);
	if (!adhoc->mlme_watch)
		return dbus_error_failed(message);

	return NULL;
}

static void adhoc_leave_cb(struct netdev *netdev, int result, void *user_data)
{
	struct adhoc_state *adhoc = user_data;

	if (result < 0) {
		l_error("Failed to leave adhoc network, %i", result);
		dbus_pending_reply(&adhoc->pending,
				dbus_error_failed(adhoc->pending));
		return;
	}

	dbus_pending_reply(&adhoc->pending,
			l_dbus_message_new_method_return(adhoc->pending));

	adhoc_reset(adhoc);
}

static struct l_dbus_message *adhoc_dbus_stop(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct adhoc_state *adhoc = user_data;

	if (adhoc->pending)
		return dbus_error_busy(message);

	/* already stopped, no-op */
	if (!adhoc->started)
		return l_dbus_message_new_method_return(message);

	if (netdev_leave_adhoc(adhoc->netdev, adhoc_leave_cb, adhoc))
		return dbus_error_failed(message);

	l_rtnl_set_linkmode_and_operstate(iwd_get_rtnl(),
					netdev_get_ifindex(adhoc->netdev),
					IF_LINK_MODE_DORMANT, IF_OPER_DOWN,
					NULL, NULL, NULL);

	adhoc->pending = l_dbus_message_ref(message);

	return NULL;
}

static void sta_append(void *data, void *user_data)
{
	struct sta_state *sta = data;
	struct l_dbus_message_builder *builder = user_data;
	const char *macstr;

	if (!sta->authenticated)
		return;

	macstr = util_address_to_string(sta->addr);

	l_dbus_message_builder_append_basic(builder, 's', macstr);
}

static bool adhoc_property_get_peers(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct adhoc_state *adhoc = user_data;

	l_dbus_message_builder_enter_array(builder, "s");

	l_queue_foreach(adhoc->sta_states, sta_append, builder);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool adhoc_property_get_started(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct adhoc_state *adhoc = user_data;
	bool started = adhoc->started;

	l_dbus_message_builder_append_basic(builder, 'b', &started);

	return true;
}

static void adhoc_setup_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Start", 0, adhoc_dbus_start, "",
					"ss", "ssid", "wpa2_psk");
	l_dbus_interface_method(interface, "Stop", 0, adhoc_dbus_stop, "", "");
	l_dbus_interface_method(interface, "StartOpen", 0,
					adhoc_dbus_start_open, "", "s", "ssid");
	l_dbus_interface_property(interface, "ConnectedPeers", 0, "as",
					adhoc_property_get_peers, NULL);
	l_dbus_interface_property(interface, "Started", 0, "b",
					adhoc_property_get_started, NULL);
}

static void adhoc_destroy_interface(void *user_data)
{
	struct adhoc_state *adhoc = user_data;

	adhoc_free(adhoc);
}

static void adhoc_add_interface(struct netdev *netdev)
{
	struct adhoc_state *adhoc;

	/* just allocate/set device, Start method will complete setup */
	adhoc = l_new(struct adhoc_state, 1);
	adhoc->netdev = netdev;
	adhoc->nl80211 = l_genl_family_new(iwd_get_genl(), NL80211_GENL_NAME);

	/* setup adhoc dbus interface */
	l_dbus_object_add_interface(dbus_get_bus(),
			netdev_get_path(netdev), IWD_ADHOC_INTERFACE, adhoc);
}

static void adhoc_remove_interface(struct netdev *netdev)
{
	l_dbus_object_remove_interface(dbus_get_bus(),
			netdev_get_path(netdev), IWD_ADHOC_INTERFACE);
}

static void adhoc_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
	case NETDEV_WATCH_EVENT_NEW:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_ADHOC &&
				netdev_get_is_up(netdev))
			adhoc_add_interface(netdev);
		break;
	case NETDEV_WATCH_EVENT_DOWN:
	case NETDEV_WATCH_EVENT_DEL:
		adhoc_remove_interface(netdev);
		break;
	default:
		break;
	}
}

static int adhoc_init(void)
{
	netdev_watch = netdev_watch_add(adhoc_netdev_watch, NULL, NULL);
	l_dbus_register_interface(dbus_get_bus(), IWD_ADHOC_INTERFACE,
			adhoc_setup_interface, adhoc_destroy_interface, false);

	return 0;
}

static void adhoc_exit(void)
{
	netdev_watch_remove(netdev_watch);
	l_dbus_unregister_interface(dbus_get_bus(), IWD_ADHOC_INTERFACE);
}

IWD_MODULE(adhoc, adhoc_init, adhoc_exit)
IWD_MODULE_DEPENDS(adhoc, netdev);
