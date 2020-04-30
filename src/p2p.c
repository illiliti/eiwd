/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
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
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/wiphy.h"
#include "src/scan.h"
#include "src/p2putil.h"
#include "src/ie.h"
#include "src/util.h"
#include "src/dbus.h"
#include "src/netdev.h"
#include "src/mpdu.h"
#include "src/common.h"
#include "src/wsc.h"
#include "src/handshake.h"
#include "src/crypto.h"
#include "src/module.h"
#include "src/frame-xchg.h"
#include "src/nl80211util.h"
#include "src/netconfig.h"
#include "src/p2p.h"

struct p2p_device {
	uint64_t wdev_id;
	uint8_t addr[6];
	struct l_genl_family *nl80211;
	struct wiphy *wiphy;
	unsigned int connections_left;
	struct p2p_capability_attr capability;
	struct p2p_device_info_attr device_info;
	uint32_t start_stop_cmd_id;
	l_dbus_property_complete_cb_t pending_complete;
	struct l_dbus_message *pending_message;

	uint8_t listen_country[3];
	uint8_t listen_oper_class;
	uint32_t listen_channel;
	unsigned int scan_interval;
	time_t next_scan_ts;
	struct l_timeout *scan_timeout;
	uint32_t scan_id;
	unsigned int chans_per_scan;
	unsigned int scan_chan_idx;
	uint64_t roc_cookie;
	unsigned int listen_duration;
	struct l_queue *discovery_users;
	struct l_queue *peer_list;

	struct p2p_peer *conn_peer;
	uint16_t conn_config_method;
	char *conn_pin;
	uint8_t conn_addr[6];
	uint16_t conn_password_id;
	unsigned int conn_num;
	struct scan_bss *conn_wsc_bss;
	struct netdev *conn_netdev;
	uint32_t conn_netdev_watch_id;
	uint32_t conn_new_intf_cmd_id;
	struct wsc_enrollee *conn_enrollee;
	struct netconfig *conn_netconfig;
	struct l_timeout *conn_dhcp_timeout;

	struct l_timeout *config_timeout;
	unsigned long go_config_delay;
	struct l_timeout *go_neg_req_timeout;
	uint8_t go_dialog_token;
	unsigned int go_scan_retry;
	uint32_t go_oper_freq;
	struct p2p_group_id_attr go_group_id;
	uint8_t go_interface_addr[6];

	bool enabled : 1;
	bool have_roc_cookie : 1;
	/*
	 * We need to track @disconnecting because while a connect action is
	 * always triggered by a DBus message, meaning that @pending_message
	 * is going to be non-NULL, a disconnect may also be a result of an
	 * error at a layer higher than netdev and may last until
	 * netdev_disconnect, or similar, finishes.
	 */
	bool disconnecting : 1;
};

struct p2p_discovery_user {
	char *client;
	struct p2p_device *dev;
	unsigned int disconnect_watch;
};

struct p2p_peer {
	struct scan_bss *bss;
	struct p2p_device *dev;
	struct wsc_dbus wsc;
	char *name;
	struct wsc_primary_device_type primary_device_type;
	const uint8_t *device_addr;
	/* Whether peer is currently a GO */
	bool group;
};

static struct l_queue *p2p_device_list;
static struct l_settings *p2p_dhcp_settings;

/*
 * For now we only scan the common 2.4GHz channels, to be replaced with
 * a query of actual allowed channels per band and reg-domain.
 */
static const int channels_social[] = { 1, 6, 11 };
static const int channels_scan_2_4_other[] = { 2, 3, 4, 5, 7, 8, 9, 10 };

enum {
	FRAME_GROUP_DEFAULT = 0,
	FRAME_GROUP_LISTEN,
	FRAME_GROUP_CONNECT,
};

static bool p2p_device_match(const void *a, const void *b)
{
	const struct p2p_device *dev = a;
	const uint64_t *wdev_id = b;

	return dev->wdev_id == *wdev_id;
}

struct p2p_device *p2p_device_find(uint64_t wdev_id)
{
	return l_queue_find(p2p_device_list, p2p_device_match, &wdev_id);
}

static const char *p2p_device_get_path(const struct p2p_device *dev)
{
	return wiphy_get_path(dev->wiphy);
}

static bool p2p_discovery_user_match(const void *a, const void *b)
{
	const struct p2p_discovery_user *user = a;

	return !strcmp(user->client, b);
}

static void p2p_discovery_user_free(void *data)
{
	struct p2p_discovery_user *user = data;

	if (user->disconnect_watch)
		l_dbus_remove_watch(dbus_get_bus(), user->disconnect_watch);

	l_free(user->client);
	l_free(user);
}

static inline bool p2p_peer_operational(struct p2p_peer *peer)
{
	return peer && peer->dev->conn_netdev && !peer->dev->conn_wsc_bss &&
		!peer->dev->conn_dhcp_timeout && !peer->wsc.pending_connect &&
		!peer->dev->disconnecting;
}

static bool p2p_peer_match(const void *a, const void *b)
{
	const struct p2p_peer *peer = a;
	const uint8_t *addr = b;

	return !memcmp(peer->bss->addr, addr, 6);
}

static const char *p2p_peer_get_path(const struct p2p_peer *peer)
{
	static char path[256];

	snprintf(path, sizeof(path),
			"%s/p2p_peers/%02x_%02x_%02x_%02x_%02x_%02x",
			p2p_device_get_path(peer->dev),
			peer->bss->addr[0], peer->bss->addr[1],
			peer->bss->addr[2], peer->bss->addr[3],
			peer->bss->addr[4], peer->bss->addr[5]);
	return path;
}

static void p2p_peer_free(void *user_data)
{
	struct p2p_peer *peer = user_data;

	scan_bss_free(peer->bss);
	l_free(peer->name);
	l_free(peer);
}

static void p2p_peer_put(void *user_data)
{
	struct p2p_peer *peer = user_data;

	/* Removes both interfaces, no need to call wsc_dbus_remove_interface */
	l_dbus_unregister_object(dbus_get_bus(), p2p_peer_get_path(peer));
	p2p_peer_free(peer);
}

static void p2p_device_discovery_start(struct p2p_device *dev);
static void p2p_device_discovery_stop(struct p2p_device *dev);

/* TODO: convert to iovecs */
static uint8_t *p2p_build_scan_ies(struct p2p_device *dev, uint8_t *buf,
					size_t buf_len, size_t *out_len)
{
	struct p2p_probe_req p2p_info = {};
	struct wsc_probe_request wsc_info = {};
	L_AUTO_FREE_VAR(uint8_t *, p2p_ie) = NULL;
	size_t p2p_ie_size;
	uint8_t *wsc_data;
	size_t wsc_data_size;
	L_AUTO_FREE_VAR(uint8_t *, wsc_ie) = NULL;
	size_t wsc_ie_size;

	p2p_info.capability = dev->capability;
	memcpy(p2p_info.listen_channel.country, dev->listen_country, 3);
	p2p_info.listen_channel.oper_class = dev->listen_oper_class;
	p2p_info.listen_channel.channel_num = dev->listen_channel;

	/*
	 * Note that through an attribute we can also request Group Owners
	 * to send us info on clients within their groups and could also
	 * show those on D-Bus.  Doesn't seem useful at this time but may
	 * be desired at some point.
	 */

	p2p_ie = p2p_build_probe_req(&p2p_info, &p2p_ie_size);
	if (!p2p_ie)
		return NULL;

	wsc_info.version2 = true;
	wsc_info.request_type = WSC_REQUEST_TYPE_ENROLLEE_INFO;
	wsc_info.config_methods = dev->device_info.wsc_config_methods;

	if (!wsc_uuid_from_addr(dev->addr, wsc_info.uuid_e))
		return NULL;

	wsc_info.primary_device_type = dev->device_info.primary_device_type;
	wsc_info.rf_bands = WSC_RF_BAND_2_4_GHZ;
	wsc_info.association_state = WSC_ASSOCIATION_STATE_NOT_ASSOCIATED;
	wsc_info.configuration_error = WSC_CONFIGURATION_ERROR_NO_ERROR;
	wsc_info.device_password_id = WSC_DEVICE_PASSWORD_ID_DEFAULT;
	l_strlcpy(wsc_info.device_name, dev->device_info.device_name,
			sizeof(wsc_info.device_name));

	wsc_data = wsc_build_probe_request(&wsc_info, &wsc_data_size);
	if (!wsc_data)
		return NULL;

	wsc_ie = ie_tlv_encapsulate_wsc_payload(wsc_data, wsc_data_size,
						&wsc_ie_size);
	l_free(wsc_data);

	if (!wsc_ie)
		return NULL;

	/* WFD and other service IEs go here */

	if (buf_len < wsc_ie_size + p2p_ie_size)
		return NULL;

	memcpy(buf + 0, wsc_ie, wsc_ie_size);
	memcpy(buf + wsc_ie_size, p2p_ie, p2p_ie_size);
	*out_len = wsc_ie_size + p2p_ie_size;
	return buf;
}

static void p2p_connection_reset(struct p2p_device *dev)
{
	struct p2p_peer *peer = dev->conn_peer;

	if (!peer)
		return;

	/*
	 * conn_peer is currently not refcounted and we make sure it's always
	 * on the dev->peer_list so we can just drop our reference.  Since we
	 * may not have been scanning for a while, don't drop the peer object
	 * now just because it's not been seen in scan results recently, its
	 * age will be checked on the next scan.
	 */
	dev->conn_peer = NULL;
	dev->disconnecting = false;
	dev->connections_left++;

	if (dev->conn_pin) {
		explicit_bzero(dev->conn_pin, strlen(dev->conn_pin));
		l_free(dev->conn_pin);
		dev->conn_pin = NULL;
	}

	l_dbus_property_changed(dbus_get_bus(), p2p_device_get_path(dev),
				IWD_P2P_INTERFACE, "AvailableConnections");

	l_timeout_remove(dev->config_timeout);
	l_timeout_remove(dev->go_neg_req_timeout);
	l_timeout_remove(dev->conn_dhcp_timeout);

	if (dev->conn_netconfig) {
		netconfig_destroy(dev->conn_netconfig);
		dev->conn_netconfig = NULL;
	}

	if (dev->conn_new_intf_cmd_id)
		/*
		 * Note this may result in the interface being created
		 * and unused, we don't have its ifindex or wdev_id here
		 * to be able to delete it.  Could use a separate netlink
		 * socket for each connection or disallowing .Disconnect
		 * calls while this command runs.
		 */
		l_genl_family_cancel(dev->nl80211, dev->conn_new_intf_cmd_id);

	if (dev->conn_enrollee)
		wsc_enrollee_cancel(dev->conn_enrollee, false);

	if (dev->conn_netdev) {
		struct l_genl_msg *msg;
		uint64_t wdev_id = netdev_get_wdev_id(dev->conn_netdev);

		msg = l_genl_msg_new(NL80211_CMD_DEL_INTERFACE);
		l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &wdev_id);

		if (!l_genl_family_send(dev->nl80211, msg, NULL, NULL, NULL)) {
			l_genl_msg_unref(msg);
			l_error("Sending DEL_INTERFACE for %s failed",
				netdev_get_name(dev->conn_netdev));
		}

		netdev_destroy(dev->conn_netdev);
		dev->conn_netdev = NULL;
	}

	/*
	 * Removing the netdev above makes sure that both the WSC connection
	 * and the final WPA2 connection (wsc.c and netdev.c) no longer need
	 * the bss so we can free it now -- if it wasn't freed as a result
	 * of wsc_enrollee_cancel or netdev_destroy triggering
	 * p2p_peer_provision_done in the first place.
	 */
	if (dev->conn_wsc_bss) {
		scan_bss_free(dev->conn_wsc_bss);
		dev->conn_wsc_bss = NULL;
	}

	netdev_watch_remove(dev->conn_netdev_watch_id);

	frame_watch_group_remove(dev->wdev_id, FRAME_GROUP_CONNECT);
	frame_xchg_stop(dev->wdev_id);

	if (!dev->enabled || (dev->enabled && dev->start_stop_cmd_id)) {
		/*
		 * The device has been disabled in the mean time, all peers
		 * have been removed except this one.  Now it's safe to
		 * drop this peer from the scan results too.
		 */
		l_queue_destroy(dev->peer_list, p2p_peer_put);
		dev->peer_list = NULL;
	}

	if (dev->enabled && !dev->start_stop_cmd_id &&
			!l_queue_isempty(dev->discovery_users))
		p2p_device_discovery_start(dev);
}

static void p2p_connect_failed(struct p2p_device *dev)
{
	struct p2p_peer *peer = dev->conn_peer;

	if (!peer)
		return;

	/* Are we in the scan for the WSC provision bss */
	if (dev->scan_id)
		scan_cancel(dev->wdev_id, dev->scan_id);

	if (peer->wsc.pending_connect)
		dbus_pending_reply(&peer->wsc.pending_connect,
				dbus_error_failed(peer->wsc.pending_connect));

	p2p_connection_reset(dev);
}

static void p2p_peer_frame_xchg(struct p2p_peer *peer, struct iovec *tx_body,
				const uint8_t *bssid,
				unsigned int retry_interval,
				unsigned int resp_timeout,
				unsigned int retries_on_ack, bool own_channel,
				uint32_t group_id, frame_xchg_cb_t cb, ...)
{
	struct p2p_device *dev = peer->dev;
	struct iovec *frame;
	const struct iovec *iov;
	struct mmpdu_header *header;
	uint8_t header_buf[32] __attribute__ ((aligned));
	int iov_cnt;
	uint32_t freq;
	va_list args;

	/* Header */
	memset(header_buf, 0, sizeof(header_buf));
	header = (void *) header_buf;
	header->fc.protocol_version = 0;
	header->fc.type = MPDU_TYPE_MANAGEMENT;
	header->fc.subtype = MPDU_MANAGEMENT_SUBTYPE_ACTION;
	/* Section 2.4.3 */
	memcpy(header->address_1, peer->device_addr, 6);	/* DA */
	memcpy(header->address_2, dev->addr, 6);		/* SA */
	memcpy(header->address_3, bssid, 6);			/* BSSID */

	for (iov = tx_body, iov_cnt = 0; iov->iov_base; iov++)
		iov_cnt++;

	frame = l_new(struct iovec, iov_cnt + 2);
	frame[0].iov_base = header_buf;
	frame[0].iov_len = (const uint8_t *) mmpdu_body(header) - header_buf;
	memcpy(frame + 1, tx_body, sizeof(struct iovec) * iov_cnt);

	freq = own_channel ?
		scan_channel_to_freq(dev->listen_channel, SCAN_BAND_2_4_GHZ) :
		peer->bss->frequency;

	va_start(args, cb);
	frame_xchg_startv(dev->wdev_id, frame, freq, retry_interval,
				resp_timeout, retries_on_ack, group_id,
				cb, dev, args);
	va_end(args);

	l_free(frame);
}

static const struct frame_xchg_prefix p2p_frame_go_neg_req = {
	/* Management -> Public Action -> P2P -> GO Negotiation Request */
	.data = (uint8_t []) {
		0x04, 0x09, 0x50, 0x6f, 0x9a, 0x09,
		P2P_ACTION_GO_NEGOTIATION_REQ
	},
	.len = 7,
};

static const struct frame_xchg_prefix p2p_frame_go_neg_resp = {
	/* Management -> Public Action -> P2P -> GO Negotiation Response */
	.data = (uint8_t []) {
		0x04, 0x09, 0x50, 0x6f, 0x9a, 0x09,
		P2P_ACTION_GO_NEGOTIATION_RESP
	},
	.len = 7,
};

static const struct frame_xchg_prefix p2p_frame_go_neg_confirm = {
	/* Management -> Public Action -> P2P -> GO Negotiation Confirm */
	.data = (uint8_t []) {
		0x04, 0x09, 0x50, 0x6f, 0x9a, 0x09,
		P2P_ACTION_GO_NEGOTIATION_CONFIRM
	},
	.len = 7,
};

static const struct frame_xchg_prefix p2p_frame_pd_resp = {
	/* Management -> Public Action -> P2P -> Provision Discovery Response */
	.data = (uint8_t []) {
		0x04, 0x09, 0x50, 0x6f, 0x9a, 0x09,
		P2P_ACTION_PROVISION_DISCOVERY_RESP
	},
	.len = 7,
};

static void p2p_netconfig_event_handler(enum netconfig_event event,
					void *user_data)
{
	struct p2p_device *dev = user_data;
	struct p2p_peer *peer = dev->conn_peer;

	switch (event) {
	case NETCONFIG_EVENT_CONNECTED:
		l_timeout_remove(dev->conn_dhcp_timeout);

		dbus_pending_reply(&peer->wsc.pending_connect,
					l_dbus_message_new_method_return(
						peer->wsc.pending_connect));
		l_dbus_property_changed(dbus_get_bus(),
					p2p_peer_get_path(dev->conn_peer),
					IWD_P2P_PEER_INTERFACE, "Connected");

		break;
	default:
		l_error("station: Unsupported netconfig event: %d.", event);
		p2p_connect_failed(dev);
		break;
	}
}

static void p2p_dhcp_timeout(struct l_timeout *timeout, void *user_data)
{
	struct p2p_device *dev = user_data;

	l_debug("");

	p2p_connect_failed(dev);
}

static void p2p_dhcp_timeout_destroy(void *user_data)
{
	struct p2p_device *dev = user_data;

	dev->conn_dhcp_timeout = NULL;
}

static void p2p_start_dhcp(struct p2p_device *dev)
{
	uint32_t ifindex = netdev_get_ifindex(dev->conn_netdev);
	unsigned int dhcp_timeout_val;

	if (!l_settings_get_uint(iwd_get_config(), "P2P", "DHCPTimeout",
					&dhcp_timeout_val))
		dhcp_timeout_val = 10;	/* 10s default */

	dev->conn_netconfig = netconfig_new(ifindex);
	if (!dev->conn_netconfig) {
		p2p_connect_failed(dev);
		return;
	}

	netconfig_configure(dev->conn_netconfig, p2p_dhcp_settings,
				dev->conn_addr, p2p_netconfig_event_handler,
				dev);
	dev->conn_dhcp_timeout = l_timeout_create(dhcp_timeout_val,
						p2p_dhcp_timeout, dev,
						p2p_dhcp_timeout_destroy);
}

static void p2p_netdev_connect_cb(struct netdev *netdev,
					enum netdev_result result,
					void *event_data, void *user_data)
{
	struct p2p_device *dev = user_data;
	struct p2p_peer *peer = dev->conn_peer;

	l_debug("result: %i", result);

	if (!peer->wsc.pending_connect || dev->disconnecting) {
		/* Shouldn't happen except maybe in the ABORTED case */
		return;
	}

	switch (result) {
	case NETDEV_RESULT_OK:
		p2p_start_dhcp(dev);
		break;
	case NETDEV_RESULT_AUTHENTICATION_FAILED:
	case NETDEV_RESULT_ASSOCIATION_FAILED:
	case NETDEV_RESULT_HANDSHAKE_FAILED:
	case NETDEV_RESULT_KEY_SETTING_FAILED:
		/*
		 * In the AUTHENTICATION_FAILED and ASSOCIATION_FAILED
		 * cases there's nothing to disconnect.  In the
		 * HANDSHAKE_FAILED and KEY_SETTINGS failed cases
		 * netdev disconnects from the GO automatically and we are
		 * called already from within the disconnect callback,
		 * so we can directly free the netdev.
		 */
		p2p_connect_failed(dev);
		break;
	case NETDEV_RESULT_ABORTED:
		/*
		 * This case can only be triggered by netdev_disconnect so
		 * we'll wait for its callback before freeing the netdev.
		 * We will also have already replied to
		 * @peer->wsc.pending_connect so we have nothing to do here.
		 */
		break;
	}
}

static void p2p_netdev_event(struct netdev *netdev, enum netdev_event event,
				void *event_data, void *user_data)
{
	struct p2p_device *dev = user_data;

	switch (event) {
	case NETDEV_EVENT_DISCONNECT_BY_AP:
	case NETDEV_EVENT_DISCONNECT_BY_SME:
		/*
		 * We may get a DISCONNECT_BY_SME as a result of a
		 * netdev_disconnect().  In that case let the callback handle
		 * that.
		 */
		if (dev->disconnecting)
			break;

		/* If we're not connected, .Connected is already False */
		if (!p2p_peer_operational(dev->conn_peer)) {
			p2p_connect_failed(dev);
			break;
		}

		l_dbus_property_changed(dbus_get_bus(),
					p2p_peer_get_path(dev->conn_peer),
					IWD_P2P_PEER_INTERFACE, "Connected");
		p2p_connection_reset(dev);
		break;
	default:
		break;
	};
}

static void p2p_handshake_event(struct handshake_state *hs,
				enum handshake_event event, void *user_data,
				...)
{
	va_list args;

	va_start(args, user_data);

	switch (event) {
	case HANDSHAKE_EVENT_FAILED:
		netdev_handshake_failed(hs, va_arg(args, int));
		break;
	default:
		break;
	}

	va_end(args);
}

static void p2p_peer_provision_done(int err, struct wsc_credentials_info *creds,
					unsigned int n_creds, void *user_data)
{
	struct p2p_peer *peer = user_data;
	struct p2p_device *dev = peer->dev;
	struct scan_bss *bss = dev->conn_wsc_bss;
	struct handshake_state *hs = NULL;
	struct iovec ie_iov = {};
	int r = -EOPNOTSUPP;
	struct p2p_association_req info = {};
	struct ie_rsn_info bss_info = {};
	struct ie_rsn_info rsn_info = {};
	uint8_t rsne_buf[256];

	l_debug("err=%i n_creds=%u", err, n_creds);

	dev->conn_wsc_bss = NULL;
	dev->conn_enrollee = NULL;

	l_timeout_remove(dev->config_timeout);
	l_timeout_remove(dev->go_neg_req_timeout);

	if (err < 0) {
		if (err == -ECANCELED && peer->wsc.pending_cancel) {
			dbus_pending_reply(&peer->wsc.pending_cancel,
				l_dbus_message_new_method_return(
						peer->wsc.pending_cancel));

			p2p_connection_reset(dev);
		} else
			p2p_connect_failed(dev);

		goto done;
	}

	if (strlen(creds[0].ssid) != bss->ssid_len ||
			memcmp(creds[0].ssid, bss->ssid, bss->ssid_len)) {
		l_error("Unsupported: the SSID from the P2P peer's WSC "
			"credentials doesn't match the SSID from the "
			"Probe Response IEs");
		goto not_supported;
	}

	/*
	 * Apparently some implementations send the intended client's address
	 * here (i.e. our), and some send the target BSS's (their own).
	 */
	if (memcmp(creds[0].addr, netdev_get_address(dev->conn_netdev), 6) &&
			memcmp(creds[0].addr, bss->addr, 6)) {
		char addr1[32], addr2[32];

		l_strlcpy(addr1, util_address_to_string(creds[0].addr),
				sizeof(addr1));
		l_strlcpy(addr2, util_address_to_string(
					netdev_get_address(dev->conn_netdev)),
				sizeof(addr2));
		l_error("Error: WSC credentials are not for our client "
			"interface (%s vs. %s)", addr1, addr2);
		goto error;
	}

	if (!bss->rsne || creds[0].security != SECURITY_PSK)
		goto not_supported;

	info.capability = dev->capability;
	info.device_info = dev->device_info;

	ie_iov.iov_base = p2p_build_association_req(&info, &ie_iov.iov_len);
	L_WARN_ON(!ie_iov.iov_base);

	scan_bss_get_rsn_info(bss, &bss_info);

	rsn_info.akm_suites = wiphy_select_akm(dev->wiphy, bss, false);
	if (!rsn_info.akm_suites)
		goto not_supported;

	rsn_info.pairwise_ciphers = wiphy_select_cipher(dev->wiphy,
						bss_info.pairwise_ciphers);
	rsn_info.group_cipher = wiphy_select_cipher(dev->wiphy,
						bss_info.group_cipher);
	if (!rsn_info.pairwise_ciphers || !rsn_info.group_cipher)
		goto not_supported;

	rsn_info.group_management_cipher = wiphy_select_cipher(dev->wiphy,
					bss_info.group_management_cipher);
	rsn_info.mfpc = rsn_info.group_management_cipher != 0;
	ie_build_rsne(&rsn_info, rsne_buf);

	hs = netdev_handshake_state_new(dev->conn_netdev);

	if (!handshake_state_set_authenticator_ie(hs, bss->rsne))
		goto not_supported;

	if (!handshake_state_set_supplicant_ie(hs, rsne_buf))
		goto not_supported;

	handshake_state_set_event_func(hs, p2p_handshake_event, dev);
	handshake_state_set_ssid(hs, bss->ssid, bss->ssid_len);

	if (creds[0].has_passphrase) {
		uint8_t psk[32];

		if (crypto_psk_from_passphrase(creds[0].passphrase, bss->ssid,
						bss->ssid_len, psk) < 0)
			goto error;

		handshake_state_set_pmk(hs, psk, 32);
	} else
		handshake_state_set_pmk(hs, creds[0].psk, 32);

	r = netdev_connect(dev->conn_netdev, bss, hs, &ie_iov, 1,
				p2p_netdev_event, p2p_netdev_connect_cb, dev);
	if (r == 0)
		goto done;

	l_error("netdev_connect error: %s (%i)", strerror(-err), -err);

error:
not_supported:
	if (r < 0) {
		if (hs)
			handshake_state_free(hs);

		p2p_connect_failed(dev);
	}

done:
	l_free(ie_iov.iov_base);
	scan_bss_free(bss);
}

static void p2p_provision_connect(struct p2p_device *dev)
{
	struct iovec iov;
	struct p2p_association_req info = {};

	/* Ready to start the provisioning */
	info.capability = dev->capability;
	info.device_info = dev->device_info;

	iov.iov_base = p2p_build_association_req(&info, &iov.iov_len);
	L_WARN_ON(!iov.iov_base);

	dev->conn_enrollee = wsc_enrollee_new(dev->conn_netdev,
						dev->conn_wsc_bss,
						dev->conn_pin, &iov, 1,
						p2p_peer_provision_done,
						dev->conn_peer);
	l_free(iov.iov_base);
}

static void p2p_device_netdev_watch_destroy(void *user_data)
{
	struct p2p_device *dev = user_data;

	dev->conn_netdev_watch_id = 0;
}

static void p2p_device_netdev_notify(struct netdev *netdev,
					enum netdev_watch_event event,
					void *user_data)
{
	struct p2p_device *dev = user_data;

	if (dev->conn_netdev != netdev)
		return;

	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
	case NETDEV_WATCH_EVENT_NEW:
		if (!dev->conn_wsc_bss || dev->conn_enrollee ||
				!netdev_get_is_up(netdev))
			break;

		p2p_provision_connect(dev);
		break;
	case NETDEV_WATCH_EVENT_DEL:
		dev->conn_netdev = NULL;
		/* Fall through */
	case NETDEV_WATCH_EVENT_DOWN:
	case NETDEV_WATCH_EVENT_ADDRESS_CHANGE:
		p2p_connect_failed(dev);
		break;
	default:
		break;
	}
}

static void p2p_device_new_interface_cb(struct l_genl_msg *msg,
					void *user_data)
{
	struct p2p_device *dev = user_data;

	l_debug("");

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("NEW_INTERFACE failed: %s",
			strerror(-l_genl_msg_get_error(msg)));
		p2p_connect_failed(dev);
		return;
	}

	/* Create the netdev so we don't have to parse the message ourselves */
	dev->conn_netdev = netdev_create_from_genl(msg, dev->conn_addr);
	if (!dev->conn_netdev) {
		p2p_connect_failed(dev);
		return;
	}

	/*
	 * Register a watch for each connection rather than having one
	 * global watch.  Each connection's watch will receive events
	 * related to all other connections too, and will check that its
	 * conn_netdev != netdev and exit immediately.  This is not ideal
	 * but it's the same complexity (n^2) as that of one global watch
	 * that receives all events and iterates over p2p_device_list to
	 * find the connection.
	 */
	dev->conn_netdev_watch_id = netdev_watch_add(p2p_device_netdev_notify,
					dev, p2p_device_netdev_watch_destroy);
}

static void p2p_device_new_interface_destroy(void *user_data)
{
	struct p2p_device *dev = user_data;

	dev->conn_new_intf_cmd_id = 0;
}

static void p2p_device_interface_create(struct p2p_device *dev)
{
	uint32_t iftype = NL80211_IFTYPE_P2P_CLIENT;
	char ifname[32];
	uint32_t wiphy_id = dev->wdev_id >> 32;
	struct l_genl_msg *msg;

	snprintf(ifname, sizeof(ifname), "wlan%i-p2p-cl%i",
			wiphy_id, dev->conn_num++);
	l_debug("creating %s", ifname);

	msg = l_genl_msg_new(NL80211_CMD_NEW_INTERFACE);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY, 4, &wiphy_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFTYPE, 4, &iftype);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFNAME,
				strlen(ifname) + 1, ifname);
	l_genl_msg_append_attr(msg, NL80211_ATTR_4ADDR, 1, "\0");
	l_genl_msg_append_attr(msg, NL80211_ATTR_SOCKET_OWNER, 0, "");

	dev->conn_new_intf_cmd_id = l_genl_family_send(dev->nl80211, msg,
					p2p_device_new_interface_cb, dev,
					p2p_device_new_interface_destroy);
	if (!dev->conn_new_intf_cmd_id) {
		l_genl_msg_unref(msg);
		l_error("Error sending NEW_INTERFACE for %s", ifname);
		p2p_connect_failed(dev);
	}
}

static void p2p_scan_destroy(void *user_data)
{
	struct p2p_device *dev = user_data;

	dev->scan_id = 0;
}

static void p2p_provision_scan_start(struct p2p_device *dev);

static bool p2p_provision_scan_notify(int err, struct l_queue *bss_list,
					void *user_data)
{
	struct p2p_device *dev = user_data;
	const struct l_queue_entry *entry;
	static const uint8_t wildcard_addr[6] =
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	l_debug("err=%i, len(bss_list)=%i", err, l_queue_length(bss_list));

	if (err) {
		l_error("P2P provision scan failed: %s (%i)", strerror(-err),
			-err);
		p2p_connect_failed(dev);
		return false;
	}

	for (entry = l_queue_get_entries(bss_list); entry;
			entry = entry->next) {
		struct scan_bss *bss = entry->data;
		const uint8_t *group_id;
		bool selected_reg;
		struct p2p_capability_attr *capability;
		enum wsc_device_password_id device_password_id;
		const uint8_t *amacs;

		/*
		 * Check if we found our target GO, some of these checks may
		 * need to be gradually relaxed as we discover non-compliant
		 * implementations but at least print a debug statement when
		 * something doesn't match.
		 */

		if (strncmp((const char *) bss->ssid, dev->go_group_id.ssid,
				bss->ssid_len))
			continue;

		if (dev->go_group_id.ssid[bss->ssid_len] != '\0')
			continue;

		if (!util_mem_is_zero(dev->go_interface_addr, 6) &&
				memcmp(bss->addr, dev->go_interface_addr, 6))
			l_debug("SSID matched but BSSID didn't match the GO's "
				"intended interface addr, proceeding anyway");

		if (!bss->wsc) {
			l_error("SSID matched but no valid WSC IE");
			continue;
		}

		if (bss->source_frame == SCAN_BSS_PROBE_RESP) {
			struct wsc_probe_response wsc_info;

			if (!bss->p2p_probe_resp_info) {
				l_error("SSID matched but no valid P2P IE");
				continue;
			}

			if (wsc_parse_probe_response(bss->wsc, bss->wsc_size,
							&wsc_info) < 0) {
				l_error("SSID matched but can't parse WSC "
					"Probe Response info");
				continue;
			}

			group_id = bss->p2p_probe_resp_info->
				device_info.device_addr;
			selected_reg = wsc_info.selected_registrar;
			capability = &bss->p2p_probe_resp_info->capability;
			device_password_id = wsc_info.device_password_id;
			amacs = wsc_info.authorized_macs;
		} else if (bss->source_frame == SCAN_BSS_BEACON) {
			struct wsc_beacon wsc_info;

			if (!bss->p2p_beacon_info) {
				l_error("SSID matched but no valid P2P IE");
				continue;
			}

			if (wsc_parse_beacon(bss->wsc, bss->wsc_size,
						&wsc_info) < 0) {
				l_error("SSID matched but can't parse WSC "
					"Beacon info");
				continue;
			}

			group_id = bss->p2p_beacon_info->device_addr;
			selected_reg = wsc_info.selected_registrar;
			capability = &bss->p2p_beacon_info->capability;
			device_password_id = wsc_info.device_password_id;
			amacs = wsc_info.authorized_macs;
		} else
			continue;

		if (memcmp(group_id, dev->go_group_id.device_addr, 6)) {
			l_error("SSID matched but Group ID address didn't");
			continue;
		}

		if (!selected_reg) {
			/*
			 * Debug level because this will sometimes happen
			 * while the target is setting up the GO mode in the
			 * course of normal operation, and gets set to true
			 * in a few seconds, we just need to keep scanning.
			 */
			l_debug("SSID matched but not a Selected Reg");
			continue;
		}

		if (dev->conn_peer->group && (capability->group_caps &
					P2P_GROUP_CAP_GROUP_FORMATION)) {
			l_error("SSID matched but not in Group Formation");
			continue;
		}

		if (!dev->conn_peer->group && !(capability->group_caps &
					P2P_GROUP_CAP_GROUP_FORMATION))
			/*
			 * We have to ignore this one for interoperability
			 * with some devices.
			 */
			l_debug("SSID matched but GO not in Group Formation, "
				"proceeding anyway");

		if (capability->group_caps & P2P_GROUP_CAP_GROUP_LIMIT) {
			l_error("SSID matched but group already full");
			continue;
		}

		if (device_password_id != dev->conn_password_id) {
			l_error("SSID matched wrong Password ID");
			continue;
		}

		if (!util_mem_is_zero(amacs, 30)) {
			bool amacs_match = false;
			int i;

			for (i = 0; i < 5; i++, amacs += 6)
				if (!memcmp(amacs, dev->addr, 6) ||
						!memcmp(amacs, wildcard_addr, 6))
					amacs_match = true;

			if (!amacs_match) {
				l_error("SSID matched we're not in AMacs");
				continue;
			}
		}

		l_debug("GO found in the scan results");

		dev->conn_wsc_bss = bss;
		p2p_device_interface_create(dev);
		l_queue_remove(bss_list, bss);
		l_queue_destroy(bss_list,
				(l_queue_destroy_func_t) scan_bss_free);
		return true;
	}

	/* Retry a few times if the WSC AP not found or not ready */
	dev->go_scan_retry++;

	if (dev->go_scan_retry > 15) {
		p2p_connect_failed(dev);
		return false;
	}

	p2p_provision_scan_start(dev);
	return false;
}

static void p2p_provision_scan_start(struct p2p_device *dev)
{
	struct scan_parameters params = {};
	uint8_t buf[256];

	params.flush = true;
	params.no_cck_rates = true;
	params.ssid = dev->go_group_id.ssid;
	params.extra_ie = p2p_build_scan_ies(dev, buf, sizeof(buf),
						&params.extra_ie_size);
	L_WARN_ON(!params.extra_ie);

	/*
	 * Initially scan just the Operating Channel the GO reported
	 * during the negotiation.  In theory there's no guarantee that
	 * it is going to be on that channel so we should fall back
	 * to scanning all the channels listed in the Channel List
	 * attribute.  For simplicity we just do a full scan in that
	 * scenario -- for most target P2P devices we wouldn't be saving
	 * ourselves any work anyway as the Channel List is going to
	 * contain all of the 2.4 and 5G channels.
	 */
	if (dev->go_scan_retry < 12) {
		params.freqs = scan_freq_set_new();
		scan_freq_set_add(params.freqs, dev->go_oper_freq);
	}

	dev->scan_id = scan_active_full(dev->wdev_id, &params, NULL,
					p2p_provision_scan_notify, dev,
					p2p_scan_destroy);

	if (params.freqs)
		scan_freq_set_free(params.freqs);
}

static void p2p_start_client_provision(struct p2p_device *dev)
{
	char bssid_str[18];

	memcpy(bssid_str, util_address_to_string(dev->go_interface_addr), 18);
	l_debug("freq=%u ssid=%s group_addr=%s bssid=%s", dev->go_oper_freq,
		dev->go_group_id.ssid,
		util_address_to_string(dev->go_group_id.device_addr),
		bssid_str);

	dev->go_scan_retry = 0;
	p2p_provision_scan_start(dev);
}

static void p2p_config_timeout_destroy(void *user_data)
{
	struct p2p_device *dev = user_data;

	dev->config_timeout = NULL;
}

static void p2p_config_timeout(struct l_timeout *timeout, void *user_data)
{
	struct p2p_device *dev = user_data;

	l_timeout_remove(dev->config_timeout);

	/* Ready to start WSC */
	p2p_start_client_provision(dev);
}

static void p2p_go_negotiation_resp_done(int error, void *user_data)
{
	struct p2p_device *dev = user_data;

	if (error)
		l_error("Sending the GO Negotiation Response failed: %s (%i)",
			strerror(-error), -error);
	else
		l_error("No GO Negotiation Confirmation frame received");

	p2p_connect_failed(dev);
}

static void p2p_go_negotiation_resp_err_done(int error, void *user_data)
{
	if (error)
		l_error("Sending the GO Negotiation Response failed: %s (%i)",
			strerror(-error), -error);
}

/*
 * Called by GO Negotiation Response and Confirmation receive handlers,
 * in both cases the channel lists are required to be subsets of our
 * own supported channels and the Operating Channel must appear in the
 * channel list.
 */
static bool p2p_device_validate_channel_list(struct p2p_device *dev,
				const struct p2p_channel_list_attr *attr,
				const struct p2p_channel_attr *oper_channel)
{
	if (l_queue_isempty(attr->channel_entries))
		return false;

	/* TODO */
	return true;
}

/*
 * It seems that sending more than about 42 channels in a frame's Channel
 * List attribute will baffle some devices enough that they will ignore
 * the frame.
 */
#define MAX_CHANNELS 40

static void p2p_add_freq_func(uint32_t freq, void *user_data)
{
	struct p2p_channel_entries *channel_entry = user_data;
	uint8_t channel;
	enum scan_band band;

	if (channel_entry->n_channels >= MAX_CHANNELS)
		return;

	channel = scan_freq_to_channel(freq, &band);

	if (band != scan_oper_class_to_band((const uint8_t *) "XX\x4",
						channel_entry->oper_class))
		return;

	channel_entry->channels[channel_entry->n_channels++] = channel;
}

static void p2p_device_fill_channel_list(struct p2p_device *dev,
					struct p2p_channel_list_attr *attr)
{
	struct p2p_channel_entries *channel_entry;
	unsigned int total_channels;

	memcpy(attr->country, dev->listen_country, 3);
	attr->channel_entries = l_queue_new();

	channel_entry = l_malloc(sizeof(struct p2p_channel_entries) +
					MAX_CHANNELS);
	channel_entry->oper_class = 81;
	channel_entry->n_channels = 0;
	scan_freq_set_foreach(wiphy_get_supported_freqs(dev->wiphy),
				p2p_add_freq_func, channel_entry);
	l_queue_push_tail(attr->channel_entries, channel_entry);
	total_channels = channel_entry->n_channels;

	if (total_channels >= MAX_CHANNELS)
		return;

	channel_entry = l_malloc(sizeof(struct p2p_channel_entries) +
					MAX_CHANNELS);
	channel_entry->oper_class = 115;
	channel_entry->n_channels = 0;
	scan_freq_set_foreach(wiphy_get_supported_freqs(dev->wiphy),
				p2p_add_freq_func, channel_entry);

	if (total_channels + channel_entry->n_channels > MAX_CHANNELS)
		channel_entry->n_channels = MAX_CHANNELS - total_channels;

	l_queue_push_tail(attr->channel_entries, channel_entry);
}

static bool p2p_go_negotiation_confirm_cb(const struct mmpdu_header *mpdu,
					const void *body, size_t body_len,
					int rssi, struct p2p_device *dev)
{
	struct p2p_go_negotiation_confirmation info;
	int r;
	enum scan_band band;
	uint32_t frequency;

	l_debug("");

	if (body_len < 8) {
		l_error("GO Negotiation Confirmation frame too short");
		p2p_connect_failed(dev);
		return true;
	}

	r = p2p_parse_go_negotiation_confirmation(body + 7, body_len - 7,
							&info);
	if (r < 0) {
		l_error("GO Negotiation Confirmation parse error %s (%i)",
			strerror(-r), -r);
		p2p_connect_failed(dev);
		return true;
	}

	if (info.dialog_token != dev->go_dialog_token) {
		l_error("GO Negotiation Response dialog token doesn't match");
		p2p_connect_failed(dev);
		return true;
	}

	if (info.status != P2P_STATUS_SUCCESS) {
		l_error("GO Negotiation Confirmation status %i", info.status);
		p2p_connect_failed(dev);
		return true;
	}

	if (!p2p_device_validate_channel_list(dev, &info.channel_list,
						&info.operating_channel))
		return true;

	band = scan_oper_class_to_band(
			(const uint8_t *) info.operating_channel.country,
			info.operating_channel.oper_class);
	frequency = scan_channel_to_freq(info.operating_channel.channel_num,
						band);
	if (!frequency) {
		l_error("Bad operating channel in GO Negotiation Confirmation");
		p2p_connect_failed(dev);
		return true;
	}

	dev->go_oper_freq = frequency;
	memcpy(&dev->go_group_id, &info.group_id,
		sizeof(struct p2p_group_id_attr));

	/*
	 * Confirmation received.  For simplicity wait idly the maximum amount
	 * of time indicated by the peer in the GO Negotiation Response's
	 * Configuration Timeout attribute and start the provisioning phase.
	 */
	dev->config_timeout = l_timeout_create_ms(dev->go_config_delay,
						p2p_config_timeout, dev,
						p2p_config_timeout_destroy);
	return true;
}

static void p2p_device_go_negotiation_req_cb(const struct mmpdu_header *mpdu,
						const void *body,
						size_t body_len, int rssi,
						void *user_data)
{
	struct p2p_device *dev = user_data;
	struct p2p_go_negotiation_req req_info;
	struct p2p_go_negotiation_resp resp_info = {};
	int r;
	uint8_t *resp_body;
	size_t resp_len;
	struct iovec iov[16];
	int iov_len = 0;
	struct p2p_peer *peer;
	enum p2p_attr_status_code status = P2P_STATUS_SUCCESS;
	bool tie_breaker = false;

	l_debug("");

	/*
	 * Check the Destination Address and the BSSID. Section 2.4.3:
	 * "When communication is not within a P2P Group, e.g. during
	 * [...] GO Negotiation [...], a P2P Device shall use the
	 * P2P Device Address of the intended destination as the BSSID in
	 * Request, or Confirmation frames and its own P2P Device Address
	 * as the BSSID in Response frames."
	 *
	 * Some drivers (brcmfmac) will report the BSSID as all zeros and
	 * some Wi-Fi Display dongles will pass their own address as the
	 * BSSID in the GO Negotiation Request so allow all three possible
	 * values.
	 */
	if (memcmp(mpdu->address_1, dev->addr, 6) ||
			(memcmp(mpdu->address_3, dev->addr, 6) &&
			 memcmp(mpdu->address_3, mpdu->address_2, 6) &&
			 !util_mem_is_zero(mpdu->address_3, 6)))
		return;

	peer = l_queue_find(dev->peer_list, p2p_peer_match, mpdu->address_2);
	if (!peer)
		return;

	if (body_len < 8)
		return;

	if (!dev->go_neg_req_timeout || peer != dev->conn_peer) {
		status = P2P_STATUS_FAIL_INFO_NOT_AVAIL;
		goto respond;
	}

	if (memcmp(mpdu->address_2, dev->conn_peer->bss->addr, 6)) {
		status = P2P_STATUS_FAIL_UNABLE_TO_ACCOMMODATE_REQUEST;
		goto respond;
	}

	r = p2p_parse_go_negotiation_req(body + 7, body_len - 7, &req_info);
	if (r < 0) {
		l_error("GO Negotiation Request parse error %s (%i)",
			strerror(-r), -r);
		p2p_connect_failed(dev);
		status = P2P_STATUS_FAIL_INVALID_PARAMS;
		goto respond;
	}

	if (req_info.go_intent == 0 && !req_info.go_tie_breaker) {
		l_error("Can't negotiate client role and GO operation not "
			"supported");

		if (peer->wsc.pending_connect) {
			struct l_dbus_message *reply =
				dbus_error_not_supported(
						peer->wsc.pending_connect);

			dbus_pending_reply(&peer->wsc.pending_connect, reply);
		}

		p2p_connect_failed(dev);
		status = P2P_STATUS_FAIL_INCOMPATIBLE_PARAMS;
		goto p2p_free;
	}

	if (req_info.capability.group_caps & P2P_GROUP_CAP_PERSISTENT_GROUP) {
		if (peer->wsc.pending_connect) {
			struct l_dbus_message *reply =
				dbus_error_not_supported(
						peer->wsc.pending_connect);

			dbus_pending_reply(&peer->wsc.pending_connect, reply);
		}

		p2p_connect_failed(dev);
		l_error("Persistent groups not supported");
		status = P2P_STATUS_FAIL_INCOMPATIBLE_PARAMS;
		goto p2p_free;
	}

	if (req_info.device_password_id != dev->conn_password_id) {
		p2p_connect_failed(dev);
		l_error("Incompatible Password ID in the GO Negotiation Req");
		status = P2P_STATUS_FAIL_INCOMPATIBLE_PROVISIONING;
		goto p2p_free;
	}

	l_timeout_remove(dev->go_neg_req_timeout);
	p2p_device_discovery_stop(dev);

	dev->go_dialog_token = req_info.dialog_token;
	dev->go_config_delay = req_info.config_timeout.go_config_timeout * 10;
	memcpy(dev->go_interface_addr, req_info.intended_interface_addr, 6);

p2p_free:
	tie_breaker = !req_info.go_tie_breaker;
	p2p_clear_go_negotiation_req(&req_info);

respond:
	/* Build and send the GO Negotiation Response */
	resp_info.dialog_token = dev->go_dialog_token;
	resp_info.status = status;
	resp_info.capability.device_caps = dev->capability.device_caps;
	resp_info.capability.group_caps = 0;	/* Reserved */
	resp_info.go_intent = 0;		/* Don't want to be the GO */
	resp_info.go_tie_breaker = tie_breaker;
	resp_info.config_timeout.go_config_timeout = 50;	/* 500ms */
	resp_info.config_timeout.client_config_timeout = 50;	/* 500ms */

	if (dev->conn_peer)
		memcpy(resp_info.intended_interface_addr, dev->conn_addr, 6);

	p2p_device_fill_channel_list(dev, &resp_info.channel_list);
	resp_info.device_info = dev->device_info;
	resp_info.device_password_id = dev->conn_password_id;

	resp_body = p2p_build_go_negotiation_resp(&resp_info, &resp_len);
	p2p_clear_go_negotiation_resp(&resp_info);

	if (!resp_body) {
		p2p_connect_failed(dev);
		return;
	}

	iov[iov_len].iov_base = resp_body;
	iov[iov_len].iov_len = resp_len;
	iov_len++;

	/* WFD and other service IEs go here */

	iov[iov_len].iov_base = NULL;

	if (status == P2P_STATUS_SUCCESS)
		p2p_peer_frame_xchg(peer, iov, dev->addr, 0, 600, 0, true,
					FRAME_GROUP_CONNECT,
					p2p_go_negotiation_resp_done,
					&p2p_frame_go_neg_confirm,
					p2p_go_negotiation_confirm_cb, NULL);
	else
		p2p_peer_frame_xchg(peer, iov, dev->addr, 0, 0, 0, true,
					FRAME_GROUP_CONNECT,
					p2p_go_negotiation_resp_err_done, NULL);

	l_debug("GO Negotiation Response sent with status %i", status);
}

static void p2p_go_negotiation_confirm_done(int error, void *user_data)
{
	struct p2p_device *dev = user_data;

	if (error) {
		/* TODO: we should probably ignore the missing ACK error */
		l_error("Sending the GO Negotiation Confirm failed: %s (%i)",
			strerror(-error), -error);
		p2p_connect_failed(dev);
		return;
	}

	/*
	 * Frame was ACKed.  For simplicity wait idly the maximum amount of
	 * time indicated by the peer in the GO Negotiation Response's
	 * Configuration Timeout attribute and start the provisioning phase.
	 */
	dev->config_timeout = l_timeout_create_ms(dev->go_config_delay,
						p2p_config_timeout, dev,
						p2p_config_timeout_destroy);
}

static void p2p_go_neg_req_timeout_destroy(void *user_data)
{
	struct p2p_device *dev = user_data;

	dev->go_neg_req_timeout = NULL;
}

static void p2p_go_neg_req_timeout(struct l_timeout *timeout, void *user_data)
{
	struct p2p_device *dev = user_data;

	l_debug("");

	p2p_connect_failed(dev);

	if (l_queue_isempty(dev->discovery_users))
		p2p_device_discovery_stop(dev);
}

static bool p2p_go_negotiation_resp_cb(const struct mmpdu_header *mpdu,
					const void *body, size_t body_len,
					int rssi, struct p2p_device *dev)
{
	struct p2p_go_negotiation_resp resp_info;
	struct p2p_go_negotiation_confirmation confirm_info = {};
	uint8_t *confirm_body;
	size_t confirm_len;
	int r;
	struct iovec iov[16];
	int iov_len = 0;
	enum scan_band band;
	uint32_t frequency;

	l_debug("");

	if (!dev->conn_peer)
		return true;

	if (body_len < 8) {
		l_error("GO Negotiation Response frame too short");
		p2p_connect_failed(dev);
		return true;
	}

	r = p2p_parse_go_negotiation_resp(body + 7, body_len - 7, &resp_info);
	if (r < 0) {
		l_error("GO Negotiation Response parse error %s (%i)",
			strerror(-r), -r);
		p2p_connect_failed(dev);
		return true;
	}

	if (resp_info.dialog_token != 1) {
		l_error("GO Negotiation Response dialog token doesn't match");
		p2p_connect_failed(dev);
		return true;
	}

	if (resp_info.status != P2P_STATUS_SUCCESS) {
		if (resp_info.status == P2P_STATUS_FAIL_INFO_NOT_AVAIL) {
			/* Give the peer 120s to restart the GO Negotiation */
			l_error("P2P_STATUS_FAIL_INFO_NOT_AVAIL: Will wait for "
				"a new GO Negotiation Request before declaring "
				"failure");
			dev->go_neg_req_timeout = l_timeout_create(120,
						p2p_go_neg_req_timeout, dev,
						p2p_go_neg_req_timeout_destroy);
			p2p_device_discovery_start(dev);
			return true;
		}

		l_error("GO Negotiation Response status %i", resp_info.status);
		p2p_connect_failed(dev);
		return true;
	}

	/*
	 * 3.1.4.2: "The Tie breaker bit in a GO Negotiation Response frame
	 * shall be toggled from the corresponding GO Negotiation Request
	 * frame."
	 */
	if (!resp_info.go_tie_breaker) {
		l_error("GO Negotiation Response tie breaker value wrong");

		if (resp_info.go_intent == 0) {
			/* Can't continue */
			p2p_connect_failed(dev);
			return true;
		}
	}

	if (resp_info.capability.group_caps & P2P_GROUP_CAP_PERSISTENT_GROUP) {
		l_error("Persistent groups not supported");
		p2p_connect_failed(dev);
		return true;
	}

	if (resp_info.device_password_id != dev->conn_password_id) {
		l_error("GO Negotiation Response WSC device password ID wrong");
		p2p_connect_failed(dev);
		return true;
	}

	if (!p2p_device_validate_channel_list(dev, &resp_info.channel_list,
						&resp_info.operating_channel))
		return true;

	band = scan_oper_class_to_band(
			(const uint8_t *) resp_info.operating_channel.country,
			resp_info.operating_channel.oper_class);
	frequency = scan_channel_to_freq(
					resp_info.operating_channel.channel_num,
					band);
	if (!frequency) {
		l_error("Bad operating channel in GO Negotiation Response");
		p2p_connect_failed(dev);
		return true;
	}

	dev->go_config_delay = resp_info.config_timeout.go_config_timeout * 10;
	dev->go_oper_freq = frequency;
	memcpy(&dev->go_group_id, &resp_info.group_id,
		sizeof(struct p2p_group_id_attr));
	memcpy(dev->go_interface_addr, resp_info.intended_interface_addr, 6);

	/* Build and send the GO Negotiation Confirmation */
	confirm_info.dialog_token = resp_info.dialog_token;
	confirm_info.status = P2P_STATUS_SUCCESS;
	confirm_info.capability.device_caps = 0;	/* Reserved */
	confirm_info.capability.group_caps = 0;		/* Reserved */
	confirm_info.channel_list = resp_info.channel_list;
	confirm_info.operating_channel = resp_info.operating_channel;

	confirm_body = p2p_build_go_negotiation_confirmation(&confirm_info,
								&confirm_len);
	p2p_clear_go_negotiation_resp(&resp_info);

	if (!confirm_body) {
		p2p_connect_failed(dev);
		return true;
	}

	iov[iov_len].iov_base = confirm_body;
	iov[iov_len].iov_len = confirm_len;
	iov_len++;

	/* WFD and other service IEs go here */

	iov[iov_len].iov_base = NULL;

	p2p_peer_frame_xchg(dev->conn_peer, iov, dev->conn_peer->device_addr,
				0, 0, 0, false, FRAME_GROUP_CONNECT,
				p2p_go_negotiation_confirm_done, NULL);
	return true;
}

static void p2p_go_negotiation_req_done(int error, void *user_data)
{
	struct p2p_device *dev = user_data;

	if (error)
		l_error("Sending the GO Negotiation Req failed: %s (%i)",
			strerror(-error), -error);
	else
		l_error("No GO Negotiation Response after Request ACKed");

	p2p_connect_failed(dev);
}

static void p2p_start_go_negotiation(struct p2p_device *dev)
{
	struct p2p_go_negotiation_req info = {};
	uint8_t *req_body;
	size_t req_len;
	struct iovec iov[16];
	int iov_len = 0;
	/*
	 * Devices should respond within 100ms but times of ~400ms are
	 * often seen instead.
	 *
	 * 3.1.4.2: "The P2P Device that sent the Group Owner Negotiation
	 * frame shall assume that Group Owner Negotiation failed and is
	 * complete if it does not receive the next frame in the exchange
	 * within 100 milliseconds of receiving an acknowledgement frame."
	 */
	unsigned int resp_timeout = 600;

	info.dialog_token = 1;
	info.capability = dev->capability;
	info.go_intent = 0;	/* Don't want to be the GO */
	info.go_tie_breaker = 0;
	info.config_timeout.go_config_timeout = 50;	/* 500ms */
	info.config_timeout.client_config_timeout = 50;	/* 500ms */
	memcpy(info.listen_channel.country, dev->listen_country, 3);
	info.listen_channel.oper_class = dev->listen_oper_class;
	info.listen_channel.channel_num = dev->listen_channel;
	memcpy(info.intended_interface_addr, dev->conn_addr, 6);

	/*
	 * In theory we support an empty set of operating channels for
	 * our potential group as a GO but we have to include our
	 * supported channels because the peer can only choose their
	 * own channels from our list.  Use the listen channel as the
	 * preferred operating channel because we have no preference.
	 */
	p2p_device_fill_channel_list(dev, &info.channel_list);
	memcpy(info.operating_channel.country, dev->listen_country, 3);
	info.operating_channel.oper_class = dev->listen_oper_class;
	info.operating_channel.channel_num = dev->listen_channel;
	info.device_info = dev->device_info;
	info.device_password_id = dev->conn_password_id;

	req_body = p2p_build_go_negotiation_req(&info, &req_len);
	p2p_clear_go_negotiation_req(&info);

	if (!req_body) {
		p2p_connect_failed(dev);
		return;
	}

	iov[iov_len].iov_base = req_body;
	iov[iov_len].iov_len = req_len;
	iov_len++;

	/* WFD and other service IEs go here */

	iov[iov_len].iov_base = NULL;

	p2p_peer_frame_xchg(dev->conn_peer, iov, dev->conn_peer->device_addr,
				100, resp_timeout, 256, false,
				FRAME_GROUP_CONNECT,
				p2p_go_negotiation_req_done,
				&p2p_frame_go_neg_resp,
				p2p_go_negotiation_resp_cb, NULL);
}

static bool p2p_provision_disc_resp_cb(const struct mmpdu_header *mpdu,
					const void *body, size_t body_len,
					int rssi, struct p2p_device *dev)
{
	struct p2p_provision_discovery_resp info;
	int r;

	l_debug("");

	if (!dev->conn_peer)
		return true;

	if (body_len < 8) {
		l_error("Provision Discovery Response frame too short");
		p2p_connect_failed(dev);
		return true;
	}

	r = p2p_parse_provision_disc_resp(body + 7, body_len - 7, &info);
	if (r < 0) {
		l_error("Provision Discovery Response parse error %s (%i)",
			strerror(-r), -r);
		p2p_connect_failed(dev);
		return true;
	}

	if (info.dialog_token != 2) {
		l_error("Provision Discovery Response dialog token doesn't "
			"match");
		p2p_connect_failed(dev);
		return true;
	}

	if (info.wsc_config_method != dev->conn_config_method) {
		l_error("Provision Discovery Response WSC device password ID "
			"wrong");
		p2p_connect_failed(dev);
		return true;
	}

	/*
	 * If we're not joining an existing group, continue with Group
	 * Formation now.
	 */
	if (!dev->conn_peer->group) {
		p2p_start_go_negotiation(dev);
		return true;
	}

	/*
	 * Indended P2P Interface address is optional, we don't have the
	 * BSSID of the group here.
	 *
	 * We might want to make sure that Group Formation is false but the
	 * Capability attribute is also optional.
	 */
	dev->go_oper_freq = dev->conn_peer->bss->frequency;
	memset(dev->go_interface_addr, 0, 6);
	memcpy(dev->go_group_id.device_addr, dev->conn_peer->device_addr, 6);
	l_strlcpy(dev->go_group_id.ssid,
			(const char *) dev->conn_peer->bss->ssid,
			dev->conn_peer->bss->ssid_len + 1);

	/* Ready to start WSC */
	p2p_start_client_provision(dev);
	return true;
}

static void p2p_provision_disc_req_done(int error, void *user_data)
{
	struct p2p_device *dev = user_data;

	if (error)
		l_error("Sending the Provision Discovery Req failed: %s (%i)",
			strerror(-error), -error);
	else
		l_error("No Provision Discovery Response after Request ACKed");

	p2p_connect_failed(dev);
}

static void p2p_start_provision_discovery(struct p2p_device *dev)
{
	struct p2p_provision_discovery_req info = { .status = -1 };
	uint8_t *req_body;
	size_t req_len;
	struct iovec iov[16];
	int iov_len = 0;

	/* This frame is pretty simple when P2Ps isn't supported */
	info.dialog_token = 2;
	info.capability = dev->capability;
	info.device_info = dev->device_info;

	if (dev->conn_peer->group) {
		memcpy(info.group_id.device_addr, dev->conn_peer->bss->addr, 6);
		memcpy(info.group_id.ssid, dev->conn_peer->bss->ssid,
			dev->conn_peer->bss->ssid_len);
	}

	info.wsc_config_method = dev->conn_config_method;

	req_body = p2p_build_provision_disc_req(&info, &req_len);
	p2p_clear_provision_disc_req(&info);

	if (!req_body) {
		p2p_connect_failed(dev);
		return;
	}

	iov[iov_len].iov_base = req_body;
	iov[iov_len].iov_len = req_len;
	iov_len++;

	/* WFD and other service IEs go here */

	iov[iov_len].iov_base = NULL;

	/*
	 * Section 3.2.3: "The Provision Discovery Request frame shall be
	 * sent to the P2P Device Address of the P2P Group Owner"
	 */
	p2p_peer_frame_xchg(dev->conn_peer, iov, dev->conn_peer->device_addr,
				200, 600, 8, false, FRAME_GROUP_CONNECT,
				p2p_provision_disc_req_done,
				&p2p_frame_pd_resp, p2p_provision_disc_resp_cb,
				NULL);
}

static bool p2p_peer_get_info(struct p2p_peer *peer,
				uint16_t *wsc_config_methods,
				struct p2p_capability_attr **capability)
{
	struct wsc_probe_request wsc_info;

	switch (peer->bss->source_frame) {
	case SCAN_BSS_PROBE_RESP:
		if (!peer->bss->p2p_probe_resp_info)
			return false;

		if (wsc_config_methods)
			*wsc_config_methods = peer->bss->p2p_probe_resp_info->
				device_info.wsc_config_methods;

		*capability = &peer->bss->p2p_probe_resp_info->capability;
		return true;
	case SCAN_BSS_PROBE_REQ:
		if (!peer->bss->p2p_probe_req_info || !peer->bss->wsc)
			return false;

		if (wsc_parse_probe_request(peer->bss->wsc, peer->bss->wsc_size,
						&wsc_info) < 0)
			return false;

		if (wsc_config_methods)
			*wsc_config_methods = wsc_info.config_methods;

		*capability = &peer->bss->p2p_probe_req_info->capability;
		return true;
	case SCAN_BSS_BEACON:
		if (!peer->bss->p2p_beacon_info || !peer->bss->wsc)
			return false;

		if (wsc_parse_probe_request(peer->bss->wsc, peer->bss->wsc_size,
						&wsc_info) < 0)
			return false;

		if (wsc_config_methods)
			*wsc_config_methods = wsc_info.config_methods;

		*capability = &peer->bss->p2p_beacon_info->capability;
		break;
	}

	return false;
}

static void p2p_peer_connect(struct p2p_peer *peer, const char *pin)
{
	struct p2p_device *dev = peer->dev;
	uint16_t wsc_config_methods;
	struct p2p_capability_attr *capability;
	struct l_dbus_message *message = peer->wsc.pending_connect;
	struct l_dbus_message *reply;

	if (dev->conn_peer) {
		reply = dbus_error_busy(message);
		goto send_error;
	}

	/*
	 * Step 1, check if the device indicates it supports our WSC method
	 * and check other flags to make sure a connection is possible.
	 */
	if (!p2p_peer_get_info(peer, &wsc_config_methods, &capability)) {
		reply = dbus_error_failed(message);
		goto send_error;
	}

	dev->conn_config_method = pin ? WSC_CONFIGURATION_METHOD_KEYPAD :
		WSC_CONFIGURATION_METHOD_PUSH_BUTTON;
	dev->conn_password_id = pin ?
		(strlen(pin) == 4 || wsc_pin_is_checksum_valid(pin) ?
		 WSC_DEVICE_PASSWORD_ID_DEFAULT :
		 WSC_DEVICE_PASSWORD_ID_USER_SPECIFIED) :
		WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON;

	if (!(wsc_config_methods & dev->conn_config_method)) {
		reply = dbus_error_not_supported(message);
		goto send_error;
	}

	if (capability->device_caps & P2P_DEVICE_CAP_DEVICE_LIMIT) {
		reply = dbus_error_not_supported(message);
		goto send_error;
	}

	if (capability->group_caps & P2P_GROUP_CAP_GROUP_LIMIT) {
		reply = dbus_error_not_supported(message);
		goto send_error;
	}

	if (capability->group_caps & P2P_GROUP_CAP_GROUP_FORMATION) {
		reply = dbus_error_busy(message);
		goto send_error;
	}

	p2p_device_discovery_stop(dev);

	/* Generate the interface address for our P2P-Client connection */
	wiphy_generate_random_address(dev->wiphy, dev->conn_addr);

	dev->conn_peer = peer; /* No ref counting so just set the pointer */
	dev->conn_pin = l_strdup(pin);
	dev->connections_left--;
	l_dbus_property_changed(dbus_get_bus(), p2p_device_get_path(dev),
				IWD_P2P_INTERFACE, "AvailableConnections");

	/*
	 * Step 2, if peer is already a GO then send the Provision Discovery
	 * before doing WSC.  If it's not then do Provision Discovery
	 * optionally as seems to be required by some implementations, and
	 * start GO negotiation following that.
	 * TODO: Add a AlwaysUsePD config setting.
	 */
	if (dev->conn_peer->group)
		p2p_start_provision_discovery(dev);
	else
		p2p_start_go_negotiation(dev);

	return;

send_error:
	dbus_pending_reply(&peer->wsc.pending_connect, reply);
}

static void p2p_peer_disconnect_cb(struct netdev *netdev, bool result,
					void *user_data)
{
	struct p2p_peer *peer = user_data;
	struct p2p_device *dev = peer->dev;

	if (!peer->wsc.pending_cancel || !dev->disconnecting)
		return;

	dbus_pending_reply(&peer->wsc.pending_cancel,
				l_dbus_message_new_method_return(
						peer->wsc.pending_cancel));

	/* Independent of the result this will just drop the whole netdev */
	p2p_connection_reset(dev);
}

static void p2p_peer_disconnect(struct p2p_peer *peer)
{
	struct p2p_device *dev = peer->dev;
	struct l_dbus_message *message = peer->wsc.pending_cancel;
	struct l_dbus_message *reply;

	if (dev->conn_peer != peer) {
		reply = dbus_error_not_connected(message);
		goto send_reply;
	}

	if (dev->disconnecting) {
		reply = dbus_error_busy(message);
		goto send_reply;
	}

	if (peer->wsc.pending_connect)
		dbus_pending_reply(&peer->wsc.pending_connect,
				dbus_error_aborted(peer->wsc.pending_connect));

	if (p2p_peer_operational(peer))
		l_dbus_property_changed(dbus_get_bus(), p2p_peer_get_path(peer),
					IWD_P2P_PEER_INTERFACE, "Connected");

	dev->disconnecting = true;

	if (dev->conn_enrollee) {
		wsc_enrollee_cancel(dev->conn_enrollee, true);
		return;
	}

	if (dev->conn_netdev && !dev->conn_wsc_bss) {
		/* Note: in theory we need to add the P2P IEs here too */
		if (netdev_disconnect(dev->conn_netdev, p2p_peer_disconnect_cb,
					peer) == 0)
			return;

		l_error("netdev_disconnect failed");
	}

	p2p_connection_reset(dev);
	reply = l_dbus_message_new_method_return(message);

send_reply:
	dbus_pending_reply(&peer->wsc.pending_cancel, reply);
}

#define SCAN_INTERVAL_MAX	3
#define SCAN_INTERVAL_STEP	1
#define CHANS_PER_SCAN_INITIAL	2
#define CHANS_PER_SCAN		2

static bool p2p_device_scan_start(struct p2p_device *dev);
static void p2p_device_roc_start(struct p2p_device *dev);

static void p2p_device_roc_timeout(struct l_timeout *timeout, void *user_data)
{
	struct p2p_device *dev = user_data;

	l_timeout_remove(dev->scan_timeout);

	if (time(NULL) < dev->next_scan_ts) {
		/*
		 * dev->scan_timeout destroy function will have been called
		 * by now so it won't overwrite the new timeout set by
		 * p2p_device_roc_start.
		 */
		p2p_device_roc_start(dev);
		return;
	}

	p2p_device_scan_start(dev);
}

static void p2p_device_roc_cancel(struct p2p_device *dev)
{
	struct l_genl_msg *msg;

	if (!dev->have_roc_cookie)
		return;

	l_debug("");

	msg = l_genl_msg_new_sized(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL, 32);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &dev->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_COOKIE, 8, &dev->roc_cookie);
	l_genl_family_send(dev->nl80211, msg, NULL, NULL, NULL);

	dev->have_roc_cookie = false;
}

static void p2p_scan_timeout_destroy(void *user_data)
{
	struct p2p_device *dev = user_data;

	dev->scan_timeout = NULL;

	if (dev->nl80211) {
		/*
		 * Most likely when the timer expires the ROC period
		 * has finished but send a cancel command to make sure,
		 * as well as handle situations like disabling P2P.
		 */
		p2p_device_roc_cancel(dev);
	}
}

static void p2p_device_roc_cb(struct l_genl_msg *msg, void *user_data)
{
	struct p2p_device *dev = user_data;
	uint64_t cookie;
	int error = l_genl_msg_get_error(msg);

	l_debug("ROC: %s (%i)", strerror(-error), -error);

	if (error)
		return;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_COOKIE, &cookie,
				NL80211_ATTR_UNSPEC) < 0)
		return;

	dev->roc_cookie = cookie;
	dev->have_roc_cookie = true;

	/*
	 * Has the command taken so long that P2P has been since disabled
	 * or the timeout otherwise ran out?
	 */
	if (!dev->scan_timeout)
		p2p_device_roc_cancel(dev);
}

static void p2p_device_roc_start(struct p2p_device *dev)
{
	struct l_genl_msg *msg;
	uint32_t listen_freq;
	uint32_t duration;
	uint32_t cmd_id;

	l_debug("");

	/*
	 * One second granularity is fine here because some randomess
	 * is desired and the intervals don't have strictly defined
	 * limits.
	 */
	duration = (dev->next_scan_ts - time(NULL)) * 1000;

	if (duration < 200)
		duration = 200;

	/*
	 * Driver max duration seems to be 5000ms or more for all drivers
	 * except mac80211_hwsim where it is only 1000ms.
	 */
	if (duration > wiphy_get_max_roc_duration(dev->wiphy))
		duration = wiphy_get_max_roc_duration(dev->wiphy);

	/*
	 * Some drivers seem to miss fewer frames if we start new requests
	 * often.
	 */
	if (duration > 1000)
		duration = 1000;

	/*
	 * Be on our listen channel, even if we're still in the 120s
	 * waiting period after a locally-initiated GO Negotiation and
	 * waiting for the peer's GO Negotiation Request.  It's not
	 * totally clear that this is how the spec intended this
	 * mechanism to work.  On one hand 3.1.4.1 says this:
	 * "A P2P Device may start Group Owner Negotiation by sending a
	 * GO Negotiation Request frame after receiving a Probe Request
	 * frame from the target P2P Device."
	 * and the Appendix D. scenarios also show GO Negotiation happening
	 * on the initiator's listen channel directly after the reception
	 * of the Probe Request from the target.  But:
	 *  1. in 3.1.4.1 that is a MAY and doesn't exclude starting GO
	 *     Negotiation also on the target's listen channel.
	 *  2. not all devices use the search state so we may never
	 *     receive a Probe Request and may end up waiting indefinitely.
	 *  3. the time the peer spends on each channel in the scan state
	 *     may be too short for the peer to receive the GO Negotiation
	 *     Request after the Probe Request before moving to the next
	 *     channel.
	 *  4. since we know the target is going to spend some time on
	 *     their own listen channel, using that channel should work in
	 *     every case.
	 *
	 * We also have this in 3.1.4.1:
	 * "When the P2P Devices arrive on a common channel and begin Group
	 * Owner Negotiation, they shall stay on that channel until Group
	 * Owner Negotiation completes."
	 * telling us that the whole negotiation should be happening on
	 * one channel seemingly supporting the new GO Negotiation being on
	 * the same channel as the original failed GO Negotiation.
	 * However the rest of the spec makes it clear they are not treated
	 * as a single GO Negotiation:
	 * 3.1.4.2:
	 * "Group Owner Negotiation is a three way frame exchange"
	 * 3.1.4.2.2:
	 * "Group Formation ends on transmission or reception of a GO
	 * Negotiation Response frame with the Status Code set to a value
	 * other than Success."
	 *
	 * 3.1.4.1 implies frame exchanges happen on the target device's
	 * Listen Channel, not our Listen Channel:
	 * "Prior to beginning the Group Formation Procedure the P2P Device
	 * shall arrive on a common channel with the target P2P Device.
	 * The Find Phase in In-band Device Discovery or Out-of-Band Device
	 * Discovery may be used for this purpose. In the former case, the
	 * P2P Device only needs to scan the Listen Channel of the target
	 * P2P Device, as opposed to all of the Social Channels."
	 *
	 * All in all we transmit our Negotiation Requests on the peer's
	 * listen channel since it is bound to spend more time on that
	 * channel than on any other channel and then we listen for a
	 * potential GO Negotiation restart on our listen channel.
	 */
	listen_freq = scan_channel_to_freq(dev->listen_channel,
						SCAN_BAND_2_4_GHZ);

	msg = l_genl_msg_new_sized(NL80211_CMD_REMAIN_ON_CHANNEL, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &dev->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &listen_freq);
	l_genl_msg_append_attr(msg, NL80211_ATTR_DURATION, 4, &duration);

	cmd_id = l_genl_family_send(dev->nl80211, msg, p2p_device_roc_cb, dev,
					NULL);
	if (!cmd_id)
		l_genl_msg_unref(msg);

	/*
	 * Time out after @duration ms independent of whether we were able to
	 * start the ROC command.  If we receive the CMD_REMAIN_ON_CHANNEL
	 * event we'll update the timeout to give the ROC command enough time
	 * to finish.  On an error or if we time out before the ROC command
	 * even starts, we'll just retry after @duration ms so we don't even
	 * need to handle errors specifically.
	 */
	dev->scan_timeout = l_timeout_create_ms(duration,
						p2p_device_roc_timeout, dev,
						p2p_scan_timeout_destroy);
	dev->listen_duration = duration;
	dev->have_roc_cookie = false;

	l_debug("started a ROC command on channel %i for %i ms",
		(int) dev->listen_channel, (int) duration);
}

static const char *p2p_peer_wsc_get_path(struct wsc_dbus *wsc)
{
	return p2p_peer_get_path(l_container_of(wsc, struct p2p_peer, wsc));
}

static void p2p_peer_wsc_connect(struct wsc_dbus *wsc, const char *pin)
{
	p2p_peer_connect(l_container_of(wsc, struct p2p_peer, wsc), pin);
}

static void p2p_peer_wsc_cancel(struct wsc_dbus *wsc)
{
	p2p_peer_disconnect(l_container_of(wsc, struct p2p_peer, wsc));
}

static void p2p_peer_wsc_remove(struct wsc_dbus *wsc)
{
	/*
	 * The WSC removal is triggered in p2p_peer_put so we call
	 * p2p_peer_free directly from there too.
	 */
}

static bool p2p_device_peer_add(struct p2p_device *dev, struct p2p_peer *peer)
{
	if (!strlen(peer->name) || !l_utf8_validate(
					peer->name, strlen(peer->name), NULL)) {
		l_debug("Device name doesn't validate for bssid %s",
			util_address_to_string(peer->bss->addr));
		return false;
	}

	if (!l_dbus_object_add_interface(dbus_get_bus(),
						p2p_peer_get_path(peer),
						IWD_P2P_PEER_INTERFACE, peer)) {
		l_debug("Unable to add the %s interface to %s",
			IWD_P2P_PEER_INTERFACE, p2p_peer_get_path(peer));
		return false;
	}

	if (!l_dbus_object_add_interface(dbus_get_bus(),
						p2p_peer_get_path(peer),
						L_DBUS_INTERFACE_PROPERTIES,
						NULL)) {
		l_dbus_unregister_object(dbus_get_bus(),
						p2p_peer_get_path(peer));
		l_debug("Unable to add the %s interface to %s",
			L_DBUS_INTERFACE_PROPERTIES, p2p_peer_get_path(peer));
		return false;
	}

	peer->wsc.get_path = p2p_peer_wsc_get_path;
	peer->wsc.connect = p2p_peer_wsc_connect;
	peer->wsc.cancel = p2p_peer_wsc_cancel;
	peer->wsc.remove = p2p_peer_wsc_remove;

	if (!wsc_dbus_add_interface(&peer->wsc)) {
		l_dbus_unregister_object(dbus_get_bus(),
						p2p_peer_get_path(peer));
		return false;
	}

	l_queue_push_tail(dev->peer_list, peer);

	return true;
}

struct p2p_peer_move_data {
	struct l_queue *new_list;
	struct p2p_peer *conn_peer;
	uint64_t now;
};

static bool p2p_peer_move_recent(void *data, void *user_data)
{
	struct p2p_peer *peer = data;
	struct p2p_peer_move_data *move_data = user_data;

	if (move_data->now > peer->bss->time_stamp + 30 * L_USEC_PER_SEC &&
			peer != move_data->conn_peer)
		return false;	/* Old, keep on the list */

	/* Recently seen or currently connected, move to the new list */
	l_queue_push_tail(move_data->new_list, peer);
	return true;
}

static bool p2p_peer_update_existing(struct scan_bss *bss,
					struct l_queue *old_list,
					struct l_queue *new_list)
{
	struct p2p_peer *peer;

	peer = l_queue_remove_if(old_list, p2p_peer_match, bss->addr);
	if (!peer)
		return false;

	/*
	 * We've seen this peer already, only update the scan_bss object.
	 * We can do this even if peer == peer->dev->conn_peer because
	 * its .bss is not used by .conn_netdev or .conn_enrollee.
	 * .conn_wsc_bss is used for both connections and it doesn't come
	 * from the discovery scan results.
	 * Do we need to update DBus properties?
	 */
	scan_bss_free(peer->bss);
	peer->bss = bss;

	l_queue_push_tail(new_list, peer);
	return true;
}

static bool p2p_scan_notify(int err, struct l_queue *bss_list,
				void *user_data)
{
	struct p2p_device *dev = user_data;
	const struct l_queue_entry *entry;
	struct l_queue *old_peer_list = dev->peer_list;
	struct p2p_peer_move_data move_data;

	if (err) {
		l_debug("P2P scan failed: %s (%i)", strerror(-err), -err);
		goto schedule;
	}

	dev->peer_list = l_queue_new();

	for (entry = l_queue_get_entries(bss_list); entry;
			entry = entry->next) {
		struct scan_bss *bss = entry->data;
		struct p2p_peer *peer;

		if (bss->source_frame != SCAN_BSS_PROBE_RESP ||
				!bss->p2p_probe_resp_info) {
			scan_bss_free(bss);
			continue;
		}

		if (p2p_peer_update_existing(bss, old_peer_list,
						dev->peer_list))
			continue;

		peer = l_new(struct p2p_peer, 1);
		peer->dev = dev;
		peer->bss = bss;
		peer->name = l_strdup(bss->p2p_probe_resp_info->
						device_info.device_name);
		peer->primary_device_type =
			bss->p2p_probe_resp_info->device_info.primary_device_type;
		peer->group =
			!!(bss->p2p_probe_resp_info->capability.group_caps &
			   P2P_GROUP_CAP_GO);
		/*
		 * Both P2P Devices and GOs can send Probe Responses so the
		 * frame's source address may not necessarily be the Device
		 * Address, use what's in the obligatory Device Info.
		 */
		peer->device_addr =
			bss->p2p_probe_resp_info->device_info.device_addr;

		if (!p2p_device_peer_add(dev, peer))
			p2p_peer_free(peer);
	}

	/*
	 * old_peer_list now only contains peers not present in the new
	 * results.  Move any peers seen in the last 30 secs to the new
	 * dev->peer_list and unref only the remaining peers.
	 */
	move_data.new_list = dev->peer_list;
	move_data.conn_peer = dev->conn_peer;
	move_data.now = l_time_now();
	l_queue_foreach_remove(old_peer_list, p2p_peer_move_recent, &move_data);
	l_queue_destroy(old_peer_list, p2p_peer_put);
	l_queue_destroy(bss_list, NULL);

schedule:
	/*
	 * Calculate interval between now and when we want the next active
	 * scan to start.  Keep issuing Remain-on-Channel commands of
	 * maximum duration until it's time to start the new scan.
	 * The listen periods are actually like a passive scan except that
	 * instead of listening for Beacons only, we also look at Probe
	 * Requests and Probe Responses because they, too, carry P2P IEs
	 * with all the information we need about peer devices.  Beacons
	 * also do, in case of GOs, but we will already get the same
	 * information from the Probe Responses and (even if we can
	 * receive the beacons in userspace in the first place) we don't
	 * want to handle so many frames.
	 *
	 * According to 3.1.2.1.1 we shall be available in listen state
	 * during Find for at least 500ms continuously at least once in
	 * every 5s.  According to 3.1.2.1.3, the Listen State lasts for
	 * between 1 and 3 one-hundred TU Intervals.
	 *
	 * The Search State duration is implementation dependent.
	 */
	if (dev->scan_interval < SCAN_INTERVAL_MAX)
		dev->scan_interval += SCAN_INTERVAL_STEP;

	dev->next_scan_ts = time(NULL) + dev->scan_interval;

	p2p_device_roc_start(dev);
	return true;
}

static bool p2p_device_scan_start(struct p2p_device *dev)
{
	struct scan_parameters params = {};
	uint8_t buf[256];
	unsigned int i;

	wiphy_get_reg_domain_country(dev->wiphy, (char *) dev->listen_country);
	dev->listen_country[2] = 4;	/* Table E-4 */
	dev->listen_oper_class = 81;	/* 2.4 band */

	params.extra_ie = p2p_build_scan_ies(dev, buf, sizeof(buf),
						&params.extra_ie_size);
	L_WARN_ON(!params.extra_ie);
	params.flush = true;
	/* P2P Wildcard SSID because we don't need legacy networks to reply */
	params.ssid = "DIRECT-";
	/*
	 * Must send probe requests at 6Mb/s, OFDM only.  The no-CCK rates
	 * flag forces the drivers to do exactly this for 2.4GHz frames.
	 *
	 * "- P2P Devices shall not use 11b rates (1, 2, 5.5, 11 Mbps) for data
	 *   and management frames except:
	 *    * Probe Request frames sent to both P2P Devices and non-P2P
	 *      Devices.
	 * - P2P Devices shall not respond to Probe Request frames that indicate
	 *   support for 11b rates only.
	 * Note 1 - This means that the P2P Group Owner transmits Beacon frames
	 * using OFDM.
	 * Note 2 - This means that the P2P Group Owner transmits Probe Response
	 * frames using OFDM, including frames sent in response to Probe
	 * Requests received at 11b rates from non 11b-only devices.
	 * Note 3 - P2P Devices shall not include 11b rates in the list of
	 * supported rates in Probe Request frame intended only for P2P Devices.
	 * 11b rates may be included in the list of supported rates in Probe
	 * Request frames intended for both P2P Devices and non-P2P Devices."
	 */
	params.no_cck_rates = true;
	params.freqs = scan_freq_set_new();

	for (i = 0; i < L_ARRAY_SIZE(channels_social); i++) {
		int chan = channels_social[i];
		uint32_t freq = scan_channel_to_freq(chan, SCAN_BAND_2_4_GHZ);

		scan_freq_set_add(params.freqs, freq);
	}

	/*
	 * Instead of doing a single Scan Phase at the beginning of the Device
	 * Discovery and then strictly a Find Phase loop as defined in the
	 * spec, mix both to keep watching for P2P groups on the non-social
	 * channels, slowly going through a few channels at a time in each
	 * Scan State iteration.  Scan dev->chans_per_scan channels each time,
	 * use dev->scan_chan_idx to keep track of which channels we've
	 * visited recently.
	 */
	for (i = 0; i < dev->chans_per_scan; i++) {
		int idx = dev->scan_chan_idx++;
		int chan = channels_scan_2_4_other[idx];
		uint32_t freq = scan_channel_to_freq(chan, SCAN_BAND_2_4_GHZ);

		if (dev->scan_chan_idx >=
				L_ARRAY_SIZE(channels_scan_2_4_other)) {
			dev->scan_chan_idx = 0;
			/*
			 * Do fewer channels per scan after we've initially
			 * gone through the 2.4 band.
			 */
			dev->chans_per_scan = CHANS_PER_SCAN;
		}

		scan_freq_set_add(params.freqs, freq);
	}

	dev->scan_id = scan_active_full(dev->wdev_id, &params, NULL,
					p2p_scan_notify, dev, p2p_scan_destroy);
	scan_freq_set_free(params.freqs);

	return dev->scan_id != 0;
}

static void p2p_probe_resp_done(int error, void *user_data)
{
	if (error)
		l_error("Sending the Probe Response failed: %s (%i)",
			strerror(-error), -error);
}

static void p2p_device_send_probe_resp(struct p2p_device *dev,
					const uint8_t *dest_addr)
{
	uint8_t resp_buf[64] __attribute__ ((aligned));
	size_t resp_len = 0;
	struct p2p_probe_resp resp_info = {};
	uint8_t *p2p_ie;
	size_t p2p_ie_size;
	struct wsc_probe_response wsc_info = {};
	uint8_t *wsc_data;
	size_t wsc_data_size;
	uint8_t *wsc_ie;
	size_t wsc_ie_size;
	struct iovec iov[16];
	int iov_len = 0;
	/* TODO: extract some of these from wiphy features */
	uint16_t capability = IE_BSS_CAP_PRIVACY | IE_BSS_CAP_SHORT_PREAMBLE;
	struct mmpdu_header *header;
	uint32_t freq;

	/* Header */
	memset(resp_buf, 0, sizeof(resp_buf));
	header = (void *) resp_buf;
	header->fc.protocol_version = 0;
	header->fc.type = MPDU_TYPE_MANAGEMENT;
	header->fc.subtype = MPDU_MANAGEMENT_SUBTYPE_PROBE_RESPONSE;
	memcpy(header->address_1, dest_addr, 6);	/* DA */
	memcpy(header->address_2, dev->addr, 6);	/* SA */
	memcpy(header->address_3, dev->addr, 6);	/* BSSID */

	resp_len = (const uint8_t *) mmpdu_body(header) - resp_buf;

	resp_len += 8;			/* Timestamp */
	resp_buf[resp_len++] = 0x64;	/* Beacon Interval: 100 TUs */
	resp_buf[resp_len++] = 0x00;
	resp_buf[resp_len++] = capability >> 0;
	resp_buf[resp_len++] = capability >> 8;
	resp_buf[resp_len++] = IE_TYPE_SSID;
	resp_buf[resp_len++] = 7;
	resp_buf[resp_len++] = 'D';
	resp_buf[resp_len++] = 'I';
	resp_buf[resp_len++] = 'R';
	resp_buf[resp_len++] = 'E';
	resp_buf[resp_len++] = 'C';
	resp_buf[resp_len++] = 'T';
	resp_buf[resp_len++] = '-';
	resp_buf[resp_len++] = IE_TYPE_SUPPORTED_RATES;
	resp_buf[resp_len++] = 8;
	resp_buf[resp_len++] = 0x8c;
	resp_buf[resp_len++] = 0x12;
	resp_buf[resp_len++] = 0x18;
	resp_buf[resp_len++] = 0x24;
	resp_buf[resp_len++] = 0x30;
	resp_buf[resp_len++] = 0x48;
	resp_buf[resp_len++] = 0x60;
	resp_buf[resp_len++] = 0x6c;

	resp_info.capability = dev->capability;
	resp_info.device_info = dev->device_info;

	p2p_ie = p2p_build_probe_resp(&resp_info, &p2p_ie_size);
	if (!p2p_ie) {
		l_error("Can't build our Probe Response P2P IE");
		return;
	}

	wsc_info.state = WSC_STATE_CONFIGURED;
	wsc_info.response_type = WSC_RESPONSE_TYPE_ENROLLEE_OPEN_8021X;
	wsc_info.uuid_e[15] = 0x01;
	wsc_info.serial_number[0] = '0';
	wsc_info.primary_device_type = dev->device_info.primary_device_type;
	l_strlcpy(wsc_info.device_name, dev->device_info.device_name,
			sizeof(wsc_info.device_name));
	wsc_info.config_methods = dev->device_info.wsc_config_methods;
	wsc_info.rf_bands = 0x01;	/* 2.4GHz */
	wsc_info.version2 = true;

	wsc_data = wsc_build_probe_response(&wsc_info, &wsc_data_size);
	if (!wsc_data) {
		l_free(p2p_ie);
		l_error("Can't build our Probe Response WSC payload");
		return;
	}

	wsc_ie = ie_tlv_encapsulate_wsc_payload(wsc_data, wsc_data_size,
						&wsc_ie_size);
	l_free(wsc_data);
	if (!wsc_ie) {
		l_free(p2p_ie);
		l_error("Can't build our Probe Response WSC IE");
		return;
	}

	iov[iov_len].iov_base = resp_buf;
	iov[iov_len].iov_len = resp_len;
	iov_len++;

	iov[iov_len].iov_base = p2p_ie;
	iov[iov_len].iov_len = p2p_ie_size;
	iov_len++;

	iov[iov_len].iov_base = wsc_ie;
	iov[iov_len].iov_len = wsc_ie_size;
	iov_len++;

	/* WFD and other service IEs go here */

	iov[iov_len].iov_base = NULL;

	freq = scan_channel_to_freq(dev->listen_channel, SCAN_BAND_2_4_GHZ);
	frame_xchg_start(dev->wdev_id, iov, freq, 0, 0, false, 0,
				p2p_probe_resp_done, dev, NULL);
	l_debug("Probe Response tx queued");

	l_free(p2p_ie);
	l_free(wsc_ie);
}

static void p2p_device_probe_cb(const struct mmpdu_header *mpdu,
				const void *body, size_t body_len,
				int rssi, void *user_data)
{
	struct p2p_device *dev = user_data;
	struct p2p_peer *peer;
	struct p2p_probe_req p2p_info;
	struct wsc_probe_request wsc_info;
	int r;
	uint8_t *wsc_payload;
	ssize_t wsc_len;
	struct scan_bss *bss;
	struct p2p_channel_attr *channel;
	enum scan_band band;
	uint32_t frequency;
	bool from_conn_peer;

	l_debug("");

	if (!dev->scan_timeout && !dev->scan_id)
		return;

	from_conn_peer =
		dev->go_neg_req_timeout && dev->conn_peer &&
		!memcmp(mpdu->address_2, dev->conn_peer->bss->addr, 6);

	wsc_payload = ie_tlv_extract_wsc_payload(body, body_len, &wsc_len);
	if (!wsc_payload)	/* Not a P2P Probe Req, ignore */
		return;

	r =  wsc_parse_probe_request(wsc_payload, wsc_len, &wsc_info);
	l_free(wsc_payload);

	if (r < 0) {
		l_error("Probe Request WSC IE parse error %s (%i)",
			strerror(-r), -r);

		/*
		 * Ignore requests with erroneous WSC IEs except if they
		 * come from the peer we're currently connecting to as a
		 * workaround for implementations sending invalid Probe
		 * Requests.
		 */
		if (!from_conn_peer)
			return;
	}

	r = p2p_parse_probe_req(body, body_len, &p2p_info);
	if (r < 0) {
		if (r == -ENOENT)	/* Not a P2P Probe Req, ignore */
			return;

		l_error("Probe Request P2P IE parse error %s (%i)",
			strerror(-r), -r);
		return;
	}

	/*
	 * We don't currently have a use case for replying to Probe Requests
	 * except when waiting for a GO Negotiation Request from our target
	 * peer.  Some of those peers (seemingly running ancient and/or
	 * hw-manufacturer-provided versions of wpa_s) will only send us GO
	 * Negotiation Requests each time they receive our Probe Response
	 * frame, even if that frame's body is unparsable.
	 */
	if (from_conn_peer) {
		/*
		 * TODO: use ap.c code to check if we match the SSID, BSSID,
		 * DSSS Channel etc. in the Probe Request, and to build the
		 * Response body.
		 */
		p2p_device_send_probe_resp(dev, mpdu->address_2);
		goto p2p_free;
	}

	/*
	 * The peer's listen frequency may be different from ours.
	 * The Listen Channel attribute is optional but if neither
	 * it nor the Operating Channel are set then we have no way
	 * to contact that peer.  Ignore such peers.
	 */
	if (p2p_info.listen_channel.country[0])
		channel = &p2p_info.listen_channel;
	else if (p2p_info.operating_channel.country[0])
		channel = &p2p_info.operating_channel;
	else
		goto p2p_free;

	band = scan_oper_class_to_band((const uint8_t *) channel->country,
					channel->oper_class);
	frequency = scan_channel_to_freq(channel->channel_num, band);
	if (!frequency)
		goto p2p_free;

	bss = scan_bss_new_from_probe_req(mpdu, body, body_len, frequency,
						rssi);
	if (!bss)
		goto p2p_free;

	bss->time_stamp = l_time_now();

	if (p2p_peer_update_existing(bss, dev->peer_list, dev->peer_list))
		goto p2p_free;

	peer = l_new(struct p2p_peer, 1);
	peer->dev = dev;
	peer->bss = bss;
	peer->name = l_strdup(wsc_info.device_name);
	peer->primary_device_type = wsc_info.primary_device_type;
	peer->group = !!(p2p_info.capability.group_caps & P2P_GROUP_CAP_GO);
	/*
	 * The Device Info attribute is present conditionally so we can't get
	 * the Device Address from there.  In theory only P2P Devices send
	 * out Probe Requests, not P2P GOs, so we assume the source address
	 * is the Device Address.
	 */
	peer->device_addr = bss->addr;

	if (!p2p_device_peer_add(dev, peer))
		p2p_peer_free(peer);

	/*
	 * TODO: check SSID/BSSID are wildcard values if present and
	 * reply with a Probe Response -- not useful in our current usage
	 * scenarios but required by the spec.
	 */

p2p_free:
	p2p_clear_probe_req(&p2p_info);
}

static void p2p_device_discovery_start(struct p2p_device *dev)
{
	if (dev->scan_timeout || dev->scan_id)
		return;

	dev->scan_interval = 1;
	dev->chans_per_scan = CHANS_PER_SCAN_INITIAL;
	dev->scan_chan_idx = 0;

	/*
	 * 3.1.2.1.1: "The Listen Channel shall be chosen at the beginning of
	 * the In-band Device Discovery"
	 *
	 * But keep the old channel if we're still waiting for the peer to
	 * restart the GO Negotiation because there may not be enough time
	 * for the peer to update our Listen Channel value before the user
	 * accepts the connection.  In that case the GO Negotiation Request
	 * would be sent on the old channel.
	 */
	if (!(dev->listen_channel && dev->conn_peer))
		dev->listen_channel = channels_social[l_getrandom_uint32() %
						L_ARRAY_SIZE(channels_social)];

	frame_watch_add(dev->wdev_id, FRAME_GROUP_LISTEN, 0x0040,
			(uint8_t *) "", 0, p2p_device_probe_cb, dev, NULL);
	frame_watch_add(dev->wdev_id, FRAME_GROUP_LISTEN, 0x00d0,
			p2p_frame_go_neg_req.data, p2p_frame_go_neg_req.len,
			p2p_device_go_negotiation_req_cb, dev, NULL);

	p2p_device_scan_start(dev);
}

static void p2p_device_discovery_stop(struct p2p_device *dev)
{
	dev->scan_interval = 0;

	if (dev->scan_id)
		scan_cancel(dev->wdev_id, dev->scan_id);

	if (dev->scan_timeout)
		l_timeout_remove(dev->scan_timeout);

	p2p_device_roc_cancel(dev);
	frame_watch_group_remove(dev->wdev_id, FRAME_GROUP_LISTEN);
}

static void p2p_device_enable_cb(struct l_genl_msg *msg, void *user_data)
{
	struct p2p_device *dev = user_data;
	int error = l_genl_msg_get_error(msg);
	struct l_dbus_message *message = dev->pending_message;

	l_debug("START/STOP_P2P_DEVICE: %s (%i)", strerror(-error), -error);

	if (error)
		goto done;

	dev->enabled = !dev->enabled;

	if (dev->enabled && !l_queue_isempty(dev->discovery_users))
		p2p_device_discovery_start(dev);

done:
	dev->pending_complete(dbus_get_bus(), message,
				error ? dbus_error_failed(message) :
				NULL);
	dev->pending_message = NULL;
	dev->pending_complete = NULL;

	if (!error)
		l_dbus_property_changed(dbus_get_bus(),
					p2p_device_get_path(dev),
					IWD_P2P_INTERFACE, "Enabled");
}

static void p2p_device_enable_destroy(void *user_data)
{
	struct p2p_device *dev = user_data;

	dev->start_stop_cmd_id = 0;
}

static bool p2p_peer_remove_disconnected(void *peer, void *conn_peer)
{
	if (peer == conn_peer)
		return false;

	p2p_peer_put(peer);
	return true;
}

static void p2p_device_start_stop(struct p2p_device *dev,
				l_dbus_property_complete_cb_t complete,
				struct l_dbus_message *message)
{
	struct l_genl_msg *cmd;

	if (dev->enabled)
		p2p_device_discovery_stop(dev);

	if (!dev->enabled)
		cmd = l_genl_msg_new_sized(NL80211_CMD_START_P2P_DEVICE, 16);
	else
		cmd = l_genl_msg_new_sized(NL80211_CMD_STOP_P2P_DEVICE, 16);

	l_genl_msg_append_attr(cmd, NL80211_ATTR_WDEV, 8, &dev->wdev_id);

	dev->start_stop_cmd_id = l_genl_family_send(dev->nl80211, cmd,
						p2p_device_enable_cb, dev,
						p2p_device_enable_destroy);
	if (!dev->start_stop_cmd_id) {
		l_genl_msg_unref(cmd);
		complete(dbus_get_bus(), message, dbus_error_failed(message));
		return;
	}

	dev->pending_message = message;
	dev->pending_complete = complete;

	if (dev->enabled) {
		/*
		 * Stopping the P2P device, drop all peers as we can't start
		 * new connections from now on.  Check if we have a connection
		 * being set up without a .conn_netdev and without
		 * .conn_wsc_bss -- this will mean the connection is still in
		 * the PD or GO Negotiation phase or inside the scan.  Those
		 * phases happen on the device interface so the connection
		 * gets immediately aborted.
		 */
		if (dev->conn_peer && !dev->conn_netdev && !dev->conn_wsc_bss)
			p2p_connect_failed(dev);

		if (!dev->conn_peer) {
			l_queue_destroy(dev->peer_list, p2p_peer_put);
			dev->peer_list = NULL;
		} else
			/*
			 * If the connection already depends on its own
			 * netdev only, we can let it continue until the user
			 * decides to disconnect.
			 */
			l_queue_foreach_remove(dev->peer_list,
						p2p_peer_remove_disconnected,
						dev->conn_peer);
	}
}

static void p2p_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct p2p_device *dev = user_data;
	uint64_t wdev_id;
	uint64_t cookie;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV, &wdev_id,
				NL80211_ATTR_COOKIE, &cookie,
				NL80211_ATTR_UNSPEC) < 0 ||
			wdev_id != dev->wdev_id)
		return;

	switch (l_genl_msg_get_command(msg)) {
	case NL80211_CMD_REMAIN_ON_CHANNEL:
		if (!dev->have_roc_cookie || cookie != dev->roc_cookie)
			break;

		if (!dev->scan_timeout)
			break;

		/*
		 * The Listen phase is actually starting here, update the
		 * timeout so we know more or less when it ends.
		 */
		l_debug("ROC started");
		l_timeout_modify_ms(dev->scan_timeout, dev->listen_duration);
		break;
	case NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL:
		/* TODO */
		break;
	}
}

#define P2P_SUPPORTED_METHODS	(			\
	WSC_CONFIGURATION_METHOD_LABEL |		\
	WSC_CONFIGURATION_METHOD_KEYPAD |		\
	WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON |	\
	WSC_CONFIGURATION_METHOD_PHYSICAL_PUSH_BUTTON |	\
	WSC_CONFIGURATION_METHOD_P2P |			\
	WSC_CONFIGURATION_METHOD_VIRTUAL_DISPLAY_PIN |	\
	WSC_CONFIGURATION_METHOD_PHYSICAL_DISPLAY_PIN)

struct p2p_device *p2p_device_update_from_genl(struct l_genl_msg *msg,
						bool create)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint8_t *ifaddr = NULL;
	const uint64_t *wdev_id = NULL;
	struct wiphy *wiphy = NULL;
	struct p2p_device *dev;
	char hostname[HOST_NAME_MAX + 1];
	char *str;
	unsigned int uint_val;

	if (!l_genl_attr_init(&attr, msg))
		return NULL;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WDEV:
			if (len != sizeof(uint64_t)) {
				l_warn("Invalid wdev index attribute");
				return NULL;
			}

			wdev_id = data;
			break;

		case NL80211_ATTR_WIPHY:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid wiphy attribute");
				return NULL;
			}

			wiphy = wiphy_find(*((uint32_t *) data));
			break;

		case NL80211_ATTR_IFTYPE:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface type attribute");
				return NULL;
			}

			if (*((uint32_t *) data) != NL80211_IFTYPE_P2P_DEVICE)
				return NULL;

			break;

		case NL80211_ATTR_MAC:
			if (len != ETH_ALEN) {
				l_warn("Invalid interface address attribute");
				return NULL;
			}

			ifaddr = data;
			break;
		}
	}

	if (!wiphy || !wdev_id || !ifaddr) {
		l_warn("Unable to parse interface information");
		return NULL;
	}

	if (create) {
		if (p2p_device_find(*wdev_id)) {
			l_debug("Duplicate p2p device %" PRIx64, *wdev_id);
			return NULL;
		}
	} else {
		dev = p2p_device_find(*wdev_id);
		if (!dev)
			return NULL;

		memcpy(dev->addr, ifaddr, ETH_ALEN);
		return NULL;
	}

	dev = l_new(struct p2p_device, 1);
	dev->wdev_id = *wdev_id;
	memcpy(dev->addr, ifaddr, ETH_ALEN);
	dev->nl80211 = l_genl_family_new(iwd_get_genl(), NL80211_GENL_NAME);
	dev->wiphy = wiphy;
	gethostname(hostname, sizeof(hostname));
	dev->connections_left = 1;

	/* TODO: allow masking capability bits through a setting? */
	dev->capability.device_caps = P2P_DEVICE_CAP_CONCURRENT_OP;
	dev->capability.group_caps = 0;

	memcpy(dev->device_info.device_addr, dev->addr, 6);

	dev->device_info.wsc_config_methods =
		WSC_CONFIGURATION_METHOD_P2P |
		WSC_CONFIGURATION_METHOD_PUSH_BUTTON;
	dev->device_info.primary_device_type.category = 1;	/* Computer */
	memcpy(dev->device_info.primary_device_type.oui, microsoft_oui, 3);
	dev->device_info.primary_device_type.oui_type = 0x04;
	dev->device_info.primary_device_type.subcategory = 1;	/* PC */
	l_strlcpy(dev->device_info.device_name, hostname,
			sizeof(dev->device_info.device_name));

	if (l_settings_get_uint(iwd_get_config(), "P2P",
				"ConfigurationMethods", &uint_val)) {
		if (!(uint_val & P2P_SUPPORTED_METHODS))
			l_error("[P2P].ConfigurationMethods must contain "
				"at least one supported method");
		else if (uint_val & ~0xffff)
			l_error("[P2P].ConfigurationMethods should be a "
				"16-bit integer");
		else
			dev->device_info.wsc_config_methods =
				uint_val & P2P_SUPPORTED_METHODS;
	}

	str = l_settings_get_string(iwd_get_config(), "P2P", "DeviceType");

	/*
	 * Standard WSC subcategories are unique and more specific than
	 * categories so there's no point for the user to specify the
	 * category if they choose to use the string format.
	 *
	 * As an example our default value (Computer - PC) can be
	 * encoded as either of:
	 *
	 * DeviceType=pc
	 * DeviceType=0x00010050f2040001
	 */
	if (str && !wsc_device_type_from_subcategory_str(
					&dev->device_info.primary_device_type,
					str)) {
		unsigned long long u;
		char *endp;

		u = strtoull(str, &endp, 0);

		/*
		 * Accept any custom category, OUI and subcategory values but
		 * require non-zero category as a sanity check.
		 */
		if (*endp != '\0' || (u & 0xffff000000000000ll) == 0)
			l_error("[P2P].DeviceType must be a subcategory string "
				"or a 64-bit integer encoding the full Primary"
				" Device Type attribute: "
				"<Category>|<OUI>|<OUI Type>|<Subcategory>");
		else {
			dev->device_info.primary_device_type.category = u >> 48;
			dev->device_info.primary_device_type.oui[0] = u >> 40;
			dev->device_info.primary_device_type.oui[1] = u >> 32;
			dev->device_info.primary_device_type.oui[2] = u >> 24;
			dev->device_info.primary_device_type.oui_type = u >> 16;
			dev->device_info.primary_device_type.subcategory = u;
		}
	}

	l_queue_push_tail(p2p_device_list, dev);

	l_debug("Created P2P device %" PRIx64, dev->wdev_id);

	scan_wdev_add(dev->wdev_id);

	if (!l_genl_family_register(dev->nl80211, NL80211_MULTICAST_GROUP_MLME,
					p2p_mlme_notify, dev, NULL))
		l_error("Registering for MLME notifications failed");

	if (!l_dbus_object_add_interface(dbus_get_bus(),
						p2p_device_get_path(dev),
						IWD_P2P_INTERFACE, dev))
		l_info("Unable to add the %s interface to %s",
			IWD_P2P_INTERFACE, p2p_device_get_path(dev));

	return dev;
}

static void p2p_device_free(void *user_data)
{
	struct p2p_device *dev = user_data;

	if (dev->pending_message) {
		struct l_dbus_message *reply =
			dbus_error_aborted(dev->pending_message);

		dev->pending_complete(dbus_get_bus(),
					dev->pending_message, reply);
		dev->pending_message = NULL;
		dev->pending_complete = NULL;
	}

	p2p_device_discovery_stop(dev);
	p2p_connection_reset(dev);
	l_dbus_unregister_object(dbus_get_bus(), p2p_device_get_path(dev));
	l_queue_destroy(dev->peer_list, p2p_peer_put);
	l_queue_destroy(dev->discovery_users, p2p_discovery_user_free);
	l_genl_family_free(dev->nl80211); /* Cancels dev->start_stop_cmd_id */
	scan_wdev_remove(dev->wdev_id);
	l_free(dev);
}

bool p2p_device_destroy(struct p2p_device *dev)
{
	if (!l_queue_remove(p2p_device_list, dev))
		return false;

	p2p_device_free(dev);
	return true;
}

static bool p2p_device_get_enabled(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct p2p_device *dev = user_data;
	bool enabled = dev->enabled;

	l_dbus_message_builder_append_basic(builder, 'b', &enabled);

	return true;
}

static struct l_dbus_message *p2p_device_set_enabled(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct p2p_device *dev = user_data;
	bool new_enabled;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &new_enabled))
		return dbus_error_invalid_args(message);

	if (dev->start_stop_cmd_id || dev->pending_message)
		return dbus_error_busy(message);

	if (dev->enabled == new_enabled) {
		complete(dbus, message, NULL);
		return NULL;
	}

	p2p_device_start_stop(dev, complete, message);
	return NULL;
}

static bool p2p_device_get_name(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct p2p_device *dev = user_data;

	l_dbus_message_builder_append_basic(builder, 's',
						dev->device_info.device_name);
	return true;
}

static struct l_dbus_message *p2p_device_set_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct p2p_device *dev = user_data;
	const char *new_name;
	bool changed = false;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &new_name))
		return dbus_error_invalid_args(message);

	if (!strcmp(new_name, dev->device_info.device_name))
		goto done;

	if (strlen(new_name) > sizeof(dev->device_info.device_name) - 1)
		return dbus_error_invalid_args(message);

	changed = true;
	l_strlcpy(dev->device_info.device_name, new_name,
			sizeof(dev->device_info.device_name));

done:
	complete(dbus, message, NULL);

	if (changed)
		l_dbus_property_changed(dbus, p2p_device_get_path(dev),
					IWD_P2P_INTERFACE, "Name");

	return NULL;
}

static bool p2p_device_get_avail_conns(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct p2p_device *dev = user_data;
	uint16_t avail_conns = dev->connections_left;

	l_dbus_message_builder_append_basic(builder, 'q', &avail_conns);
	return true;
}

static struct l_dbus_message *p2p_device_get_peers(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct p2p_device *dev = user_data;
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;
	const struct l_queue_entry *entry;

	if (!l_dbus_message_get_arguments(message, ""))
		return dbus_error_invalid_args(message);

	reply = l_dbus_message_new_method_return(message);
	builder = l_dbus_message_builder_new(reply);

	l_dbus_message_builder_enter_array(builder, "(on)");

	for (entry = l_queue_get_entries(dev->peer_list); entry;
			entry = entry->next) {
		const struct p2p_peer *peer = entry->data;
		int16_t signal_strength = peer->bss->signal_strength;

		l_dbus_message_builder_enter_struct(builder, "on");
		l_dbus_message_builder_append_basic(builder, 'o',
						p2p_peer_get_path(peer));
		l_dbus_message_builder_append_basic(builder, 'n',
							&signal_strength);
		l_dbus_message_builder_leave_struct(builder);
	}

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static void p2p_device_discovery_disconnect(struct l_dbus *dbus, void *user_data)
{
	struct p2p_discovery_user *user = user_data;
	struct p2p_device *dev = user->dev;

	l_debug("P2P Device Discovery user %s disconnected", user->client);

	l_queue_remove(dev->discovery_users, user);
	p2p_discovery_user_free(user);

	if (l_queue_isempty(dev->discovery_users))
		p2p_device_discovery_stop(dev);
}

static void p2p_device_discovery_destroy(void *user_data)
{
	struct p2p_discovery_user *user = user_data;

	user->disconnect_watch = 0;
}

static struct l_dbus_message *p2p_device_request_discovery(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct p2p_device *dev = user_data;
	struct p2p_discovery_user *user;
	bool first_user = l_queue_isempty(dev->discovery_users);

	if (!l_dbus_message_get_arguments(message, ""))
		return dbus_error_invalid_args(message);

	if (l_queue_find(dev->discovery_users, p2p_discovery_user_match,
				l_dbus_message_get_sender(message)))
		return dbus_error_already_exists(message);

	user = l_new(struct p2p_discovery_user, 1);
	user->client = l_strdup(l_dbus_message_get_sender(message));
	user->dev = dev;
	user->disconnect_watch = l_dbus_add_disconnect_watch(dbus,
						user->client,
						p2p_device_discovery_disconnect,
						user,
						p2p_device_discovery_destroy);
	l_queue_push_tail(dev->discovery_users, user);

	if (first_user && !dev->conn_peer && dev->enabled)
		p2p_device_discovery_start(dev);

	return l_dbus_message_new_method_return(message);
}

static struct l_dbus_message *p2p_device_release_discovery(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct p2p_device *dev = user_data;
	struct p2p_discovery_user *user;

	if (!l_dbus_message_get_arguments(message, ""))
		return dbus_error_invalid_args(message);

	user = l_queue_remove_if(dev->discovery_users,
				p2p_discovery_user_match,
				l_dbus_message_get_sender(message));
	if (!user)
		return dbus_error_not_found(message);

	p2p_discovery_user_free(user);

	/*
	 * If dev->conn_peer is non-NULL, we may be scanning as a way to
	 * listen for a GO Negotiation Request from the target peer.  In
	 * that case we don't stop the device discovery when the list
	 * becomes empty.
	 */
	if (l_queue_isempty(dev->discovery_users) && !dev->conn_peer)
		p2p_device_discovery_stop(dev);

	return l_dbus_message_new_method_return(message);
}

static void p2p_interface_setup(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, "Enabled", 0, "b",
					p2p_device_get_enabled,
					p2p_device_set_enabled);
	l_dbus_interface_property(interface, "Name", 0, "s",
					p2p_device_get_name,
					p2p_device_set_name);
	l_dbus_interface_property(interface, "AvailableConnections", 0, "q",
					p2p_device_get_avail_conns, NULL);
	l_dbus_interface_method(interface, "GetPeers", 0,
				p2p_device_get_peers, "a(on)", "", "peers");
	l_dbus_interface_method(interface, "RequestDiscovery", 0,
				p2p_device_request_discovery, "", "");
	l_dbus_interface_method(interface, "ReleaseDiscovery", 0,
				p2p_device_release_discovery, "", "");
}

static bool p2p_peer_get_name(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct p2p_peer *peer = user_data;

	l_dbus_message_builder_append_basic(builder, 's', peer->name);
	return true;
}

static bool p2p_peer_get_category(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct p2p_peer *peer = user_data;
	const char *category;

	if (!wsc_device_type_to_dbus_str(&peer->primary_device_type,
						&category, NULL) ||
			!category)
		category = "unknown-device";

	l_dbus_message_builder_append_basic(builder, 's', category);
	return true;
}

static bool p2p_peer_get_subcategory(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct p2p_peer *peer = user_data;
	const char *subcategory;

	/*
	 * Should we generate subcategory strings with the numerical
	 * values for the subcategories we don't know, such as
	 * "Vendor-specific 00:11:22:33 44" ?
	 */

	if (!wsc_device_type_to_dbus_str(&peer->primary_device_type,
						NULL, &subcategory) ||
			!subcategory)
		return false;

	l_dbus_message_builder_append_basic(builder, 's', subcategory);
	return true;
}

static bool p2p_peer_get_connected(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct p2p_peer *peer = user_data;
	bool connected = p2p_peer_operational(peer) &&
		peer->dev->conn_peer == peer;

	l_dbus_message_builder_append_basic(builder, 'b', &connected);
	return true;
}

static struct l_dbus_message *p2p_peer_dbus_disconnect(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct p2p_peer *peer = user_data;

	if (!l_dbus_message_get_arguments(message, ""))
		return dbus_error_invalid_args(message);

	/*
	 * Save the message for both WSC.Cancel and Peer.Disconnect the
	 * same way.
	 */
	peer->wsc.pending_cancel = l_dbus_message_ref(message);

	p2p_peer_disconnect(peer);
	return NULL;
}

static void p2p_peer_interface_setup(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, "Name", 0, "s",
					p2p_peer_get_name, NULL);
	l_dbus_interface_property(interface, "DeviceCategory", 0, "s",
					p2p_peer_get_category, NULL);
	l_dbus_interface_property(interface, "DeviceSubcategory", 0, "s",
					p2p_peer_get_subcategory, NULL);
	l_dbus_interface_property(interface, "Connected", 0, "b",
					p2p_peer_get_connected, NULL);
	l_dbus_interface_method(interface, "Disconnect", 0,
				p2p_peer_dbus_disconnect, "", "");
}

static int p2p_init(void)
{
	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_P2P_INTERFACE,
					p2p_interface_setup,
					NULL, false))
		l_error("Unable to register the %s interface",
			IWD_P2P_INTERFACE);

	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_P2P_PEER_INTERFACE,
					p2p_peer_interface_setup,
					NULL, false))
		l_error("Unable to register the %s interface",
			IWD_P2P_PEER_INTERFACE);

	p2p_dhcp_settings = l_settings_new();
	p2p_device_list = l_queue_new();

	return 0;
}

static void p2p_exit(void)
{
	l_dbus_unregister_interface(dbus_get_bus(), IWD_P2P_INTERFACE);
	l_dbus_unregister_interface(dbus_get_bus(), IWD_P2P_PEER_INTERFACE);
	l_queue_destroy(p2p_device_list, p2p_device_free);
	p2p_device_list = NULL;
	l_settings_free(p2p_dhcp_settings);
	p2p_dhcp_settings = NULL;
}

IWD_MODULE(p2p, p2p_init, p2p_exit)
IWD_MODULE_DEPENDS(p2p, wiphy)
IWD_MODULE_DEPENDS(p2p, scan)
IWD_MODULE_DEPENDS(p2p, netconfig)
