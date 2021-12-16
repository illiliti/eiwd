/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/dbus.h"
#include "src/netdev.h"
#include "src/module.h"
#include "src/dpp-util.h"
#include "src/band.h"
#include "src/frame-xchg.h"
#include "src/offchannel.h"
#include "src/wiphy.h"
#include "src/ie.h"
#include "src/iwd.h"
#include "src/util.h"

static uint32_t netdev_watch;
static struct l_genl_family *nl80211;
static uint8_t broadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

enum dpp_state {
	DPP_STATE_NOTHING,
	DPP_STATE_PRESENCE,
};

struct dpp_sm {
	struct netdev *netdev;
	char *uri;

	uint64_t wdev_id;

	uint8_t *pub_asn1;
	size_t pub_asn1_len;
	uint8_t pub_boot_hash[32];
	const struct l_ecc_curve *curve;
	size_t key_len;
	size_t nonce_len;
	struct l_ecc_scalar *boot_private;
	struct l_ecc_point *boot_public;

	enum dpp_state state;

	uint32_t *freqs;
	size_t freqs_len;
	size_t freqs_idx;
	uint32_t dwell;
	uint32_t current_freq;
	struct scan_freq_set *presence_list;

	uint32_t offchannel_id;
};

static void dpp_reset(struct dpp_sm *dpp)
{
	if (dpp->uri) {
		l_free(dpp->uri);
		dpp->uri = NULL;
	}

	if (dpp->freqs) {
		l_free(dpp->freqs);
		dpp->freqs = NULL;
	}

	if (dpp->offchannel_id) {
		offchannel_cancel(dpp->wdev_id, dpp->offchannel_id);
		dpp->offchannel_id = 0;
	}

	dpp->state = DPP_STATE_NOTHING;
}

static void dpp_free(struct dpp_sm *dpp)
{
	dpp_reset(dpp);

	if (dpp->pub_asn1) {
		l_free(dpp->pub_asn1);
		dpp->pub_asn1 = NULL;
	}

	if (dpp->boot_public) {
		l_ecc_point_free(dpp->boot_public);
		dpp->boot_public = NULL;
	}

	if (dpp->boot_private) {
		l_ecc_scalar_free(dpp->boot_private);
		dpp->boot_private = NULL;
	}

	l_free(dpp);
}

static void dpp_send_frame_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("Error sending frame");
}

static void dpp_send_frame(uint64_t wdev_id, struct iovec *iov, size_t iov_len,
			uint32_t freq)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &freq);
	l_genl_msg_append_attr(msg, NL80211_ATTR_OFFCHANNEL_TX_OK, 0, NULL);
	l_genl_msg_append_attrv(msg, NL80211_ATTR_FRAME, iov, iov_len);

	l_debug("Sending frame on frequency %u", freq);

	if (!l_genl_family_send(nl80211, msg, dpp_send_frame_cb, NULL, NULL))
		l_error("Could not send CMD_FRAME");
}

static size_t dpp_append_attr(uint8_t *to, enum dpp_attribute_type type,
				void *attr, size_t attr_len)
{
	l_put_le16(type, to);
	l_put_le16(attr_len, to + 2);
	memcpy(to + 4, attr, attr_len);

	return attr_len + 4;
}

static size_t dpp_build_header(const uint8_t *src, const uint8_t *dest,
				enum dpp_frame_type type,
				uint8_t buf[static 32])
{
	uint8_t *ptr = buf + 24;

	memset(buf, 0, 32);

	l_put_le16(0x00d0, buf);
	memcpy(buf + 4, dest, 6);
	memcpy(buf + 10, src, 6);
	memcpy(buf + 16, broadcast, 6);

	*ptr++ = 0x04;			/* Category: Public */
	*ptr++ = 0x09;			/* Action: Vendor specific usage */
	memcpy(ptr, wifi_alliance_oui, 3);
	ptr += 3;
	*ptr++ = 0x1a;			/* WiFi Alliance DPP OI type */
	*ptr++ = 1;			/* Cryptosuite */
	*ptr++ = type;

	return ptr - buf;
}

static void dpp_presence_announce(struct dpp_sm *dpp)
{
	struct netdev *netdev = dpp->netdev;
	uint8_t hdr[32];
	uint8_t attrs[32 + 4];
	uint8_t hash[32];
	uint8_t *ptr = attrs;
	const uint8_t *addr = netdev_get_address(netdev);
	struct iovec iov[2];

	iov[0].iov_len = dpp_build_header(addr, broadcast,
					DPP_FRAME_PRESENCE_ANNOUNCEMENT, hdr);
	iov[0].iov_base = hdr;

	dpp_hash(L_CHECKSUM_SHA256, hash, 2, "chirp", strlen("chirp"),
			dpp->pub_asn1, dpp->pub_asn1_len);

	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH, hash, 32);

	iov[1].iov_base = attrs;
	iov[1].iov_len = ptr - attrs;

	l_debug("Sending presense annoucement on frequency %u and waiting %u",
		dpp->current_freq, dpp->dwell);

	dpp_send_frame(netdev_get_wdev_id(netdev), iov, 2, dpp->current_freq);
}

static void dpp_roc_started(void *user_data)
{
	struct dpp_sm *dpp = user_data;

	dpp_presence_announce(dpp);
}

static void dpp_create(struct netdev *netdev)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct dpp_sm *dpp = l_new(struct dpp_sm, 1);

	dpp->netdev = netdev;
	dpp->state = DPP_STATE_NOTHING;
	dpp->wdev_id = netdev_get_wdev_id(netdev);
	dpp->curve = l_ecc_curve_from_ike_group(19);
	dpp->key_len = l_ecc_curve_get_scalar_bytes(dpp->curve);
	dpp->nonce_len = dpp_nonce_len_from_key_len(dpp->key_len);

	l_ecdh_generate_key_pair(dpp->curve, &dpp->boot_private,
					&dpp->boot_public);

	dpp->pub_asn1 = dpp_point_to_asn1(dpp->boot_public, &dpp->pub_asn1_len);

	dpp_hash(L_CHECKSUM_SHA256, dpp->pub_boot_hash, 1,
			dpp->pub_asn1, dpp->pub_asn1_len);

	l_dbus_object_add_interface(dbus, netdev_get_path(netdev),
					IWD_DPP_INTERFACE, dpp);
}

static void dpp_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_NEW:
	case NETDEV_WATCH_EVENT_UP:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_STATION &&
				netdev_get_is_up(netdev))
			dpp_create(netdev);
		break;
	case NETDEV_WATCH_EVENT_DEL:
	case NETDEV_WATCH_EVENT_DOWN:
		l_dbus_object_remove_interface(dbus_get_bus(),
						netdev_get_path(netdev),
						IWD_DPP_INTERFACE);
		break;
	default:
		break;
	}
}

static void dpp_presence_timeout(int error, void *user_data)
{
	struct dpp_sm *dpp = user_data;

	if (dpp->state != DPP_STATE_PRESENCE) {
		l_debug("DPP state changed, stopping presence announcements");
		dpp->freqs_idx = 0;
		return;
	}

	dpp->freqs_idx++;

	if (dpp->freqs_idx >= dpp->freqs_len) {
		l_debug("Max retries on presence announcements");
		dpp->freqs_idx = 0;
	}

	dpp->current_freq = dpp->freqs[dpp->freqs_idx];

	l_debug("Presence timeout, moving to next frequency %u, duration %u",
			dpp->current_freq, dpp->dwell);

	dpp->offchannel_id = offchannel_start(netdev_get_wdev_id(dpp->netdev),
			dpp->current_freq, dpp->dwell, dpp_roc_started,
			dpp, dpp_presence_timeout);
}

/*
 * EasyConnect 2.0 - 6.2.2
 */
static uint32_t *dpp_add_default_channels(struct dpp_sm *dpp, size_t *len_out)
{
	struct wiphy *wiphy = wiphy_find_by_wdev(
					netdev_get_wdev_id(dpp->netdev));
	const struct scan_freq_set *list = wiphy_get_supported_freqs(wiphy);
	uint32_t freq;

	if (!dpp->presence_list)
		dpp->presence_list = scan_freq_set_new();

	scan_freq_set_add(dpp->presence_list, band_channel_to_freq(6,
						BAND_FREQ_2_4_GHZ));
	/*
	 * "5 GHz: Channel 44 (5.220 GHz) if local regulations permit operation
	 * only in the 5.150 - 5.250 GHz band and Channel 149 (5.745 GHz)
	 * otherwise"
	 */
	freq = band_channel_to_freq(149, BAND_FREQ_5_GHZ);

	if (scan_freq_set_contains(list, freq))
		scan_freq_set_add(dpp->presence_list, freq);
	else
		scan_freq_set_add(dpp->presence_list,
				band_channel_to_freq(44, BAND_FREQ_5_GHZ));

	/* TODO: 60GHz: Channel 2 */

	return scan_freq_set_to_fixed_array(dpp->presence_list, len_out);
}

/*
 * TODO: There is an entire procedure defined in the spec where you increase
 * the ROC timeout with each unsuccessful iteration of channels, wait on channel
 * for long periods of time etc. Due to offchannel issues in the kernel this
 * procedure is not being fully implemented. In reality doing this would result
 * in quite terrible DPP performance anyways.
 */
static void dpp_start_presence(struct dpp_sm *dpp, uint32_t *limit_freqs,
					size_t limit_len)
{
	uint32_t max_roc = wiphy_get_max_roc_duration(
					wiphy_find_by_wdev(dpp->wdev_id));

	if (2000 < max_roc)
		max_roc = 2000;

	if (limit_freqs) {
		dpp->freqs = l_memdup(limit_freqs, sizeof(uint32_t) * limit_len);
		dpp->freqs_len = limit_len;
	} else
		dpp->freqs = dpp_add_default_channels(dpp, &dpp->freqs_len);

	dpp->dwell = max_roc;
	dpp->freqs_idx = 0;
	dpp->current_freq = dpp->freqs[0];

	dpp->offchannel_id = offchannel_start(netdev_get_wdev_id(dpp->netdev),
			dpp->current_freq, dpp->dwell, dpp_roc_started,
			dpp, dpp_presence_timeout);
}

static struct l_dbus_message *dpp_dbus_start_enrollee(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct dpp_sm *dpp = user_data;
	uint32_t freq = band_channel_to_freq(6, BAND_FREQ_2_4_GHZ);
	struct l_dbus_message *reply;

	if (dpp->state != DPP_STATE_NOTHING)
		return dbus_error_busy(message);

	dpp->uri = dpp_generate_uri(dpp->pub_asn1, dpp->pub_asn1_len, 2,
					netdev_get_address(dpp->netdev), &freq,
					1, NULL, NULL);

	dpp->state = DPP_STATE_PRESENCE;

	l_debug("DPP Start Enrollee: %s", dpp->uri);

	/*
	 * Going off spec here. Select a single channel to send presence
	 * announcements on. This will be advertised in the URI. The full
	 * presence procedure can be implemented if it is ever needed.
	 */
	dpp_start_presence(dpp, &freq, 1);

	reply = l_dbus_message_new_method_return(message);

	l_dbus_message_set_arguments(reply, "s", dpp->uri);

	return reply;
}

static struct l_dbus_message *dpp_dbus_stop(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct dpp_sm *dpp = user_data;

	dpp_reset(dpp);

	return l_dbus_message_new_method_return(message);
}

static void dpp_setup_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "StartEnrollee", 0,
				dpp_dbus_start_enrollee, "s", "", "uri");
	l_dbus_interface_method(interface, "Stop", 0,
				dpp_dbus_stop, "", "");
}

static void dpp_destroy_interface(void *user_data)
{
	struct dpp_sm *dpp = user_data;

	dpp_free(dpp);
}

static int dpp_init(void)
{
	nl80211 = l_genl_family_new(iwd_get_genl(), NL80211_GENL_NAME);
	if (!nl80211) {
		l_error("Failed to obtain nl80211");
		return -EIO;
	}

	netdev_watch = netdev_watch_add(dpp_netdev_watch, NULL, NULL);

	l_dbus_register_interface(dbus_get_bus(), IWD_DPP_INTERFACE,
					dpp_setup_interface,
					dpp_destroy_interface, false);
	return 0;
}

static void dpp_exit(void)
{
	l_debug("");

	netdev_watch_remove(netdev_watch);
}

IWD_MODULE(dpp, dpp_init, dpp_exit);
IWD_MODULE_DEPENDS(dpp, netdev);
