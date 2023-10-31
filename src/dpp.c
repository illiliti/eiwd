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

#include "src/missing.h"
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
#include "src/crypto.h"
#include "src/mpdu.h"
#include "ell/useful.h"
#include "src/common.h"
#include "src/json.h"
#include "src/storage.h"
#include "src/station.h"
#include "src/scan.h"
#include "src/network.h"
#include "src/handshake.h"
#include "src/nl80211util.h"

#define DPP_FRAME_MAX_RETRIES 5
#define DPP_FRAME_RETRY_TIMEOUT 1
#define DPP_AUTH_PROTO_TIMEOUT 10

static uint32_t netdev_watch;
static struct l_genl_family *nl80211;
static uint8_t broadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static struct l_queue *dpp_list;
static uint32_t mlme_watch;
static uint32_t unicast_watch;

static uint8_t dpp_prefix[] = { 0x04, 0x09, 0x50, 0x6f, 0x9a, 0x1a, 0x01 };

enum dpp_state {
	DPP_STATE_NOTHING,
	DPP_STATE_PRESENCE,
	DPP_STATE_AUTHENTICATING,
	DPP_STATE_CONFIGURING,
};

enum dpp_capability {
	DPP_CAPABILITY_ENROLLEE = 0x01,
	DPP_CAPABILITY_CONFIGURATOR = 0x02,
};

struct dpp_sm {
	struct netdev *netdev;
	char *uri;
	uint8_t role;

	uint64_t wdev_id;

	uint8_t *own_asn1;
	size_t own_asn1_len;
	uint8_t *peer_asn1;
	size_t peer_asn1_len;
	uint8_t own_boot_hash[32];
	uint8_t peer_boot_hash[32];
	const struct l_ecc_curve *curve;
	size_t key_len;
	size_t nonce_len;
	struct l_ecc_scalar *boot_private;
	struct l_ecc_point *boot_public;
	struct l_ecc_point *peer_boot_public;

	enum dpp_state state;

	/*
	 * List of frequencies to jump between. The presence of this list is
	 * also used to signify that a configurator is an initiator vs responder
	 */
	uint32_t *freqs;
	size_t freqs_len;
	size_t freqs_idx;
	uint32_t dwell;
	uint32_t current_freq;
	uint32_t new_freq;
	struct scan_freq_set *presence_list;
	uint32_t max_roc;

	uint32_t offchannel_id;

	uint8_t peer_addr[6];
	uint8_t r_nonce[32];
	uint8_t i_nonce[32];
	uint8_t e_nonce[32];

	struct l_ecc_scalar *m;
	uint64_t ke[L_ECC_MAX_DIGITS];
	uint64_t k1[L_ECC_MAX_DIGITS];
	uint64_t k2[L_ECC_MAX_DIGITS];
	uint64_t auth_tag[L_ECC_MAX_DIGITS];

	struct l_ecc_scalar *proto_private;
	struct l_ecc_point *own_proto_public;

	struct l_ecc_point *peer_proto_public;

	uint8_t diag_token;

	/* Timeout of either auth/config protocol */
	struct l_timeout *timeout;

	struct dpp_configuration *config;
	uint32_t connect_scan_id;
	uint64_t frame_cookie;
	uint8_t frame_retry;
	void *frame_pending;
	size_t frame_size;
	struct l_timeout *retry_timeout;

	struct l_dbus_message *pending;

	bool mcast_support : 1;
	bool roc_started : 1;
	bool channel_switch : 1;
	bool mutual_auth : 1;
};

static bool dpp_get_started(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct dpp_sm *dpp = user_data;
	bool started = (dpp->state != DPP_STATE_NOTHING);

	l_dbus_message_builder_append_basic(builder, 'b', &started);

	return true;
}

static bool dpp_get_role(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct dpp_sm *dpp = user_data;
	const char *role;

	if (dpp->state == DPP_STATE_NOTHING)
		return false;

	switch (dpp->role) {
	case DPP_CAPABILITY_ENROLLEE:
		role = "enrollee";
		break;
	case DPP_CAPABILITY_CONFIGURATOR:
		role = "configurator";
		break;
	default:
		return false;
	}

	l_dbus_message_builder_append_basic(builder, 's', role);
	return true;
}

static bool dpp_get_uri(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct dpp_sm *dpp = user_data;

	if (dpp->state == DPP_STATE_NOTHING)
		return false;

	l_dbus_message_builder_append_basic(builder, 's', dpp->uri);
	return true;
}

static void dpp_property_changed_notify(struct dpp_sm *dpp)
{
	const char *path = netdev_get_path(dpp->netdev);

	l_dbus_property_changed(dbus_get_bus(), path, IWD_DPP_INTERFACE,
				"Started");
	l_dbus_property_changed(dbus_get_bus(), path, IWD_DPP_INTERFACE,
				"Role");
	l_dbus_property_changed(dbus_get_bus(), path, IWD_DPP_INTERFACE,
				"URI");
}

static void *dpp_serialize_iovec(struct iovec *iov, size_t iov_len,
				size_t *out_len)
{
	unsigned int i;
	size_t size = 0;
	uint8_t *ret;

	for (i = 0; i < iov_len; i++)
		size += iov[i].iov_len;

	ret = l_malloc(size);
	size = 0;

	for (i = 0; i < iov_len; i++) {
		memcpy(ret + size, iov[i].iov_base, iov[i].iov_len);
		size += iov[i].iov_len;
	}

	if (out_len)
		*out_len = size;

	return ret;
}

static void dpp_free_auth_data(struct dpp_sm *dpp)
{
	if (dpp->own_proto_public) {
		l_ecc_point_free(dpp->own_proto_public);
		dpp->own_proto_public = NULL;
	}

	if (dpp->proto_private) {
		l_ecc_scalar_free(dpp->proto_private);
		dpp->proto_private = NULL;
	}

	if (dpp->peer_proto_public) {
		l_ecc_point_free(dpp->peer_proto_public);
		dpp->peer_proto_public = NULL;
	}

	if (dpp->peer_boot_public) {
		l_ecc_point_free(dpp->peer_boot_public);
		dpp->peer_boot_public = NULL;
	}

	if (dpp->m) {
		l_ecc_scalar_free(dpp->m);
		dpp->m = NULL;
	}
}

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

	if (dpp->timeout) {
		l_timeout_remove(dpp->timeout);
		dpp->timeout = NULL;
	}

	if (dpp->config) {
		dpp_configuration_free(dpp->config);
		dpp->config = NULL;
	}

	if (dpp->connect_scan_id) {
		scan_cancel(dpp->wdev_id, dpp->connect_scan_id);
		dpp->connect_scan_id = 0;
	}

	if (dpp->peer_asn1) {
		l_free(dpp->peer_asn1);
		dpp->peer_asn1 = NULL;
	}

	if (dpp->frame_pending) {
		l_free(dpp->frame_pending);
		dpp->frame_pending = NULL;
	}

	if (dpp->retry_timeout) {
		l_timeout_remove(dpp->retry_timeout);
		dpp->retry_timeout = NULL;
	}

	dpp->state = DPP_STATE_NOTHING;
	dpp->new_freq = 0;
	dpp->frame_retry = 0;
	dpp->frame_cookie = 0;

	explicit_bzero(dpp->r_nonce, dpp->nonce_len);
	explicit_bzero(dpp->i_nonce, dpp->nonce_len);
	explicit_bzero(dpp->e_nonce, dpp->nonce_len);
	explicit_bzero(dpp->ke, dpp->key_len);
	explicit_bzero(dpp->k1, dpp->key_len);
	explicit_bzero(dpp->k2, dpp->key_len);
	explicit_bzero(dpp->auth_tag, dpp->key_len);

	dpp_free_auth_data(dpp);

	dpp_property_changed_notify(dpp);
}

static void dpp_free(struct dpp_sm *dpp)
{
	dpp_reset(dpp);

	if (dpp->own_asn1) {
		l_free(dpp->own_asn1);
		dpp->own_asn1 = NULL;
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
	struct dpp_sm *dpp = user_data;
	int err = l_genl_msg_get_error(msg);

	if (err < 0) {
		l_error("Error sending frame (%d)", err);
		return;
	}

	if (nl80211_parse_attrs(msg, NL80211_ATTR_COOKIE, &dpp->frame_cookie,
				NL80211_ATTR_UNSPEC) < 0)
		l_error("Error parsing frame cookie");
}

static void dpp_send_frame(struct dpp_sm *dpp,
				struct iovec *iov, size_t iov_len,
				uint32_t freq)
{
	struct l_genl_msg *msg;

	/*
	 * A received frame could potentially come in after the ROC session has
	 * ended. In this case the frame needs to be stored until ROC is started
	 * and sent at that time. The offchannel_id is also checked since
	 * this is not applicable when DPP is in a responder role waiting
	 * on the currently connected channel i.e. offchannel is never used.
	 */
	if (!dpp->roc_started && dpp->offchannel_id) {
		dpp->frame_pending = dpp_serialize_iovec(iov, iov_len,
							&dpp->frame_size);
		return;
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &dpp->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &freq);
	l_genl_msg_append_attr(msg, NL80211_ATTR_OFFCHANNEL_TX_OK, 0, NULL);
	l_genl_msg_append_attrv(msg, NL80211_ATTR_FRAME, iov, iov_len);

	l_debug("Sending frame on frequency %u", freq);

	if (!l_genl_family_send(nl80211, msg, dpp_send_frame_cb, dpp, NULL)) {
		l_error("Could not send CMD_FRAME");
		l_genl_msg_unref(msg);
	}
}

static void dpp_frame_retry(struct dpp_sm *dpp)
{
	struct iovec iov;

	iov.iov_base = dpp->frame_pending;
	iov.iov_len = dpp->frame_size;

	dpp_send_frame(dpp, &iov, 1, dpp->current_freq);

	l_free(dpp->frame_pending);
	dpp->frame_pending = NULL;
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

static size_t dpp_build_config_header(const uint8_t *src, const uint8_t *dest,
					uint8_t diag_token,
					uint8_t buf[static 37])
{
	uint8_t *ptr = buf + 24;

	memset(buf, 0, 37);

	l_put_le16(0x00d0, buf);
	memcpy(buf + 4, dest, 6);
	memcpy(buf + 10, src, 6);
	memcpy(buf + 16, broadcast, 6);

	*ptr++ = 0x04; /* Public */
	*ptr++ = 0x0a; /* Action */
	*ptr++ = diag_token;

	*ptr++ = IE_TYPE_ADVERTISEMENT_PROTOCOL;
	*ptr++ = 8; /* len */
	*ptr++ = 0x00;
	*ptr++ = IE_TYPE_VENDOR_SPECIFIC;
	*ptr++ = 5;
	memcpy(ptr, wifi_alliance_oui, 3);
	ptr += 3;
	*ptr++ = 0x1a;
	*ptr++ = 1;

	return ptr - buf;
}

static void dpp_protocol_timeout(struct l_timeout *timeout, void *user_data)
{
	struct dpp_sm *dpp = user_data;

	l_debug("DPP timed out");

	dpp_reset(dpp);
}

static void dpp_reset_protocol_timer(struct dpp_sm *dpp, uint32_t time)
{
	if (dpp->timeout)
		l_timeout_modify(dpp->timeout, time);
	else
		dpp->timeout = l_timeout_create(time, dpp_protocol_timeout,
						dpp, NULL);
}

/*
 * The configuration protocols use of AD components is somewhat confusing
 * since the request/response frames are of a different format than the rest.
 * In addition there are situations where the components length is zero yet it
 * is still passed as such to AES-SIV.
 *
 * For the configuration request/response frames:
 *
 * "AAD for use with AES-SIV for protected messages in the DPP Configuration
 * protocol shall consist of all octets in the Query Request and Query Response
 * fields up to the first octet of the Wrapped Data attribute, which is the last
 * attribute in a DPP Configuration frame. When the number of octets of AAD is
 * zero, the number of components of AAD passed to AES-SIV is zero."
 *
 *  - For configuration requests the optional query request field is not
 *    included, therefore no AAD data is passed. (dpp_configuration_start)
 *
 *  - The configuration response does contain a query response field which is
 *    5 bytes. (dpp_handle_config_response_frame)
 *
 * For the configuration result/status, the same rules are used as the
 * authentication protocol. This is reiterated in section 6.4.1.
 *
 *  - For the configuration result there is some confusion as to exactly how the
 *    second AAD component should be passed (since the spec specifically
 *    mentions using two components). There are no attributes prior to the
 *    wrapped data component meaning the length would be zero.
 *    Hostapd/wpa_supplicant pass a zero length AAD component to AES-SIV which
 *    does effect the resulting encryption/decryption so this is also what IWD
 *    will do to remain compliant with it.
 */
static void dpp_configuration_start(struct dpp_sm *dpp, const uint8_t *addr)
{
	const char *json = "{\"name\":\"IWD\",\"wi-fi_tech\":\"infra\","
				"\"netRole\":\"sta\"}";
	struct iovec iov[3];
	uint8_t hdr[37];
	uint8_t attrs[512];
	size_t json_len = strlen(json);
	uint8_t *ptr = attrs;

	l_getrandom(&dpp->diag_token, 1);

	iov[0].iov_len = dpp_build_config_header(
					netdev_get_address(dpp->netdev),
					addr, dpp->diag_token, hdr);
	iov[0].iov_base = hdr;

	l_getrandom(dpp->e_nonce, dpp->nonce_len);

	/* length */
	ptr += 2;

	/*
	 * "AAD for use with AES-SIV for protected messages in the DPP
	 * Configuration protocol shall consist of all octets in the Query
	 * Request and Query Response fields up to the first octet of the
	 * Wrapped Data attribute"
	 *
	 * In this case there is no query request/response fields, nor any
	 * attributes besides wrapped data meaning zero AD components.
	 */
	ptr += dpp_append_wrapped_data(NULL, 0, NULL, 0, ptr, sizeof(attrs),
			dpp->ke, dpp->key_len, 2,
			DPP_ATTR_ENROLLEE_NONCE, dpp->nonce_len, dpp->e_nonce,
			DPP_ATTR_CONFIGURATION_REQUEST, json_len, json);

	l_put_le16(ptr - attrs - 2, attrs);

	iov[1].iov_base = attrs;
	iov[1].iov_len = ptr - attrs;

	dpp->state = DPP_STATE_CONFIGURING;

	dpp_send_frame(dpp, iov, 2, dpp->current_freq);
}

static void send_config_result(struct dpp_sm *dpp, const uint8_t *to)
{
	uint8_t hdr[32];
	struct iovec iov[2];
	uint8_t attrs[256];
	uint8_t *ptr = attrs;
	uint8_t zero = 0;

	iov[0].iov_len = dpp_build_header(netdev_get_address(dpp->netdev), to,
					DPP_FRAME_CONFIGURATION_RESULT, hdr);
	iov[0].iov_base = hdr;

	ptr += dpp_append_wrapped_data(hdr + 26, 6, attrs, 0, ptr,
			sizeof(attrs), dpp->ke, dpp->key_len, 2,
			DPP_ATTR_STATUS, (size_t) 1, &zero,
			DPP_ATTR_ENROLLEE_NONCE, dpp->nonce_len, dpp->e_nonce);

	iov[1].iov_base = attrs;
	iov[1].iov_len = ptr - attrs;

	dpp_send_frame(dpp, iov, 2, dpp->current_freq);
}

static void dpp_write_config(struct dpp_configuration *config,
				struct network *network)
{
	char ssid[33];
	_auto_(l_settings_free) struct l_settings *settings = l_settings_new();
	_auto_(l_free) char *path;
	_auto_(l_free) uint8_t *psk = NULL;
	size_t psk_len;

	memcpy(ssid, config->ssid, config->ssid_len);
	ssid[config->ssid_len] = '\0';

	path = storage_get_network_file_path(SECURITY_PSK, ssid);

	if (l_settings_load_from_file(settings, path)) {
		/* Remove any existing Security keys */
		l_settings_remove_group(settings, "Security");
	}

	if (config->passphrase) {
		l_settings_set_string(settings, "Security", "Passphrase",
				config->passphrase);
		if (network)
			network_set_passphrase(network, config->passphrase);

	} else if (config->psk) {
		l_settings_set_string(settings, "Security", "PreSharedKey",
				config->psk);

		psk = l_util_from_hexstring(config->psk, &psk_len);

		if (network)
			network_set_psk(network, psk);
	}

	l_debug("Storing credential for '%s(%s)'", ssid,
						security_to_str(SECURITY_PSK));
	storage_network_sync(SECURITY_PSK, ssid, settings);
}

static void dpp_scan_triggered(int err, void *user_data)
{
	/* Not much can be done in this case */
	if (err < 0)
		l_error("Failed to trigger DPP scan");
}

static bool dpp_scan_results(int err, struct l_queue *bss_list,
				const struct scan_freq_set *freqs,
				void *userdata)
{
	struct dpp_sm *dpp = userdata;
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));

	if (err < 0)
		return false;

	station_set_scan_results(station, bss_list, freqs, true);

	return true;
}

static void dpp_scan_destroy(void *userdata)
{
	struct dpp_sm *dpp = userdata;

	dpp->connect_scan_id = 0;
	dpp_reset(dpp);
}

static void dpp_handle_config_response_frame(const struct mmpdu_header *frame,
				const void *body, size_t body_len,
				int rssi, void *user_data)
{
	struct dpp_sm *dpp = user_data;
	const uint8_t *ptr = body;
	uint16_t status;
	uint16_t fragmented; /* Fragmented/Comeback delay field */
	uint8_t adv_protocol_element[] = { 0x6C, 0x08, 0x7F };
	uint8_t adv_protocol_id[] = { 0xDD, 0x05, 0x50, 0x6F,
					0x9A, 0x1A, 0x01 };
	uint16_t query_len;
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	const char *json = NULL;
	size_t json_len = 0;
	int dstatus = -1;
	const uint8_t *wrapped = NULL;
	const uint8_t *e_nonce = NULL;
	size_t wrapped_len = 0;
	_auto_(l_free) uint8_t *unwrapped = NULL;
	struct dpp_configuration *config;
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));
	struct network *network = NULL;
	struct scan_bss *bss = NULL;
	char ssid[33];

	if (dpp->state != DPP_STATE_CONFIGURING)
		return;

	/*
	 * Can a configuration request come from someone other than who you
	 * authenticated to?
	 */
	if (memcmp(dpp->peer_addr, frame->address_2, 6))
		return;

	if (body_len < 19)
		return;

	ptr += 2;

	if (*ptr++ != dpp->diag_token)
		return;

	status = l_get_le16(ptr);
	ptr += 2;

	if (status != 0) {
		l_debug("Bad configuration status %u", status);
		return;
	}

	fragmented = l_get_le16(ptr);
	ptr += 2;

	/*
	 * TODO: handle 0x0001 (fragmented), as well as comeback delay.
	 */
	if (fragmented != 0) {
		l_debug("Fragmented messages not currently supported");
		return;
	}

	if (memcmp(ptr, adv_protocol_element, sizeof(adv_protocol_element))) {
		l_debug("Invalid Advertisement protocol element");
		return;
	}

	ptr += sizeof(adv_protocol_element);

	if (memcmp(ptr, adv_protocol_id, sizeof(adv_protocol_id))) {
		l_debug("Invalid Advertisement protocol ID");
		return;
	}

	ptr += sizeof(adv_protocol_id);

	query_len = l_get_le16(ptr);
	ptr += 2;

	if (query_len > body_len - 19)
		return;

	dpp_attr_iter_init(&iter, ptr, query_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_STATUS:
			dstatus = l_get_u8(data);
			break;
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			/*
			 * TODO: CSR Attribute
			 */
			break;
		}
	}

	if (dstatus != DPP_STATUS_OK || !wrapped) {
		l_debug("Bad status or missing attributes");
		return;
	}

	unwrapped = dpp_unwrap_attr(ptr, wrapped - ptr - 4, NULL, 0, dpp->ke,
					dpp->key_len, wrapped, wrapped_len,
					&wrapped_len);
	if (!unwrapped) {
		l_debug("Failed to unwrap");
		return;
	}

	dpp_attr_iter_init(&iter, unwrapped, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_ENROLLEE_NONCE:
			if (len != dpp->nonce_len)
				break;

			if (memcmp(data, dpp->e_nonce, dpp->nonce_len))
				break;

			e_nonce = data;
			break;
		case DPP_ATTR_CONFIGURATION_OBJECT:
			json = (const char *)data;
			json_len = len;
			break;
		default:
			break;
		}
	}

	if (!json || !e_nonce) {
		l_debug("No configuration object in response");
		return;
	}

	config = dpp_parse_configuration_object(json, json_len);
	if (!config) {
		l_error("Configuration object did not parse");
		return;
	}

	/*
	 * We should have a station device, but if not DPP can write the
	 * credentials out and be done
	 */
	if (station) {
		memcpy(ssid, config->ssid, config->ssid_len);
		ssid[config->ssid_len] = '\0';

		network = station_network_find(station, ssid, SECURITY_PSK);
		if (network)
			bss = network_bss_select(network, true);
	}

	dpp_write_config(config, network);
	dpp_configuration_free(config);

	send_config_result(dpp, dpp->peer_addr);

	offchannel_cancel(dpp->wdev_id, dpp->offchannel_id);

	if (network && bss)
		__station_connect_network(station, network, bss);
	else if (station) {
		dpp->connect_scan_id = scan_active(dpp->wdev_id, NULL, 0,
						dpp_scan_triggered,
						dpp_scan_results, dpp,
						dpp_scan_destroy);
		if (dpp->connect_scan_id)
			return;
	}

	dpp_reset(dpp);
}

static void dpp_send_config_response(struct dpp_sm *dpp, uint8_t status)
{
	_auto_(l_free) char *json = NULL;
	struct iovec iov[3];
	uint8_t hdr[41];
	uint8_t attrs[512];
	size_t json_len;
	uint8_t *ptr = hdr + 24;

	memset(hdr, 0, sizeof(hdr));

	l_put_le16(0x00d0, hdr);
	memcpy(hdr + 4, dpp->peer_addr, 6);
	memcpy(hdr + 10, netdev_get_address(dpp->netdev), 6);
	memcpy(hdr + 16, broadcast, 6);

	*ptr++ = 0x04;
	*ptr++ = 0x0b;
	*ptr++ = dpp->diag_token;
	l_put_le16(0, ptr); /* status */
	ptr += 2;
	l_put_le16(0, ptr); /* fragmented (no) */
	ptr += 2;
	*ptr++ = IE_TYPE_ADVERTISEMENT_PROTOCOL;
	*ptr++ = 0x08;
	*ptr++ = 0x7f;
	*ptr++ = IE_TYPE_VENDOR_SPECIFIC;
	*ptr++ = 5;
	memcpy(ptr, wifi_alliance_oui, sizeof(wifi_alliance_oui));
	ptr += sizeof(wifi_alliance_oui);
	*ptr++ = 0x1a;
	*ptr++ = 1;

	iov[0].iov_base = hdr;
	iov[0].iov_len = ptr - hdr;

	ptr = attrs;

	ptr += 2; /* length */

	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &status, 1);

	/*
	 * There are several failure status codes that can be used (defined in
	 * 6.4.3.1), each with their own set of attributes that should be
	 * included. For now IWD's basic DPP implementation will assume
	 * STATUS_CONFIGURE_FAILURE which only includes the E-Nonce.
	 */
	if (status == DPP_STATUS_OK) {
		json = dpp_configuration_to_json(dpp->config);
		json_len = strlen(json);

		ptr += dpp_append_wrapped_data(attrs + 2, ptr - attrs - 2,
						NULL, 0, ptr, sizeof(attrs),
						dpp->ke, dpp->key_len, 2,
						DPP_ATTR_ENROLLEE_NONCE,
						dpp->nonce_len, dpp->e_nonce,
						DPP_ATTR_CONFIGURATION_OBJECT,
						json_len, json);
	} else
		ptr += dpp_append_wrapped_data(attrs + 2, ptr - attrs - 2,
						NULL, 0, ptr, sizeof(attrs),
						dpp->ke, dpp->key_len, 2,
						DPP_ATTR_ENROLLEE_NONCE,
						dpp->nonce_len, dpp->e_nonce);

	l_put_le16(ptr - attrs - 2, attrs);

	iov[1].iov_base = attrs;
	iov[1].iov_len = ptr - attrs;

	dpp_send_frame(dpp, iov, 2, dpp->current_freq);
}

static void dpp_handle_config_request_frame(const struct mmpdu_header *frame,
				const void *body, size_t body_len,
				int rssi, void *user_data)
{
	struct dpp_sm *dpp = user_data;
	const uint8_t *ptr = body;
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	const char *json = NULL;
	size_t json_len = 0;
	struct json_contents *c;
	const uint8_t *wrapped = NULL;
	const uint8_t *e_nonce = NULL;
	size_t wrapped_len = 0;
	_auto_(l_free) uint8_t *unwrapped = NULL;
	uint8_t hdr_check[] = { IE_TYPE_ADVERTISEMENT_PROTOCOL, 0x08, 0x7f,
				IE_TYPE_VENDOR_SPECIFIC, 5 };
	struct json_iter jsiter;
	_auto_(l_free) char *tech = NULL;
	_auto_(l_free) char *role = NULL;

	if (dpp->state != DPP_STATE_AUTHENTICATING) {
		l_debug("Configuration request in wrong state");
		return;
	}

	if (dpp->role != DPP_CAPABILITY_CONFIGURATOR)
		return;

	if (memcmp(dpp->peer_addr, frame->address_2, 6)) {
		l_debug("Configuration request not from authenticated peer");
		return;
	}

	if (body_len < 15) {
		l_debug("Configuration request data not long enough");
		return;
	}

	ptr += 2;

	dpp->diag_token = *ptr++;

	if (memcmp(ptr, hdr_check, sizeof(hdr_check)))
		return;

	ptr += sizeof(hdr_check);

	if (memcmp(ptr, wifi_alliance_oui, sizeof(wifi_alliance_oui)))
		return;

	ptr += sizeof(wifi_alliance_oui);

	if (*ptr != 0x1a && *(ptr + 1) != 1)
		return;

	ptr += 2;

	len = l_get_le16(ptr);
	ptr += 2;

	if (len > body_len - 15)
		return;

	dpp_attr_iter_init(&iter, ptr, len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			/* Wrapped data should be only attribute */
			return;
		}
	}

	if (!wrapped) {
		l_debug("Wrapped data missing");
		return;
	}

	unwrapped = dpp_unwrap_attr(NULL, 0, NULL, 0, dpp->ke,
					dpp->key_len, wrapped, wrapped_len,
					&wrapped_len);
	if (!unwrapped) {
		l_debug("Failed to unwrap");
		return;
	}

	dpp_attr_iter_init(&iter, unwrapped, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_ENROLLEE_NONCE:
			if (len != dpp->nonce_len)
				break;

			e_nonce = data;
			break;
		case DPP_ATTR_CONFIGURATION_REQUEST:
			json = (const char *)data;
			json_len = len;
			break;
		default:
			break;
		}
	}

	if (!json || !e_nonce) {
		l_debug("No configuration object in response");
		return;
	}

	c = json_contents_new(json, json_len);
	if (!c) {
		json_contents_free(c);
		return;
	}

	json_iter_init(&jsiter, c);

	/*
	 * Check mandatory values (Table 7). There isn't much that can be done
	 * with these, but the spec requires they be included.
	 */
	if (!json_iter_parse(&jsiter,
			JSON_MANDATORY("name", JSON_STRING, NULL),
			JSON_MANDATORY("wi-fi_tech", JSON_STRING, &tech),
			JSON_MANDATORY("netRole", JSON_STRING, &role),
			JSON_UNDEFINED))
		goto configure_failure;

	if (strcmp(tech, "infra"))
		goto configure_failure;

	if (strcmp(role, "sta"))
		goto configure_failure;

	json_contents_free(c);

	memcpy(dpp->e_nonce, e_nonce, dpp->nonce_len);

	dpp->state = DPP_STATE_CONFIGURING;

	dpp_send_config_response(dpp, DPP_STATUS_OK);

	return;

configure_failure:
	dpp_send_config_response(dpp, DPP_STATUS_CONFIGURE_FAILURE);
	/*
	 * The other peer is still authenticated, and can potentially send
	 * additional requests so keep this session alive.
	 */
}

static void dpp_handle_config_result_frame(struct dpp_sm *dpp,
					const uint8_t *from, const void *body,
					size_t body_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	int status = -1;
	const void *e_nonce = NULL;
	const void *wrapped = NULL;
	size_t wrapped_len;
	_auto_(l_free) void *unwrapped = NULL;

	if (dpp->state != DPP_STATE_CONFIGURING)
		return;

	dpp_attr_iter_init(&iter, body + 8, body_len - 8);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			/* Wrapped data should be only attribute */
			return;
		}
	}

	if (!wrapped)
		return;

	unwrapped = dpp_unwrap_attr(body + 2, wrapped - body - 6, wrapped, 0,
					dpp->ke, dpp->key_len, wrapped,
					wrapped_len, &wrapped_len);
	if (!unwrapped) {
		l_debug("Failed to unwrap DPP configuration result");
		return;
	}

	dpp_attr_iter_init(&iter, unwrapped, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_STATUS:
			status = l_get_u8(data);
			break;
		case DPP_ATTR_ENROLLEE_NONCE:
			e_nonce = data;
			break;
		default:
			break;
		}
	}

	if (status != DPP_STATUS_OK || !e_nonce)
		l_debug("Enrollee signaled a failed configuration");
	else
		l_debug("Configuration success");

	dpp_reset(dpp);
}

/*
 * The Authentication protocol has a consistent use of AD components, and this
 * use is defined in 6.3.1.4:
 *
 * "Invocations of AES-SIV in the DPP Authentication protocol that produce
 * ciphertext that is part of an additional AES-SIV invocation do not use AAD;
 * in other words, the number of AAD components is set to zero. All other
 * invocations of AES-SIV in the DPP Authentication protocol shall pass a vector
 * of AAD having two components of AAD in the following order: (1) the DPP
 * header, as defined in Table 30, from the OUI field (inclusive) to the DPP
 * Frame Type field (inclusive); and (2) all octets in a DPP Public Action frame
 * after the DPP Frame Type field up to and including the last octet of the last
 * attribute before the Wrapped Data attribute"
 *
 * In practice you see this as AD0 being some offset in the frame (offset to the
 * OUI). For outgoing packets this is 26 bytes offset since the header is built
 * manually. For incoming packets the offset is 2 bytes. The length is always
 * 6 bytes for AD0.
 *
 * The AD1 data is always the start of the attributes, and length is the number
 * of bytes from these attributes to wrapped data. e.g.
 *
 * ad1 = attrs
 * ad1_len = ptr - attrs
 */
static void send_authenticate_response(struct dpp_sm *dpp)
{
	uint8_t hdr[32];
	uint8_t attrs[512];
	uint8_t *ptr = attrs;
	uint8_t status = DPP_STATUS_OK;
	uint64_t r_proto_key[L_ECC_MAX_DIGITS * 2];
	uint8_t version = 2;
	struct iovec iov[3];
	uint8_t wrapped2_plaintext[dpp->key_len + 4];
	uint8_t wrapped2[dpp->key_len + 16 + 8];
	size_t wrapped2_len;

	l_ecc_point_get_data(dpp->own_proto_public, r_proto_key,
				sizeof(r_proto_key));

	iov[0].iov_len = dpp_build_header(netdev_get_address(dpp->netdev),
				dpp->peer_addr,
				DPP_FRAME_AUTHENTICATION_RESPONSE, hdr);
	iov[0].iov_base = hdr;

	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &status, 1);
	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH,
				dpp->own_boot_hash, 32);
	if (dpp->mutual_auth)
		ptr += dpp_append_attr(ptr, DPP_ATTR_INITIATOR_BOOT_KEY_HASH,
				dpp->peer_boot_hash, 32);
	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_PROTOCOL_KEY,
				r_proto_key, dpp->key_len * 2);
	ptr += dpp_append_attr(ptr, DPP_ATTR_PROTOCOL_VERSION, &version, 1);

	/* Wrap up secondary data (R-Auth) */
	wrapped2_len = dpp_append_attr(wrapped2_plaintext,
					DPP_ATTR_RESPONDER_AUTH_TAG,
					dpp->auth_tag, dpp->key_len);
	/*
	 * "Invocations of AES-SIV in the DPP Authentication protocol that
	 * produce ciphertext that is part of an additional AES-SIV invocation
	 * do not use AAD; in other words, the number of AAD components is set
	 * to zero.""
	 */
	if (!aes_siv_encrypt(dpp->ke, dpp->key_len, wrapped2_plaintext,
					dpp->key_len + 4, NULL, 0, wrapped2)) {
		l_error("Failed to encrypt wrapped data");
		return;
	}

	wrapped2_len += 16;

	ptr += dpp_append_wrapped_data(hdr + 26, 6, attrs, ptr - attrs,
			ptr, sizeof(attrs), dpp->k2, dpp->key_len, 4,
			DPP_ATTR_RESPONDER_NONCE, dpp->nonce_len, dpp->r_nonce,
			DPP_ATTR_INITIATOR_NONCE, dpp->nonce_len, dpp->i_nonce,
			DPP_ATTR_RESPONDER_CAPABILITIES, (size_t) 1, &dpp->role,
			DPP_ATTR_WRAPPED_DATA, wrapped2_len, wrapped2);

	iov[1].iov_base = attrs;
	iov[1].iov_len = ptr - attrs;

	dpp_send_frame(dpp, iov, 2, dpp->current_freq);
}

static void authenticate_confirm(struct dpp_sm *dpp, const uint8_t *from,
					const uint8_t *body, size_t body_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	int status = -1;
	const uint8_t *r_boot_hash = NULL;
	const void *wrapped = NULL;
	const uint8_t *i_auth = NULL;
	size_t i_auth_len;
	_auto_(l_free) uint8_t *unwrapped = NULL;
	size_t wrapped_len = 0;
	uint64_t i_auth_check[L_ECC_MAX_DIGITS];
	const void *unwrap_key;
	const void *ad0 = body + 2;
	const void *ad1 = body + 8;
	struct l_ecc_point *bi = NULL;

	if (dpp->state != DPP_STATE_AUTHENTICATING)
		return;

	if (memcmp(from, dpp->peer_addr, 6))
		return;

	l_debug("authenticate confirm");

	dpp_attr_iter_init(&iter, body + 8, body_len - 8);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_STATUS:
			status = l_get_u8(data);
			break;
		case DPP_ATTR_RESPONDER_BOOT_KEY_HASH:
			r_boot_hash = data;
			/*
			 * Spec requires this, but does not mention if anything
			 * is to be done with it.
			 */
			break;
		case DPP_ATTR_INITIATOR_BOOT_KEY_HASH:
			/* No mutual authentication */
			break;
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			break;
		}
	}

	if (!r_boot_hash || !wrapped) {
		l_debug("Attributes missing from authenticate confirm");
		return;
	}

	/*
	 * "The Responder obtains the DPP Authentication Confirm frame and
	 * checks the value of the DPP Status field. If the value of the DPP
	 * Status field is STATUS_NOT_COMPATIBLE or STATUS_AUTH_FAILURE, the
	 * Responder unwraps the wrapped data portion of the frame using k2"
	 */
	if (status == DPP_STATUS_OK)
		unwrap_key = dpp->ke;
	else if (status == DPP_STATUS_NOT_COMPATIBLE ||
				status == DPP_STATUS_AUTH_FAILURE)
		unwrap_key = dpp->k2;
	else
		goto auth_confirm_failed;

	unwrapped = dpp_unwrap_attr(ad0, 6, ad1, wrapped - 4 - ad1,
			unwrap_key, dpp->key_len, wrapped, wrapped_len,
			&wrapped_len);
	if (!unwrapped)
		goto auth_confirm_failed;

	if (status != DPP_STATUS_OK) {
		/*
		 * "If unwrapping is successful, the Responder should generate
		 * an alert indicating the reason for the protocol failure."
		 */
		l_debug("Authentication failed due to status %s",
				status == DPP_STATUS_NOT_COMPATIBLE ?
				"NOT_COMPATIBLE" : "AUTH_FAILURE");
		goto auth_confirm_failed;
	}

	dpp_attr_iter_init(&iter, unwrapped, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_INITIATOR_AUTH_TAG:
			i_auth = data;
			i_auth_len = len;
			break;
		case DPP_ATTR_RESPONDER_NONCE:
			/* Only if error */
			break;
		default:
			break;
		}
	}

	if (!i_auth || i_auth_len != dpp->key_len) {
		l_debug("I-Auth missing from wrapped data");
		goto auth_confirm_failed;
	}

	if (dpp->mutual_auth)
		bi = dpp->peer_boot_public;

	dpp_derive_i_auth(dpp->r_nonce, dpp->i_nonce, dpp->nonce_len,
				dpp->own_proto_public, dpp->peer_proto_public,
				dpp->boot_public, bi, i_auth_check);

	if (memcmp(i_auth, i_auth_check, i_auth_len)) {
		l_error("I-Auth did not verify");
		goto auth_confirm_failed;
	}

	l_debug("Authentication successful");

	dpp_reset_protocol_timer(dpp, DPP_AUTH_PROTO_TIMEOUT);

	if (dpp->role == DPP_CAPABILITY_ENROLLEE)
		dpp_configuration_start(dpp, from);

	return;

auth_confirm_failed:
	dpp->state = DPP_STATE_PRESENCE;
	dpp_free_auth_data(dpp);
}

static void dpp_auth_request_failed(struct dpp_sm *dpp,
					enum dpp_status status,
					void *k1)
{
	uint8_t hdr[32];
	uint8_t attrs[128];
	uint8_t *ptr = attrs;
	uint8_t version = 2;
	uint8_t s = status;
	struct iovec iov[2];

	iov[0].iov_len = dpp_build_header(netdev_get_address(dpp->netdev),
				dpp->peer_addr,
				DPP_FRAME_AUTHENTICATION_RESPONSE, hdr);
	iov[0].iov_base = hdr;

	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &s, 1);
	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH,
				dpp->own_boot_hash, 32);

	ptr += dpp_append_attr(ptr, DPP_ATTR_PROTOCOL_VERSION, &version, 1);

	ptr += dpp_append_wrapped_data(hdr + 26, 6, attrs, ptr - attrs,
			ptr, sizeof(attrs) - (ptr - attrs), k1, dpp->key_len, 2,
			DPP_ATTR_INITIATOR_NONCE, dpp->nonce_len, dpp->i_nonce,
			DPP_ATTR_RESPONDER_CAPABILITIES,
			(size_t) 1, &dpp->role);

	iov[1].iov_base = attrs;
	iov[1].iov_len = ptr - attrs;

	dpp_send_frame(dpp, iov, 2, dpp->current_freq);
}

static bool dpp_check_roles(struct dpp_sm *dpp, uint8_t peer_capa)
{
	if (dpp->role == DPP_CAPABILITY_ENROLLEE &&
			!(peer_capa & DPP_CAPABILITY_CONFIGURATOR))
		return false;
	else if (dpp->role == DPP_CAPABILITY_CONFIGURATOR &&
			!(peer_capa & DPP_CAPABILITY_ENROLLEE))
		return false;

	return true;
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
			dpp->own_asn1, dpp->own_asn1_len);

	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH, hash, 32);

	iov[1].iov_base = attrs;
	iov[1].iov_len = ptr - attrs;

	l_debug("Sending presence announcement on frequency %u and waiting %u",
		dpp->current_freq, dpp->dwell);

	dpp_send_frame(dpp, iov, 2, dpp->current_freq);
}

static bool dpp_send_authenticate_request(struct dpp_sm *dpp)
{
	uint8_t hdr[32];
	uint8_t attrs[256];
	uint8_t *ptr = attrs;
	uint64_t i_proto_key[L_ECC_MAX_DIGITS * 2];
	uint8_t version = 2;
	struct iovec iov[2];
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));
	struct scan_bss *bss = station_get_connected_bss(station);

	/* Got disconnected by the time the peer was discovered */
	if (!bss) {
		dpp_reset(dpp);
		return false;
	}

	l_ecc_point_get_data(dpp->own_proto_public, i_proto_key,
				sizeof(i_proto_key));

	iov[0].iov_len = dpp_build_header(netdev_get_address(dpp->netdev),
				dpp->peer_addr,
				DPP_FRAME_AUTHENTICATION_REQUEST, hdr);
	iov[0].iov_base = hdr;

	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH,
				dpp->peer_boot_hash, 32);
	ptr += dpp_append_attr(ptr, DPP_ATTR_INITIATOR_BOOT_KEY_HASH,
				dpp->own_boot_hash, 32);
	ptr += dpp_append_attr(ptr, DPP_ATTR_INITIATOR_PROTOCOL_KEY,
				i_proto_key, dpp->key_len * 2);
	ptr += dpp_append_attr(ptr, DPP_ATTR_PROTOCOL_VERSION, &version, 1);

	if (dpp->current_freq != bss->frequency) {
		uint8_t pair[2] = { 81,
				band_freq_to_channel(bss->frequency, NULL) };

		ptr += dpp_append_attr(ptr, DPP_ATTR_CHANNEL, pair, 2);
	}

	ptr += dpp_append_wrapped_data(hdr + 26, 6, attrs, ptr - attrs,
			ptr, sizeof(attrs), dpp->k1, dpp->key_len, 2,
			DPP_ATTR_INITIATOR_NONCE, dpp->nonce_len, dpp->i_nonce,
			DPP_ATTR_INITIATOR_CAPABILITIES,
			(size_t) 1, &dpp->role);

	iov[1].iov_base = attrs;
	iov[1].iov_len = ptr - attrs;

	dpp_send_frame(dpp, iov, 2, dpp->current_freq);

	return true;
}

static void dpp_roc_started(void *user_data)
{
	struct dpp_sm *dpp = user_data;

	/*
	 * - If a configurator, nothing to do but wait for a request
	 *   (unless multicast frame registration is unsupported in which case
	 *   send an authenticate request now)
	 * - If in the presence state continue sending announcements.
	 * - If authenticating, and this is a result of a channel switch send
	 *   the authenticate response now.
	 */

	dpp->roc_started = true;

	/*
	 * The retry timer indicates a frame was not acked in which case we
	 * should not change any state or send any frames until that expires.
	 */
	if (dpp->retry_timeout)
		return;

	if (dpp->frame_pending) {
		dpp_frame_retry(dpp);
		return;
	}

	switch (dpp->state) {
	case DPP_STATE_PRESENCE:
		if (dpp->role == DPP_CAPABILITY_CONFIGURATOR)
			return;

		if (dpp->pending) {
			struct l_dbus_message *reply =
				l_dbus_message_new_method_return(dpp->pending);

			l_dbus_message_set_arguments(reply, "s", dpp->uri);

			dbus_pending_reply(&dpp->pending, reply);
		}

		dpp_presence_announce(dpp);
		break;
	case DPP_STATE_AUTHENTICATING:
		/*
		 * No multicast frame registration support, jump right into
		 * sending auth frames. This diverges from the 2.0 spec, but in
		 * reality the the main path nearly all drivers will hit.
		 */
		if (dpp->role == DPP_CAPABILITY_CONFIGURATOR) {
			if (dpp->mcast_support)
				return;

			dpp_send_authenticate_request(dpp);
			return;
		}

		if (dpp->new_freq) {
			dpp->current_freq = dpp->new_freq;
			dpp->new_freq = 0;
			send_authenticate_response(dpp);
		}

		break;
	default:
		break;
	}
}

static void dpp_start_offchannel(struct dpp_sm *dpp, uint32_t freq);

static void dpp_offchannel_timeout(int error, void *user_data)
{
	struct dpp_sm *dpp = user_data;

	dpp->offchannel_id = 0;
	dpp->roc_started = false;

	/*
	 * If cancelled this is likely due to netdev going down or from Stop().
	 * Otherwise there was some other problem which is probably not
	 * recoverable.
	 */
	if (error == -ECANCELED)
		return;
	else if (error == -EIO)
		goto next_roc;
	else if (error < 0)
		goto protocol_failed;

	switch (dpp->state) {
	case DPP_STATE_PRESENCE:
		break;
	case DPP_STATE_NOTHING:
		/* Protocol already terminated */
		return;
	case DPP_STATE_AUTHENTICATING:
	case DPP_STATE_CONFIGURING:
		goto next_roc;
	}

	dpp->freqs_idx++;

	if (dpp->freqs_idx >= dpp->freqs_len) {
		l_debug("Max retries offchannel");
		dpp->freqs_idx = 0;
	}

	dpp->current_freq = dpp->freqs[dpp->freqs_idx];

	l_debug("Offchannel timeout, moving to next frequency %u, duration %u",
			dpp->current_freq, dpp->dwell);

next_roc:
	dpp_start_offchannel(dpp, dpp->current_freq);

	return;

protocol_failed:
	dpp_reset(dpp);
}

static void dpp_start_offchannel(struct dpp_sm *dpp, uint32_t freq)
{
	/*
	 * This needs to be handled carefully for a few reasons:
	 *
	 * First, the next offchannel operation needs to be started prior to
	 * canceling an existing one. This is so the offchannel work can
	 * continue uninterrupted without any other work items starting in
	 * between canceling and starting the next (e.g. if a scan request is
	 * sitting in the queue).
	 *
	 * Second, dpp_offchannel_timeout resets dpp->offchannel_id to zero
	 * which is why the new ID is saved and only set to dpp->offchannel_id
	 * once the previous offchannel work is cancelled (i.e. destroy() has
	 * been called).
	 */
	uint32_t id = offchannel_start(netdev_get_wdev_id(dpp->netdev),
				WIPHY_WORK_PRIORITY_OFFCHANNEL,
				freq, dpp->dwell, dpp_roc_started,
				dpp, dpp_offchannel_timeout);

	if (dpp->offchannel_id)
		offchannel_cancel(dpp->wdev_id, dpp->offchannel_id);

	dpp->offchannel_id = id;
}

static void authenticate_request(struct dpp_sm *dpp, const uint8_t *from,
					const uint8_t *body, size_t body_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	const uint8_t *r_boot = NULL;
	const uint8_t *i_boot = NULL;
	const uint8_t *i_proto = NULL;
	const void *wrapped = NULL;
	const uint8_t *i_nonce = NULL;
	uint8_t i_capa = 0;
	size_t r_boot_len = 0, i_proto_len = 0, wrapped_len = 0;
	size_t i_nonce_len = 0;
	_auto_(l_free) uint8_t *unwrapped = NULL;
	_auto_(l_ecc_scalar_free) struct l_ecc_scalar *m = NULL;
	_auto_(l_ecc_scalar_free) struct l_ecc_scalar *n = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *l = NULL;
	struct l_ecc_point *bi = NULL;
	uint64_t k1[L_ECC_MAX_DIGITS];
	const void *ad0 = body + 2;
	const void *ad1 = body + 8;
	uint32_t freq;

	if (util_is_broadcast_address(from))
		return;

	if (dpp->state != DPP_STATE_PRESENCE)
		return;

	l_debug("authenticate request");

	dpp_attr_iter_init(&iter, body + 8, body_len - 8);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_INITIATOR_BOOT_KEY_HASH:
			i_boot = data;
			/*
			 * This attribute is required by the spec, but only
			 * used for mutual authentication.
			 */
			break;
		case DPP_ATTR_RESPONDER_BOOT_KEY_HASH:
			r_boot = data;
			r_boot_len = len;
			break;
		case DPP_ATTR_INITIATOR_PROTOCOL_KEY:
			i_proto = data;
			i_proto_len = len;
			break;
		case DPP_ATTR_WRAPPED_DATA:
			/* I-Nonce/I-Capabilities part of wrapped data */
			wrapped = data;
			wrapped_len = len;
			break;

		/* Optional attributes */
		case DPP_ATTR_PROTOCOL_VERSION:
			if (l_get_u8(data) != 2) {
				l_debug("Protocol version did not match");
				return;
			}

			break;

		case DPP_ATTR_CHANNEL:
			if (len != 2)
				return;

			freq = oci_to_frequency(l_get_u8(data),
						l_get_u8(data + 1));

			if (freq == dpp->current_freq)
				break;

			/*
			 * Configurators are already connected to a network, so
			 * to preserve wireless performance the enrollee will
			 * be required to be on this channel, not a channel it
			 * requests.
			 */
			if (dpp->role == DPP_CAPABILITY_CONFIGURATOR)
				return;

			/*
			 * Otherwise, as an enrollee, we can jump to whatever
			 * channel the configurator requests
			 */
			dpp->new_freq = freq;

			l_debug("Configurator requested a new frequency %u",
					dpp->new_freq);

			dpp_start_offchannel(dpp, dpp->new_freq);

			break;
		default:
			break;
		}
	}

	if (!r_boot || !i_boot || !i_proto || !wrapped)
		goto auth_request_failed;

	if (r_boot_len != 32 || memcmp(dpp->own_boot_hash,
					r_boot, r_boot_len)) {
		l_debug("Responder boot key hash failed to verify");
		goto auth_request_failed;
	}

	dpp->peer_proto_public = l_ecc_point_from_data(dpp->curve,
						L_ECC_POINT_TYPE_FULL,
						i_proto, i_proto_len);
	if (!dpp->peer_proto_public) {
		l_debug("Initiators protocol key invalid");
		goto auth_request_failed;
	}

	m = dpp_derive_k1(dpp->peer_proto_public, dpp->boot_private, k1);
	if (!m)
		goto auth_request_failed;

	unwrapped = dpp_unwrap_attr(ad0, 6, ad1, wrapped - 4 - ad1,
			k1, dpp->key_len, wrapped, wrapped_len, &wrapped_len);
	if (!unwrapped)
		goto auth_request_failed;

	dpp_attr_iter_init(&iter, unwrapped, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_INITIATOR_NONCE:
			i_nonce = data;
			i_nonce_len = len;
			break;
		case DPP_ATTR_INITIATOR_CAPABILITIES:
			/*
			 * "If the Responder is not capable of supporting the
			 * role indicated by the Initiator, it shall respond
			 * with a DPP Authentication Response frame indicating
			 * failure by adding the DPP Status field set to
			 * STATUS_NOT_COMPATIBLE"
			 */
			i_capa = l_get_u8(data);

			if (!dpp_check_roles(dpp, i_capa)) {
				l_debug("Peer does not support required role");
				dpp_auth_request_failed(dpp,
						DPP_STATUS_NOT_COMPATIBLE, k1);
				goto auth_request_failed;
			}

			break;
		default:
			break;
		}
	}

	if (i_nonce_len != dpp->nonce_len) {
		l_debug("I-Nonce has unexpected length %zu", i_nonce_len);
		goto auth_request_failed;
	}

	memcpy(dpp->i_nonce, i_nonce, i_nonce_len);

	if (dpp->mutual_auth) {
		l = dpp_derive_lr(dpp->boot_private, dpp->proto_private,
					dpp->peer_boot_public);
		bi = dpp->peer_boot_public;
	}

	/* Derive keys k2, ke, and R-Auth for authentication response */

	n = dpp_derive_k2(dpp->peer_proto_public, dpp->proto_private, dpp->k2);
	if (!n)
		goto auth_request_failed;

	l_getrandom(dpp->r_nonce, dpp->nonce_len);

	if (!dpp_derive_ke(dpp->i_nonce, dpp->r_nonce, m, n, l, dpp->ke))
		goto auth_request_failed;

	if (!dpp_derive_r_auth(dpp->i_nonce, dpp->r_nonce, dpp->nonce_len,
				dpp->peer_proto_public, dpp->own_proto_public,
				bi, dpp->boot_public, dpp->auth_tag))
		goto auth_request_failed;

	memcpy(dpp->peer_addr, from, 6);

	dpp->state = DPP_STATE_AUTHENTICATING;
	dpp_reset_protocol_timer(dpp, DPP_AUTH_PROTO_TIMEOUT);

	/* Don't send if the frequency is changing */
	if (!dpp->new_freq)
		send_authenticate_response(dpp);

	return;

auth_request_failed:
	dpp->state = DPP_STATE_PRESENCE;
	dpp_free_auth_data(dpp);
}

static void dpp_send_authenticate_confirm(struct dpp_sm *dpp)
{
	uint8_t hdr[32];
	struct iovec iov[2];
	uint8_t attrs[256];
	uint8_t *ptr = attrs;
	uint8_t zero = 0;

	iov[0].iov_len = dpp_build_header(netdev_get_address(dpp->netdev),
					dpp->peer_addr,
					DPP_FRAME_AUTHENTICATION_CONFIRM, hdr);
	iov[0].iov_base = hdr;

	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &zero, 1);
	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH,
					dpp->peer_boot_hash, 32);
	if (dpp->mutual_auth)
		ptr += dpp_append_attr(ptr, DPP_ATTR_INITIATOR_BOOT_KEY_HASH,
					dpp->own_boot_hash, 32);

	ptr += dpp_append_wrapped_data(hdr + 26, 6, attrs, ptr - attrs, ptr,
			sizeof(attrs), dpp->ke, dpp->key_len, 1,
			DPP_ATTR_INITIATOR_AUTH_TAG, dpp->key_len,
			dpp->auth_tag);

	iov[1].iov_base = attrs;
	iov[1].iov_len = ptr - attrs;

	dpp_send_frame(dpp, iov, 2, dpp->current_freq);
}

static void authenticate_response(struct dpp_sm *dpp, const uint8_t *from,
					const uint8_t *body, size_t body_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	int status = -1;
	const void *r_boot_hash = NULL;
	const void *r_proto = NULL;
	size_t r_proto_len = 0;
	const void *wrapped = NULL;
	size_t wrapped_len;
	_auto_(l_free) uint8_t *unwrapped1 = NULL;
	_auto_(l_free) uint8_t *unwrapped2 = NULL;
	const void *r_nonce = NULL;
	const void *i_nonce = NULL;
	const void *r_auth = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *r_proto_key = NULL;
	_auto_(l_ecc_scalar_free) struct l_ecc_scalar *n = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *l = NULL;
	struct l_ecc_point *bi = NULL;
	const void *ad0 = body + 2;
	const void *ad1 = body + 8;
	uint64_t r_auth_derived[L_ECC_MAX_DIGITS];

	l_debug("Authenticate response");

	if (dpp->state != DPP_STATE_AUTHENTICATING)
		return;

	if (dpp->role != DPP_CAPABILITY_CONFIGURATOR)
		return;

	if (!dpp->freqs)
		return;

	if (memcmp(from, dpp->peer_addr, 6))
		return;

	dpp_attr_iter_init(&iter, body + 8, body_len - 8);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_STATUS:
			if (len != 1)
				return;

			status = l_get_u8(data);
			break;
		case DPP_ATTR_RESPONDER_BOOT_KEY_HASH:
			r_boot_hash = data;
			break;
		case DPP_ATTR_RESPONDER_PROTOCOL_KEY:
			r_proto = data;
			r_proto_len = len;
			break;
		case DPP_ATTR_PROTOCOL_VERSION:
			if (len != 1 || l_get_u8(data) != 2)
				return;
			break;
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			break;
		}
	}

	if (status != DPP_STATUS_OK || !r_boot_hash || !r_proto ) {
		l_debug("Auth response bad status or missing attributes");
		return;
	}

	r_proto_key = l_ecc_point_from_data(dpp->curve, L_ECC_POINT_TYPE_FULL,
						r_proto, r_proto_len);
	if (!r_proto_key) {
		l_debug("Peers protocol key was invalid");
		return;
	}

	n = dpp_derive_k2(r_proto_key, dpp->proto_private, dpp->k2);

	unwrapped1 = dpp_unwrap_attr(ad0, 6, ad1, wrapped - 4 - ad1, dpp->k2,
					dpp->key_len, wrapped, wrapped_len,
					&wrapped_len);
	if (!unwrapped1) {
		l_debug("Failed to unwrap primary data");
		return;
	}

	wrapped = NULL;

	dpp_attr_iter_init(&iter, unwrapped1, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_RESPONDER_NONCE:
			if (len != dpp->nonce_len)
				return;

			r_nonce = data;
			break;
		case DPP_ATTR_INITIATOR_NONCE:
			if (len != dpp->nonce_len)
				return;

			i_nonce = data;
			break;
		case DPP_ATTR_RESPONDER_CAPABILITIES:
			break;
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			break;
		}
	}

	if (!r_nonce || !i_nonce || !wrapped) {
		l_debug("Wrapped data missing attributes");
		return;
	}

	if (dpp->mutual_auth) {
		l = dpp_derive_li(dpp->peer_boot_public, r_proto_key,
					dpp->boot_private);
		bi = dpp->boot_public;
	}

	if (!dpp_derive_ke(i_nonce, r_nonce, dpp->m, n, l, dpp->ke)) {
		l_debug("Failed to derive ke");
		return;
	}

	unwrapped2 = dpp_unwrap_attr(NULL, 0, NULL, 0, dpp->ke, dpp->key_len,
					wrapped, wrapped_len, &wrapped_len);
	if (!unwrapped2) {
		l_debug("Failed to unwrap secondary data");
		return;
	}

	dpp_attr_iter_init(&iter, unwrapped2, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_RESPONDER_AUTH_TAG:
			if (len != dpp->key_len)
				return;

			r_auth = data;
			break;
		default:
			break;
		}
	}

	if (!r_auth) {
		l_debug("R-Auth was not in secondary wrapped data");
		return;
	}

	if (!dpp_derive_r_auth(i_nonce, r_nonce, dpp->nonce_len,
				dpp->own_proto_public, r_proto_key, bi,
				dpp->peer_boot_public, r_auth_derived)) {
		l_debug("Failed to derive r_auth");
		return;
	}

	if (memcmp(r_auth, r_auth_derived, dpp->key_len)) {
		l_debug("R-Auth did not verify");
		return;
	}

	if (!dpp_derive_i_auth(r_nonce, i_nonce, dpp->nonce_len,
				r_proto_key, dpp->own_proto_public,
				dpp->peer_boot_public, bi, dpp->auth_tag)) {
		l_debug("Could not derive I-Auth");
		return;
	}

	dpp->channel_switch = false;
	dpp->current_freq = dpp->new_freq;

	dpp_send_authenticate_confirm(dpp);
}

static void dpp_handle_presence_announcement(struct dpp_sm *dpp,
						const uint8_t *from,
						const uint8_t *body,
						size_t body_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	const void *r_boot = NULL;
	size_t r_boot_len = 0;
	uint8_t hash[32];

	l_debug("Presence announcement "MAC, MAC_STR(from));

	/* Must be a configurator, in an initiator role, in PRESENCE state */
	if (dpp->state != DPP_STATE_PRESENCE)
		return;

	if (dpp->role != DPP_CAPABILITY_CONFIGURATOR)
		return;

	if (!dpp->freqs)
		return;

	/*
	 * The URI may not have contained a MAC address, if this announcement
	 * verifies set peer_addr then.
	 */
	if (!l_memeqzero(dpp->peer_addr, 6) &&
				memcmp(from, dpp->peer_addr, 6)) {
		l_debug("Unexpected source "MAC" expected "MAC, MAC_STR(from),
						MAC_STR(dpp->peer_addr));
		return;
	}

	dpp_attr_iter_init(&iter, body + 8, body_len - 8);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_RESPONDER_BOOT_KEY_HASH:
			r_boot = data;
			r_boot_len = len;
			break;
		default:
			break;
		}
	}

	if (!r_boot || r_boot_len != 32) {
		l_debug("No responder boot hash");
		return;
	}

	/* Hash what we have for the peer and check its our enrollee */
	dpp_hash(L_CHECKSUM_SHA256, hash, 2, "chirp", strlen("chirp"),
			dpp->peer_asn1, dpp->peer_asn1_len);

	if (memcmp(hash, r_boot, sizeof(hash))) {
		l_debug("Peers boot hash did not match");
		return;
	}

	/*
	 * This is the peer we expected, save away the address and derive the
	 * initial keys.
	 */
	memcpy(dpp->peer_addr, from, 6);

	dpp->state = DPP_STATE_AUTHENTICATING;

	if (!dpp_send_authenticate_request(dpp))
		return;

	/*
	 * Requested the peer to move to another channel for the remainder of
	 * the protocol. IWD's current logic prohibits a configurator from
	 * running while not connected, so we can assume here that the new
	 * frequency is the same of the connected BSS. Wait until an ACK is
	 * received for the auth request then cancel the offchannel request.
	 */
	if (dpp->current_freq != dpp->new_freq)
		dpp->channel_switch = true;
}

static void dpp_handle_frame(struct dpp_sm *dpp,
				const struct mmpdu_header *frame,
				const void *body, size_t body_len)
{
	const uint8_t *ptr;

	/*
	 * Both handlers offset by 8 bytes to reach the beginning of the DPP
	 * attributes. Easier checking this in one place, which also covers the
	 * frame type byte.
	 */
	if (body_len < 8)
		return;

	ptr = body + 7;

	switch (*ptr) {
	case DPP_FRAME_AUTHENTICATION_REQUEST:
		authenticate_request(dpp, frame->address_2, body, body_len);
		break;
	case DPP_FRAME_AUTHENTICATION_RESPONSE:
		authenticate_response(dpp, frame->address_2, body, body_len);
		break;
	case DPP_FRAME_AUTHENTICATION_CONFIRM:
		authenticate_confirm(dpp, frame->address_2, body, body_len);
		break;
	case DPP_FRAME_CONFIGURATION_RESULT:
		dpp_handle_config_result_frame(dpp, frame->address_2,
						body, body_len);
		break;
	case DPP_FRAME_PRESENCE_ANNOUNCEMENT:
		dpp_handle_presence_announcement(dpp, frame->address_2,
							body, body_len);
		break;
	default:
		l_debug("Unhandled DPP frame %u", *ptr);
		break;
	}
}

static bool match_wdev(const void *a, const void *b)
{
	const struct dpp_sm *dpp = a;
	const uint64_t *wdev_id = b;

	return *wdev_id == dpp->wdev_id;
}

static void dpp_frame_timeout(struct l_timeout *timeout, void *user_data)
{
	struct dpp_sm *dpp = user_data;

	l_timeout_remove(timeout);
	dpp->retry_timeout = NULL;

	/*
	 * ROC has not yet started (in between an ROC timeout and starting a
	 * new session), this will most likely result in the frame failing to
	 * send. Just bail out now and the roc_started callback will take care
	 * of sending this out.
	 */
	if (dpp->offchannel_id && !dpp->roc_started)
		return;

	dpp_frame_retry(dpp);
}

static void dpp_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct dpp_sm *dpp;
	uint64_t wdev_id = 0;
	uint64_t cookie = 0;
	bool ack = false;
	struct iovec iov;
	uint8_t cmd = l_genl_msg_get_command(msg);

	if (cmd != NL80211_CMD_FRAME_TX_STATUS)
		return;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV, &wdev_id,
				NL80211_ATTR_COOKIE, &cookie,
				NL80211_ATTR_ACK, &ack,
				NL80211_ATTR_FRAME, &iov,
				NL80211_ATTR_UNSPEC) < 0)
		return;

	dpp = l_queue_find(dpp_list, match_wdev, &wdev_id);
	if (!dpp)
		return;

	if (dpp->state <= DPP_STATE_PRESENCE)
		return;


	if (dpp->frame_cookie != cookie)
		return;

	/*
	 * Only want to handle the no-ACK case. Re-transmitting an ACKed
	 * frame likely wont do any good, at least in the case of DPP.
	 */
	if (!ack)
		goto retransmit;

	/*
	 * Special handling for a channel transition when acting as a
	 * configurator. The auth request was sent offchannel so we need to
	 * wait for the ACK before going back to the connected channel.
	 */
	if (dpp->channel_switch) {
		if (dpp->offchannel_id) {
			offchannel_cancel(dpp->wdev_id, dpp->offchannel_id);
			dpp->offchannel_id = 0;
		}

		dpp->channel_switch = false;
	}

	return;

retransmit:
	if (dpp->frame_retry > DPP_FRAME_MAX_RETRIES) {
		dpp_reset(dpp);
		return;
	}

	/* This should never happen */
	if (L_WARN_ON(dpp->frame_pending))
		return;

	l_debug("No ACK from peer, re-transmitting in %us",
			DPP_FRAME_RETRY_TIMEOUT);

	dpp->frame_retry++;

	dpp->frame_pending = l_memdup(iov.iov_base, iov.iov_len);
	dpp->frame_size = iov.iov_len;
	dpp->retry_timeout = l_timeout_create(DPP_FRAME_RETRY_TIMEOUT,
						dpp_frame_timeout, dpp, NULL);
}

static void dpp_unicast_notify(struct l_genl_msg *msg, void *user_data)
{
	struct dpp_sm *dpp;
	const uint64_t *wdev_id = NULL;
	struct l_genl_attr attr;
	uint16_t type, len, frame_len;
	const void *data;
	const struct mmpdu_header *mpdu = NULL;
	const uint8_t *body;
	size_t body_len;

	if (l_genl_msg_get_command(msg) != NL80211_CMD_FRAME)
		return;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WDEV:
			if (len != 8)
				break;

			wdev_id = data;
			break;

		case NL80211_ATTR_FRAME:
			mpdu = mpdu_validate(data, len);
			if (!mpdu) {
				l_warn("Frame didn't validate as MMPDU");
				return;
			}

			frame_len = len;
			break;
		}
	}

	if (!wdev_id) {
		l_warn("Bad wdev attribute");
		return;
	}

	dpp = l_queue_find(dpp_list, match_wdev, wdev_id);
	if (!dpp)
		return;

	if (!mpdu) {
		l_warn("Missing frame data");
		return;
	}

	body = mmpdu_body(mpdu);
	body_len = (const uint8_t *) mpdu + frame_len - body;

	if (body_len < sizeof(dpp_prefix) ||
			memcmp(body, dpp_prefix, sizeof(dpp_prefix)) != 0)
		return;

	dpp_handle_frame(dpp, mpdu, body, body_len);
}

static void dpp_frame_watch_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("Could not register frame watch type %04x: %i",
			L_PTR_TO_UINT(user_data), l_genl_msg_get_error(msg));
}

/*
 * Special case the frame watch which includes the presence frames since they
 * require multicast support. This is only supported by ath9k, so adding
 * general support to frame-xchg isn't desireable.
 */
static void dpp_frame_watch(struct dpp_sm *dpp, uint16_t frame_type,
				const uint8_t *prefix, size_t prefix_len)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_REGISTER_FRAME, 32 + prefix_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &dpp->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME_TYPE, 2, &frame_type);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME_MATCH,
				prefix_len, prefix);
	if (dpp->mcast_support)
		l_genl_msg_append_attr(msg, NL80211_ATTR_RECEIVE_MULTICAST,
					0, NULL);

	l_genl_family_send(nl80211, msg, dpp_frame_watch_cb,
					L_UINT_TO_PTR(frame_type), NULL);
}

static void dpp_create(struct netdev *netdev)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct dpp_sm *dpp = l_new(struct dpp_sm, 1);
	uint8_t dpp_conf_response_prefix[] = { 0x04, 0x0b };
	uint8_t dpp_conf_request_prefix[] = { 0x04, 0x0a };
	uint64_t wdev_id = netdev_get_wdev_id(netdev);

	dpp->netdev = netdev;
	dpp->state = DPP_STATE_NOTHING;
	dpp->wdev_id = wdev_id;
	dpp->curve = l_ecc_curve_from_ike_group(19);
	dpp->key_len = l_ecc_curve_get_scalar_bytes(dpp->curve);
	dpp->nonce_len = dpp_nonce_len_from_key_len(dpp->key_len);
	dpp->max_roc = wiphy_get_max_roc_duration(wiphy_find_by_wdev(wdev_id));
	dpp->mcast_support = wiphy_has_ext_feature(
				wiphy_find_by_wdev(dpp->wdev_id),
				NL80211_EXT_FEATURE_MULTICAST_REGISTRATIONS);

	l_ecdh_generate_key_pair(dpp->curve, &dpp->boot_private,
					&dpp->boot_public);

	dpp->own_asn1 = dpp_point_to_asn1(dpp->boot_public, &dpp->own_asn1_len);

	dpp_hash(L_CHECKSUM_SHA256, dpp->own_boot_hash, 1,
			dpp->own_asn1, dpp->own_asn1_len);

	l_dbus_object_add_interface(dbus, netdev_get_path(netdev),
					IWD_DPP_INTERFACE, dpp);

	dpp_frame_watch(dpp, 0x00d0, dpp_prefix, sizeof(dpp_prefix));

	frame_watch_add(netdev_get_wdev_id(netdev), 0, 0x00d0,
				dpp_conf_response_prefix,
				sizeof(dpp_conf_response_prefix),
				dpp_handle_config_response_frame, dpp, NULL);
	frame_watch_add(netdev_get_wdev_id(netdev), 0, 0x00d0,
				dpp_conf_request_prefix,
				sizeof(dpp_conf_request_prefix),
				dpp_handle_config_request_frame, dpp, NULL);

	l_queue_push_tail(dpp_list, dpp);
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
	if (limit_freqs) {
		dpp->freqs = l_memdup(limit_freqs, sizeof(uint32_t) * limit_len);
		dpp->freqs_len = limit_len;
	} else
		dpp->freqs = dpp_add_default_channels(dpp, &dpp->freqs_len);

	dpp->dwell = (dpp->max_roc < 2000) ? dpp->max_roc : 2000;
	dpp->freqs_idx = 0;
	dpp->current_freq = dpp->freqs[0];

	dpp_start_offchannel(dpp, dpp->current_freq);
}

static struct l_dbus_message *dpp_dbus_start_enrollee(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct dpp_sm *dpp = user_data;
	uint32_t freq = band_channel_to_freq(6, BAND_FREQ_2_4_GHZ);
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));

	if (dpp->state != DPP_STATE_NOTHING)
		return dbus_error_busy(message);

	/*
	 * Station isn't actually required for DPP itself, although this will
	 * prevent connecting to the network once configured.
	 */
	if (station && station_get_connected_network(station)) {
		l_warn("cannot be enrollee while connected, please disconnect");
		return dbus_error_busy(message);
	} else if (!station)
		l_debug("No station device, continuing anyways...");

	dpp->uri = dpp_generate_uri(dpp->own_asn1, dpp->own_asn1_len, 2,
					netdev_get_address(dpp->netdev), &freq,
					1, NULL, NULL);

	dpp->state = DPP_STATE_PRESENCE;
	dpp->role = DPP_CAPABILITY_ENROLLEE;

	l_ecdh_generate_key_pair(dpp->curve, &dpp->proto_private,
					&dpp->own_proto_public);

	l_debug("DPP Start Enrollee: %s", dpp->uri);

	dpp->pending = l_dbus_message_ref(message);

	/*
	 * Going off spec here. Select a single channel to send presence
	 * announcements on. This will be advertised in the URI. The full
	 * presence procedure can be implemented if it is ever needed.
	 */
	dpp_start_presence(dpp, &freq, 1);

	dpp_property_changed_notify(dpp);

	return NULL;
}

/*
 * Set up the configurator for an initiator role. The configurator
 * will go offchannel to frequencies advertised by the enrollees URI or,
 * if no channels are provided, use a default channel list.
 */
static bool dpp_configurator_start_presence(struct dpp_sm *dpp, const char *uri)
{
	_auto_(l_free) uint32_t *freqs = NULL;
	size_t freqs_len = 0;
	struct dpp_uri_info *info;

	info = dpp_parse_uri(uri);
	if (!info)
		return false;

	/*
	 * Very few drivers actually support registration of multicast frames.
	 * This renders the presence procedure impossible on most drivers.
	 * But not all is lost. If the URI contains the MAC and channel
	 * info we an start going through channels sending auth requests which
	 * is basically DPP 1.0. Otherwise DPP cannot start.
	 */
	if (!dpp->mcast_support &&
				(l_memeqzero(info->mac, 6) || !info->freqs)) {
		l_error("No multicast registration support, URI must contain "
			"MAC and channel information");
		dpp_free_uri_info(info);
		return false;
	}

	if (!l_memeqzero(info->mac, 6))
		memcpy(dpp->peer_addr, info->mac, 6);

	if (info->freqs)
		freqs = scan_freq_set_to_fixed_array(info->freqs, &freqs_len);

	dpp->peer_boot_public = l_ecc_point_clone(info->boot_public);
	dpp->peer_asn1 = dpp_point_to_asn1(info->boot_public,
						&dpp->peer_asn1_len);

	dpp_free_uri_info(info);

	if (!dpp->peer_asn1) {
		l_debug("Peer boot key did not convert to asn1");
		return false;
	}

	dpp_hash(L_CHECKSUM_SHA256, dpp->peer_boot_hash, 1, dpp->peer_asn1,
			dpp->peer_asn1_len);

	dpp_start_presence(dpp, freqs, freqs_len);

	return true;
}

static struct l_dbus_message *dpp_start_configurator_common(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data,
						bool responder)
{
	struct dpp_sm *dpp = user_data;
	struct l_dbus_message *reply;
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));
	struct scan_bss *bss;
	struct network *network;
	struct l_settings *settings;
	struct handshake_state *hs = netdev_get_handshake(dpp->netdev);
	const char *uri;

	/*
	 * For now limit the configurator to only configuring enrollees to the
	 * currently connected network.
	 */
	if (!station)
		return dbus_error_not_available(message);

	bss = station_get_connected_bss(station);
	network = station_get_connected_network(station);
	if (!bss || !network)
		return dbus_error_not_connected(message);

	settings = network_get_settings(network);
	if (!settings)
		return dbus_error_not_configured(message);

	if (network_get_security(network) != SECURITY_PSK)
		return dbus_error_not_supported(message);

	if (dpp->state != DPP_STATE_NOTHING)
		return dbus_error_busy(message);

	l_ecdh_generate_key_pair(dpp->curve, &dpp->proto_private,
					&dpp->own_proto_public);

	dpp->state = DPP_STATE_PRESENCE;

	if (!responder) {
		if (!l_dbus_message_get_arguments(message, "s", &uri))
			return dbus_error_invalid_args(message);

		if (!dpp_configurator_start_presence(dpp, uri))
			return dbus_error_invalid_args(message);

		/* Since we have the peer's URI generate the keys now */
		l_getrandom(dpp->i_nonce, dpp->nonce_len);

		dpp->m = dpp_derive_k1(dpp->peer_boot_public,
					dpp->proto_private, dpp->k1);

		if (!dpp->mcast_support)
			dpp->state = DPP_STATE_AUTHENTICATING;

		dpp->new_freq = bss->frequency;
	} else
		dpp->current_freq = bss->frequency;

	dpp->uri = dpp_generate_uri(dpp->own_asn1, dpp->own_asn1_len, 2,
					netdev_get_address(dpp->netdev),
					&bss->frequency, 1, NULL, NULL);
	dpp->role = DPP_CAPABILITY_CONFIGURATOR;
	dpp->config = dpp_configuration_new(settings,
						network_get_ssid(network),
						hs->akm_suite);

	dpp_property_changed_notify(dpp);

	l_debug("DPP Start Configurator: %s", dpp->uri);

	reply = l_dbus_message_new_method_return(message);

	l_dbus_message_set_arguments(reply, "s", dpp->uri);

	return reply;
}

static struct l_dbus_message *dpp_dbus_start_configurator(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	return dpp_start_configurator_common(dbus, message, user_data, true);
}

static struct l_dbus_message *dpp_dbus_configure_enrollee(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	return dpp_start_configurator_common(dbus, message, user_data, false);
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
	l_dbus_interface_method(interface, "StartConfigurator", 0,
				dpp_dbus_start_configurator, "s", "", "uri");
	l_dbus_interface_method(interface, "ConfigureEnrollee", 0,
				dpp_dbus_configure_enrollee, "", "s", "uri");
	l_dbus_interface_method(interface, "Stop", 0,
				dpp_dbus_stop, "", "");

	l_dbus_interface_property(interface, "Started", 0, "b", dpp_get_started,
					NULL);
	l_dbus_interface_property(interface, "Role", 0, "s", dpp_get_role,
					NULL);
	l_dbus_interface_property(interface, "URI", 0, "s", dpp_get_uri, NULL);
}

static void dpp_destroy_interface(void *user_data)
{
	struct dpp_sm *dpp = user_data;

	l_queue_remove(dpp_list, dpp);

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

	mlme_watch = l_genl_family_register(nl80211, "mlme", dpp_mlme_notify,
						NULL, NULL);

	unicast_watch = l_genl_add_unicast_watch(iwd_get_genl(),
						NL80211_GENL_NAME,
						dpp_unicast_notify,
						NULL, NULL);

	dpp_list = l_queue_new();

	return 0;
}

static void dpp_exit(void)
{
	l_debug("");

	l_dbus_unregister_interface(dbus_get_bus(), IWD_DPP_INTERFACE);

	netdev_watch_remove(netdev_watch);

	l_genl_remove_unicast_watch(iwd_get_genl(), unicast_watch);

	l_genl_family_unregister(nl80211, mlme_watch);
	mlme_watch = 0;

	l_genl_family_free(nl80211);
	nl80211 = NULL;

	l_queue_destroy(dpp_list, (l_queue_destroy_func_t) dpp_free);
}

IWD_MODULE(dpp, dpp_init, dpp_exit);
IWD_MODULE_DEPENDS(dpp, netdev);
