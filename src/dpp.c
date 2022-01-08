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

static uint32_t netdev_watch;
static struct l_genl_family *nl80211;
static uint8_t broadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

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

	uint8_t auth_addr[6];
	uint8_t r_nonce[32];
	uint8_t i_nonce[32];
	uint8_t e_nonce[32];

	uint64_t ke[L_ECC_MAX_DIGITS];
	uint64_t k2[L_ECC_MAX_DIGITS];

	struct l_ecc_scalar *proto_private;
	struct l_ecc_point *proto_public;

	struct l_ecc_point *i_proto_public;

	uint8_t diag_token;

	/* Timeout of either auth/config protocol */
	struct l_timeout *timeout;

	struct dpp_configuration *config;
	uint32_t connect_scan_id;
};

static void dpp_free_auth_data(struct dpp_sm *dpp)
{
	if (dpp->proto_public) {
		l_ecc_point_free(dpp->proto_public);
		dpp->proto_public = NULL;
	}

	if (dpp->proto_private) {
		l_ecc_scalar_free(dpp->proto_private);
		dpp->proto_private = NULL;
	}

	if (dpp->i_proto_public) {
		l_ecc_point_free(dpp->i_proto_public);
		dpp->i_proto_public = NULL;
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

	dpp->state = DPP_STATE_NOTHING;

	explicit_bzero(dpp->r_nonce, dpp->nonce_len);
	explicit_bzero(dpp->i_nonce, dpp->nonce_len);
	explicit_bzero(dpp->e_nonce, dpp->nonce_len);
	explicit_bzero(dpp->ke, dpp->key_len);
	explicit_bzero(dpp->k2, dpp->key_len);

	dpp_free_auth_data(dpp);
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

	if (!l_genl_family_send(nl80211, msg, dpp_send_frame_cb, NULL, NULL)) {
		l_error("Could not send CMD_FRAME");
		l_genl_msg_unref(msg);
	}
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

static void dpp_reset_protocol_timer(struct dpp_sm *dpp)
{
	if (dpp->timeout)
		l_timeout_modify(dpp->timeout, 10);
	else
		dpp->timeout = l_timeout_create(10, dpp_protocol_timeout,
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

	dpp_send_frame(dpp->wdev_id, iov, 2, dpp->current_freq);
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
			DPP_ATTR_STATUS, 1, &zero,
			DPP_ATTR_ENROLLEE_NONCE, dpp->nonce_len, dpp->e_nonce);

	iov[1].iov_base = attrs;
	iov[1].iov_len = ptr - attrs;

	dpp_send_frame(dpp->wdev_id, iov, 2, dpp->current_freq);
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
	struct network *network;
	struct scan_bss *bss = NULL;
	char ssid[33];

	if (dpp->state != DPP_STATE_CONFIGURING)
		return;

	/*
	 * Can a configuration request come from someone other than who you
	 * authenticated to?
	 */
	if (memcmp(dpp->auth_addr, frame->address_2, 6))
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

	memcpy(ssid, config->ssid, config->ssid_len);
	ssid[config->ssid_len] = '\0';

	network = station_network_find(station, ssid, SECURITY_PSK);
	if (network)
		bss = network_bss_select(network, true);

	dpp_write_config(config, network);

	if (network && bss)
		__station_connect_network(station, network, bss);
	else {
		dpp->connect_scan_id = scan_active(dpp->wdev_id, NULL, 0,
						dpp_scan_triggered,
						dpp_scan_results, dpp,
						dpp_scan_destroy);
		if (!dpp->connect_scan_id)
			goto scan_failed;
	}

	dpp_configuration_free(config);

	send_config_result(dpp, dpp->auth_addr);

scan_failed:
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
	memcpy(hdr + 4, dpp->auth_addr, 6);
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

	dpp_send_frame(dpp->wdev_id, iov, 2, dpp->current_freq);
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

	if (memcmp(dpp->auth_addr, frame->address_2, 6)) {
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
static void send_authenticate_response(struct dpp_sm *dpp, void *r_auth)
{
	uint8_t hdr[32];
	uint8_t attrs[256];
	uint8_t *ptr = attrs;
	uint8_t status = DPP_STATUS_OK;
	uint64_t r_proto_key[L_ECC_MAX_DIGITS * 2];
	uint8_t version = 2;
	struct iovec iov[3];
	uint8_t wrapped2_plaintext[dpp->key_len + 4];
	uint8_t wrapped2[dpp->key_len + 16 + 8];
	size_t wrapped2_len;

	l_ecc_point_get_data(dpp->proto_public, r_proto_key,
				sizeof(r_proto_key));

	iov[0].iov_len = dpp_build_header(netdev_get_address(dpp->netdev),
				dpp->auth_addr,
				DPP_FRAME_AUTHENTICATION_RESPONSE, hdr);
	iov[0].iov_base = hdr;

	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &status, 1);
	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH,
				dpp->pub_boot_hash, 32);
	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_PROTOCOL_KEY,
				r_proto_key, dpp->key_len * 2);
	ptr += dpp_append_attr(ptr, DPP_ATTR_PROTOCOL_VERSION, &version, 1);

	/* Wrap up secondary data (R-Auth) */
	wrapped2_len = dpp_append_attr(wrapped2_plaintext,
					DPP_ATTR_RESPONDER_AUTH_TAG,
					r_auth, dpp->key_len);
	/*
	 * "Invocations of AES-SIV in the DPP Authentication protocol that
	 * produce ciphertext that is part of an additional AES-SIV invocation
	 * do not use AAD; in other words, the number of AAD components is set
	 * to zero.""
	 */
	aes_siv_encrypt(dpp->ke, dpp->key_len, wrapped2_plaintext,
					dpp->key_len + 4, NULL, 0, wrapped2);

	wrapped2_len += 16;

	ptr += dpp_append_wrapped_data(hdr + 26, 6, attrs, ptr - attrs,
			ptr, sizeof(attrs), dpp->k2, dpp->key_len, 4,
			DPP_ATTR_RESPONDER_NONCE, dpp->nonce_len, dpp->r_nonce,
			DPP_ATTR_INITIATOR_NONCE, dpp->nonce_len, dpp->i_nonce,
			DPP_ATTR_RESPONDER_CAPABILITIES, 1, &dpp->role,
			DPP_ATTR_WRAPPED_DATA, wrapped2_len, wrapped2);

	iov[1].iov_base = attrs;
	iov[1].iov_len = ptr - attrs;

	dpp_send_frame(netdev_get_wdev_id(dpp->netdev), iov, 2,
				dpp->current_freq);
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

	if (dpp->state != DPP_STATE_AUTHENTICATING)
		return;

	if (memcmp(from, dpp->auth_addr, 6))
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

	dpp_derive_i_auth(dpp->r_nonce, dpp->i_nonce, dpp->nonce_len,
				dpp->proto_public, dpp->i_proto_public,
				dpp->boot_public, i_auth_check);

	if (memcmp(i_auth, i_auth_check, i_auth_len)) {
		l_error("I-Auth did not verify");
		goto auth_confirm_failed;
	}

	l_debug("Authentication successful");

	dpp_reset_protocol_timer(dpp);

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
				dpp->auth_addr,
				DPP_FRAME_AUTHENTICATION_RESPONSE, hdr);
	iov[0].iov_base = hdr;

	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &s, 1);
	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH,
				dpp->pub_boot_hash, 32);

	ptr += dpp_append_attr(ptr, DPP_ATTR_PROTOCOL_VERSION, &version, 1);

	ptr += dpp_append_wrapped_data(hdr + 26, 6, attrs, ptr - attrs,
			ptr, sizeof(attrs) - (ptr - attrs), k1, dpp->key_len, 2,
			DPP_ATTR_INITIATOR_NONCE, dpp->nonce_len, dpp->i_nonce,
			DPP_ATTR_RESPONDER_CAPABILITIES, 1, &dpp->role);

	iov[1].iov_base = attrs;
	iov[1].iov_len = ptr - attrs;

	dpp_send_frame(netdev_get_wdev_id(dpp->netdev), iov, 2,
				dpp->current_freq);
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
	uint64_t k1[L_ECC_MAX_DIGITS];
	uint64_t r_auth[L_ECC_MAX_DIGITS];
	const void *ad0 = body + 2;
	const void *ad1 = body + 8;

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
		/*
		 * TODO: Go on this channel for remainder of auth protocol.
		 *
		 * "the Responder determines whether it can use the requested
		 * channel for the following exchanges. If so, it sends the DPP
		 * Authentication Response frame on that channel. If not, it
		 * discards the DPP Authentication Request frame without
		 * replying to it."
		 *
		 * For the time being this feature is not being implemented and
		 * the frame will be dropped.
		 */
		case DPP_ATTR_CHANNEL:
			return;
		default:
			break;
		}
	}

	if (!r_boot || !i_boot || !i_proto || !wrapped)
		goto auth_request_failed;

	if (r_boot_len != 32 || memcmp(dpp->pub_boot_hash,
					r_boot, r_boot_len)) {
		l_debug("Responder boot key hash failed to verify");
		goto auth_request_failed;
	}

	dpp->i_proto_public = l_ecc_point_from_data(dpp->curve,
						L_ECC_POINT_TYPE_FULL,
						i_proto, i_proto_len);
	if (!dpp->i_proto_public) {
		l_debug("Initiators protocol key invalid");
		goto auth_request_failed;
	}

	m = dpp_derive_k1(dpp->i_proto_public, dpp->boot_private, k1);
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

	/* Derive keys k2, ke, and R-Auth for authentication response */

	l_ecdh_generate_key_pair(dpp->curve, &dpp->proto_private,
					&dpp->proto_public);

	n = dpp_derive_k2(dpp->i_proto_public, dpp->proto_private, dpp->k2);
	if (!n)
		goto auth_request_failed;

	l_getrandom(dpp->r_nonce, dpp->nonce_len);

	if (!dpp_derive_ke(dpp->i_nonce, dpp->r_nonce, m, n, dpp->ke))
		goto auth_request_failed;

	if (!dpp_derive_r_auth(dpp->i_nonce, dpp->r_nonce, dpp->nonce_len,
				dpp->i_proto_public, dpp->proto_public,
				dpp->boot_public, r_auth))
		goto auth_request_failed;

	memcpy(dpp->auth_addr, from, 6);

	dpp->state = DPP_STATE_AUTHENTICATING;
	dpp_reset_protocol_timer(dpp);

	send_authenticate_response(dpp, r_auth);

	return;

auth_request_failed:
	dpp->state = DPP_STATE_PRESENCE;
	dpp_free_auth_data(dpp);
}

static void dpp_handle_frame(const struct mmpdu_header *frame,
				const void *body, size_t body_len,
				int rssi, void *user_data)
{
	struct dpp_sm *dpp = user_data;
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
	case DPP_FRAME_AUTHENTICATION_CONFIRM:
		authenticate_confirm(dpp, frame->address_2, body, body_len);
		break;
	case DPP_FRAME_CONFIGURATION_RESULT:
		dpp_handle_config_result_frame(dpp, frame->address_2,
						body, body_len);
		break;
	default:
		l_debug("Unhandled DPP frame %u", *ptr);
		break;
	}
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

	/*
	 * If not in presence procedure or in a configurator role, just stay
	 * on channel.
	 */
	if (dpp->state != DPP_STATE_PRESENCE ||
			dpp->role == DPP_CAPABILITY_CONFIGURATOR)
		return;

	dpp_presence_announce(dpp);
}

static void dpp_create(struct netdev *netdev)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct dpp_sm *dpp = l_new(struct dpp_sm, 1);
	uint8_t dpp_prefix[] = { 0x04, 0x09, 0x50, 0x6f, 0x9a, 0x1a, 0x01 };
	uint8_t dpp_conf_response_prefix[] = { 0x04, 0x0b };
	uint8_t dpp_conf_request_prefix[] = { 0x04, 0x0a };

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

	frame_watch_add(netdev_get_wdev_id(netdev), 0, 0x00d0, dpp_prefix,
				sizeof(dpp_prefix), dpp_handle_frame,
				dpp, NULL);
	frame_watch_add(netdev_get_wdev_id(netdev), 0, 0x00d0,
				dpp_conf_response_prefix,
				sizeof(dpp_conf_response_prefix),
				dpp_handle_config_response_frame, dpp, NULL);
	frame_watch_add(netdev_get_wdev_id(netdev), 0, 0x00d0,
				dpp_conf_request_prefix,
				sizeof(dpp_conf_request_prefix),
				dpp_handle_config_request_frame, dpp, NULL);
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
		l_debug("Max retries on presence announcements");
		dpp->freqs_idx = 0;
	}

	dpp->current_freq = dpp->freqs[dpp->freqs_idx];

	l_debug("Presence timeout, moving to next frequency %u, duration %u",
			dpp->current_freq, dpp->dwell);

next_roc:
	dpp->offchannel_id = offchannel_start(netdev_get_wdev_id(dpp->netdev),
			dpp->current_freq, dpp->dwell, dpp_roc_started,
			dpp, dpp_presence_timeout);
	return;

protocol_failed:
	dpp_reset(dpp);
	return;
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
	dpp->role = DPP_CAPABILITY_ENROLLEE;

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

static struct l_dbus_message *dpp_dbus_start_configurator(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct dpp_sm *dpp = user_data;
	struct l_dbus_message *reply;
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));
	struct scan_bss *bss;
	struct network *network;
	struct l_settings *settings;
	struct handshake_state *hs = netdev_get_handshake(dpp->netdev);

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

	dpp->uri = dpp_generate_uri(dpp->pub_asn1, dpp->pub_asn1_len, 2,
					netdev_get_address(dpp->netdev),
					&bss->frequency, 1, NULL, NULL);

	dpp->state = DPP_STATE_PRESENCE;
	dpp->role = DPP_CAPABILITY_CONFIGURATOR;
	dpp->current_freq = bss->frequency;
	dpp->config = dpp_configuration_new(settings,
						network_get_ssid(network),
						hs->akm_suite);

	l_debug("DPP Start Configurator: %s", dpp->uri);

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
	l_dbus_interface_method(interface, "StartConfigurator", 0,
				dpp_dbus_start_configurator, "s", "", "uri");
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
