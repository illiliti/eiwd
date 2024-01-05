/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2015-2019  Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <ell/ell.h>

#include "ell/useful.h"
#include "src/missing.h"
#include "src/module.h"
#include "src/dbus.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/station.h"
#include "src/scan.h"
#include "src/ie.h"
#include "src/wscutil.h"
#include "src/util.h"
#include "src/handshake.h"
#include "src/eap-wsc.h"
#include "src/common.h"
#include "src/storage.h"
#include "src/iwd.h"
#include "src/network.h"
#include "src/wsc.h"
#include "src/band.h"

#define WALK_TIME 120

static uint32_t netdev_watch = 0;

struct wsc_enrollee {
	struct netdev *netdev;
	struct wsc_credentials_info creds[3];
	uint32_t n_creds;
	struct l_settings *eap_settings;
	wsc_done_cb_t done_cb;
	void *done_data;
	bool disconnecting : 1;
};

static struct l_dbus_message *wsc_error_session_overlap(
						struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg,
					IWD_WSC_INTERFACE ".SessionOverlap",
					"Multiple sessions detected");
}

static struct l_dbus_message *wsc_error_no_credentials(
						struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_WSC_INTERFACE ".NoCredentials",
					"No usable credentials obtained");
}

static struct l_dbus_message *wsc_error_not_reachable(
						struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_WSC_INTERFACE ".NotReachable",
					"Credentials obtained, but network is "
					"unreachable");
}

static struct l_dbus_message *wsc_error_walk_time_expired(
						struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg,
					IWD_WSC_INTERFACE ".WalkTimeExpired",
					"No APs in PushButton mode found in "
					"the allotted time");
}

static struct l_dbus_message *wsc_error_time_expired(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg,
					IWD_WSC_INTERFACE ".TimeExpired",
					"No APs in PIN mode found in "
					"the allotted time");
}

static void wsc_enrollee_connect_cb(struct netdev *netdev,
					enum netdev_result result,
					void *event_data, void *user_data)
{
	struct wsc_enrollee *wsce = user_data;

	l_debug("%d, result: %d", netdev_get_ifindex(wsce->netdev), result);

	if (wsce->disconnecting)
		return;	/* Free the state in the disconnect callback */

	if (!wsce->done_cb)
		goto done;

	if (result == NETDEV_RESULT_HANDSHAKE_FAILED && wsce->n_creds > 0) {
		wsce->done_cb(0, wsce->creds, wsce->n_creds, wsce->done_data);
		goto done;
	}

	switch (result) {
	case NETDEV_RESULT_ABORTED:
		wsce->done_cb(-ECANCELED, NULL, 0, wsce->done_data);
		break;
	case NETDEV_RESULT_HANDSHAKE_FAILED:
		wsce->done_cb(-ENOKEY, NULL, 0, wsce->done_data);
		break;
	default:
		wsce->done_cb(-EIO, NULL, 0, wsce->done_data);
		break;
	}

done:
	wsc_enrollee_free(wsce);
}

static void wsc_enrollee_credential_obtained(struct wsc_enrollee *wsce,
					const struct wsc_credential *cred)
{
	uint16_t auth_mask;
	unsigned int i;

	l_debug("Obtained credenials for SSID: %s, address: %s",
			util_ssid_to_utf8(cred->ssid_len, cred->ssid),
			util_address_to_string(cred->addr));

	l_debug("auth_type: %02x, encryption_type: %02x",
			cred->auth_type, cred->encryption_type);

	if (getenv("IWD_WSC_DEBUG_KEYS"))
		l_debug("Key (%u): %.*s", cred->network_key_len,
				cred->network_key_len, cred->network_key);

	if (wsce->n_creds == L_ARRAY_SIZE(wsce->creds)) {
		l_warn("Maximum number of credentials obtained, ignoring...");
		return;
	}

	if (!util_ssid_is_utf8(cred->ssid_len, cred->ssid)) {
		l_warn("Ignoring Credentials with non-UTF8 SSID");
		return;
	}

	memcpy(wsce->creds[wsce->n_creds].ssid, cred->ssid, cred->ssid_len);
	wsce->creds[wsce->n_creds].ssid[cred->ssid_len] = '\0';

	/* We only support open/personal wpa/personal wpa2 */
	auth_mask = WSC_AUTHENTICATION_TYPE_OPEN |
			WSC_AUTHENTICATION_TYPE_WPA_PERSONAL |
			WSC_AUTHENTICATION_TYPE_WPA2_PERSONAL;
	if ((cred->auth_type & auth_mask) == 0) {
		l_warn("Ignoring Credentials with unsupported auth_type");
		return;
	}

	if (cred->auth_type & WSC_AUTHENTICATION_TYPE_OPEN) {
		auth_mask &= ~WSC_AUTHENTICATION_TYPE_OPEN;

		if (cred->auth_type & auth_mask) {
			l_warn("Ignoring mixed open/wpa credentials");
			return;
		}

		wsce->creds[wsce->n_creds].security = SECURITY_NONE;
	} else
		wsce->creds[wsce->n_creds].security = SECURITY_PSK;

	switch (wsce->creds[wsce->n_creds].security) {
	case SECURITY_NONE:
		if (cred->network_key_len != 0) {
			l_warn("ignoring invalid open key length");
			return;
		}

		break;
	case SECURITY_PSK:
		if (cred->network_key_len == 64) {
			unsigned char *decoded;
			const char *hex = (const char *) cred->network_key;

			decoded = l_util_from_hexstring(hex, NULL);
			if (!decoded) {
				l_warn("Ignoring non-hex network_key");
				return;
			}

			memcpy(wsce->creds[wsce->n_creds].psk, decoded, 32);
			explicit_bzero(decoded, 32);
			l_free(decoded);
		} else {
			strncpy(wsce->creds[wsce->n_creds].passphrase,
					(const char *) cred->network_key,
					cred->network_key_len);
			wsce->creds[wsce->n_creds].has_passphrase = true;
		}

		break;
	default:
		return;
	}

	for (i = 0; i < wsce->n_creds; i++) {
		if (strcmp(wsce->creds[i].ssid,
				wsce->creds[wsce->n_creds].ssid))
			continue;

		l_warn("Found duplicate credentials for SSID: %s",
				wsce->creds[i].ssid);
		explicit_bzero(&wsce->creds[wsce->n_creds],
				sizeof(wsce->creds[wsce->n_creds]));
		return;
	}

	memcpy(wsce->creds[wsce->n_creds].addr, cred->addr, 6);
	wsce->n_creds += 1;
}

static void wsc_enrollee_netdev_event(struct netdev *netdev,
					enum netdev_event event,
					void *event_data, void *user_data)
{
	struct wsc_enrollee *wsce = user_data;

	switch (event) {
	case NETDEV_EVENT_AUTHENTICATING:
	case NETDEV_EVENT_ASSOCIATING:
		break;
	case NETDEV_EVENT_DISCONNECT_BY_AP:
		l_debug("Disconnect by AP");
		wsc_enrollee_connect_cb(wsce->netdev,
					NETDEV_RESULT_HANDSHAKE_FAILED,
					event_data, wsce);
		break;
	case NETDEV_EVENT_RSSI_THRESHOLD_LOW:
	case NETDEV_EVENT_RSSI_THRESHOLD_HIGH:
		break;
	default:
		l_debug("Unexpected event: %d", event);
		break;
	}
}

static void wsc_enrollee_handshake_event(struct handshake_state *hs,
						enum handshake_event event,
						void *user_data, ...)
{
	struct wsc_enrollee *wsce = user_data;
	va_list args;

	va_start(args, user_data);

	switch (event) {
	case HANDSHAKE_EVENT_FAILED:
		netdev_handshake_failed(hs, va_arg(args, int));
		break;
	case HANDSHAKE_EVENT_EAP_NOTIFY:
	{
		unsigned int eap_event = va_arg(args, unsigned int);

		switch (eap_event) {
		case EAP_WSC_EVENT_CREDENTIAL_OBTAINED:
			wsc_enrollee_credential_obtained(wsce,
				va_arg(args, const struct wsc_credential *));
			break;
		default:
			l_debug("Got event: %d", eap_event);
		}

		break;
	}
	default:
		break;
	}

	va_end(args);
}

static inline enum wsc_rf_band freq_to_rf_band(uint32_t freq)
{
	enum band_freq band;

	band_freq_to_channel(freq, &band);

	switch (band) {
	case BAND_FREQ_2_4_GHZ:
		return WSC_RF_BAND_2_4_GHZ;
	case BAND_FREQ_5_GHZ:
	case BAND_FREQ_6_GHZ:
		return WSC_RF_BAND_5_0_GHZ;
	}

	return WSC_RF_BAND_2_4_GHZ;
}

static int wsc_enrollee_connect(struct wsc_enrollee *wsce, struct scan_bss *bss,
					const char *pin, struct iovec *ies,
					unsigned int ies_num)
{
	struct handshake_state *hs;
	struct l_settings *settings = l_settings_new();
	int r;
	struct wsc_association_request request;
	uint8_t *pdu;
	size_t pdu_len;
	struct iovec ie_iov[1 + ies_num];

	hs = netdev_handshake_state_new(wsce->netdev);

	l_settings_set_string(settings, "Security", "EAP-Identity",
					"WFA-SimpleConfig-Enrollee-1-0");
	l_settings_set_string(settings, "Security", "EAP-Method", "WSC");

	l_settings_set_uint(settings, "WSC", "RFBand",
					freq_to_rf_band(bss->frequency));
	l_settings_set_uint(settings, "WSC", "ConfigurationMethods",
				WSC_CONFIGURATION_METHOD_VIRTUAL_DISPLAY_PIN |
				WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON |
				WSC_CONFIGURATION_METHOD_KEYPAD);
	l_settings_set_string(settings, "WSC", "PrimaryDeviceType",
					"0-00000000-0");
	l_settings_set_string(settings, "WSC", "EnrolleeMAC",
		util_address_to_string(netdev_get_address(wsce->netdev)));

	if (pin) {
		enum wsc_device_password_id dpid;

		if (strlen(pin) == 4 || wsc_pin_is_checksum_valid(pin))
			dpid = WSC_DEVICE_PASSWORD_ID_DEFAULT;
		else
			dpid = WSC_DEVICE_PASSWORD_ID_USER_SPECIFIED;

		l_settings_set_uint(settings, "WSC", "DevicePasswordId", dpid);
		l_settings_set_string(settings, "WSC", "DevicePassword", pin);
	}

	handshake_state_set_event_func(hs, wsc_enrollee_handshake_event, wsce);
	handshake_state_set_8021x_config(hs, settings);
	handshake_state_set_ssid(hs, bss->ssid, bss->ssid_len);
	wsce->eap_settings = settings;

	request.version2 = true;
	request.request_type = WSC_REQUEST_TYPE_ENROLLEE_OPEN_8021X;

	pdu = wsc_build_association_request(&request, &pdu_len);
	if (!pdu) {
		r = -ENOMEM;
		goto error;
	}

	ie_iov[0].iov_base = ie_tlv_encapsulate_wsc_payload(pdu, pdu_len,
							&ie_iov[0].iov_len);
	l_free(pdu);

	if (!ie_iov[0].iov_base) {
		r = -ENOMEM;
		goto error;
	}

	if (ies_num)
		memcpy(ie_iov + 1, ies, sizeof(struct iovec) * ies_num);

	handshake_state_set_vendor_ies(hs, ie_iov, 1 + ies_num);

	r = netdev_connect(wsce->netdev, bss, hs,
				wsc_enrollee_netdev_event,
				wsc_enrollee_connect_cb, wsce);
	l_free(ie_iov[0].iov_base);

	if (r == 0)
		return 0;

error:
	handshake_state_free(hs);
	return r;
}

struct wsc_enrollee *wsc_enrollee_new(struct netdev *netdev,
					struct scan_bss *target,
					const char *pin,
					struct iovec *ies, unsigned int ies_num,
					wsc_done_cb_t done_cb, void *user_data)
{
	struct wsc_enrollee *wsce;

	wsce = l_new(struct wsc_enrollee, 1);
	wsce->netdev = netdev;
	wsce->done_cb = done_cb;
	wsce->done_data = user_data;

	if (wsc_enrollee_connect(wsce, target, pin, ies, ies_num) == 0)
		return wsce;

	wsc_enrollee_free(wsce);
	return NULL;
}

static void wsc_enrollee_disconnect_cb(struct netdev *netdev, bool result,
					void *user_data)
{
	struct wsc_enrollee *wsce = user_data;

	wsce->done_cb(-ECANCELED, NULL, 0, wsce->done_data);
	wsc_enrollee_free(wsce);
}

void wsc_enrollee_cancel(struct wsc_enrollee *wsce, bool defer_cb)
{
	if (defer_cb) {
		wsce->disconnecting = true;
		netdev_disconnect(wsce->netdev, wsc_enrollee_disconnect_cb,
					wsce);
	} else {
		wsce->done_cb(-ECANCELED, NULL, 0, wsce->done_data);
		wsce->done_cb = NULL;
		/*
		 * Results in a call to
		 * wsc_enrollee_connect_cb -> wsc_enrollee_free
		 */
		netdev_disconnect(wsce->netdev, NULL, NULL);
	}
}

void wsc_enrollee_free(struct wsc_enrollee *wsce)
{
	l_settings_free(wsce->eap_settings);
	explicit_bzero(wsce->creds, sizeof(wsce->creds));
	l_free(wsce);
}

struct wsc_station_dbus {
	struct wsc_dbus super;
	struct wsc_enrollee *enrollee;
	struct scan_bss *target;
	struct netdev *netdev;
	struct station *station;
	uint8_t *wsc_ies;
	size_t wsc_ies_size;
	struct l_timeout *walk_timer;
	uint32_t scan_id;
	uint32_t station_state_watch;
};

#define CONNECT_REPLY(wsc, message)					\
	if ((wsc)->super.pending_connect)				\
		dbus_pending_reply(&(wsc)->super.pending_connect,	\
				message((wsc)->super.pending_connect))	\

#define CANCEL_REPLY(wsc, message)					\
	if ((wsc)->super.pending_cancel)				\
		dbus_pending_reply(&(wsc)->super.pending_cancel,	\
				message((wsc)->super.pending_cancel))	\

static void wsc_try_credentials(struct wsc_station_dbus *wsc,
				struct wsc_credentials_info *creds,
				unsigned int n_creds)
{
	unsigned int i;
	struct network *network;
	struct scan_bss *bss;

	for (i = 0; i < n_creds; i++) {
		network = station_network_find(wsc->station, creds[i].ssid,
						creds[i].security);
		if (!network)
			continue;

		bss = network_bss_find_by_addr(network, creds[i].addr);

		if (!bss)
			bss = network_bss_select(network, true);

		if (!bss)
			continue;

		if (creds[i].security == SECURITY_PSK) {
			bool ret;

			/*
			 * Prefer setting passphrase, this will work for both
			 * WPA2 and WPA3 since the PSK can always be generated
			 * if needed
			 */
			if (creds[i].has_passphrase)
				ret = network_set_passphrase(network,
							creds[i].passphrase);
			else
				ret = network_set_psk(network, creds[i].psk);

			if (!ret)
				continue;
		}

		station_connect_network(wsc->station, network, bss,
						wsc->super.pending_connect);
		l_dbus_message_unref(wsc->super.pending_connect);
		wsc->super.pending_connect = NULL;

		return;
	}

	CONNECT_REPLY(wsc, wsc_error_not_reachable);
	station_set_autoconnect(wsc->station, true);
}

static void wsc_store_credentials(struct wsc_credentials_info *creds,
					unsigned int n_creds)
{
	unsigned int i;

	/* We don't store any non-open/psk credentials */
	for (i = 0; i < n_creds; i++) {
		enum security security = creds[i].security;
		const char *ssid = creds[i].ssid;
		_auto_(l_settings_free) struct l_settings *settings =
							l_settings_new();
		_auto_(l_free) char *path =
				storage_get_network_file_path(security, ssid);

		if (l_settings_load_from_file(settings, path)) {
			/*
			 * Nothing to do,
			 * so don't overwrite any existing settings
			 */
			if (security == SECURITY_NONE)
				continue;

			/* Remove any existing Security keys */
			l_settings_remove_group(settings, "Security");
		}

		if (security == SECURITY_PSK) {
			if (creds[i].has_passphrase)
				l_settings_set_string(settings, "Security",
					"Passphrase", creds[i].passphrase);
			else
				l_settings_set_bytes(settings, "Security",
						"PreSharedKey", creds[i].psk,
						sizeof(creds[i].psk));
		}

		l_debug("Storing credential for '%s(%s)'", ssid,
						security_to_str(security));
		storage_network_sync(security, ssid, settings);
	}
}

static void wsc_dbus_done_cb(int err, struct wsc_credentials_info *creds,
				unsigned int n_creds, void *user_data)
{
	struct wsc_station_dbus *wsc = user_data;

	wsc->enrollee = NULL;
	wsc->target = NULL;

	l_debug("err=%i", err);

	if (err && wsc->station)
		station_set_autoconnect(wsc->station, true);

	switch (err) {
	case 0:
		break;
	case -ECANCELED:
		/* Send reply if we haven't already sent one e.g. in Cancel() */
		CONNECT_REPLY(wsc, dbus_error_aborted);
		CANCEL_REPLY(wsc, l_dbus_message_new_method_return);
		return;
	case -ENOKEY:
		CONNECT_REPLY(wsc, wsc_error_no_credentials);
		return;
	case -EBUSY:
		CONNECT_REPLY(wsc, dbus_error_busy);
		return;
	default:
		CONNECT_REPLY(wsc, dbus_error_failed);
		return;
	}

	wsc_store_credentials(creds, n_creds);
	wsc_try_credentials(wsc, creds, n_creds);
}

static void wsc_connect(struct wsc_station_dbus *wsc)
{
	const char *pin = NULL;

	if (!strcmp(l_dbus_message_get_member(wsc->super.pending_connect),
			"StartPin"))
		l_dbus_message_get_arguments(wsc->super.pending_connect, "s",
						&pin);

	wsc->enrollee = wsc_enrollee_new(wsc->netdev, wsc->target, pin, NULL, 0,
						wsc_dbus_done_cb, wsc);
	if (wsc->enrollee)
		return;

	wsc_dbus_done_cb(-EIO, NULL, 0, wsc);
}

static void station_state_watch(enum station_state state, void *userdata)
{
	struct wsc_station_dbus *wsc = userdata;

	if (state != STATION_STATE_DISCONNECTED)
		return;

	l_debug("%p", wsc);

	station_remove_state_watch(wsc->station, wsc->station_state_watch);
	wsc->station_state_watch = 0;

	wsc_connect(wsc);
}

static void wsc_check_can_connect(struct wsc_station_dbus *wsc,
					struct scan_bss *target)
{
	l_debug("%p", wsc);

	/*
	 * For now we assign the target pointer directly, since we should not
	 * be triggering any more scans while disconnecting / connecting
	 */
	wsc->target = target;
	station_set_autoconnect(wsc->station, false);

	switch (station_get_state(wsc->station)) {
	case STATION_STATE_DISCONNECTED:
		wsc_connect(wsc);
		return;
	case STATION_STATE_CONNECTING:
	case STATION_STATE_CONNECTING_AUTO:
	case STATION_STATE_CONNECTED:
	case STATION_STATE_NETCONFIG:
		if (station_disconnect(wsc->station) < 0)
			goto error;

		/* fall through */
	case STATION_STATE_DISCONNECTING:
		wsc->station_state_watch =
			station_add_state_watch(wsc->station,
						station_state_watch,
						wsc, NULL);
		return;
	case STATION_STATE_AUTOCONNECT_QUICK:
	case STATION_STATE_AUTOCONNECT_FULL:
	case STATION_STATE_ROAMING:
	case STATION_STATE_FT_ROAMING:
	case STATION_STATE_FW_ROAMING:
		l_warn("%s: invalid station state", __func__);
		break;
	}
error:
	wsc->target = NULL;
	CONNECT_REPLY(wsc, dbus_error_failed);
}

static void wsc_cancel_scan(struct wsc_station_dbus *wsc)
{
	l_free(wsc->wsc_ies);
	wsc->wsc_ies = 0;

	if (wsc->scan_id > 0) {
		scan_cancel(netdev_get_wdev_id(wsc->netdev), wsc->scan_id);
		wsc->scan_id = 0;
	}

	if (wsc->walk_timer) {
		l_timeout_remove(wsc->walk_timer);
		wsc->walk_timer = NULL;
	}
}

static void walk_timeout(struct l_timeout *timeout, void *user_data)
{
	struct wsc_station_dbus *wsc = user_data;

	wsc_cancel_scan(wsc);
	CONNECT_REPLY(wsc, wsc_error_walk_time_expired);
}

static void pin_timeout(struct l_timeout *timeout, void *user_data)
{
	struct wsc_station_dbus *wsc = user_data;

	wsc_cancel_scan(wsc);
	CONNECT_REPLY(wsc, wsc_error_time_expired);
}

static bool push_button_scan_results(int err, struct l_queue *bss_list,
					const struct scan_freq_set *freqs,
					void *userdata)
{
	struct wsc_station_dbus *wsc = userdata;
	struct scan_bss *bss_2g;
	struct scan_bss *bss_5g;
	struct scan_bss *target;
	uint8_t uuid_2g[16];
	uint8_t uuid_5g[16];
	const struct l_queue_entry *bss_entry;
	struct wsc_probe_response probe_response;

	if (err) {
		wsc_cancel_scan(wsc);
		CONNECT_REPLY(wsc, dbus_error_failed);

		return false;
	}

	bss_2g = NULL;
	bss_5g = NULL;

	wsc->scan_id = 0;

	for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
				bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;
		enum band_freq band;
		int err;

		l_debug("bss '%s' with SSID: %s, freq: %u",
			util_address_to_string(bss->addr),
			util_ssid_to_utf8(bss->ssid_len, bss->ssid),
			bss->frequency);

		l_debug("bss->wsc: %p, %zu", bss->wsc, bss->wsc_size);

		if (!bss->wsc)
			continue;

		err = wsc_parse_probe_response(bss->wsc, bss->wsc_size,
						&probe_response);
		if (err < 0) {
			l_debug("ProbeResponse parse failed: %s",
							strerror(-err));
			continue;
		}

		l_debug("SelectedRegistar: %s",
			probe_response.selected_registrar ? "true" : "false");

		if (!probe_response.selected_registrar)
			continue;

		if (probe_response.device_password_id !=
				WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON)
			continue;

		band_freq_to_channel(bss->frequency, &band);

		switch (band) {
		case BAND_FREQ_2_4_GHZ:
			if (bss_2g) {
				l_debug("2G Session overlap error");
				goto session_overlap;
			}

			bss_2g = bss;
			memcpy(uuid_2g, probe_response.uuid_e, 16);
			break;

		case BAND_FREQ_5_GHZ:
			if (bss_5g) {
				l_debug("5G Session overlap error");
				goto session_overlap;
			}

			bss_5g = bss;
			memcpy(uuid_5g, probe_response.uuid_e, 16);
			break;

		default:
			return false;
		}
	}

	if (bss_2g && bss_5g && memcmp(uuid_2g, uuid_5g, 16)) {
		l_debug("Found two PBC APs on different bands");
		goto session_overlap;
	}

	if (bss_5g)
		target = bss_5g;
	else if (bss_2g)
		target = bss_2g;
	else {
		l_debug("No PBC APs found, running the scan again");
		wsc->scan_id = scan_active(netdev_get_wdev_id(wsc->netdev),
						wsc->wsc_ies, wsc->wsc_ies_size,
						NULL, push_button_scan_results,
						wsc, NULL);
		return false;
	}

	wsc_cancel_scan(wsc);
	station_set_scan_results(wsc->station, bss_list, freqs, false);

	l_debug("Found AP to connect to: %s",
			util_address_to_string(target->addr));
	wsc_check_can_connect(wsc, target);

	return true;

session_overlap:
	wsc_cancel_scan(wsc);
	CONNECT_REPLY(wsc, wsc_error_session_overlap);

	return false;
}

static const char *authorized_macs_to_string(const uint8_t *authorized_macs)
{
	unsigned int i;
	unsigned int offset = 0;
	/* Max of 5 addresses in AuthorizedMacs, 17 bytes / address */
	static char buf[128];

	for (i = 0; i < 5; i++) {
		const uint8_t *addr = authorized_macs + i * 6;

		if (l_memeqzero(addr, 6))
			continue;

		offset += sprintf(buf + offset, "%s",
						util_address_to_string(addr));
	}

	return buf;
}

static bool authorized_macs_contains(const uint8_t *authorized_macs,
							const uint8_t *target)
{
	unsigned int i;

	for (i = 0; i < 5; i++) {
		const uint8_t *addr = authorized_macs + i * 6;

		if (!memcmp(addr, target, 6))
			return true;
	}

	return false;
}

static bool pin_scan_results(int err, struct l_queue *bss_list,
				const struct scan_freq_set *freqs,
				void *userdata)
{
	static const uint8_t wildcard_address[] =
					{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	struct wsc_station_dbus *wsc = userdata;
	struct scan_bss *target = NULL;
	const struct l_queue_entry *bss_entry;
	struct wsc_probe_response probe_response;

	if (err) {
		wsc_cancel_scan(wsc);
		CONNECT_REPLY(wsc, dbus_error_failed);

		return false;
	}

	wsc->scan_id = 0;

	for (bss_entry = l_queue_get_entries(bss_list); bss_entry;
				bss_entry = bss_entry->next) {
		struct scan_bss *bss = bss_entry->data;
		const uint8_t *amacs;
		int err;

		l_debug("bss '%s' with SSID: %s, freq: %u",
			util_address_to_string(bss->addr),
			util_ssid_to_utf8(bss->ssid_len, bss->ssid),
			bss->frequency);

		l_debug("bss->wsc: %p, %zu", bss->wsc, bss->wsc_size);

		if (!bss->wsc)
			continue;

		err = wsc_parse_probe_response(bss->wsc, bss->wsc_size,
						&probe_response);
		if (err < 0) {
			l_debug("ProbeResponse parse failed: %s",
							strerror(-err));
			continue;
		}

		if (probe_response.device_password_id !=
					WSC_DEVICE_PASSWORD_ID_DEFAULT &&
				probe_response.device_password_id !=
					WSC_DEVICE_PASSWORD_ID_USER_SPECIFIED)
			continue;

		l_debug("SelectedRegistar: %s",
			probe_response.selected_registrar ? "true" : "false");

		/*
		 * WSC Best Practices v2.0.1, Section 3.4:
		 * In a mixed environment with both WSC 1.0 and WSC 2.0 APs, an
		 * Enrollee should be prepared to run both the WSC 1.0 and
		 * WSC 2.0 forms of discovery. An Enrollee may scan available
		 * channels and then order PIN attempts with prospective APs
		 * as follows:
		 * 1. WSC 2.0 AP with the Selected Registrar attribute TRUE
		 * and the Enrollee's MAC address in the AuthorizedMACs
		 * sub-element in Beacons and Probe Responses.
		 * 2. WSC 2.0 APs with the Selected Registrar attribute TRUE
		 * and the wildcard MAC address in the AuthorizedMACs
		 * sub-element in Beacons and Probe Responses, ordered by
		 * decreasing RSSI.
		 * 3. WSC 1.0 APs, ordered by decreasing RSSI.
		 * If option 1 is available, options 2 and 3 should be
		 * unnecessary.
		 */
		if (!probe_response.selected_registrar)
			continue;

		amacs = probe_response.authorized_macs;
		l_debug("AuthorizedMacs: %s", authorized_macs_to_string(amacs));

		if (authorized_macs_contains(amacs,
					netdev_get_address(wsc->netdev))) {
			target = bss;
			break;
		} else if (!target && authorized_macs_contains(amacs,
							wildcard_address))
			target = bss;
	}

	if (!target) {
		l_debug("No PIN APs found, running the scan again");
		wsc->scan_id = scan_active(netdev_get_wdev_id(wsc->netdev),
						wsc->wsc_ies, wsc->wsc_ies_size,
						NULL, pin_scan_results,
						wsc, NULL);
		return false;
	}

	wsc_cancel_scan(wsc);
	station_set_scan_results(wsc->station, bss_list, freqs, false);

	l_debug("Found AP to connect to: %s",
			util_address_to_string(target->addr));
	wsc_check_can_connect(wsc, target);

	return true;
}

static bool wsc_initiate_scan(struct wsc_station_dbus *wsc,
					enum wsc_device_password_id dpid,
					scan_notify_func_t callback)
{
	static const uint8_t wfa_oui[] = { 0x00, 0x50, 0xF2 };
	struct wsc_probe_request req;
	struct wiphy *wiphy = netdev_get_wiphy(wsc->netdev);
	uint32_t bands;
	uint8_t *wsc_data;
	size_t wsc_data_size;

	memset(&req, 0, sizeof(req));

	req.version2 = true;
	req.request_type = WSC_REQUEST_TYPE_ENROLLEE_INFO;

	/* TODO: Grab from configuration file ? */
	req.config_methods = WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON |
				WSC_CONFIGURATION_METHOD_KEYPAD;

	if (!wsc_uuid_from_addr(netdev_get_address(wsc->netdev), req.uuid_e))
		return false;

	/* TODO: Grab from configuration file ? */
	req.primary_device_type.category = 255;
	memcpy(req.primary_device_type.oui, wfa_oui, 3);
	req.primary_device_type.oui_type = 0x04;
	req.primary_device_type.subcategory = 0;

	bands = wiphy_get_supported_bands(wiphy);
	if (bands & BAND_FREQ_2_4_GHZ)
		req.rf_bands |= WSC_RF_BAND_2_4_GHZ;
	if (bands & BAND_FREQ_5_GHZ)
		req.rf_bands |= WSC_RF_BAND_5_0_GHZ;

	req.association_state = WSC_ASSOCIATION_STATE_NOT_ASSOCIATED;
	req.configuration_error = WSC_CONFIGURATION_ERROR_NO_ERROR;
	req.device_password_id = dpid;
	req.request_to_enroll = true;

	wsc_data = wsc_build_probe_request(&req, &wsc_data_size);
	if (!wsc_data)
		return false;

	wsc->wsc_ies = ie_tlv_encapsulate_wsc_payload(wsc_data, wsc_data_size,
							&wsc->wsc_ies_size);
	l_free(wsc_data);

	if (!wsc->wsc_ies)
		return false;

	wsc->scan_id = scan_active(netdev_get_wdev_id(wsc->netdev),
					wsc->wsc_ies, wsc->wsc_ies_size,
					NULL, callback, wsc, NULL);
	if (!wsc->scan_id) {
		l_free(wsc->wsc_ies);
		wsc->wsc_ies = NULL;

		return false;
	}

	return true;
}

static const char *wsc_station_dbus_get_path(struct wsc_dbus *super)
{
	struct wsc_station_dbus *wsc =
		l_container_of(super, struct wsc_station_dbus, super);

	return netdev_get_path(wsc->netdev);
}

static void wsc_station_dbus_connect(struct wsc_dbus *super,
						const char *pin)
{
	struct wsc_station_dbus *wsc =
		l_container_of(super, struct wsc_station_dbus, super);
	scan_notify_func_t scan_callback;
	enum wsc_device_password_id dpid;

	wsc->station = station_find(netdev_get_ifindex(wsc->netdev));
	if (!wsc->station) {
		CONNECT_REPLY(wsc, dbus_error_not_available);
		return;
	}

	if (pin) {
		if (strlen(pin) == 4 || wsc_pin_is_checksum_valid(pin))
			dpid = WSC_DEVICE_PASSWORD_ID_DEFAULT;
		else
			dpid = WSC_DEVICE_PASSWORD_ID_USER_SPECIFIED;

		scan_callback = pin_scan_results;
	} else {
		dpid = WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON;
		scan_callback = push_button_scan_results;
	}

	if (!wsc_initiate_scan(wsc, dpid, scan_callback)) {
		CONNECT_REPLY(wsc, dbus_error_failed);
		return;
	}

	if (pin) {
		wsc->walk_timer = l_timeout_create(60, pin_timeout, wsc, NULL);
	} else {
		wsc->walk_timer = l_timeout_create(WALK_TIME, walk_timeout, wsc,
							NULL);
	}
}

static void wsc_station_dbus_cancel(struct wsc_dbus *super)
{
	struct wsc_station_dbus *wsc =
		l_container_of(super, struct wsc_station_dbus, super);

	wsc_cancel_scan(wsc);

	if (wsc->station_state_watch) {
		station_remove_state_watch(wsc->station,
						wsc->station_state_watch);
		wsc->station_state_watch = 0;
		wsc->target = NULL;
	}

	CONNECT_REPLY(wsc, dbus_error_aborted);

	if (wsc->enrollee)
		wsc_enrollee_cancel(wsc->enrollee, true);
	else
		CANCEL_REPLY(wsc, l_dbus_message_new_method_return);
}

static void wsc_station_dbus_remove(struct wsc_dbus *super)
{
	struct wsc_station_dbus *wsc =
		l_container_of(super, struct wsc_station_dbus, super);

	wsc_cancel_scan(wsc);

	if (wsc->station_state_watch) {
		station_remove_state_watch(wsc->station,
						wsc->station_state_watch);
		wsc->station_state_watch = 0;
	}

	if (wsc->enrollee)
		wsc_enrollee_free(wsc->enrollee);

	l_free(wsc);
}

static struct l_dbus_message *wsc_push_button(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct wsc_dbus *wsc = user_data;

	l_debug("");

	if (!l_dbus_message_get_arguments(message, ""))
		return dbus_error_invalid_args(message);

	if (wsc->pending_connect || wsc->pending_cancel)
		return dbus_error_busy(message);

	wsc->pending_connect = l_dbus_message_ref(message);
	wsc->connect(wsc, NULL);
	return NULL;
}

static struct l_dbus_message *wsc_generate_pin(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct wsc_dbus *wsc = user_data;
	struct l_dbus_message *reply;
	char pin[9];

	l_debug("");

	if (wsc->pending_connect)
		return dbus_error_busy(message);

	if (!wsc_pin_generate(pin))
		return dbus_error_failed(message);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "s", pin);
	explicit_bzero(pin, 9);

	return reply;
}

static struct l_dbus_message *wsc_start_pin(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct wsc_dbus *wsc = user_data;
	const char *pin;

	l_debug("");

	if (wsc->pending_connect || wsc->pending_cancel)
		return dbus_error_busy(message);

	if (!l_dbus_message_get_arguments(message, "s", &pin))
		return dbus_error_invalid_args(message);

	if (!wsc_pin_is_valid(pin))
		return dbus_error_invalid_format(message);

	wsc->pending_connect = l_dbus_message_ref(message);
	wsc->connect(wsc, pin);
	return NULL;
}

static struct l_dbus_message *wsc_cancel(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct wsc_dbus *wsc = user_data;

	l_debug("");

	if (!l_dbus_message_get_arguments(message, ""))
		return dbus_error_invalid_args(message);

	if (!wsc->pending_connect)
		return dbus_error_not_available(message);

	if (wsc->pending_cancel)
		return dbus_error_busy(message);

	wsc->pending_cancel = l_dbus_message_ref(message);
	wsc->cancel(wsc);
	return NULL;
}

static void setup_wsc_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "PushButton", 0,
				wsc_push_button, "", "");
	l_dbus_interface_method(interface, "GeneratePin", 0,
				wsc_generate_pin, "s", "", "pin");
	l_dbus_interface_method(interface, "StartPin", 0,
				wsc_start_pin, "", "s", "pin");
	l_dbus_interface_method(interface, "Cancel", 0,
				wsc_cancel, "", "");
}

bool wsc_dbus_add_interface(struct wsc_dbus *wsc)
{
	struct l_dbus *dbus = dbus_get_bus();

	if (!l_dbus_object_add_interface(dbus, wsc->get_path(wsc),
						IWD_WSC_INTERFACE, wsc)) {
		l_info("Unable to register %s interface", IWD_WSC_INTERFACE);
		return false;
	}

	return true;
}

void wsc_dbus_remove_interface(struct wsc_dbus *wsc)
{
	struct l_dbus *dbus = dbus_get_bus();

	l_dbus_object_remove_interface(dbus, wsc->get_path(wsc),
					IWD_WSC_INTERFACE);
}

static void wsc_dbus_free(void *user_data)
{
	struct wsc_dbus *wsc = user_data;

	if (wsc->pending_connect)
		dbus_pending_reply(&wsc->pending_connect,
				dbus_error_not_available(wsc->pending_connect));

	if (wsc->pending_cancel)
		dbus_pending_reply(&wsc->pending_cancel,
				dbus_error_aborted(wsc->pending_cancel));

	wsc->remove(wsc);
}

static void wsc_add_station(struct netdev *netdev)
{
	struct wsc_station_dbus *wsc;

	if (!wiphy_get_max_scan_ie_len(netdev_get_wiphy(netdev))) {
		l_debug("Simple Configuration isn't supported by ifindex %u",
						netdev_get_ifindex(netdev));

		return;
	}

	wsc = l_new(struct wsc_station_dbus, 1);
	wsc->netdev = netdev;
	wsc->super.get_path = wsc_station_dbus_get_path;
	wsc->super.connect = wsc_station_dbus_connect;
	wsc->super.cancel = wsc_station_dbus_cancel;
	wsc->super.remove = wsc_station_dbus_remove;

	if (!wsc_dbus_add_interface(&wsc->super))
		wsc_station_dbus_remove(&wsc->super);
}

static void wsc_remove_station(struct netdev *netdev)
{
	struct l_dbus *dbus = dbus_get_bus();

	l_dbus_object_remove_interface(dbus, netdev_get_path(netdev),
					IWD_WSC_INTERFACE);
}

static void wsc_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
	case NETDEV_WATCH_EVENT_NEW:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_STATION &&
				netdev_get_is_up(netdev))
			wsc_add_station(netdev);
		break;
	case NETDEV_WATCH_EVENT_DOWN:
	case NETDEV_WATCH_EVENT_DEL:
		wsc_remove_station(netdev);
		break;
	default:
		break;
	}
}

static int wsc_init(void)
{
	l_debug("");
	netdev_watch = netdev_watch_add(wsc_netdev_watch, NULL, NULL);
	l_dbus_register_interface(dbus_get_bus(), IWD_WSC_INTERFACE,
					setup_wsc_interface,
					wsc_dbus_free, false);
	return 0;
}

static void wsc_exit(void)
{
	l_debug("");
	l_dbus_unregister_interface(dbus_get_bus(), IWD_WSC_INTERFACE);
	netdev_watch_remove(netdev_watch);
}

IWD_MODULE(wsc, wsc_init, wsc_exit)
IWD_MODULE_DEPENDS(wsc, netdev);
