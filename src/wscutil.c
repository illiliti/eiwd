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

#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>

#include <ell/ell.h>

#include "src/util.h"
#include "src/ie.h"
#include "src/wscutil.h"

const unsigned char wsc_wfa_oui[3] = { 0x00, 0x37, 0x2a };

void wsc_wfa_ext_iter_init(struct wsc_wfa_ext_iter *iter,
				const unsigned char *pdu, unsigned short len)
{
	iter->pdu = pdu;
	iter->max = len;
	iter->pos = 0;
}

bool wsc_wfa_ext_iter_next(struct wsc_wfa_ext_iter *iter)
{
	const unsigned char *start = iter->pdu + iter->pos;
	const unsigned char *end = iter->pdu + iter->max;
	unsigned char type;
	unsigned char len;

	if (iter->pos + 2 >= iter->max)
		return false;

	type = *start;
	start += 1;

	len = *start;
	start += 1;

	if (len > end - start)
		return false;

	iter->type = type;
	iter->len = len;
	iter->data = start;

	iter->pos = start + len - iter->pdu;

	return true;
}

void wsc_attr_iter_init(struct wsc_attr_iter *iter, const unsigned char *pdu,
			unsigned int len)
{
	iter->pdu = pdu;
	iter->max = len;
	iter->pos = 0;
}

bool wsc_attr_iter_next(struct wsc_attr_iter *iter)
{
	const unsigned char *start = iter->pdu + iter->pos;
	const unsigned char *end = iter->pdu + iter->max;
	unsigned short type;
	unsigned short len;

	/* Make sure we have at least type + len fields */
	if (iter->pos + 4 >= iter->max)
		return false;

	type = l_get_be16(start);
	start += 2;

	len = l_get_be16(start);
	start += 2;

	if (len > end - start)
		return false;

	iter->type = type;
	iter->len = len;
	iter->data = start;

	iter->pos = start + len - iter->pdu;

	return true;
}

bool wsc_attr_iter_recurse_wfa_ext(struct wsc_attr_iter *iter,
					struct wsc_wfa_ext_iter *wfa_iter)
{
	if (iter->type != WSC_ATTR_VENDOR_EXTENSION)
		return false;

	if (iter->len < 3)
		return false;

	if (memcmp(iter->data, wsc_wfa_oui, sizeof(wsc_wfa_oui)))
		return false;

	wsc_wfa_ext_iter_init(wfa_iter, iter->data + 3, iter->len - 3);

	return true;
}

typedef bool (*attr_handler)(struct wsc_attr_iter *, void *);

static bool extract_uint8(struct wsc_attr_iter *iter, void *data)
{
	uint8_t *to = data;

	if (wsc_attr_iter_get_length(iter) != 1)
		return false;

	*to = *wsc_attr_iter_get_data(iter);

	return true;
}

static bool extract_uint16(struct wsc_attr_iter *iter, void *data)
{
	uint16_t *to = data;

	if (wsc_attr_iter_get_length(iter) != 2)
		return false;

	*to = l_get_be16(wsc_attr_iter_get_data(iter));

	return true;
}

static bool extract_bool(struct wsc_attr_iter *iter, void *data)
{
	bool *to = data;

	if (wsc_attr_iter_get_length(iter) != 1)
		return false;

	*to = *wsc_attr_iter_get_data(iter) ? true : false;

	return true;
}

static bool extract_uuid(struct wsc_attr_iter *iter, void *data)
{
	if (wsc_attr_iter_get_length(iter) != 16)
		return false;

	memcpy(data, wsc_attr_iter_get_data(iter), 16);
	return true;
}

static bool extract_hash(struct wsc_attr_iter *iter, void *data)
{
	if (wsc_attr_iter_get_length(iter) != 32)
		return false;

	memcpy(data, wsc_attr_iter_get_data(iter), 32);
	return true;
}

static bool extract_authenticator(struct wsc_attr_iter *iter, void *data)
{
	if (wsc_attr_iter_get_length(iter) != 8)
		return false;

	memcpy(data, wsc_attr_iter_get_data(iter), 8);
	return true;
}

static bool extract_ascii_string(struct wsc_attr_iter *iter, void *data,
					unsigned int max_len)
{
	char *out = data;
	const uint8_t *p;
	unsigned int len;
	unsigned int i;

	len = wsc_attr_iter_get_length(iter);
	if (len > max_len)
		return false;

	p = wsc_attr_iter_get_data(iter);

	for (i = 0; i < len; i++) {
		if (!p[i])
			break;

		if (!l_ascii_isprint(p[i]))
			return false;
	}

	memcpy(out, p, i);
	out[i] = '\0';
	return true;
}

static bool extract_utf8_string(struct wsc_attr_iter *iter, void *data,
					unsigned int max_len)
{
	char *out = data;
	const uint8_t *p;
	unsigned int len;
	unsigned int i;

	len = wsc_attr_iter_get_length(iter);
	if (len > max_len)
		return false;

	p = wsc_attr_iter_get_data(iter);

	for (i = 0; i < len; i++) {
		if (!p[i])
			break;
	}

	if (!l_utf8_validate((const char *) p, i, NULL))
		return false;

	memcpy(out, p, i);
	out[i] = '\0';
	return true;
}

static bool extract_nonce(struct wsc_attr_iter *iter, void *data)
{
	if (wsc_attr_iter_get_length(iter) != 16)
		return false;

	memcpy(data, wsc_attr_iter_get_data(iter), 16);
	return true;
}

static bool extract_association_state(struct wsc_attr_iter *iter, void *data)
{
	enum wsc_association_state *out = data;
	uint16_t as;

	if (!extract_uint16(iter, &as))
		return false;

	/* WSC 2.0.5: Table 31 */
	if (as > 4)
		return false;

	*out = as;
	return true;
}

static bool extract_configuration_error(struct wsc_attr_iter *iter, void *data)
{
	enum wsc_configuration_error *out = data;
	uint16_t ce;

	if (!extract_uint16(iter, &ce))
		return false;

	/* WSC 2.0.5: Table 34 */
	if (ce > 20)
		return false;

	*out = ce;
	return true;
}

static bool extract_device_name(struct wsc_attr_iter *iter, void *data)
{
	return extract_utf8_string(iter, data, 32);
}

static bool extract_device_password_id(struct wsc_attr_iter *iter, void *data)
{
	uint16_t v;
	enum wsc_device_password_id *out = data;

	if (wsc_attr_iter_get_length(iter) != 2)
		return false;

	v = l_get_be16(wsc_attr_iter_get_data(iter));
	if (v > 0x0008)
		return false;

	*out = v;
	return true;
}

static bool extract_encrypted_settings(struct wsc_attr_iter *iter, void *data)
{
	struct iovec *iov = data;

	iov->iov_len = wsc_attr_iter_get_length(iter);
	iov->iov_base = (void *) wsc_attr_iter_get_data(iter);

	return true;
}

static bool extract_mac_address(struct wsc_attr_iter *iter, void *data)
{
	if (wsc_attr_iter_get_length(iter) != 6)
		return false;

	memcpy(data, wsc_attr_iter_get_data(iter), 6);
	return true;
}

static bool extract_manufacturer(struct wsc_attr_iter *iter, void *data)
{
	return extract_ascii_string(iter, data, 64);
}

static bool extract_message_type(struct wsc_attr_iter *iter, void *data)
{
	enum wsc_message_type *out = data;
	uint8_t mt;

	if (!extract_uint8(iter, &mt))
		return false;

	/* WSC 2.0.5: Table 42 */
	if (!mt || mt > 0x0f)
		return false;

	*out = mt;
	return true;
}

static bool extract_model_name(struct wsc_attr_iter *iter, void *data)
{
	return extract_ascii_string(iter, data, 32);
}

static bool extract_model_number(struct wsc_attr_iter *iter, void *data)
{
	return extract_ascii_string(iter, data, 32);
}

static bool extract_network_key(struct wsc_attr_iter *iter, void *data)
{
	struct iovec *network_key = data;
	unsigned int len;
	const uint8_t *key;

	len = wsc_attr_iter_get_length(iter);
	if (len > 64)
		return false;

	/*
	 * WSC 2.0.5, Section 12, Network Key:
	 * "Some existing implementations based on v1.0h null-terminate the
	 * passphrase value, i.e., add an extra 0x00 octet into the end of
	 * the value. For backwards compatibility, implementations shall be
	 * able to parse such a value"
	 */
	key = wsc_attr_iter_get_data(iter);
	if (len && key[len - 1] == 0x00)
		len--;

	network_key->iov_len = len;
	network_key->iov_base = (void *) key;

	return true;
}

static bool extract_new_password(struct wsc_attr_iter *iter, void *data)
{
	struct iovec *new_password = data;
	unsigned int len;

	len = wsc_attr_iter_get_length(iter);
	if (len > 64)
		return false;

	new_password->iov_len = len;
	new_password->iov_base = (void *) wsc_attr_iter_get_data(iter);

	return true;
}

static bool extract_os_version(struct wsc_attr_iter *iter, void *data)
{
	uint32_t v;
	uint32_t *out = data;

	if (wsc_attr_iter_get_length(iter) != 4)
		return false;

	v = l_get_be32(wsc_attr_iter_get_data(iter));

	/*
	 * The OS Version component indicates what operating system is running
	 * on the device. It is a four-byte field. The most significant bit is
	 * reserved and always set to one.
	 *
	 * We do not strictly check this as at least Apple's WPS implementation
	 * does not set the MSB to 1.
	 */
	*out = v & 0x7fffffff;
	return true;
}

static bool extract_public_key(struct wsc_attr_iter *iter, void *data)
{
	if (wsc_attr_iter_get_length(iter) != 192)
		return false;

	memcpy(data, wsc_attr_iter_get_data(iter), 192);
	return true;
}

int wsc_parse_primary_device_type(const uint8_t *pdu, size_t len,
					struct wsc_primary_device_type *out)
{
	uint16_t category;

	if (len != 8)
		return -EINVAL;

	category = l_get_be16(pdu);
	if (category > 12 && category != 255)
		return -EINVAL;

	out->category = category;
	memcpy(out->oui, pdu + 2, 3);
	out->oui_type = pdu[5];
	out->subcategory = l_get_be16(pdu + 6);
	return 0;
}

static bool extract_primary_device_type(struct wsc_attr_iter *iter, void *data)
{
	return wsc_parse_primary_device_type(wsc_attr_iter_get_data(iter),
						wsc_attr_iter_get_length(iter),
						data) == 0;
}

static bool extract_request_type(struct wsc_attr_iter *iter, void *data)
{
	enum wsc_request_type *out = data;
	uint8_t rt;

	if (!extract_uint8(iter, &rt))
		return false;

	/* WSC 2.0.5: Table 42 */
	if (rt > 3)
		return false;

	*out = rt;
	return true;
}

static bool extract_response_type(struct wsc_attr_iter *iter, void *data)
{
	enum wsc_response_type *out = data;
	uint8_t rt;

	if (!extract_uint8(iter, &rt))
		return false;

	/* WSC 2.0.5: Table 43 */
	if (rt > 3)
		return false;

	*out = rt;
	return true;
}

static bool extract_serial_number(struct wsc_attr_iter *iter, void *data)
{
	return extract_ascii_string(iter, data, 32);
}

static bool extract_ssid(struct wsc_attr_iter *iter, void *data)
{
	struct iovec *ssid = data;
	unsigned int len;

	len = wsc_attr_iter_get_length(iter);
	if (len > SSID_MAX_SIZE)
		return false;

	ssid->iov_len = len;
	ssid->iov_base = (void *) wsc_attr_iter_get_data(iter);

	return true;
}

static bool extract_version(struct wsc_attr_iter *iter, void *data)
{
	uint8_t *out = data;
	uint8_t v;

	if (!extract_uint8(iter, &v))
		return false;

	/*
	 * "This attribute is always set to value 0x10 (version 1.0)
	 * for backwards compatibility"
	 */
	if (v != 0x10)
		return false;

	*out = v;
	return true;
}

static bool extract_wsc_state(struct wsc_attr_iter *iter, void *data)
{
	enum wsc_state *out = data;
	uint8_t st;

	if (!extract_uint8(iter, &st))
		return false;

	if (st < 1 || st > 2)
		return false;

	*out = st;
	return true;
}

static attr_handler handler_for_type(enum wsc_attr type)
{
	switch (type) {
	case WSC_ATTR_AP_SETUP_LOCKED:
		return extract_bool;
	case WSC_ATTR_ASSOCIATION_STATE:
		return extract_association_state;
	case WSC_ATTR_AUTHENTICATION_TYPE:
	case WSC_ATTR_AUTHENTICATION_TYPE_FLAGS:
		return extract_uint16;
	case WSC_ATTR_AUTHENTICATOR:
		return extract_authenticator;
	case WSC_ATTR_CONFIGURATION_ERROR:
		return extract_configuration_error;
	case WSC_ATTR_CONFIGURATION_METHODS:
		return extract_uint16;
	case WSC_ATTR_CONNECTION_TYPE_FLAGS:
		return extract_uint8;
	case WSC_ATTR_DEVICE_NAME:
		return extract_device_name;
	case WSC_ATTR_DEVICE_PASSWORD_ID:
		return extract_device_password_id;
	case WSC_ATTR_E_HASH1:
	case WSC_ATTR_E_HASH2:
		return extract_hash;
	case WSC_ATTR_E_SNONCE1:
	case WSC_ATTR_E_SNONCE2:
		return extract_nonce;
	case WSC_ATTR_ENCRYPTED_SETTINGS:
		return extract_encrypted_settings;
	case WSC_ATTR_ENCRYPTION_TYPE:
	case WSC_ATTR_ENCRYPTION_TYPE_FLAGS:
		return extract_uint16;
	case WSC_ATTR_ENROLLEE_NONCE:
		return extract_nonce;
	case WSC_ATTR_KEY_WRAP_AUTHENTICATOR:
		return extract_authenticator;
	case WSC_ATTR_MAC_ADDRESS:
		return extract_mac_address;
	case WSC_ATTR_MANUFACTURER:
		return extract_manufacturer;
	case WSC_ATTR_MESSAGE_TYPE:
		return extract_message_type;
	case WSC_ATTR_MODEL_NAME:
		return extract_model_name;
	case WSC_ATTR_MODEL_NUMBER:
		return extract_model_number;
	case WSC_ATTR_NETWORK_INDEX:
		return extract_uint8;
	case WSC_ATTR_NETWORK_KEY:
		return extract_network_key;
	case WSC_ATTR_NEW_PASSWORD:
		return extract_new_password;
	case WSC_ATTR_NETWORK_KEY_INDEX:
		return extract_uint8;
	case WSC_ATTR_OS_VERSION:
		return extract_os_version;
	case WSC_ATTR_PUBLIC_KEY:
		return extract_public_key;
	case WSC_ATTR_PRIMARY_DEVICE_TYPE:
		return extract_primary_device_type;
	case WSC_ATTR_REGISTRAR_NONCE:
		return extract_nonce;
	case WSC_ATTR_REQUEST_TYPE:
		return extract_request_type;
	case WSC_ATTR_REQUESTED_DEVICE_TYPE:
		return extract_primary_device_type;
	case WSC_ATTR_RESPONSE_TYPE:
		return extract_response_type;
	case WSC_ATTR_RF_BANDS:
		return extract_uint8;
	case WSC_ATTR_R_HASH1:
	case WSC_ATTR_R_HASH2:
		return extract_hash;
	case WSC_ATTR_R_SNONCE1:
	case WSC_ATTR_R_SNONCE2:
		return extract_nonce;
	case WSC_ATTR_SELECTED_REGISTRAR:
		return extract_bool;
	case WSC_ATTR_SELECTED_REGISTRAR_CONFIGURATION_METHODS:
		return extract_uint16;
	case WSC_ATTR_SERIAL_NUMBER:
		return extract_serial_number;
	case WSC_ATTR_SSID:
		return extract_ssid;
	case WSC_ATTR_VERSION:
		return extract_version;
	case WSC_ATTR_WSC_STATE:
		return extract_wsc_state;
	case WSC_ATTR_UUID_E:
		return extract_uuid;
	case WSC_ATTR_UUID_R:
		return extract_uuid;
	default:
		break;
	}

	return NULL;
}

struct attr_handler_entry {
	enum wsc_attr type;
	unsigned int flags;
	void *data;
	bool present;
};

static bool verify_version2(struct wsc_wfa_ext_iter *ext_iter)
{
	if (!wsc_wfa_ext_iter_next(ext_iter))
		return false;

	if (wsc_wfa_ext_iter_get_type(ext_iter) != WSC_WFA_EXTENSION_VERSION2)
		return false;

	if (wsc_wfa_ext_iter_get_length(ext_iter) != 1)
		return false;

	return true;
}

int wsc_parse_attrs(const unsigned char *pdu, unsigned int len,
			bool *out_version2, struct wsc_wfa_ext_iter *ext_iter,
			enum wsc_attr authenticator_type,
			uint8_t *authenticator, int type, ...)
{
	struct wsc_attr_iter iter;
	struct l_queue *entries;
	const struct l_queue_entry *e;
	va_list args;
	bool version2 = false;
	bool sr = false;
	bool have_required = true;
	bool parse_error = false;

	if (ext_iter) /* In case of no WFA extension */
		wsc_wfa_ext_iter_init(ext_iter, NULL, 0);

	wsc_attr_iter_init(&iter, pdu, len);

	va_start(args, type);

	entries = l_queue_new();

	while (type != WSC_ATTR_INVALID) {
		struct attr_handler_entry *entry;

		entry = l_new(struct attr_handler_entry, 1);

		entry->type = type;
		entry->flags = va_arg(args, unsigned int);
		entry->data = va_arg(args, void *);

		type = va_arg(args, enum wsc_attr);
		l_queue_push_tail(entries, entry);
	}

	va_end(args);
	e = l_queue_get_entries(entries);

	while (wsc_attr_iter_next(&iter)) {
		attr_handler handler;
		struct attr_handler_entry *entry;
		const struct l_queue_entry *e2;

		for (e2 = e; e2; e2 = e2->next) {
			entry = e2->data;

			if (wsc_attr_iter_get_type(&iter) == entry->type) {
				entry->present = true;
				break;
			}

			if (entry->flags & WSC_ATTR_FLAG_REQUIRED) {
				have_required = false;
				goto done;
			}
		}

		if (e2 == NULL) {
			if (!ext_iter)
				break;

			if (wsc_attr_iter_get_type(&iter)
					!= WSC_ATTR_VENDOR_EXTENSION)
				break;

			if (!wsc_attr_iter_recurse_wfa_ext(&iter, ext_iter))
				break;

			if (!verify_version2(ext_iter)) {
				parse_error = true;
				goto done;
			}

			version2 = true;
			continue;
		}

		if (entry->type == WSC_ATTR_SELECTED_REGISTRAR)
			sr = true;

		handler = handler_for_type(entry->type);

		if (!handler(&iter, entry->data)) {
			parse_error = true;
			goto done;
		}

		e = e2->next;
	}

	for (; e; e = e->next) {
		struct attr_handler_entry *entry = e->data;

		if (entry->flags & WSC_ATTR_FLAG_REQUIRED) {
			parse_error = true;
			goto done;
		}
	}

	/* Authenticator element must be the last element */
	if (authenticator) {
		while (wsc_attr_iter_get_type(&iter) != authenticator_type) {
			if (!wsc_attr_iter_next(&iter)) {
				have_required = false;
				goto done;
			}
		}

		if (!extract_authenticator(&iter, authenticator)) {
			parse_error = true;
			goto done;
		}

		if (wsc_attr_iter_next(&iter) != false) {
			parse_error = true;
			goto done;
		}

		if (wsc_attr_iter_get_pos(&iter) != len) {
			parse_error = true;
			goto done;
		}
	}

	/*
	 * Check for Version 2.0 required attributes.
	 * If version2 attribute is present in the WFA Vendor field,
	 * then check the required attributes are present.  Mostly relevant
	 * for Probe Request messages according to 8.2.4 in WSC 2.0.5
	 */
	if (version2) {
		struct attr_handler_entry *entry;

		for (e = l_queue_get_entries(entries); e; e = e->next) {
			entry = e->data;

			if (!(entry->flags & WSC_ATTR_FLAG_VERSION2))
				continue;

			if (entry->present)
				continue;

			parse_error = true;
			goto done;
		}
	}

	/*
	 * If Selected Registrar is present and true, then certain attributes
	 * must also be present.
	 */
	if (sr) {
		struct attr_handler_entry *entry;

		for (e = l_queue_get_entries(entries); e; e = e->next) {
			entry = e->data;

			if (!(entry->flags & WSC_ATTR_FLAG_REGISTRAR))
				continue;

			if (entry->present)
				continue;

			parse_error = true;
			goto done;
		}

	}

done:
	l_queue_destroy(entries, l_free);

	if (!have_required)
		return -EINVAL;
	if (parse_error)
		return -EBADMSG;

	if (out_version2)
		*out_version2 = version2;

	return 0;
}

static bool wfa_extract_bool(struct wsc_wfa_ext_iter *iter, void *data)
{
	bool *to = data;

	if (wsc_wfa_ext_iter_get_length(iter) != 1)
		return false;

	*to = *wsc_wfa_ext_iter_get_data(iter);
	return true;
}

static bool wfa_extract_authorized_macs(struct wsc_wfa_ext_iter *iter,
								void *data)
{
	uint8_t *to = data;
	unsigned int len = wsc_wfa_ext_iter_get_length(iter);
	unsigned int mod;

	if (!len || len > 30)
		return false;

	mod = len % 6;
	if (mod)
		return false;

	memcpy(to, wsc_wfa_ext_iter_get_data(iter), len);
	return true;
}

static bool wfa_extract_registrar_configuration_methods(
				struct wsc_wfa_ext_iter *iter, void *data)
{
	uint16_t *to = data;

	if (wsc_wfa_ext_iter_get_length(iter) != 2)
		return false;

	*to = l_get_be16(wsc_wfa_ext_iter_get_data(iter));
	return true;
}

#define REQUIRED(attr, out) \
	WSC_ATTR_ ## attr, WSC_ATTR_FLAG_REQUIRED, out

#define OPTIONAL(attr, out) \
	WSC_ATTR_ ## attr, 0, out

#define REGISTRAR(attr, out) \
	WSC_ATTR_ ## attr, WSC_ATTR_FLAG_REGISTRAR, out

#define VERSION2(attr, out) \
	WSC_ATTR_ ## attr, WSC_ATTR_FLAG_VERSION2, out

int wsc_parse_credential(const uint8_t *pdu, uint32_t len,
						struct wsc_credential *out)
{
	uint8_t network_index;
	struct iovec ssid;
	uint8_t network_key_index;
	struct iovec network_key;
	int r;

	memset(out, 0, sizeof(*out));

	r = wsc_parse_attrs(pdu, len, NULL, NULL, 0, NULL,
		REQUIRED(NETWORK_INDEX, &network_index),
		REQUIRED(SSID, &ssid),
		REQUIRED(AUTHENTICATION_TYPE, &out->auth_type),
		REQUIRED(ENCRYPTION_TYPE, &out->encryption_type),
		OPTIONAL(NETWORK_KEY_INDEX, &network_key_index),
		REQUIRED(NETWORK_KEY, &network_key),
		REQUIRED(MAC_ADDRESS, &out->addr),
		/* TODO: Parse EAP attributes */
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	memcpy(out->ssid, ssid.iov_base, ssid.iov_len);
	out->ssid_len = ssid.iov_len;

	while (out->ssid_len > 0 && out->ssid[out->ssid_len - 1] == 0)
		out->ssid_len -= 1;

	if (!out->ssid_len)
		return -EBADMSG;

	memcpy(out->network_key, network_key.iov_base, network_key.iov_len);
	out->network_key_len = network_key.iov_len;

	/* TODO: Parse Network Key Shareable inside WFA EXT */

	return 0;
}

int wsc_parse_beacon(const unsigned char *pdu, unsigned int len,
				struct wsc_beacon *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;

	memset(out, 0, sizeof(struct wsc_beacon));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter, 0, NULL,
		REQUIRED(VERSION, &version),
		REQUIRED(WSC_STATE, &out->state),
		OPTIONAL(AP_SETUP_LOCKED, &out->ap_setup_locked),
		OPTIONAL(SELECTED_REGISTRAR, &out->selected_registrar),
		REGISTRAR(DEVICE_PASSWORD_ID, &out->device_password_id),
		REGISTRAR(SELECTED_REGISTRAR_CONFIGURATION_METHODS,
					&out->selected_reg_config_methods),
		OPTIONAL(UUID_E, &out->uuid_e),
		OPTIONAL(RF_BANDS, &out->rf_bands),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (!wsc_wfa_ext_iter_next(&iter))
		goto done;

	if (wsc_wfa_ext_iter_get_type(&iter) ==
					WSC_WFA_EXTENSION_AUTHORIZED_MACS) {
		if (!wfa_extract_authorized_macs(&iter, &out->authorized_macs))
			return -EBADMSG;

		if (!wsc_wfa_ext_iter_next(&iter))
			goto done;
	}

	if (wsc_wfa_ext_iter_get_type(&iter) ==
			WSC_WFA_EXTENSION_REGISTRAR_CONFIGRATION_METHODS) {
		if (!wfa_extract_registrar_configuration_methods(&iter,
						&out->reg_config_methods))
			return -EBADMSG;

		if (!wsc_wfa_ext_iter_next(&iter))
			goto done;
	}

	return -EINVAL;

done:
	return 0;
}

int wsc_parse_probe_response(const unsigned char *pdu, unsigned int len,
				struct wsc_probe_response *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;

	memset(out, 0, sizeof(struct wsc_probe_response));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter, 0, NULL,
		REQUIRED(VERSION, &version),
		REQUIRED(WSC_STATE, &out->state),
		OPTIONAL(AP_SETUP_LOCKED, &out->ap_setup_locked),
		OPTIONAL(SELECTED_REGISTRAR, &out->selected_registrar),
		REGISTRAR(DEVICE_PASSWORD_ID, &out->device_password_id),
		REGISTRAR(SELECTED_REGISTRAR_CONFIGURATION_METHODS,
					&out->selected_reg_config_methods),
		REQUIRED(RESPONSE_TYPE, &out->response_type),
		REQUIRED(UUID_E, &out->uuid_e),
		REQUIRED(MANUFACTURER, &out->manufacturer),
		REQUIRED(MODEL_NAME, &out->model_name),
		REQUIRED(MODEL_NUMBER, &out->model_number),
		REQUIRED(SERIAL_NUMBER, &out->serial_number),
		REQUIRED(PRIMARY_DEVICE_TYPE, &out->primary_device_type),
		REQUIRED(DEVICE_NAME, &out->device_name),
		REQUIRED(CONFIGURATION_METHODS, &out->config_methods),
		OPTIONAL(RF_BANDS, &out->rf_bands),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (!wsc_wfa_ext_iter_next(&iter))
		goto done;

	if (wsc_wfa_ext_iter_get_type(&iter) ==
					WSC_WFA_EXTENSION_AUTHORIZED_MACS) {
		if (!wfa_extract_authorized_macs(&iter, &out->authorized_macs))
			return -EBADMSG;

		if (!wsc_wfa_ext_iter_next(&iter))
			goto done;
	}

	if (wsc_wfa_ext_iter_get_type(&iter) ==
			WSC_WFA_EXTENSION_REGISTRAR_CONFIGRATION_METHODS) {
		if (!wfa_extract_registrar_configuration_methods(&iter,
						&out->reg_config_methods))
			return -EBADMSG;

		if (!wsc_wfa_ext_iter_next(&iter))
			goto done;
	}

	return -EINVAL;

done:
	return 0;
}

int wsc_parse_probe_request(const unsigned char *pdu, unsigned int len,
				struct wsc_probe_request *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;

	memset(out, 0, sizeof(struct wsc_probe_request));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter, 0, NULL,
		REQUIRED(VERSION, &version),
		REQUIRED(REQUEST_TYPE, &out->request_type),
		REQUIRED(CONFIGURATION_METHODS, &out->config_methods),
		REQUIRED(UUID_E, &out->uuid_e),
		REQUIRED(PRIMARY_DEVICE_TYPE, &out->primary_device_type),
		REQUIRED(RF_BANDS, &out->rf_bands),
		REQUIRED(ASSOCIATION_STATE, &out->association_state),
		REQUIRED(CONFIGURATION_ERROR, &out->configuration_error),
		REQUIRED(DEVICE_PASSWORD_ID, &out->device_password_id),
		VERSION2(MANUFACTURER, &out->manufacturer),
		VERSION2(MODEL_NAME, &out->model_name),
		VERSION2(MODEL_NUMBER, &out->model_number),
		VERSION2(DEVICE_NAME, &out->device_name),
		OPTIONAL(REQUESTED_DEVICE_TYPE, &out->requested_device_type),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (!wsc_wfa_ext_iter_next(&iter))
		goto done;

	if (wsc_wfa_ext_iter_get_type(&iter) ==
					WSC_WFA_EXTENSION_REQUEST_TO_ENROLL) {
		if (!wfa_extract_bool(&iter, &out->request_to_enroll))
			return -EBADMSG;

		if (!wsc_wfa_ext_iter_next(&iter))
			goto done;
	}

	return -EINVAL;

done:
	return 0;
}

int wsc_parse_association_request(const uint8_t *pdu, uint32_t len,
					struct wsc_association_request *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;

	memset(out, 0, sizeof(struct wsc_association_request));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter, 0, NULL,
		REQUIRED(VERSION, &version),
		REQUIRED(REQUEST_TYPE, &out->request_type),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	return 0;
}

int wsc_parse_association_response(const uint8_t *pdu, uint32_t len,
					struct wsc_association_response *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;

	memset(out, 0, sizeof(struct wsc_association_response));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter, 0, NULL,
		REQUIRED(VERSION, &version),
		REQUIRED(RESPONSE_TYPE, &out->response_type),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	return 0;
}

int wsc_parse_m1(const uint8_t *pdu, uint32_t len, struct wsc_m1 *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;
	enum wsc_message_type msg_type;

	memset(out, 0, sizeof(struct wsc_m1));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter, 0, NULL,
		REQUIRED(VERSION, &version),
		REQUIRED(MESSAGE_TYPE, &msg_type),
		REQUIRED(UUID_E, &out->uuid_e),
		REQUIRED(MAC_ADDRESS, &out->addr),
		REQUIRED(ENROLLEE_NONCE, &out->enrollee_nonce),
		REQUIRED(PUBLIC_KEY, &out->public_key),
		REQUIRED(AUTHENTICATION_TYPE_FLAGS, &out->auth_type_flags),
		REQUIRED(ENCRYPTION_TYPE_FLAGS, &out->encryption_type_flags),
		REQUIRED(CONNECTION_TYPE_FLAGS, &out->connection_type_flags),
		REQUIRED(CONFIGURATION_METHODS, &out->config_methods),
		REQUIRED(WSC_STATE, &out->state),
		REQUIRED(MANUFACTURER, &out->manufacturer),
		REQUIRED(MODEL_NAME, &out->model_name),
		REQUIRED(MODEL_NUMBER, &out->model_number),
		REQUIRED(SERIAL_NUMBER, &out->serial_number),
		REQUIRED(PRIMARY_DEVICE_TYPE, &out->primary_device_type),
		REQUIRED(DEVICE_NAME, &out->device_name),
		REQUIRED(RF_BANDS, &out->rf_bands),
		REQUIRED(ASSOCIATION_STATE, &out->association_state),
		REQUIRED(DEVICE_PASSWORD_ID, &out->device_password_id),
		REQUIRED(CONFIGURATION_ERROR, &out->configuration_error),
		REQUIRED(OS_VERSION, &out->os_version),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (msg_type != WSC_MESSAGE_TYPE_M1)
		return -EBADMSG;

	/* WSC 2.0.5, Section 8.3.1: "Specific RF band used for this message" */
	if (__builtin_popcount(out->rf_bands) != 1)
		return -EBADMSG;

	if (!wsc_wfa_ext_iter_next(&iter))
		goto done;

	if (wsc_wfa_ext_iter_get_type(&iter) ==
					WSC_WFA_EXTENSION_REQUEST_TO_ENROLL) {
		if (!wfa_extract_bool(&iter, &out->request_to_enroll))
			return -EBADMSG;

		if (!wsc_wfa_ext_iter_next(&iter))
			goto done;
	}

	return -EINVAL;

done:
	return 0;
}

int wsc_parse_m2(const uint8_t *pdu, uint32_t len, struct wsc_m2 *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;
	enum wsc_message_type msg_type;

	memset(out, 0, sizeof(struct wsc_m2));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter,
		WSC_ATTR_AUTHENTICATOR, out->authenticator,
		REQUIRED(VERSION, &version),
		REQUIRED(MESSAGE_TYPE, &msg_type),
		REQUIRED(ENROLLEE_NONCE, &out->enrollee_nonce),
		REQUIRED(REGISTRAR_NONCE, &out->registrar_nonce),
		REQUIRED(UUID_R, &out->uuid_r),
		REQUIRED(PUBLIC_KEY, &out->public_key),
		REQUIRED(AUTHENTICATION_TYPE_FLAGS, &out->auth_type_flags),
		REQUIRED(ENCRYPTION_TYPE_FLAGS, &out->encryption_type_flags),
		REQUIRED(CONNECTION_TYPE_FLAGS, &out->connection_type_flags),
		REQUIRED(CONFIGURATION_METHODS, &out->config_methods),
		REQUIRED(MANUFACTURER, &out->manufacturer),
		REQUIRED(MODEL_NAME, &out->model_name),
		REQUIRED(MODEL_NUMBER, &out->model_number),
		REQUIRED(SERIAL_NUMBER, &out->serial_number),
		REQUIRED(PRIMARY_DEVICE_TYPE, &out->primary_device_type),
		REQUIRED(DEVICE_NAME, &out->device_name),
		REQUIRED(RF_BANDS, &out->rf_bands),
		REQUIRED(ASSOCIATION_STATE, &out->association_state),
		REQUIRED(CONFIGURATION_ERROR, &out->configuration_error),
		REQUIRED(DEVICE_PASSWORD_ID, &out->device_password_id),
		REQUIRED(OS_VERSION, &out->os_version),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (msg_type != WSC_MESSAGE_TYPE_M2)
		return -EBADMSG;

	/* WSC 2.0.5, Section 8.3.2: "Specific RF band used for this message" */
	if (__builtin_popcount(out->rf_bands) != 1)
		return -EBADMSG;

	return 0;
}

int wsc_parse_m3(const uint8_t *pdu, uint32_t len, struct wsc_m3 *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;
	enum wsc_message_type msg_type;

	memset(out, 0, sizeof(struct wsc_m3));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter,
		WSC_ATTR_AUTHENTICATOR, out->authenticator,
		REQUIRED(VERSION, &version),
		REQUIRED(MESSAGE_TYPE, &msg_type),
		REQUIRED(REGISTRAR_NONCE, &out->registrar_nonce),
		REQUIRED(E_HASH1, &out->e_hash1),
		REQUIRED(E_HASH2, &out->e_hash2),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (msg_type != WSC_MESSAGE_TYPE_M3)
		return -EBADMSG;

	return 0;
}

int wsc_parse_m4(const uint8_t *pdu, uint32_t len, struct wsc_m4 *out,
						struct iovec *out_encrypted)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;
	enum wsc_message_type msg_type;

	memset(out, 0, sizeof(struct wsc_m4));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter,
		WSC_ATTR_AUTHENTICATOR, out->authenticator,
		REQUIRED(VERSION, &version),
		REQUIRED(MESSAGE_TYPE, &msg_type),
		REQUIRED(ENROLLEE_NONCE, &out->enrollee_nonce),
		REQUIRED(R_HASH1, &out->r_hash1),
		REQUIRED(R_HASH2, &out->r_hash2),
		REQUIRED(ENCRYPTED_SETTINGS, out_encrypted),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (msg_type != WSC_MESSAGE_TYPE_M4)
		return -EBADMSG;

	return 0;
}

int wsc_parse_m4_encrypted_settings(const uint8_t *pdu, uint32_t len,
					struct wsc_m4_encrypted_settings *out)
{
	memset(out, 0, sizeof(*out));

	return wsc_parse_attrs(pdu, len, NULL, NULL,
			WSC_ATTR_KEY_WRAP_AUTHENTICATOR, out->authenticator,
			REQUIRED(R_SNONCE1, out->r_snonce1),
			WSC_ATTR_INVALID);
}

int wsc_parse_m5(const uint8_t *pdu, uint32_t len, struct wsc_m5 *out,
						struct iovec *out_encrypted)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;
	enum wsc_message_type msg_type;

	memset(out, 0, sizeof(struct wsc_m5));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter,
		WSC_ATTR_AUTHENTICATOR, out->authenticator,
		REQUIRED(VERSION, &version),
		REQUIRED(MESSAGE_TYPE, &msg_type),
		REQUIRED(REGISTRAR_NONCE, &out->registrar_nonce),
		REQUIRED(ENCRYPTED_SETTINGS, out_encrypted),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (msg_type != WSC_MESSAGE_TYPE_M5)
		return -EBADMSG;

	return 0;
}

int wsc_parse_m5_encrypted_settings(const uint8_t *pdu, uint32_t len,
					struct wsc_m5_encrypted_settings *out)
{
	memset(out, 0, sizeof(*out));

	return wsc_parse_attrs(pdu, len, NULL, NULL,
			WSC_ATTR_KEY_WRAP_AUTHENTICATOR, out->authenticator,
			REQUIRED(E_SNONCE1, out->e_snonce1),
			WSC_ATTR_INVALID);
}

int wsc_parse_m6(const uint8_t *pdu, uint32_t len, struct wsc_m6 *out,
						struct iovec *out_encrypted)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;
	enum wsc_message_type msg_type;

	memset(out, 0, sizeof(struct wsc_m6));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter,
		WSC_ATTR_AUTHENTICATOR, out->authenticator,
		REQUIRED(VERSION, &version),
		REQUIRED(MESSAGE_TYPE, &msg_type),
		REQUIRED(ENROLLEE_NONCE, &out->enrollee_nonce),
		REQUIRED(ENCRYPTED_SETTINGS, out_encrypted),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (msg_type != WSC_MESSAGE_TYPE_M6)
		return -EBADMSG;

	return 0;
}

int wsc_parse_m6_encrypted_settings(const uint8_t *pdu, uint32_t len,
					struct wsc_m6_encrypted_settings *out)
{
	memset(out, 0, sizeof(*out));

	return wsc_parse_attrs(pdu, len, NULL, NULL,
			WSC_ATTR_KEY_WRAP_AUTHENTICATOR, out->authenticator,
			REQUIRED(R_SNONCE2, out->r_snonce2),
			WSC_ATTR_INVALID);
}

int wsc_parse_m7(const uint8_t *pdu, uint32_t len, struct wsc_m7 *out,
						struct iovec *out_encrypted)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;
	enum wsc_message_type msg_type;

	memset(out, 0, sizeof(struct wsc_m7));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter,
		WSC_ATTR_AUTHENTICATOR, out->authenticator,
		REQUIRED(VERSION, &version),
		REQUIRED(MESSAGE_TYPE, &msg_type),
		REQUIRED(REGISTRAR_NONCE, &out->registrar_nonce),
		REQUIRED(ENCRYPTED_SETTINGS, out_encrypted),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (msg_type != WSC_MESSAGE_TYPE_M7)
		return -EBADMSG;

	return 0;
}

int wsc_parse_m7_encrypted_settings(const uint8_t *pdu, uint32_t len,
					struct wsc_m7_encrypted_settings *out)
{
	memset(out, 0, sizeof(*out));

	return wsc_parse_attrs(pdu, len, NULL, NULL,
			WSC_ATTR_KEY_WRAP_AUTHENTICATOR, out->authenticator,
			REQUIRED(E_SNONCE2, out->e_snonce2),
			WSC_ATTR_INVALID);
}

int wsc_parse_m8(const uint8_t *pdu, uint32_t len, struct wsc_m8 *out,
						struct iovec *out_encrypted)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;
	enum wsc_message_type msg_type;

	memset(out, 0, sizeof(struct wsc_m8));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter,
		WSC_ATTR_AUTHENTICATOR, out->authenticator,
		REQUIRED(VERSION, &version),
		REQUIRED(MESSAGE_TYPE, &msg_type),
		REQUIRED(ENROLLEE_NONCE, &out->enrollee_nonce),
		REQUIRED(ENCRYPTED_SETTINGS, out_encrypted),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (msg_type != WSC_MESSAGE_TYPE_M8)
		return -EBADMSG;

	return 0;
}

int wsc_parse_m8_encrypted_settings(const uint8_t *pdu, uint32_t len,
					struct wsc_m8_encrypted_settings *out,
					struct iovec *iov, size_t *iovcnt)
{
	struct wsc_attr_iter iter;
	size_t n_cred = 0;

	memset(out, 0, sizeof(*out));
	wsc_attr_iter_init(&iter, pdu, len);

	if (!wsc_attr_iter_next(&iter))
		return -EBADMSG;

	while (wsc_attr_iter_get_type(&iter) == WSC_ATTR_CREDENTIAL) {
		if (n_cred < *iovcnt) {
			iov[n_cred].iov_base =
				(void *) wsc_attr_iter_get_data(&iter);
			iov[n_cred].iov_len = wsc_attr_iter_get_length(&iter);
			n_cred += 1;
		}

		if (!wsc_attr_iter_next(&iter))
			return -EBADMSG;
	}

	/* At least one Credential element is required */
	if (!n_cred)
		return -EBADMSG;

	if (wsc_attr_iter_get_type(&iter) == WSC_ATTR_NEW_PASSWORD) {
		struct iovec np;

		if (!extract_new_password(&iter, &np))
			return -EBADMSG;

		memcpy(out->new_password, np.iov_base, np.iov_len);
		out->new_password_len = np.iov_len;

		if (!wsc_attr_iter_next(&iter))
			return -EBADMSG;

		/*
		 * According to WSC 2.0.5, Table 21, Device Password ID is
		 * "Required if New Password is included."
		 */
		if (wsc_attr_iter_get_type(&iter) !=
					WSC_ATTR_DEVICE_PASSWORD_ID)
			return -EBADMSG;
	}

	if (wsc_attr_iter_get_type(&iter) == WSC_ATTR_DEVICE_PASSWORD_ID) {
		extract_device_password_id(&iter, &out->device_password_id);

		if (!wsc_attr_iter_next(&iter))
			return -EBADMSG;
	}

	while (wsc_attr_iter_get_type(&iter) !=
					WSC_ATTR_KEY_WRAP_AUTHENTICATOR) {
		if (!wsc_attr_iter_next(&iter))
			return -EBADMSG;
	}

	if (!extract_authenticator(&iter, &out->authenticator))
		return -EBADMSG;

	if (wsc_attr_iter_get_pos(&iter) != len)
		return -EBADMSG;

	*iovcnt = n_cred;

	return 0;
}

int wsc_parse_wsc_ack(const uint8_t *pdu, uint32_t len, struct wsc_ack *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;
	enum wsc_message_type msg_type;

	memset(out, 0, sizeof(struct wsc_ack));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter, 0, NULL,
		REQUIRED(VERSION, &version),
		REQUIRED(MESSAGE_TYPE, &msg_type),
		REQUIRED(ENROLLEE_NONCE, &out->enrollee_nonce),
		REQUIRED(REGISTRAR_NONCE, &out->registrar_nonce),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (msg_type != WSC_MESSAGE_TYPE_WSC_ACK)
		return -EBADMSG;

	return 0;
}

int wsc_parse_wsc_nack(const uint8_t *pdu, uint32_t len, struct wsc_nack *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;
	enum wsc_message_type msg_type;

	memset(out, 0, sizeof(struct wsc_nack));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter, 0, NULL,
		REQUIRED(VERSION, &version),
		REQUIRED(MESSAGE_TYPE, &msg_type),
		REQUIRED(ENROLLEE_NONCE, &out->enrollee_nonce),
		REQUIRED(REGISTRAR_NONCE, &out->registrar_nonce),
		REQUIRED(CONFIGURATION_ERROR, &out->configuration_error),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (msg_type != WSC_MESSAGE_TYPE_WSC_NACK)
		return -EBADMSG;

	return 0;
}

int wsc_parse_wsc_done(const uint8_t *pdu, uint32_t len, struct wsc_done *out)
{
	int r;
	struct wsc_wfa_ext_iter iter;
	uint8_t version;
	enum wsc_message_type msg_type;

	memset(out, 0, sizeof(struct wsc_done));

	r = wsc_parse_attrs(pdu, len, &out->version2, &iter, 0, NULL,
		REQUIRED(VERSION, &version),
		REQUIRED(MESSAGE_TYPE, &msg_type),
		REQUIRED(ENROLLEE_NONCE, &out->enrollee_nonce),
		REQUIRED(REGISTRAR_NONCE, &out->registrar_nonce),
		WSC_ATTR_INVALID);

	if (r < 0)
		return r;

	if (msg_type != WSC_MESSAGE_TYPE_WSC_DONE)
		return -EBADMSG;

	return 0;
}

struct wsc_attr_builder {
	size_t capacity;
	uint8_t *buf;
	size_t offset;
	uint16_t curlen;
};

static void wsc_attr_builder_grow(struct wsc_attr_builder *builder)
{
	builder->buf = l_realloc(builder->buf, builder->capacity * 2);
	builder->capacity *= 2;
}

static bool wsc_attr_builder_start_attr(struct wsc_attr_builder *builder,
						enum wsc_attr type)
{
	uint8_t *bytes;

	/* TLVs must be length > 0 */
	if (builder->curlen == 0 && builder->offset != 0)
		return false;

	/* Record previous attribute's length */
	if (builder->curlen > 0) {
		bytes = builder->buf + builder->offset;
		l_put_be16(builder->curlen - 4, bytes + 2);
		builder->offset += builder->curlen;
	}

	builder->curlen = 4;

	if (builder->offset + 4 >= builder->capacity)
		wsc_attr_builder_grow(builder);

	bytes = builder->buf + builder->offset;
	l_put_be16(type, bytes);

	return true;
}

static bool wsc_attr_builder_put_u8(struct wsc_attr_builder *builder, uint8_t v)
{
	if (builder->offset + builder->curlen + 1 >= builder->capacity)
		wsc_attr_builder_grow(builder);

	builder->buf[builder->offset + builder->curlen] = v;
	builder->curlen += 1;

	return true;
}

static bool wsc_attr_builder_put_u16(struct wsc_attr_builder *builder,
								uint16_t v)
{
	if (builder->offset + builder->curlen + 2 >= builder->capacity)
		wsc_attr_builder_grow(builder);

	l_put_be16(v, builder->buf + builder->offset + builder->curlen);
	builder->curlen += 2;

	return true;
}

static bool wsc_attr_builder_put_u32(struct wsc_attr_builder *builder,
								uint32_t v)
{
	if (builder->offset + builder->curlen + 4 >= builder->capacity)
		wsc_attr_builder_grow(builder);

	l_put_be32(v, builder->buf + builder->offset + builder->curlen);
	builder->curlen += 4;

	return true;
}

static bool wsc_attr_builder_put_bytes(struct wsc_attr_builder *builder,
					const void *bytes, size_t size)
{
	while (builder->offset + builder->curlen + size >= builder->capacity)
		wsc_attr_builder_grow(builder);

	memcpy(builder->buf + builder->offset + builder->curlen, bytes, size);
	builder->curlen += size;

	return true;
}

static bool wsc_attr_builder_put_oui(struct wsc_attr_builder *builder,
							const uint8_t *oui)
{
	if (builder->offset + builder->curlen + 3 >= builder->capacity)
		wsc_attr_builder_grow(builder);

	memcpy(builder->buf + builder->offset + builder->curlen, oui, 3);
	builder->curlen += 3;

	return true;
}

static bool wsc_attr_builder_put_string(struct wsc_attr_builder *builder,
							const char *string)
{
	size_t len;

	len = string ? strlen(string) : 0;

	if (len == 0) {
		string = " ";
		len = 1;
	}

	if (builder->offset + builder->curlen + len >= builder->capacity)
		wsc_attr_builder_grow(builder);

	memcpy(builder->buf + builder->offset + builder->curlen, string, len);
	builder->curlen += len;

	return true;
}

static struct wsc_attr_builder *wsc_attr_builder_new(size_t initial_capacity)
{
	struct wsc_attr_builder *builder;

	if (initial_capacity == 0)
		return NULL;

	builder = l_new(struct wsc_attr_builder, 1);
	builder->buf = l_malloc(initial_capacity);
	builder->capacity = initial_capacity;

	return builder;
}

static uint8_t *wsc_attr_builder_free(struct wsc_attr_builder *builder,
					bool free_contents,
					size_t *out_size)
{
	uint8_t *ret;

	if (builder->curlen > 0) {
		uint8_t *bytes = builder->buf + builder->offset;

		l_put_be16(builder->curlen - 4, bytes + 2);
		builder->offset += builder->curlen;
		builder->curlen = 0;
	}

	if (free_contents) {
		l_free(builder->buf);
		builder->buf = NULL;
	}

	ret = builder->buf;

	if (out_size)
		*out_size = builder->offset;

	l_free(builder);

	return ret;
}

static void build_ap_setup_locked(struct wsc_attr_builder *builder, bool locked)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_AP_SETUP_LOCKED);
	wsc_attr_builder_put_u8(builder, locked ? 0x01 : 0x00);
}

static void build_association_state(struct wsc_attr_builder *builder,
					enum wsc_association_state state)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_ASSOCIATION_STATE);
	wsc_attr_builder_put_u16(builder, state);
}

static void build_authentication_type(struct wsc_attr_builder *builder,
							uint16_t auth_type)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_AUTHENTICATION_TYPE);
	wsc_attr_builder_put_u16(builder, auth_type);
}

static void build_authentication_type_flags(struct wsc_attr_builder *builder,
					uint16_t auth_type_flags)
{
	wsc_attr_builder_start_attr(builder,
					WSC_ATTR_AUTHENTICATION_TYPE_FLAGS);
	wsc_attr_builder_put_u16(builder, auth_type_flags);
}

static void build_authenticator(struct wsc_attr_builder *builder,
					const uint8_t *authenticator)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_AUTHENTICATOR);
	wsc_attr_builder_put_bytes(builder, authenticator, 8);
}

static void build_configuration_error(struct wsc_attr_builder *builder,
					enum wsc_configuration_error error)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_CONFIGURATION_ERROR);
	wsc_attr_builder_put_u16(builder, error);
}

static void build_configuration_methods(struct wsc_attr_builder *builder,
						uint16_t config_methods)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_CONFIGURATION_METHODS);
	wsc_attr_builder_put_u16(builder, config_methods);
}

static void build_connection_type_flags(struct wsc_attr_builder *builder,
						uint8_t connection_type_flags)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_CONNECTION_TYPE_FLAGS);
	wsc_attr_builder_put_u8(builder, connection_type_flags);
}

static void build_device_name(struct wsc_attr_builder *builder,
						const char *device_name)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_DEVICE_NAME);
	wsc_attr_builder_put_string(builder, device_name);
}

static void build_device_password_id(struct wsc_attr_builder *builder,
					enum wsc_device_password_id id)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_DEVICE_PASSWORD_ID);
	wsc_attr_builder_put_u16(builder, id);
}

static void build_encryption_type(struct wsc_attr_builder *builder,
						uint16_t encryption_type)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_ENCRYPTION_TYPE);
	wsc_attr_builder_put_u16(builder, encryption_type);
}

static void build_encryption_type_flags(struct wsc_attr_builder *builder,
						uint16_t encryption_type_flags)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_ENCRYPTION_TYPE_FLAGS);
	wsc_attr_builder_put_u16(builder, encryption_type_flags);
}

static void build_e_hash1(struct wsc_attr_builder *builder,
							const uint8_t *e_hash1)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_E_HASH1);
	wsc_attr_builder_put_bytes(builder, e_hash1, 32);
}

static void build_e_hash2(struct wsc_attr_builder *builder,
							const uint8_t *e_hash2)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_E_HASH2);
	wsc_attr_builder_put_bytes(builder, e_hash2, 32);
}

static void build_e_snonce1(struct wsc_attr_builder *builder,
							const uint8_t *nonce)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_E_SNONCE1);
	wsc_attr_builder_put_bytes(builder, nonce, 16);
}

static void build_e_snonce2(struct wsc_attr_builder *builder,
							const uint8_t *nonce)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_E_SNONCE2);
	wsc_attr_builder_put_bytes(builder, nonce, 16);
}

static void build_enrollee_nonce(struct wsc_attr_builder *builder,
							const uint8_t *nonce)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_ENROLLEE_NONCE);
	wsc_attr_builder_put_bytes(builder, nonce, 16);
}

static void build_key_wrap_authenticator(struct wsc_attr_builder *builder,
						const uint8_t *authenticator)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_KEY_WRAP_AUTHENTICATOR);
	wsc_attr_builder_put_bytes(builder, authenticator, 8);
}

static void build_mac_address(struct wsc_attr_builder *builder,
							const uint8_t *addr)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_MAC_ADDRESS);
	wsc_attr_builder_put_bytes(builder, addr, 6);
}

static void build_manufacturer(struct wsc_attr_builder *builder,
						const char *manufacturer)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_MANUFACTURER);
	wsc_attr_builder_put_string(builder, manufacturer);
}

static void build_message_type(struct wsc_attr_builder *builder,
						enum wsc_message_type type)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_MESSAGE_TYPE);
	wsc_attr_builder_put_u8(builder, type);
}

static void build_model_name(struct wsc_attr_builder *builder,
						const char *model_name)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_MODEL_NAME);
	wsc_attr_builder_put_string(builder, model_name);
}

static void build_model_number(struct wsc_attr_builder *builder,
						const char *model_number)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_MODEL_NUMBER);
	wsc_attr_builder_put_string(builder, model_number);
}

static void build_network_index(struct wsc_attr_builder *builder,
							uint8_t network_index)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_NETWORK_INDEX);
	wsc_attr_builder_put_u8(builder, network_index);
}

static void build_network_key(struct wsc_attr_builder *builder,
					const uint8_t *key, size_t key_len)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_NETWORK_KEY);
	wsc_attr_builder_put_bytes(builder, key, key_len);
}

static void build_new_password(struct wsc_attr_builder *builder,
				const uint8_t *password, size_t password_len)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_NEW_PASSWORD);
	wsc_attr_builder_put_bytes(builder, password, password_len);
}

static void build_os_version(struct wsc_attr_builder *builder,
							uint32_t os_version)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_OS_VERSION);
	wsc_attr_builder_put_u32(builder, os_version | 0x80000000);
}

static void build_primary_device_type(struct wsc_attr_builder *builder,
				const struct wsc_primary_device_type *pdt)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_PRIMARY_DEVICE_TYPE);
	wsc_attr_builder_put_u16(builder, pdt->category);
	wsc_attr_builder_put_oui(builder, pdt->oui);
	wsc_attr_builder_put_u8(builder, pdt->oui_type);
	wsc_attr_builder_put_u16(builder, pdt->subcategory);
}

static void build_public_key(struct wsc_attr_builder *builder,
						const uint8_t *public_key)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_PUBLIC_KEY);
	wsc_attr_builder_put_bytes(builder, public_key, 192);
}

static void build_registrar_nonce(struct wsc_attr_builder *builder,
							const uint8_t *nonce)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_REGISTRAR_NONCE);
	wsc_attr_builder_put_bytes(builder, nonce, 16);
}

static void build_request_type(struct wsc_attr_builder *builder,
						enum wsc_request_type type)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_REQUEST_TYPE);
	wsc_attr_builder_put_u8(builder, type);
}

static void build_response_type(struct wsc_attr_builder *builder,
						enum wsc_response_type type)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_RESPONSE_TYPE);
	wsc_attr_builder_put_u8(builder, type);
}

static void build_rf_bands(struct wsc_attr_builder *builder, uint8_t rf_bands)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_RF_BANDS);
	wsc_attr_builder_put_u8(builder, rf_bands);
}

static void build_r_hash1(struct wsc_attr_builder *builder,
							const uint8_t *r_hash1)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_R_HASH1);
	wsc_attr_builder_put_bytes(builder, r_hash1, 32);
}

static void build_r_hash2(struct wsc_attr_builder *builder,
							const uint8_t *r_hash2)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_R_HASH2);
	wsc_attr_builder_put_bytes(builder, r_hash2, 32);
}

static void build_r_snonce1(struct wsc_attr_builder *builder,
							const uint8_t *nonce)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_R_SNONCE1);
	wsc_attr_builder_put_bytes(builder, nonce, 16);
}

static void build_r_snonce2(struct wsc_attr_builder *builder,
							const uint8_t *nonce)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_R_SNONCE2);
	wsc_attr_builder_put_bytes(builder, nonce, 16);
}

static void build_selected_registrar(struct wsc_attr_builder *builder,
							bool selected)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_SELECTED_REGISTRAR);
	wsc_attr_builder_put_u8(builder, selected ? 0x01 : 0x00);
}

static void build_selected_registrar_configuration_methods(
					struct wsc_attr_builder *builder,
					uint16_t config_methods)
{
	wsc_attr_builder_start_attr(builder,
			WSC_ATTR_SELECTED_REGISTRAR_CONFIGURATION_METHODS);
	wsc_attr_builder_put_u16(builder, config_methods);
}

static void build_ssid(struct wsc_attr_builder *builder, const uint8_t *ssid,
							size_t ssid_len)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_SSID);
	wsc_attr_builder_put_bytes(builder, ssid, ssid_len);
}

static void build_serial_number(struct wsc_attr_builder *builder,
						const char *serial_number)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_SERIAL_NUMBER);
	wsc_attr_builder_put_string(builder, serial_number);
}

static void build_uuid_e(struct wsc_attr_builder *builder, const uint8_t *uuid)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_UUID_E);
	wsc_attr_builder_put_bytes(builder, uuid, 16);
}

static void build_uuid_r(struct wsc_attr_builder *builder, const uint8_t *uuid)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_UUID_R);
	wsc_attr_builder_put_bytes(builder, uuid, 16);
}

static void build_version(struct wsc_attr_builder *builder, uint8_t version)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_VERSION);
	wsc_attr_builder_put_u8(builder, version);
}

static void build_wsc_state(struct wsc_attr_builder *builder,
					enum wsc_state state)
{
	wsc_attr_builder_start_attr(builder, WSC_ATTR_WSC_STATE);
	wsc_attr_builder_put_u8(builder, state);
}

#define START_WFA_VENDOR_EXTENSION()					\
	wsc_attr_builder_start_attr(builder, WSC_ATTR_VENDOR_EXTENSION);\
	wsc_attr_builder_put_oui(builder, wsc_wfa_oui);			\
	wsc_attr_builder_put_u8(builder, WSC_WFA_EXTENSION_VERSION2);	\
	wsc_attr_builder_put_u8(builder, 1);				\
	wsc_attr_builder_put_u8(builder, 0x20)

static void wfa_build_authorized_macs(struct wsc_attr_builder *builder,
				const uint8_t authorized_macs[static 30])
{
	int count;

	for (count = 1; count < 5; count++)
		if (l_memeqzero(authorized_macs + count * 6, 6))
			break;

	wsc_attr_builder_put_u8(builder, WSC_WFA_EXTENSION_AUTHORIZED_MACS);
	wsc_attr_builder_put_u8(builder, count * 6);
	wsc_attr_builder_put_bytes(builder, authorized_macs, count * 6);
}

uint8_t *wsc_build_credential(const struct wsc_credential *in, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(128);
	build_network_index(builder, 1);
	build_ssid(builder, in->ssid, in->ssid_len);
	build_authentication_type(builder, in->auth_type);
	build_encryption_type(builder, in->encryption_type);
	build_network_key(builder, in->network_key, in->network_key_len);
	build_mac_address(builder, in->addr);

	/* TODO: Append EAP attrs & Network Key Shareable inside WFA EXT */

	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

static void build_credential(struct wsc_attr_builder *builder,
					const struct wsc_credential *cred)
{
	size_t data_len;
	uint8_t *data = wsc_build_credential(cred, &data_len);

	wsc_attr_builder_start_attr(builder, WSC_ATTR_CREDENTIAL);
	wsc_attr_builder_put_bytes(builder, data, data_len);
	l_free(data);
}

uint8_t *wsc_build_beacon(const struct wsc_beacon *beacon, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(512);
	build_version(builder, 0x10);
	build_wsc_state(builder, beacon->state);

	if (beacon->ap_setup_locked)
		build_ap_setup_locked(builder, true);

	if (beacon->selected_registrar) {
		build_selected_registrar(builder, true);
		build_device_password_id(builder, beacon->device_password_id);
		build_selected_registrar_configuration_methods(builder,
					beacon->selected_reg_config_methods);
	}

	/* These two "should be provided" if dual-band */
	if (__builtin_popcount(beacon->rf_bands) > 1) {
		if (beacon->selected_registrar)
			build_uuid_e(builder, beacon->uuid_e);

		build_rf_bands(builder, beacon->rf_bands);
	}

	if (!beacon->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

	if (!l_memeqzero(beacon->authorized_macs, 6))
		wfa_build_authorized_macs(builder, beacon->authorized_macs);

	if (beacon->reg_config_methods) {
		wsc_attr_builder_put_u8(builder,
			WSC_WFA_EXTENSION_REGISTRAR_CONFIGRATION_METHODS);
		wsc_attr_builder_put_u8(builder, 2);
		wsc_attr_builder_put_u16(builder, beacon->reg_config_methods);
	}

done:
	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_probe_request(const struct wsc_probe_request *probe_request,
							size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(512);
	build_version(builder, 0x10);
	build_request_type(builder, probe_request->request_type);
	build_configuration_methods(builder, probe_request->config_methods);
	build_uuid_e(builder, probe_request->uuid_e);
	build_primary_device_type(builder, &probe_request->primary_device_type);
	build_rf_bands(builder, probe_request->rf_bands);
	build_association_state(builder, probe_request->association_state);
	build_configuration_error(builder, probe_request->configuration_error);
	build_device_password_id(builder, probe_request->device_password_id);

	if (!probe_request->version2)
		goto done;

	build_manufacturer(builder, probe_request->manufacturer);
	build_model_name(builder, probe_request->model_name);
	build_model_number(builder, probe_request->model_number);
	build_device_name(builder, probe_request->device_name);

	START_WFA_VENDOR_EXTENSION();

	if (!probe_request->request_to_enroll)
		goto done;

	wsc_attr_builder_put_u8(builder, WSC_WFA_EXTENSION_REQUEST_TO_ENROLL);
	wsc_attr_builder_put_u8(builder, 1);
	wsc_attr_builder_put_u8(builder, 1);

done:
	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_probe_response(
		const struct wsc_probe_response *probe_response,
		size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(512);
	build_version(builder, 0x10);
	build_wsc_state(builder, probe_response->state);

	if (probe_response->ap_setup_locked)
		build_ap_setup_locked(builder, true);

	if (probe_response->selected_registrar) {
		build_selected_registrar(builder, true);
		build_device_password_id(builder,
				probe_response->device_password_id);
		build_selected_registrar_configuration_methods(builder,
				probe_response->selected_reg_config_methods);
	}

	build_response_type(builder, probe_response->response_type);
	build_uuid_e(builder, probe_response->uuid_e);
	build_manufacturer(builder, probe_response->manufacturer);
	build_model_name(builder, probe_response->model_name);
	build_model_number(builder, probe_response->model_number);
	build_serial_number(builder, probe_response->serial_number);
	build_primary_device_type(builder,
					&probe_response->primary_device_type);
	build_device_name(builder, probe_response->device_name);
	build_configuration_methods(builder, probe_response->config_methods);

	if (__builtin_popcount(probe_response->rf_bands) > 1)
		build_rf_bands(builder, probe_response->rf_bands);

	if (!probe_response->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

	if (!l_memeqzero(probe_response->authorized_macs, 6))
		wfa_build_authorized_macs(builder,
					probe_response->authorized_macs);

	if (probe_response->reg_config_methods) {
		wsc_attr_builder_put_u8(builder,
			WSC_WFA_EXTENSION_REGISTRAR_CONFIGRATION_METHODS);
		wsc_attr_builder_put_u8(builder, 2);
		wsc_attr_builder_put_u16(builder,
					probe_response->reg_config_methods);
	}

done:
	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_association_request(
		const struct wsc_association_request *association_request,
		size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(128);
	build_version(builder, 0x10);
	build_request_type(builder, association_request->request_type);

	if (!association_request->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_association_response(
		const struct wsc_association_response *association_response,
		size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(128);
	build_version(builder, 0x10);
	build_response_type(builder, association_response->response_type);

	if (!association_response->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_m1(const struct wsc_m1 *m1, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(1024);
	build_version(builder, 0x10);
	build_message_type(builder, WSC_MESSAGE_TYPE_M1);
	build_uuid_e(builder, m1->uuid_e);
	build_mac_address(builder, m1->addr);
	build_enrollee_nonce(builder, m1->enrollee_nonce);
	build_public_key(builder, m1->public_key);
	build_authentication_type_flags(builder, m1->auth_type_flags);
	build_encryption_type_flags(builder, m1->encryption_type_flags);
	build_connection_type_flags(builder, m1->connection_type_flags);
	build_configuration_methods(builder, m1->config_methods);
	build_wsc_state(builder, m1->state);
	build_manufacturer(builder, m1->manufacturer);
	build_model_name(builder, m1->model_name);
	build_model_number(builder, m1->model_number);
	build_serial_number(builder, m1->serial_number);
	build_primary_device_type(builder, &m1->primary_device_type);
	build_device_name(builder, m1->device_name);
	build_rf_bands(builder, m1->rf_bands);
	build_association_state(builder, m1->association_state);
	build_device_password_id(builder, m1->device_password_id);
	build_configuration_error(builder, m1->configuration_error);
	build_os_version(builder, m1->os_version);

	if (!m1->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

	if (!m1->request_to_enroll)
		goto done;

	wsc_attr_builder_put_u8(builder, WSC_WFA_EXTENSION_REQUEST_TO_ENROLL);
	wsc_attr_builder_put_u8(builder, 1);
	wsc_attr_builder_put_u8(builder, 1);

done:
	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_m2(const struct wsc_m2 *m2, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(1024);
	build_version(builder, 0x10);
	build_message_type(builder, WSC_MESSAGE_TYPE_M2);
	build_enrollee_nonce(builder, m2->enrollee_nonce);
	build_registrar_nonce(builder, m2->registrar_nonce);
	build_uuid_r(builder, m2->uuid_r);
	build_public_key(builder, m2->public_key);
	build_authentication_type_flags(builder, m2->auth_type_flags);
	build_encryption_type_flags(builder, m2->encryption_type_flags);
	build_connection_type_flags(builder, m2->connection_type_flags);
	build_configuration_methods(builder, m2->config_methods);
	build_manufacturer(builder, m2->manufacturer);
	build_model_name(builder, m2->model_name);
	build_model_number(builder, m2->model_number);
	build_serial_number(builder, m2->serial_number);
	build_primary_device_type(builder, &m2->primary_device_type);
	build_device_name(builder, m2->device_name);
	build_rf_bands(builder, m2->rf_bands);
	build_association_state(builder, m2->association_state);
	build_configuration_error(builder, m2->configuration_error);
	build_device_password_id(builder, m2->device_password_id);
	build_os_version(builder, m2->os_version);

	if (!m2->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	build_authenticator(builder, m2->authenticator);

	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_m3(const struct wsc_m3 *m3, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(256);
	build_version(builder, 0x10);
	build_message_type(builder, WSC_MESSAGE_TYPE_M3);
	build_registrar_nonce(builder, m3->registrar_nonce);
	build_e_hash1(builder, m3->e_hash1);
	build_e_hash2(builder, m3->e_hash2);

	if (!m3->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	build_authenticator(builder, m3->authenticator);

	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_m4(const struct wsc_m4 *m4, const uint8_t *encrypted,
			size_t encrypted_len, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(256);
	build_version(builder, 0x10);
	build_message_type(builder, WSC_MESSAGE_TYPE_M4);
	build_enrollee_nonce(builder, m4->enrollee_nonce);
	build_r_hash1(builder, m4->r_hash1);
	build_r_hash2(builder, m4->r_hash2);

	wsc_attr_builder_start_attr(builder, WSC_ATTR_ENCRYPTED_SETTINGS);
	wsc_attr_builder_put_bytes(builder, encrypted, encrypted_len);

	if (!m4->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	build_authenticator(builder, m4->authenticator);

	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_m4_encrypted_settings(
				const struct wsc_m4_encrypted_settings *in,
				size_t *out_len)
{
	struct wsc_attr_builder *builder;

	builder = wsc_attr_builder_new(256);
	build_r_snonce1(builder, in->r_snonce1);
	build_key_wrap_authenticator(builder, in->authenticator);

	return wsc_attr_builder_free(builder, false, out_len);
}

uint8_t *wsc_build_m5(const struct wsc_m5 *m5, const uint8_t *encrypted,
			size_t encrypted_len, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(256);
	build_version(builder, 0x10);
	build_message_type(builder, WSC_MESSAGE_TYPE_M5);
	build_registrar_nonce(builder, m5->registrar_nonce);

	wsc_attr_builder_start_attr(builder, WSC_ATTR_ENCRYPTED_SETTINGS);
	wsc_attr_builder_put_bytes(builder, encrypted, encrypted_len);

	if (!m5->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	build_authenticator(builder, m5->authenticator);

	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_m5_encrypted_settings(
				const struct wsc_m5_encrypted_settings *in,
				size_t *out_len)
{
	struct wsc_attr_builder *builder;

	builder = wsc_attr_builder_new(256);
	build_e_snonce1(builder, in->e_snonce1);
	build_key_wrap_authenticator(builder, in->authenticator);

	return wsc_attr_builder_free(builder, false, out_len);
}

uint8_t *wsc_build_m6(const struct wsc_m6 *m6, const uint8_t *encrypted,
			size_t encrypted_len, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(256);
	build_version(builder, 0x10);
	build_message_type(builder, WSC_MESSAGE_TYPE_M6);
	build_enrollee_nonce(builder, m6->enrollee_nonce);

	wsc_attr_builder_start_attr(builder, WSC_ATTR_ENCRYPTED_SETTINGS);
	wsc_attr_builder_put_bytes(builder, encrypted, encrypted_len);

	if (!m6->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	build_authenticator(builder, m6->authenticator);

	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_m6_encrypted_settings(
				const struct wsc_m6_encrypted_settings *in,
				size_t *out_len)
{
	struct wsc_attr_builder *builder;

	builder = wsc_attr_builder_new(256);
	build_r_snonce2(builder, in->r_snonce2);
	build_key_wrap_authenticator(builder, in->authenticator);

	return wsc_attr_builder_free(builder, false, out_len);
}

uint8_t *wsc_build_m7(const struct wsc_m7 *m7, const uint8_t *encrypted,
			size_t encrypted_len, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(256);
	build_version(builder, 0x10);
	build_message_type(builder, WSC_MESSAGE_TYPE_M7);
	build_registrar_nonce(builder, m7->registrar_nonce);

	wsc_attr_builder_start_attr(builder, WSC_ATTR_ENCRYPTED_SETTINGS);
	wsc_attr_builder_put_bytes(builder, encrypted, encrypted_len);

	if (!m7->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	build_authenticator(builder, m7->authenticator);

	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_m7_encrypted_settings(
				const struct wsc_m7_encrypted_settings *in,
				size_t *out_len)
{
	struct wsc_attr_builder *builder;

	builder = wsc_attr_builder_new(256);
	build_e_snonce2(builder, in->e_snonce2);
	build_key_wrap_authenticator(builder, in->authenticator);

	return wsc_attr_builder_free(builder, false, out_len);
}

uint8_t *wsc_build_m8(const struct wsc_m8 *m8, const uint8_t *encrypted,
			size_t encrypted_len, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(256);
	build_version(builder, 0x10);
	build_message_type(builder, WSC_MESSAGE_TYPE_M8);
	build_enrollee_nonce(builder, m8->enrollee_nonce);

	wsc_attr_builder_start_attr(builder, WSC_ATTR_ENCRYPTED_SETTINGS);
	wsc_attr_builder_put_bytes(builder, encrypted, encrypted_len);

	if (!m8->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	build_authenticator(builder, m8->authenticator);

	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_m8_encrypted_settings(
				const struct wsc_m8_encrypted_settings *in,
				const struct wsc_credential *creds,
				unsigned int creds_cnt, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	unsigned int i;

	builder = wsc_attr_builder_new(256);

	for (i = 0; i < creds_cnt; i++)
		build_credential(builder, &creds[i]);

	if (in->new_password_len) {
		build_new_password(builder, in->new_password,
					in->new_password_len);
		build_device_password_id(builder, in->device_password_id);
	}

	build_key_wrap_authenticator(builder, in->authenticator);

	return wsc_attr_builder_free(builder, false, out_len);
}

uint8_t *wsc_build_wsc_ack(const struct wsc_ack *ack, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(256);
	build_version(builder, 0x10);
	build_message_type(builder, WSC_MESSAGE_TYPE_WSC_ACK);
	build_enrollee_nonce(builder, ack->enrollee_nonce);
	build_registrar_nonce(builder, ack->registrar_nonce);

	if (!ack->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_wsc_nack(const struct wsc_nack *nack, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(256);
	build_version(builder, 0x10);
	build_message_type(builder, WSC_MESSAGE_TYPE_WSC_NACK);
	build_enrollee_nonce(builder, nack->enrollee_nonce);
	build_registrar_nonce(builder, nack->registrar_nonce);
	build_configuration_error(builder, nack->configuration_error);

	if (!nack->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_wsc_done(const struct wsc_done *done, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(256);
	build_version(builder, 0x10);
	build_message_type(builder, WSC_MESSAGE_TYPE_WSC_DONE);
	build_enrollee_nonce(builder, done->enrollee_nonce);
	build_registrar_nonce(builder, done->registrar_nonce);

	if (!done->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

uint8_t *wsc_build_p2p_attrs(const struct wsc_p2p_attrs *attrs, size_t *out_len)
{
	struct wsc_attr_builder *builder;
	uint8_t *ret;

	builder = wsc_attr_builder_new(512);

	if (attrs->version)
		build_version(builder, 0x10);

	if (attrs->device_password_id)
		build_device_password_id(builder, attrs->device_password_id);

	if (attrs->config_methods)
		build_configuration_methods(builder, attrs->config_methods);

	if (!attrs->version2)
		goto done;

	START_WFA_VENDOR_EXTENSION();

done:
	ret = wsc_attr_builder_free(builder, false, out_len);
	return ret;
}

bool wsc_uuid_from_addr(const uint8_t addr[], uint8_t *out_uuid)
{
	/* Reuse the NSID from WPA Supplicant for compatibility */
	static const uint8_t nsid[] = {
		0x52, 0x64, 0x80, 0xf8, 0xc9, 0x9b, 0x4b, 0xe5,
		0xa6, 0x55, 0x58, 0xed, 0x5f, 0x5d, 0x60, 0x84,
	};

	return l_uuid_v5(nsid, addr, 6, out_uuid);
}

/* WSC 2.0.5, Section 7.3 */
bool wsc_kdf(const void *key, void *output, size_t size)
{
	static char *personalization = "Wi-Fi Easy and Secure Key Derivation";
	struct l_checksum *hmac;
	unsigned int i, offset = 0;
	unsigned int counter;
	uint8_t counter_be[4];
	uint8_t total_key_bits[4];
	struct iovec iov[3] = {
		[0] = { .iov_base = counter_be, .iov_len = 4 },
		[1] = { .iov_base = personalization,
					.iov_len = strlen(personalization) },
		[2] = { .iov_base = total_key_bits, .iov_len = 4 },
	};

	hmac = l_checksum_new_hmac(L_CHECKSUM_SHA256, key, 32);
	if (!hmac)
		return false;

	/* Length is denominated in bits, not bytes */
	l_put_be32(size * 8, total_key_bits);

	/* KDF processes in 256-bit chunks (32 bytes) */
	for (i = 0, counter = 1; i < (size + 31) / 32; i++, counter++) {
		size_t len;

		if (size - offset > 32)
			len = 32;
		else
			len = size - offset;

		l_put_be32(counter, counter_be);

		l_checksum_updatev(hmac, iov, 3);
		l_checksum_get_digest(hmac, output + offset, len);

		offset += len;
	}

	l_checksum_free(hmac);

	return true;
}

bool wsc_pin_is_valid(const char *pin)
{
	unsigned int i;

	for (i = 0; pin[i] >= '0' && pin[i] <= '9'; i++)
		;

	if (pin[i])
		return false;

	if (i != 8 && i != 4)
		return false;

	return true;
}

/* Takes the first 7 characters of a PIN as input and computes a check digit */
static char compute_check_digit(const char *pin)
{
	unsigned int accum = 0;
	unsigned int digit;

	accum += 3 * ((pin[0] - '0') % 10);
	accum += 1 * ((pin[1] - '0') % 10);
	accum += 3 * ((pin[2] - '0') % 10);
	accum += 1 * ((pin[3] - '0') % 10);
	accum += 3 * ((pin[4] - '0') % 10);
	accum += 1 * ((pin[5] - '0') % 10);
	accum += 3 * ((pin[6] - '0') % 10);

	digit = (10 - (accum % 10)) % 10;
	return '0' + digit;
}

/*
 * Validates the checksum digit and returns true if valid.  Assumes that the
 * input is an 8-byte PIN already validated by wsc_pin_is_valid()
 */
bool wsc_pin_is_checksum_valid(const char *pin)
{
	char digit = compute_check_digit(pin);
	return pin[7] == digit;
}

/*
 * Generate an 8 character PIN string into buffer given by @pin.  @pin must be
 * at least 9 bytes long to account for the nul character.
 */
bool wsc_pin_generate(char *pin)
{
	uint32_t random;
	bool ok;

	ok = l_getrandom(&random, sizeof(random));
	if (!ok)
		return ok;

	snprintf(pin, 8, "%07u", random);
	pin[7] = compute_check_digit(pin);
	pin[8] = '\0';

	return true;
}

struct device_type_category_info {
	const char *category_str;
	unsigned int subcategory_max;
	const char **subcategory_str;
};

/* WSC 2.0.5, Table 41 strings adapted to IWD DBus enum convention */
struct device_type_category_info device_type_categories[] = {
	[1] = {
		"computer",
		10,
		(const char *[]) {
			[1] = "pc",
			[2] = "server",
			[3] = "media-center",
			[4] = "ultra-mobile-pc",
			[5] = "notebook",
			[6] = "desktop",
			[7] = "mobile-internet-device",
			[8] = "netbook",
			[9] = "tablet",
			[10] = "ultrabook",
		},
	},
	[2] = {
		"input-device",
		9,
		(const char *[]) {
			[1] = "keyboard",
			[2] = "mouse",
			[3] = "joystick",
			[4] = "trackball",
			[5] = "gaming-controller",
			[6] = "remote",
			[7] = "touchscreen",
			[8] = "biometric-reader",
			[9] = "barcode-reader",
		},
	},
	[3] = {
		"printer-scanner",
		5,
		(const char *[]) {
			[1] = "printer-print-server",
			[2] = "scanner",
			[3] = "fax",
			[4] = "copier",
			[5] = "printer-scanner-fax-copier",
		},
	},
	[4] = {
		"camera",
		4,
		(const char *[]) {
			[1] = "digital-still-camera",
			[2] = "video-camera",
			[3] = "web-camera",
			[4] = "security-camera",
		},
	},
	[5] = {
		"storage",
		1,
		(const char *[]) {
			[1] = "nas",
		},
	},
	[6] = {
		"network-infrastructure",
		5,
		(const char *[]) {
			[1] = "ap",
			[2] = "router",
			[3] = "switch",
			[4] = "gateway",
			[5] = "bridge",
		},
	},
	[7] = {
		"display",
		4,
		(const char *[]) {
			[1] = "television",
			[2] = "electronic-picture-frame",
			[3] = "projector",
			[4] = "monitor",
		},
	},
	[8] = {
		"multimedia-device",
		6,
		(const char *[]) {
			[1] = "dar",
			[2] = "pvr",
			[3] = "mcx",
			[4] = "set-top-box",
			[5] = "media-server-adapter-extender",
			[6] = "portable-video-player",
		},
	},
	[9] = {
		"gaming-device",
		5,
		(const char *[]) {
			[1] = "xbox",
			[2] = "xbox360",
			[3] = "playstation",
			[4] = "game-console-adapter",
			[5] = "portable-gaming-device",
		},
	},
	[10] = {
		"telephone",
		5,
		(const char *[]) {
			[1] = "windows-mobile",
			[2] = "single-mode-phone",
			[3] = "dual-mode-phone",
			[4] = "single-mode-smartphone",
			[5] = "dual-mode-smartphone",
		},
	},
	[11] = {
		"audio-device",
		7,
		(const char *[]) {
			[1] = "audio-tuner-receiver",
			[2] = "speakers",
			[3] = "portable-music-player",
			[4] = "headset",
			[5] = "headphones",
			[6] = "microphone",
			[7] = "home-theater-system",
		},
	},
	[12] = {
		"docking-device",
		2,
		(const char *[]) {
			[1] = "computer-docking-station",
			[2] = "media-kiosk",
		},
	},
};

bool wsc_device_type_to_dbus_str(const struct wsc_primary_device_type *val,
					const char **category_str,
					const char **subcategory_str)
{
	struct device_type_category_info *cat;

	if (val->category >= L_ARRAY_SIZE(device_type_categories))
		return false;

	cat = &device_type_categories[val->category];

	if (!cat->category_str)
		return false;

	if (category_str)
		*category_str = cat->category_str;

	if (!subcategory_str)
		return true;

	if (memcmp(val->oui, microsoft_oui, 3) || val->oui_type != 4)
		*subcategory_str = NULL;	/* Vendor-specific */
	else if (val->subcategory <= cat->subcategory_max &&
			cat->subcategory_str[val->subcategory])
		*subcategory_str = cat->subcategory_str[val->subcategory];
	else
		*subcategory_str = NULL;	/* Unknown */

	return true;
}

bool wsc_device_type_from_subcategory_str(struct wsc_primary_device_type *out,
						const char *subcategory_str)
{
	struct device_type_category_info *cat = device_type_categories + 1;
	unsigned int i;

	for (i = 1; i < L_ARRAY_SIZE(device_type_categories); i++, cat++) {
		unsigned int j;

		for (j = 1; j <= cat->subcategory_max; j++)
			if (!strcasecmp(subcategory_str,
					cat->subcategory_str[j])) {
				out->category = i;
				memcpy(out->oui, microsoft_oui, 3);
				out->oui_type = 4;
				out->subcategory = j;
				return true;
			}
	}

	return false;
}

bool wsc_device_type_from_setting_str(const char *value,
					struct wsc_primary_device_type *out)
{
	unsigned long long u;
	char *endp;

	if (!value)
		return false;

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
	 * DeviceType=1-0050f204-1
	 */
	if (wsc_device_type_from_subcategory_str(out, value))
		return true;

	u = strtoull(value, &endp, 0);

	/*
	 * Accept any custom category, OUI and subcategory values but require
	 * non-zero category as a sanity check.
	 */
	if (*endp == '\0' && (u & 0xffff000000000000ll) != 0) {
		out->category = u >> 48;
		out->oui[0] = u >> 40;
		out->oui[1] = u >> 32;
		out->oui[2] = u >> 24;
		out->oui_type = u >> 16;
		out->subcategory = u;
		return true;
	}

	return sscanf(value, "%hx-%2hhx%2hhx%2hhx%2hhx-%2hx", &out->category,
			&out->oui[0], &out->oui[1], &out->oui[2],
			&out->oui_type, &out->subcategory) == 6;
}
