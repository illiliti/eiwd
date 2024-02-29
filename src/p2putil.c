/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

#include "src/p2putil.h"
#include "src/ie.h"

void p2p_attr_iter_init(struct p2p_attr_iter *iter, const uint8_t *pdu,
			size_t len)

{
	iter->pos = pdu;
	iter->end = pdu + len;
	iter->type = -1;
}

/* Wi-Fi P2P Technical Specification v1.7 Section 4.1.1 */
bool p2p_attr_iter_next(struct p2p_attr_iter *iter)
{
	if (iter->type != (enum p2p_attr) -1)
		iter->pos += 3 + iter->len;

	if (iter->pos + 3 > iter->end ||
			iter->pos + 3 + l_get_le16(iter->pos + 1) > iter->end)
		return false;

	iter->type = iter->pos[0];
	iter->len = l_get_le16(iter->pos + 1);
	return true;
}

void wfd_subelem_iter_init(struct wfd_subelem_iter *iter, const uint8_t *pdu,
				size_t len)
{
	iter->pos = pdu;
	iter->end = pdu + len;
	iter->type = -1;
}

bool wfd_subelem_iter_next(struct wfd_subelem_iter *iter)
{
	if (iter->type != (enum wfd_subelem_type) -1)
		iter->pos += 3 + iter->len;

	if (iter->pos + 3 > iter->end ||
			iter->pos + 3 + l_get_be16(iter->pos + 1) > iter->end)
		return false;

	iter->type = iter->pos[0];
	iter->len = l_get_be16(iter->pos + 1);
	return true;
}

enum attr_flag {
	ATTR_FLAG_REQUIRED  = 0x1,  /* Always required */
};

typedef bool (*attr_handler)(const uint8_t *, size_t, void *);

static bool extract_p2p_byte(const uint8_t *attr, size_t len,
				void *data)
{
	uint8_t *out = data;

	if (len != 1)
		return false;

	*out = attr[0];
	return true;
}

/* Section 4.1.2 */
static bool extract_p2p_status(const uint8_t *attr, size_t len,
				void *data)
{
	enum p2p_attr_status_code *out = data;

	if (len != 1)
		return false;

	*out = attr[0];
	return true;
}

/* Section 4.1.4 */
static bool extract_p2p_capability(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_capability_attr *out = data;

	if (len != 2)
		return false;

	out->device_caps = attr[0];
	out->group_caps = attr[1];
	return true;
}

/* Section 4.1.5, 4.1.9, 4.1.11, ... */
static bool extract_p2p_addr(const uint8_t *attr, size_t len,
				void *data)
{
	uint8_t *out = data;

	if (len != 6)
		return false;

	memcpy(out, attr, 6);
	return true;
}

struct p2p_go_intent_attr {
	uint8_t intent;
	bool tie_breaker;
};

/* Section 4.1.6 */
static bool extract_p2p_go_intent(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_go_intent_attr *out = data;
	uint8_t intent;

	if (len != 1)
		return false;

	intent = attr[0] >> 1;

	if (intent & ~15)
		return false;

	out->intent = intent;
	out->tie_breaker = attr[0] & 1;

	return true;
}

/* Section 4.1.7 */
static bool extract_p2p_config_timeout(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_config_timeout_attr *out = data;

	if (len != 2)
		return false;

	out->go_config_timeout = attr[0];
	out->client_config_timeout = attr[1];
	return true;
}

/* Section 4.1.8, 4.1.19, ... */
static bool extract_p2p_channel(const uint8_t *attr, size_t len,
				void *data)
{
	struct p2p_channel_attr *out = data;

	if (len != 5)
		return false;

	out->country[0] = attr[0];
	out->country[1] = attr[1];
	out->country[2] = attr[2];
	out->oper_class = attr[3];
	out->channel_num = attr[4];
	return true;
}

/* Section 4.1.10 */
static bool extract_p2p_listen_timing(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_extended_listen_timing_attr *out = data;

	if (len != 4)
		return false;

	out->avail_period_ms = l_get_le16(attr + 0);
	out->avail_interval_ms = l_get_le16(attr + 2);
	return true;
}

/* Section 4.1.13 */
static bool extract_p2p_channel_list(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_channel_list_attr *out = data;

	/*
	 * Some devices reply with an empty Channel Entry List inside the
	 * Channel List attribute of a GO Negotiation Response (status 1),
	 * so tolerate a length of 3.
	 */
	if (len < 3)
		return false;

	out->country[0] = *attr++;
	out->country[1] = *attr++;
	out->country[2] = *attr++;
	len -= 3;

	out->channel_entries = l_queue_new();

	while (len) {
		struct p2p_channel_entries *entries;

		if (len < 2 || len < (size_t) 2 + attr[1]) {
			l_queue_destroy(out->channel_entries, l_free);
			out->channel_entries = NULL;
			return false;
		}

		entries = l_malloc(sizeof(struct p2p_channel_entries) + attr[1]);
		entries->oper_class = *attr++;
		entries->n_channels = *attr++;
		memcpy(entries->channels, attr, entries->n_channels);
		l_queue_push_tail(out->channel_entries, entries);

		attr += entries->n_channels;
		len -= 2 + entries->n_channels;
	}

	return true;
}

/* Section 4.1.14 */
static bool extract_p2p_notice_of_absence(const uint8_t *attr, size_t len,
						void *data)
{
	struct p2p_notice_of_absence_attr *out = data;
	uint8_t index;
	uint8_t ct_window;
	bool opp_ps;

	if (len % 13 != 2)
		return false;

	index = *attr++;
	ct_window = *attr & 127;
	opp_ps = *attr++ >> 7;
	len -= 2;

	if (opp_ps && !ct_window)
		return false;

	out->index = index;
	out->opp_ps = opp_ps;
	out->ct_window = ct_window;
	out->descriptors = l_queue_new();

	while (len) {
		struct p2p_notice_of_absence_desc *desc;

		desc = l_new(struct p2p_notice_of_absence_desc, 1);
		desc->count_type = attr[0];
		desc->duration = l_get_le32(attr + 1);
		desc->interval = l_get_le32(attr + 5);
		desc->start_time = l_get_le32(attr + 9);
		l_queue_push_tail(out->descriptors, desc);

		attr += 13;
		len -= 13;
	}

	return true;
}

/* Section 4.1.15 */
static bool extract_p2p_device_info(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_device_info_attr *out = data;
	int r;
	int name_len;
	int i;
	int types_num;

	if (len < 21)
		return false;

	memcpy(out->device_addr, attr + 0, 6);
	out->wsc_config_methods = l_get_be16(attr + 6);

	r = wsc_parse_primary_device_type(attr + 8, 8,
						&out->primary_device_type);
	if (r < 0)
		return false;

	types_num = attr[16];
	if (len < 17u + types_num * 8 + 4)
		return false;

	if (l_get_be16(attr + 17 + types_num * 8) != WSC_ATTR_DEVICE_NAME)
		return false;

	name_len = l_get_be16(attr + 17 + types_num * 8 + 2);
	if (len < 17u + types_num * 8 + 4 + name_len || name_len > 32)
		return false;

	out->secondary_device_types = l_queue_new();

	for (i = 0; i < types_num; i++) {
		struct wsc_primary_device_type *device_type =
			l_new(struct wsc_primary_device_type, 1);

		l_queue_push_tail(out->secondary_device_types, device_type);

		r = wsc_parse_primary_device_type(attr + 17 + i * 8, 8,
							device_type);
		if (r < 0) {
			l_queue_destroy(out->secondary_device_types, l_free);
			out->secondary_device_types = NULL;
			return false;
		}
	}

	memcpy(out->device_name, attr + 17 + types_num * 8 + 4, name_len);

	return true;
}

static void p2p_clear_client_info_descriptor(void *data)
{
	struct p2p_client_info_descriptor *desc = data;

	l_queue_destroy(desc->secondary_device_types, l_free);
	l_free(desc);
}

/* Section 4.1.16 */
static bool extract_p2p_group_info(const uint8_t *attr, size_t len,
					void *data)
{
	struct l_queue **out = data;

	while (len) {
		uint8_t desc_len = *attr++;
		struct p2p_client_info_descriptor *desc;
		int r, name_len, i, types_num;

		if (len < 1u + desc_len)
			goto error;

		if (!*out)
			*out = l_queue_new();

		desc = l_new(struct p2p_client_info_descriptor, 1);
		l_queue_push_tail(*out, desc);

		memcpy(desc->device_addr, attr + 0, 6);
		memcpy(desc->interface_addr, attr + 6, 6);
		desc->device_caps = attr[12];
		desc->wsc_config_methods = l_get_be16(attr + 13);

		r = wsc_parse_primary_device_type(attr + 15, 8,
						&desc->primary_device_type);
		if (r < 0)
			goto error;

		types_num = attr[23];
		if (desc_len < 24 + types_num * 8 + 4)
			goto error;

		if (l_get_be16(attr + 24 + types_num * 8) !=
				WSC_ATTR_DEVICE_NAME)
			goto error;

		name_len = l_get_be16(attr + 24 + types_num * 8 + 2);
		if (desc_len < 24 + types_num * 8 + 4 + name_len ||
				name_len > 32)
			goto error;

		desc->secondary_device_types = l_queue_new();

		for (i = 0; i < types_num; i++) {
			struct wsc_primary_device_type *device_type =
				l_new(struct wsc_primary_device_type, 1);

			l_queue_push_tail(desc->secondary_device_types,
						device_type);

			r = wsc_parse_primary_device_type(attr + 24 + i * 8, 8,
								device_type);
			if (r < 0)
				goto error;
		}

		memcpy(desc->device_name, attr + 24 + types_num * 8 + 4,
			name_len);

		attr += 24 + types_num * 8 + 4 + name_len;
		len -= 1 + desc_len;
	}

	return true;

error:
	l_queue_destroy(*out, p2p_clear_client_info_descriptor);
	*out = NULL;

	return false;
}

/* Section 4.1.17, 4.1.29, ... */
static bool extract_p2p_group_id(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_group_id_attr *out = data;

	if (len < 6 || len > 38)
		return false;

	memcpy(out->device_addr, attr + 0, 6);
	memcpy(out->ssid, attr + 6, len - 6);
	return true;
}

/* Section 4.1.18 */
static bool extract_p2p_interface(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_interface_attr *out = data;
	int addr_count;

	if (len < 7)
		return false;

	addr_count = attr[6];

	if (len < 7u + addr_count * 6)
		return false;

	memcpy(out->device_addr, attr + 0, 6);
	out->interface_addrs = l_queue_new();
	attr += 7;

	while (addr_count--) {
		l_queue_push_tail(out->interface_addrs, l_memdup(attr, 6));
		attr += 6;
	}

	return true;
}

/* Section 4.1.20 */
static bool extract_p2p_invitation_flags(const uint8_t *attr, size_t len,
						void *data)
{
	bool *out = data;

	if (len != 1)
		return false;

	*out = attr[0] & 1; /* Invitation Type flag */
	return true;
}

/* Section 4.1.22 */
static bool extract_p2p_service_hashes(const uint8_t *attr, size_t len,
					void *data)
{
	struct l_queue **out = data;

	if (len % 6 != 0)
		return false;

	*out = l_queue_new();

	while (len) {
		l_queue_push_tail(*out, l_memdup(attr, 6));
		attr += 6;
		len -= 6;
	}

	return true;
}

/* Section 4.1.23 */
static bool extract_p2p_session_info(const uint8_t *attr, size_t len,
					void *data)
{
	struct p2p_session_info_data_attr *out = data;

	out->data_len = len;
	memcpy(out->data, data, len);
	return true;
}

/* Section 4.1.25 */
static bool extract_p2p_advertisement_id(const uint8_t *attr, size_t len,
						void *data)
{
	struct p2p_advertisement_id_info_attr *out = data;

	if (len != 10)
		return false;

	out->advertisement_id = l_get_le32(attr + 0);
	memcpy(out->service_mac_addr, attr + 4, 6);
	return true;
}

static void p2p_clear_advertised_service_descriptor(void *data)
{
	struct p2p_advertised_service_descriptor *desc = data;

	l_free(desc->service_name);
	l_free(desc);
}

/* Section 4.1.26 */
static bool extract_p2p_advertised_service_info(const uint8_t *attr, size_t len,
						void *data)
{
	struct l_queue **q = data;
	struct l_queue *out = NULL;

	while (len) {
		struct p2p_advertised_service_descriptor *desc;
		int name_len;

		if (len < 7)
			goto error;

		name_len = attr[6];
		if (len < 7u + name_len)
			goto error;

		if (!l_utf8_validate((const char *) attr + 7, name_len, NULL))
			goto error;

		if (!out)
			out = l_queue_new();

		desc = l_new(struct p2p_advertised_service_descriptor, 1);
		l_queue_push_tail(out, desc);

		desc->advertisement_id = l_get_le32(attr + 0);
		desc->wsc_config_methods = l_get_be16(attr + 4);
		desc->service_name = l_strndup((const char *) attr + 7,
						name_len);

		attr += 7 + name_len;
		len -= 7 + name_len;
	}

	*q = out;

	return true;

error:
	l_queue_destroy(out, p2p_clear_advertised_service_descriptor);
	return false;
}

/* Section 4.1.27 */
static bool extract_p2p_session_id(const uint8_t *attr, size_t len, void *data)
{
	struct p2p_session_id_info_attr *out = data;

	if (len != 10)
		return false;

	out->session_id = l_get_le32(attr + 0);
	memcpy(out->session_mac_addr, attr + 4, 6);
	return true;
}

/* Section 4.1.28 */
static bool extract_p2p_feature_capability(const uint8_t *attr, size_t len,
						void *data)
{
	enum p2p_asp_coordination_transport_protocol *out = data;

	if (len != 2)
		return false;

	if (attr[0] == 0x01)
		*out = P2P_ASP_TRANSPORT_UDP;
	else
		*out = P2P_ASP_TRANSPORT_UNKNOWN;

	return true;
}

static attr_handler handler_for_type(enum p2p_attr type)
{
	switch (type) {
	case P2P_ATTR_STATUS:
		return extract_p2p_status;
	case P2P_ATTR_MINOR_REASON_CODE:
		return extract_p2p_byte;
	case P2P_ATTR_P2P_CAPABILITY:
		return extract_p2p_capability;
	case P2P_ATTR_P2P_DEVICE_ID:
	case P2P_ATTR_P2P_GROUP_BSSID:
	case P2P_ATTR_INTENDED_P2P_INTERFACE_ADDR:
		return extract_p2p_addr;
	case P2P_ATTR_GO_INTENT:
		return extract_p2p_go_intent;
	case P2P_ATTR_CONFIGURATION_TIMEOUT:
		return extract_p2p_config_timeout;
	case P2P_ATTR_LISTEN_CHANNEL:
	case P2P_ATTR_OPERATING_CHANNEL:
		return extract_p2p_channel;
	case P2P_ATTR_EXTENDED_LISTEN_TIMING:
		return extract_p2p_listen_timing;
	case P2P_ATTR_P2P_MANAGEABILITY:
		break;
	case P2P_ATTR_CHANNEL_LIST:
		return extract_p2p_channel_list;
	case P2P_ATTR_NOTICE_OF_ABSENCE:
		return extract_p2p_notice_of_absence;
	case P2P_ATTR_P2P_DEVICE_INFO:
		return extract_p2p_device_info;
	case P2P_ATTR_P2P_GROUP_INFO:
		return extract_p2p_group_info;
	case P2P_ATTR_P2P_GROUP_ID:
	case P2P_ATTR_PERSISTENT_GROUP_INFO:
		return extract_p2p_group_id;
	case P2P_ATTR_P2P_INTERFACE:
		return extract_p2p_interface;
	case P2P_ATTR_INVITATION_FLAGS:
		return extract_p2p_invitation_flags;
	case P2P_ATTR_OOB_GO_NEGOTIATION_CHANNEL:
		break;
	case P2P_ATTR_SVC_HASH:
		return extract_p2p_service_hashes;
	case P2P_ATTR_SESSION_INFO_DATA_INFO:
		return extract_p2p_session_info;
	case P2P_ATTR_CONNECTION_CAPABILITY_INFO:
		return extract_p2p_byte;
	case P2P_ATTR_ADVERTISEMENT_ID_INFO:
		return extract_p2p_advertisement_id;
	case P2P_ATTR_ADVERTISED_SVC_INFO:
		return extract_p2p_advertised_service_info;
	case P2P_ATTR_SESSION_ID_INFO:
		return extract_p2p_session_id;
	case P2P_ATTR_FEATURE_CAPABILITY:
		return extract_p2p_feature_capability;
	case P2P_ATTR_VENDOR_SPECIFIC_ATTR:
		break;
	}

	return NULL;
}

struct attr_handler_entry {
	enum p2p_attr type;
	unsigned int flags;
	void *data;
	bool present;
};

/*
 * This function may find an error after having parsed part of the message
 * and may have allocated memory so the output needs to be deallocated
 * properly even on error return values.
 */
static int p2p_parse_attrs(const uint8_t *pdu, size_t len, int type, ...)
{
	struct p2p_attr_iter iter;
	uint8_t *p2p_data;
	ssize_t p2p_len;
	struct l_queue *entries;
	va_list args;
	bool have_required = true;
	bool parse_error = false;
	struct attr_handler_entry *entry;
	const struct l_queue_entry *e;

	p2p_data = ie_tlv_extract_p2p_payload(pdu, len, &p2p_len);
	if (!p2p_data)
		return p2p_len;

	p2p_attr_iter_init(&iter, p2p_data, p2p_len);

	va_start(args, type);

	entries = l_queue_new();

	while (type != -1) {
		entry = l_new(struct attr_handler_entry, 1);

		entry->type = type;
		entry->flags = va_arg(args, unsigned int);
		entry->data = va_arg(args, void *);

		type = va_arg(args, enum p2p_attr);
		l_queue_push_tail(entries, entry);
	}

	va_end(args);

	while (p2p_attr_iter_next(&iter)) {
		attr_handler handler;

		for (e = l_queue_get_entries(entries); e; e = e->next) {
			entry = e->data;

			if (p2p_attr_iter_get_type(&iter) == entry->type)
				break;
		}

		if (!e || entry->present) {
			parse_error = true;
			goto done;
		}

		entry->present = true;
		handler = handler_for_type(entry->type);

		if (!handler(p2p_attr_iter_get_data(&iter),
				p2p_attr_iter_get_length(&iter), entry->data)) {
			parse_error = true;
			goto done;
		}
	}

	for (e = l_queue_get_entries(entries); e; e = e->next) {
		entry = e->data;

		if (!entry->present && (entry->flags & ATTR_FLAG_REQUIRED)) {
			have_required = false;
			goto done;
		}
	}

done:
	l_free(p2p_data);
	l_queue_destroy(entries, l_free);

	if (!have_required)
		return -EINVAL;
	if (parse_error)
		return -EBADMSG;

	return 0;
}

#define REQUIRED(attr, out) \
	P2P_ATTR_ ## attr, ATTR_FLAG_REQUIRED, out

#define OPTIONAL(attr, out) \
	P2P_ATTR_ ## attr, 0, out

/* Section 4.2.1 */
int p2p_parse_beacon(const uint8_t *pdu, size_t len, struct p2p_beacon *out)
{
	struct p2p_beacon d = {0};
	int r;

	r = p2p_parse_attrs(pdu, len,
			REQUIRED(P2P_CAPABILITY, &d.capability),
			REQUIRED(P2P_DEVICE_ID, &d.device_addr),
			OPTIONAL(NOTICE_OF_ABSENCE, &d.notice_of_absence),
			-1);

	if (r >= 0)
		memcpy(out, &d, sizeof(d));
	else
		p2p_clear_beacon(&d);

	return r;
}

/* Section 4.2.2 */
int p2p_parse_probe_req(const uint8_t *pdu, size_t len,
			struct p2p_probe_req *out)
{
	struct p2p_probe_req d = {0};
	int r;

	r = p2p_parse_attrs(pdu, len,
			REQUIRED(P2P_CAPABILITY, &d.capability),
			OPTIONAL(P2P_DEVICE_ID, &d.device_addr),
			OPTIONAL(LISTEN_CHANNEL, &d.listen_channel),
			OPTIONAL(EXTENDED_LISTEN_TIMING,
					&d.listen_availability),
			OPTIONAL(P2P_DEVICE_INFO, &d.device_info),
			OPTIONAL(OPERATING_CHANNEL, &d.operating_channel),
			OPTIONAL(SVC_HASH, &d.service_hashes),
			-1);

	if (r >= 0)
		memcpy(out, &d, sizeof(d));
	else
		p2p_clear_probe_req(&d);

	/*
	 * The additional WSC IE attributes are already covered by
	 * wsc_parse_probe_request.
	 */

	return r;
}

/* Section 4.2.3 */
int p2p_parse_probe_resp(const uint8_t *pdu, size_t len,
				struct p2p_probe_resp *out)
{
	struct p2p_probe_resp d = {0};
	int r;

	r = p2p_parse_attrs(pdu, len,
			REQUIRED(P2P_CAPABILITY, &d.capability),
			OPTIONAL(EXTENDED_LISTEN_TIMING,
					&d.listen_availability),
			OPTIONAL(NOTICE_OF_ABSENCE, &d.notice_of_absence),
			REQUIRED(P2P_DEVICE_INFO, &d.device_info),
			OPTIONAL(P2P_GROUP_INFO, &d.group_clients),
			OPTIONAL(ADVERTISED_SVC_INFO, &d.advertised_svcs),
			-1);

	if (r >= 0)
		memcpy(out, &d, sizeof(d));
	else
		p2p_clear_probe_resp(&d);

	return r;
}

/* Section 4.2.4 */
int p2p_parse_association_req(const uint8_t *pdu, size_t len,
				struct p2p_association_req *out)
{
	struct p2p_association_req d = {0};
	int r;

	r = p2p_parse_attrs(pdu, len,
			REQUIRED(P2P_CAPABILITY, &d.capability),
			OPTIONAL(EXTENDED_LISTEN_TIMING,
					&d.listen_availability),
			OPTIONAL(P2P_DEVICE_INFO, &d.device_info),
			OPTIONAL(P2P_INTERFACE, &d.interface),
			-1);

	if (r >= 0)
		memcpy(out, &d, sizeof(d));
	else
		p2p_clear_association_req(&d);

	return r;
}

/* Section 4.2.5 */
int p2p_parse_association_resp(const uint8_t *pdu, size_t len,
				struct p2p_association_resp *out)
{
	struct p2p_association_resp d = {0};
	int r;

	r = p2p_parse_attrs(pdu, len,
			OPTIONAL(STATUS, &d.status),
			OPTIONAL(EXTENDED_LISTEN_TIMING,
					&d.listen_availability),
			-1);

	if (r >= 0)
		memcpy(out, &d, sizeof(d));

	return r;
}

/* Section 4.2.6 */
int p2p_parse_deauthentication(const uint8_t *pdu, size_t len,
				struct p2p_deauthentication *out)
{
	int r;
	uint8_t reason = 0;

	r = p2p_parse_attrs(pdu, len,
			REQUIRED(MINOR_REASON_CODE, &reason),
			-1);

	/* The P2P IE is optional */
	if (r < 0 && r != -ENOENT)
		return r;

	out->minor_reason_code = reason;
	return 0;
}

/* Section 4.2.7 */
int p2p_parse_disassociation(const uint8_t *pdu, size_t len,
				struct p2p_disassociation *out)
{
	int r;
	uint8_t reason = 0;

	r = p2p_parse_attrs(pdu, len,
			REQUIRED(MINOR_REASON_CODE, &reason),
			-1);

	/* The P2P IE is optional */
	if (r < 0 && r != -ENOENT)
		return r;

	out->minor_reason_code = reason;
	return 0;
}

#define WSC_REQUIRED(attr, out) \
	WSC_ATTR_ ## attr, WSC_ATTR_FLAG_REQUIRED, out

#define WSC_OPTIONAL(attr, out) \
	WSC_ATTR_ ## attr, 0, out

/* Section 4.2.9.2 */
int p2p_parse_go_negotiation_req(const uint8_t *pdu, size_t len,
					struct p2p_go_negotiation_req *out)
{
	struct p2p_go_negotiation_req d = {0};
	int r;
	struct p2p_go_intent_attr go_intent;
	uint8_t *wsc_data;
	ssize_t wsc_len;
	uint8_t wsc_version;

	if (len < 1)
		return -EINVAL;

	d.dialog_token = pdu[0];
	if (d.dialog_token == 0)
		return -EINVAL;

	r = p2p_parse_attrs(pdu + 1, len - 1,
			REQUIRED(P2P_CAPABILITY, &d.capability),
			REQUIRED(GO_INTENT, &go_intent),
			REQUIRED(CONFIGURATION_TIMEOUT, &d.config_timeout),
			REQUIRED(LISTEN_CHANNEL, &d.listen_channel),
			OPTIONAL(EXTENDED_LISTEN_TIMING,
					&d.listen_availability),
			REQUIRED(INTENDED_P2P_INTERFACE_ADDR,
					&d.intended_interface_addr),
			REQUIRED(CHANNEL_LIST, &d.channel_list),
			REQUIRED(P2P_DEVICE_INFO, &d.device_info),
			REQUIRED(OPERATING_CHANNEL, &d.operating_channel),
			-1);
	if (r < 0)
		goto error;

	wsc_data = ie_tlv_extract_wsc_payload(pdu + 1, len - 1, &wsc_len);
	if (!wsc_data) {
		r = wsc_len;
		goto error;
	}

	r = wsc_parse_attrs(wsc_data, wsc_len, NULL, NULL, 0, NULL,
			WSC_REQUIRED(VERSION, &wsc_version),
			WSC_REQUIRED(DEVICE_PASSWORD_ID, &d.device_password_id),
			WSC_ATTR_INVALID);
	l_free(wsc_data);

	if (r < 0)
		goto error;

	d.go_intent = go_intent.intent;
	d.go_tie_breaker = go_intent.tie_breaker;

	d.wfd = ie_tlv_extract_wfd_payload(pdu + 1, len - 1, &d.wfd_size);

	memcpy(out, &d, sizeof(d));
	return 0;

error:
	p2p_clear_go_negotiation_req(&d);
	return r;
}

/* Section 4.2.9.3 */
int p2p_parse_go_negotiation_resp(const uint8_t *pdu, size_t len,
					struct p2p_go_negotiation_resp *out)
{
	struct p2p_go_negotiation_resp d = {0};
	int r;
	struct p2p_go_intent_attr go_intent;
	uint8_t *wsc_data;
	ssize_t wsc_len;
	uint8_t wsc_version;

	if (len < 1)
		return -EINVAL;

	d.dialog_token = pdu[0];
	if (d.dialog_token == 0)
		return -EINVAL;

	r = p2p_parse_attrs(pdu + 1, len - 1,
			REQUIRED(STATUS, &d.status),
			REQUIRED(P2P_CAPABILITY, &d.capability),
			REQUIRED(GO_INTENT, &go_intent),
			REQUIRED(CONFIGURATION_TIMEOUT, &d.config_timeout),
			OPTIONAL(OPERATING_CHANNEL, &d.operating_channel),
			REQUIRED(INTENDED_P2P_INTERFACE_ADDR,
					&d.intended_interface_addr),
			REQUIRED(CHANNEL_LIST, &d.channel_list),
			REQUIRED(P2P_DEVICE_INFO, &d.device_info),
			OPTIONAL(P2P_GROUP_ID, &d.group_id),
			-1);
	if (r < 0)
		goto error;

	wsc_data = ie_tlv_extract_wsc_payload(pdu + 1, len - 1, &wsc_len);
	if (!wsc_data) {
		r = wsc_len;
		goto error;
	}

	r = wsc_parse_attrs(wsc_data, wsc_len, NULL, NULL, 0, NULL,
			WSC_REQUIRED(VERSION, &wsc_version),
			WSC_REQUIRED(DEVICE_PASSWORD_ID, &d.device_password_id),
			WSC_ATTR_INVALID);
	l_free(wsc_data);

	if (r < 0)
		goto error;

	d.go_intent = go_intent.intent;
	d.go_tie_breaker = go_intent.tie_breaker;

	d.wfd = ie_tlv_extract_wfd_payload(pdu + 1, len - 1, &d.wfd_size);

	memcpy(out, &d, sizeof(d));
	return 0;

error:
	p2p_clear_go_negotiation_resp(&d);
	return r;
}

/* Section 4.2.9.4 */
int p2p_parse_go_negotiation_confirmation(const uint8_t *pdu, size_t len,
				struct p2p_go_negotiation_confirmation *out)
{
	struct p2p_go_negotiation_confirmation d = {0};
	int r;

	if (len < 1)
		return -EINVAL;

	d.dialog_token = pdu[0];
	if (d.dialog_token == 0)
		return -EINVAL;

	r = p2p_parse_attrs(pdu + 1, len - 1,
			REQUIRED(STATUS, &d.status),
			REQUIRED(P2P_CAPABILITY, &d.capability),
			REQUIRED(OPERATING_CHANNEL, &d.operating_channel),
			REQUIRED(CHANNEL_LIST, &d.channel_list),
			OPTIONAL(P2P_GROUP_ID, &d.group_id),
			-1);
	if (r < 0)
		goto error;

	d.wfd = ie_tlv_extract_wfd_payload(pdu + 1, len - 1, &d.wfd_size);

	memcpy(out, &d, sizeof(d));
	return 0;

error:
	p2p_clear_go_negotiation_confirmation(&d);
	return r;
}

/* Section 4.2.9.5 */
int p2p_parse_invitation_req(const uint8_t *pdu, size_t len,
				struct p2p_invitation_req *out)
{
	struct p2p_invitation_req d = {0};
	int r;
	uint8_t *wsc_data;
	ssize_t wsc_len;
	bool wsc_version2;

	if (len < 1)
		return -EINVAL;

	d.dialog_token = pdu[0];
	if (d.dialog_token == 0)
		return -EINVAL;

	r = p2p_parse_attrs(pdu + 1, len - 1,
			REQUIRED(CONFIGURATION_TIMEOUT, &d.config_timeout),
			REQUIRED(INVITATION_FLAGS,
					&d.reinvoke_persistent_group),
			OPTIONAL(OPERATING_CHANNEL, &d.operating_channel),
			OPTIONAL(P2P_GROUP_BSSID, &d.group_bssid),
			REQUIRED(CHANNEL_LIST, &d.channel_list),
			REQUIRED(P2P_GROUP_ID, &d.group_id),
			REQUIRED(P2P_DEVICE_INFO, &d.device_info),
			-1);
	if (r < 0)
		goto error;

	/* A WSC IE is optional */
	wsc_data = ie_tlv_extract_wsc_payload(pdu + 1, len - 1, &wsc_len);
	if (wsc_data) {
		r = wsc_parse_attrs(
			wsc_data, wsc_len, &wsc_version2, NULL, 0, NULL,
			WSC_REQUIRED(DEVICE_PASSWORD_ID, &d.device_password_id),
			WSC_ATTR_INVALID);
		l_free(wsc_data);

		if (r >= 0 && !wsc_version2) {
			r = -EINVAL;
			goto error;
		}
	}

	d.wfd = ie_tlv_extract_wfd_payload(pdu + 1, len - 1, &d.wfd_size);

	memcpy(out, &d, sizeof(d));
	return 0;

error:
	p2p_clear_invitation_req(&d);
	return r;
}

/* Section 4.2.9.6 */
int p2p_parse_invitation_resp(const uint8_t *pdu, size_t len,
				struct p2p_invitation_resp *out)
{
	struct p2p_invitation_resp d = {0};
	int r;

	if (len < 1)
		return -EINVAL;

	d.dialog_token = pdu[0];
	if (d.dialog_token == 0)
		return -EINVAL;

	r = p2p_parse_attrs(pdu + 1, len - 1,
			REQUIRED(STATUS, &d.status),
			REQUIRED(CONFIGURATION_TIMEOUT, &d.config_timeout),
			OPTIONAL(OPERATING_CHANNEL, &d.operating_channel),
			OPTIONAL(P2P_GROUP_BSSID, &d.group_bssid),
			OPTIONAL(CHANNEL_LIST, &d.channel_list),
			-1);
	if (r < 0)
		goto error;

	d.wfd = ie_tlv_extract_wfd_payload(pdu + 1, len - 1, &d.wfd_size);

	memcpy(out, &d, sizeof(d));
	return 0;

error:
	p2p_clear_invitation_resp(&d);
	return r;
}

/* Section 4.2.9.7 */
int p2p_parse_device_disc_req(const uint8_t *pdu, size_t len,
				struct p2p_device_discoverability_req *out)
{
	struct p2p_device_discoverability_req d = {0};
	int r;

	if (len < 1)
		return -EINVAL;

	d.dialog_token = pdu[0];
	if (d.dialog_token == 0)
		return -EINVAL;

	r = p2p_parse_attrs(pdu + 1, len - 1,
			REQUIRED(P2P_DEVICE_ID, &d.device_addr),
			REQUIRED(P2P_GROUP_ID, &d.group_id),
			-1);

	if (r >= 0)
		memcpy(out, &d, sizeof(d));

	return r;
}

/* Section 4.2.9.8 */
int p2p_parse_device_disc_resp(const uint8_t *pdu, size_t len,
				struct p2p_device_discoverability_resp *out)
{
	struct p2p_device_discoverability_resp d = {0};
	int r;

	if (len < 1)
		return -EINVAL;

	d.dialog_token = pdu[0];
	if (d.dialog_token == 0)
		return -EINVAL;

	r = p2p_parse_attrs(pdu + 1, len - 1,
			REQUIRED(STATUS, &d.status),
			-1);

	if (r >= 0)
		memcpy(out, &d, sizeof(d));

	return r;
}

/* Section 4.2.9.9 */
int p2p_parse_provision_disc_req(const uint8_t *pdu, size_t len,
				struct p2p_provision_discovery_req *out)
{
	struct p2p_provision_discovery_req d = {0};
	int r;
	uint8_t *wsc_data;
	ssize_t wsc_len;

	if (len < 1)
		return -EINVAL;

	d.status = -1;

	d.dialog_token = pdu[0];
	if (d.dialog_token == 0)
		return -EINVAL;

	r = p2p_parse_attrs(pdu + 1, len - 1,
			REQUIRED(P2P_CAPABILITY, &d.capability),
			REQUIRED(P2P_DEVICE_INFO, &d.device_info),
			OPTIONAL(P2P_GROUP_ID, &d.group_id),
			OPTIONAL(INTENDED_P2P_INTERFACE_ADDR,
					&d.intended_interface_addr),
			OPTIONAL(STATUS, &d.status),
			OPTIONAL(OPERATING_CHANNEL, &d.operating_channel),
			OPTIONAL(CHANNEL_LIST, &d.channel_list),
			OPTIONAL(SESSION_INFO_DATA_INFO, &d.session_info),
			OPTIONAL(CONNECTION_CAPABILITY_INFO,
					&d.connection_capability),
			OPTIONAL(ADVERTISEMENT_ID_INFO, &d.advertisement_id),
			OPTIONAL(CONFIGURATION_TIMEOUT, &d.config_timeout),
			OPTIONAL(LISTEN_CHANNEL, &d.listen_channel),
			OPTIONAL(SESSION_ID_INFO, &d.session_id),
			OPTIONAL(FEATURE_CAPABILITY, &d.transport_protocol),
			OPTIONAL(PERSISTENT_GROUP_INFO,
					&d.persistent_group_info),
			-1);
	if (r < 0)
		goto error;

	wsc_data = ie_tlv_extract_wsc_payload(pdu + 1, len - 1, &wsc_len);
	if (wsc_len < 0) {
		r = wsc_len;
		goto error;
	}

	r = wsc_parse_attrs(wsc_data, wsc_len, NULL, NULL, 0, NULL,
			WSC_REQUIRED(CONFIGURATION_METHODS,
					&d.wsc_config_method),
			WSC_ATTR_INVALID);
	l_free(wsc_data);

	if (r < 0)
		goto error;

	/*
	 * 4.2.9.9: "A single method shall be set in the Config Methods
	 * attribute."
	 */
	if (__builtin_popcount(d.wsc_config_method) != 1) {
		r = -EINVAL;
		goto error;
	}

	d.wfd = ie_tlv_extract_wfd_payload(pdu + 1, len - 1, &d.wfd_size);

	memcpy(out, &d, sizeof(d));
	return 0;

error:
	p2p_clear_provision_disc_req(&d);
	return r;
}

/* Section 4.2.9.10 */
int p2p_parse_provision_disc_resp(const uint8_t *pdu, size_t len,
				struct p2p_provision_discovery_resp *out)
{
	struct p2p_provision_discovery_resp d = {0};
	int r;
	uint8_t *wsc_data;
	ssize_t wsc_len;

	if (len < 1)
		return -EINVAL;

	d.status = -1;

	d.dialog_token = pdu[0];
	if (d.dialog_token == 0)
		return -EINVAL;

	/*
	 * The P2P IE is optional but, if present, some of the attributes
	 * are required for this frame type.
	 */
	r = p2p_parse_attrs(pdu + 1, len - 1,
			REQUIRED(STATUS, &d.status),
			REQUIRED(P2P_CAPABILITY, &d.capability),
			REQUIRED(P2P_DEVICE_INFO, &d.device_info),
			OPTIONAL(P2P_GROUP_ID, &d.group_id),
			OPTIONAL(INTENDED_P2P_INTERFACE_ADDR,
					&d.intended_interface_addr),
			OPTIONAL(OPERATING_CHANNEL, &d.operating_channel),
			OPTIONAL(CHANNEL_LIST, &d.channel_list),
			OPTIONAL(CONNECTION_CAPABILITY_INFO,
					&d.connection_capability),
			REQUIRED(ADVERTISEMENT_ID_INFO, &d.advertisement_id),
			OPTIONAL(CONFIGURATION_TIMEOUT, &d.config_timeout),
			REQUIRED(SESSION_ID_INFO, &d.session_id),
			REQUIRED(FEATURE_CAPABILITY, &d.transport_protocol),
			OPTIONAL(PERSISTENT_GROUP_INFO,
					&d.persistent_group_info),
			REQUIRED(SESSION_INFO_DATA_INFO, &d.session_info),
			-1);
	if (r < 0 && r != -ENOENT)
		goto error;

	wsc_data = ie_tlv_extract_wsc_payload(pdu + 1, len - 1, &wsc_len);
	if (wsc_len < 0) {
		r = wsc_len;
		goto error;
	}

	r = wsc_parse_attrs(wsc_data, wsc_len, NULL, NULL, 0, NULL,
			WSC_REQUIRED(CONFIGURATION_METHODS,
					&d.wsc_config_method),
			WSC_ATTR_INVALID);
	l_free(wsc_data);

	if (r < 0)
		goto error;

	/*
	 * 4.2.9.10: "The value of the Config Methods attribute shall be
	 * set to the same value received in the Provision Discovery
	 * Request frame to indicate success or shall be null to indicate
	 * failure of the request."
	 */
	if (__builtin_popcount(d.wsc_config_method) > 1) {
		r = -EINVAL;
		goto error;
	}

	d.wfd = ie_tlv_extract_wfd_payload(pdu + 1, len - 1, &d.wfd_size);

	memcpy(out, &d, sizeof(d));
	return 0;

error:
	p2p_clear_provision_disc_resp(&d);
	return r;
}

/* Section 4.2.10.2 */
int p2p_parse_notice_of_absence(const uint8_t *pdu, size_t len,
				struct p2p_notice_of_absence *out)
{
	struct p2p_notice_of_absence d = {0};
	int r;

	if (len < 1)
		return -EINVAL;

	r = p2p_parse_attrs(pdu + 1, len - 1,
			REQUIRED(NOTICE_OF_ABSENCE, &d.notice_of_absence),
			-1);

	if (r >= 0)
		memcpy(out, &d, sizeof(d));
	else
		p2p_clear_notice_of_absence(&d);

	return r;
}

/* Section 4.2.10.3 */
int p2p_parse_presence_req(const uint8_t *pdu, size_t len,
				struct p2p_presence_req *out)
{
	struct p2p_presence_req d = {0};
	int r;

	if (len < 1)
		return -EINVAL;

	d.dialog_token = pdu[0];
	if (d.dialog_token == 0)
		return -EINVAL;

	r = p2p_parse_attrs(pdu + 1, len - 1,
			REQUIRED(NOTICE_OF_ABSENCE, &d.notice_of_absence),
			-1);

	if (r >= 0)
		memcpy(out, &d, sizeof(d));
	else
		p2p_clear_presence_req(&d);

	return r;
}

/* Section 4.2.10.4 */
int p2p_parse_presence_resp(const uint8_t *pdu, size_t len,
				struct p2p_presence_resp *out)
{
	struct p2p_presence_resp d = {0};
	int r;

	if (len < 1)
		return -EINVAL;

	d.dialog_token = pdu[0];
	if (d.dialog_token == 0)
		return -EINVAL;

	r = p2p_parse_attrs(pdu + 1, len - 1,
			REQUIRED(STATUS, &d.status),
			REQUIRED(NOTICE_OF_ABSENCE, &d.notice_of_absence),
			-1);

	if (r >= 0)
		memcpy(out, &d, sizeof(d));
	else
		p2p_clear_presence_resp(&d);

	return r;
}

/* Section 4.2.10.5 */
int p2p_parse_go_disc_req(const uint8_t *pdu, size_t len)
{
	if (len != 1 || pdu[0] != 0)
		return -EINVAL;

	return 0;
}

static void p2p_clear_channel_list_attr(struct p2p_channel_list_attr *attr)
{
	l_queue_destroy(attr->channel_entries, l_free);
	attr->channel_entries = NULL;
}

static void p2p_clear_notice_of_absence_attr(
					struct p2p_notice_of_absence_attr *attr)
{
	l_queue_destroy(attr->descriptors, l_free);
	attr->descriptors = NULL;
}

static void p2p_clear_device_info_attr(struct p2p_device_info_attr *attr)
{
	l_queue_destroy(attr->secondary_device_types, l_free);
	attr->secondary_device_types = NULL;
}

static void p2p_clear_group_info_attr(struct l_queue **group_clients)
{
	l_queue_destroy(*group_clients, p2p_clear_client_info_descriptor);
	*group_clients = NULL;
}

static void p2p_clear_interface_attr(struct p2p_interface_attr *attr)
{
	l_queue_destroy(attr->interface_addrs, l_free);
	attr->interface_addrs = NULL;
}

static void p2p_clear_svc_hash_attr(struct l_queue **hashes)
{
	l_queue_destroy(*hashes, l_free);
	*hashes = NULL;
}

static void p2p_clear_advertised_service_info_attr(struct l_queue **descriptors)
{
	l_queue_destroy(*descriptors, p2p_clear_advertised_service_descriptor);
	*descriptors = NULL;
}

void p2p_clear_beacon(struct p2p_beacon *data)
{
	p2p_clear_notice_of_absence_attr(&data->notice_of_absence);
}

void p2p_clear_probe_req(struct p2p_probe_req *data)
{
	p2p_clear_device_info_attr(&data->device_info);
	p2p_clear_svc_hash_attr(&data->service_hashes);
}

void p2p_clear_probe_resp(struct p2p_probe_resp *data)
{
	p2p_clear_notice_of_absence_attr(&data->notice_of_absence);
	p2p_clear_device_info_attr(&data->device_info);
	p2p_clear_group_info_attr(&data->group_clients);
	p2p_clear_advertised_service_info_attr(&data->advertised_svcs);
}

void p2p_clear_association_req(struct p2p_association_req *data)
{
	p2p_clear_device_info_attr(&data->device_info);
	p2p_clear_interface_attr(&data->interface);
}

void p2p_clear_association_resp(struct p2p_association_resp *data)
{
}

void p2p_clear_go_negotiation_req(struct p2p_go_negotiation_req *data)
{
	p2p_clear_channel_list_attr(&data->channel_list);
	p2p_clear_device_info_attr(&data->device_info);
	l_free(data->wfd);
	data->wfd = NULL;
}

void p2p_clear_go_negotiation_resp(struct p2p_go_negotiation_resp *data)
{
	p2p_clear_channel_list_attr(&data->channel_list);
	p2p_clear_device_info_attr(&data->device_info);
	l_free(data->wfd);
	data->wfd = NULL;
}

void p2p_clear_go_negotiation_confirmation(
				struct p2p_go_negotiation_confirmation *data)
{
	p2p_clear_channel_list_attr(&data->channel_list);
	l_free(data->wfd);
	data->wfd = NULL;
}

void p2p_clear_invitation_req(struct p2p_invitation_req *data)
{
	p2p_clear_channel_list_attr(&data->channel_list);
	p2p_clear_device_info_attr(&data->device_info);
	l_free(data->wfd);
	data->wfd = NULL;
}

void p2p_clear_invitation_resp(struct p2p_invitation_resp *data)
{
	p2p_clear_channel_list_attr(&data->channel_list);
	l_free(data->wfd);
	data->wfd = NULL;
}

void p2p_clear_provision_disc_req(struct p2p_provision_discovery_req *data)
{
	p2p_clear_channel_list_attr(&data->channel_list);
	p2p_clear_device_info_attr(&data->device_info);
	l_free(data->wfd);
	data->wfd = NULL;
}

void p2p_clear_provision_disc_resp(struct p2p_provision_discovery_resp *data)
{
	p2p_clear_channel_list_attr(&data->channel_list);
	p2p_clear_device_info_attr(&data->device_info);
	l_free(data->wfd);
	data->wfd = NULL;
}

void p2p_clear_notice_of_absence(struct p2p_notice_of_absence *data)
{
	p2p_clear_notice_of_absence_attr(&data->notice_of_absence);
}

void p2p_clear_presence_req(struct p2p_presence_req *data)
{
	p2p_clear_notice_of_absence_attr(&data->notice_of_absence);
}

void p2p_clear_presence_resp(struct p2p_presence_resp *data)
{
	p2p_clear_notice_of_absence_attr(&data->notice_of_absence);
}

struct p2p_attr_builder {
	size_t capacity;
	uint8_t *buf;
	uint16_t offset;
	uint16_t curlen;
};

static void p2p_attr_builder_grow(struct p2p_attr_builder *builder)
{
	builder->buf = l_realloc(builder->buf, builder->capacity * 2);
	builder->capacity *= 2;
}

/* Section 4.1.1 */
static void p2p_attr_builder_start_attr(struct p2p_attr_builder *builder,
					enum p2p_attr type)
{
	/* Record previous attribute's length */
	if (builder->curlen || builder->offset) {
		l_put_le16(builder->curlen, builder->buf + builder->offset + 1);
		builder->offset += 3 + builder->curlen;
		builder->curlen = 0;
	}

	if (builder->offset + 3u >= builder->capacity)
		p2p_attr_builder_grow(builder);

	builder->buf[builder->offset] = type;
}

static void p2p_attr_builder_put_u8(struct p2p_attr_builder *builder, uint8_t v)
{
	if (builder->offset + 3u + builder->curlen + 1u >= builder->capacity)
		p2p_attr_builder_grow(builder);

	builder->buf[builder->offset + 3 + builder->curlen] = v;
	builder->curlen += 1;
}

static void p2p_attr_builder_put_u16(struct p2p_attr_builder *builder,
					uint16_t v)
{
	if (builder->offset + 3u + builder->curlen + 2u >= builder->capacity)
		p2p_attr_builder_grow(builder);

	l_put_le16(v, builder->buf + builder->offset + 3 + builder->curlen);
	builder->curlen += 2;
}

static void p2p_attr_builder_put_be16(struct p2p_attr_builder *builder,
					uint16_t v)
{
	if (builder->offset + 3u + builder->curlen + 2u >= builder->capacity)
		p2p_attr_builder_grow(builder);

	l_put_be16(v, builder->buf + builder->offset + 3 + builder->curlen);
	builder->curlen += 2;
}

static void p2p_attr_builder_put_u32(struct p2p_attr_builder *builder,
					uint32_t v)
{
	if (builder->offset + 3u + builder->curlen + 4u >= builder->capacity)
		p2p_attr_builder_grow(builder);

	l_put_le32(v, builder->buf + builder->offset + 3 + builder->curlen);
	builder->curlen += 4;
}

static void p2p_attr_builder_put_bytes(struct p2p_attr_builder *builder,
					const void *bytes, size_t size)
{
	while (builder->offset + 3u + builder->curlen + size >=
			builder->capacity)
		p2p_attr_builder_grow(builder);

	memcpy(builder->buf + builder->offset + 3 + builder->curlen,
		bytes, size);
	builder->curlen += size;
}

static void p2p_attr_builder_put_oui(struct p2p_attr_builder *builder,
					const uint8_t *oui)
{
	if (builder->offset + 3u + builder->curlen + 3u >= builder->capacity)
		p2p_attr_builder_grow(builder);

	memcpy(builder->buf + builder->offset + 3 + builder->curlen, oui, 3);
	builder->curlen += 3;
}

static struct p2p_attr_builder *p2p_attr_builder_new(size_t initial_capacity)
{
	struct p2p_attr_builder *builder;

	if (initial_capacity == 0)
		return NULL;

	builder = l_new(struct p2p_attr_builder, 1);
	builder->buf = l_malloc(initial_capacity);
	builder->capacity = initial_capacity;

	return builder;
}

static uint8_t *p2p_attr_builder_free(struct p2p_attr_builder *builder,
					bool free_contents, size_t *out_size)
{
	uint8_t *ret;

	if (builder->curlen > 0 || builder->offset) {
		l_put_le16(builder->curlen, builder->buf + builder->offset + 1);
		builder->offset += 3 + builder->curlen;
	}

	if (free_contents) {
		l_free(builder->buf);
		ret = NULL;
	} else
		ret = builder->buf;

	if (out_size)
		*out_size = builder->offset;

	l_free(builder);

	return ret;
}

static void p2p_build_u8_attr(struct p2p_attr_builder *builder,
				enum p2p_attr type, uint8_t value)
{
	p2p_attr_builder_start_attr(builder, type);
	p2p_attr_builder_put_u8(builder, value);
}

/* Section 4.1.4 */
static void p2p_build_capability(struct p2p_attr_builder *builder,
					const struct p2p_capability_attr *attr)
{
	/* Always required */
	p2p_attr_builder_start_attr(builder, P2P_ATTR_P2P_CAPABILITY);
	p2p_attr_builder_put_u8(builder, attr->device_caps);
	p2p_attr_builder_put_u8(builder, attr->group_caps);
}

static const uint8_t zero_addr[6];

/* Section 4.1.5, 4.1.9, 4.1.11, ... */
static void p2p_build_addr(struct p2p_attr_builder *builder, bool optional,
				enum p2p_attr type, const uint8_t *addr)
{
	if (optional && !memcmp(addr, zero_addr, 6))
		return;

	p2p_attr_builder_start_attr(builder, type);
	p2p_attr_builder_put_bytes(builder, addr, 6);
}

/* Section 4.1.6 */
static void p2p_build_go_intent(struct p2p_attr_builder *builder,
				uint8_t intent, bool tie_breaker)
{
	/* Always required */
	p2p_attr_builder_start_attr(builder, P2P_ATTR_GO_INTENT);
	p2p_attr_builder_put_u8(builder, tie_breaker | (intent << 1));
}

/* Section 4.1.7 */
static void p2p_build_config_timeout(struct p2p_attr_builder *builder,
				bool optional,
				const struct p2p_config_timeout_attr *attr)
{
	if (optional && !attr->go_config_timeout &&
			!attr->client_config_timeout)
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_CONFIGURATION_TIMEOUT);
	p2p_attr_builder_put_u8(builder, attr->go_config_timeout);
	p2p_attr_builder_put_u8(builder, attr->client_config_timeout);
}

/* Section 4.1.8, 4.1.19, ... */
static void p2p_build_channel(struct p2p_attr_builder *builder, bool optional,
				enum p2p_attr type,
				const struct p2p_channel_attr *attr)
{
	if (optional && !attr->country[0])
		return;

	p2p_attr_builder_start_attr(builder, type);
	p2p_attr_builder_put_bytes(builder, attr->country, 3);
	p2p_attr_builder_put_u8(builder, attr->oper_class);
	p2p_attr_builder_put_u8(builder, attr->channel_num);
}

/* Section 4.1.10 */
static void p2p_build_extended_listen_timing(struct p2p_attr_builder *builder,
			const struct p2p_extended_listen_timing_attr *attr)
{
	/* Always optional */
	if (!attr->avail_period_ms && !attr->avail_interval_ms)
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_EXTENDED_LISTEN_TIMING);
	p2p_attr_builder_put_u16(builder, attr->avail_period_ms);
	p2p_attr_builder_put_u16(builder, attr->avail_interval_ms);
}

/* Section 4.1.13 */
static void p2p_build_channel_list(struct p2p_attr_builder *builder,
			bool optional,
			const struct p2p_channel_list_attr *attr)
{
	const struct l_queue_entry *entry;

	if (optional && !attr->channel_entries)
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_CHANNEL_LIST);
	p2p_attr_builder_put_bytes(builder, attr->country, 3);

	for (entry = l_queue_get_entries(attr->channel_entries); entry;
			entry = entry->next) {
		const struct p2p_channel_entries *entries = entry->data;

		p2p_attr_builder_put_u8(builder, entries->oper_class);
		p2p_attr_builder_put_u8(builder, entries->n_channels);
		p2p_attr_builder_put_bytes(builder, entries->channels,
						entries->n_channels);
	}
}

/* Section 4.1.14 */
static void p2p_build_notice_of_absence_attr(struct p2p_attr_builder *builder,
				bool optional,
				const struct p2p_notice_of_absence_attr *attr)
{
	const struct l_queue_entry *entry;

	if (optional && !attr->ct_window && !attr->descriptors)
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_NOTICE_OF_ABSENCE);
	p2p_attr_builder_put_u8(builder, attr->index);
	p2p_attr_builder_put_u8(builder,
				attr->ct_window | (attr->opp_ps ? 0x80 : 0));

	for (entry = l_queue_get_entries(attr->descriptors); entry;
			entry = entry->next) {
		const struct p2p_notice_of_absence_desc *desc = entry->data;

		p2p_attr_builder_put_u8(builder, desc->count_type);
		p2p_attr_builder_put_u32(builder, desc->duration);
		p2p_attr_builder_put_u32(builder, desc->interval);
		p2p_attr_builder_put_u32(builder, desc->start_time);
	}
}

static void p2p_build_wsc_device_type(struct p2p_attr_builder *builder,
				const struct wsc_primary_device_type *pdt)
{
	p2p_attr_builder_put_be16(builder, pdt->category);
	p2p_attr_builder_put_oui(builder, pdt->oui);
	p2p_attr_builder_put_u8(builder, pdt->oui_type);
	p2p_attr_builder_put_be16(builder, pdt->subcategory);
}

/* Section 4.1.15 */
static void p2p_build_device_info(struct p2p_attr_builder *builder,
					bool optional,
					const struct p2p_device_info_attr *attr)
{
	const struct l_queue_entry *entry;

	if (optional && !memcmp(attr->device_addr, zero_addr, 6))
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_P2P_DEVICE_INFO);
	p2p_attr_builder_put_bytes(builder, attr->device_addr, 6);
	p2p_attr_builder_put_be16(builder, attr->wsc_config_methods);
	p2p_build_wsc_device_type(builder, &attr->primary_device_type);
	p2p_attr_builder_put_u8(builder,
				l_queue_length(attr->secondary_device_types));

	for (entry = l_queue_get_entries(attr->secondary_device_types); entry;
			entry = entry->next)
		p2p_build_wsc_device_type(builder, entry->data);

	p2p_attr_builder_put_be16(builder, WSC_ATTR_DEVICE_NAME);
	p2p_attr_builder_put_be16(builder, strlen(attr->device_name));
	p2p_attr_builder_put_bytes(builder, attr->device_name,
					strlen(attr->device_name));
}

/* Section 4.1.16 */
static void p2p_build_group_info(struct p2p_attr_builder *builder,
					struct l_queue *clients)
{
	const struct l_queue_entry *entry;

	/* Always optional */
	if (!clients)
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_P2P_GROUP_INFO);

	for (entry = l_queue_get_entries(clients); entry; entry = entry->next) {
		const struct l_queue_entry *entry2;
		const struct p2p_client_info_descriptor *desc = entry->data;

		p2p_attr_builder_put_bytes(builder, desc->device_addr, 6);
		p2p_attr_builder_put_bytes(builder, desc->interface_addr, 6);
		p2p_attr_builder_put_u8(builder, desc->device_caps);
		p2p_attr_builder_put_be16(builder, desc->wsc_config_methods);
		p2p_build_wsc_device_type(builder, &desc->primary_device_type);
		p2p_attr_builder_put_u8(builder,
				l_queue_length(desc->secondary_device_types));

		for (entry2 = l_queue_get_entries(desc->secondary_device_types);
				entry2; entry2 = entry->next)
			p2p_build_wsc_device_type(builder, entry2->data);

		p2p_attr_builder_put_be16(builder, WSC_ATTR_DEVICE_NAME);
		p2p_attr_builder_put_be16(builder, strlen(desc->device_name));
		p2p_attr_builder_put_bytes(builder, desc->device_name,
						strlen(desc->device_name));
	}
}

/* Section 4.1.17, 4.1.29 */
static void p2p_build_group_id(struct p2p_attr_builder *builder, bool optional,
				enum p2p_attr type,
				const struct p2p_group_id_attr *attr)
{
	if (optional && !memcmp(attr->device_addr, zero_addr, 6))
		return;

	p2p_attr_builder_start_attr(builder, type);
	p2p_attr_builder_put_bytes(builder, attr->device_addr, 6);
	p2p_attr_builder_put_bytes(builder, attr->ssid, strlen(attr->ssid));
}

/* Section 4.1.18 */
static void p2p_build_interface(struct p2p_attr_builder *builder,
				const struct p2p_interface_attr *attr)
{
	const struct l_queue_entry *entry;

	/* Always optional */
	if (!memcmp(attr->device_addr, zero_addr, 6))
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_P2P_INTERFACE);
	p2p_attr_builder_put_bytes(builder, attr->device_addr, 6);
	p2p_attr_builder_put_u8(builder, l_queue_length(attr->interface_addrs));

	for (entry = l_queue_get_entries(attr->interface_addrs); entry;
			entry = entry->next)
		p2p_attr_builder_put_bytes(builder, entry->data, 6);
}

/* Section 4.1.22 */
static void p2p_build_svc_hash(struct p2p_attr_builder *builder,
				struct l_queue *service_hashes)
{
	const struct l_queue_entry *entry;

	/* Always optional */
	if (!service_hashes)
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_SVC_HASH);

	for (entry = l_queue_get_entries(service_hashes); entry;
			entry = entry->next)
		p2p_attr_builder_put_bytes(builder, entry->data, 6);
}

/* Section 4.1.23 */
static void p2p_build_session_data(struct p2p_attr_builder *builder,
				const struct p2p_session_info_data_attr *attr)
{
	/* Always optional */
	if (!attr->data_len)
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_SESSION_INFO_DATA_INFO);
	p2p_attr_builder_put_bytes(builder, attr->data, attr->data_len);
}

/* Section 4.1.25 */
static void p2p_build_advertisement_id(struct p2p_attr_builder *builder,
			bool optional,
			const struct p2p_advertisement_id_info_attr *attr)
{
	if (optional && !memcmp(attr->service_mac_addr, zero_addr, 6))
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_ADVERTISEMENT_ID_INFO);
	p2p_attr_builder_put_u32(builder, attr->advertisement_id);
	p2p_attr_builder_put_bytes(builder, attr->service_mac_addr, 6);
}

/* Section 4.1.26 */
static void p2p_build_advertised_service_info(struct p2p_attr_builder *builder,
						struct l_queue *services)
{
	const struct l_queue_entry *entry;

	/* Always optional */
	if (!services)
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_ADVERTISED_SVC_INFO);

	for (entry = l_queue_get_entries(services); entry;
			entry = entry->next) {
		const struct p2p_advertised_service_descriptor *desc =
			entry->data;

		p2p_attr_builder_put_u32(builder, desc->advertisement_id);
		p2p_attr_builder_put_be16(builder, desc->wsc_config_methods);
		p2p_attr_builder_put_u8(builder, strlen(desc->service_name));
		p2p_attr_builder_put_bytes(builder, desc->service_name,
						strlen(desc->service_name));
	}
}

/* Section 4.1.27 */
static void p2p_build_session_id(struct p2p_attr_builder *builder,
				bool optional,
				const struct p2p_session_id_info_attr *attr)
{
	if (optional && !memcmp(attr->session_mac_addr, zero_addr, 6))
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_SESSION_ID_INFO);
	p2p_attr_builder_put_u32(builder, attr->session_id);
	p2p_attr_builder_put_bytes(builder, attr->session_mac_addr, 6);
}

/* Section 4.1.28 */
static void p2p_build_feature_capability(struct p2p_attr_builder *builder,
			bool optional,
			enum p2p_asp_coordination_transport_protocol attr)
{
	if (optional && attr == P2P_ASP_TRANSPORT_UNKNOWN)
		return;

	p2p_attr_builder_start_attr(builder, P2P_ATTR_FEATURE_CAPABILITY);
	p2p_attr_builder_put_u8(builder, 0x01); /* P2P_ASP_TRANSPORT_UDP */
	p2p_attr_builder_put_u8(builder, 0x00); /* Reserved */
}

/* Section 4.2.1 */
uint8_t *p2p_build_beacon(const struct p2p_beacon *data, size_t *out_len)
{
	struct p2p_attr_builder *builder;
	uint8_t *ret;
	uint8_t *tlv;
	size_t tlv_len;

	builder = p2p_attr_builder_new(512);
	p2p_build_capability(builder, &data->capability);
	p2p_build_addr(builder, false, P2P_ATTR_P2P_DEVICE_ID,
			data->device_addr);
	p2p_build_notice_of_absence_attr(builder, true,
						&data->notice_of_absence);

	tlv = p2p_attr_builder_free(builder, false, &tlv_len);
	ret = ie_tlv_encapsulate_p2p_payload(tlv, tlv_len, out_len);
	l_free(tlv);
	return ret;
}

/* Section 4.2.2 */
uint8_t *p2p_build_probe_req(const struct p2p_probe_req *data, size_t *out_len)
{
	struct p2p_attr_builder *builder;
	uint8_t *ret;
	uint8_t *tlv;
	size_t tlv_len;

	builder = p2p_attr_builder_new(512);
	p2p_build_capability(builder, &data->capability);
	p2p_build_addr(builder, true, P2P_ATTR_P2P_DEVICE_ID,
			data->device_addr);
	p2p_build_channel(builder, true, P2P_ATTR_LISTEN_CHANNEL,
				&data->listen_channel);
	p2p_build_extended_listen_timing(builder, &data->listen_availability);
	p2p_build_device_info(builder, true, &data->device_info);
	p2p_build_channel(builder, true, P2P_ATTR_OPERATING_CHANNEL,
				&data->operating_channel);
	p2p_build_svc_hash(builder, data->service_hashes);

	tlv = p2p_attr_builder_free(builder, false, &tlv_len);
	ret = ie_tlv_encapsulate_p2p_payload(tlv, tlv_len, out_len);
	l_free(tlv);
	return ret;
}

/* Section 4.2.3 */
uint8_t *p2p_build_probe_resp(const struct p2p_probe_resp *data,
				size_t *out_len)
{
	struct p2p_attr_builder *builder;
	uint8_t *ret;
	uint8_t *tlv;
	size_t tlv_len;

	builder = p2p_attr_builder_new(512);
	p2p_build_capability(builder, &data->capability);
	p2p_build_extended_listen_timing(builder, &data->listen_availability);
	p2p_build_notice_of_absence_attr(builder, true,
						&data->notice_of_absence);
	p2p_build_device_info(builder, false, &data->device_info);
	p2p_build_group_info(builder, data->group_clients);
	p2p_build_advertised_service_info(builder, data->advertised_svcs);

	tlv = p2p_attr_builder_free(builder, false, &tlv_len);
	ret = ie_tlv_encapsulate_p2p_payload(tlv, tlv_len, out_len);
	l_free(tlv);
	return ret;
}

/* Section 4.2.4 */
uint8_t *p2p_build_association_req(const struct p2p_association_req *data,
					size_t *out_len)
{
	struct p2p_attr_builder *builder;
	uint8_t *ret;
	uint8_t *tlv;
	size_t tlv_len;

	builder = p2p_attr_builder_new(512);
	p2p_build_capability(builder, &data->capability);
	p2p_build_extended_listen_timing(builder, &data->listen_availability);
	p2p_build_device_info(builder, true, &data->device_info);
	p2p_build_interface(builder, &data->interface);

	tlv = p2p_attr_builder_free(builder, false, &tlv_len);
	ret = ie_tlv_encapsulate_p2p_payload(tlv, tlv_len, out_len);
	l_free(tlv);
	return ret;
}

/* Section 4.2.5 */
uint8_t *p2p_build_association_resp(const struct p2p_association_resp *data,
					size_t *out_len)
{
	struct p2p_attr_builder *builder;
	uint8_t *ret;
	uint8_t *tlv;
	size_t tlv_len;

	builder = p2p_attr_builder_new(32);

	/*
	 * 4.2.5: "The Status attribute shall be present [...] when a
	 * (Re) association Request frame is denied."
	 *
	 * Note the P2P IE may end up being empty but is required for
	 * this frame type nevertheless.
	 */
	if (data->status != P2P_STATUS_SUCCESS &&
			data->status != P2P_STATUS_SUCCESS_ACCEPTED_BY_USER)
		p2p_build_u8_attr(builder, P2P_ATTR_STATUS, data->status);

	p2p_build_extended_listen_timing(builder, &data->listen_availability);

	tlv = p2p_attr_builder_free(builder, false, &tlv_len);
	ret = ie_tlv_encapsulate_p2p_payload(tlv, tlv_len, out_len);
	l_free(tlv);
	return ret;
}

/* Section 4.2.6 */
uint8_t *p2p_build_deauthentication(const struct p2p_deauthentication *data,
					size_t *out_len)
{
	struct p2p_attr_builder *builder;
	uint8_t *ret;
	uint8_t *tlv;
	size_t tlv_len;

	if (!data->minor_reason_code) {
		*out_len = 0;
		return (uint8_t *) "";
	}

	builder = p2p_attr_builder_new(512);
	p2p_build_u8_attr(builder, P2P_ATTR_MINOR_REASON_CODE,
				data->minor_reason_code);

	tlv = p2p_attr_builder_free(builder, false, &tlv_len);
	ret = ie_tlv_encapsulate_p2p_payload(tlv, tlv_len, out_len);
	l_free(tlv);
	return ret;
}

/* Section 4.2.7 */
uint8_t *p2p_build_disassociation(const struct p2p_disassociation *data,
					size_t *out_len)
{
	struct p2p_attr_builder *builder;
	uint8_t *ret;
	uint8_t *tlv;
	size_t tlv_len;

	if (!data->minor_reason_code) {
		*out_len = 0;
		return (uint8_t *) "";
	}

	builder = p2p_attr_builder_new(512);
	p2p_build_u8_attr(builder, P2P_ATTR_MINOR_REASON_CODE,
				data->minor_reason_code);

	tlv = p2p_attr_builder_free(builder, false, &tlv_len);
	ret = ie_tlv_encapsulate_p2p_payload(tlv, tlv_len, out_len);
	l_free(tlv);
	return ret;
}

/* Sections 4.2.9.1, 4.2.10.1.  Note: consumes @p2p_attrs */
static uint8_t *p2p_build_action_frame(bool public, uint8_t frame_subtype,
					uint8_t dialog_token,
					struct p2p_attr_builder *p2p_attrs,
					const struct wsc_p2p_attrs *wsc_attrs,
					const uint8_t *wfd_ie,
					size_t wfd_ie_len, size_t *out_len)
{
	uint8_t *p2p_ie, *wsc_ie, *ret;
	size_t p2p_ie_len, wsc_ie_len;
	int pos = 0;

	if (p2p_attrs) {
		uint8_t *payload;
		size_t payload_len;

		payload = p2p_attr_builder_free(p2p_attrs, false, &payload_len);
		p2p_ie = ie_tlv_encapsulate_p2p_payload(payload, payload_len,
							&p2p_ie_len);
		l_free(payload);
	} else
		p2p_ie = NULL;

	if (wsc_attrs) {
		uint8_t *payload;
		size_t payload_len;

		payload = wsc_build_p2p_attrs(wsc_attrs, &payload_len);
		wsc_ie = ie_tlv_encapsulate_wsc_payload(payload, payload_len,
							&wsc_ie_len);
		l_free(payload);
	} else
		wsc_ie = NULL;

	*out_len = (public ? 8 : 7) + (p2p_ie ? p2p_ie_len : 0) +
		(wsc_ie ? wsc_ie_len : 0) + (wfd_ie ? wfd_ie_len : 0);
	ret = l_malloc(*out_len);

	if (public) {
		ret[pos++] = 0x04; /* Category: Public Action */
		ret[pos++] = 0x09; /* Action: Vendor Specific */
	} else
		ret[pos++] = 0x7f; /* Category: Vendor Specific */

	ret[pos++] = wifi_alliance_oui[0];
	ret[pos++] = wifi_alliance_oui[1];
	ret[pos++] = wifi_alliance_oui[2];
	ret[pos++] = 0x09;	/* OUI type: Wi-Fi Alliance P2P v1.0 */
	ret[pos++] = frame_subtype;
	ret[pos++] = dialog_token;

	if (p2p_ie) {
		memcpy(ret + pos, p2p_ie, p2p_ie_len);
		l_free(p2p_ie);
		pos += p2p_ie_len;
	}

	if (wsc_ie) {
		memcpy(ret + pos, wsc_ie, wsc_ie_len);
		l_free(wsc_ie);
		pos += wsc_ie_len;
	}

	if (wfd_ie)
		memcpy(ret + pos, wfd_ie, wfd_ie_len);

	return ret;
}

/* Section 4.2.9.2 */
uint8_t *p2p_build_go_negotiation_req(const struct p2p_go_negotiation_req *data,
					size_t *out_len)
{
	struct p2p_attr_builder *builder;
	struct wsc_p2p_attrs wsc_attrs = {};

	builder = p2p_attr_builder_new(512);
	p2p_build_capability(builder, &data->capability);
	p2p_build_go_intent(builder, data->go_intent, data->go_tie_breaker);
	p2p_build_config_timeout(builder, false, &data->config_timeout);
	p2p_build_channel(builder, true, P2P_ATTR_LISTEN_CHANNEL,
				&data->listen_channel);
	p2p_build_extended_listen_timing(builder, &data->listen_availability);
	p2p_build_addr(builder, false, P2P_ATTR_INTENDED_P2P_INTERFACE_ADDR,
			data->intended_interface_addr);
	p2p_build_channel_list(builder, false, &data->channel_list);
	p2p_build_device_info(builder, false, &data->device_info);
	p2p_build_channel(builder, true, P2P_ATTR_OPERATING_CHANNEL,
				&data->operating_channel);

	wsc_attrs.version = true;
	wsc_attrs.device_password_id = data->device_password_id;

	return p2p_build_action_frame(true, P2P_ACTION_GO_NEGOTIATION_REQ,
					data->dialog_token, builder, &wsc_attrs,
					data->wfd, data->wfd_size, out_len);
}

/* Section 4.2.9.3 */
uint8_t *p2p_build_go_negotiation_resp(
				const struct p2p_go_negotiation_resp *data,
				size_t *out_len)
{
	struct p2p_attr_builder *builder;
	struct wsc_p2p_attrs wsc_attrs = {};

	builder = p2p_attr_builder_new(512);
	p2p_build_u8_attr(builder, P2P_ATTR_STATUS, data->status);
	p2p_build_capability(builder, &data->capability);
	p2p_build_go_intent(builder, data->go_intent, data->go_tie_breaker);
	p2p_build_config_timeout(builder, false, &data->config_timeout);
	p2p_build_channel(builder, true, P2P_ATTR_OPERATING_CHANNEL,
				&data->operating_channel);
	p2p_build_addr(builder, false, P2P_ATTR_INTENDED_P2P_INTERFACE_ADDR,
			data->intended_interface_addr);
	p2p_build_channel_list(builder, false, &data->channel_list);
	p2p_build_device_info(builder, false, &data->device_info);
	p2p_build_group_id(builder, true, P2P_ATTR_P2P_GROUP_ID,
				&data->group_id);

	wsc_attrs.version = true;
	wsc_attrs.device_password_id = data->device_password_id;

	return p2p_build_action_frame(true, P2P_ACTION_GO_NEGOTIATION_RESP,
					data->dialog_token, builder, &wsc_attrs,
					data->wfd, data->wfd_size, out_len);
}

/* Section 4.2.9.4 */
uint8_t *p2p_build_go_negotiation_confirmation(
			const struct p2p_go_negotiation_confirmation *data,
			size_t *out_len)
{
	struct p2p_attr_builder *builder;

	builder = p2p_attr_builder_new(512);
	p2p_build_u8_attr(builder, P2P_ATTR_STATUS, data->status);
	p2p_build_capability(builder, &data->capability);
	p2p_build_channel(builder, false, P2P_ATTR_OPERATING_CHANNEL,
				&data->operating_channel);
	p2p_build_channel_list(builder, false, &data->channel_list);
	p2p_build_group_id(builder, true, P2P_ATTR_P2P_GROUP_ID,
				&data->group_id);

	return p2p_build_action_frame(true, P2P_ACTION_GO_NEGOTIATION_CONFIRM,
					data->dialog_token, builder, NULL,
					data->wfd, data->wfd_size, out_len);
}

/* Section 4.2.9.5 */
uint8_t *p2p_build_invitation_req(const struct p2p_invitation_req *data,
					size_t *out_len)
{
	struct p2p_attr_builder *builder;
	struct wsc_p2p_attrs wsc_attrs = {};

	builder = p2p_attr_builder_new(512);
	p2p_build_config_timeout(builder, false, &data->config_timeout);
	p2p_build_u8_attr(builder, P2P_ATTR_INVITATION_FLAGS,
				data->reinvoke_persistent_group ? 0x01 : 0x00);
	p2p_build_channel(builder, true, P2P_ATTR_OPERATING_CHANNEL,
				&data->operating_channel);
	p2p_build_addr(builder, true, P2P_ATTR_P2P_GROUP_BSSID,
			data->group_bssid);
	p2p_build_channel_list(builder, false, &data->channel_list);
	p2p_build_group_id(builder, false, P2P_ATTR_P2P_GROUP_ID,
				&data->group_id);
	p2p_build_device_info(builder, false, &data->device_info);

	/* Optional WSC IE for NFC Static Handover */
	wsc_attrs.version2 = true;
	wsc_attrs.device_password_id = data->device_password_id;

	return p2p_build_action_frame(true, P2P_ACTION_INVITATION_REQ,
					data->dialog_token, builder,
					data->device_password_id ?
					&wsc_attrs : NULL,
					data->wfd, data->wfd_size, out_len);
}

/* Section 4.2.9.6 */
uint8_t *p2p_build_invitation_resp(const struct p2p_invitation_resp *data,
					size_t *out_len)
{
	struct p2p_attr_builder *builder;

	builder = p2p_attr_builder_new(512);
	p2p_build_u8_attr(builder, P2P_ATTR_STATUS, data->status);
	p2p_build_config_timeout(builder, false, &data->config_timeout);

	if (data->status == P2P_STATUS_SUCCESS ||
			data->status == P2P_STATUS_SUCCESS_ACCEPTED_BY_USER) {
		p2p_build_channel(builder, false, P2P_ATTR_OPERATING_CHANNEL,
					&data->operating_channel);
		p2p_build_addr(builder, false, P2P_ATTR_P2P_GROUP_BSSID,
				data->group_bssid);
		p2p_build_channel_list(builder, false, &data->channel_list);
	}

	return p2p_build_action_frame(true, P2P_ACTION_INVITATION_RESP,
					data->dialog_token, builder, NULL,
					data->wfd, data->wfd_size, out_len);
}

/* Section 4.2.9.7 */
uint8_t *p2p_build_device_disc_req(
			const struct p2p_device_discoverability_req *data,
			size_t *out_len)
{
	struct p2p_attr_builder *builder;

	builder = p2p_attr_builder_new(64);
	p2p_build_addr(builder, false, P2P_ATTR_P2P_DEVICE_ID,
			data->device_addr);
	p2p_build_group_id(builder, false, P2P_ATTR_P2P_GROUP_ID,
				&data->group_id);

	return p2p_build_action_frame(true,
					P2P_ACTION_DEVICE_DISCOVERABILITY_REQ,
					data->dialog_token, builder, NULL,
					NULL, 0, out_len);
}

/* Section 4.2.9.8 */
uint8_t *p2p_build_device_disc_resp(
			const struct p2p_device_discoverability_resp *data,
			size_t *out_len)
{
	struct p2p_attr_builder *builder;

	builder = p2p_attr_builder_new(16);
	p2p_build_u8_attr(builder, P2P_ATTR_STATUS, data->status);

	return p2p_build_action_frame(true,
					P2P_ACTION_DEVICE_DISCOVERABILITY_RESP,
					data->dialog_token, builder, NULL,
					NULL, 0, out_len);
}

/* Section 4.2.9.9 */
uint8_t *p2p_build_provision_disc_req(
				const struct p2p_provision_discovery_req *data,
				size_t *out_len)
{
	struct p2p_attr_builder *builder;
	struct wsc_p2p_attrs wsc_attrs = {};

	builder = p2p_attr_builder_new(512);
	p2p_build_capability(builder, &data->capability);
	p2p_build_device_info(builder, false, &data->device_info);
	p2p_build_group_id(builder, true, P2P_ATTR_P2P_GROUP_ID,
				&data->group_id);
	p2p_build_addr(builder, true, P2P_ATTR_INTENDED_P2P_INTERFACE_ADDR,
			data->intended_interface_addr);

	if (data->status != (enum p2p_attr_status_code) -1)
		p2p_build_u8_attr(builder, P2P_ATTR_STATUS, data->status);

	p2p_build_channel(builder, true, P2P_ATTR_OPERATING_CHANNEL,
				&data->operating_channel);
	p2p_build_channel_list(builder, true, &data->channel_list);
	p2p_build_session_data(builder, &data->session_info);

	if (data->connection_capability)
		p2p_build_u8_attr(builder, P2P_ATTR_CONNECTION_CAPABILITY_INFO,
					data->connection_capability);

	p2p_build_advertisement_id(builder, true, &data->advertisement_id);
	p2p_build_config_timeout(builder, true, &data->config_timeout);
	p2p_build_channel(builder, true, P2P_ATTR_LISTEN_CHANNEL,
				&data->listen_channel);
	p2p_build_session_id(builder, true, &data->session_id);
	p2p_build_feature_capability(builder, true, data->transport_protocol);
	p2p_build_group_id(builder, true, P2P_ATTR_PERSISTENT_GROUP_INFO,
				&data->persistent_group_info);

	wsc_attrs.config_methods = data->wsc_config_method;

	return p2p_build_action_frame(true, P2P_ACTION_PROVISION_DISCOVERY_REQ,
					data->dialog_token, builder, &wsc_attrs,
					data->wfd, data->wfd_size, out_len);
}

/* Section 4.2.9.10 */
uint8_t *p2p_build_provision_disc_resp(
				const struct p2p_provision_discovery_resp *data,
				size_t *out_len)
{
	struct p2p_attr_builder *builder = NULL;
	struct wsc_p2p_attrs wsc_attrs = {};

	if (data->status != (enum p2p_attr_status_code) -1) {
		builder = p2p_attr_builder_new(512);
		p2p_build_u8_attr(builder, P2P_ATTR_STATUS, data->status);
		p2p_build_capability(builder, &data->capability);
		p2p_build_device_info(builder, false, &data->device_info);
		p2p_build_group_id(builder, true, P2P_ATTR_P2P_GROUP_ID,
					&data->group_id);
		p2p_build_addr(builder, true,
				P2P_ATTR_INTENDED_P2P_INTERFACE_ADDR,
				data->intended_interface_addr);
		p2p_build_channel(builder, true, P2P_ATTR_OPERATING_CHANNEL,
					&data->operating_channel);
		p2p_build_channel_list(builder, true, &data->channel_list);

		if (data->connection_capability)
			p2p_build_u8_attr(builder,
					P2P_ATTR_CONNECTION_CAPABILITY_INFO,
					data->connection_capability);

		p2p_build_advertisement_id(builder, false,
						&data->advertisement_id);
		p2p_build_config_timeout(builder, true, &data->config_timeout);
		p2p_build_session_id(builder, false, &data->session_id);
		p2p_build_feature_capability(builder, false,
						data->transport_protocol);
		p2p_build_group_id(builder, true,
					P2P_ATTR_PERSISTENT_GROUP_INFO,
					&data->persistent_group_info);
		p2p_build_session_data(builder, &data->session_info);
	}

	wsc_attrs.config_methods = data->wsc_config_method;

	return p2p_build_action_frame(true, P2P_ACTION_PROVISION_DISCOVERY_RESP,
					data->dialog_token, builder, &wsc_attrs,
					data->wfd, data->wfd_size, out_len);
}

/* Section 4.2.10.2 */
uint8_t *p2p_build_notice_of_absence(const struct p2p_notice_of_absence *data,
					size_t *out_len)
{
	struct p2p_attr_builder *builder;

	builder = p2p_attr_builder_new(128);
	p2p_build_notice_of_absence_attr(builder, false,
						&data->notice_of_absence);

	return p2p_build_action_frame(false, P2P_ACTION_NOTICE_OF_ABSENCE,
					0, builder, NULL, NULL, 0, out_len);
}

/* Section 4.2.10.3 */
uint8_t *p2p_build_presence_req(const struct p2p_presence_req *data,
				size_t *out_len)
{
	struct p2p_attr_builder *builder;

	builder = p2p_attr_builder_new(128);
	p2p_build_notice_of_absence_attr(builder, false,
						&data->notice_of_absence);

	return p2p_build_action_frame(false, P2P_ACTION_PRESENCE_REQ,
					0, builder, NULL, NULL, 0, out_len);
}

/* Section 4.2.10.4 */
uint8_t *p2p_build_presence_resp(const struct p2p_presence_resp *data,
					size_t *out_len)
{
	struct p2p_attr_builder *builder;

	builder = p2p_attr_builder_new(128);
	p2p_build_u8_attr(builder, P2P_ATTR_STATUS, data->status);
	p2p_build_notice_of_absence_attr(builder, false,
						&data->notice_of_absence);

	return p2p_build_action_frame(false, P2P_ACTION_PRESENCE_RESP,
					0, builder, NULL, NULL, 0, out_len);
}

/* Section 4.2.10.5 */
uint8_t *p2p_build_go_disc_req(size_t *out_len)
{
	return p2p_build_action_frame(false, P2P_ACTION_GO_DISCOVERABILITY_REQ,
					0, NULL, NULL, NULL, 0, out_len);
}

/*
 * Select a string of random characters from the set defined in section
 * 3.2.1:
 *
 * "Following "DIRECT-" the SSID shall contain two ASCII characters "xy",
 * randomly selected with a uniform distribution from the following
 * character set: upper case letters, lower case letters and numbers."
 *
 * "The WPA2-Personal pass-phrase shall contain at least eight ASCII
 * characters randomly selected with a uniform distribution from the
 * following character set: upper case letters, lower case letters and
 * numbers."
 *
 * Our random distribution is not uniform but close enough for use in
 * the SSID.
 */
void p2p_get_random_string(char *buf, size_t len)
{
#define CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" \
		"0123456789"
	static const int set_size = strlen(CHARSET);

	l_getrandom(buf, len);

	while (len) {
		int index = (uint8_t) *buf % set_size;

		*buf++ = CHARSET[index];
		len--;
	}
#undef CHARSET
}
