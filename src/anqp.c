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

#include <stdint.h>

#include <ell/ell.h>

#include "src/module.h"
#include "src/anqp.h"
#include "src/util.h"
#include "src/ie.h"
#include "src/scan.h"
#include "src/iwd.h"
#include "src/mpdu.h"
#include "src/frame-xchg.h"

#include "linux/nl80211.h"

#define ANQP_GROUP	0

struct anqp_request {
	uint64_t wdev_id;
	anqp_response_func_t anqp_cb;
	anqp_destroy_func_t anqp_destroy;
	void *anqp_data;
	uint8_t anqp_token;
	uint32_t frequency;
	uint8_t *frame;
	size_t frame_len;
	uint32_t id;
};

static void anqp_destroy(void *user_data)
{
	struct anqp_request *request = user_data;

	if (request->anqp_destroy)
		request->anqp_destroy(request->anqp_data);

	l_free(request->frame);
	l_free(request);
}

/*
 * By using frame-xchg we should get called back here for any frame matching our
 * prefix until the duration expires. If frame-xchg is never signalled 'done'
 * (returning true) we should get a timeout in anqp_frame_timeout. This is
 * why we drop any improperly formatted frames without cleaning up the request.
 */
static bool anqp_response_frame_event(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	struct anqp_request *request = user_data;
	const uint8_t *ptr = body;
	uint16_t status_code;
	uint16_t delay;
	uint16_t qrlen;
	uint8_t adv_proto_len;
	uint8_t token;

	if (body_len < 9)
		return false;

	/* Skip past category/action since this frame was prefixed matched */
	ptr += 2;
	body_len -= 2;

	/* dialog token */
	token = *ptr++;

	if (request->anqp_token != token)
		return false;

	status_code = l_get_le16(ptr);
	ptr += 2;
	body_len -= 2;

	if (status_code != 0) {
		l_error("Bad status code on GAS response %u", status_code);
		return false;
	}

	delay = l_get_le16(ptr);
	ptr += 2;
	body_len -= 2;

	/*
	 * IEEE 80211-2016 Section 9.6.8.13
	 *
	 * The value 0 will be returned by the STA when a Query Response is
	 * provided in this frame
	 */
	if (delay != 0) {
		l_error("GAS comeback delay was not zero");
		return false;
	}

	if (*ptr != IE_TYPE_ADVERTISEMENT_PROTOCOL) {
		l_error("GAS request not advertisement protocol");
		return false;
	}

	ptr++;
	body_len--;

	adv_proto_len = *ptr++;
	body_len--;

	if (body_len < adv_proto_len)
		return false;

	ptr += adv_proto_len;
	body_len -= adv_proto_len;

	if (body_len < 2)
		return false;

	qrlen = l_get_le16(ptr);
	ptr += 2;

	if (body_len < qrlen)
		return false;

	l_debug("ANQP response received from "MAC, MAC_STR(hdr->address_2));

	if (request->anqp_cb)
		request->anqp_cb(ANQP_SUCCESS, ptr, qrlen, request->anqp_data);

	anqp_destroy(request);

	return true;
}

static const struct frame_xchg_prefix anqp_frame_prefix = {
	.frame_type = 0x00d0,
	.data = (uint8_t []) {
		0x04, 0x0b,
	},
	.len = 2,
};

static void anqp_frame_timeout(int error, void *user_data)
{
	struct anqp_request *request = user_data;
	enum anqp_result result = ANQP_TIMEOUT;

	if (error < 0) {
		result = ANQP_FAILED;
		l_error("Sending ANQP request failed: %s (%i)",
			strerror(-error), -error);
	}

	if (request->anqp_cb)
		request->anqp_cb(result, NULL, 0, request->anqp_data);

	if (request->anqp_destroy)
		request->anqp_destroy(request->anqp_data);

	anqp_destroy(request);
}

static uint8_t *anqp_build_frame(const uint8_t *addr, struct scan_bss *bss,
					uint8_t anqp_token,
					const uint8_t *anqp, size_t len,
					size_t *len_out)
{
	uint8_t *frame = l_malloc(len + 33);
	uint8_t *ptr;

	memset(frame, 0, len + 33);

	l_put_le16(0x00d0, frame + 0);
	memcpy(frame + 4, bss->addr, 6);
	memcpy(frame + 10, addr, 6);
	memcpy(frame + 16, bss->addr, 6);

	ptr = frame + 24;

	*ptr++ = 0x04;			/* Category: Public */
	*ptr++ = 0x0a;			/* Action: GAS initial Request */
	*ptr++ = anqp_token;		/* Dialog Token */
	*ptr++ = IE_TYPE_ADVERTISEMENT_PROTOCOL;
	*ptr++ = 2;

	*ptr++ = 0x7f;
	*ptr++ = IE_ADVERTISEMENT_ANQP;
	l_put_le16(len, ptr);
	ptr += 2;

	memcpy(ptr, anqp, len);
	ptr += len;

	*len_out = ptr - frame;

	return frame;
}

uint32_t anqp_request(uint64_t wdev_id, const uint8_t *addr,
			struct scan_bss *bss, const uint8_t *anqp,
			size_t len, anqp_response_func_t cb,
			void *user_data, anqp_destroy_func_t destroy)
{
	struct anqp_request *request;
	struct iovec iov[2];

	request = l_new(struct anqp_request, 1);

	request->wdev_id = wdev_id;
	request->frequency = bss->frequency;
	request->anqp_cb = cb;
	request->anqp_destroy = destroy;
	/*
	 * WPA3 Specificiation version 3, Section 9.4:
	 * "A STA shall use a randomized dialog token for every new GAS
	 * exchange."
	 */
	l_getrandom(&request->anqp_token, sizeof(request->anqp_token));
	request->anqp_data = user_data;

	request->frame = anqp_build_frame(addr, bss, request->anqp_token,
						anqp, len,
						&request->frame_len);

	iov[0].iov_base = request->frame;
	iov[0].iov_len = request->frame_len;
	iov[1].iov_base = NULL;

	l_debug("Sending ANQP request to "MAC, MAC_STR(bss->addr));

	request->id = frame_xchg_start(request->wdev_id, iov,
				request->frequency, 0, 300, 0,
				ANQP_GROUP, anqp_frame_timeout, request, NULL,
				&anqp_frame_prefix, anqp_response_frame_event,
				NULL);

	return request->id;
}

void anqp_cancel(uint32_t id)
{
	frame_xchg_cancel(id);
}
