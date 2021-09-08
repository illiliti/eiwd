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

#include <errno.h>

struct auth_proto {
	bool (*start)(struct auth_proto *ap);
	void (*free)(struct auth_proto *ap);
	/*
	 * Callback to receive an Authenticate frame. auth-protos should
	 * return error codes consistent with one another as some are treated
	 * specially:
	 *
	 * 0 indicates success, and that a state transition occurred.
	 * -ENOMSG or -EBADMSG indicates the message should be ignored silently
	 * -EAGAIN indicates a retry, and no state transition occurred. Any
	 *         retry is handled by the auth-proto internally
	 * -EPROTO indicates a fatal error
	 * Any other < 0 return will be treated as a fatal error
	 * > 0 indicates a fatal error with status code. This only applies to
	 *         non-sta cases as non-zero status codes are rejected by the
	 *         kernel when in station mode.
	 */
	int (*rx_authenticate)(struct auth_proto *driver,
					const uint8_t *frame, size_t len);
	int (*rx_associate)(struct auth_proto *driver,
					const uint8_t *frame, size_t len);
	bool (*auth_timeout)(struct auth_proto *ap);
	bool (*assoc_timeout)(struct auth_proto *ap);
	uint8_t prev_bssid[6];
};

static inline void auth_proto_free(struct auth_proto *ap)
{
	if (ap && ap->free)
		ap->free(ap);
}

static inline bool auth_proto_start(struct auth_proto *ap)
{
	if (ap && ap->start)
		return ap->start(ap);

	return false;
}

static inline int auth_proto_rx_authenticate(struct auth_proto *ap,
						const uint8_t *frame,
						size_t frame_len)
{
	if (ap && ap->rx_authenticate)
		return ap->rx_authenticate(ap, frame, frame_len);

	return -ENOTSUP;
}

static inline int auth_proto_rx_associate(struct auth_proto *ap,
						const uint8_t *frame,
						size_t frame_len)
{
	if (ap && ap->rx_associate)
		return ap->rx_associate(ap, frame, frame_len);

	return -ENOTSUP;
}

static inline bool auth_proto_auth_timeout(struct auth_proto *ap)
{
	if (ap && ap->auth_timeout)
		return ap->auth_timeout(ap);

	return false;
}

static inline bool auth_proto_assoc_timeout(struct auth_proto *ap)
{
	if (ap && ap->assoc_timeout)
		return ap->assoc_timeout(ap);

	return false;
}
