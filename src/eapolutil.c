/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2019  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <ell/ell.h>

#include "src/eapolutil.h"

const struct eapol_key *eapol_key_validate(const uint8_t *frame, size_t len,
						size_t mic_len)
{
	const struct eapol_key *ek;

	/*
	 * Since EAPOL_KEY_DATA_LEN actually gets the key data length bytes we
	 * have to check this first, otherwise we could potentially overrun the
	 * frame buffer
	 */
	if (len < EAPOL_FRAME_LEN(mic_len))
		return NULL;

	ek = (const struct eapol_key *) frame;

	if (len < EAPOL_FRAME_LEN(mic_len) + EAPOL_KEY_DATA_LEN(ek, mic_len))
		return NULL;

	switch (ek->header.protocol_version) {
	case EAPOL_PROTOCOL_VERSION_2001:
	case EAPOL_PROTOCOL_VERSION_2004:
	case EAPOL_PROTOCOL_VERSION_2010:
		break;
	default:
		return NULL;
	}

	if (ek->header.packet_type != 3)
		return NULL;

	switch (ek->descriptor_type) {
	case EAPOL_DESCRIPTOR_TYPE_RC4:
	case EAPOL_DESCRIPTOR_TYPE_80211:
	case EAPOL_DESCRIPTOR_TYPE_WPA:
		break;
	default:
		return NULL;
	}

	switch (ek->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AKM_DEFINED:
		break;
	default:
		return NULL;
	}

	return ek;
}
