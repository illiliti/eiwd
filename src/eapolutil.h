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

#include <stdint.h>
#include <stdbool.h>
#include <asm/byteorder.h>
#include <linux/types.h>

enum ie_rsn_akm_suite;
enum ie_rsn_cipher_suite;

enum eapol_protocol_version {
	EAPOL_PROTOCOL_VERSION_2001	= 1,
	EAPOL_PROTOCOL_VERSION_2004	= 2,
	EAPOL_PROTOCOL_VERSION_2010	= 3,
};

/*
 * 802.1X-2010: Table 11-5-Descriptor Type value assignments
 * The WPA key type of 254 comes from somewhere else.  Seems it is a legacy
 * value that might still be used by older implementations
 */
enum eapol_descriptor_type {
	EAPOL_DESCRIPTOR_TYPE_RC4	= 1,
	EAPOL_DESCRIPTOR_TYPE_80211	= 2,
	EAPOL_DESCRIPTOR_TYPE_WPA	= 254,
};

enum eapol_key_descriptor_version {
	EAPOL_KEY_DESCRIPTOR_VERSION_AKM_DEFINED	= 0,
	EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4	= 1,
	EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES	= 2,
	EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES	= 3,
};

struct eapol_header {
	uint8_t protocol_version;
	uint8_t packet_type;
	__be16 packet_len;
} __attribute__ ((packed));

struct eapol_frame {
	struct eapol_header header;
	uint8_t data[];
} __attribute__ ((packed));

/* gets pointer to MIC */
#define EAPOL_KEY_MIC(ek) ((ek)->key_data)

/* get key data length */
#define EAPOL_KEY_DATA_LEN(ek, mic_len) l_get_be16((ek)->key_data + (mic_len))

/* gets pointer to key data */
#define EAPOL_KEY_DATA(ek, mic_len) ((ek)->key_data + (mic_len) + 2)

/* gets frame length (not including key data) */
#define EAPOL_FRAME_LEN(mic_len) (sizeof(struct eapol_key) + (mic_len) + 2)

struct eapol_key {
	struct eapol_header header;
	uint8_t descriptor_type;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	bool key_mic:1;
	bool secure:1;
	bool error:1;
	bool request:1;
	bool encrypted_key_data:1;
	bool smk_message:1;
	uint8_t reserved2:2;
	uint8_t key_descriptor_version:3;
	bool key_type:1;
	uint8_t wpa_key_id:2; /* Bits 4-5 reserved in RSN, Key ID in WPA */
	bool install:1;
	bool key_ack:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t reserved2:2;
	bool smk_message:1;
	bool encrypted_key_data:1;
	bool request:1;
	bool error:1;
	bool secure:1;
	bool key_mic:1;
	bool key_ack:1;
	bool install:1;
	uint8_t wpa_key_id:2; /* Bits 4-5 reserved in RSN, Key ID in WPA */
	bool key_type:1;
	uint8_t key_descriptor_version:3;
#else
#error  "Please fix <asm/byteorder.h>"
#endif

	__be16 key_length;
	__be64 key_replay_counter;
	uint8_t key_nonce[32];
	uint8_t eapol_key_iv[16];
	uint8_t key_rsc[8];
	uint8_t reserved[8];
	uint8_t key_data[];
} __attribute__ ((packed));

const struct eapol_key *eapol_key_validate(const uint8_t *frame, size_t len,
						size_t mic_len);
int eapol_key_descriptor_version_from_akm(enum ie_rsn_akm_suite akm,
					enum ie_rsn_cipher_suite pairwise,
					uint8_t *out_version);
