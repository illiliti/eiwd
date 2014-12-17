/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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

/* 802.11, Table 8-1 "Valid type and subtype combinations" */
enum mpdu_type {
	MPDU_TYPE_MANAGEMENT = 0,
};

/* 802.11, Table 8-1 "Valid type and subtype combinations" */
enum mpdu_management_subtype {
	MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION   = 0xB,
	MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION = 0xC,
};

/* 802.11, Section 8.4.1.1 Authentication Algorithm Number field */
enum mpdu_authentication_algorithm_number {
	MPDU_AUTH_ALGO_OPEN_SYSTEM = 0,
	MPDU_AUTH_ALGO_SHARED_KEY,
};

/* 802.11, Section 8.2.4.1.1, Figure 8-2 */
struct mpdu_fc {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t protocol_version:2;
	uint8_t type:2;
	uint8_t subtype:4;
	bool to_ds:1;
	bool from_ds:1;
	bool more_fragments:1;
	bool retry:1;
	bool power_mgmt:1;
	bool more_data:1;
	bool protected_frame:1;
	bool order:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t subtype:4;
	uint8_t type:2;
	uint8_t protocol_version:2;
	bool order:1;
	bool protected_frame:1;
	bool more_data:1;
	bool power_mgmt:1;
	bool retry:1;
	bool more_fragments:1;
	bool from_ds:1;
	bool to_ds:1;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.1 */
struct mpdu_mgmt_header {
	__le16 duration;
	unsigned char address_1[6];
	unsigned char address_2[6];
	unsigned char address_3[6];
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__le16 fragment_number:4;
	__le16 sequence_number:12;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__le16 sequence_number:12;
	__le16 fragment_number:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__le32 ht_control; /* ToDo? */
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.11 */
struct mpdu_authentication {
	__le16 algorithm;
	__le16 transaction_sequence;
	__le16 status;

	union {
		struct {
			uint8_t element_id;
			uint8_t challenge_text_len;
			unsigned char challenge_text[253];
		} __attribute__ ((packed)) shared_key_23;
	};
	/* ToDo: FT and SAE parts? */
} __attribute__ ((packed));

/* 802.11, Section 8.3.3.12 */
struct mpdu_deauthentication {
	__le16 reason_code;
	/* ToDo: Vendor specific IE? MME? */
} __attribute__ ((packed));

struct mpdu {
	struct mpdu_fc fc;
	struct mpdu_mgmt_header mgmt_hdr;
	union {
		struct mpdu_authentication auth;
		struct mpdu_deauthentication deauth;
	};
} __attribute__ ((packed));

bool mpdu_validate(const unsigned char *mpdu, int len);
