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

#include <string.h>
#include <alloca.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <ell/ell.h>

#include "ell/useful.h"
#include "src/missing.h"
#include "src/module.h"
#include "src/crypto.h"
#include "src/eapol.h"
#include "src/ie.h"
#include "src/util.h"
#include "src/mpdu.h"
#include "src/eap.h"
#include "src/handshake.h"
#include "src/watchlist.h"
#include "src/erp.h"
#include "src/iwd.h"
#include "src/band.h"

static struct l_queue *state_machines;
static struct l_queue *preauths;
static struct watchlist frame_watches;
static uint32_t eapol_4way_handshake_time = 2;

static eapol_rekey_offload_func_t rekey_offload = NULL;

static eapol_tx_packet_func_t tx_packet = NULL;
static eapol_install_pmk_func_t install_pmk = NULL;
static void *tx_user_data;

#define VERIFY_IS_ZERO(field)						\
	do {								\
		if (!l_memeqzero((field), sizeof((field))))	\
			return false;					\
	} while (false)							\

#define MIC_MAXLEN	32

static bool eapol_aes_siv_encrypt(const uint8_t *kek, size_t kek_len,
				struct eapol_key *frame,
				const uint8_t *data, size_t len)
{
	uint8_t encr[16 + len];
	struct iovec ad[1];

	ad[0].iov_base = frame;
	ad[0].iov_len = EAPOL_KEY_DATA(frame, 0) - (uint8_t *)frame;

	if (!aes_siv_encrypt(kek, kek_len, EAPOL_KEY_DATA(frame, 0),
				len, ad, 1, encr))
		return false;

	memcpy(EAPOL_KEY_DATA(frame, 0), encr, sizeof(encr));

	return true;
}

/*
 * MIC calculation depends on the selected hash function.  The has function
 * is given in the EAPoL Key Descriptor Version field.
 *
 * The input struct eapol_key *frame should have a zero-d MIC field
 */
bool eapol_calculate_mic(enum ie_rsn_akm_suite akm, const uint8_t *kck,
				const struct eapol_key *frame, uint8_t *mic,
				size_t mic_len)
{
	size_t frame_len = EAPOL_FRAME_LEN(mic_len) +
					EAPOL_KEY_DATA_LEN(frame, mic_len);

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		return hmac_md5(kck, 16, frame, frame_len, mic, mic_len);
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
		return hmac_sha1(kck, 16, frame, frame_len, mic, mic_len);
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		return cmac_aes(kck, 16, frame, frame_len, mic, mic_len);
	case EAPOL_KEY_DESCRIPTOR_VERSION_AKM_DEFINED:
		switch (akm) {
		case IE_RSN_AKM_SUITE_SAE_SHA256:
		case IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256:
		case IE_RSN_AKM_SUITE_OSEN:
			return cmac_aes(kck, 16, frame, frame_len,
						mic, mic_len);
		case IE_RSN_AKM_SUITE_OWE:
			switch (mic_len) {
			case 16:
				return hmac_sha256(kck, mic_len, frame,
						frame_len, mic,
						mic_len);
			case 24:
				return hmac_sha384(kck, 24, frame, frame_len,
						mic, mic_len);
			}

			/* fall through */
		default:
			return false;
		}
	default:
		return false;
	}
}

bool eapol_verify_mic(enum ie_rsn_akm_suite akm, const uint8_t *kck,
			const struct eapol_key *frame, size_t mic_len)
{
	uint8_t mic[MIC_MAXLEN];
	struct iovec iov[3];
	struct l_checksum *checksum = NULL;

	iov[0].iov_base = (void *) frame;
	iov[0].iov_len = offsetof(struct eapol_key, key_data);

	memset(mic, 0, sizeof(mic));
	iov[1].iov_base = mic;
	iov[1].iov_len = mic_len;

	iov[2].iov_base = (void *) EAPOL_KEY_DATA(frame, mic_len) - 2;
	iov[2].iov_len = EAPOL_KEY_DATA_LEN(frame, mic_len) + 2;

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		checksum = l_checksum_new_hmac(L_CHECKSUM_MD5, kck, 16);
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
		checksum = l_checksum_new_hmac(L_CHECKSUM_SHA1, kck, 16);
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		checksum = l_checksum_new_cmac_aes(kck, 16);
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_AKM_DEFINED:
		switch (akm) {
		case IE_RSN_AKM_SUITE_SAE_SHA256:
		case IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256:
		case IE_RSN_AKM_SUITE_OSEN:
			checksum = l_checksum_new_cmac_aes(kck, 16);
			break;
		case IE_RSN_AKM_SUITE_OWE:
			switch (mic_len) {
			case 16:
				checksum = l_checksum_new_hmac(
							L_CHECKSUM_SHA256,
							kck, 16);
				break;
			case 24:
				checksum = l_checksum_new_hmac(
							L_CHECKSUM_SHA384,
							kck, 24);
				break;
			case 32:
				checksum = l_checksum_new_hmac(
							L_CHECKSUM_SHA512,
							kck, 32);
				break;
			default:
				l_error("Invalid MIC length of %zu for OWE",
						mic_len);
				return false;
			}

			break;
		default:
			return false;
		}

		break;
	default:
		return false;
	}

	if (checksum == NULL)
		return false;

	l_checksum_updatev(checksum, iov, 3);
	l_checksum_get_digest(checksum, mic, mic_len);
	l_checksum_free(checksum);

	if (!memcmp(frame->key_data, mic, mic_len))
		return true;

	return false;
}

/*
 * IEEE 802.11 Table 12-8 -- Integrity and key-wrap algorithms
 */
static size_t eapol_get_mic_length(enum ie_rsn_akm_suite akm, size_t pmk_len)
{
	switch (akm) {
	case IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA384:
	case IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384:
		return 24;
	case IE_RSN_AKM_SUITE_OWE:
		switch (pmk_len) {
		case 32:
			return 16;
		case 48:
			return 24;
		case 64:
			return 32;
		default:
			l_error("Invalid PMK length of %zu for OWE", pmk_len);
			return 0;
		}
	case IE_RSN_AKM_SUITE_FILS_SHA256:
	case IE_RSN_AKM_SUITE_FILS_SHA384:
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256:
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384:
		return 0;
	default:
		return 16;
	}
}

uint8_t *eapol_decrypt_key_data(enum ie_rsn_akm_suite akm, const uint8_t *kek,
				const struct eapol_key *frame,
				size_t *decrypted_size, size_t mic_len)
{
	size_t key_data_len = EAPOL_KEY_DATA_LEN(frame, mic_len);
	const uint8_t *key_data = EAPOL_KEY_DATA(frame, mic_len);
	size_t expected_len;
	uint8_t *buf;
	size_t kek_len;

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		expected_len = key_data_len;
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_AKM_DEFINED:
		switch (akm) {
		case IE_RSN_AKM_SUITE_FILS_SHA256:
		case IE_RSN_AKM_SUITE_FILS_SHA384:
		case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256:
		case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384:
			if (key_data_len < 16)
				return NULL;

			expected_len = key_data_len - 16;
			break;
		case IE_RSN_AKM_SUITE_SAE_SHA256:
		case IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256:
		case IE_RSN_AKM_SUITE_OWE:
		case IE_RSN_AKM_SUITE_OSEN:
			if (key_data_len < 24 || key_data_len % 8)
				return NULL;

			expected_len = key_data_len - 8;
			break;
		default:
			return NULL;
		}

		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		if (key_data_len < 24 || key_data_len % 8)
			return NULL;

		expected_len = key_data_len - 8;
		break;
	default:
		return NULL;
	}

	buf = l_new(uint8_t, expected_len);

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
	{
		uint8_t key[32];
		bool ret;

		memcpy(key, frame->eapol_key_iv, 16);
		memcpy(key + 16, kek, 16);

		ret = arc4_skip(key, 32, 256, key_data, key_data_len, buf);
		explicit_bzero(key, sizeof(key));

		if (!ret)
			goto error;

		break;
	}
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AKM_DEFINED:
		switch (akm) {
		case IE_RSN_AKM_SUITE_OWE:
			switch (mic_len) {
			case 16:
				kek_len = 16;
				break;
			case 24:
			case 32:
				kek_len = 32;
				break;
			default:
				l_error("Invalid MIC length of %zu for OWE",
						mic_len);
				goto error;
			}

			if (!aes_unwrap(kek, kek_len, key_data,
						key_data_len, buf))
				goto error;

			break;
		case IE_RSN_AKM_SUITE_FILS_SHA256:
		case IE_RSN_AKM_SUITE_FILS_SHA384:
		case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256:
		case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384:
		{
			struct iovec ad[1];

			ad[0].iov_base = (void *)frame;
			ad[0].iov_len = key_data - (const uint8_t *)frame;

			if (akm == IE_RSN_AKM_SUITE_FILS_SHA256 || akm ==
					IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256)
				kek_len = 32;
			else
				kek_len = 64;

			if (!aes_siv_decrypt(kek, kek_len, key_data,
						key_data_len, ad, 1, buf))
				goto error;

			break;
		}
		default:
			kek_len = 16;

			if (!aes_unwrap(kek, kek_len, key_data,
						key_data_len, buf))
				goto error;
			break;
		}

		break;
	}

	if (decrypted_size)
		*decrypted_size = expected_len;

	return buf;

error:
	l_free(buf);
	return NULL;
}

/*
 * Pad and encrypt the plaintext Key Data contents in @key_data using
 * the encryption scheme required by @out_frame->key_descriptor_version,
 * write results to @out_frame->key_data and @out_frame->key_data_len.
 *
 * Note that for efficiency @key_data is being modified, including in
 * case of failure, so it must be sufficiently larger than @key_data_len.
 */
static int eapol_encrypt_key_data(const uint8_t *kek, uint8_t *key_data,
				size_t key_data_len,
				struct eapol_key *out_frame, size_t mic_len)
{
	uint8_t key[32];
	bool ret;

	switch (out_frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		/*
		 * Not following the spec to generate the IV. The spec outlines
		 * a procedure where a 32 byte buffer is held and incremented
		 * each time nonces are created, and the IV comes from this
		 * buffer. In the end randomizing the IV every time should be
		 * just as good. This is how we handle the GTK in AP mode.
		 */
		l_getrandom(out_frame->eapol_key_iv, 16);

		memcpy(key, out_frame->eapol_key_iv, 16);
		memcpy(key + 16, kek, 16);

		ret = arc4_skip(key, 32, 256, key_data, key_data_len,
				EAPOL_KEY_DATA(out_frame, mic_len));
		explicit_bzero(key, sizeof(key));

		if (!ret)
			return -ENOTSUP;

		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		if (key_data_len < 16 || key_data_len % 8)
			key_data[key_data_len++] = 0xdd;
		while (key_data_len < 16 || key_data_len % 8)
			key_data[key_data_len++] = 0x00;

		if (!aes_wrap(kek, key_data, key_data_len,
					EAPOL_KEY_DATA(out_frame, mic_len)))
			return -ENOPROTOOPT;

		key_data_len += 8;

		break;
	}

	l_put_be16(key_data_len, EAPOL_KEY_DATA(out_frame, mic_len) - 2);

	return key_data_len;
}

static void eapol_key_data_append(struct eapol_key *ek,
				size_t mic_len,
				enum handshake_kde selector,
				const uint8_t *data, size_t data_len)
{
	uint16_t key_data_len = EAPOL_KEY_DATA_LEN(ek, mic_len);
	uint8_t *ptr = EAPOL_KEY_DATA(ek, mic_len);

	ptr[key_data_len++] = IE_TYPE_VENDOR_SPECIFIC;
	ptr[key_data_len++] = 4 + data_len;
	l_put_be32(selector, ptr + key_data_len);
	key_data_len += 4;
	memcpy(ptr + key_data_len, data, data_len);
	key_data_len += data_len;
	l_put_be16(key_data_len, ek->key_data + mic_len);
}

#define VERIFY_PTK_COMMON(ek)	\
	if (!ek->key_type)	\
		return false;	\
	if (ek->smk_message)	\
		return false;	\
	if (ek->request)	\
		return false;	\
	if (ek->error)		\
		return false	\

bool eapol_verify_ptk_1_of_4(const struct eapol_key *ek, size_t mic_len,
				bool ptk_complete)
{
	/* Verify according to 802.11, Section 11.6.6.2 */
	VERIFY_PTK_COMMON(ek);

	if (ek->install)
		return false;

	if (!ek->key_ack)
		return false;

	if (ek->key_mic)
		return false;

	if (ek->secure != ptk_complete)
		return false;

	if (ek->encrypted_key_data)
		return false;

	if (ek->wpa_key_id)
		return false;

	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);

	if (!l_memeqzero(EAPOL_KEY_MIC(ek), mic_len))
		return false;

	return true;
}

bool eapol_verify_ptk_2_of_4(const struct eapol_key *ek, bool ptk_complete)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.6.3 */
	VERIFY_PTK_COMMON(ek);

	if (ek->install)
		return false;

	if (ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (ek->secure != ptk_complete)
		return false;

	if (ek->encrypted_key_data)
		return false;

	if (ek->wpa_key_id)
		return false;

	if (ek->request)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	L_WARN_ON(key_len != 0);

	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);

	return true;
}

bool eapol_verify_ptk_3_of_4(const struct eapol_key *ek, bool is_wpa,
				size_t mic_len)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.6.4 */
	VERIFY_PTK_COMMON(ek);

	/*
	 * TODO: Handle cases where install might be 0:
	 * For PTK generation, 0 only if the AP does not support key mapping
	 * keys, or if the STA has the No Pairwise bit (in the RSN Capabilities
	 * field) equal to 1 and only the group key is used.
	 */
	if (!ek->install)
		return false;

	if (!ek->key_ack)
		return false;

	if (mic_len && !ek->key_mic)
		return false;

	if (ek->secure != !is_wpa)
		return false;

	/* Must be encrypted when GTK is present but reserved in WPA */
	if (!ek->encrypted_key_data && !is_wpa)
		return false;

	if (ek->wpa_key_id)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 16 && key_len != 32)
		return false;

	VERIFY_IS_ZERO(ek->reserved);

	return true;
}

bool eapol_verify_ptk_4_of_4(const struct eapol_key *ek, bool is_wpa)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.6.5 */
	VERIFY_PTK_COMMON(ek);

	if (ek->install)
		return false;

	if (ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (ek->secure != !is_wpa)
		return false;

	if (ek->encrypted_key_data)
		return false;

	if (ek->wpa_key_id)
		return false;

	if (ek->request)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	L_WARN_ON(key_len != 0);

	VERIFY_IS_ZERO(ek->key_nonce);
	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);

	return true;
}

#define VERIFY_GTK_COMMON(ek)	\
	if (ek->key_type)	\
		return false;	\
	if (ek->smk_message)	\
		return false;	\
	if (ek->request)	\
		return false;	\
	if (ek->error)		\
		return false;	\
	if (ek->install)	\
		return false	\

bool eapol_verify_gtk_1_of_2(const struct eapol_key *ek, bool is_wpa,
				size_t mic_len)
{
	uint16_t key_len;

	VERIFY_GTK_COMMON(ek);

	if (!ek->key_ack)
		return false;

	if (mic_len && !ek->key_mic)
		return false;

	if (!ek->secure)
		return false;

	/* Must be encrypted when GTK is present but reserved in WPA */
	if (!ek->encrypted_key_data && !is_wpa)
		return false;

	/*
	 * In P802.11i/D3.0 the Key Length should be 16 for WPA but hostapd
	 * uses 16 for CCMP and 32 for TKIP.  Since 802.11i-2004 there's
	 * inconsistency in the required value, for example 0 is clearly
	 * specified in 802.11-2012 11.6.7.2 but 11.6.2 doesn't list 0 and
	 * makes the value depend on the pairwise key type.
	 */
	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0 && key_len != 16 && key_len != 32)
		return false;

	VERIFY_IS_ZERO(ek->reserved);

	/*
	 * WPA_80211_v3_1, Section 2.2.4:
	 * "Key Index (bits 4 and 5): specifies the key id of the temporal
	 * key of the key derived from the message. The value of this shall be
	 * zero (0) if the value of Key Type (bit 4) is Pairwise (1). The Key
	 * Type and Key Index shall not both be 0 in the same message.
	 *
	 * Group keys shall not use key id 0. This means that key ids 1 to 3
	 * are available to be used to identify Group keys. This document
	 * recommends that implementations reserve key ids 1 and 2 for Group
	 * Keys, and that key id 3 is not used.
	 */
	if (is_wpa && !ek->wpa_key_id)
		return false;

	return true;
}

bool eapol_verify_gtk_2_of_2(const struct eapol_key *ek, bool is_wpa)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.7.3 */
	VERIFY_GTK_COMMON(ek);

	if (ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (!ek->secure)
		return false;

	if (ek->encrypted_key_data)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0)
		return false;

	VERIFY_IS_ZERO(ek->key_nonce);
	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);

	return true;
}

static struct eapol_key *eapol_create_common(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				bool secure,
				uint64_t key_replay_counter,
				const uint8_t snonce[],
				size_t extra_len,
				const uint8_t *extra_data,
				int key_type,
				bool is_wpa,
				size_t mic_len)
{
	size_t extra_key_len = (mic_len == 0) ? 16 : 0;
	size_t to_alloc = EAPOL_FRAME_LEN(mic_len);

	struct eapol_key *out_frame = l_malloc(to_alloc + extra_len +
						extra_key_len);

	memset(out_frame, 0, to_alloc + extra_len + extra_key_len);

	out_frame->header.protocol_version = protocol;
	out_frame->header.packet_type = 0x3;
	out_frame->header.packet_len = L_CPU_TO_BE16(to_alloc + extra_len +
							extra_key_len - 4);
	out_frame->descriptor_type = is_wpa ? EAPOL_DESCRIPTOR_TYPE_WPA :
		EAPOL_DESCRIPTOR_TYPE_80211;
	out_frame->key_descriptor_version = version;
	out_frame->key_type = key_type;
	out_frame->install = false;
	out_frame->key_ack = false;
	out_frame->key_mic = (mic_len) ? true : false;
	out_frame->secure = secure;
	out_frame->error = false;
	out_frame->request = false;
	out_frame->encrypted_key_data = (mic_len) ? false : true;
	out_frame->smk_message = false;
	out_frame->key_length = 0;
	out_frame->key_replay_counter = L_CPU_TO_BE64(key_replay_counter);
	memcpy(out_frame->key_nonce, snonce, sizeof(out_frame->key_nonce));

	l_put_be16(extra_len + extra_key_len, out_frame->key_data + mic_len);

	if (extra_len)
		memcpy(EAPOL_KEY_DATA(out_frame, mic_len), extra_data,
					extra_len);

	return out_frame;
}

struct eapol_key *eapol_create_ptk_2_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				const uint8_t snonce[],
				size_t extra_len,
				const uint8_t *extra_data,
				bool is_wpa,
				size_t mic_len,
				bool secure)
{
	return eapol_create_common(protocol, version, secure,
					key_replay_counter, snonce, extra_len,
					extra_data, 1, is_wpa, mic_len);
}

struct eapol_key *eapol_create_ptk_4_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				bool is_wpa,
				size_t mic_len)
{
	uint8_t snonce[32];

	memset(snonce, 0, sizeof(snonce));
	return eapol_create_common(protocol, version,
					is_wpa ? false : true,
					key_replay_counter, snonce, 0, NULL,
					1, is_wpa, mic_len);
}

struct eapol_key *eapol_create_gtk_2_of_2(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				size_t extra_len,
				const uint8_t *extra_data,
				bool is_wpa, uint8_t wpa_key_id, size_t mic_len)
{
	uint8_t snonce[32];
	struct eapol_key *step2;

	memset(snonce, 0, sizeof(snonce));
	step2 = eapol_create_common(protocol, version, true,
					key_replay_counter, snonce,
					extra_len, extra_data, 0, is_wpa,
					mic_len);

	if (!step2)
		return step2;

	/*
	 * WPA_80211_v3_1, Section 2.2.4:
	 * "The Key Type and Key Index shall not both be 0 in the same message"
	 *
	 * The above means that even though sending the key index back to the
	 * AP has no practical value, we must still do so.
	 */
	if (is_wpa)
		step2->wpa_key_id = wpa_key_id;

	return step2;
}

struct eapol_frame_watch {
	uint32_t ifindex;
	struct watchlist_item super;
};

static void eapol_frame_watch_free(struct watchlist_item *item)
{
	struct eapol_frame_watch *efw =
		l_container_of(item, struct eapol_frame_watch, super);

	l_free(efw);
}

static const struct watchlist_ops eapol_frame_watch_ops = {
	.item_free = eapol_frame_watch_free,
};

static int32_t eapol_frame_watch_add(uint32_t ifindex,
					eapol_frame_watch_func_t handler,
					void *user_data)
{
	struct eapol_frame_watch *efw;

	efw = l_new(struct eapol_frame_watch, 1);
	efw->ifindex = ifindex;

	return watchlist_link(&frame_watches, &efw->super,
				handler, user_data, NULL);
}

static bool eapol_frame_watch_remove(uint32_t id)
{
	return watchlist_remove(&frame_watches, id);
}

struct eapol_sm {
	struct handshake_state *handshake;
	enum eapol_protocol_version protocol_version;
	uint64_t replay_counter;
	void *user_data;
	struct l_timeout *timeout;
	struct l_timeout *eapol_start_timeout;
	unsigned int frame_retry;
	uint16_t listen_interval;
	bool have_replay:1;
	bool started:1;
	bool use_eapol_start:1;
	bool require_handshake:1;
	bool eap_exchanged:1;
	bool last_eap_unencrypted:1;
	struct eap_state *eap;
	struct eapol_frame *early_frame;
	bool early_frame_unencrypted : 1;
	uint32_t watch_id;
	uint8_t installed_gtk_len;
	uint8_t installed_gtk[CRYPTO_MAX_GTK_LEN];
	uint8_t installed_igtk_len;
	uint8_t installed_igtk[CRYPTO_MAX_IGTK_LEN];
	unsigned int mic_len;
	bool rekey : 1;
};

static void eapol_sm_destroy(void *value)
{
	struct eapol_sm *sm = value;

	l_timeout_remove(sm->timeout);
	l_timeout_remove(sm->eapol_start_timeout);

	if (sm->eap)
		eap_free(sm->eap);

	l_free(sm->early_frame);

	eapol_frame_watch_remove(sm->watch_id);

	sm->installed_gtk_len = 0;
	explicit_bzero(sm->installed_gtk, sizeof(sm->installed_gtk));
	sm->installed_igtk_len = 0;
	explicit_bzero(sm->installed_igtk, sizeof(sm->installed_igtk));

	l_free(sm);
}

struct eapol_sm *eapol_sm_new(struct handshake_state *hs)
{
	struct eapol_sm *sm;

	sm = l_new(struct eapol_sm, 1);

	sm->handshake = hs;

	if (hs->settings_8021x && !hs->authenticator)
		sm->use_eapol_start = true;

	sm->require_handshake = true;

	return sm;
}

void eapol_sm_free(struct eapol_sm *sm)
{
	l_queue_remove(state_machines, sm);

	eapol_sm_destroy(sm);
}

void eapol_sm_set_listen_interval(struct eapol_sm *sm, uint16_t interval)
{
	sm->listen_interval = interval;
}

void eapol_sm_set_user_data(struct eapol_sm *sm, void *user_data)
{
	sm->user_data = user_data;
}

static void eapol_sm_write(struct eapol_sm *sm, const struct eapol_frame *ef,
				bool noencrypt)
{
	const uint8_t *dst = sm->handshake->authenticator ?
		sm->handshake->spa : sm->handshake->aa;

	__eapol_tx_packet(sm->handshake->ifindex, dst, ETH_P_PAE, ef,
				noencrypt);
}

static inline void handshake_failed(struct eapol_sm *sm, uint16_t reason_code)
{
	handshake_event(sm->handshake, HANDSHAKE_EVENT_FAILED, reason_code);

	eapol_sm_free(sm);
}

static void eapol_timeout(struct l_timeout *timeout, void *user_data)
{
	struct eapol_sm *sm = user_data;

	l_timeout_remove(sm->timeout);
	sm->timeout = NULL;

	handshake_failed(sm, MMPDU_REASON_CODE_4WAY_HANDSHAKE_TIMEOUT);
}

static void eapol_install_gtk(struct eapol_sm *sm, uint8_t gtk_key_index,
					const uint8_t *gtk, size_t gtk_len,
					const uint8_t *rsc)
{
	/*
	 * Don't install the same GTK.  On older kernels this resets the
	 * replay counters, etc and can lead to various attacks
	 */
	if (sm->installed_gtk_len == gtk_len &&
			!memcmp(sm->installed_gtk, gtk, gtk_len))
		return;

	handshake_state_install_gtk(sm->handshake, gtk_key_index,
					gtk, gtk_len, rsc, 6);
	memcpy(sm->installed_gtk, gtk, gtk_len);
	sm->installed_gtk_len = gtk_len;
}

static void eapol_install_igtk(struct eapol_sm *sm, uint16_t igtk_key_index,
					const uint8_t *igtk, size_t igtk_len)
{
	/*
	 * Don't install the same IGTK.  On older kernels this resets the
	 * replay counters, etc and can lead to various attacks
	 */
	if (sm->installed_igtk_len == igtk_len - 6 &&
			!memcmp(sm->installed_igtk, igtk + 6, igtk_len - 6))
		return;

	handshake_state_install_igtk(sm->handshake, igtk_key_index,
						igtk + 6, igtk_len - 6, igtk);
	memcpy(sm->installed_igtk, igtk + 6, igtk_len - 6);
	sm->installed_igtk_len = igtk_len - 6;
}

static void __send_eapol_start(struct eapol_sm *sm, bool noencrypt)
{
	uint8_t buf[sizeof(struct eapol_frame)];
	struct eapol_frame *frame = (struct eapol_frame *) buf;

	handshake_event(sm->handshake, HANDSHAKE_EVENT_STARTED);

	frame->header.protocol_version = EAPOL_PROTOCOL_VERSION_2001;
	frame->header.packet_type = 1;
	l_put_be16(0, &frame->header.packet_len);

	eapol_sm_write(sm, frame, noencrypt);
}

static void send_eapol_start(struct l_timeout *timeout, void *user_data)
{
	struct eapol_sm *sm = user_data;

	l_timeout_remove(sm->eapol_start_timeout);
	sm->eapol_start_timeout = NULL;

	/*
	 * AP is probably waiting for us to start, so always send unencrypted
	 * since the key hasn't been established yet
	 */
	__send_eapol_start(sm, true);
}

static void eapol_set_key_timeout(struct eapol_sm *sm,
					l_timeout_notify_cb_t cb)
{
	/*
	 * 802.11-2016 12.7.6.6: "The retransmit timeout value shall be
	 * 100 ms for the first timeout, half the listen interval for the
	 * second timeout, and the listen interval for subsequent timeouts.
	 * If there is no listen interval or the listen interval is zero,
	 * then 100 ms shall be used for all timeout values."
	 */
	unsigned int timeout_ms = 100;
	unsigned int beacon_us = 100 * 1024;

	sm->frame_retry++;

	if (sm->frame_retry == 2 &&
			sm->listen_interval != 0)
		timeout_ms = sm->listen_interval * beacon_us / 2000;
	else if (sm->frame_retry > 2 &&
			sm->listen_interval != 0)
		timeout_ms = sm->listen_interval * beacon_us / 1000;

	if (sm->frame_retry > 1)
		l_timeout_modify_ms(sm->timeout, timeout_ms);
	else {
		if (sm->timeout)
			l_timeout_remove(sm->timeout);

		sm->timeout = l_timeout_create_ms(timeout_ms, cb, sm,
								NULL);
	}
}

/*
 * GCC version 8.3 seems to have trouble correctly calculating
 * ek->header.packet_len when optimization is enabled.  This results in iwd
 * sending invalid 1_of_4 packets (with the KDE payload missing).  Work
 * around this by dropping to O0 for this function when old GCC versions
 * are used
 */
#if __GNUC__ < 9
#pragma GCC optimize ("O0")
#endif

/* 802.11-2016 Section 12.7.6.2 */
static void eapol_send_ptk_1_of_4(struct eapol_sm *sm)
{
	const uint8_t *aa = sm->handshake->aa;
	uint8_t frame_buf[512];
	struct eapol_key *ek = (struct eapol_key *) frame_buf;
	enum crypto_cipher cipher = ie_rsn_cipher_suite_to_cipher(
				sm->handshake->pairwise_cipher);
	uint8_t pmkid[16];
	uint8_t key_descriptor_version;

	handshake_state_new_anonce(sm->handshake);

	sm->handshake->ptk_complete = false;

	sm->replay_counter++;

	memset(ek, 0, EAPOL_FRAME_LEN(sm->mic_len));
	ek->header.protocol_version = sm->protocol_version;
	ek->header.packet_type = 0x3;
	ek->descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211;
	L_WARN_ON(eapol_key_descriptor_version_from_akm(
				sm->handshake->akm_suite,
				sm->handshake->pairwise_cipher,
				&key_descriptor_version) < 0);
	ek->key_descriptor_version = key_descriptor_version;
	ek->key_type = true;
	ek->key_ack = true;
	ek->key_length = L_CPU_TO_BE16(crypto_cipher_key_len(cipher));
	ek->key_replay_counter = L_CPU_TO_BE64(sm->replay_counter);
	memcpy(ek->key_nonce, sm->handshake->anonce, sizeof(ek->key_nonce));

	/* Write the PMKID KDE into Key Data field unencrypted */
	crypto_derive_pmkid(sm->handshake->pmk, sm->handshake->spa, aa,
			pmkid, false);

	eapol_key_data_append(ek, sm->mic_len, HANDSHAKE_KDE_PMKID, pmkid, 16);

	ek->header.packet_len = L_CPU_TO_BE16(EAPOL_FRAME_LEN(sm->mic_len) +
				EAPOL_KEY_DATA_LEN(ek, sm->mic_len) - 4);

	l_debug("STA: "MAC" retries=%u", MAC_STR(sm->handshake->spa),
			sm->frame_retry);

	eapol_sm_write(sm, (struct eapol_frame *) ek, false);
}

#if __GNUC__ < 9
#pragma GCC reset_options
#endif

static void eapol_ptk_1_of_4_retry(struct l_timeout *timeout, void *user_data)
{
	struct eapol_sm *sm = user_data;

	if (sm->frame_retry >= 3) {
		handshake_failed(sm, MMPDU_REASON_CODE_4WAY_HANDSHAKE_TIMEOUT);
		return;
	}

	eapol_send_ptk_1_of_4(sm);

	eapol_set_key_timeout(sm, eapol_ptk_1_of_4_retry);
}

static inline size_t append_ie(uint8_t *ies, const uint8_t *ie)
{
	if (!ie)
		return 0;

	memcpy(ies, ie, ie[1] + 2);
	return ie[1] + 2;
}

static size_t append_oci(uint8_t *ies, const struct band_chandef *chandef)
{
	unsigned int len = 0;

	ies[len++] = IE_TYPE_VENDOR_SPECIFIC;
	ies[len++] = 4 + 3;
	l_put_be32(HANDSHAKE_KDE_OCI, ies + len);
	len += 4;
	oci_from_chandef(chandef, ies + len);
	len += 3;

	return len;
}

static void eapol_handle_ptk_1_of_4(struct eapol_sm *sm,
					const struct eapol_key *ek,
					bool unencrypted)
{
	const uint8_t *kck;
	struct eapol_key *step2;
	uint8_t mic[MIC_MAXLEN];
	uint8_t ies[1024];
	size_t ies_len;
	const uint8_t *own_ie = sm->handshake->supplicant_ie;
	const uint8_t *pmkid;
	struct ie_rsn_info rsn_info;

	l_debug("ifindex=%u", sm->handshake->ifindex);

	if (!eapol_verify_ptk_1_of_4(ek, sm->mic_len,
					sm->handshake->ptk_complete))
		return;

	if (sm->handshake->ptk_complete && unencrypted) {
		l_debug("Dropping unexpectedly unencrypted PTK 1/4 frame");
		return;
	}

	pmkid = handshake_util_find_pmkid_kde(EAPOL_KEY_DATA(ek, sm->mic_len),
					EAPOL_KEY_DATA_LEN(ek, sm->mic_len));

	if (!sm->handshake->wpa_ie) {
		if (ie_parse_rsne_from_data(own_ie, own_ie[1] + 2,
						&rsn_info) < 0)
			goto error_unspecified;
	}

	/*
	 * Require the PMKID KDE whenever we've sent a list of PMKIDs in
	 * our RSNE and we've haven't seen any EAPOL-EAP frame since
	 * (sm->eap_exchanged is false), otherwise treat it as optional and
	 * only validate it against our PMK.  Some 802.11-2012 sections
	 * show message 1/4 without a PMKID KDE and there are APs that
	 * send no PMKID KDE.
	 */
	if (!sm->eap_exchanged && !sm->handshake->wpa_ie &&
			rsn_info.num_pmkids &&
			sm->require_handshake) {
		bool found = false;
		int i;

		if (!pmkid)
			goto error_unspecified;

		for (i = 0; i < rsn_info.num_pmkids; i++)
			if (!l_secure_memcmp(rsn_info.pmkids + i * 16,
						pmkid, 16)) {
				found = true;
				break;
			}

		if (!found)
			goto error_unspecified;
	} else if (pmkid) {
		uint8_t own_pmkid[16];

		if (!handshake_state_get_pmkid(sm->handshake, own_pmkid))
			goto error_unspecified;

		if (l_secure_memcmp(pmkid, own_pmkid, 16)) {
			l_debug("Authenticator sent a PMKID that didn't match");

			/*
			 * If the AP has a different PMKSA from ours and we
			 * have means to create a new PMKSA through EAP then
			 * try that, otherwise give up.
			 */
			if (sm->eap) {
				__send_eapol_start(sm, unencrypted);
				return;
			}

			/*
			 * Some APs are known to send a PMKID KDE with all
			 * zeros for the PMKID.  Others just send seemingly
			 * random data.  Likely we can still
			 * successfully negotiate a handshake, so ignore this
			 * for now and treat it as if the PMKID KDE was not
			 * included
			 */
		}
	}

	/*
	 * If we're in a state where we have successfully processed Message 3,
	 * then assume that the new message 1 is a PTK rekey and start a new
	 * handshake
	 */
	if (!sm->handshake->have_snonce ||
			memcmp(sm->handshake->anonce,
					ek->key_nonce, sizeof(ek->key_nonce)) ||
			sm->handshake->ptk_complete) {
		if (sm->handshake->ptk_complete && sm->handshake->no_rekey) {
			/*
			 * In case of rekey not being allowed, signal to upper
			 * layers that we need to do a full reauth
			 */
			handshake_event(sm->handshake,
					HANDSHAKE_EVENT_REKEY_FAILED);
			return;
		}

		if (sm->handshake->ptk_complete)
			sm->rekey = true;

		handshake_state_new_snonce(sm->handshake);
		handshake_state_set_anonce(sm->handshake, ek->key_nonce);

		if (!handshake_state_derive_ptk(sm->handshake))
			goto error_unspecified;
	}

	if (IE_AKM_IS_FT(sm->handshake->akm_suite)) {
		/*
		 * Rebuild the RSNE to include the PMKR1Name and append
		 * MDE + FTE.
		 */
		rsn_info.num_pmkids = 1;
		rsn_info.pmkids = sm->handshake->pmk_r1_name;

		ie_build_rsne(&rsn_info, ies);
		ies_len = ies[1] + 2;

		ies_len += append_ie(ies + ies_len, sm->handshake->mde);
		ies_len += append_ie(ies + ies_len, sm->handshake->fte);
	} else {
		ies_len = append_ie(ies, own_ie);
	}

	if (sm->handshake->support_ip_allocation) {
		/* Wi-Fi P2P Technical Specification v1.7 Table 58 */
		ies[ies_len++] = IE_TYPE_VENDOR_SPECIFIC;
		ies[ies_len++] = 4 + 1;
		l_put_be32(HANDSHAKE_KDE_IP_ADDRESS_REQ, ies + ies_len);
		ies_len += 4;
		ies[ies_len++] = 0x01;
	}

	/*
	 * IEEE 802.11-2020 Section 12.7.6.3
	 * "Additionally, contains an OCI KDE when
	 *  dot11RSNAOperatingChannelValidationActivated is true on the
	 *  Supplicant."
	 */
	if (sm->handshake->supplicant_ocvc && sm->handshake->chandef)
		ies_len += append_oci(ies + ies_len, sm->handshake->chandef);

	/*
	 * 802.11-2020, Section 12.7.6.3:
	 * "The RSNXE that the Supplicant sent in its (Re)Association Request
	 * frame, if this element is present in the (Re)Association Request
	 * frame that the Supplicant sent."
	 */
	ies_len += append_ie(ies + ies_len, sm->handshake->supplicant_rsnxe);

	step2 = eapol_create_ptk_2_of_4(sm->protocol_version,
					ek->key_descriptor_version,
					L_BE64_TO_CPU(ek->key_replay_counter),
					sm->handshake->snonce, ies_len, ies,
					sm->handshake->wpa_ie, sm->mic_len,
					sm->rekey);

	kck = handshake_state_get_kck(sm->handshake);

	if (sm->mic_len) {
		if (!eapol_calculate_mic(sm->handshake->akm_suite, kck,
				step2, mic, sm->mic_len)) {
			l_info("MIC calculation failed. "
				"Ensure Kernel Crypto is available.");
			l_free(step2);
			handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);

			return;
		}

		memcpy(EAPOL_KEY_MIC(step2), mic, sm->mic_len);
	} else {
		if (!eapol_aes_siv_encrypt(
				handshake_state_get_kek(sm->handshake),
				handshake_state_get_kek_len(sm->handshake),
				step2, ies, ies_len)) {
			l_debug("AES-SIV encryption failed");
			l_free(step2);
			handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
			return;
		}
	}

	eapol_sm_write(sm, (struct eapol_frame *) step2, unencrypted);
	l_free(step2);

	l_timeout_remove(sm->eapol_start_timeout);
	sm->eapol_start_timeout = NULL;

	return;

error_unspecified:
	handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
}

#define EAPOL_PAIRWISE_UPDATE_COUNT 3

/* 802.11-2016 Section 12.7.6.4 */
static void eapol_send_ptk_3_of_4(struct eapol_sm *sm)
{
	uint8_t frame_buf[512];
	unsigned int rsne_len = sm->handshake->authenticator_ie[1] + 2;
	uint8_t key_data_buf[128 + rsne_len];
	int key_data_len = rsne_len;
	struct eapol_key *ek = (struct eapol_key *) frame_buf;
	enum crypto_cipher cipher = ie_rsn_cipher_suite_to_cipher(
				sm->handshake->pairwise_cipher);
	enum crypto_cipher group_cipher = ie_rsn_cipher_suite_to_cipher(
				sm->handshake->group_cipher);
	const uint8_t *kck;
	const uint8_t *kek;
	uint8_t key_descriptor_version;

	sm->replay_counter++;

	memset(ek, 0, EAPOL_FRAME_LEN(sm->mic_len));
	ek->header.protocol_version = sm->protocol_version;
	ek->header.packet_type = 0x3;
	ek->descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211;
	L_WARN_ON(eapol_key_descriptor_version_from_akm(
				sm->handshake->akm_suite,
				sm->handshake->pairwise_cipher,
				&key_descriptor_version) < 0);
	ek->key_descriptor_version = key_descriptor_version;
	ek->key_type = true;
	ek->install = true;
	ek->key_ack = true;
	ek->key_mic = true;
	ek->secure = true;
	ek->encrypted_key_data = true;
	ek->key_length = L_CPU_TO_BE16(crypto_cipher_key_len(cipher));
	ek->key_replay_counter = L_CPU_TO_BE64(sm->replay_counter);
	memcpy(ek->key_nonce, sm->handshake->anonce, sizeof(ek->key_nonce));
	memcpy(ek->key_rsc, sm->handshake->gtk_rsc, 6);
	ek->key_rsc[6] = 0;
	ek->key_rsc[7] = 0;

	/*
	 * Just one RSNE in Key Data as we either accept the single pairwise
	 * cipher in the supplicant IE or fail.
	 */
	memcpy(key_data_buf, sm->handshake->authenticator_ie, rsne_len);

	if (group_cipher) {
		uint8_t *gtk_kde = key_data_buf + key_data_len;

		handshake_util_build_gtk_kde(group_cipher,
						sm->handshake->gtk,
						sm->handshake->gtk_index,
						gtk_kde);
		key_data_len += gtk_kde[1] + 2;
	}

	if (sm->handshake->support_ip_allocation &&
			!sm->handshake->client_ip_addr) {
		handshake_event(sm->handshake, HANDSHAKE_EVENT_P2P_IP_REQUEST);

		/*
		 * If .support_ip_allocation was set, the
		 * HANDSHAKE_EVENT_P2P_IP_REQUEST handler is expected to set
		 * .client_ip_addr if not already set.  Check if the handler
		 * was successful in allocating an address, if it wasn't we'll
		 * just skip the IP Address Allocation KDE.  In either case if
		 * we need to resend message 3/4 the event callback won't be
		 * triggered again because the condition above will be false.
		 */
		if (!sm->handshake->client_ip_addr)
			sm->handshake->support_ip_allocation = false;
	}

	if (sm->handshake->support_ip_allocation) {
		/* Wi-Fi P2P Technical Specification v1.7 Table 59 */
		key_data_buf[key_data_len++] = IE_TYPE_VENDOR_SPECIFIC;
		key_data_buf[key_data_len++] = 4 + 12;
		l_put_be32(HANDSHAKE_KDE_IP_ADDRESS_ALLOC,
				key_data_buf + key_data_len + 0);
		l_put_u32(sm->handshake->client_ip_addr,
				key_data_buf + key_data_len + 4);
		l_put_u32(sm->handshake->subnet_mask,
				key_data_buf + key_data_len + 8);
		l_put_u32(sm->handshake->go_ip_addr,
				key_data_buf + key_data_len + 12);
		key_data_len += 4 + 12;
	}

	kek = handshake_state_get_kek(sm->handshake);
	key_data_len = eapol_encrypt_key_data(kek, key_data_buf,
						key_data_len, ek, sm->mic_len);
	explicit_bzero(key_data_buf, sizeof(key_data_buf));

	if (key_data_len < 0)
		return;

	ek->header.packet_len = L_CPU_TO_BE16(EAPOL_FRAME_LEN(sm->mic_len) +
				key_data_len - 4);

	kck = handshake_state_get_kck(sm->handshake);

	if (!eapol_calculate_mic(sm->handshake->akm_suite, kck, ek,
			EAPOL_KEY_MIC(ek), sm->mic_len))
		return;

	l_debug("STA: "MAC" retries=%u", MAC_STR(sm->handshake->spa),
			sm->frame_retry);

	eapol_sm_write(sm, (struct eapol_frame *) ek, false);
}

static void eapol_ptk_3_of_4_retry(struct l_timeout *timeout,
						void *user_data)
{
	struct eapol_sm *sm = user_data;

	if (sm->frame_retry >= EAPOL_PAIRWISE_UPDATE_COUNT) {
		handshake_failed(sm, MMPDU_REASON_CODE_4WAY_HANDSHAKE_TIMEOUT);
		return;
	}

	eapol_send_ptk_3_of_4(sm);

	eapol_set_key_timeout(sm, eapol_ptk_3_of_4_retry);

	l_debug("attempt %i", sm->frame_retry);
}

static const uint8_t *eapol_find_rsne(const uint8_t *data, size_t data_len,
				const uint8_t **optional)
{
	struct ie_tlv_iter iter;
	const uint8_t *first = NULL;

	ie_tlv_iter_init(&iter, data, data_len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_RSN)
			continue;

		if (!first) {
			first = ie_tlv_iter_get_data(&iter) - 2;
			continue;
		}

		if (optional)
			*optional = ie_tlv_iter_get_data(&iter) - 2;

		return first;
	}

	return first;
}

static const uint8_t *eapol_find_wfa_kde(const uint8_t *data, size_t data_len,
					uint8_t oi_type)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, data_len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) == IE_TYPE_VENDOR_SPECIFIC) {
			if (!is_ie_wfa_ie(iter.data, iter.len, oi_type))
				continue;
		} else
			continue;

		return ie_tlv_iter_get_data(&iter) - 2;
	}

	return NULL;
}

/* 802.11-2016 Section 12.7.6.3 */
static void eapol_handle_ptk_2_of_4(struct eapol_sm *sm,
					const struct eapol_key *ek)
{
	const uint8_t *rsne;
	size_t ptk_size;
	const uint8_t *kck;
	const uint8_t *aa = sm->handshake->aa;

	l_debug("ifindex=%u", sm->handshake->ifindex);

	if (!eapol_verify_ptk_2_of_4(ek, sm->handshake->ptk_complete))
		return;

	if (L_BE64_TO_CPU(ek->key_replay_counter) != sm->replay_counter)
		return;

	ptk_size = handshake_state_get_ptk_size(sm->handshake);

	if (!crypto_derive_pairwise_ptk(sm->handshake->pmk,
					sm->handshake->pmk_len,
					sm->handshake->spa, aa,
					sm->handshake->anonce, ek->key_nonce,
					sm->handshake->ptk, ptk_size,
					L_CHECKSUM_SHA1))
		return;

	kck = handshake_state_get_kck(sm->handshake);

	if (!eapol_verify_mic(sm->handshake->akm_suite, kck, ek,
					sm->mic_len))
		return;

	/*
	 * 12.7.6.3 b) 2) "the Authenticator checks that the RSNE bitwise
	 * matches that from the (Re)Association Request frame.
	 */
	rsne = eapol_find_rsne(EAPOL_KEY_DATA(ek, sm->mic_len),
				EAPOL_KEY_DATA_LEN(ek, sm->mic_len), NULL);
	if (!rsne || rsne[1] != sm->handshake->supplicant_ie[1] ||
			memcmp(rsne + 2, sm->handshake->supplicant_ie + 2,
				rsne[1])) {
		handshake_failed(sm, MMPDU_REASON_CODE_IE_DIFFERENT);
		return;
	}

	if (sm->handshake->support_ip_allocation) {
		size_t len;
		const uint8_t *ip_req_kde =
			handshake_util_find_kde(HANDSHAKE_KDE_IP_ADDRESS_REQ,
					EAPOL_KEY_DATA(ek, sm->mic_len),
					EAPOL_KEY_DATA_LEN(ek, sm->mic_len),
					&len);

		if (ip_req_kde && (len < 1 || ip_req_kde[0] != 0x01)) {
			l_debug("Invalid IP Address Request KDE in frame 2/4");
			handshake_failed(sm, MMPDU_REASON_CODE_INVALID_IE);
			return;
		}

		sm->handshake->support_ip_allocation = ip_req_kde != NULL;
	}

	memcpy(sm->handshake->snonce, ek->key_nonce,
			sizeof(sm->handshake->snonce));
	sm->handshake->have_snonce = true;

	sm->frame_retry = 0;

	eapol_ptk_3_of_4_retry(NULL, sm);
}

static const uint8_t *eapol_find_wpa_ie(const uint8_t *data, size_t data_len)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, data_len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
			continue;

		if (is_ie_wpa_ie(ie_tlv_iter_get_data(&iter),
				ie_tlv_iter_get_length(&iter)))
			return ie_tlv_iter_get_data(&iter) - 2;
	}

	return NULL;
}

static bool eapol_check_ip_mask(const uint8_t *mask,
				const uint8_t *ip1, const uint8_t *ip2)
{
	uint32_t mask_uint = l_get_be32(mask);
	uint32_t ip1_uint = l_get_be32(ip1);
	uint32_t ip2_uint = l_get_be32(ip2);

	return
		/* Check IPs are in the same subnet */
		((ip1_uint ^ ip2_uint) & mask_uint) == 0 &&
		/* Check IPs are different */
		ip1_uint != ip2_uint &&
		/* Check IPs are not subnet addresses */
		(ip1_uint & ~mask_uint) != 0 &&
		(ip2_uint & ~mask_uint) != 0 &&
		/* Check IPs are not broadcast addresses */
		(ip1_uint | mask_uint) != 0xffffffff &&
		(ip2_uint | mask_uint) != 0xffffffff &&
		/* Check the 1s are at the start of the mask */
		(uint32_t) (mask_uint << __builtin_popcountl(mask_uint)) == 0;
}

static int eapol_ie_matches(const void *ies, size_t ies_len,
					enum ie_type type, uint8_t *target_ie)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, ies, ies_len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != type)
			continue;

		if (!target_ie)
			return -EINVAL;

		if (memcmp(ie_tlv_iter_get_data(&iter) - 2,
						target_ie, target_ie[1] + 2))
			return -EBADMSG;

		return 0;
	}

	if (!target_ie)
		return 0;

	return -ENOENT;
}

static void eapol_handle_ptk_3_of_4(struct eapol_sm *sm,
					const struct eapol_key *ek,
					const uint8_t *decrypted_key_data,
					size_t decrypted_key_data_size,
					bool unencrypted)
{
	struct handshake_state *hs = sm->handshake;
	const uint8_t *kck;
	const uint8_t *kek;
	_auto_(l_free) struct eapol_key *step4 = NULL;
	uint8_t mic[MIC_MAXLEN];
	const uint8_t *gtk = NULL;
	size_t gtk_len;
	const uint8_t *igtk = NULL;
	size_t igtk_len;
	const uint8_t *key_id = NULL;
	size_t key_id_len;
	const uint8_t *rsne;
	struct ie_rsn_info rsn_info;
	const uint8_t *optional_rsne = NULL;
	const uint8_t *transition_disable;
	size_t transition_disable_len;
	uint8_t gtk_key_index;
	uint16_t igtk_key_index;
	const uint8_t *oci;
	size_t oci_len;
	int r;

	l_debug("ifindex=%u", hs->ifindex);

	if (!eapol_verify_ptk_3_of_4(ek, hs->wpa_ie, sm->mic_len))
		return;

	/*
	 * 802.11-2016, Section 12.7.6.4:
	 * "On reception of message 3, the Supplicant silently discards the
	 * message if the Key Replay Counter field value has already been used
	 * or if the ANonce value in message 3 differs from the ANonce value
	 * in message 1."
	 */
	if (memcmp(hs->anonce, ek->key_nonce, sizeof(ek->key_nonce)))
		return;

	/*
	 * 11.6.6.4: "Verifies the RSNE. If it is part of a Fast BSS Transition
	 * Initial Mobility Domain Association, see 12.4.2. Otherwise, if it is
	 * not identical to that the STA received in the Beacon or Probe
	 * Response frame, the STA shall disassociate.
	 */
	if (hs->wpa_ie)
		rsne = eapol_find_wpa_ie(decrypted_key_data,
					decrypted_key_data_size);
	else if (hs->osen_ie)
		rsne = eapol_find_wfa_kde(decrypted_key_data,
					decrypted_key_data_size,
					IE_WFA_OI_OSEN);
	else
		rsne = eapol_find_rsne(decrypted_key_data,
					decrypted_key_data_size,
					&optional_rsne);

	if (!rsne)
		goto error_ie_different;

	if (!hs->wpa_ie)
		r = ie_parse_rsne_from_data(rsne, rsne[1] + 2, &rsn_info);
	else
		r = ie_parse_wpa_from_data(rsne, rsne[1] + 2, &rsn_info);

	if (r < 0)
		goto error_ie_different;

	if ((rsne[1] != hs->authenticator_ie[1] ||
			memcmp(rsne + 2, hs->authenticator_ie + 2, rsne[1])) &&
			!handshake_util_ap_ie_matches(&rsn_info,
							hs->authenticator_ie,
							hs->wpa_ie))
		goto error_ie_different;

	oci = handshake_util_find_kde(HANDSHAKE_KDE_OCI, decrypted_key_data,
					decrypted_key_data_size, &oci_len);

	if (hs->akm_suite &
			(IE_RSN_AKM_SUITE_FT_OVER_8021X |
			 IE_RSN_AKM_SUITE_FT_USING_PSK |
			 IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256)) {
		if (rsn_info.num_pmkids != 1 || memcmp(rsn_info.pmkids,
						hs->pmk_r1_name, 16))
			goto error_ie_different;

		if (eapol_ie_matches(decrypted_key_data,
					decrypted_key_data_size,
					IE_TYPE_MOBILITY_DOMAIN,
					hs->mde) < 0)
			goto error_ie_different;

		if (eapol_ie_matches(decrypted_key_data,
					decrypted_key_data_size,
					IE_TYPE_FAST_BSS_TRANSITION,
					hs->fte) < 0)
			goto error_ie_different;
	}

	/*
	 * 802.11-2020, Section 12.7.6.4:
	 * "If the RSNXE is present, the Supplicant verifies that the RSNXE is
	 * identical to that the STA received in the Beacon or Probe Response
	 * frame."
	 *
	 * Verify only if RSN is used
	 */
	if (!hs->osen_ie && !hs->wpa_ie &&
			eapol_ie_matches(decrypted_key_data,
					decrypted_key_data_size,
					IE_TYPE_RSNX,
					hs->authenticator_rsnxe) < 0)
		goto error_ie_different;

	/*
	 * 802.11-2020, Section 12.7.6.4
	 * If dot11RSNAOperatingChannelValidationActivated is true and
	 * Authenticator RSNE indicates OCVC capability, the Supplicant
	 * silently discards message 3 if any of the following are true:
	 *  - OCI KDE or FTE OCI subelement is missing in the message
	 *  - Channel information in the OCI does not match current operating
	 *    channel parameters (see 12.2.9)
	 */
	if (hs->authenticator_ocvc &&
			handshake_state_verify_oci(hs, oci, oci_len) < 0)
		return;

	/*
	 * If ptk_complete is set, then we are receiving Message 3 again.
	 * It must be a retransmission, otherwise the anonce wouldn't match
	 * and we wouldn't get here.  Skip processing the rest of the message
	 * and send our reply.  Do not install the keys again.
	 */
	if (hs->ptk_complete)
		goto retransmit;

	/*
	 * 11.6.6.4: "If a second RSNE is provided in the message, the
	 * Supplicant uses the pairwise cipher suite specified in the second
	 * RSNE or deauthenticates."
	 */
	if (optional_rsne) {
		struct ie_rsn_info info2;
		uint16_t override;

		if (ie_parse_rsne_from_data(optional_rsne, optional_rsne[1] + 2,
						&info2) < 0)
			goto error_ie_different;

		/*
		 * 11.6.2:
		 * It may happen, for example, that a Supplicant selects a
		 * pairwise cipher suite which is advertised by an AP, but
		 * which policy disallows for this particular STA. An
		 * Authenticator may, therefore, insert a second RSNE to
		 * overrule the STA's selection. An Authenticator's SME shall
		 * insert the second RSNE, after the first RSNE, only for this
		 * purpose. The pairwise cipher suite in the second RSNE
		 * included shall be one of the ciphers advertised by the
		 * Authenticator. All other fields in the second RSNE shall be
		 * identical to the first RSNE.
		 *
		 * - Check that akm_suites and group_cipher are the same
		 *   between rsne1 and rsne2
		 * - Check that pairwise_ciphers is not the same between rsne1
		 *   and rsne2
		 * - Check that rsne2 pairwise_ciphers is a subset of rsne
		 */
		if (rsn_info.akm_suites != info2.akm_suites ||
				rsn_info.group_cipher != info2.group_cipher)
			goto error_ie_different;

		override = info2.pairwise_ciphers;

		if (override == rsn_info.pairwise_ciphers ||
				!(rsn_info.pairwise_ciphers & override) ||
				__builtin_popcount(override) != 1) {
			handshake_failed(sm,
				MMPDU_REASON_CODE_INVALID_PAIRWISE_CIPHER);
			return;
		}

		handshake_state_override_pairwise_cipher(hs, override);
	}

	if (!hs->wpa_ie && hs->group_cipher !=
				IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC) {
		gtk = handshake_util_find_gtk_kde(decrypted_key_data,
							decrypted_key_data_size,
							&gtk_len);
		if (!gtk) {
			handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
			return;
		}

		/* TODO: Handle tx bit */

		gtk_key_index = bit_field(gtk[0], 0, 2);
		gtk += 2;
		gtk_len -= 2;
	}

	if (hs->mfp) {
		igtk = handshake_util_find_igtk_kde(decrypted_key_data,
							decrypted_key_data_size,
							&igtk_len);
		if (!igtk) {
			handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
			return;
		}

		igtk_key_index = l_get_le16(igtk);
		igtk += 2;
		igtk_len -= 2;
	}

	key_id = handshake_util_find_kde(HANDSHAKE_KDE_KEY_ID,
					decrypted_key_data,
					decrypted_key_data_size, &key_id_len);
	if (hs->ext_key_id_capable) {
		uint8_t idx;

		if (!key_id) {
			l_debug("No extended key KDE in frame 3/4");
			handshake_failed(sm, MMPDU_REASON_CODE_INVALID_IE);
			return;
		}

		if (key_id_len != 2) {
			l_error("invalid Key ID KDE format");
			handshake_failed(sm, MMPDU_REASON_CODE_INVALID_IE);
			return;
		}

		idx = bit_field(key_id[0], 0, 2);

		/*
		 * IEEE 802.11-2020 - 12.7.6.4 4-way handshake message 3
		 * "... the Authenticator assigns a new Key ID for the PTKSA in
		 * the range of 0 to 1 that is different from the Key ID
		 * assigned in the previous handshake"
		 */
		if ((idx != 0 && idx != 1) || (sm->rekey &&
						idx == hs->active_tk_index)) {
			l_error("invalid Key ID KDE value (%u)", idx);
			handshake_failed(sm, MMPDU_REASON_CODE_INVALID_IE);
			return;
		}

		hs->active_tk_index = idx;

		l_debug("using Extended key ID %u", hs->active_tk_index);
	}

	if (hs->support_ip_allocation) {
		size_t len;
		const uint8_t *ip_alloc_kde =
			handshake_util_find_kde(HANDSHAKE_KDE_IP_ADDRESS_ALLOC,
						decrypted_key_data,
						decrypted_key_data_size,
						&len);

		if (ip_alloc_kde && (len < 12 ||
				!eapol_check_ip_mask(ip_alloc_kde + 4,
							ip_alloc_kde,
							ip_alloc_kde + 8))) {
			l_debug("Invalid IP Allocation KDE in frame 3/4");
			handshake_failed(sm, MMPDU_REASON_CODE_INVALID_IE);
			return;
		}

		hs->support_ip_allocation = ip_alloc_kde != NULL;

		if (ip_alloc_kde) {
			hs->client_ip_addr = l_get_u32(ip_alloc_kde);
			hs->subnet_mask = l_get_u32(ip_alloc_kde + 4);
			hs->go_ip_addr = l_get_u32(ip_alloc_kde + 8);
		} else
			l_debug("Authenticator ignored our IP Address Request");
	}

	transition_disable =
		handshake_util_find_kde(HANDSHAKE_KDE_TRANSITION_DISABLE,
					decrypted_key_data,
					decrypted_key_data_size,
					&transition_disable_len);
	if (transition_disable)
		handshake_event(hs, HANDSHAKE_EVENT_TRANSITION_DISABLE,
				transition_disable, transition_disable_len);

retransmit:
	/*
	 * 802.11-2016, Section 12.7.6.4:
	 * "b) Verifies the message 3 MIC. If the calculated MIC does not match
	 * the MIC that the Authenticator included in the EAPOL-Key frame, the
	 * Supplicant silently discards message 3."
	 * "c) Updates the last-seen value of the Key Replay Counter field."
	 *
	 * Note that part b was done in eapol_key_handle
	 */
	sm->replay_counter = L_BE64_TO_CPU(ek->key_replay_counter);
	sm->have_replay = true;

	step4 = eapol_create_ptk_4_of_4(sm->protocol_version,
					ek->key_descriptor_version,
					sm->replay_counter,
					hs->wpa_ie, sm->mic_len);

	kck = handshake_state_get_kck(hs);
	kek = handshake_state_get_kek(hs);

	if (sm->mic_len) {
		if (!eapol_calculate_mic(hs->akm_suite, kck,
						step4, mic, sm->mic_len)) {
			l_debug("MIC Calculation failed");
			handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
			return;
		}

		memcpy(EAPOL_KEY_MIC(step4), mic, sm->mic_len);
	} else {
		if (!eapol_aes_siv_encrypt(handshake_state_get_kek(hs),
						handshake_state_get_kek_len(hs),
						step4, NULL, 0)) {
			l_debug("AES-SIV encryption failed");
			handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
			return;
		}
	}

	/*
	 * For WPA1 the group handshake should be happening after we set the
	 * ptk, this flag tells netdev to wait for the gtk/igtk before
	 * completing the connection.
	 */
	if (!gtk && hs->group_cipher != IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC)
		hs->wait_for_gtk = true;

	if (gtk)
		eapol_install_gtk(sm, gtk_key_index, gtk, gtk_len, ek->key_rsc);

	if (igtk)
		eapol_install_igtk(sm, igtk_key_index, igtk, igtk_len);

	/*
	 * Only install if this is the first 3/4 message (not retransmitting)
	 * and a rekey. Initial associations don't need the special RX -> TX
	 * procedure and can install the TK normally
	 */
	if (key_id && hs->ext_key_id_capable && sm->rekey) {
		handshake_state_install_ext_ptk(hs, hs->active_tk_index,
						(struct eapol_frame *) step4,
						ETH_P_PAE, unencrypted);

		return;
	}

	eapol_sm_write(sm, (struct eapol_frame *) step4, unencrypted);

	if (hs->ptk_complete)
		return;

	handshake_state_install_ptk(hs);

	if (rekey_offload)
		rekey_offload(hs->ifindex, kek, kck,
				sm->replay_counter, sm->user_data);

	l_timeout_remove(sm->timeout);
	sm->timeout = NULL;

	return;

error_ie_different:
	handshake_failed(sm, MMPDU_REASON_CODE_IE_DIFFERENT);
}

/* 802.11-2016 Section 12.7.6.5 */
static void eapol_handle_ptk_4_of_4(struct eapol_sm *sm,
					const struct eapol_key *ek)
{
	const uint8_t *kck;

	l_debug("ifindex=%u", sm->handshake->ifindex);

	if (!eapol_verify_ptk_4_of_4(ek, false))
		return;

	if (L_BE64_TO_CPU(ek->key_replay_counter) != sm->replay_counter)
		return;

	kck = handshake_state_get_kck(sm->handshake);

	if (!eapol_verify_mic(sm->handshake->akm_suite, kck, ek,
				sm->mic_len))
		return;

	l_timeout_remove(sm->timeout);
	sm->timeout = NULL;

	/*
	 * If ptk_complete is set, then we are receiving Message 4 again.
	 * This might be a retransmission, so accept but don't install
	 * the keys again.
	 */
	if (!sm->handshake->ptk_complete)
		handshake_state_install_ptk(sm->handshake);

	sm->handshake->ptk_complete = true;
}

static void eapol_handle_gtk_1_of_2(struct eapol_sm *sm,
					const struct eapol_key *ek,
					const uint8_t *decrypted_key_data,
					size_t decrypted_key_data_size,
					bool unencrypted)
{
	struct handshake_state *hs = sm->handshake;
	const uint8_t *kck;
	struct eapol_key *step2;
	uint8_t mic[MIC_MAXLEN];
	const uint8_t *gtk;
	size_t gtk_len;
	uint8_t gtk_key_index;
	const uint8_t *igtk;
	size_t igtk_len;
	uint16_t igtk_key_index;
	const uint8_t *oci;
	size_t oci_len;
	uint8_t ies[1024];
	size_t ies_len = 0;

	l_debug("ifindex=%u", hs->ifindex);

	if (!eapol_verify_gtk_1_of_2(ek, hs->wpa_ie, sm->mic_len))
		return;

	oci = handshake_util_find_kde(HANDSHAKE_KDE_OCI, decrypted_key_data,
					decrypted_key_data_size, &oci_len);

	/*
	 * 802.11-2020, Section 12.7.2.2
	 * If dot11RSNAOperatingChannelValidationActivated is true and
	 * Authenticator RSNE indicates OCVC capability, the Supplicant
	 * silently discards message 1 if any of the following are true:
	 *   - OCI KDE is missing in the message
	 *   - Channel information in the OCI KDE does not match current
	 *   operating channel parameters (see 12.2.9)
	 */
	if (hs->authenticator_ocvc &&
			handshake_state_verify_oci(hs, oci, oci_len) < 0)
		return;

	if (!hs->wpa_ie) {
		gtk = handshake_util_find_gtk_kde(decrypted_key_data,
							decrypted_key_data_size,
							&gtk_len);
		if (!gtk)
			return;

		gtk_key_index = bit_field(gtk[0], 0, 2);
		gtk += 2;
		gtk_len -= 2;
	} else {
		gtk = decrypted_key_data;
		gtk_len = decrypted_key_data_size;

		if (!gtk || gtk_len < CRYPTO_MIN_GTK_LEN ||
						gtk_len > CRYPTO_MAX_GTK_LEN)
			return;

		gtk_key_index = ek->wpa_key_id;
	}

	if (hs->mfp) {
		igtk = handshake_util_find_igtk_kde(decrypted_key_data,
							decrypted_key_data_size,
							&igtk_len);
		if (!igtk)
			return;

		igtk_key_index = l_get_le16(igtk);
		igtk += 2;
		igtk_len -= 2;
	} else
		igtk = NULL;

	/*
	 * IEEE 802.11-2020 Section 12.7.7.3
	 * "Key Data = OCI KDE when dot11RSNAOperatingChannelValidationActivated
	 *  on the [Supplicant]"
	 *
	 * Note: The spec reads "Authenticator" but this is incorrect and
	 * appears to be a copy-paste from a previous section. Above it has been
	 * changed to Supplicant.
	 */
	if (sm->handshake->supplicant_ocvc && sm->handshake->chandef)
		ies_len += append_oci(ies + ies_len, sm->handshake->chandef);

	/*
	 * 802.11-2016, Section 12.7.7.2:
	 * "
	 * a) Verifies that the Key Replay Counter field value has not yet been
	 * seen before, i.e., its value is strictly larger than that in any
	 * other EAPOL-Key frame received thus far during this session.
	 * b) Verifies that the MIC is valid, i.e., it uses the KCK that is
	 * part of the PTK to verify that there is no data integrity error.
	 * c) Uses the MLME-SETKEYS.request primitive to configure the temporal
	 * GTK and, when present, IGTK into its IEEE 802.11 MAC.
	 * d) Responds by creating and sending message 2 of the group key
	 * handshake to the Authenticator and incrementing the replay counter.
	 * "
	 * Note: steps a & b are performed in eapol_key_handle
	 */
	sm->replay_counter = L_BE64_TO_CPU(ek->key_replay_counter);
	sm->have_replay = true;

	step2 = eapol_create_gtk_2_of_2(sm->protocol_version,
					ek->key_descriptor_version,
					sm->replay_counter,
					ies_len, ies,
					hs->wpa_ie, ek->wpa_key_id,
					sm->mic_len);

	kck = handshake_state_get_kck(hs);

	if (sm->mic_len) {
		if (!eapol_calculate_mic(hs->akm_suite, kck,
						step2, mic, sm->mic_len)) {
			l_debug("MIC calculation failed");
			l_free(step2);
			handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
			return;
		}

		memcpy(EAPOL_KEY_MIC(step2), mic, sm->mic_len);
	} else {
		if (!eapol_aes_siv_encrypt(handshake_state_get_kek(hs),
						handshake_state_get_kek_len(hs),
						step2, NULL, 0)) {
			l_debug("AES-SIV encryption failed");
			l_free(step2);
			handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
			return;
		}
	}

	eapol_sm_write(sm, (struct eapol_frame *) step2, unencrypted);
	l_free(step2);

	eapol_install_gtk(sm, gtk_key_index, gtk, gtk_len, ek->key_rsc);

	if (igtk)
		eapol_install_igtk(sm, igtk_key_index, igtk, igtk_len);
}

static struct eapol_sm *eapol_find_sm(uint32_t ifindex, const uint8_t *aa)
{
	const struct l_queue_entry *entry;
	struct eapol_sm *sm;

	for (entry = l_queue_get_entries(state_machines); entry;
					entry = entry->next) {
		sm = entry->data;

		if (sm->handshake->ifindex != ifindex)
			continue;

		if (memcmp(sm->handshake->aa, aa, ETH_ALEN))
			continue;

		return sm;
	}

	return NULL;
}

static void eapol_key_handle(struct eapol_sm *sm,
				const struct eapol_frame *frame,
				bool unencrypted)
{
	struct handshake_state *hs = sm->handshake;
	const struct eapol_key *ek;
	const uint8_t *kck;
	const uint8_t *kek;
	uint8_t *decrypted_key_data = NULL;
	size_t key_data_len = 0;
	uint64_t replay_counter;
	uint8_t expected_key_descriptor_version;

	ek = eapol_key_validate((const uint8_t *) frame,
				sizeof(struct eapol_header) +
				L_BE16_TO_CPU(frame->header.packet_len),
				sm->mic_len);
	if (!ek)
		return;

	/* Wrong direction */
	if (!ek->key_ack)
		return;

	if (L_WARN_ON(eapol_key_descriptor_version_from_akm(hs->akm_suite,
				hs->pairwise_cipher,
				&expected_key_descriptor_version) < 0))
		return;

	if (L_WARN_ON(expected_key_descriptor_version !=
				ek->key_descriptor_version))
		return;

	/* Further Descriptor Type check */
	if (!hs->wpa_ie && ek->descriptor_type != EAPOL_DESCRIPTOR_TYPE_80211)
		return;
	else if (hs->wpa_ie &&
			ek->descriptor_type != EAPOL_DESCRIPTOR_TYPE_WPA)
		return;

	replay_counter = L_BE64_TO_CPU(ek->key_replay_counter);

	/*
	 * 802.11-2016, Section 12.7.2:
	 * "The Supplicant and Authenticator shall track the key replay counter
	 * per security association. The key replay counter shall be
	 * initialized to 0 on (re)association. The Authenticator shall
	 * increment the key replay counter on each successive EAPOL-Key frame."
	 *
	 * and
	 *
	 * "The Supplicant should also use the key replay counter and ignore
	 * EAPOL-Key frames with a Key Replay Counter field value smaller than
	 * or equal to any received in a valid message. The local Key Replay
	 * Counter field should not be updated until after the EAPOL-Key MIC is
	 * checked and is found to be valid. In other words, the Supplicant
	 * never updates the Key Replay Counter field for message 1 in the
	 * 4-way handshake, as it includes no MIC. This implies the Supplicant
	 * needs to allow for retransmission of message 1 when checking for
	 * the key replay counter of message 3."
	 *
	 * Note: The latter condition implies that Message 1 and Message 3
	 * can have the same replay counter, though other parts of the spec
	 * mandate that the Authenticator has to increment the replay counter
	 * for each frame sent.  Contradictory.
	 */
	if (sm->have_replay && sm->replay_counter >= replay_counter)
		return;

	kck = handshake_state_get_kck(hs);

	if (ek->key_mic) {
		/* Haven't received step 1 yet, so no ptk */
		if (!hs->have_snonce)
			return;

		if (!eapol_verify_mic(hs->akm_suite, kck, ek, sm->mic_len))
			return;
	}

	if ((ek->encrypted_key_data && !hs->wpa_ie) ||
			(ek->key_type == 0 && hs->wpa_ie)) {
		/*
		 * If using a MIC (non-FILS) but haven't received step 1 yet
		 * we disregard since there will be no ptk
		 */
		if (sm->mic_len && !hs->have_snonce)
			return;

		kek = handshake_state_get_kek(hs);

		decrypted_key_data = eapol_decrypt_key_data(
					hs->akm_suite, kek,
					ek, &key_data_len, sm->mic_len);
		if (!decrypted_key_data)
			return;
	} else
		key_data_len = EAPOL_KEY_DATA_LEN(ek, sm->mic_len);

	if (ek->key_type == 0) {
		/* GTK handshake allowed only after PTK handshake complete */
		if (!hs->ptk_complete)
			goto done;

		if (hs->group_cipher == IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC)
			goto done;

		if (!decrypted_key_data)
			goto done;

		eapol_handle_gtk_1_of_2(sm, ek, decrypted_key_data,
					key_data_len, unencrypted);
		goto done;
	}

	/* If no MIC, then assume packet 1, otherwise packet 3 */
	if (!ek->key_mic && !ek->encrypted_key_data)
		eapol_handle_ptk_1_of_4(sm, ek, unencrypted);
	else {
		if (!key_data_len)
			goto done;

		eapol_handle_ptk_3_of_4(sm, ek,
					decrypted_key_data ?:
					EAPOL_KEY_DATA(ek, sm->mic_len),
					key_data_len, unencrypted);
	}

done:
	if (decrypted_key_data)
		explicit_bzero(decrypted_key_data, key_data_len);

	l_free(decrypted_key_data);
}

/* This respresentes the eapMsg message in 802.1X Figure 8-1 */
static void eapol_eap_msg_cb(const uint8_t *eap_data, size_t len,
					void *user_data)
{
	struct eapol_sm *sm = user_data;
	uint8_t buf[sizeof(struct eapol_frame) + len];
	struct eapol_frame *frame = (struct eapol_frame *) buf;

	frame->header.protocol_version = sm->protocol_version;
	frame->header.packet_type = 0;
	l_put_be16(len, &frame->header.packet_len);

	memcpy(frame->data, eap_data, len);

	eapol_sm_write(sm, frame, sm->last_eap_unencrypted);
}

/* This respresentes the eapTimout, eapFail and eapSuccess messages */
static void eapol_eap_complete_cb(enum eap_result result, void *user_data)
{
	struct eapol_sm *sm = user_data;

	l_info("EAP completed with %s", result == EAP_RESULT_SUCCESS ?
			"eapSuccess" : (result == EAP_RESULT_FAIL ?
				"eapFail" : "eapTimeout"));

	if (result != EAP_RESULT_SUCCESS) {
		eap_free(sm->eap);
		sm->eap = NULL;
		handshake_failed(sm, MMPDU_REASON_CODE_IEEE8021X_FAILED);
		return;
	}

	if (install_pmk)
		install_pmk(sm->handshake, sm->handshake->pmk,
				sm->handshake->pmk_len);

	eap_reset(sm->eap);

	if (sm->handshake->authenticator) {
		if (L_WARN_ON(!sm->handshake->have_pmk)) {
			handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
			return;
		}

		/* sm->mic_len will have been set in eapol_eap_results_cb */

		/* Kick off 4-Way Handshake */
		eapol_ptk_1_of_4_retry(NULL, sm);
	}
}

/* This respresentes the eapResults message */
static void eapol_eap_results_cb(const uint8_t *msk_data, size_t msk_len,
				const uint8_t *emsk_data, size_t emsk_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *session_id, size_t session_len,
				void *user_data)
{
	struct eapol_sm *sm = user_data;

	l_debug("EAP key material received");

	/*
	 * 802.11i 8.5.1.2:
	 *    "When not using a PSK, the PMK is derived from the AAA key.
	 *    The PMK shall be computed as the first 256 bits (bits 0-255)
	 *    of the AAA key: PMK = L(PTK, 0, 256)."
	 * 802.11-2016 12.7.1.3:
	 *    "When not using a PSK, the PMK is derived from the MSK.
	 *    The PMK shall be computed as the first PMK_bits bits
	 *    (bits 0 to PMK_bits-1) of the MSK: PMK = L(MSK, 0, PMK_bits)."
	 * RFC5247 explains AAA-Key refers to the MSK and confirms the
	 * first 32 bytes of the MSK are used.  MSK is at least 64 octets
	 * long per RFC3748.  Note WEP derives the PTK from MSK differently.
	 *
	 * In a Fast Transition initial mobility domain association the PMK
	 * maps to the XXKey, except with EAP:
	 * 802.11-2016 12.7.1.7.3:
	 *    "If the AKM negotiated is 00-0F-AC:3, then [...] XXKey shall be
	 *    the second 256 bits of the MSK (which is derived from the IEEE
	 *    802.1X authentication), i.e., XXKey = L(MSK, 256, 256)."
	 * So we need to save the first 64 bytes at minimum.
	 */

	if (sm->handshake->akm_suite == IE_RSN_AKM_SUITE_FT_OVER_8021X) {
		if (msk_len < 64)
			goto msk_short;
	} else {
		if (msk_len < 32)
			goto msk_short;
	}

	if (msk_len > sizeof(sm->handshake->pmk))
		msk_len = sizeof(sm->handshake->pmk);

	sm->mic_len = eapol_get_mic_length(sm->handshake->akm_suite,
						sm->handshake->pmk_len);

	switch (sm->handshake->akm_suite) {
	case IE_RSN_AKM_SUITE_FT_OVER_8021X:
		msk_len = 64;
		break;
	case IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA384:
	case IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384:
		msk_len = 48;
		break;
	default:
		msk_len = 32;
		break;
	}

	handshake_state_set_pmk(sm->handshake, msk_data, msk_len);

	if (sm->handshake->support_fils && emsk_data && session_id)
		erp_cache_add(eap_get_identity(sm->eap), session_id,
				session_len, emsk_data, emsk_len,
				(const char *)sm->handshake->ssid);

	return;

msk_short:
	l_error("EAP method's MSK too short for AKM suite %u",
			sm->handshake->akm_suite);

	handshake_failed(sm, MMPDU_REASON_CODE_IEEE8021X_FAILED);
}

static void eapol_eap_event_cb(unsigned int event,
				const void *event_data, void *user_data)
{
	struct eapol_sm *sm = user_data;

	handshake_event(sm->handshake, HANDSHAKE_EVENT_EAP_NOTIFY, event,
			event_data);
}

void eapol_sm_set_use_eapol_start(struct eapol_sm *sm, bool enabled)
{
	sm->use_eapol_start = enabled;
}

void eapol_sm_set_require_handshake(struct eapol_sm *sm, bool enabled)
{
	sm->require_handshake = enabled;

	if (!sm->require_handshake)
		sm->use_eapol_start = false;
}

static void eapol_auth_key_handle(struct eapol_sm *sm,
				const struct eapol_frame *frame)
{
	size_t frame_len = 4 + L_BE16_TO_CPU(frame->header.packet_len);
	const struct eapol_key *ek = eapol_key_validate((const void *) frame,
							frame_len, sm->mic_len);
	uint16_t key_data_len;

	if (!ek)
		return;

	/* Wrong direction */
	if (ek->key_ack)
		return;

	if (ek->request)
		return; /* Not supported */

	if (!sm->handshake->have_anonce)
		return; /* Not expecting an EAPoL-Key yet */

	key_data_len = EAPOL_KEY_DATA_LEN(ek, sm->mic_len);
	if (key_data_len != 0)
		eapol_handle_ptk_2_of_4(sm, ek);
	else
		eapol_handle_ptk_4_of_4(sm, ek);
}

static void eapol_rx_auth_packet(uint16_t proto, const uint8_t *from,
				const struct eapol_frame *frame,
				bool noencrypt,
				void *user_data)
{
	struct eapol_sm *sm = user_data;

	if (proto != ETH_P_PAE || memcmp(from, sm->handshake->spa, 6))
		return;

	if (sm->handshake->ptk_complete && noencrypt) {
		l_debug("Dropping unexpected unencrypted EAPoL frame");
		return;
	}

	switch (frame->header.packet_type) {
	case 0:	/* EAPOL-EAP */
		if (!sm->eap) {
			l_error("Authenticator received an unexpected "
				"EAPOL-EAP frame from %s",
				util_address_to_string(from));
			return;
		}

		eap_rx_packet(sm->eap, frame->data,
				L_BE16_TO_CPU(frame->header.packet_len));
		break;

	case 1:	/* EAPOL-Start */
		/*
		 * The supplicant may have sent an EAPoL-Start even before
		 * we queued our EAP Identity Request or it may have missed our
		 * early Identity Request and may need a retransmission.  Tell
		 * sm->eap so it can decide whether to send a new Identity
		 * Request or ignore this.
		 *
		 * TODO: if we're already past the full handshake, send a
		 * new msg 1/4.
		 */
		if (sm->eap)
			eap_start(sm->eap);

		break;

	case 3: /* EAPOL-Key */
		eapol_auth_key_handle(sm, frame);
		break;

	default:
		l_error("Authenticator received unknown packet type %i from %s",
			frame->header.packet_type,
			util_address_to_string(from));
		return;
	}
}

static void eapol_rx_packet(uint16_t proto, const uint8_t *from,
				const struct eapol_frame *frame,
				bool unencrypted,
				void *user_data)
{
	struct eapol_sm *sm = user_data;

	if (proto != ETH_P_PAE || memcmp(from, sm->handshake->aa, 6))
		return;

	if (!sm->started) {
		size_t len = sizeof(struct eapol_header) +
			L_BE16_TO_CPU(frame->header.packet_len);

		/*
		 * If the state machine hasn't started yet save the frame
		 * for processing later.
		 */
		if (sm->early_frame) /* Is the 1-element queue full */
			return;

		sm->early_frame = l_memdup(frame, len);
		sm->early_frame_unencrypted = unencrypted;

		return;
	}

	if (!sm->protocol_version)
		sm->protocol_version = frame->header.protocol_version;

	switch (frame->header.packet_type) {
	case 0: /* EAPOL-EAP */
		if (sm->handshake->ptk_complete && unencrypted) {
			l_debug("Dropping unexpected unencrypted EAP frame");
			return;
		}

		l_timeout_remove(sm->eapol_start_timeout);
		sm->eapol_start_timeout = 0;

		if (!sm->eap) {
			/* If we're not configured for EAP, send a NAK */
			sm->eap = eap_new(eapol_eap_msg_cb,
						eapol_eap_complete_cb, sm);

			if (!sm->eap)
				return;

			eap_set_key_material_func(sm->eap,
							eapol_eap_results_cb);
		}

		sm->eap_exchanged = true;
		sm->last_eap_unencrypted = unencrypted;

		eap_rx_packet(sm->eap, frame->data,
				L_BE16_TO_CPU(frame->header.packet_len));

		break;

	case 3: /* EAPOL-Key */
		if (!sm->handshake->have_pmk) {
			if (!sm->eap)
				return;

			/*
			 * Either this is an error (EAP negotiation in
			 * progress) or the server is giving us a chance to
			 * use a cached PMK.  We don't yet cache PMKs so
			 * send an EAPOL-Start if we haven't sent one yet.
			 */
			if (sm->eapol_start_timeout) {
				l_timeout_remove(sm->eapol_start_timeout);
				sm->eapol_start_timeout = NULL;
				__send_eapol_start(sm, unencrypted);
			}

			return;
		}

		eapol_key_handle(sm, frame, unencrypted);
		break;

	default:
		return;
	}
}

void __eapol_update_replay_counter(uint32_t ifindex, const uint8_t *spa,
				const uint8_t *aa, uint64_t replay_counter)
{
	struct eapol_sm *sm;

	sm = eapol_find_sm(ifindex, aa);

	if (!sm)
		return;

	if (sm->replay_counter >= replay_counter)
		return;

	sm->replay_counter = replay_counter;
}

void __eapol_set_tx_packet_func(eapol_tx_packet_func_t func)
{
	tx_packet = func;
}

void __eapol_set_tx_user_data(void *user_data)
{
	tx_user_data = user_data;
}

void __eapol_set_rekey_offload_func(eapol_rekey_offload_func_t func)
{
	rekey_offload = func;
}

void __eapol_set_install_pmk_func(eapol_install_pmk_func_t func)
{
	install_pmk = func;
}

void eapol_register(struct eapol_sm *sm)
{
	eapol_frame_watch_func_t rx_handler = sm->handshake->authenticator ?
		eapol_rx_auth_packet : eapol_rx_packet;

	l_queue_push_head(state_machines, sm);

	sm->watch_id = eapol_frame_watch_add(sm->handshake->ifindex,
						rx_handler, sm);
	sm->protocol_version = sm->handshake->proto_version;
}

bool eapol_start(struct eapol_sm *sm)
{
	if (sm->handshake->settings_8021x) {
		_auto_(l_free) char *network_id = NULL;

		sm->eap = eap_new(eapol_eap_msg_cb, eapol_eap_complete_cb, sm);

		if (!sm->eap)
			goto eap_error;

		if (!eap_load_settings(sm->eap, sm->handshake->settings_8021x,
					"EAP-")) {
			eap_free(sm->eap);
			sm->eap = NULL;

			goto eap_error;
		}

		eap_set_key_material_func(sm->eap, eapol_eap_results_cb);
		eap_set_event_func(sm->eap, eapol_eap_event_cb);

		network_id = l_util_hexstring(sm->handshake->ssid,
						sm->handshake->ssid_len);
		eap_set_peer_id(sm->eap, network_id);
	}

	sm->started = true;

	if (sm->require_handshake)
		sm->timeout = l_timeout_create(eapol_4way_handshake_time,
				eapol_timeout, sm, NULL);

	if (!sm->handshake->authenticator && sm->use_eapol_start) {
		/*
		 * We start a short timeout, if EAP packets are not received
		 * from AP, then we send the EAPoL-Start
		 */
		sm->eapol_start_timeout =
				l_timeout_create(1, send_eapol_start, sm, NULL);
	}

	sm->mic_len = eapol_get_mic_length(sm->handshake->akm_suite,
						sm->handshake->pmk_len);

	/* Process any frames received early due to scheduling */
	if (sm->early_frame) {
		eapol_rx_packet(ETH_P_PAE, sm->handshake->aa,
				sm->early_frame, sm->early_frame_unencrypted,
				sm);
		l_free(sm->early_frame);
		sm->early_frame = NULL;
	}

	if (sm->handshake->authenticator) {
		if (!sm->protocol_version)
			sm->protocol_version = EAPOL_PROTOCOL_VERSION_2004;

		if (sm->handshake->settings_8021x) {
			/*
			 * If we're allowed to, send EAP Identity request
			 * immediately, otherwise wait for an EAPoL-Start.
			 */
			if (!sm->use_eapol_start)
				eap_start(sm->eap);
		} else {
			if (L_WARN_ON(!sm->handshake->have_pmk))
				return false;

			/* Kick off handshake */
			eapol_ptk_1_of_4_retry(NULL, sm);
		}
	}

	return true;

eap_error:
	l_error("Error initializing EAP for ifindex %i",
			(int) sm->handshake->ifindex);

	return false;
}

struct preauth_sm {
	uint32_t ifindex;
	uint8_t aa[6];
	uint8_t spa[6];
	struct eap_state *eap;
	uint8_t pmk[32];
	eapol_preauth_cb_t cb;
	eapol_preauth_destroy_func_t destroy;
	void *user_data;
	struct l_timeout *timeout;
	uint32_t watch_id;
	bool initial_rx:1;
};

#define EAPOL_TIMEOUT_SEC 1

static void preauth_sm_destroy(void *value)
{
	struct preauth_sm *sm = value;

	if (sm->destroy)
		sm->destroy(sm->user_data);

	eap_free(sm->eap);
	l_timeout_remove(sm->timeout);
	eapol_frame_watch_remove(sm->watch_id);
	l_free(sm);
}

static void preauth_frame(struct preauth_sm *sm, uint8_t packet_type,
				const uint8_t *data, size_t data_len)
{
	uint8_t buf[sizeof(struct eapol_frame) + data_len];
	struct eapol_frame *frame = (struct eapol_frame *) buf;

	frame->header.protocol_version = EAPOL_PROTOCOL_VERSION_2001;
	frame->header.packet_type = packet_type;
	l_put_be16(data_len, &frame->header.packet_len);

	if (data_len)
		memcpy(frame->data, data, data_len);

	__eapol_tx_packet(sm->ifindex, sm->aa, 0x88c7, frame, false);
}

static void preauth_rx_packet(uint16_t proto, const uint8_t *from,
				const struct eapol_frame *frame,
				bool unencrypted,
				void *user_data)
{
	struct preauth_sm *sm = user_data;

	if (proto != 0x88c7 || memcmp(from, sm->aa, 6))
		return;

	/*
	 * We do not expect any pre-auth packets to be unencrypted
	 * since we're authenticating via the currently connected AP
	 * and pre-authentication implies we are already connected
	 * and the keys are set
	 */
	if (L_WARN_ON(unencrypted))
		return;

	if (frame->header.packet_type != 0) /* EAPOL-EAP */
		return;

	if (!sm->initial_rx) {
		sm->initial_rx = true;

		/*
		 * Initial frame from authenticator received, it's alive
		 * so set a longer timeout.  The timeout is for the whole
		 * EAP exchange as we have no way to monitor the
		 * negotiation progress and keep rearming the timer each
		 * time progress is made.
		 */
		l_timeout_modify(sm->timeout, EAPOL_TIMEOUT_SEC * 3);
	}

	eap_rx_packet(sm->eap, frame->data,
			L_BE16_TO_CPU(frame->header.packet_len));
}

static void preauth_eap_msg_cb(const uint8_t *eap_data, size_t len,
				void *user_data)
{
	struct preauth_sm *sm = user_data;

	preauth_frame(sm, 0, eap_data, len);
}

static void preauth_eap_complete_cb(enum eap_result result, void *user_data)
{
	struct preauth_sm *sm = user_data;

	l_info("Preauthentication completed with %s",
		result == EAP_RESULT_SUCCESS ? "eapSuccess" :
		(result == EAP_RESULT_FAIL ? "eapFail" : "eapTimeout"));

	l_queue_remove(preauths, sm);

	if (result == EAP_RESULT_SUCCESS)
		sm->cb(sm->pmk, sm->user_data);
	else
		sm->cb(NULL, sm->user_data);

	preauth_sm_destroy(sm);
}

/* See eapol_eap_results_cb for documentation */
static void preauth_eap_results_cb(const uint8_t *msk_data, size_t msk_len,
				const uint8_t *emsk_data, size_t emsk_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *session_id, size_t session_len,
				void *user_data)
{
	struct preauth_sm *sm = user_data;

	l_debug("Preauthentication EAP key material received");

	if (msk_len < 32)
		goto msk_short;

	memcpy(sm->pmk, msk_data, 32);

	return;

msk_short:
	l_error("Preauthentication MSK too short");

	l_queue_remove(preauths, sm);

	sm->cb(NULL, sm->user_data);

	preauth_sm_destroy(sm);
}

static void preauth_timeout(struct l_timeout *timeout, void *user_data)
{
	struct preauth_sm *sm = user_data;

	l_error("Preauthentication timeout");

	l_queue_remove(preauths, sm);

	sm->cb(NULL, sm->user_data);

	preauth_sm_destroy(sm);
}

struct preauth_sm *eapol_preauth_start(const uint8_t *aa,
					const struct handshake_state *hs,
					eapol_preauth_cb_t cb, void *user_data,
					eapol_preauth_destroy_func_t destroy)
{
	struct preauth_sm *sm;

	sm = l_new(struct preauth_sm, 1);

	sm->ifindex = hs->ifindex;
	memcpy(sm->aa, aa, 6);
	memcpy(sm->spa, hs->spa, 6);
	sm->cb = cb;
	sm->destroy = destroy;
	sm->user_data = user_data;

	sm->eap = eap_new(preauth_eap_msg_cb, preauth_eap_complete_cb, sm);
	if (!sm->eap)
		goto err_free_sm;

	if (!eap_load_settings(sm->eap, hs->settings_8021x, "EAP-"))
		goto err_free_eap;

	eap_set_key_material_func(sm->eap, preauth_eap_results_cb);

	sm->timeout = l_timeout_create(EAPOL_TIMEOUT_SEC, preauth_timeout,
					sm, NULL);

	sm->watch_id = eapol_frame_watch_add(sm->ifindex,
						preauth_rx_packet, sm);

	l_queue_push_head(preauths, sm);

	/* Send EAPOL-Start */
	preauth_frame(sm, 1, NULL, 0);

	return sm;

err_free_eap:
	eap_free(sm->eap);
err_free_sm:
	l_free(sm);

	return NULL;
}

static bool preauth_remove_by_ifindex(void *data, void *user_data)
{
	struct preauth_sm *sm = data;

	if (sm->ifindex != L_PTR_TO_UINT(user_data))
		return false;

	preauth_sm_destroy(sm);

	return true;
}

void eapol_preauth_cancel(uint32_t ifindex)
{
	l_queue_foreach_remove(preauths, preauth_remove_by_ifindex,
				L_UINT_TO_PTR(ifindex));
}

static bool eapol_frame_watch_match_ifindex(const void *a, const void *b)
{
	struct eapol_frame_watch *efw =
		l_container_of(a, struct eapol_frame_watch, super);

	return efw->ifindex == L_PTR_TO_UINT(b);
}

void __eapol_rx_packet(uint32_t ifindex, const uint8_t *src, uint16_t proto,
					const uint8_t *frame, size_t len,
					bool noencrypt)
{
	const struct eapol_header *eh;

	/* Validate Header */
	if (len < sizeof(struct eapol_header))
		return;

	eh = (const struct eapol_header *) frame;

	switch (eh->protocol_version) {
	case EAPOL_PROTOCOL_VERSION_2001:
	case EAPOL_PROTOCOL_VERSION_2004:
	case EAPOL_PROTOCOL_VERSION_2010:
		break;
	default:
		return;
	}

	if (len < sizeof(struct eapol_header) + L_BE16_TO_CPU(eh->packet_len))
		return;

	WATCHLIST_NOTIFY_MATCHES(&frame_watches,
					eapol_frame_watch_match_ifindex,
					L_UINT_TO_PTR(ifindex),
					eapol_frame_watch_func_t, proto, src,
					(const struct eapol_frame *) eh,
					noencrypt);
}

void __eapol_tx_packet(uint32_t ifindex, const uint8_t *dst, uint16_t proto,
			const struct eapol_frame *frame, bool noencrypt)
{
	if (!tx_packet)
		return;

	tx_packet(ifindex, dst, proto, frame, noencrypt, tx_user_data);
}

void __eapol_set_config(struct l_settings *config)
{
	if (!l_settings_get_uint(config, "EAPoL",
			"MaxHandshakeTime", &eapol_4way_handshake_time))
		eapol_4way_handshake_time = 5;
}

int eapol_init(void)
{
	state_machines = l_queue_new();
	preauths = l_queue_new();
	watchlist_init(&frame_watches, &eapol_frame_watch_ops);

	return 0;
}

void eapol_exit(void)
{
	if (!l_queue_isempty(state_machines))
		l_warn("stale eapol state machines found");

	l_queue_destroy(state_machines, eapol_sm_destroy);

	if (!l_queue_isempty(preauths))
		l_warn("stale preauth state machines found");

	l_queue_destroy(preauths, preauth_sm_destroy);

	watchlist_destroy(&frame_watches);
}

IWD_MODULE(eapol, eapol_init, eapol_exit);
