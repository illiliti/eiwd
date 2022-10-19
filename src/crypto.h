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

#include <stddef.h>
#include <stdbool.h>

struct l_ecc_point;

enum crypto_cipher {
	CRYPTO_CIPHER_WEP40 = 0x000fac01,
	CRYPTO_CIPHER_WEP104 = 0x000fac05,
	CRYPTO_CIPHER_TKIP = 0x000fac02,
	CRYPTO_CIPHER_CCMP = 0x000fac04,
	CRYPTO_CIPHER_BIP_CMAC = 0x000fac06,
};

enum crypto_akm {
	CRYPTO_AKM_8021X = 0x000fac01,
	CRYPTO_AKM_PSK = 0x000fac02,
	CRYPTO_AKM_FT_OVER_8021X = 0x000fac03,
	CRYPTO_AKM_FT_USING_PSK = 0x000fac04,
	CRYPTO_AKM_8021X_SHA256 = 0x000fac05,
	CRYPTO_AKM_PSK_SHA256 = 0x000fac06,
	CRYPTO_AKM_TDLS = 0x000fac07,
	CRYPTO_AKM_SAE_SHA256 = 0x000fac08,
	CRYPTO_AKM_FT_OVER_SAE_SHA256 = 0x000fac09,
	CRYPTO_AKM_AP_PEER_KEY_SHA256 = 0x000fac0a,
	CRYPTO_AKM_8021X_SUITE_B_SHA256 = 0x000fac0b,
	CRYPTO_AKM_8021X_SUITE_B_SHA384 = 0x000fac0c,
	CRYPTO_AKM_FT_OVER_8021X_SHA384 = 0x000fac0d,
	CRYPTO_AKM_FILS_SHA256 = 0x000fac0e,
	CRYPTO_AKM_FILS_SHA384 = 0x000fac0f,
	CRYPTO_AKM_FT_OVER_FILS_SHA256 = 0x000fac10,
	CRYPTO_AKM_FT_OVER_FILS_SHA384 = 0x000fac11,
	CRYPTO_AKM_OWE = 0x000fac12,
	CRYPTO_AKM_OSEN = 0x506f9a01,
};

/* Min & Max reported by crypto_cipher_key_len when ignoring WEP */
#define CRYPTO_MIN_GTK_LEN 16
#define CRYPTO_MAX_GTK_LEN 32
#define CRYPTO_MIN_IGTK_LEN 16
#define CRYPTO_MAX_IGTK_LEN 32

extern const unsigned char crypto_dh5_prime[];
extern size_t crypto_dh5_prime_size;
extern const unsigned char crypto_dh5_generator[];
extern size_t crypto_dh5_generator_size;

bool hmac_md5(const void *key, size_t key_len,
		const void *data, size_t data_len, void *output, size_t size);
bool hmac_sha1(const void *key, size_t key_len,
		const void *data, size_t data_len, void *output, size_t size);
bool hmac_sha256(const void *key, size_t key_len,
		const void *data, size_t data_len, void *output, size_t size);
bool hmac_sha384(const void *key, size_t key_len,
		const void *data, size_t data_len, void *output, size_t size);
bool cmac_aes(const void *key, size_t key_len,
		const void *data, size_t data_len, void *output, size_t size);

bool aes_unwrap(const uint8_t *kek, size_t kek_len, const uint8_t *in, size_t len,
			uint8_t *out);
bool aes_wrap(const uint8_t *kek, const uint8_t *in, size_t len, uint8_t *out);
bool arc4_skip(const uint8_t *key, size_t key_len, size_t skip,
		const uint8_t *in, size_t len, uint8_t *out);

bool aes_siv_encrypt(const void *key, size_t key_len, const void *in,
			size_t in_len, struct iovec *ad, size_t num_ad,
			void *out);
bool aes_siv_decrypt(const void *key, size_t key_len, const void *in,
			size_t in_len, struct iovec *ad, size_t num_ad,
			void *out);

int crypto_cipher_key_len(enum crypto_cipher cipher);
int crypto_cipher_tk_bits(enum crypto_cipher cipher);

bool crypto_passphrase_is_valid(const char *passphrase);

int crypto_psk_from_passphrase(const char *passphrase,
				const unsigned char *ssid, size_t ssid_len,
				unsigned char *out_psk);

bool crypto_kdf(enum l_checksum_type type, const void *key, size_t key_len,
		const void *prefix, size_t prefix_len,
		const void *data, size_t data_len, void *output, size_t size);
bool kdf_sha256(const void *key, size_t key_len,
		const void *prefix, size_t prefix_len,
		const void *data, size_t data_len, void *output, size_t size);
bool kdf_sha384(const void *key, size_t key_len,
		const void *prefix, size_t prefix_len,
		const void *data, size_t data_len, void *output, size_t size);
bool prf_sha1(const void *key, size_t key_len,
		const void *prefix, size_t prefix_len,
		const void *data, size_t data_len, void *output, size_t size);
bool prf_plus_sha1(const void *key, size_t key_len,
		const void *prefix, size_t prefix_len,
		const void *data, size_t data_len, void *output, size_t size);

bool prf_plus(enum l_checksum_type type, const void *key, size_t key_len,
		const char *label, void *out, size_t out_len,
		size_t n_extra, ...);

bool hkdf_extract(enum l_checksum_type type, const void *key, size_t key_len,
				uint8_t num_args, void *out, ...);

bool hkdf_expand(enum l_checksum_type type, const void *key, size_t key_len,
				const char *info, void *out, size_t out_len);

bool crypto_derive_pairwise_ptk(const uint8_t *pmk, size_t pmk_len,
				const uint8_t *addr1, const uint8_t *addr2,
				const uint8_t *nonce1, const uint8_t *nonce2,
				uint8_t *out_ptk, size_t ptk_len,
				enum l_checksum_type type);

bool crypto_derive_pmk_r0(const uint8_t *xxkey, size_t xxkey_len,
				const uint8_t *ssid, size_t ssid_len,
				uint16_t mdid,
				const uint8_t *r0khid, size_t r0kh_len,
				const uint8_t *s0khid, bool sha384,
				uint8_t *out_pmk_r0, uint8_t *out_pmk_r0_name);
bool crypto_derive_pmk_r1(const uint8_t *pmk_r0,
				const uint8_t *r1khid, const uint8_t *s1khid,
				const uint8_t *pmk_r0_name, bool sha384,
				uint8_t *out_pmk_r1,
				uint8_t *out_pmk_r1_name);
bool crypto_derive_ft_ptk(const uint8_t *pmk_r1, const uint8_t *pmk_r1_name,
				const uint8_t *addr1, const uint8_t *addr2,
				const uint8_t *nonce1, const uint8_t *nonce2,
				bool sha384, uint8_t *out_ptk, size_t ptk_len,
				uint8_t *out_ptk_name);

bool crypto_derive_pmkid(const uint8_t *pmk,
				const uint8_t *addr1, const uint8_t *addr2,
				uint8_t *out_pmkid, bool use_sha256);

enum crypto_sae {
	CRYPTO_SAE_LOOPING,
	CRYPTO_SAE_HASH_TO_ELEMENT,
};

enum l_checksum_type crypto_sae_hash_from_ecc_prime_len(enum crypto_sae type,
							size_t prime_len);
struct l_ecc_point *crypto_derive_sae_pt_ecc(unsigned int group,
						const char *ssid,
						const char *password,
						const char *identifier);
struct l_ecc_point *crypto_derive_sae_pwe_from_pt_ecc(const uint8_t *mac1,
						const uint8_t *mac2,
						const struct l_ecc_point *pt);
