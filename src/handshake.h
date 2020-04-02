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

struct handshake_state;
enum crypto_cipher;

/* 802.11-2016 Table 12-6 in section 12.7.2 */
enum handshake_kde {
	HANDSHAKE_KDE_GTK		= 0x000fac01,
	HANDSHAKE_KDE_MAC_ADDRESS	= 0x000fac03,
	HANDSHAKE_KDE_PMKID		= 0x000fac04,
	HANDSHAKE_KDE_SMK		= 0x000fac05,
	HANDSHAKE_KDE_NONCE		= 0x000fac06,
	HANDSHAKE_KDE_LIFETIME		= 0x000fac07,
	HANDSHAKE_KDE_ERROR		= 0x000fac08,
	HANDSHAKE_KDE_IGTK		= 0x000fac09,
	HANDSHAKE_KDE_KEY_ID		= 0x000fac0a,
	HANDSHAKE_KDE_MULTIBAND_GTK	= 0x000fac0b,
	HANDSHAKE_KDE_MULTIBAND_KEY_ID	= 0x000fac0c,
};

enum handshake_event {
	HANDSHAKE_EVENT_STARTED,
	HANDSHAKE_EVENT_SETTING_KEYS,
	HANDSHAKE_EVENT_SETTING_KEYS_FAILED,
	HANDSHAKE_EVENT_COMPLETE,
	HANDSHAKE_EVENT_FAILED,
	HANDSHAKE_EVENT_REKEY_FAILED,
	HANDSHAKE_EVENT_EAP_NOTIFY,
};

typedef void (*handshake_event_func_t)(struct handshake_state *hs,
					enum handshake_event event,
					void *user_data, ...);

typedef bool (*handshake_get_nonce_func_t)(uint8_t nonce[]);
typedef void (*handshake_install_tk_func_t)(struct handshake_state *hs,
					const uint8_t *tk, uint32_t cipher);
typedef void (*handshake_install_gtk_func_t)(struct handshake_state *hs,
					uint16_t key_index,
					const uint8_t *gtk, uint8_t gtk_len,
					const uint8_t *rsc, uint8_t rsc_len,
					uint32_t cipher);
typedef void (*handshake_install_igtk_func_t)(struct handshake_state *hs,
					uint16_t key_index,
					const uint8_t *igtk, uint8_t igtk_len,
					const uint8_t *ipn, uint8_t ipn_len,
					uint32_t cipher);

void __handshake_set_get_nonce_func(handshake_get_nonce_func_t func);
void __handshake_set_install_tk_func(handshake_install_tk_func_t func);
void __handshake_set_install_gtk_func(handshake_install_gtk_func_t func);
void __handshake_set_install_igtk_func(handshake_install_igtk_func_t func);

struct handshake_state {
	uint32_t ifindex;
	uint8_t spa[6];
	uint8_t aa[6];
	uint8_t *authenticator_ie;
	uint8_t *supplicant_ie;
	uint8_t *mde;
	uint8_t *fte;
	enum ie_rsn_cipher_suite pairwise_cipher;
	enum ie_rsn_cipher_suite group_cipher;
	enum ie_rsn_cipher_suite group_management_cipher;
	enum ie_rsn_akm_suite akm_suite;
	uint8_t pmk[64];
	size_t pmk_len;
	uint8_t snonce[32];
	uint8_t anonce[32];
	uint8_t ptk[136];
	uint8_t pmk_r0[48];
	uint8_t pmk_r0_name[16];
	uint8_t pmk_r1[48];
	uint8_t pmk_r1_name[16];
	uint8_t pmkid[16];
	uint8_t fils_ft[48];
	uint8_t fils_ft_len;
	struct l_settings *settings_8021x;
	bool have_snonce : 1;
	bool ptk_complete : 1;
	bool wpa_ie : 1;
	bool osen_ie : 1;
	bool have_pmk : 1;
	bool mfp : 1;
	bool have_anonce : 1;
	bool have_pmkid : 1;
	bool authenticator : 1;
	bool wait_for_gtk : 1;
	bool no_rekey : 1;
	bool support_fils : 1;
	uint8_t ssid[32];
	size_t ssid_len;
	char *passphrase;
	uint8_t r0khid[48];
	size_t r0khid_len;
	uint8_t r1khid[6];
	uint8_t gtk[32];
	uint8_t gtk_rsc[6];
	uint8_t proto_version : 2;
	unsigned int gtk_index;
	struct erp_cache_entry *erp_cache;
	void *user_data;

	void (*free)(struct handshake_state *s);

	handshake_event_func_t event_func;
};

#define handshake_event(hs, event, ...)	\
	do {	\
		if (!(hs)->event_func)	\
			break;	\
	\
		(hs)->event_func((hs), event, (hs)->user_data, ##__VA_ARGS__); \
	} while (0)

void handshake_state_free(struct handshake_state *s);

void handshake_state_set_supplicant_address(struct handshake_state *s,
						const uint8_t *spa);
void handshake_state_set_authenticator_address(struct handshake_state *s,
						const uint8_t *aa);
void handshake_state_set_authenticator(struct handshake_state *s, bool auth);
void handshake_state_set_pmk(struct handshake_state *s, const uint8_t *pmk,
				size_t pmk_len);
void handshake_state_set_ptk(struct handshake_state *s, const uint8_t *ptk,
				size_t ptk_len);
void handshake_state_set_8021x_config(struct handshake_state *s,
					struct l_settings *settings);
bool handshake_state_set_authenticator_ie(struct handshake_state *s,
						const uint8_t *ie);
bool handshake_state_set_supplicant_ie(struct handshake_state *s,
						const uint8_t *ie);
void handshake_state_set_ssid(struct handshake_state *s,
					const uint8_t *ssid, size_t ssid_len);
void handshake_state_set_mde(struct handshake_state *s,
					const uint8_t *mde);
void handshake_state_set_fte(struct handshake_state *s, const uint8_t *fte);

void handshake_state_set_kh_ids(struct handshake_state *s,
				const uint8_t *r0khid, size_t r0khid_len,
				const uint8_t *r1khid);

void handshake_state_set_event_func(struct handshake_state *s,
					handshake_event_func_t func,
					void *user_data);
void handshake_state_set_passphrase(struct handshake_state *s,
					const char *passphrase);
void handshake_state_set_no_rekey(struct handshake_state *s, bool no_rekey);

void handshake_state_set_fils_ft(struct handshake_state *s,
					const uint8_t *fils_ft,
					size_t fils_ft_len);

void handshake_state_set_protocol_version(struct handshake_state *s,
						uint8_t proto_version);

void handshake_state_new_snonce(struct handshake_state *s);
void handshake_state_new_anonce(struct handshake_state *s);
void handshake_state_set_anonce(struct handshake_state *s,
				const uint8_t *anonce);
void handshake_state_set_pmkid(struct handshake_state *s, const uint8_t *pmkid);
bool handshake_state_derive_ptk(struct handshake_state *s);
size_t handshake_state_get_ptk_size(struct handshake_state *s);
size_t handshake_state_get_kck_len(struct handshake_state *s);
const uint8_t *handshake_state_get_kck(struct handshake_state *s);
size_t handshake_state_get_kek_len(struct handshake_state *s);
const uint8_t *handshake_state_get_kek(struct handshake_state *s);
void handshake_state_install_ptk(struct handshake_state *s);

void handshake_state_install_gtk(struct handshake_state *s,
					uint16_t gtk_key_index,
					const uint8_t *gtk, size_t gtk_len,
					const uint8_t *rsc, uint8_t rsc_len);

void handshake_state_install_igtk(struct handshake_state *s,
					uint16_t igtk_key_index,
					const uint8_t *igtk, size_t igtk_len,
					const uint8_t *ipn);

void handshake_state_override_pairwise_cipher(struct handshake_state *s,
					enum ie_rsn_cipher_suite pairwise);

bool handshake_state_get_pmkid(struct handshake_state *s, uint8_t *out_pmkid);

bool handshake_decode_fte_key(struct handshake_state *s, const uint8_t *wrapped,
				size_t key_len, uint8_t *key_out);

void handshake_state_set_gtk(struct handshake_state *s, const uint8_t *key,
				unsigned int key_index, const uint8_t *rsc);

bool handshake_util_ap_ie_matches(const uint8_t *msg_ie,
					const uint8_t *scan_ie, bool is_wpa);

const uint8_t *handshake_util_find_gtk_kde(const uint8_t *data, size_t data_len,
					size_t *out_gtk_len);
const uint8_t *handshake_util_find_igtk_kde(const uint8_t *data,
					size_t data_len, size_t *out_igtk_len);
const uint8_t *handshake_util_find_pmkid_kde(const uint8_t *data,
					size_t data_len);
void handshake_util_build_gtk_kde(enum crypto_cipher cipher, const uint8_t *key,
					unsigned int key_index, uint8_t *to);
