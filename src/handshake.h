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
struct eapol_frame;

enum handshake_kde {
	/* 802.11-2020 Table 12-9 in section 12.7.2 */
	HANDSHAKE_KDE_GTK		= 0x000fac01,
	HANDSHAKE_KDE_MAC_ADDRESS	= 0x000fac03,
	HANDSHAKE_KDE_PMKID		= 0x000fac04,
	HANDSHAKE_KDE_NONCE		= 0x000fac06,
	HANDSHAKE_KDE_LIFETIME		= 0x000fac07,
	HANDSHAKE_KDE_ERROR		= 0x000fac08,
	HANDSHAKE_KDE_IGTK		= 0x000fac09,
	HANDSHAKE_KDE_KEY_ID		= 0x000fac0a,
	HANDSHAKE_KDE_MULTIBAND_GTK	= 0x000fac0b,
	HANDSHAKE_KDE_MULTIBAND_KEY_ID	= 0x000fac0c,
	HANDSHAKE_KDE_OCI		= 0x000fac0d,
	HANDSHAKE_KDE_BIGTK		= 0x000fac0e,
	/* Wi-Fi P2P Technical Specification v1.7 4.2.8 */
	HANDSHAKE_KDE_IP_ADDRESS_REQ	= 0x506f9a04,
	HANDSHAKE_KDE_IP_ADDRESS_ALLOC	= 0x506f9a05,
	/* Wi-Fi WPA3 Specification v3.0 Table 4 */
	HANDSHAKE_KDE_TRANSITION_DISABLE = 0x506f9a20,
};

enum handshake_event {
	HANDSHAKE_EVENT_STARTED,
	HANDSHAKE_EVENT_SETTING_KEYS,
	HANDSHAKE_EVENT_SETTING_KEYS_FAILED,
	HANDSHAKE_EVENT_COMPLETE,
	HANDSHAKE_EVENT_FAILED,
	HANDSHAKE_EVENT_REKEY_FAILED,
	HANDSHAKE_EVENT_EAP_NOTIFY,
	HANDSHAKE_EVENT_TRANSITION_DISABLE,
	HANDSHAKE_EVENT_P2P_IP_REQUEST,
	HANDSHAKE_EVENT_REKEY_COMPLETE,
};

typedef void (*handshake_event_func_t)(struct handshake_state *hs,
					enum handshake_event event,
					void *user_data, ...);

typedef bool (*handshake_get_nonce_func_t)(uint8_t nonce[]);
typedef void (*handshake_install_tk_func_t)(struct handshake_state *hs,
					uint8_t key_index,
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
typedef void (*handshake_install_ext_tk_func_t)(struct handshake_state *hs,
					uint8_t key_idx, const uint8_t *tk,
					uint32_t cipher,
					const struct eapol_frame *step4,
					uint16_t proto, bool noencrypt);

void __handshake_set_get_nonce_func(handshake_get_nonce_func_t func);
void __handshake_set_install_tk_func(handshake_install_tk_func_t func);
void __handshake_set_install_gtk_func(handshake_install_gtk_func_t func);
void __handshake_set_install_igtk_func(handshake_install_igtk_func_t func);
void __handshake_set_install_ext_tk_func(handshake_install_ext_tk_func_t func);

struct handshake_state {
	uint32_t ifindex;
	uint8_t spa[6];
	uint8_t aa[6];
	uint8_t *authenticator_ie;
	uint8_t *supplicant_ie;
	uint8_t *authenticator_rsnxe;
	uint8_t *supplicant_rsnxe;
	uint8_t *mde;
	uint8_t *fte;
	uint8_t *vendor_ies;
	size_t vendor_ies_len;
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
	struct l_ecc_point **ecc_sae_pts;
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
	bool authenticator_ocvc : 1;
	bool supplicant_ocvc : 1;
	bool ext_key_id_capable : 1;
	bool force_default_owe_group : 1;
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
	uint8_t active_tk_index;
	struct erp_cache_entry *erp_cache;
	bool support_ip_allocation : 1;
	uint32_t client_ip_addr;
	uint32_t subnet_mask;
	uint32_t go_ip_addr;
	uint8_t *fils_ip_req_ie;
	uint8_t *fils_ip_resp_ie;
	struct band_chandef *chandef;
	void *user_data;

	void (*free)(struct handshake_state *s);
	bool in_event;

	handshake_event_func_t event_func;
};

#define HSID(x) UNIQUE_ID(handshake_, x)

#define handshake_event(_hs, event, ...)				\
	({								\
		bool HSID(freed) = false;				\
		typeof(_hs) HSID(hs) = (_hs);				\
									\
		if (HSID(hs)->event_func && !HSID(hs)->in_event) {	\
			HSID(hs)->in_event = true;			\
			HSID(hs)->event_func(HSID(hs), (event),		\
					HSID(hs)->user_data,		\
					##__VA_ARGS__);			\
									\
			if (!HSID(hs)->in_event) {			\
				handshake_state_free(HSID(hs));		\
				HSID(freed) = true;			\
			} else						\
				HSID(hs)->in_event = false;		\
		}							\
		HSID(freed);						\
	})

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
void handshake_state_set_authenticator_rsnxe(struct handshake_state *s,
						const uint8_t *ie);
void handshake_state_set_supplicant_rsnxe(struct handshake_state *s,
						const uint8_t *ie);
void handshake_state_set_ssid(struct handshake_state *s,
					const uint8_t *ssid, size_t ssid_len);
void handshake_state_set_mde(struct handshake_state *s,
					const uint8_t *mde);
void handshake_state_set_fte(struct handshake_state *s, const uint8_t *fte);
void handshake_state_set_vendor_ies(struct handshake_state *s,
					const struct iovec *iov,
					size_t n_iovs);

void handshake_state_set_kh_ids(struct handshake_state *s,
				const uint8_t *r0khid, size_t r0khid_len,
				const uint8_t *r1khid);

void handshake_state_set_event_func(struct handshake_state *s,
					handshake_event_func_t func,
					void *user_data);
void handshake_state_set_passphrase(struct handshake_state *s,
					const char *passphrase);
bool handshake_state_add_ecc_sae_pt(struct handshake_state *s,
					const struct l_ecc_point *pt);
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

void handshake_state_install_ext_ptk(struct handshake_state *s,
				uint8_t key_idx,
				struct eapol_frame *ek, uint16_t proto,
				bool noencrypt);

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

void handshake_state_set_chandef(struct handshake_state *s,
					struct band_chandef *chandef);
int handshake_state_verify_oci(struct handshake_state *s, const uint8_t *oci,
				size_t oci_len);

bool handshake_util_ap_ie_matches(const struct ie_rsn_info *msg_info,
					const uint8_t *scan_ie, bool is_wpa);

const uint8_t *handshake_util_find_kde(enum handshake_kde selector,
					const uint8_t *data, size_t data_len,
					size_t *out_kde_len);
const uint8_t *handshake_util_find_gtk_kde(const uint8_t *data, size_t data_len,
					size_t *out_gtk_len);
const uint8_t *handshake_util_find_igtk_kde(const uint8_t *data,
					size_t data_len, size_t *out_igtk_len);
const uint8_t *handshake_util_find_pmkid_kde(const uint8_t *data,
					size_t data_len);
void handshake_util_build_gtk_kde(enum crypto_cipher cipher, const uint8_t *key,
					unsigned int key_index, uint8_t *to);
