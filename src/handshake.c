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
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/filter.h>

#include <ell/ell.h>

#include "src/missing.h"
#include "src/crypto.h"
#include "src/ie.h"
#include "src/util.h"
#include "src/handshake.h"
#include "src/erp.h"
#include "src/band.h"

static inline unsigned int n_ecc_groups(void)
{
	const unsigned int *groups = l_ecc_supported_ike_groups();
	unsigned int j = 0;

	while (groups[j])
		j += 1;

	return j;
}

static inline int ecc_group_index(unsigned int group)
{
	const unsigned int *groups = l_ecc_supported_ike_groups();
	int j;

	for (j = 0; groups[j]; j++)
		if (groups[j] == group)
			return j;

	return -ENOENT;
}

static bool handshake_get_nonce(uint8_t nonce[])
{
	return l_getrandom(nonce, 32);
}

static handshake_get_nonce_func_t get_nonce = handshake_get_nonce;
static handshake_install_tk_func_t install_tk = NULL;
static handshake_install_gtk_func_t install_gtk = NULL;
static handshake_install_igtk_func_t install_igtk = NULL;
static handshake_install_ext_tk_func_t install_ext_tk = NULL;

void __handshake_set_get_nonce_func(handshake_get_nonce_func_t func)
{
	get_nonce = func;
}

void __handshake_set_install_tk_func(handshake_install_tk_func_t func)
{
	install_tk = func;
}

void __handshake_set_install_gtk_func(handshake_install_gtk_func_t func)
{
	install_gtk = func;
}

void __handshake_set_install_igtk_func(handshake_install_igtk_func_t func)
{
	install_igtk = func;
}

void __handshake_set_install_ext_tk_func(handshake_install_ext_tk_func_t func)
{
	install_ext_tk = func;
}

void handshake_state_free(struct handshake_state *s)
{
	__typeof__(s->free) destroy;

	if (!s)
		return;

	destroy = s->free;

	if (s->in_event) {
		s->in_event = false;
		return;
	}

	l_free(s->authenticator_ie);
	l_free(s->supplicant_ie);
	l_free(s->authenticator_rsnxe);
	l_free(s->supplicant_rsnxe);
	l_free(s->mde);
	l_free(s->authenticator_fte);
	l_free(s->supplicant_fte);
	l_free(s->fils_ip_req_ie);
	l_free(s->fils_ip_resp_ie);
	l_free(s->vendor_ies);

	if (s->erp_cache)
		erp_cache_put(s->erp_cache);

	l_free(s->chandef);

	if (s->passphrase) {
		explicit_bzero(s->passphrase, strlen(s->passphrase));
		l_free(s->passphrase);
	}

	if (s->password_identifier) {
		explicit_bzero(s->password_identifier,
				strlen(s->password_identifier));
		l_free(s->password_identifier);
	}

	if (s->ecc_sae_pts) {
		unsigned int i;

		for (i = 0; i < n_ecc_groups(); i++)
			l_ecc_point_free(s->ecc_sae_pts[i]);

		l_free(s->ecc_sae_pts);
	}

	explicit_bzero(s, sizeof(*s));

	if (destroy)
		destroy(s);
}

void handshake_state_set_supplicant_address(struct handshake_state *s,
						const uint8_t *spa)
{
	memcpy(s->spa, spa, sizeof(s->spa));
}

void handshake_state_set_authenticator_address(struct handshake_state *s,
						const uint8_t *aa)
{
	memcpy(s->aa, aa, sizeof(s->aa));
}

void handshake_state_set_authenticator(struct handshake_state *s, bool auth)
{
	s->authenticator = auth;
}

void handshake_state_set_pmk(struct handshake_state *s, const uint8_t *pmk,
				size_t pmk_len)
{
	memcpy(s->pmk, pmk, pmk_len);
	s->pmk_len = pmk_len;
	s->have_pmk = true;
}

void handshake_state_set_ptk(struct handshake_state *s, const uint8_t *ptk,
				size_t ptk_len)
{
	memcpy(s->ptk, ptk, ptk_len);
	s->ptk_complete = true;
}

void handshake_state_set_8021x_config(struct handshake_state *s,
					struct l_settings *settings)
{
	s->settings_8021x = settings;
}

bool handshake_state_set_authenticator_ie(struct handshake_state *s,
						const uint8_t *ie)
{
	struct ie_rsn_info info;

	if (!ie_parse_rsne_from_data(ie, ie[1] + 2, &info))
		goto valid_ie;

	if (!ie_parse_wpa_from_data(ie, ie[1] + 2, &info))
		goto valid_ie;

	if (ie_parse_osen_from_data(ie, ie[1] + 2, &info) < 0)
		return false;

valid_ie:
	l_free(s->authenticator_ie);
	s->authenticator_ie = l_memdup(ie, ie[1] + 2u);

	s->authenticator_ocvc = info.ocvc;

	return true;
}

bool handshake_state_set_supplicant_ie(struct handshake_state *s,
						const uint8_t *ie)
{
	struct ie_rsn_info info;
	bool wpa_ie = false;
	bool osen_ie = false;

	if (!ie_parse_rsne_from_data(ie, ie[1] + 2, &info))
		goto valid_ie;

	if (!ie_parse_wpa_from_data(ie, ie[1] + 2, &info)) {
		wpa_ie = true;
		goto valid_ie;
	}

	if (ie_parse_osen_from_data(ie, ie[1] + 2, &info) < 0)
		return false;

	osen_ie = true;

valid_ie:
	if (__builtin_popcount(info.pairwise_ciphers) != 1)
		return false;

	if (__builtin_popcount(info.akm_suites) != 1)
		return false;

	l_free(s->supplicant_ie);
	s->supplicant_ie = l_memdup(ie, ie[1] + 2u);

	s->osen_ie = osen_ie;
	s->wpa_ie = wpa_ie;

	s->pairwise_cipher = info.pairwise_ciphers;
	s->group_cipher = info.group_cipher;
	s->group_management_cipher = info.group_management_cipher;
	s->akm_suite = info.akm_suites;
	s->supplicant_ocvc = info.ocvc;
	s->ext_key_id_capable = info.extended_key_id;

	/*
	 * Don't set MFP for OSEN otherwise EAPoL will attempt to negotiate a
	 * iGTK which is not allowed for OSEN.
	 */
	if (!s->osen_ie)
		s->mfp = info.mfpc;

	return true;
}

static void replace_ie(uint8_t **old, const uint8_t *new)
{
	if (*old == NULL) {
		*old = new ? l_memdup(new, new[1] + 2) : NULL;
		return;
	}

	if (!new) {
		l_free(*old);
		*old = NULL;
		return;
	}

	if ((*old)[1] == new[1] && !memcmp(*old, new, new[1] + 2))
		return;

	l_free(*old);
	*old = l_memdup(new, new[1] + 2);
}

void handshake_state_set_authenticator_rsnxe(struct handshake_state *s,
						const uint8_t *ie)
{
	l_free(s->authenticator_rsnxe);
	s->authenticator_rsnxe = ie ? l_memdup(ie, ie[1] + 2) : NULL;
}

void handshake_state_set_supplicant_rsnxe(struct handshake_state *s,
						const uint8_t *ie)
{
	replace_ie(&s->supplicant_rsnxe, ie);
}

void handshake_state_set_ssid(struct handshake_state *s, const uint8_t *ssid,
				size_t ssid_len)
{
	memcpy(s->ssid, ssid, ssid_len);
	s->ssid_len = ssid_len;
}

void handshake_state_set_mde(struct handshake_state *s, const uint8_t *mde)
{
	replace_ie(&s->mde, mde);
}

void handshake_state_set_authenticator_fte(struct handshake_state *s,
						const uint8_t *fte)
{
	replace_ie(&s->authenticator_fte, fte);
}

void handshake_state_set_supplicant_fte(struct handshake_state *s,
						const uint8_t *fte)
{
	replace_ie(&s->supplicant_fte, fte);
}

void handshake_state_set_vendor_ies(struct handshake_state *s,
					const struct iovec *iov,
					size_t n_iovs)
{
	size_t i;
	size_t len;

	l_free(s->vendor_ies);
	s->vendor_ies = NULL;

	if (n_iovs == 0) {
		s->vendor_ies_len = 0;
		return;
	}

	for (i = 0, len = 0; i < n_iovs; i++)
		len += iov[i].iov_len;

	s->vendor_ies_len = len;
	s->vendor_ies = l_malloc(len);

	for (i = 0, len = 0; i < n_iovs; i++) {
		memcpy(s->vendor_ies + len, iov[i].iov_base, iov[i].iov_len);
		len += iov[i].iov_len;
	}
}

void handshake_state_set_kh_ids(struct handshake_state *s,
				const uint8_t *r0khid, size_t r0khid_len,
				const uint8_t *r1khid)
{
	memcpy(s->r0khid, r0khid, r0khid_len);
	s->r0khid_len = r0khid_len;

	memcpy(s->r1khid, r1khid, 6);
}

void handshake_state_set_event_func(struct handshake_state *s,
					handshake_event_func_t func,
					void *user_data)
{
	s->event_func = func;
	s->user_data = user_data;
}

void handshake_state_set_passphrase(struct handshake_state *s,
					const char *passphrase)
{
	s->passphrase = l_strdup(passphrase);
}

void handshake_state_set_password_identifier(struct handshake_state *s,
						const char *id)
{
	s->password_identifier = l_strdup(id);
}

void handshake_state_set_no_rekey(struct handshake_state *s, bool no_rekey)
{
	s->no_rekey = no_rekey;
}

void handshake_state_set_fils_ft(struct handshake_state *s,
					const uint8_t *fils_ft,
					size_t fils_ft_len)
{
	memcpy(s->fils_ft, fils_ft, fils_ft_len);
	s->fils_ft_len = fils_ft_len;
}

/*
 * Override the protocol version used for EAPoL packets.  The selection is as
 * follows:
 *  0 -> Automatic, use same proto as the request for the response and
 *       2004 when in authenticator mode
 *  1 -> Chooses 2001 Protocol Version
 *  2 -> Chooses 2004 Protocol Version
 *  3 -> Chooses 2010 Protocol Version
 */
void handshake_state_set_protocol_version(struct handshake_state *s,
						uint8_t proto_version)
{
	s->proto_version = proto_version;
}

void handshake_state_new_snonce(struct handshake_state *s)
{
	get_nonce(s->snonce);

	s->have_snonce = true;
}

void handshake_state_new_anonce(struct handshake_state *s)
{
	get_nonce(s->anonce);

	s->have_anonce = true;
}

void handshake_state_set_anonce(struct handshake_state *s,
				const uint8_t *anonce)
{
	memcpy(s->anonce, anonce, 32);
}

/* A multi-purpose getter for key sizes */
static bool handshake_get_key_sizes(struct handshake_state *s, size_t *ptk_size,
					size_t *kck_size, size_t *kek_size)
{
	size_t kck;
	size_t kek;
	size_t tk;
	enum crypto_cipher cipher =
			ie_rsn_cipher_suite_to_cipher(s->pairwise_cipher);

	tk = crypto_cipher_key_len(cipher);

	/*
	 * IEEE 802.11-2016 Table 12-8: Integrity and key-wrap algorithms
	 *
	 * From the table, only 00-0F-AC:12 and 00-0F-AC:13 use longer KCK and
	 * KEK keys, which are 24 and 32 bytes respectively. The remainder use
	 * 16 and 16 respectively.
	 */
	switch (s->akm_suite) {
	case IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA256:
	case IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384:
		kck = 24;
		kek = 32;
		break;
	case IE_RSN_AKM_SUITE_OWE:
		/*
		 * RFC 8110 Section 4.4 Table 2
		 *
		 * Luckily with OWE we can deduce the key lengths from the PMK
		 * size, since the PMK size maps to unique KCK/KEK lengths.
		 */
		switch (s->pmk_len) {
		case 32:
			/* SHA-256 used for PMK */
			kck = 16;
			kek = 16;
			break;
		case 48:
			/* SHA-384 used for PMK */
			kck = 24;
			kek = 32;
			break;
		case 64:
			/* SHA-512 used for PMK */
			kck = 32;
			kek = 32;
			break;
		default:
			l_error("Invalid PMK length for OWE %zu\n", s->pmk_len);
			return false;
		}

		break;
	case IE_RSN_AKM_SUITE_FILS_SHA256:
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256:
		kck = 0;
		kek = 32;
		break;
	case IE_RSN_AKM_SUITE_FILS_SHA384:
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384:
		kck = 0;
		kek = 64;
		break;
	default:
		kck = 16;
		kek = 16;
		break;
	}

	if (ptk_size) {
		*ptk_size = kck + kek + tk;
		if (s->akm_suite == IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256)
			*ptk_size += 32;
		else if (s->akm_suite == IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384)
			*ptk_size += 56;
	}

	if (kck_size)
		*kck_size = kck;

	if (kek_size)
		*kek_size = kek;

	return true;
}

bool handshake_state_derive_ptk(struct handshake_state *s)
{
	size_t ptk_size;
	enum l_checksum_type type;

	if (!(s->akm_suite & (IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256 |
			IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384)))
		if (!s->have_snonce || !s->have_pmk)
			return false;

	if ((s->akm_suite & (IE_RSN_AKM_SUITE_FT_OVER_8021X |
				IE_RSN_AKM_SUITE_FT_USING_PSK |
				IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256 |
				IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256 |
				IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384)) &&
			(!s->mde || !s->authenticator_fte))
		return false;

	s->ptk_complete = false;

	if (s->akm_suite & IE_RSN_AKM_SUITE_OWE) {
		if (s->pmk_len == 32)
			type = L_CHECKSUM_SHA256;
		else if (s->pmk_len == 48)
			type = L_CHECKSUM_SHA384;
		else if (s->pmk_len == 64)
			type = L_CHECKSUM_SHA512;
		else
			return false;
	} else if (s->akm_suite & (IE_RSN_AKM_SUITE_FILS_SHA384 |
			IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384))
		type = L_CHECKSUM_SHA384;
	else if (s->akm_suite & (IE_RSN_AKM_SUITE_8021X_SHA256 |
			IE_RSN_AKM_SUITE_PSK_SHA256 |
			IE_RSN_AKM_SUITE_SAE_SHA256 |
			IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256 |
			IE_RSN_AKM_SUITE_FILS_SHA256 |
			IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256 |
			IE_RSN_AKM_SUITE_OSEN))
		type = L_CHECKSUM_SHA256;
	else
		type = L_CHECKSUM_SHA1;

	ptk_size = handshake_state_get_ptk_size(s);

	if (s->akm_suite & (IE_RSN_AKM_SUITE_FT_OVER_8021X |
				IE_RSN_AKM_SUITE_FT_USING_PSK |
				IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256 |
				IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256 |
				IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384)) {
		uint16_t mdid;
		uint8_t ptk_name[16];
		const uint8_t *xxkey = s->pmk;
		size_t xxkey_len = 32;
		bool sha384 = (s->akm_suite &
					IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384);

		/*
		 * In a Fast Transition initial mobility domain association
		 * the PMK maps to the XXKey, except with EAP:
		 * 802.11-2016 12.7.1.7.3:
		 *    "If the AKM negotiated is 00-0F-AC:3, then [...] XXKey
		 *    shall be the second 256 bits of the MSK (which is
		 *    derived from the IEEE 802.1X authentication), i.e.,
		 *    XXKey = L(MSK, 256, 256)."
		 */
		if (s->akm_suite == IE_RSN_AKM_SUITE_FT_OVER_8021X)
			xxkey = s->pmk + 32;
		else if (s->akm_suite & (IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256 |
				IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384)) {
			xxkey = s->fils_ft;
			xxkey_len = s->fils_ft_len;
		}

		ie_parse_mobility_domain_from_data(s->mde, s->mde[1] + 2,
							&mdid, NULL, NULL);

		if (!crypto_derive_pmk_r0(xxkey, xxkey_len, s->ssid,
						s->ssid_len, mdid,
						s->r0khid, s->r0khid_len,
						s->spa, sha384,
						s->pmk_r0, s->pmk_r0_name))
			return false;

		if (!crypto_derive_pmk_r1(s->pmk_r0, s->r1khid, s->spa,
						s->pmk_r0_name, sha384,
						s->pmk_r1, s->pmk_r1_name))
			return false;

		if (!crypto_derive_ft_ptk(s->pmk_r1, s->pmk_r1_name, s->aa,
						s->spa, s->snonce, s->anonce,
						sha384, s->ptk, ptk_size,
						ptk_name))
			return false;
	} else
		if (!crypto_derive_pairwise_ptk(s->pmk, s->pmk_len, s->spa,
						s->aa, s->anonce, s->snonce,
						s->ptk, ptk_size, type))
			return false;

	return true;
}

size_t handshake_state_get_ptk_size(struct handshake_state *s)
{
	size_t ptk_size;

	if (!handshake_get_key_sizes(s, &ptk_size, NULL, NULL))
		return 0;

	return ptk_size;
}

const uint8_t *handshake_state_get_kck(struct handshake_state *s)
{
	/*
	 * FILS itself does not derive a KCK, but FILS-FT derives additional
	 * key bytes at the end of the PTK, which contains a special KCK used
	 * for fast transition. Since the normal FILS protocol will never call
	 * this, we can assume that its only being called for FILS-FT and is
	 * requesting this special KCK.
	 */
	if (s->akm_suite & IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256)
		return s->ptk + 48;
	else if (s->akm_suite & IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384)
		return s->ptk + 80;

	return s->ptk;
}

size_t handshake_state_get_kck_len(struct handshake_state *s)
{
	if (s->akm_suite & IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384)
		return 24;

	return 16;
}

size_t handshake_state_get_kek_len(struct handshake_state *s)
{
	size_t kek_size;

	if (!handshake_get_key_sizes(s, NULL, NULL, &kek_size))
		return 0;

	return kek_size;
}

const uint8_t *handshake_state_get_kek(struct handshake_state *s)
{
	size_t kck_size;

	if (!handshake_get_key_sizes(s, NULL, &kck_size, NULL))
		return NULL;

	return s->ptk + kck_size;
}

static const uint8_t *handshake_get_tk(struct handshake_state *s)
{
	size_t kck_size, kek_size;

	if (!handshake_get_key_sizes(s, NULL, &kck_size, &kek_size))
		return NULL;

	return s->ptk + kck_size + kek_size;
}

void handshake_state_install_ptk(struct handshake_state *s)
{
	s->ptk_complete = true;

	if (install_tk) {
		uint32_t cipher = ie_rsn_cipher_suite_to_cipher(
							s->pairwise_cipher);

		handshake_event(s, HANDSHAKE_EVENT_SETTING_KEYS);

		install_tk(s, s->active_tk_index, handshake_get_tk(s), cipher);
	}
}

void handshake_state_install_ext_ptk(struct handshake_state *s,
				uint8_t key_idx,
				struct eapol_frame *ek, uint16_t proto,
				bool noencrypt)
{
	s->ptk_complete = true;

	if (install_ext_tk) {
		uint32_t cipher =
			ie_rsn_cipher_suite_to_cipher(s->pairwise_cipher);

		install_ext_tk(s, key_idx, handshake_get_tk(s), cipher, ek,
				proto, noencrypt);
	}
}


void handshake_state_install_gtk(struct handshake_state *s,
					uint16_t gtk_key_index,
					const uint8_t *gtk, size_t gtk_len,
					const uint8_t *rsc, uint8_t rsc_len)
{
	if (install_gtk) {
		uint32_t cipher =
			ie_rsn_cipher_suite_to_cipher(s->group_cipher);

		install_gtk(s, gtk_key_index, gtk, gtk_len,
				rsc, rsc_len, cipher);
	}
}

void handshake_state_install_igtk(struct handshake_state *s,
					uint16_t igtk_key_index,
					const uint8_t *igtk, size_t igtk_len,
					const uint8_t *ipn)
{
	if (install_igtk) {
		uint32_t cipher =
			ie_rsn_cipher_suite_to_cipher(
						s->group_management_cipher);

		install_igtk(s, igtk_key_index, igtk, igtk_len,
				ipn, 6, cipher);
	}
}

void handshake_state_override_pairwise_cipher(struct handshake_state *s,
					enum ie_rsn_cipher_suite pairwise)
{
	s->pairwise_cipher = pairwise;
}

void handshake_state_set_pmkid(struct handshake_state *s, const uint8_t *pmkid)
{
	memcpy(s->pmkid, pmkid, 16);
	s->have_pmkid = true;
}

bool handshake_state_get_pmkid(struct handshake_state *s, uint8_t *out_pmkid,
				enum l_checksum_type sha)
{
	/* SAE exports pmkid */
	if (s->have_pmkid) {
		memcpy(out_pmkid, s->pmkid, 16);
		return true;
	}

	if (!s->have_pmk)
		return false;

	return crypto_derive_pmkid(s->pmk, 32, s->spa, s->aa, out_pmkid,
					sha);
}

bool handshake_state_pmkid_matches(struct handshake_state *s,
					const uint8_t *check)
{
	uint8_t own_pmkid[16];
	enum l_checksum_type sha;

	/*
	 * 802.11-2020 Table 9-151 defines the hashing algorithm to use
	 * for various AKM's. Note some AKMs are omitted here because they
	 * export the PMKID individually (SAE/FILS/FT-PSK)
	 *
	 * SHA1:
	 * 	00-0F-AC:1 (8021X)
	 * 	00-0F-AC:2 (PSK)
	 *
	 * SHA256:
	 * 	00-0F-AC:3 (FT-8021X)
	 * 	00-0F-AC:5 (8021X-SHA256)
	 * 	00-0F-AC:6 (PSK-SHA256)
	 *
	 * SHA384:
	 * 	00-0F-AC:13 (FT-8021X-SHA384)
	 */
	if (s->akm_suite & (IE_RSN_AKM_SUITE_8021X_SHA256 |
			IE_RSN_AKM_SUITE_PSK_SHA256 |
			IE_RSN_AKM_SUITE_FT_OVER_8021X))
		sha = L_CHECKSUM_SHA256;
	else
		sha = L_CHECKSUM_SHA1;

	if (!handshake_state_get_pmkid(s, own_pmkid, sha))
		return false;

	if (l_secure_memcmp(own_pmkid, check, 16)) {
		if (s->akm_suite != IE_RSN_AKM_SUITE_FT_OVER_8021X)
			return false;

		l_debug("PMKID did not match, trying SHA1 derivation");

		if (!handshake_state_get_pmkid(s, own_pmkid, L_CHECKSUM_SHA1))
			return false;

		return l_secure_memcmp(own_pmkid, check, 16) == 0;
	}

	return true;
}

void handshake_state_set_gtk(struct handshake_state *s, const uint8_t *key,
				unsigned int key_index, const uint8_t *rsc)
{
	enum crypto_cipher cipher =
		ie_rsn_cipher_suite_to_cipher(s->group_cipher);
	int key_len = crypto_cipher_key_len(cipher);

	if (!key_len)
		return;

	memcpy(s->gtk, key, key_len);
	s->gtk_index = key_index;
	memcpy(s->gtk_rsc, rsc, 6);
}

void handshake_state_set_igtk(struct handshake_state *s, const uint8_t *key,
				unsigned int key_index, const uint8_t *rsc)
{
	enum crypto_cipher cipher =
		ie_rsn_cipher_suite_to_cipher(s->group_management_cipher);
	int key_len = crypto_cipher_key_len(cipher);

	if (!key_len)
		return;

	memcpy(s->igtk, key, key_len);
	s->igtk_index = key_index;
	memcpy(s->igtk_rsc, rsc, 6);
}

/*
 * This function performs a match of the RSN/WPA IE obtained from the scan
 * results vs the RSN/WPA IE obtained as part of the 4-way handshake.  If they
 * don't match, the EAPoL packet must be silently discarded.
 */
bool handshake_util_ap_ie_matches(const struct ie_rsn_info *msg_info,
					const uint8_t *scan_ie, bool is_wpa)
{
	struct ie_rsn_info scan_info;
	int r;

	if (!is_wpa)
		r = ie_parse_rsne_from_data(scan_ie,
						scan_ie[1] + 2, &scan_info);
	else
		r = ie_parse_wpa_from_data(scan_ie, scan_ie[1] + 2, &scan_info);

	if (r < 0)
		return false;

	if (msg_info->group_cipher != scan_info.group_cipher)
		return false;

	if (msg_info->pairwise_ciphers != scan_info.pairwise_ciphers)
		return false;

	if (msg_info->akm_suites != scan_info.akm_suites)
		return false;

	if (msg_info->preauthentication != scan_info.preauthentication)
		return false;

	if (msg_info->no_pairwise != scan_info.no_pairwise)
		return false;

	if (msg_info->ptksa_replay_counter != scan_info.ptksa_replay_counter)
		return false;

	if (msg_info->gtksa_replay_counter != scan_info.gtksa_replay_counter)
		return false;

	if (msg_info->mfpr != scan_info.mfpr)
		return false;

	if (msg_info->mfpc != scan_info.mfpc)
		return false;

	if (msg_info->peerkey_enabled != scan_info.peerkey_enabled)
		return false;

	if (msg_info->spp_a_msdu_capable != scan_info.spp_a_msdu_capable)
		return false;

	if (msg_info->spp_a_msdu_required != scan_info.spp_a_msdu_required)
		return false;

	if (msg_info->pbac != scan_info.pbac)
		return false;

	if (msg_info->extended_key_id != scan_info.extended_key_id)
		return false;

	if (msg_info->ocvc != scan_info.ocvc)
		return false;

	/* We don't check the PMKIDs since these might actually be different */

	if (msg_info->group_management_cipher !=
			scan_info.group_management_cipher)
		return false;

	return true;
}

const uint8_t *handshake_util_find_kde(enum handshake_kde selector,
				const uint8_t *data, size_t data_len,
				size_t *out_kde_len)
{
	struct ie_tlv_iter iter;
	const uint8_t *result;
	unsigned int len;

	ie_tlv_iter_init(&iter, data, data_len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
			continue;

		len = ie_tlv_iter_get_length(&iter);
		if (len < 4)		/* Take care of padding */
			return NULL;

		/* Check OUI */
		result = ie_tlv_iter_get_data(&iter);
		if (l_get_be32(result) != selector)
			continue;

		if (out_kde_len)
			*out_kde_len = len - 4;

		return result + 4;
	}

	return NULL;
}

const uint8_t *handshake_util_find_gtk_kde(const uint8_t *data, size_t data_len,
						size_t *out_gtk_len)
{
	size_t gtk_len;
	const uint8_t *gtk = handshake_util_find_kde(HANDSHAKE_KDE_GTK,
						data, data_len, &gtk_len);

	if (!gtk)
		return NULL;

	/*
	 * Account for KeyId, TX and Reserved octet
	 * See 802.11-2016, Figure 12-35
	 */
	if (gtk_len < CRYPTO_MIN_GTK_LEN + 2)
		return NULL;

	if (gtk_len > CRYPTO_MAX_GTK_LEN + 2)
		return NULL;

	if (out_gtk_len)
		*out_gtk_len = gtk_len;

	return gtk;
}

const uint8_t *handshake_util_find_igtk_kde(const uint8_t *data,
						size_t data_len,
						size_t *out_igtk_len)
{
	size_t igtk_len;
	const uint8_t *igtk = handshake_util_find_kde(HANDSHAKE_KDE_IGTK,
						data, data_len, &igtk_len);

	if (!igtk)
		return NULL;

	/*
	 * Account for KeyId and IPN
	 * See 802.11-2016, Figure 12-42
	 */
	if (igtk_len < CRYPTO_MIN_IGTK_LEN + 8)
		return NULL;

	if (igtk_len > CRYPTO_MAX_IGTK_LEN + 8)
		return NULL;

	if (out_igtk_len)
		*out_igtk_len = igtk_len;

	return igtk;
}

const uint8_t *handshake_util_find_pmkid_kde(const uint8_t *data,
						size_t data_len)
{
	const uint8_t *pmkid;
	size_t pmkid_len;

	pmkid = handshake_util_find_kde(HANDSHAKE_KDE_PMKID, data, data_len,
					&pmkid_len);

	if (pmkid && pmkid_len != 16)
		return NULL;

	return pmkid;
}

/* Defined in 802.11-2016 12.7.2 j), Figure 12-34 */
void handshake_util_build_gtk_kde(enum crypto_cipher cipher, const uint8_t *key,
					unsigned int key_index, uint8_t *to)
{
	size_t key_len = crypto_cipher_key_len(cipher);

	*to++ = IE_TYPE_VENDOR_SPECIFIC;
	*to++ = 6 + key_len;
	l_put_be32(HANDSHAKE_KDE_GTK, to);
	to += 4;
	*to++ = key_index;
	*to++ = 0;
	memcpy(to, key, key_len);
}

void handshake_util_build_igtk_kde(enum crypto_cipher cipher, const uint8_t *key,
					unsigned int key_index, uint8_t *to)
{
	size_t key_len = crypto_cipher_key_len(cipher);

	*to++ = IE_TYPE_VENDOR_SPECIFIC;
	*to++ = 12 + key_len;
	l_put_be32(HANDSHAKE_KDE_IGTK, to);
	to += 4;
	*to++ = key_index;
	*to++ = 0;

	/** Initialize PN to zero **/
	memset(to, 0, 6);
	to += 6;

	memcpy(to, key, key_len);
}

static const uint8_t *handshake_state_get_ft_fils_kek(struct handshake_state *s,
						size_t *len)
{
	if (s->akm_suite & IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256) {
		if (len)
			*len = 16;

		return s->ptk + 64;
	} else if (s->akm_suite & IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384) {
		if (len)
			*len = 32;

		return s->ptk + 104;
	}

	return NULL;
}

/*
 * Unwrap a GTK / IGTK included in an FTE following 802.11-2012, Section 12.8.5:
 *
 * "If a GTK or an IGTK are included, the Key field of the subelement shall be
 * encrypted using KEK and the NIST AES key wrap algorithm. The Key field shall
 * be padded before encrypting if the key length is less than 16 octets or if
 * it is not a multiple of 8. The padding consists of appending a single octet
 * 0xdd followed by zero or more 0x00 octets. When processing a received
 * message, the receiver shall ignore this trailing padding. Addition of
 * padding does not change the value of the Key Length field. Note that the
 * length of the encrypted Key field can be determined from the length of the
 * GTK or IGTK subelement.
 */
bool handshake_decode_fte_key(struct handshake_state *s, const uint8_t *wrapped,
				size_t key_len, uint8_t *key_out)
{
	const uint8_t *kek;
	size_t kek_len = handshake_state_get_kek_len(s);
	size_t padded_len = key_len < 16 ? 16 : align_len(key_len, 8);

	if (s->akm_suite & (IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256 |
				IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384))
		kek = handshake_state_get_ft_fils_kek(s, &kek_len);
	else
		kek = handshake_state_get_kek(s);

	if (!aes_unwrap(kek, kek_len, wrapped, padded_len + 8, key_out))
		return false;

	if (key_len < padded_len && key_out[key_len++] != 0xdd)
		return false;

	while (key_len < padded_len)
		if (key_out[key_len++] != 0x00)
			return false;

	return true;
}

/* Add SAE-PT for ECC groups.  The group is carried by the point itself */
bool handshake_state_add_ecc_sae_pt(struct handshake_state *s,
						const struct l_ecc_point *pt)
{
	const struct l_ecc_curve *curve;
	int i;

	if (!pt)
		return false;

	curve = l_ecc_point_get_curve(pt);

	if (!s->ecc_sae_pts)
		s->ecc_sae_pts = l_new(struct l_ecc_point *, n_ecc_groups());

	if ((i = ecc_group_index(l_ecc_curve_get_ike_group(curve))) < 0)
		return false;

	if (s->ecc_sae_pts[i])
		return false;

	s->ecc_sae_pts[i] = l_ecc_point_clone(pt);
	return true;
}

void handshake_state_set_chandef(struct handshake_state *s,
						struct band_chandef *chandef)
{
	if (s->chandef)
		l_free(s->chandef);

	s->chandef = chandef;
}

int handshake_state_verify_oci(struct handshake_state *s, const uint8_t *oci,
				size_t oci_len)
{
	int r = -ENOENT;
	bool ocvc;

	l_debug("oci_len: %zu", oci ? oci_len : 0);

	if (!oci)
		goto done;

	r = -EBADMSG;
	if (oci_len != 3)
		goto done;

	l_debug("operating_class: %hu", oci[0]);
	l_debug("primary_channel_number: %hu", oci[1]);
	l_debug("frequency segment 1 channel number: %hu", oci[2]);

	r = -EINVAL;

	if (!s->chandef) {
		l_debug("Own chandef unavailable");
		goto done;
	}

	r = oci_verify(oci, s->chandef);
	if (r < 0)
		l_debug("OCI verification failed: %s", strerror(-r));

done:
	if (!r)
		return r;

	/* Only enforce validation if we're configured to do so */
	ocvc = s->authenticator ? s->authenticator_ocvc : s->supplicant_ocvc;
	if (!ocvc)
		r = 0;

	return r;
}
