
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

#include <ell/ell.h>

#include "ell/useful.h"
#include "src/ie.h"
#include "src/fils.h"
#include "src/handshake.h"
#include "src/mpdu.h"
#include "src/crypto.h"
#include "src/util.h"
#include "src/missing.h"
#include "src/erp.h"
#include "src/auth-proto.h"
#include "src/band.h"

#define FILS_NONCE_LEN		16
#define FILS_SESSION_LEN	8

struct fils_sm {
	struct auth_proto ap;
	struct erp_state *erp;
	struct handshake_state *hs;
	void *user_data;

	fils_tx_authenticate_func_t auth;
	fils_tx_associate_func_t assoc;
	fils_get_oci_func_t get_oci;

	uint8_t nonce[FILS_NONCE_LEN];
	uint8_t anonce[FILS_NONCE_LEN];
	uint8_t session[FILS_SESSION_LEN];

	uint8_t ick[48];
	size_t ick_len;
	uint8_t kek_and_tk[64 + 16];
	size_t kek_len;
	uint8_t pmk[48];
	size_t pmk_len;
	uint8_t pmkid[16];

	uint8_t fils_ft[48];
	size_t fils_ft_len;
};

static void fils_derive_pmkid(struct fils_sm *fils, const uint8_t *erp_data,
				size_t len)
{
	struct l_checksum *sha;
	enum l_checksum_type type;

	if (fils->hs->akm_suite & (IE_RSN_AKM_SUITE_FILS_SHA256 |
			IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256))
		type = L_CHECKSUM_SHA256;
	else
		type = L_CHECKSUM_SHA384;

	sha = l_checksum_new(type);
	l_checksum_update(sha, erp_data, len);
	l_checksum_get_digest(sha, fils->pmkid, sizeof(fils->pmkid));
	l_checksum_free(sha);
}

static void fils_erp_tx_func(const uint8_t *eap_data, size_t len,
				void *user_data)
{
	struct fils_sm *fils = user_data;
	struct ie_tlv_builder builder;
	uint8_t data[256];
	uint8_t *ptr = data;
	struct ie_rsn_info rsn_info;
	uint8_t *rsne;

	l_getrandom(fils->nonce, 16);
	l_getrandom(fils->session, 8);

	fils_derive_pmkid(fils, eap_data, len);

	/* transaction */
	l_put_le16(1, ptr);
	ptr += 2;
	/* status success */
	l_put_le16(0, ptr);
	ptr += 2;

	ie_tlv_builder_init(&builder, ptr, sizeof(data) - 4);

	ie_parse_rsne_from_data(fils->hs->supplicant_ie,
				fils->hs->supplicant_ie[1] + 2,
				&rsn_info);
	rsne = alloca(256);
	ie_build_rsne(&rsn_info, rsne);

	ie_tlv_builder_next(&builder, IE_TYPE_RSN);
	ie_tlv_builder_set_data(&builder, rsne + 2, rsne[1]);

	ie_tlv_builder_next(&builder, IE_TYPE_FILS_NONCE);
	ie_tlv_builder_set_data(&builder, fils->nonce, sizeof(fils->nonce));

	ie_tlv_builder_next(&builder, IE_TYPE_FILS_SESSION);
	ie_tlv_builder_set_data(&builder, fils->session, sizeof(fils->session));

	ie_tlv_builder_next(&builder, IE_TYPE_FILS_WRAPPED_DATA);
	ie_tlv_builder_set_data(&builder, eap_data, len);

	if (fils->hs->mde) {
		ie_tlv_builder_next(&builder, IE_TYPE_MOBILITY_DOMAIN);
		ie_tlv_builder_set_data(&builder, fils->hs->mde + 2,
						fils->hs->mde[1]);
	}

	ie_tlv_builder_finalize(&builder, &len);

	fils->auth(data, ptr - data + len, fils->user_data);
}

static int fils_derive_key_data(struct fils_sm *fils)
{
	const void *rmsk;
	size_t rmsk_len;
	struct ie_tlv_builder builder;
	uint8_t key[FILS_NONCE_LEN * 2];
	uint8_t key_data[64 + 48 + 16 + 48]; /* largest ICK, KEK, TK, FILS-FT */
	uint8_t key_auth[48];
	uint8_t data[44];
	uint8_t *ptr = data;
	size_t hash_len;
	struct iovec iov[5];
	size_t iov_elems = 0;
	size_t fils_ft_len = 0;
	bool sha384;
	size_t ie_len;
	uint8_t *rsne = NULL;
	uint8_t oci[6];

	rmsk = erp_get_rmsk(fils->erp, &rmsk_len);

	if (fils->hs->akm_suite == IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256)
		fils_ft_len = 32;
	else if (fils->hs->akm_suite == IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384)
		fils_ft_len = 48;
	/*
	 * IEEE 802.11ai - Section 12.12.2.5.3
	 */
	if (fils->hs->akm_suite & (IE_RSN_AKM_SUITE_FILS_SHA256 |
				IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256)) {
		sha384 = false;
		hash_len = 32;
	} else {
		sha384 = true;
		hash_len = 48;
	}

	fils->kek_len = handshake_state_get_kek_len(fils->hs);

	/* key is SNonce || ANonce */
	memcpy(key, fils->nonce, sizeof(fils->nonce));
	memcpy(key + FILS_NONCE_LEN, fils->anonce, sizeof(fils->anonce));

	if (sha384)
		hmac_sha384(key, sizeof(key), rmsk, rmsk_len,
				fils->pmk, hash_len);
	else
		hmac_sha256(key, sizeof(key), rmsk, rmsk_len,
				fils->pmk, hash_len);

	fils->pmk_len = hash_len;

	/*
	 * IEEE 802.11ai - 12.12.2.5.3 PTKSA key derivation with FILS
	 *                             authentication
	 *
	 * FILS-Key-Data = PRF-X(PMK, "FILS PTK Derivation", SPA || AA ||
	 *                                                   SNonce || ANonce)
	 */
	memcpy(ptr, fils->hs->spa, 6);
	ptr += 6;
	memcpy(ptr, fils->hs->aa, 6);
	ptr += 6;
	memcpy(ptr, fils->nonce, sizeof(fils->nonce));
	ptr += sizeof(fils->nonce);
	memcpy(ptr, fils->anonce, sizeof(fils->anonce));
	ptr += sizeof(fils->anonce);

	if (sha384)
		kdf_sha384(fils->pmk, hash_len, "FILS PTK Derivation",
				strlen("FILS PTK Derivation"), data,
				sizeof(data), key_data,
				hash_len + fils->kek_len + 16 + fils_ft_len);
	else
		kdf_sha256(fils->pmk, hash_len, "FILS PTK Derivation",
				strlen("FILS PTK Derivation"), data,
				sizeof(data), key_data,
				hash_len + fils->kek_len + 16 + fils_ft_len);

	ptr = data;

	/*
	 * IEEE 802.11ai - 12.12.2.6.2 (Re)Association Request for FILS key
	 *			confirmation
	 *
	 * Key-Auth = HMAC-Hash(ICK, SNonce || ANonce || STA-MAC || AP-BSSID)
	 */
	memcpy(ptr, fils->nonce, sizeof(fils->nonce));
	ptr += sizeof(fils->nonce);
	memcpy(ptr, fils->anonce, sizeof(fils->anonce));
	ptr += sizeof(fils->anonce);
	memcpy(ptr, fils->hs->spa, 6);
	ptr += 6;
	memcpy(ptr, fils->hs->aa, 6);
	ptr += 6;

	memcpy(fils->ick, key_data, hash_len);
	fils->ick_len = hash_len;

	if (fils_ft_len) {
		memcpy(fils->fils_ft, key_data + hash_len + fils->kek_len + 16,
				fils_ft_len);
		fils->fils_ft_len = fils_ft_len;
	}

	handshake_state_set_fils_ft(fils->hs, fils->fils_ft, fils->fils_ft_len);

	if (sha384)
		hmac_sha384(fils->ick, hash_len, data, ptr - data,
				key_auth, hash_len);
	else
		hmac_sha256(fils->ick, hash_len, data, ptr - data,
				key_auth, hash_len);

	ie_tlv_builder_init(&builder, NULL, 0);

	ie_tlv_builder_next(&builder, IE_TYPE_FILS_KEY_CONFIRMATION);
	ie_tlv_builder_set_data(&builder, key_auth, hash_len);

	ie_tlv_builder_next(&builder, IE_TYPE_FILS_SESSION);
	ie_tlv_builder_set_data(&builder, fils->session, sizeof(fils->session));

	iov[iov_elems].iov_base = ie_tlv_builder_finalize(&builder, &ie_len);
	iov[iov_elems].iov_len = ie_len;
	iov_elems++;
	iov[iov_elems].iov_base = fils->hs->supplicant_ie;
	iov[iov_elems].iov_len = fils->hs->supplicant_ie[1] + 2;
	iov_elems++;

	if (fils->hs->mde) {
		struct ie_rsn_info rsn_info;

		/*
		 * IEEE 8021.11ai Section 13.2.4:
		 *
		 * If a key hierarchy already exists for this STA belonging to
		 * the same mobility domain (i.e., having the same MDID), the
		 * R0KH shall delete the existing PMK-R0 security association
		 * and PMK-R1 security associations.
		 *
		 * All this means is we need to re-derive the new FT keys. This
		 * will rederive the PTK too, but it will be overwritten with
		 * the FILS PTK after associate
		 */
		handshake_state_derive_ptk(fils->hs);

		iov[iov_elems].iov_base = fils->hs->mde;
		iov[iov_elems].iov_len = fils->hs->mde[1] + 2;
		iov_elems++;

		if (ie_parse_rsne_from_data(fils->hs->supplicant_ie,
						fils->hs->supplicant_ie[1] + 2,
						&rsn_info) < 0)
			return -EPROTO;

		rsn_info.num_pmkids = 1;
		rsn_info.pmkids = fils->hs->pmk_r1_name;

		rsne = alloca(256);
		ie_build_rsne(&rsn_info, rsne);

		iov[iov_elems].iov_base = rsne;
		iov[iov_elems].iov_len = rsne[1] + 2;
		iov_elems += 1;
	}

	/*
	 * IEEE 802.11 Section 12.11.2.6.2
	 * "If dot11RSNAOperatingChannelValidationActivated is true and AP
	 * indicates OCVC capability, the STA shall include OCI element in the
	 * request"
	 */
	if (fils->hs->supplicant_ocvc && fils->hs->chandef) {
		oci[0] = IE_TYPE_EXTENSION;
		oci[1] = 4;
		oci[2] = IE_TYPE_OCI & 0xff;
		oci_from_chandef(fils->hs->chandef, oci + 3);

		iov[iov_elems].iov_base = oci;
		iov[iov_elems].iov_len = 6;
		iov_elems++;
	}

	memcpy(data, fils->nonce, sizeof(fils->nonce));
	memcpy(data + sizeof(fils->nonce), fils->anonce, sizeof(fils->anonce));

	memcpy(fils->kek_and_tk, key_data + hash_len, fils->kek_len + 16);

	fils->assoc(iov, iov_elems, fils->kek_and_tk, fils->kek_len, data,
			FILS_NONCE_LEN * 2, fils->user_data);

	return 0;
}

static bool fils_start(struct auth_proto *driver)
{
	struct fils_sm *fils = l_container_of(driver, struct fils_sm, ap);

	return erp_start(fils->erp);
}

static void fils_free(struct auth_proto *driver)
{
	struct fils_sm *fils = l_container_of(driver, struct fils_sm, ap);

	erp_free(fils->erp);

	explicit_bzero(fils->ick, sizeof(fils->ick));
	explicit_bzero(fils->kek_and_tk, sizeof(fils->kek_and_tk));
	explicit_bzero(fils->pmk, fils->pmk_len);
	explicit_bzero(fils->pmkid, sizeof(fils->pmkid));

	l_free(fils);
}

static int fils_rx_authenticate(struct auth_proto *driver, const uint8_t *frame,
				size_t len)
{
	struct fils_sm *fils = l_container_of(driver, struct fils_sm, ap);
	const struct mmpdu_header *hdr = (const struct mmpdu_header *) frame;
	const struct mmpdu_authentication *auth = mmpdu_body(hdr);
	uint16_t alg;
	struct ie_tlv_iter iter;
	const uint8_t *anonce = NULL;
	const uint8_t *session = NULL;
	const uint8_t *wrapped = NULL;
	size_t wrapped_len = 0;
	const uint8_t *rsne = NULL;
	const uint8_t *mde = NULL;
	const uint8_t *fte = NULL;

	if (auth->status != 0) {
		l_debug("invalid status %u", auth->status);
		return L_LE16_TO_CPU(auth->status);
	}

	alg = L_LE16_TO_CPU(auth->algorithm);
	if (alg != MMPDU_AUTH_ALGO_FILS_SK &&
			alg != MMPDU_AUTH_ALGO_FILS_SK_PFS) {
		l_debug("invalid auth algorithm %u", auth->algorithm);
		return MMPDU_STATUS_CODE_UNSUP_AUTH_ALG;
	}

	ie_tlv_iter_init(&iter, auth->ies, (const uint8_t *) hdr + len -
				auth->ies);
	while (ie_tlv_iter_next(&iter)) {
		switch (iter.tag) {
		case IE_TYPE_FILS_NONCE:
			if (iter.len != FILS_NONCE_LEN)
				goto invalid_ies;

			anonce = iter.data;
			break;
		case IE_TYPE_FILS_SESSION:
			if (iter.len != FILS_SESSION_LEN)
				goto invalid_ies;

			session = iter.data;
			break;
		case IE_TYPE_FILS_WRAPPED_DATA:
			wrapped = iter.data;
			wrapped_len = iter.len;
			break;
		case IE_TYPE_RSN:
			if (rsne)
				goto invalid_ies;

			rsne = ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_MOBILITY_DOMAIN:
			if (mde)
				goto invalid_ies;

			mde = ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_FAST_BSS_TRANSITION:
			if (fte)
				goto invalid_ies;

			fte = ie_tlv_iter_get_data(&iter) - 2;
			break;

		default:
			continue;
		}
	}

	if (!anonce || !session || !wrapped) {
		l_debug("Auth did not include required IEs");
		goto invalid_ies;
	}

	if (mde)
		handshake_state_set_mde(fils->hs, mde);

	if (fte) {
		struct handshake_state *hs = fils->hs;
		uint32_t kck_len = handshake_state_get_kck_len(hs);
		struct ie_ft_info ft_info;

		if (ie_parse_fast_bss_transition_from_data(fte, fte[1] + 2,
					kck_len, &ft_info) < 0)
			goto invalid_ies;

		handshake_state_set_authenticator_fte(fils->hs, fte);
		handshake_state_set_kh_ids(fils->hs, ft_info.r0khid,
							ft_info.r0khid_len,
							ft_info.r1khid);
	}

	memcpy(fils->anonce, anonce, FILS_NONCE_LEN);

	if (erp_rx_packet(fils->erp, wrapped, wrapped_len) < 0)
		goto invalid_ies;

	return fils->get_oci(fils->user_data);


invalid_ies:
	return MMPDU_STATUS_CODE_INVALID_ELEMENT;
}

static int fils_rx_oci(struct auth_proto *driver)
{
	struct fils_sm *fils = l_container_of(driver, struct fils_sm, ap);

	return fils_derive_key_data(fils);
}

static int fils_rx_associate(struct auth_proto *driver, const uint8_t *frame,
				size_t len)
{
	struct fils_sm *fils = l_container_of(driver, struct fils_sm, ap);
	const struct mmpdu_header *hdr = (const struct mmpdu_header *) frame;
	const struct mmpdu_association_response *assoc = mmpdu_body(hdr);
	struct ie_tlv_iter iter;
	uint8_t key_rsc[8];
	const uint8_t *gtk = NULL;
	size_t gtk_len;
	uint8_t gtk_key_index;
	const uint8_t *igtk = NULL;
	size_t igtk_len;
	uint8_t igtk_key_index;
	const uint8_t *ap_key_auth = NULL;
	uint8_t expected_key_auth[48];
	bool sha384 = (fils->hs->akm_suite & (IE_RSN_AKM_SUITE_FILS_SHA384 |
			IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384));
	uint8_t data[44];
	uint8_t *ptr;

	if (assoc->status_code != 0)
		return L_CPU_TO_LE16(assoc->status_code);

	ie_tlv_iter_init(&iter, assoc->ies, (const uint8_t *) hdr + len -
				assoc->ies);

	while (ie_tlv_iter_next(&iter)) {
		switch (iter.tag) {
		case IE_TYPE_KEY_DELIVERY:
			if (iter.len < 8)
				goto invalid_ies;

			memcpy(key_rsc, iter.data, 8);

			gtk = handshake_util_find_gtk_kde(iter.data + 8,
								iter.len - 8,
								&gtk_len);
			if (!gtk)
				goto invalid_ies;

			gtk_key_index = bit_field(gtk[0], 0, 2);
			gtk += 2;
			gtk_len -= 2;

			if (!fils->hs->mfp)
				break;

			igtk = handshake_util_find_igtk_kde(iter.data + 8,
								iter.len - 8,
								&igtk_len);
			if (!igtk)
				goto invalid_ies;

			igtk_key_index = l_get_le16(igtk);
			igtk += 2;
			igtk_len -= 2;

			break;
		case IE_TYPE_FILS_KEY_CONFIRMATION:
			if (sha384 && iter.len != 48)
				goto invalid_ies;

			if (!sha384 && iter.len != 32)
				goto invalid_ies;

			ap_key_auth = iter.data;
			break;
		}
	}

	if (!ap_key_auth) {
		l_debug("Associate did not include KeyAuth IE");
		goto invalid_ies;
	}

	ptr = data;

	memcpy(ptr, fils->anonce, sizeof(fils->anonce));
	ptr += sizeof(fils->anonce);
	memcpy(ptr, fils->nonce, sizeof(fils->nonce));
	ptr += sizeof(fils->nonce);
	memcpy(ptr, fils->hs->aa, 6);
	ptr += 6;
	memcpy(ptr, fils->hs->spa, 6);
	ptr += 6;

	if (sha384)
		hmac_sha384(fils->ick, fils->ick_len, data, ptr - data,
				expected_key_auth, fils->ick_len);
	else
		hmac_sha256(fils->ick, fils->ick_len, data, ptr - data,
				expected_key_auth, fils->ick_len);

	if (memcmp(ap_key_auth, expected_key_auth, fils->ick_len)) {
		l_error("AP KeyAuth did not verify");
		return -EBADMSG;
	}

	handshake_state_set_pmk(fils->hs, fils->pmk, fils->pmk_len);
	handshake_state_set_pmkid(fils->hs, fils->pmkid);

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
	if (gtk)
		handshake_state_install_gtk(fils->hs, gtk_key_index, gtk,
						gtk_len, key_rsc, 6);

	if (igtk)
		handshake_state_install_igtk(fils->hs, igtk_key_index,
						igtk + 6, igtk_len - 6, igtk);
_Pragma("GCC diagnostic pop")

	handshake_state_set_ptk(fils->hs, fils->kek_and_tk, fils->kek_len + 16);
	handshake_state_install_ptk(fils->hs);

	return 0;

invalid_ies:
	return MMPDU_STATUS_CODE_INVALID_ELEMENT;
}

struct auth_proto *fils_sm_new(struct handshake_state *hs,
				fils_tx_authenticate_func_t auth,
				fils_tx_associate_func_t assoc,
				fils_get_oci_func_t get_oci,
				void *user_data)
{
	struct fils_sm *fils;

	fils = l_new(struct fils_sm, 1);

	fils->auth = auth;
	fils->assoc = assoc;
	fils->get_oci = get_oci;
	fils->user_data = user_data;
	fils->hs = hs;

	fils->ap.start = fils_start;
	fils->ap.free = fils_free;
	fils->ap.rx_oci = fils_rx_oci;
	fils->ap.rx_authenticate = fils_rx_authenticate;
	fils->ap.rx_associate = fils_rx_associate;

	fils->erp = erp_new(hs->erp_cache, fils_erp_tx_func, fils);

	return &fils->ap;
}
