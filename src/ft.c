/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
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

#include "src/ie.h"
#include "src/handshake.h"
#include "src/crypto.h"
#include "src/ft.h"
#include "src/mpdu.h"
#include "src/auth-proto.h"

struct ft_sm {
	struct auth_proto ap;
	struct handshake_state *hs;

	ft_tx_authenticate_func_t tx_auth;
	ft_tx_associate_func_t tx_assoc;

	void *user_data;
};

/*
 * Calculate the MIC field of the FTE and write it directly to that FTE,
 * assuming it was all zeros before.  See 12.8.4 and 12.8.5.
 */
static bool ft_calculate_fte_mic(struct handshake_state *hs, uint8_t seq_num,
				const uint8_t *rsne, const uint8_t *fte,
				const uint8_t *ric, uint8_t *out_mic)
{
	struct iovec iov[10];
	int iov_elems = 0;
	struct l_checksum *checksum;
	const uint8_t *kck = handshake_state_get_kck(hs);
	size_t kck_len = handshake_state_get_kck_len(hs);
	uint8_t zero_mic[24] = {};

	iov[iov_elems].iov_base = hs->spa;
	iov[iov_elems++].iov_len = 6;

	iov[iov_elems].iov_base = hs->aa;
	iov[iov_elems++].iov_len = 6;

	iov[iov_elems].iov_base = &seq_num;
	iov[iov_elems++].iov_len = 1;

	if (rsne) {
		iov[iov_elems].iov_base = (void *) rsne;
		iov[iov_elems++].iov_len = rsne[1] + 2;
	}

	iov[iov_elems].iov_base = hs->mde;
	iov[iov_elems++].iov_len = hs->mde[1] + 2;

	if (fte) {
		iov[iov_elems].iov_base = (void *) fte;
		iov[iov_elems++].iov_len = 4;

		iov[iov_elems].iov_base = zero_mic;
		iov[iov_elems++].iov_len = kck_len;

		iov[iov_elems].iov_base = (void *) (fte + 4 + kck_len);
		iov[iov_elems++].iov_len = fte[1] + 2 - 4 - kck_len;
	}

	if (ric) {
		iov[iov_elems].iov_base = (void *) ric;
		iov[iov_elems++].iov_len = ric[1] + 2;
	}

	if (kck_len == 16)
		checksum = l_checksum_new_cmac_aes(kck, kck_len);
	else
		checksum = l_checksum_new_hmac(L_CHECKSUM_SHA384, kck, kck_len);

	if (!checksum)
		return false;

	l_checksum_updatev(checksum, iov, iov_elems);
	l_checksum_get_digest(checksum, out_mic, kck_len);
	l_checksum_free(checksum);

	return true;
}

/*
 * Validate the FC, the addresses, Auth Type and authentication sequence
 * number of an FT Authentication Response frame, return status code, and
 * the start of the IE array (RSN, MD, FT, TI and RIC).
 * See 8.3.3.1 for the header and 8.3.3.11 for the body format.
 */
static bool ft_parse_authentication_resp_frame(const uint8_t *data, size_t len,
				const uint8_t *addr1, const uint8_t *addr2,
				const uint8_t *addr3, uint16_t auth_seq,
				uint16_t *out_status, const uint8_t **out_ies,
				size_t *out_ies_len)
{
	const uint16_t frame_type = 0x00b0;
	uint16_t status = 0;

	if (len < 30)
		return false;

	/* Check FC == Management Frame -> Authentication */
	if (l_get_le16(data + 0) != frame_type)
		return false;

	if (memcmp(data + 4, addr1, 6))
		return false;
	if (memcmp(data + 10, addr2, 6))
		return false;
	if (memcmp(data + 16, addr3, 6))
		return false;

	/* Check Authentication algorithm number is FT (2) */
	if (l_get_le16(data + 24) != 2)
		return false;

	if (l_get_le16(data + 26) != auth_seq)
		return false;

	if (auth_seq == 2 || auth_seq == 4)
		status = l_get_le16(data + 28);

	if (out_status)
		*out_status = status;

	if (status == 0 && out_ies) {
		*out_ies = data + 28;
		*out_ies_len = len - 28;
	}

	return true;
}

static bool ft_parse_action_resp_frame(const uint8_t *frame, size_t frame_len,
					const uint8_t *spa, const uint8_t *aa,
					uint16_t *out_status,
					const uint8_t **out_ies,
					size_t *out_ies_len)
{
	uint16_t status = 0;

	/* Category FT */
	if (frame[0] != 6)
		return false;

	/* FT Action */
	if (frame[1] != 2)
		return false;

	if (memcmp(frame + 2, spa, 6))
		return false;
	if (memcmp(frame + 8, aa, 6))
		return false;

	status = l_get_le16(frame + 14);

	if (out_status)
		*out_status = status;

	if (status == 0 && out_ies) {
		*out_ies = frame + 16;
		*out_ies_len = frame_len - 16;
	}

	return true;
}

static bool ft_parse_associate_resp_frame(const uint8_t *frame, size_t frame_len,
				uint16_t *out_status, const uint8_t **rsne,
				const uint8_t **mde, const uint8_t **fte)
{
	const struct mmpdu_header *mpdu;
	const struct mmpdu_association_response *body;
	struct ie_tlv_iter iter;

	mpdu = mpdu_validate(frame, frame_len);
	if (!mpdu)
		return false;

	body = mmpdu_body(mpdu);

	ie_tlv_iter_init(&iter, body->ies, (const uint8_t *) mpdu + frame_len -
				body->ies);

	while (ie_tlv_iter_next(&iter)) {
		switch (ie_tlv_iter_get_tag(&iter)) {
		case IE_TYPE_RSN:
			if (*rsne)
				return false;

			*rsne = ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_MOBILITY_DOMAIN:
			if (*mde)
				return false;

			*mde = ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_FAST_BSS_TRANSITION:
			if (*fte)
				return false;

			*fte = ie_tlv_iter_get_data(&iter) - 2;
			break;
		}
	}

	*out_status = L_LE16_TO_CPU(body->status_code);

	return true;
}

static int ft_tx_reassociate(struct ft_sm *ft)
{
	struct iovec iov[3];
	int iov_elems = 0;
	struct handshake_state *hs = ft->hs;
	uint32_t kck_len = handshake_state_get_kck_len(hs);
	bool is_rsn = hs->supplicant_ie != NULL;
	uint8_t *rsne = NULL;

	if (is_rsn) {
		struct ie_rsn_info rsn_info;

		/*
		 * Rebuild the RSNE to include the PMKR1Name and append
		 * MDE + FTE.
		 *
		 * 12.8.4: "If present, the RSNE shall be set as follows:
		 * — Version field shall be set to 1.
		 * — PMKID Count field shall be set to 1.
		 * — PMKID field shall contain the PMKR1Name.
		 * — All other fields shall be as specified in 8.4.2.27
		 *   and 11.5.3."
		 */
		if (ie_parse_rsne_from_data(hs->supplicant_ie,
						hs->supplicant_ie[1] + 2,
						&rsn_info) < 0)
			goto error;

		rsn_info.num_pmkids = 1;
		rsn_info.pmkids = hs->pmk_r1_name;

		rsne = alloca(256);
		ie_build_rsne(&rsn_info, rsne);

		iov[iov_elems].iov_base = rsne;
		iov[iov_elems].iov_len = rsne[1] + 2;
		iov_elems += 1;
	}

	/* The MDE advertised by the BSS must be passed verbatim */
	iov[iov_elems].iov_base = (void *) hs->mde;
	iov[iov_elems].iov_len = hs->mde[1] + 2;
	iov_elems += 1;

	if (is_rsn) {
		struct ie_ft_info ft_info;
		uint8_t *fte;

		/*
		 * 12.8.4: "If present, the FTE shall be set as follows:
		 * — ANonce, SNonce, R0KH-ID, and R1KH-ID shall be set to
		 *   the values contained in the second message of this
		 *   sequence.
		 * — The Element Count field of the MIC Control field shall
		 *   be set to the number of elements protected in this
		 *   frame (variable).
		 * [...]
		 * — All other fields shall be set to 0."
		 */

		memset(&ft_info, 0, sizeof(ft_info));

		ft_info.mic_element_count = 3;
		memcpy(ft_info.r0khid, hs->r0khid, hs->r0khid_len);
		ft_info.r0khid_len = hs->r0khid_len;
		memcpy(ft_info.r1khid, hs->r1khid, 6);
		ft_info.r1khid_present = true;
		memcpy(ft_info.anonce, hs->anonce, 32);
		memcpy(ft_info.snonce, hs->snonce, 32);

		fte = alloca(256);
		ie_build_fast_bss_transition(&ft_info, kck_len, fte);

		if (!ft_calculate_fte_mic(hs, 5, rsne, fte, NULL, ft_info.mic))
			goto error;

		/* Rebuild the FT IE now with the MIC included */
		ie_build_fast_bss_transition(&ft_info, kck_len, fte);

		iov[iov_elems].iov_base = fte;
		iov[iov_elems].iov_len = fte[1] + 2;
		iov_elems += 1;
	}

	ft->tx_assoc(iov, iov_elems, ft->user_data);

	return 0;

error:
	return -EINVAL;
}

static int ft_parse_ies(const uint8_t *ies, size_t ies_len,
			const uint8_t **rsne_out, const uint8_t **mde_out,
			const uint8_t **fte_out)
{
	struct ie_tlv_iter iter;
	const uint8_t *rsne = NULL;
	const uint8_t *mde = NULL;
	const uint8_t *fte = NULL;

	ie_tlv_iter_init(&iter, ies, ies_len);

	while (ie_tlv_iter_next(&iter)) {
		switch (ie_tlv_iter_get_tag(&iter)) {
		case IE_TYPE_RSN:
			if (rsne)
				goto ft_error;

			rsne = ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_MOBILITY_DOMAIN:
			if (mde)
				goto ft_error;

			mde = ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_FAST_BSS_TRANSITION:
			if (fte)
				goto ft_error;

			fte = ie_tlv_iter_get_data(&iter) - 2;
			break;
		}
	}

	if (rsne_out)
		*rsne_out = rsne;

	if (mde_out)
		*mde_out = mde;

	if (fte_out)
		*fte_out = fte;

	return 0;

ft_error:
	return -EINVAL;
}

static bool ft_verify_rsne(const uint8_t *rsne, const uint8_t *pmk_r0_name,
				const uint8_t *authenticator_ie)
{
	/*
	 * In an RSN, check for an RSNE containing the PMK-R0-Name and
	 * the remaining fields same as in the advertised RSNE.
	 *
	 * 12.8.3: "The RSNE shall be present only if dot11RSNAActivated
	 * is true. If present, the RSNE shall be set as follows:
	 * — Version field shall be set to 1.
	 * — PMKID Count field shall be set to 1.
	 * — PMKID List field shall be set to the value contained in the
	 *   first message of this sequence.
	 * — All other fields shall be identical to the contents of the
	 *   RSNE advertised by the AP in Beacon and Probe Response frames."
	 */

	struct ie_rsn_info msg2_rsne;

	if (!rsne)
		return false;

	if (ie_parse_rsne_from_data(rsne, rsne[1] + 2,
						&msg2_rsne) < 0)
		return false;

	if (msg2_rsne.num_pmkids != 1 ||
				memcmp(msg2_rsne.pmkids, pmk_r0_name, 16))
		return false;

	if (!handshake_util_ap_ie_matches(rsne, authenticator_ie, false))
		return false;

	return true;
}

static bool ft_parse_fte(struct handshake_state *hs,
				const uint8_t *snonce,
				const uint8_t *fte,
				struct ie_ft_info *ft_info)
{
	/*
	 * In an RSN, check for an FT IE with the same R0KH-ID and the same
	 * SNonce that we sent, and check that the R1KH-ID and the ANonce
	 * are present.  Use them to generate new PMK-R1, PMK-R1-Name and PTK
	 * in handshake.c.
	 *
	 * 12.8.3: "The FTE shall be present only if dot11RSNAActivated is
	 * true. If present, the FTE shall be set as follows:
	 * — R0KH-ID shall be identical to the R0KH-ID provided by the FTO
	 *   in the first message.
	 * — R1KH-ID shall be set to the R1KH-ID of the target AP, from
	 *   dot11FTR1KeyHolderID.
	 * — ANonce shall be set to a value chosen randomly by the target AP,
	 *   following the recommendations of 11.6.5.
	 * — SNonce shall be set to the value contained in the first message
	 *   of this sequence.
	 * — All other fields shall be set to 0."
	 */
	uint8_t zeros[24] = {};
	uint32_t kck_len = handshake_state_get_kck_len(hs);

	if (!fte)
		return false;

	if (ie_parse_fast_bss_transition_from_data(fte, fte[1] + 2,
					kck_len, ft_info) < 0)
		return false;

	if (ft_info->mic_element_count != 0 ||
			memcmp(ft_info->mic, zeros, kck_len))
		return false;

	if (hs->r0khid_len != ft_info->r0khid_len ||
			memcmp(hs->r0khid, ft_info->r0khid,
				hs->r0khid_len) ||
			!ft_info->r1khid_present)
		return false;

	if (memcmp(ft_info->snonce, snonce, 32))
		return false;

	return true;
}

static int ft_process_ies(struct handshake_state *hs, const uint8_t *ies,
			size_t ies_len)
{
	const uint8_t *rsne = NULL;
	const uint8_t *mde = NULL;
	const uint8_t *fte = NULL;
	bool is_rsn;

	/* Check 802.11r IEs */
	if (!ies)
		goto ft_error;

	if (ft_parse_ies(ies, ies_len, &rsne, &mde, &fte) < 0)
		goto ft_error;

	is_rsn = hs->supplicant_ie != NULL;

	if (is_rsn) {
		if (!ft_verify_rsne(rsne, hs->pmk_r0_name,
					hs->authenticator_ie))
			goto ft_error;
	} else if (rsne)
		goto ft_error;

	/*
	 * Check for an MD IE identical to the one we sent in message 1
	 *
	 * 12.8.3: "The MDE shall contain the MDID and FT Capability and
	 * Policy fields. This element shall be the same as the MDE
	 * advertised by the target AP in Beacon and Probe Response frames."
	 */
	if (!mde || memcmp(hs->mde, mde, hs->mde[1] + 2))
		goto ft_error;

	if (is_rsn) {
		struct ie_ft_info ft_info;

		if (!ft_parse_fte(hs, hs->snonce, fte, &ft_info))
			goto ft_error;

		handshake_state_set_fte(hs, fte);

		handshake_state_set_anonce(hs, ft_info.anonce);

		handshake_state_set_kh_ids(hs, ft_info.r0khid,
						ft_info.r0khid_len,
						ft_info.r1khid);

		handshake_state_derive_ptk(hs);
	} else if (fte)
		goto ft_error;

	return 0;

ft_error:
	return -EBADMSG;
}

static int ft_rx_action(struct auth_proto *ap, const uint8_t *frame,
				size_t frame_len)
{
	struct ft_sm *ft = l_container_of(ap, struct ft_sm, ap);
	uint16_t status_code = MMPDU_STATUS_CODE_UNSPECIFIED;
	const uint8_t *ies = NULL;
	size_t ies_len;
	int ret;

	if (!ft_parse_action_resp_frame(frame, frame_len, ft->hs->spa,
						ft->hs->aa, &status_code,
						&ies, &ies_len))
		return -EBADMSG;

	/* AP Rejected the authenticate / associate */
	if (status_code != 0)
		goto auth_error;

	ret = ft_process_ies(ft->hs, ies, ies_len);
	if (ret < 0)
		goto auth_error;

	return ft_tx_reassociate(ft);

auth_error:
	return (int)status_code;
}

static int ft_rx_authenticate(struct auth_proto *ap, const uint8_t *frame,
				size_t frame_len)
{
	struct ft_sm *ft = l_container_of(ap, struct ft_sm, ap);
	uint16_t status_code = MMPDU_STATUS_CODE_UNSPECIFIED;
	const uint8_t *ies = NULL;
	size_t ies_len;
	int ret;

	/*
	 * Parse the Authentication Response and validate the contents
	 * according to 12.5.2 / 12.5.4: RSN or non-RSN Over-the-air
	 * FT Protocol.
	 */
	if (!ft_parse_authentication_resp_frame(frame, frame_len, ft->hs->spa,
					ft->hs->aa, ft->hs->aa, 2, &status_code,
					&ies, &ies_len))
			goto auth_error;

	/* AP Rejected the authenticate / associate */
	if (status_code != 0)
		goto auth_error;

	ret = ft_process_ies(ft->hs, ies, ies_len);
	if (ret < 0)
		goto auth_error;

	return ft_tx_reassociate(ft);

auth_error:
	return (int)status_code;
}

static int ft_rx_associate(struct auth_proto *ap, const uint8_t *frame,
				size_t frame_len)
{
	struct ft_sm *ft = l_container_of(ap, struct ft_sm, ap);
	struct handshake_state *hs = ft->hs;
	uint32_t kck_len = handshake_state_get_kck_len(hs);
	const uint8_t *rsne = NULL;
	const uint8_t *mde = NULL;
	const uint8_t *fte = NULL;
	const uint8_t *sent_mde = hs->mde;
	bool is_rsn = hs->supplicant_ie != NULL;
	uint16_t out_status;

	if (!ft_parse_associate_resp_frame(frame, frame_len, &out_status, &rsne,
					&mde, &fte))
		return -EBADMSG;

	/*
	 * During a transition in an RSN, check for an RSNE containing the
	 * PMK-R1-Name and the remaining fields same as in the advertised
	 * RSNE.
	 *
	 * 12.8.5: "The RSNE shall be present only if dot11RSNAActivated is
	 * true. If present, the RSNE shall be set as follows:
	 * — Version field shall be set to 1.
	 * — PMKID Count field shall be set to 1.
	 * — PMKID field shall contain the PMKR1Name
	 * — All other fields shall be identical to the contents of the RSNE
	 *   advertised by the target AP in Beacon and Probe Response frames."
	 */
	if (is_rsn) {
		struct ie_rsn_info msg4_rsne;

		if (!rsne)
			return -EBADMSG;

		if (ie_parse_rsne_from_data(rsne, rsne[1] + 2,
						&msg4_rsne) < 0)
			return -EBADMSG;

		if (msg4_rsne.num_pmkids != 1 ||
				memcmp(msg4_rsne.pmkids, hs->pmk_r1_name, 16))
			return -EBADMSG;

		if (!handshake_util_ap_ie_matches(rsne, hs->authenticator_ie,
							false))
			return -EBADMSG;
	} else {
		if (rsne)
			return -EBADMSG;
	}

	/* An MD IE identical to the one we sent must be present */
	if (sent_mde && (!mde || memcmp(sent_mde, mde, sent_mde[1] + 2)))
		return -EBADMSG;

	/*
	 * An FT IE is required in an initial mobility domain
	 * association and re-associations in an RSN but not present
	 * in a non-RSN (12.4.2 vs. 12.4.3).
	 */
	if (sent_mde && is_rsn && !fte)
		return -EBADMSG;
	if (!(sent_mde && is_rsn) && fte)
		return -EBADMSG;

	if (fte) {
		struct ie_ft_info ft_info;
		uint8_t mic[24];

		if (ie_parse_fast_bss_transition_from_data(fte, fte[1] + 2,
						kck_len, &ft_info) < 0)
			return -EBADMSG;

		/*
		 * In an RSN, check for an FT IE with the same
		 * R0KH-ID, R1KH-ID, ANonce and SNonce that we
		 * received in message 2, MIC Element Count
		 * of 6 and the correct MIC.
		 */

		if (!ft_calculate_fte_mic(hs, 6, rsne, fte, NULL, mic))
			return -EBADMSG;

		if (ft_info.mic_element_count != 3 ||
				memcmp(ft_info.mic, mic, kck_len))
			return -EBADMSG;

		if (hs->r0khid_len != ft_info.r0khid_len ||
				memcmp(hs->r0khid, ft_info.r0khid,
					hs->r0khid_len) ||
				!ft_info.r1khid_present ||
				memcmp(hs->r1khid, ft_info.r1khid, 6))
			return -EBADMSG;

		if (memcmp(ft_info.anonce, hs->anonce, 32))
			return -EBADMSG;

		if (memcmp(ft_info.snonce, hs->snonce, 32))
			return -EBADMSG;

		if (ft_info.gtk_len) {
			uint8_t gtk[32];

			if (!handshake_decode_fte_key(hs, ft_info.gtk,
							ft_info.gtk_len,
							gtk))
				return -EBADMSG;

			if (ft_info.gtk_rsc[6] != 0x00 ||
					ft_info.gtk_rsc[7] != 0x00)
				return -EBADMSG;

			handshake_state_install_gtk(hs, ft_info.gtk_key_id,
							gtk, ft_info.gtk_len,
							ft_info.gtk_rsc, 6);
		}

		if (ft_info.igtk_len) {
			uint8_t igtk[16];

			if (!handshake_decode_fte_key(hs, ft_info.igtk,
						ft_info.igtk_len, igtk))
				return -EBADMSG;

			handshake_state_install_igtk(hs, ft_info.igtk_key_id,
						igtk, ft_info.igtk_len,
						ft_info.igtk_ipn);
		}

		handshake_state_install_ptk(ft->hs);
	}

	return 0;
}

static void ft_sm_free(struct auth_proto *ap)
{
	struct ft_sm *ft = l_container_of(ap, struct ft_sm, ap);

	l_free(ft);
}

bool ft_build_authenticate_ies(struct handshake_state *hs,
				const uint8_t *new_snonce, uint8_t *buf,
				size_t *len)
{
	uint32_t kck_len = handshake_state_get_kck_len(hs);
	bool is_rsn = hs->supplicant_ie != NULL;
	uint8_t *ptr = buf;

	if (is_rsn) {
		struct ie_rsn_info rsn_info;

		/*
		 * Rebuild the RSNE to include the PMKR0Name and append
		 * MDE + FTE.
		 *
		 * 12.8.2: "If present, the RSNE shall be set as follows:
		 * — Version field shall be set to 1.
		 * — PMKID Count field shall be set to 1.
		 * — PMKID List field shall contain the PMKR0Name.
		 * — All other fields shall be as specified in 8.4.2.27
		 *   and 11.5.3."
		 */
		if (ie_parse_rsne_from_data(hs->supplicant_ie,
						hs->supplicant_ie[1] + 2,
						&rsn_info) < 0)
			return false;

		rsn_info.num_pmkids = 1;
		rsn_info.pmkids = hs->pmk_r0_name;

		ie_build_rsne(&rsn_info, ptr);
		ptr += ptr[1] + 2;
	}

	/* The MDE advertised by the BSS must be passed verbatim */
	ptr[0] = IE_TYPE_MOBILITY_DOMAIN;
	ptr[1] = 3;
	memcpy(ptr + 2, hs->mde + 2, 3);
	ptr += 5;

	if (is_rsn) {
		struct ie_ft_info ft_info;

		/*
		 * 12.8.2: "If present, the FTE shall be set as follows:
		 * — R0KH-ID shall be the value of R0KH-ID obtained by the
		 *   FTO during its FT initial mobility domain association
		 *   exchange.
		 * — SNonce shall be set to a value chosen randomly by the
		 *   FTO, following the recommendations of 11.6.5.
		 * — All other fields shall be set to 0."
		 */

		memset(&ft_info, 0, sizeof(ft_info));

		memcpy(ft_info.r0khid, hs->r0khid, hs->r0khid_len);
		ft_info.r0khid_len = hs->r0khid_len;

		memcpy(ft_info.snonce, new_snonce, 32);

		ie_build_fast_bss_transition(&ft_info, kck_len, ptr);

		ptr += ptr[1] + 2;
	}

	if (len)
		*len = ptr - buf;

	return true;
}

static bool ft_start(struct auth_proto *ap)
{
	struct ft_sm *ft = l_container_of(ap, struct ft_sm, ap);
	struct handshake_state *hs = ft->hs;
	struct iovec iov;
	uint8_t buf[512];
	size_t len;

	if (!ft_build_authenticate_ies(hs, hs->snonce, buf, &len))
		return false;

	iov.iov_base = buf;
	iov.iov_len = len;

	ft->tx_auth(&iov, 1, ft->user_data);

	return true;
}

static struct auth_proto *ft_sm_new(struct handshake_state *hs,
				ft_tx_authenticate_func_t tx_auth,
				ft_tx_associate_func_t tx_assoc,
				bool over_air,
				void *user_data)
{
	struct ft_sm *ft = l_new(struct ft_sm, 1);

	ft->tx_auth = tx_auth;
	ft->tx_assoc = tx_assoc;
	ft->hs = hs;
	ft->user_data = user_data;

	ft->ap.rx_authenticate = (over_air) ? ft_rx_authenticate : ft_rx_action;
	ft->ap.rx_associate = ft_rx_associate;
	ft->ap.start = ft_start;
	ft->ap.free = ft_sm_free;

	return &ft->ap;
}

struct auth_proto *ft_over_air_sm_new(struct handshake_state *hs,
				ft_tx_authenticate_func_t tx_auth,
				ft_tx_associate_func_t tx_assoc,
				void *user_data)
{
	return ft_sm_new(hs, tx_auth, tx_assoc, true, user_data);
}

struct auth_proto *ft_over_ds_sm_new(struct handshake_state *hs,
				ft_tx_authenticate_func_t tx_auth,
				ft_tx_associate_func_t tx_assoc,
				void *user_data)
{
	return ft_sm_new(hs, tx_auth, tx_assoc, false, user_data);
}
