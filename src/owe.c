/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "crypto.h"
#include "ie.h"
#include "handshake.h"
#include "owe.h"
#include "mpdu.h"

struct owe_sm {
	struct handshake_state *hs;
	const struct l_ecc_curve *curve;
	struct l_ecc_scalar *private;
	struct l_ecc_point *public_key;
	uint8_t retry;
	uint16_t group;
	const unsigned int *ecc_groups;

	owe_tx_authenticate_func_t auth_tx;
	owe_tx_associate_func_t assoc_tx;
	owe_complete_func_t complete;
	void *user_data;
};

static bool owe_reset(struct owe_sm *owe)
{
	/*
	 * Reset OWE with a different curve group and generate a new key pair
	 */
	if (owe->ecc_groups[owe->retry] == 0)
		return false;

	owe->group = owe->ecc_groups[owe->retry];
	owe->curve = l_ecc_curve_get_ike_group(owe->group);

	if (owe->private)
		l_ecc_scalar_free(owe->private);

	if (owe->public_key)
		l_ecc_point_free(owe->public_key);

	if (!l_ecdh_generate_key_pair(owe->curve, &owe->private,
					&owe->public_key))
		return false;

	return true;
}

struct owe_sm *owe_sm_new(struct handshake_state *hs,
				owe_tx_authenticate_func_t auth,
				owe_tx_associate_func_t assoc,
				owe_complete_func_t complete, void *user_data)
{
	struct owe_sm *owe = l_new(struct owe_sm, 1);

	owe->hs = hs;
	owe->auth_tx = auth;
	owe->assoc_tx = assoc;
	owe->user_data = user_data;
	owe->complete = complete;
	owe->ecc_groups = l_ecc_curve_get_supported_ike_groups();

	if (!owe_reset(owe)) {
		l_free(owe);
		return NULL;
	}

	return owe;
}

void owe_sm_free(struct owe_sm *owe)
{
	l_ecc_scalar_free(owe->private);
	l_ecc_point_free(owe->public_key);

	l_free(owe);
}

void owe_start(struct owe_sm *owe)
{
	owe->auth_tx(owe->user_data);
}

void owe_rx_authenticate(struct owe_sm *owe)
{
	uint8_t buf[5 + L_ECC_SCALAR_MAX_BYTES];
	struct iovec iov[3];
	int iov_elems = 0;
	size_t len;

	/*
	 * RFC 8110 Section 4.3
	 * A client wishing to do OWE MUST indicate the OWE AKM in the RSN
	 * element portion of the 802.11 association request ...
	 */
	iov[iov_elems].iov_base = owe->hs->supplicant_ie;
	iov[iov_elems].iov_len = owe->hs->supplicant_ie[1] + 2;
	iov_elems++;

	/*
	 * ... and MUST include a Diffie-Hellman Parameter element to its
	 * 802.11 association request.
	 */
	buf[0] = IE_TYPE_EXTENSION;
	buf[2] = IE_TYPE_OWE_DH_PARAM - 256;
	l_put_le16(owe->group, buf + 3); /* group */
	len = l_ecc_point_get_x(owe->public_key, buf + 5,
					L_ECC_SCALAR_MAX_BYTES);
	buf[1] = 3 + len; /* length */

	iov[iov_elems].iov_base = (void *) buf;
	iov[iov_elems].iov_len = buf[1] + 2;
	iov_elems++;

	owe->assoc_tx(iov, iov_elems, owe->user_data);
}

/*
 * RFC 8110 Section 4.4 Post Association
 */
static bool owe_compute_keys(struct owe_sm *owe, const void *public_key,
			size_t pub_len)
{
	struct l_ecc_scalar *shared_secret;
	uint8_t ss_buf[L_ECC_SCALAR_MAX_BYTES];
	uint8_t prk[L_ECC_SCALAR_MAX_BYTES];
	uint8_t pmk[L_ECC_SCALAR_MAX_BYTES];
	uint8_t pmkid[16];
	uint8_t key[L_ECC_SCALAR_MAX_BYTES + L_ECC_SCALAR_MAX_BYTES + 2];
	uint8_t *ptr = key;
	struct iovec iov[2];
	struct l_checksum *sha;
	struct l_ecc_point *other_public;
	ssize_t nbytes;
	enum l_checksum_type type;

	other_public = l_ecc_point_from_data(owe->curve,
						L_ECC_POINT_TYPE_COMPLIANT,
						public_key, pub_len);
	if (!other_public) {
		l_error("AP public key was not valid");
		return false;
	}

	if (!l_ecdh_generate_shared_secret(owe->private, other_public,
						&shared_secret)) {
		return false;
	}

	l_ecc_point_free(other_public);

	nbytes = l_ecc_scalar_get_data(shared_secret, ss_buf, sizeof(ss_buf));

	l_ecc_scalar_free(shared_secret);

	ptr += l_ecc_point_get_x(owe->public_key, ptr, sizeof(key));
	memcpy(ptr, public_key, nbytes);
	ptr += nbytes;
	l_put_le16(owe->group, ptr);
	ptr += 2;

	switch (owe->group) {
	case 19:
		type = L_CHECKSUM_SHA256;
		break;
	case 20:
		type = L_CHECKSUM_SHA384;
		break;
	default:
		goto failed;
	}

	/* prk = HKDF-extract(C | A | group, z) */
	if (!hkdf_extract(type, key, ptr - key, 1, prk, ss_buf, nbytes))
		goto failed;

	/* PMK = HKDF-expand(prk, "OWE Key Generation", n) */
	if (!hkdf_expand(type, prk, nbytes, "OWE Key Generation",
				strlen("OWE Key Generation"), pmk, nbytes))
		goto failed;

	sha = l_checksum_new(type);

	/* PMKID = Truncate-128(Hash(C | A)) */
	iov[0].iov_base = key; /* first nbytes of key are owe->public_key */
	iov[0].iov_len = nbytes;
	iov[1].iov_base = (void *) public_key;
	iov[1].iov_len = nbytes;

	l_checksum_updatev(sha, iov, 2);

	l_checksum_get_digest(sha, pmkid, 16);

	l_checksum_free(sha);

	handshake_state_set_pmk(owe->hs, pmk, nbytes);
	handshake_state_set_pmkid(owe->hs, pmkid);

	return true;

failed:
	memset(ss_buf, 0, sizeof(ss_buf));
	l_ecc_scalar_free(shared_secret);
	return false;
}

void owe_rx_associate(struct owe_sm *owe, const uint8_t *frame, size_t len)
{
	const struct mmpdu_header *mpdu = NULL;
	const struct mmpdu_association_response *body;
	struct ie_tlv_iter iter;
	size_t owe_dh_len = 0;
	const uint8_t *owe_dh = NULL;
	struct ie_rsn_info info;
	bool akm_found;
	const void *data;

	mpdu = mpdu_validate(frame, len);
	if (!mpdu) {
		l_error("could not process frame");
		goto owe_failed;
	}

	body = mmpdu_body(mpdu);

	if (body->status_code) {
		owe->complete(body->status_code, owe->user_data);
		return;
	}

	ie_tlv_iter_init(&iter, body->ies, (const uint8_t *) mpdu + len -
				body->ies);

	while (ie_tlv_iter_next(&iter)) {
		uint16_t tag = ie_tlv_iter_get_tag(&iter);

		data = ie_tlv_iter_get_data(&iter);
		len = ie_tlv_iter_get_length(&iter);

		switch (tag) {
		case IE_TYPE_OWE_DH_PARAM:
			owe_dh = data;
			owe_dh_len = len;

			break;
		case IE_TYPE_RSN:
			if (ie_parse_rsne(&iter, &info) < 0) {
				l_error("could not parse RSN IE");
				goto owe_failed;
			}

			/*
			 * RFC 8110 Section 4.2
			 * An AP agreeing to do OWE MUST include the OWE AKM in
			 * the RSN element portion of the 802.11 association
			 * response.
			 */
			if (info.akm_suites != IE_RSN_AKM_SUITE_OWE) {
				l_error("OWE AKM not included");
				goto owe_failed;
			}

			akm_found = true;

			break;
		default:
			continue;
		}
	}

	if (!owe_dh || owe_dh_len < 34 || !akm_found) {
		l_error("associate response did not include proper OWE IE's");
		goto owe_failed;
	}

	if (l_get_le16(owe_dh) != owe->group) {
		l_error("associate response contained unsupported group %u",
				l_get_le16(owe_dh));
		goto owe_failed;
	}

	if (!owe_compute_keys(owe, owe_dh + 2, owe_dh_len - 2)) {
		l_error("could not compute OWE keys");
		goto owe_failed;
	}

	owe->complete(0, owe->user_data);

	return;

owe_failed:
	owe->complete(MMPDU_REASON_CODE_UNSPECIFIED, owe->user_data);
}

bool owe_retry(struct owe_sm *owe)
{
	/* retry with another group, if possible */
	owe->retry++;

	if (!owe_reset(owe))
		return false;

	l_debug("OWE retrying with group %u", owe->group);

	owe_start(owe);

	return true;
}
