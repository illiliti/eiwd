/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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

#include "src/crypto.h"
#include "src/ie.h"
#include "src/handshake.h"
#include "src/owe.h"
#include "src/mpdu.h"
#include "src/auth-proto.h"

struct owe_sm {
	struct handshake_state *hs;
	const struct l_ecc_curve *curve;
	struct l_ecc_scalar *private;
	struct l_ecc_point *public_key;
	uint8_t retry;
	uint16_t group;
	const unsigned int *ecc_groups;
};

static bool owe_reset(struct owe_sm *owe)
{
	if (owe->hs->force_default_owe_group) {
		if (owe->retry != 0) {
			l_warn("Forced default OWE group but was rejected!");
			return false;
		}

		l_debug("Forcing default OWE group 19");

		owe->retry++;
		owe->group = 19;

		goto get_curve;
	}

	/*
	 * Reset OWE with a different curve group and generate a new key pair
	 */
	if (owe->ecc_groups[owe->retry] == 0)
		return false;

	owe->group = owe->ecc_groups[owe->retry];

get_curve:
	owe->curve = l_ecc_curve_from_ike_group(owe->group);

	if (owe->private)
		l_ecc_scalar_free(owe->private);

	if (owe->public_key)
		l_ecc_point_free(owe->public_key);

	if (!l_ecdh_generate_key_pair(owe->curve, &owe->private,
					&owe->public_key))
		return false;

	return true;
}

void owe_sm_free(struct owe_sm *owe)
{
	l_ecc_scalar_free(owe->private);
	l_ecc_point_free(owe->public_key);

	l_free(owe);
}

void owe_build_dh_ie(struct owe_sm *owe, uint8_t *buf, size_t *len_out)
{
	/*
	 * A client wishing to do OWE ... MUST include a Diffie-Hellman
	 * Parameter element to its 802.11 association request.
	 */
	buf[0] = IE_TYPE_EXTENSION;
	buf[2] = IE_TYPE_OWE_DH_PARAM - 256;
	l_put_le16(owe->group, buf + 3); /* group */
	*len_out = l_ecc_point_get_x(owe->public_key, buf + 5,
					L_ECC_SCALAR_MAX_BYTES);
	buf[1] = 3 + *len_out; /* length */

	*len_out += 5;
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
		l_ecc_point_free(other_public);
		return false;
	}

	l_ecc_point_free(other_public);

	nbytes = l_ecc_scalar_get_data(shared_secret, ss_buf, sizeof(ss_buf));
	l_ecc_scalar_free(shared_secret);

	if (nbytes < 0)
		return false;

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
	if (!hkdf_expand(type, prk, nbytes, "OWE Key Generation", pmk, nbytes))
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
	return false;
}

bool owe_next_group(struct owe_sm *owe)
{
	/* retry with another group, if possible */
	owe->retry++;

	if (!owe_reset(owe))
		return false;

	return true;
}

int owe_process_dh_ie(struct owe_sm *owe, const uint8_t *dh, size_t len)
{
	if (!dh || len < 34) {
		l_error("associate response did not include proper OWE IE's");
		goto invalid_ies;
	}

	if (l_get_le16(dh) != owe->group) {
		l_error("associate response contained unsupported group %u",
				l_get_le16(dh));
		return -EBADMSG;
	}

	if (!owe_compute_keys(owe, dh + 2, len - 2)) {
		l_error("could not compute OWE keys");
		return -EBADMSG;
	}

	return 0;

invalid_ies:
	return MMPDU_STATUS_CODE_INVALID_ELEMENT;
}

struct owe_sm *owe_sm_new(struct handshake_state *hs)
{
	struct owe_sm *owe = l_new(struct owe_sm, 1);

	owe->hs = hs;
	owe->ecc_groups = l_ecc_supported_ike_groups();

	if (!owe_reset(owe)) {
		l_free(owe);
		return NULL;
	}

	return owe;
}
