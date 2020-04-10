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

#include "src/missing.h"
#include "src/util.h"
#include "src/ie.h"
#include "src/handshake.h"
#include "src/crypto.h"
#include "src/mpdu.h"
#include "src/sae.h"
#include "src/auth-proto.h"

#define SAE_RETRANSMIT_TIMEOUT	2
#define SAE_SYNC_MAX		3

enum sae_state {
	SAE_STATE_NOTHING = 0,
	SAE_STATE_COMMITTED = 1,
	SAE_STATE_CONFIRMED = 2,
	SAE_STATE_ACCEPTED = 3,
};

struct sae_sm {
	struct auth_proto ap;
	struct handshake_state *handshake;
	struct l_ecc_point *pwe;
	enum sae_state state;
	const struct l_ecc_curve *curve;
	unsigned int group;
	uint8_t group_retry;
	const unsigned int *ecc_groups;
	struct l_ecc_scalar *rand;
	struct l_ecc_scalar *scalar;
	struct l_ecc_scalar *p_scalar;
	struct l_ecc_point *element;
	struct l_ecc_point *p_element;
	uint16_t send_confirm;
	uint8_t kck[32];
	uint8_t pmk[32];
	uint8_t pmkid[16];
	uint8_t *token;
	size_t token_len;
	/* number of state resyncs that have occurred */
	uint16_t sync;
	/* number of SAE confirm messages that have been sent */
	uint16_t sc;
	/* received value of the send-confirm counter */
	uint16_t rc;
	/* remote peer */
	uint8_t peer[6];

	sae_tx_authenticate_func_t tx_auth;
	sae_tx_associate_func_t tx_assoc;
	void *user_data;
};

static bool sae_pwd_seed(const uint8_t *addr1, const uint8_t *addr2,
				uint8_t *base, size_t base_len,
				uint8_t counter, uint8_t *out)
{
	uint8_t key[12];

	if (memcmp(addr1, addr2, 6) > 0) {
		memcpy(key, addr1, 6);
		memcpy(key + 6, addr2, 6);
	} else {
		memcpy(key, addr2, 6);
		memcpy(key + 6, addr1, 6);
	}

	return hkdf_extract(L_CHECKSUM_SHA256, key, 12, 2, out, base, base_len,
					&counter, (size_t) 1);
}

static struct l_ecc_scalar *sae_pwd_value(const struct l_ecc_curve *curve,
						uint8_t *pwd_seed)
{
	uint8_t pwd_value[L_ECC_SCALAR_MAX_BYTES];
	uint8_t prime[L_ECC_SCALAR_MAX_BYTES];
	ssize_t len;
	struct l_ecc_scalar *p = l_ecc_curve_get_prime(curve);

	len = l_ecc_scalar_get_data(p, prime, sizeof(prime));

	l_ecc_scalar_free(p);

	if (!kdf_sha256(pwd_seed, 32, "SAE Hunting and Pecking",
			strlen("SAE Hunting and Pecking"), prime, len,
			pwd_value, len))
		return NULL;

	return l_ecc_scalar_new(curve, pwd_value, sizeof(pwd_value));
}

/* IEEE 802.11-2016 - Section 12.4.2 Assumptions on SAE */
static bool sae_cn(const uint8_t *kck, uint16_t send_confirm,
			struct l_ecc_scalar *scalar1,
			struct l_ecc_point *element1,
			struct l_ecc_scalar *scalar2,
			struct l_ecc_point *element2,
			uint8_t *confirm)
{
	uint8_t s1[L_ECC_SCALAR_MAX_BYTES];
	uint8_t s2[L_ECC_SCALAR_MAX_BYTES];
	uint8_t e1[L_ECC_POINT_MAX_BYTES];
	uint8_t e2[L_ECC_POINT_MAX_BYTES];
	struct l_checksum *hmac;
	struct iovec iov[5];
	int ret;

	hmac = l_checksum_new_hmac(L_CHECKSUM_SHA256, kck, 32);
	if (!hmac)
		return false;

	iov[0].iov_base = &send_confirm;
	iov[0].iov_len = 2;
	iov[1].iov_base = (void *) s1;
	iov[1].iov_len = l_ecc_scalar_get_data(scalar1, s1, sizeof(s1));
	iov[2].iov_base = (void *) e1;
	iov[2].iov_len = l_ecc_point_get_data(element1, e1, sizeof(e1));
	iov[3].iov_base = (void *) s2;
	iov[3].iov_len = l_ecc_scalar_get_data(scalar2, s2, sizeof(s2));
	iov[4].iov_base = (void *) e2;
	iov[4].iov_len = l_ecc_point_get_data(element2, e2, sizeof(e2));

	l_checksum_updatev(hmac, iov, 5);

	ret = l_checksum_get_digest(hmac, confirm, 32);

	l_checksum_free(hmac);

	return (ret == 32);
}

static void sae_reject_authentication(struct sae_sm *sm, uint16_t reason)
{
	uint8_t reject[6];
	uint8_t *ptr = reject;

	/* transaction */
	l_put_u16(1, ptr);
	ptr += 2;
	/* status success */
	l_put_u16(reason, ptr);
	ptr += 2;

	if (reason == MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP) {
		l_put_u16(sm->group, ptr);
		ptr += 2;
	}

	sm->tx_auth(reject, ptr - reject, sm->user_data);
}

static struct l_ecc_scalar *sae_new_residue(const struct l_ecc_curve *curve,
						bool residue)
{
	struct l_ecc_scalar *s = l_ecc_scalar_new_random(curve);

	while (l_ecc_scalar_legendre(s) != ((residue) ? -1 : 1)) {
		l_ecc_scalar_free(s);
		s = l_ecc_scalar_new_random(curve);
	}

	return s;
}

static bool sae_is_quadradic_residue(const struct l_ecc_curve *curve,
						struct l_ecc_scalar *value,
						struct l_ecc_scalar *qr,
						struct l_ecc_scalar *qnr)
{
	uint64_t rbuf[L_ECC_MAX_DIGITS];
	struct l_ecc_scalar *y_sqr = l_ecc_scalar_new(curve, NULL, 0);
	struct l_ecc_scalar *r = l_ecc_scalar_new_random(curve);
	struct l_ecc_scalar *num = l_ecc_scalar_new(curve, NULL, 0);
	size_t bytes;

	l_ecc_scalar_sum_x(y_sqr, value);

	l_ecc_scalar_multiply(num, y_sqr, r);
	l_ecc_scalar_multiply(num, num, r);

	l_ecc_scalar_free(y_sqr);

	bytes = l_ecc_scalar_get_data(r, rbuf, sizeof(rbuf));
	l_ecc_scalar_free(r);

	if (bytes <= 0) {
		l_ecc_scalar_free(num);
		return false;
	}

	if (rbuf[bytes / 8 - 1] & 1) {
		l_ecc_scalar_multiply(num, num, qr);

		if (l_ecc_scalar_legendre(num) == -1) {
			l_ecc_scalar_free(num);
			return true;
		}
	} else {
		l_ecc_scalar_multiply(num, num, qnr);

		if (l_ecc_scalar_legendre(num) == 1) {
			l_ecc_scalar_free(num);
			return true;
		}
	}

	l_ecc_scalar_free(num);

	return false;
}

/*
 * IEEE 802.11-2016 Section 12.4.4.2.2
 * Generation of the password element with ECC groups
 */
static bool sae_compute_pwe(struct sae_sm *sm, char *password,
				const uint8_t *addr1, const uint8_t *addr2)
{
	bool found = false;
	uint8_t counter;
	uint8_t pwd_seed[32];
	struct l_ecc_scalar *pwd_value;
	uint8_t random[32];
	uint8_t *base = (uint8_t *) password;
	size_t base_len = strlen(password);
	uint8_t save[32] = { 0 };
	struct l_ecc_scalar *qr;
	struct l_ecc_scalar *qnr;
	uint8_t x[L_ECC_SCALAR_MAX_BYTES];

	/* create qr/qnr prior to beginning hunting-and-pecking loop */
	qr = sae_new_residue(sm->curve, true);
	qnr = sae_new_residue(sm->curve, false);

	for (counter = 1; counter <= 20; counter++) {
		/* pwd-seed = H(max(addr1, addr2) || min(addr1, addr2),
		 *                base || counter)
		 * pwd-value = KDF-256(pwd-seed, "SAE Hunting and Pecking", p)
		 */
		sae_pwd_seed(addr1, addr2, base, base_len, counter, pwd_seed);

		pwd_value = sae_pwd_value(sm->curve, pwd_seed);
		if (!pwd_value)
			continue;

		if (sae_is_quadradic_residue(sm->curve, pwd_value, qr, qnr)) {
			if (found == false) {
				l_ecc_scalar_get_data(pwd_value, x, sizeof(x));

				memcpy(save, pwd_seed, 32);

				l_getrandom(random, 32);
				base = random;
				base_len = 32;

				found = true;
			}
		}

		l_ecc_scalar_free(pwd_value);
	}

	l_ecc_scalar_free(qr);
	l_ecc_scalar_free(qnr);

	if (!found) {
		l_error("max PWE iterations reached!");
		return false;
	}

	if (!(save[31] & 1))
		sm->pwe = l_ecc_point_from_data(sm->curve,
					L_ECC_POINT_TYPE_COMPRESSED_BIT1,
					x, sizeof(x));
	else
		sm->pwe = l_ecc_point_from_data(sm->curve,
					L_ECC_POINT_TYPE_COMPRESSED_BIT0,
					x, sizeof(x));

	if (!sm->pwe) {
		l_error("computing y failed, was x quadratic residue?");
		return false;
	}

	return true;
}

static bool sae_build_commit(struct sae_sm *sm, const uint8_t *addr1,
				const uint8_t *addr2, uint8_t *commit,
				size_t *len, bool retry)
{
	struct l_ecc_scalar *mask;
	uint8_t *ptr = commit;
	struct l_ecc_scalar *order;

	if (retry)
		goto old_commit;

	if (!sm->handshake->passphrase) {
		l_error("no handshake passphrase found");
		return false;
	}

	if (!sae_compute_pwe(sm, sm->handshake->passphrase, addr1, addr2)) {
		l_error("could not compute PWE");
		return false;
	}

	sm->scalar = l_ecc_scalar_new(sm->curve, NULL, 0);
	sm->rand = l_ecc_scalar_new_random(sm->curve);
	mask = l_ecc_scalar_new_random(sm->curve);

	order = l_ecc_curve_get_order(sm->curve);

	/* commit-scalar = (rand + mask) mod r */
	l_ecc_scalar_add(sm->scalar, sm->rand, mask, order);

	l_ecc_scalar_free(order);

	/* commit-element = inv(mask * PWE) */
	sm->element = l_ecc_point_new(sm->curve);
	l_ecc_point_multiply(sm->element, mask, sm->pwe);
	l_ecc_point_inverse(sm->element);

	l_ecc_scalar_free(mask);

	/*
	 * Several cases require retransmitting the same commit message. The
	 * anti-clogging code path requires this as well as the retransmission
	 * timeout.
	 */
old_commit:

	/* transaction */
	l_put_le16(1, ptr);
	ptr += 2;
	/* status success */
	l_put_le16(0, ptr);
	ptr += 2;
	/* group */
	l_put_le16(sm->group, ptr);
	ptr += 2;

	if (sm->token) {
		memcpy(ptr, sm->token, sm->token_len);
		ptr += sm->token_len;
	}

	ptr += l_ecc_scalar_get_data(sm->scalar, ptr, L_ECC_SCALAR_MAX_BYTES);
	ptr += l_ecc_point_get_data(sm->element, ptr, L_ECC_POINT_MAX_BYTES);

	*len = ptr - commit;

	return true;
}

static void sae_send_confirm(struct sae_sm *sm)
{
	uint8_t confirm[32];
	uint8_t body[38];
	uint8_t *ptr = body;

	/*
	 * confirm = CN(KCK, send-confirm, commit-scalar, COMMIT-ELEMENT,
	 *			peer-commit-scalar, PEER-COMMIT-ELEMENT)
	 */
	sae_cn(sm->kck, sm->sc, sm->scalar, sm->element, sm->p_scalar,
			sm->p_element, confirm);

	l_put_le16(2, ptr);
	ptr += 2;
	l_put_le16(0, ptr);
	ptr += 2;
	l_put_le16(sm->sc, ptr);
	ptr += 2;
	memcpy(ptr, confirm, 32);
	ptr += 32;

	sm->state = SAE_STATE_CONFIRMED;

	sm->tx_auth(body, 38, sm->user_data);
}

static int sae_process_commit(struct sae_sm *sm, const uint8_t *from,
					const uint8_t *frame, size_t len)
{
	uint8_t *ptr = (uint8_t *) frame;
	uint8_t k[L_ECC_SCALAR_MAX_BYTES];
	struct l_ecc_point *k_point;
	uint8_t zero_key[32] = { 0 };
	uint8_t keyseed[32];
	uint8_t kck_and_pmk[2][32];
	uint8_t tmp[L_ECC_SCALAR_MAX_BYTES];
	struct l_ecc_scalar *tmp_scalar;
	uint16_t group;
	uint16_t reason = MMPDU_REASON_CODE_UNSPECIFIED;
	ssize_t klen;
	struct l_ecc_scalar *order;
	unsigned int nbytes = l_ecc_curve_get_scalar_bytes(sm->curve);

	if (sm->state != SAE_STATE_COMMITTED) {
		l_error("bad state %u", sm->state);
		goto reject;
	}

	/* Scalar + Point + group */
	if (len < nbytes + nbytes * 2 + 2) {
		l_error("bad packet length");
		goto reject;
	}

	group = l_get_le16(ptr);
	ptr += 2;

	if (group != sm->group) {
		sae_reject_authentication(sm,
				MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP);
		return 0;
	}

	sm->p_scalar = l_ecc_scalar_new(sm->curve, ptr, nbytes);
	if (!sm->p_scalar) {
		l_error("Server sent invalid P_Scalar during commit");
		reason = MMPDU_REASON_CODE_UNSPECIFIED;
		goto reject;
	}

	ptr += nbytes;

	sm->p_element = l_ecc_point_from_data(sm->curve, L_ECC_POINT_TYPE_FULL,
						ptr, nbytes * 2);
	if (!sm->p_element) {
		l_error("Server sent invalid P_Element during commit");
		reason = MMPDU_REASON_CODE_UNSPECIFIED;
		goto reject;
	}

	if (l_ecc_scalars_are_equal(sm->p_scalar, sm->scalar) ||
			l_ecc_points_are_equal(sm->p_element, sm->element)) {
		/* possible reflection attack, silently discard message */
		l_warn("peer scalar or element matched own, discarding frame");

		return 0;
	}

	sm->sc++;

	/*
	 * K = scalar-op(rand, (element-op(scalar-op(peer-commit-scalar, PWE),
	 *			PEER-COMMIT-ELEMENT)))
	 */
	k_point = l_ecc_point_new(sm->curve);

	/* k_point = scalar-op(peer-commit-scalar, PWE) */
	l_ecc_point_multiply(k_point, sm->p_scalar, sm->pwe);

	/* k_point = element-op(k_point, PEER-COMMIT-ELEMENT) */
	l_ecc_point_add(k_point, k_point, sm->p_element);

	/* k_point = scalar-op(rand, k_point) */
	l_ecc_point_multiply(k_point, sm->rand, k_point);

	/*
	 * IEEE 802.11-2016 - Section 12.4.4.2.1 ECC group definition
	 * ECC groups make use of a mapping function, F, that maps a
	 * point (x, y) that satisfies the curve equation to its x-coordinate—
	 * i.e., if P = (x, y) then F(P) = x.
	 */
	klen = l_ecc_point_get_x(k_point, k, sizeof(k));

	l_ecc_point_free(k_point);

	if (klen < 0)
		goto reject;

	/* keyseed = H(<0>32, k) */
	hmac_sha256(zero_key, 32, k, klen, keyseed, 32);

	/*
	 * kck_and_pmk = KDF-Hash-512(keyseed, "SAE KCK and PMK",
				(commit-scalar + peer-commit-scalar) mod r)
	 */
	tmp_scalar = l_ecc_scalar_new(sm->curve, NULL, 0);
	order = l_ecc_curve_get_order(sm->curve);

	l_ecc_scalar_add(tmp_scalar, sm->p_scalar, sm->scalar, order);
	l_ecc_scalar_get_data(tmp_scalar, tmp, sizeof(tmp));

	kdf_sha256(keyseed, 32, "SAE KCK and PMK", strlen("SAE KCK and PMK"),
			tmp, nbytes, kck_and_pmk, 64);

	memcpy(sm->kck, kck_and_pmk[0], 32);
	memcpy(sm->pmk, kck_and_pmk[1], 32);

	/*
	 * PMKID = L((commit-scalar + peer-commit-scalar) mod r, 0, 128)
	 */
	l_ecc_scalar_add(tmp_scalar, sm->scalar, sm->p_scalar, order);
	l_ecc_scalar_get_data(tmp_scalar, tmp, sizeof(tmp));

	l_ecc_scalar_free(order);

	l_ecc_scalar_free(tmp_scalar);
	/* don't set the handshakes pmkid until confirm is verified */
	memcpy(sm->pmkid, tmp, 16);

	sae_send_confirm(sm);

	return 0;

reject:
	sae_reject_authentication(sm, reason);
	return -EBADMSG;
}

static bool sae_verify_confirm(struct sae_sm *sm, const uint8_t *frame)
{
	uint8_t check[32];
	uint16_t rc = l_get_le16(frame);

	sae_cn(sm->kck, rc, sm->p_scalar, sm->p_element, sm->scalar,
			sm->element, check);

	if (memcmp(frame + 2, check, 32)) {
		l_error("confirm did not match");
		return false;
	}

	sm->rc = rc;

	return true;
}

static int sae_process_confirm(struct sae_sm *sm, const uint8_t *from,
				const uint8_t *frame, size_t len)
{
	const uint8_t *ptr = frame;

	if (sm->state != SAE_STATE_CONFIRMED) {
		l_error("bad state %u", sm->state);
		goto reject;
	}

	if (len < 34) {
		l_error("bad length");
		goto reject;
	}

	if (!sae_verify_confirm(sm, ptr))
		goto reject;

	/* Sc shall be set to the value 2^16 - 1 */
	sm->sc = 0xffff;

	handshake_state_set_pmkid(sm->handshake, sm->pmkid);
	handshake_state_set_pmk(sm->handshake, sm->pmk, 32);

	sm->state = SAE_STATE_ACCEPTED;

	sm->tx_assoc(sm->user_data);

	return 0;

reject:
	sae_reject_authentication(sm, MMPDU_REASON_CODE_UNSPECIFIED);
	return -EBADMSG;
}

static bool sae_send_commit(struct sae_sm *sm, bool retry)
{
	struct handshake_state *hs = sm->handshake;
	/* regular commit + possible 256 byte token + 6 bytes header */
	uint8_t commit[L_ECC_SCALAR_MAX_BYTES + L_ECC_POINT_MAX_BYTES + 262];
	size_t len;

	if (!sae_build_commit(sm, hs->spa, hs->aa, commit, &len, retry))
		return false;

	sm->state = SAE_STATE_COMMITTED;

	sm->tx_auth(commit, len, sm->user_data);

	return true;
}

static bool sae_timeout(struct auth_proto *ap)
{
	struct sae_sm *sm = l_container_of(ap, struct sae_sm, ap);

	/* regardless of state, reject if sync exceeds max */
	if (sm->sync > SAE_SYNC_MAX) {
		sae_reject_authentication(sm, MMPDU_REASON_CODE_UNSPECIFIED);
		return false;
	}

	sm->sync++;

	switch (sm->state) {
	case SAE_STATE_COMMITTED:
		sae_send_commit(sm, true);
		break;
	case SAE_STATE_CONFIRMED:
		sm->sc++;
		sae_send_confirm(sm);
		break;
	default:
		/* should never happen */
		l_error("SAE timeout in bad state %u", sm->state);
		return false;
	}

	return true;
}

/*
 * 802.11-2016 - Section 12.4.8.6.4
 * If the Status code is ANTI_CLOGGING_TOKEN_REQUIRED, a new SAE Commit message
 * shall be constructed with the Anti-Clogging Token from the received
 * Authentication frame, and the commit-scalar and COMMIT-ELEMENT previously
 * sent. The new SAE Commit message shall be transmitted to the peer, Sync shall
 * be zeroed, and the t0 (retransmission) timer shall be set.
 */
static void sae_process_anti_clogging(struct sae_sm *sm, const uint8_t *ptr,
					size_t len)
{
	/*
	 * IEEE 802.11-2016 - Section 12.4.6 Anti-clogging tokens
	 *
	 * "It is suggested that an Anti-Clogging Token not exceed 256 octets"
	 *
	 * Also ensure the token is at least 1 byte. The packet passed in will
	 * contain the group number, meaning the anti-clogging token length is
	 * going to be 2 bytes less than the passed in length. This is why we
	 * are checking 3 > len > 258.
	 */
	if (len < 3 || len > 258) {
		l_error("anti-clogging token size invalid %zu", len);
		return;
	}

	sm->token = l_memdup(ptr + 2, len - 2);
	sm->token_len = len - 2;
	sm->sync = 0;

	sae_send_commit(sm, true);
}

/*
 * 802.11-2016 - 12.4.8.6.3 Protocol instance behavior - Nothing state
 */
static int sae_verify_nothing(struct sae_sm *sm, uint16_t transaction,
					uint16_t status, const uint8_t *frame,
					size_t len)
{
	/*
	 * TODO: This does not handle the transition from NOTHING -> CONFIRMED
	 * as this is only relevant to the AP or in Mesh mode which is not
	 * yet supported.
	 */
	if (transaction != SAE_STATE_COMMITTED)
		return -EBADMSG;

	/* frame shall be silently discarded and Del event sent */
	if (status != 0)
		return -EBADMSG;

	if (len < 2)
		return -EBADMSG;

	/* reject with unsupported group */
	if (l_get_le16(frame) != sm->group) {
		sae_reject_authentication(sm,
				MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP);
		return -EBADMSG;
	}

	return 0;
}

static void sae_reset_state(struct sae_sm *sm)
{
	l_free(sm->token);
	sm->token = NULL;

	l_ecc_scalar_free(sm->scalar);
	sm->scalar = NULL;
	l_ecc_scalar_free(sm->p_scalar);
	sm->p_scalar = NULL;
	l_ecc_scalar_free(sm->rand);
	sm->rand = NULL;
	l_ecc_point_free(sm->element);
	sm->element = NULL;
	l_ecc_point_free(sm->p_element);
	sm->p_element = NULL;
	l_ecc_point_free(sm->pwe);
	sm->pwe = NULL;
}

/*
 * 802.11-2016 - 12.4.8.6.4 Protocol instance behavior - Committed state
 */
static int sae_verify_committed(struct sae_sm *sm, uint16_t transaction,
					uint16_t status, const uint8_t *frame,
					size_t len)
{
	/*
	 * Upon receipt of a Con event...
	 * Then the protocol instance checks the value of Sync. If it
	 * is greater than dot11RSNASAESync, the protocol instance shall send a
	 * Del event to the parent process and transition back to Nothing state.
	 * If Sync is not greater than dot11RSNASAESync, the protocol instance
	 * shall increment Sync, transmit the last SAE Commit message sent to
	 * the peer...
	 */
	if (transaction == SAE_STATE_CONFIRMED) {
		if (sm->sync > SAE_SYNC_MAX)
			return -EBADMSG;

		sm->sync++;

		sae_send_commit(sm, true);

		return -EAGAIN;
	}

	switch (status) {
	case MMPDU_STATUS_CODE_ANTI_CLOGGING_TOKEN_REQ:
		sae_process_anti_clogging(sm, frame, len);
		return -EAGAIN;
	case MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP:
		/*
		 * TODO: hostapd in its current state does not include the
		 * group number as it should. This is a violation of the spec,
		 * but there isn't much we can do about it. We simply treat this
		 * response as if its rejecting our last commit message (which
		 * it most likely is). If/When this is fixed we should be
		 * checking that the group matches here, e.g.
		 *
		 * if (l_get_le16(frame) != sm->group)
		 * 	return false;
		 *
		 * According to 802.11 Section 12.4.8.6.4:
		 *
		 * "If the rejected group does not match the last offered group
		 * the protocol instance shall silently discard the message and
		 * set the t0 (retransmission) timer"
		 */
		if (len == 0)
			l_warn("AP did not include group number in response!");
		else if (len >= 2 && (l_get_le16(frame) != sm->group))
			return -EBADMSG;

		sm->group_retry++;

		if (sm->ecc_groups[sm->group_retry] == 0) {
			/*
			 * "If there are no other groups to choose, the protocol
			 * instance shall send a Del event to the parent process
			 * and transitions back to Nothing state"
			 */
			sm->state = SAE_STATE_NOTHING;
			goto reject_unsupp_group;
		}

		/*
		 * "If the rejected group matches the last offered group, the
		 * protocol instance shall choose a different group and generate
		 * the PWE and the secret values according to 12.4.5.2; it then
		 * generates and transmits a new SAE Commit message to the peer,
		 * zeros Sync, sets the t0 (retransmission) timer, and remains
		 * in Committed state"
		 */

		sae_reset_state(sm);

		sm->group = sm->ecc_groups[sm->group_retry];
		sm->curve = l_ecc_curve_get_ike_group(sm->group);

		sm->sync = 0;

		sae_send_commit(sm, false);

		return -EAGAIN;
	case 0:
		if (len < 2)
			return -EBADMSG;

		if (l_get_le16(frame) == sm->group)
			return 0;

		if (!l_ecc_curve_get_ike_group(l_get_le16(frame))) {
			if (sm->sync > SAE_SYNC_MAX)
				return -EBADMSG;

			sm->sync++;

			goto reject_unsupp_group;
		}

		/*
		 * If we get here we know that the groups do not match, but the
		 * group provided in the frame is supported. From section
		 * 12.4.8.6.4 we see:
		 *
		 * "If the group is supported but does not match that used when
		 * the protocol instance constructed its SAE Commit message,
		 * DiffGrp shall be set and the local identity and peer identity
		 * shall be checked"
		 */

		if (memcmp(sm->handshake->spa, sm->handshake->aa, 6) > 0) {
			/*
			 * "The mesh STA, with the numerically greater of the two
			 * MAC addresses, drops the received SAE Commit message,
			 * retransmits its last SAE Commit message, and shall
			 * set the t0 (retransmission) timer and remain in
			 * Committed state"
			 */
			sae_send_commit(sm, true);

			return 0;
		}

		/*
		 * "The mesh STA, with the numerically lesser of the two
		 * MAC addresses, zeros Sync, shall increment Sc, choose
		 * the group from the received SAE Commit message,
		 * generate new PWE and new secret values according to
		 * 12.4.5.2, process the received SAE Commit message
		 * according to 12.4.5.4, generate a new SAE Commit
		 * message and SAE Confirm message, and shall transmit
		 * the new Commit and Confirm to the peer. It shall then
		 * transition to Confirmed state."
		 */
		sm->sync = 0;
		sm->sc++;
		sm->group = l_get_le16(frame);
		sm->curve = l_ecc_curve_get_ike_group(sm->group);

		sae_send_commit(sm, false);

		sm->state = SAE_STATE_CONFIRMED;

		/*
		 * The processing and sending of the confirm message
		 * will happen after we return. Since we have set the
		 * state to CONFIRMED, our confirm handler will get
		 * called.
		 */

		return 0;
	default:
		/*
		 * If the Status is some other nonzero value, the frame shall
		 * be silently discarded...
		 */
		return 0;
	}

reject_unsupp_group:
	sae_reject_authentication(sm,
			MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP);
	return MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP;
}

/*
 * 802.11-2016 - 12.4.8.6.5 Protocol instance behavior - Confirmed state
 */
static int sae_verify_confirmed(struct sae_sm *sm, uint16_t trans,
					uint16_t status, const uint8_t *frame,
					size_t len)
{
	if (trans == SAE_STATE_CONFIRMED)
		return 0;

	/*
	 * If the Status is nonzero, the frame shall be silently discarded...
	 */
	if (status != 0)
		return 0;

	/*
	 * If Sync is greater than dot11RSNASAESync, the protocol instance
	 * shall send the parent process a Del event and transitions back to
	 * Nothing state.
	 */
	if (sm->sync > SAE_SYNC_MAX)
		return -EBADMSG;

	if (len < 2)
		return -EBADMSG;

	/* frame shall be silently discarded */
	if (l_get_le16(frame) != sm->group)
		return 0;

	/*
	 * the protocol instance shall increment Sync, increment Sc, and
	 * transmit its Commit and Confirm (with the new Sc value) messages.
	 */
	sm->sync++;
	sm->sc++;

	sae_send_commit(sm, true);
	sae_send_confirm(sm);

	return 0;
}

/*
 * 802.11-2016 - 12.4.8.6.6 Protocol instance behavior - Accepted state
 */
static int sae_verify_accepted(struct sae_sm *sm, uint16_t trans,
					uint16_t status, const uint8_t *frame,
					size_t len)
{
	uint16_t sc;

	/* spec does not specify what to do here, so print and discard */
	if (trans != SAE_STATE_CONFIRMED) {
		l_error("received transaction %u in accepted state", trans);
		return -EBADMSG;
	}

	if (sm->sync > SAE_SYNC_MAX)
		return -EBADMSG;

	if (len < 2)
		return -EBADMSG;

	sc = l_get_le16(frame);

	/*
	 * ... the value of send-confirm shall be checked. If the value is not
	 * greater than Rc or is equal to 2^16 - 1, the received frame shall be
	 * silently discarded.
	 */
	if (sc <= sm->rc || sc == 0xffff)
		return -EBADMSG;

	/*
	 * If the verification fails, the received frame shall be silently
	 * discarded.
	 */
	if (!sae_verify_confirm(sm, frame))
		return -EBADMSG;

	/*
	 * If the verification succeeds, the Rc variable shall be set to the
	 * send-confirm portion of the frame, the Sync shall be incremented and
	 * a new SAE Confirm message shall be constructed (with Sc set to
	 * 2^16 - 1) and sent to the peer.
	 */
	sm->sync++;
	sm->sc = 0xffff;

	sae_send_confirm(sm);

	return 0;
}

static int sae_verify_packet(struct sae_sm *sm, uint16_t trans,
				uint16_t status, const uint8_t *frame,
				size_t len)
{
	if (trans != SAE_STATE_COMMITTED && trans != SAE_STATE_CONFIRMED)
		return -EBADMSG;

	switch (sm->state) {
	case SAE_STATE_NOTHING:
		return sae_verify_nothing(sm, trans, status, frame, len);
	case SAE_STATE_COMMITTED:
		return sae_verify_committed(sm, trans, status, frame, len);
	case SAE_STATE_CONFIRMED:
		return sae_verify_confirmed(sm, trans, status, frame, len);
	case SAE_STATE_ACCEPTED:
		return sae_verify_accepted(sm, trans, status, frame, len);
	}

	/* should never get here */
	return -1;
}

static int sae_rx_authenticate(struct auth_proto *ap,
				const uint8_t *frame, size_t len)
{
	struct sae_sm *sm = l_container_of(ap, struct sae_sm, ap);
	const struct mmpdu_header *hdr = mpdu_validate(frame, len);
	const struct mmpdu_authentication *auth;
	int ret;

	if (!hdr) {
		l_debug("Auth frame header did not validate");
		goto reject;
	}

	auth = mmpdu_body(hdr);

	len -= mmpdu_header_len(hdr);

	ret = sae_verify_packet(sm, L_LE16_TO_CPU(auth->transaction_sequence),
					L_LE16_TO_CPU(auth->status),
					auth->ies, len - 6);
	if (ret != 0)
		return ret;

	switch (L_LE16_TO_CPU(auth->transaction_sequence)) {
	case SAE_STATE_COMMITTED:
		return sae_process_commit(sm, hdr->address_2, auth->ies,
						len - 6);
	case SAE_STATE_CONFIRMED:
		return sae_process_confirm(sm, hdr->address_2, auth->ies,
						len - 6);
	default:
		l_error("invalid transaction sequence %u",
				L_LE16_TO_CPU(auth->transaction_sequence));
	}

reject:
	sae_reject_authentication(sm, MMPDU_REASON_CODE_UNSPECIFIED);

	return -EBADMSG;
}

static int sae_rx_associate(struct auth_proto *ap, const uint8_t *frame,
				size_t len)
{
	const struct mmpdu_header *mpdu = NULL;
	const struct mmpdu_association_response *body;

	mpdu = mpdu_validate(frame, len);
	if (!mpdu) {
		l_error("could not process frame");
		return -EBADMSG;
	}

	body = mmpdu_body(mpdu);

	if (body->status_code != 0)
		return L_LE16_TO_CPU(body->status_code);

	return 0;
}

static bool sae_start(struct auth_proto *ap)
{
	struct sae_sm *sm = l_container_of(ap, struct sae_sm, ap);

	if (sm->handshake->authenticator)
		memcpy(sm->peer, sm->handshake->spa, 6);
	else
		memcpy(sm->peer, sm->handshake->aa, 6);

	return sae_send_commit(sm, false);
}

static void sae_free(struct auth_proto *ap)
{
	struct sae_sm *sm = l_container_of(ap, struct sae_sm, ap);

	sae_reset_state(sm);

	/* zero out whole structure, including keys */
	explicit_bzero(sm, sizeof(struct sae_sm));

	l_free(sm);
}

struct auth_proto *sae_sm_new(struct handshake_state *hs,
				sae_tx_authenticate_func_t tx_auth,
				sae_tx_associate_func_t tx_assoc,
				void *user_data)
{
	struct sae_sm *sm;

	sm = l_new(struct sae_sm, 1);

	if (!sm)
		return NULL;

	sm->tx_auth = tx_auth;
	sm->tx_assoc = tx_assoc;
	sm->user_data = user_data;
	sm->handshake = hs;
	sm->state = SAE_STATE_NOTHING;
	sm->ecc_groups = l_ecc_curve_get_supported_ike_groups();
	sm->group = sm->ecc_groups[sm->group_retry];
	sm->curve = l_ecc_curve_get_ike_group(sm->group);

	sm->ap.start = sae_start;
	sm->ap.free = sae_free;
	sm->ap.rx_authenticate = sae_rx_authenticate;
	sm->ap.rx_associate = sae_rx_associate;
	sm->ap.auth_timeout = sae_timeout;

	return &sm->ap;
}
