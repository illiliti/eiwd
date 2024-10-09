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

#define _GNU_SOURCE
#include <stdlib.h>

#include <ell/ell.h>

#include "src/missing.h"
#include "src/util.h"
#include "src/ie.h"
#include "src/handshake.h"
#include "src/crypto.h"
#include "src/mpdu.h"
#include "src/auth-proto.h"
#include "src/sae.h"
#include "src/module.h"

static bool debug;

/* SHA-512 is the highest supported hashing function as of 802.11-2020 */
#define SAE_MAX_HASH_LEN 64

#define SAE_RETRANSMIT_TIMEOUT	2
#define SAE_SYNC_MAX		3
#define SAE_MAX_ASSOC_RETRY	3

#define sae_debug(fmat, ...) \
({	\
	if (debug) \
		l_info("[SAE]: "fmat, ##__VA_ARGS__); \
})

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
	int group_retry;
	uint16_t *rejected_groups;
	struct l_ecc_scalar *rand;
	struct l_ecc_scalar *scalar;
	struct l_ecc_scalar *p_scalar;
	struct l_ecc_point *element;
	struct l_ecc_point *p_element;
	uint16_t send_confirm;
	uint8_t kck[SAE_MAX_HASH_LEN];
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
	uint8_t assoc_retry;

	sae_tx_authenticate_func_t tx_auth;
	sae_tx_associate_func_t tx_assoc;
	void *user_data;
	enum crypto_sae sae_type;

	bool force_default_group : 1;
};

static enum mmpdu_status_code sae_status_code(struct sae_sm *sm)
{
	switch (sm->sae_type) {
	case CRYPTO_SAE_LOOPING:
		return MMPDU_STATUS_CODE_SUCCESS;
	case CRYPTO_SAE_HASH_TO_ELEMENT:
		return MMPDU_STATUS_CODE_SAE_HASH_TO_ELEMENT;
	}

	return MMPDU_STATUS_CODE_UNSPECIFIED;
}

static void sae_rejected_groups_append(struct sae_sm *sm, uint16_t group)
{
	uint16_t i;

	if (!sm->rejected_groups) {
		sm->rejected_groups = reallocarray(NULL, 2, sizeof(uint16_t));
		sm->rejected_groups[0] = 1;
		sm->rejected_groups[1] = group;
		return;
	}

	for (i = 1; i <= sm->rejected_groups[0]; i++)
		if (sm->rejected_groups[i] == group)
			return;

	sm->rejected_groups = reallocarray(sm->rejected_groups,
						i + 1, sizeof(uint16_t));
	sm->rejected_groups[0] += 1;
	sm->rejected_groups[i] = group;
}

static void sae_reset_state(struct sae_sm *sm)
{
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

static int sae_choose_next_group(struct sae_sm *sm)
{
	const unsigned int *ecc_groups = l_ecc_supported_ike_groups();
	bool reset = sm->group_retry >= 0;
	unsigned int group;

	/* Find the next group in the list */
	while ((group = ecc_groups[++sm->group_retry])) {
		/*
		 * Forcing the default group; only choose group 19. If we have
		 * already passed 19 (due to a retry) we will exhaust all other
		 * groups and should fail.
		 */
		if (sm->force_default_group && group != 19)
			continue;

		/* Ensure the PT was derived for this group */
		if (sm->sae_type == CRYPTO_SAE_HASH_TO_ELEMENT &&
				!sm->handshake->ecc_sae_pts[sm->group_retry])
			continue;

		break;
	}

	if (!group)
		return -ENOENT;

	sm->group = group;

	if (reset)
		sae_reset_state(sm);

	sae_debug("Using group %u", sm->group);

	sm->curve = l_ecc_curve_from_ike_group(sm->group);

	return 0;
}

static int sae_valid_group(struct sae_sm *sm, unsigned int group)
{
	const unsigned int *ecc_groups = l_ecc_supported_ike_groups();
	unsigned int i;

	for (i = sm->group_retry; ecc_groups[i]; i++) {
		if (ecc_groups[i] != group)
			continue;

		if (sm->sae_type != CRYPTO_SAE_LOOPING &&
				!sm->handshake->ecc_sae_pts[i])
			continue;

		return i;
	}

	return -ENOENT;
}

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

/*
 * Computes KDF-256(pwd_seed, "SAE Hunting and Pecking", p). If the output is
 * greater than p, the output is set to qnr, a quadratic non-residue.
 * Since this happens with very low probability, using the same qnr is fine.
 */
static struct l_ecc_scalar *sae_pwd_value(const struct l_ecc_curve *curve,
						uint8_t *pwd_seed, uint8_t *qnr)
{
	uint8_t pwd_value[L_ECC_SCALAR_MAX_BYTES];
	uint8_t prime[L_ECC_SCALAR_MAX_BYTES];
	ssize_t len;
	int is_in_range;
	struct l_ecc_scalar *p = l_ecc_curve_get_prime(curve);

	len = l_ecc_scalar_get_data(p, prime, sizeof(prime));
	l_ecc_scalar_free(p);

	if (!kdf_sha256(pwd_seed, 32, "SAE Hunting and Pecking",
			strlen("SAE Hunting and Pecking"), prime, len,
			pwd_value, len))
		return NULL;

	/*
	 * If pwd_value >= prime, this iteration should fail. We need a smooth
	 * control flow, so we need to continue anyway.
	 */
	is_in_range = l_secure_memcmp(pwd_value, prime, len);
	/*
	 * We only consider is_in_range == -1 as valid, meaning the value of the
	 * MSB defines the mask.
	 */
	is_in_range = util_secure_fill_with_msb(is_in_range);

	/*
	 * libell has public Legendre symbol only for l_ecc_scalar, but they
	 * cannot be created if the coordinate is greater than the p. Hence,
	 * to avoid control flow dependencies, we replace pwd_value by a dummy
	 * quadratic non residue if we generate a value >= prime.
	 */
	util_secure_select((uint8_t) is_in_range, pwd_value, qnr,
						pwd_value, sizeof(pwd_value));

	return l_ecc_scalar_new(curve, pwd_value, sizeof(pwd_value));
}

/* IEEE 802.11-2016 - Section 12.4.2 Assumptions on SAE */
static ssize_t sae_cn(struct sae_sm *sm, uint16_t send_confirm,
			struct l_ecc_scalar *scalar1,
			struct l_ecc_point *element1,
			struct l_ecc_scalar *scalar2,
			struct l_ecc_point *element2,
			uint8_t *confirm)
{
	enum l_checksum_type hash =
		crypto_sae_hash_from_ecc_prime_len(sm->sae_type,
				l_ecc_curve_get_scalar_bytes(sm->curve));
	size_t hash_len = l_checksum_digest_length(hash);
	uint8_t s1[L_ECC_SCALAR_MAX_BYTES];
	uint8_t s2[L_ECC_SCALAR_MAX_BYTES];
	uint8_t e1[L_ECC_POINT_MAX_BYTES];
	uint8_t e2[L_ECC_POINT_MAX_BYTES];
	struct l_checksum *hmac;
	struct iovec iov[5];
	ssize_t ret;

	hmac = l_checksum_new_hmac(hash, sm->kck, hash_len);
	if (!hmac)
		return false;

	send_confirm = L_CPU_TO_LE16(send_confirm);

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
	ret = l_checksum_get_digest(hmac, confirm, hash_len);
	l_checksum_free(hmac);

	return ret;
}

static int sae_reject(struct sae_sm *sm, uint16_t transaction, uint16_t status)
{
	uint8_t reject[6];
	uint8_t *ptr = reject;

	if (!sm->handshake->authenticator)
		return -EPROTO;

	/* transaction */
	l_put_u16(transaction, ptr);
	ptr += 2;

	l_put_u16(status, ptr);
	ptr += 2;

	if (status == MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP) {
		l_put_u16(sm->group, ptr);
		ptr += 2;
	}

	sae_debug("Rejecting exchange transaction=%u status=%u",
			transaction, status);

	sm->tx_auth(reject, ptr - reject, sm->user_data);

	return status;
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

static uint8_t sae_is_quadradic_residue(const struct l_ecc_curve *curve,
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
		return 0;
	}

	if (rbuf[bytes / 8 - 1] & 1) {
		l_ecc_scalar_multiply(num, num, qr);

		if (l_ecc_scalar_legendre(num) == -1) {
			l_ecc_scalar_free(num);
			return 1;
		}
	} else {
		l_ecc_scalar_multiply(num, num, qnr);

		if (l_ecc_scalar_legendre(num) == 1) {
			l_ecc_scalar_free(num);
			return 1;
		}
	}

	l_ecc_scalar_free(num);

	return 0;
}

/*
 * IEEE 802.11-2016 Section 12.4.4.2.2
 * Generation of the password element with ECC groups
 */
static struct l_ecc_point *sae_compute_pwe(const struct l_ecc_curve *curve,
						const char *password,
						const uint8_t *addr1,
						const uint8_t *addr2)
{
	uint8_t found = 0;
	uint8_t is_residue;
	uint8_t is_odd = 0;
	uint8_t counter;
	uint8_t pwd_seed[32];
	uint8_t x[L_ECC_SCALAR_MAX_BYTES];
	uint8_t x_cand[L_ECC_SCALAR_MAX_BYTES];
	struct l_ecc_scalar *pwd_value;
	uint8_t *dummy;
	uint8_t *base;
	size_t base_len;
	struct l_ecc_scalar *qr;
	struct l_ecc_scalar *qnr;
	uint8_t qnr_bin[L_ECC_SCALAR_MAX_BYTES] = {0};
	struct l_ecc_point *pwe;
	unsigned int bytes = l_ecc_curve_get_scalar_bytes(curve);

	/* create qr/qnr prior to beginning hunting-and-pecking loop */
	qr = sae_new_residue(curve, true);
	qnr = sae_new_residue(curve, false);
	l_ecc_scalar_get_data(qnr, qnr_bin, sizeof(qnr_bin));

	/*
	 * Allocate memory for the base, and set a random dummy to be used in
	 * additional iterations, once a valid value is found
	 */
	base_len = strlen(password);
	base = l_malloc(base_len * sizeof(*base));
	dummy = l_malloc(base_len * sizeof(*dummy));
	l_getrandom(dummy, base_len);

	/*
	 * Loop with constant time and memory access
	 * We do 30 iterations instead of the 40 recommended to achieve a
	 * resonnable security/complexity trade-off.
	 */
	for (counter = 1; counter <= 30; counter++) {
		/*
		 * Set base to either dummy or password, depending on found's
		 * value.
		 * A non-secure version would be:
		 *	base = (found ? dummy : password);
		 */
		util_secure_select(found, dummy, (uint8_t *)password,
					base, base_len);

		/*
		 * pwd-seed = H(max(addr1, addr2) || min(addr1, addr2),
		 *				base || counter)
		 * pwd-value = KDF-256(pwd-seed, "SAE Hunting and Pecking", p)
		 */
		sae_pwd_seed(addr1, addr2, base, base_len, counter, pwd_seed);
		/*
		 * The case pwd_value > prime is handled inside, so that
		 * execution can continue whatever the result is, without
		 * changing the outcome.
		 */
		pwd_value = sae_pwd_value(curve, pwd_seed, qnr_bin);

		/*
		 * Check if the candidate is a valid x-coordinate on our curve,
		 * and convert it from scalar to binary.
		 */
		is_residue = sae_is_quadradic_residue(curve, pwd_value,
								qr, qnr);
		l_ecc_scalar_get_data(pwd_value, x_cand, sizeof(x_cand));

		/*
		 * If we already found the point, we overwrite x with itself.
		 * Otherwise, we copy the new candidate into x.
		 */
		util_secure_select(found, x, x_cand, x, sizeof(x));
		is_odd = util_secure_select_byte(found, is_odd,
							pwd_seed[31] & 0x01);

		/*
		 * found is 0 or 0xff here and is_residue is 0 or 1. Bitwise OR
		 * of them (with is_residue converted to 0/0xff) handles this
		 * in constant time.
		 */
		found |= is_residue * 0xff;

		memset(pwd_seed, 0, sizeof(pwd_seed));
		l_ecc_scalar_free(pwd_value);
	}

	l_ecc_scalar_free(qr);
	l_ecc_scalar_free(qnr);
	l_free(dummy);
	l_free(base);

	if (!found) {
		l_error("max PWE iterations reached!");
		return NULL;
	}

	/*
	 * The 802.11 spec requires the point be solved unambiguously (since
	 * solving for Y results in two solutions). The correct Y value
	 * is chosen based on the LSB of the pwd-seed:
	 *
	 *     if (LSB(y) == LSB(pwd-seed))
	 *     then
	 *         PWE = (x, y)
	 *     else
	 *         PWE = (x, p-y)
	 *
	 * The ELL API (somewhat hidden from view here) automatically
	 * performs a subtraction (P - Y) when:
	 *     - Y is even and BIT1
	 *     - Y is odd and BIT0
	 *
	 * So we choose the point type which matches the parity of
	 * pwd-seed. This means a subtraction will be performed (P - Y)
	 * if the parity of pwd-seed and the computed Y do not match.
	 */
	pwe = l_ecc_point_from_data(curve,
				is_odd ? L_ECC_POINT_TYPE_COMPRESSED_BIT1 :
				L_ECC_POINT_TYPE_COMPRESSED_BIT0, x, bytes);
	if (!pwe)
		l_error("computing y failed, was x quadratic residue?");

	return pwe;
}

static int sae_build_commit(struct sae_sm *sm, const uint8_t *addr1,
				const uint8_t *addr2, uint8_t *commit,
				size_t len, bool retry)
{
	struct l_ecc_scalar *mask;
	uint8_t *ptr = commit;
	struct l_ecc_scalar *order;
	struct ie_tlv_builder builder;

	if (retry)
		goto old_commit;

	switch (sm->sae_type) {
	case CRYPTO_SAE_HASH_TO_ELEMENT:
	{
		const struct l_ecc_point *pt =
			sm->handshake->ecc_sae_pts[sm->group_retry];

		sm->pwe = crypto_derive_sae_pwe_from_pt_ecc(addr1, addr2, pt);
		break;
	}
	case CRYPTO_SAE_LOOPING:
		sm->pwe = sae_compute_pwe(sm->curve, sm->handshake->passphrase,
						addr1, addr2);
		break;
	}

	if (!sm->pwe) {
		l_error("could not compute PWE");
		return -EIO;
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

	/*
	 * 12.4.7.4 Encoding and decoding of SAE Commit messages
	 * Refer to Table 9-40 for order and Table 9-41 for presence
	 * of elements
	 */

	/* "a Transaction Sequence Number of 1" */
	l_put_le16(1, ptr);
	ptr += 2;

	/* "a Status Code of SUCCESS or SAE_HASH_TO_ELEMENT" */
	l_put_le16(sae_status_code(sm), ptr);
	ptr += 2;

	/* group */
	l_put_le16(sm->group, ptr);
	ptr += 2;

	if (sm->sae_type == CRYPTO_SAE_LOOPING && sm->token) {
		memcpy(ptr, sm->token, sm->token_len);
		ptr += sm->token_len;
	}

	ptr += l_ecc_scalar_get_data(sm->scalar, ptr, L_ECC_SCALAR_MAX_BYTES);
	ptr += l_ecc_point_get_data(sm->element, ptr, L_ECC_POINT_MAX_BYTES);

	ie_tlv_builder_init(&builder, ptr, len - (ptr - commit));

	if (sm->sae_type != CRYPTO_SAE_LOOPING && sm->rejected_groups) {
		ie_tlv_builder_next(&builder, IE_TYPE_REJECTED_GROUPS);
		ie_tlv_builder_set_data(&builder, sm->rejected_groups + 1,
				sm->rejected_groups[0] * sizeof(uint16_t));
	}

	if (sm->sae_type != CRYPTO_SAE_LOOPING && sm->token) {
		ie_tlv_builder_next(&builder,
					IE_TYPE_ANTI_CLOGGING_TOKEN_CONTAINER);
		ie_tlv_builder_set_data(&builder, sm->token, sm->token_len);
	}

	if (sm->sae_type == CRYPTO_SAE_HASH_TO_ELEMENT &&
					sm->handshake->password_identifier) {
		ie_tlv_builder_next(&builder, IE_TYPE_PASSWORD_IDENTIFIER);
		ie_tlv_builder_set_data(&builder,
				sm->handshake->password_identifier,
				strlen(sm->handshake->password_identifier));
	}

	ie_tlv_builder_finalize(&builder, &len);

	return ptr - commit + len;
}

static bool sae_send_confirm(struct sae_sm *sm)
{
	uint8_t confirm[SAE_MAX_HASH_LEN];
	uint8_t body[sizeof(confirm) + 6];
	uint8_t *ptr = body;
	ssize_t r;

	/*
	 * confirm = CN(KCK, send-confirm, commit-scalar, COMMIT-ELEMENT,
	 *			peer-commit-scalar, PEER-COMMIT-ELEMENT)
	 */
	r = sae_cn(sm, sm->sc, sm->scalar, sm->element, sm->p_scalar,
			sm->p_element, confirm);
	if (r < 0)
		return false;

	l_put_le16(2, ptr);
	ptr += 2;
	l_put_le16(0, ptr);
	ptr += 2;
	l_put_le16(sm->sc, ptr);
	ptr += 2;
	memcpy(ptr, confirm, r);
	ptr += r;

	sae_debug("Sending Confirm to "MAC" sc=%u",
			MAC_STR(sm->handshake->aa), sm->sc);

	sm->tx_auth(body, ptr - body, sm->user_data);
	return true;
}

static int sae_calculate_keys(struct sae_sm *sm)
{
	unsigned int nbytes = l_ecc_curve_get_scalar_bytes(sm->curve);
	enum l_checksum_type hash =
		crypto_sae_hash_from_ecc_prime_len(sm->sae_type, nbytes);
	size_t hash_len = l_checksum_digest_length(hash);
	struct l_ecc_point *k_point;
	uint8_t k[L_ECC_SCALAR_MAX_BYTES];
	ssize_t klen;
	const void *salt = NULL;
	size_t salt_len = 0;
	uint8_t keyseed[SAE_MAX_HASH_LEN];
	uint8_t kck_and_pmk[SAE_MAX_HASH_LEN + 32];
	uint8_t tmp[L_ECC_SCALAR_MAX_BYTES];
	struct l_ecc_scalar *tmp_scalar;
	struct l_ecc_scalar *order;

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
	 * point (x, y) that satisfies the curve equation to its x-coordinate-
	 * i.e., if P = (x, y) then F(P) = x.
	 */
	klen = l_ecc_point_get_x(k_point, k, sizeof(k));
	l_ecc_point_free(k_point);

	if (klen < 0)
		return sae_reject(sm, SAE_STATE_COMMITTED,
				MMPDU_STATUS_CODE_UNSPECIFIED);

	/*
	 * keyseed = H(salt, k)
	 *
	 * 802.11-2020 12.4.5.4:
	 * Hash to Element case:
	 * "... a salt consisting of the concatenation of the rejected groups
	 * from each peer's Rejected Groups element shall be
	 * passed to the KDF; those of the peer with the highest MAC address go
	 * first (if only one sent a Rejected Groups element then the salt will
	 * consist of that list). "
	 *
	 * Looping case:
	 * "...the salt shall consist of a series of octets of the value zero
	 * whose length equals the length of the digest of the hash function
	 * used to instantiate H()."
	 *
	 * NOTE: We use hkdf_extract here since it is just an hmac invocation
	 * and it handles the case of the zero key for us.
	 */
	if (sm->sae_type != CRYPTO_SAE_LOOPING && sm->rejected_groups) {
		salt = sm->rejected_groups + 1;
		salt_len = sm->rejected_groups[0] * sizeof(uint16_t);
	}

	hkdf_extract(hash, salt, salt_len, 1, keyseed, k, klen);

	/*
	 * context = (commit-scalar + peer-commit-scalar) mod r
	 * Length = Q + 256
	 * kck_and_pmk = KDF-Hash-Length(keyseed, "SAE KCK and PMK", context)
	 * KCK = L(kck_and_pmk, 0, Q)
	 * PMK = L(kck_and_pmk, Q, 256)
	 *
	 * Q is the length of the digest of the H(), the hash function used
	 */
	tmp_scalar = l_ecc_scalar_new(sm->curve, NULL, 0);
	order = l_ecc_curve_get_order(sm->curve);

	l_ecc_scalar_add(tmp_scalar, sm->p_scalar, sm->scalar, order);
	l_ecc_scalar_get_data(tmp_scalar, tmp, sizeof(tmp));

	crypto_kdf(hash, keyseed, hash_len,
			"SAE KCK and PMK", strlen("SAE KCK and PMK"),
			tmp, nbytes, kck_and_pmk, hash_len + 32);

	memcpy(sm->kck, kck_and_pmk, hash_len);
	memcpy(sm->pmk, kck_and_pmk + hash_len, 32);

	/*
	 * PMKID = L((commit-scalar + peer-commit-scalar) mod r, 0, 128)
	 */
	l_ecc_scalar_add(tmp_scalar, sm->scalar, sm->p_scalar, order);
	l_ecc_scalar_get_data(tmp_scalar, tmp, sizeof(tmp));

	l_ecc_scalar_free(order);

	l_ecc_scalar_free(tmp_scalar);
	/* don't set the handshakes pmkid until confirm is verified */
	memcpy(sm->pmkid, tmp, 16);

	return 0;
}


static int sae_process_commit(struct sae_sm *sm, const uint8_t *from,
					const uint8_t *frame, size_t len)
{
	uint8_t *ptr = (uint8_t *) frame;
	unsigned int nbytes = l_ecc_curve_get_scalar_bytes(sm->curve);
	int r;

	ptr += 2;

	sm->p_scalar = l_ecc_scalar_new(sm->curve, ptr, nbytes);
	if (!sm->p_scalar) {
		l_error("Server sent invalid P_Scalar during commit");
		return sae_reject(sm, SAE_STATE_COMMITTED,
				MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP);
	}

	ptr += nbytes;

	sm->p_element = l_ecc_point_from_data(sm->curve, L_ECC_POINT_TYPE_FULL,
						ptr, nbytes * 2);
	if (!sm->p_element) {
		l_error("Server sent invalid P_Element during commit");
		return sae_reject(sm, SAE_STATE_COMMITTED,
				MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP);
	}

	/*
	 * If they match those sent as part of the protocol instance's own
	 * SAE Commit message, the frame shall be silently discarded (because
	 * it is evidence of a reflection attack) and the t0 (retransmission)
	 * timer shall be set.
	 */
	if (l_ecc_scalars_are_equal(sm->p_scalar, sm->scalar) ||
			l_ecc_points_are_equal(sm->p_element, sm->element)) {
		l_warn("peer scalar or element matched own, discarding frame");
		return -ENOMSG;
	}

	sm->sc++;

	r = sae_calculate_keys(sm);
	if (r != 0)
		return r;

	if (!sae_send_confirm(sm))
		return -EPROTO;

	sm->state = SAE_STATE_CONFIRMED;

	return 0;
}

static bool sae_verify_confirm(struct sae_sm *sm, const uint8_t *frame)
{
	uint8_t check[SAE_MAX_HASH_LEN];
	uint16_t rc = l_get_le16(frame);
	ssize_t r;

	r = sae_cn(sm, rc, sm->p_scalar, sm->p_element, sm->scalar,
			sm->element, check);
	if (r < 0)
		return false;

	if (memcmp(frame + 2, check, r))
		return false;

	sm->rc = rc;

	return true;
}

static int sae_process_confirm(struct sae_sm *sm, const uint8_t *from,
				const uint8_t *frame, size_t len)
{
	const uint8_t *ptr = frame;

	/*
	 * If processing is unsuccessful and the SAE Confirm message is not
	 * verified, protocol instance shall remain in Confirmed state.
	 *
	 * NOTE: We diverge from the protocol here and bail out early
	 */
	if (!sae_verify_confirm(sm, ptr)) {
		l_error("SAE: Confirm could not be verified");
		return sae_reject(sm, SAE_STATE_CONFIRMED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
	}

	/* Sc shall be set to the value 2^16 - 1 */
	sm->sc = 0xffff;

	handshake_state_set_pmkid(sm->handshake, sm->pmkid);
	handshake_state_set_pmk(sm->handshake, sm->pmk, 32);

	sm->state = SAE_STATE_ACCEPTED;

	if (!sm->handshake->authenticator) {
		sae_debug("Sending Associate to "
				MAC, MAC_STR(sm->handshake->aa));
		sm->tx_assoc(sm->user_data);
	} else {
		if (!sae_send_confirm(sm))
			return -EPROTO;
	}

	return 0;
}

static bool sae_send_commit(struct sae_sm *sm, bool retry)
{
	struct handshake_state *hs = sm->handshake;
	/* regular commit + 3x IEs (257 bytes) + 6 bytes header */
	uint8_t commit[L_ECC_SCALAR_MAX_BYTES + L_ECC_POINT_MAX_BYTES + 777];
	int r;

	r = sae_build_commit(sm, hs->spa, hs->aa,
					commit, sizeof(commit), retry);
	if (r < 0)
		return false;

	sae_debug("Sending Commit to "MAC, MAC_STR(hs->aa));

	sm->tx_auth(commit, r, sm->user_data);

	return true;
}

static bool sae_assoc_timeout(struct auth_proto *ap)
{
	struct sae_sm *sm = l_container_of(ap, struct sae_sm, ap);

	if (sm->assoc_retry >= SAE_MAX_ASSOC_RETRY)
		return false;

	sm->assoc_retry++;

	sae_debug("Retry Associate to "MAC, MAC_STR(sm->handshake->aa));

	sm->tx_assoc(sm->user_data);

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
static int sae_process_anti_clogging(struct sae_sm *sm, const uint8_t *ptr,
					size_t len)
{
	/*
	 * 802.11 doesn't talk about validating the group of the Anti-Clogging
	 * Request message.  We assume here that the group is something that
	 * we would have potentially sent
	 */
	if (len < 2)
		return -EBADMSG;

	if (sae_valid_group(sm, l_get_le16(ptr)) < 0)
		return -EBADMSG;

	len -= 2;
	ptr += 2;

	/*
	 * 802.11-2020, Table 9-41:
	 * When the hash-to-element method is used to derive the PWE, the
	 * Anti-Clogging Token Container element is present if the
	 * Status Code field is ANTI_CLOGGING_TOKEN_REQUIRED
	 */
	if (sm->sae_type != CRYPTO_SAE_LOOPING) {
		if (len < 3)
			return -EBADMSG;

		if (ptr[0] != IE_TYPE_EXTENSION || ptr[2] != 93 ||
				ptr[1] < 2 || len < ptr[1] + 2u)
			return -EBADMSG;

		len = ptr[1] - 1;
		ptr += 3;
	}

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
	if (len < 1 || len > 256) {
		l_error("anti-clogging token size invalid %zu", len);
		return -EBADMSG;
	}

	sae_debug("Processed anti-clogging token");

	l_free(sm->token);
	sm->token = l_memdup(ptr, len);
	sm->token_len = len;
	sm->sync = 0;

	sae_send_commit(sm, true);

	return -EAGAIN;
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
	if (l_get_le16(frame) != sm->group)
		return sae_reject(sm, SAE_STATE_COMMITTED,
				MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP);

	return 0;
}

/*
 * 802.11-2016 - 12.4.8.6.4 Protocol instance behavior - Committed state
 */
static int sae_verify_committed(struct sae_sm *sm, uint16_t transaction,
					uint16_t status, const uint8_t *frame,
					size_t len)
{
	unsigned int skip;
	struct ie_tlv_iter iter;

	if (sm->handshake->authenticator &&
			transaction == SAE_STATE_CONFIRMED) {
		enum l_checksum_type hash =
			crypto_sae_hash_from_ecc_prime_len(sm->sae_type,
				l_ecc_curve_get_scalar_bytes(sm->curve));
		size_t hash_len = l_checksum_digest_length(hash);

		if (len < hash_len + 2) {
			l_error("SAE: Confirm packet too short");
			return -EBADMSG;
		}

		/*
		 * TODO: Add extra functionality such as supporting
		 * anti-clogging tokens and tracking rejected groups. Note
		 * that the cryptographic confirm field value will be checked
		 * at a later point.
		 */

		return 0;
	} else if (transaction == SAE_STATE_CONFIRMED) {
		/*
		 * Upon receipt of a Con event...
		 * Then the protocol instance checks the value of Sync. If it
		 * is greater than dot11RSNASAESync, the protocol instance
		 * shall send a Del event to the parent process and transition
		 * back to Nothing state.
		 * If Sync is not greater than dot11RSNASAESync, the protocol
		 * instance shall increment Sync, transmit the last SAE Commit
		 * message sent to the peer...
		 */
		if (sm->sync > SAE_SYNC_MAX)
			return -ETIMEDOUT;

		sm->sync++;
		sae_send_commit(sm, true);

		return -EAGAIN;
	}

	if (status == MMPDU_STATUS_CODE_ANTI_CLOGGING_TOKEN_REQ)
		return sae_process_anti_clogging(sm, frame, len);

	if (status == MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP) {
		/*
		 * TODO: hostapd in its current state does not include the
		 * group number as it should. This is a violation of the spec,
		 * but there isn't much we can do about it. We simply treat this
		 * response as if its rejecting our last commit message (which
		 * it most likely is). If/When this is fixed we should be
		 * checking that the group matches here, e.g.
		 *
		 * if (l_get_le16(frame) != sm->group)
		 *	return false;
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
			return -ENOMSG;

		sae_rejected_groups_append(sm, L_CPU_TO_LE16(sm->group));

		/*
		 * "If the rejected group matches the last offered group, the
		 * protocol instance shall choose a different group and generate
		 * the PWE and the secret values according to 12.4.5.2; it then
		 * generates and transmits a new SAE Commit message to the peer,
		 * zeros Sync, sets the t0 (retransmission) timer, and remains
		 * in Committed state"
		 */
		if (sae_choose_next_group(sm) < 0) {
			/*
			 * "If there are no other groups to choose, the protocol
			 * instance shall send a Del event to the parent process
			 * and transitions back to Nothing state"
			 */
			sm->state = SAE_STATE_NOTHING;
			goto reject_unsupp_group;
		}

		sae_debug("AP rejected group, trying again with group %u",
				sm->group);

		sm->sync = 0;
		sae_send_commit(sm, false);

		return -EAGAIN;
	}

	/*
	 * If the Status is some other nonzero value, the frame shall be
	 * silently discarded and the t0 (retransmission) timer shall be set.
	 */
	switch (status) {
	case 0:
	case MMPDU_STATUS_CODE_SAE_HASH_TO_ELEMENT:
		if (status != sae_status_code(sm))
			return -EBADMSG;
		break;
	case MMPDU_STATUS_CODE_UNKNOWN_PASSWORD_IDENTIFIER:
		sae_debug("Incorrect password identifier, check "
				"[Security].PasswordIdentifier");
		/* fall through */
	default:
		return -ENOMSG;
	}

	if (len < 2)
		return -EBADMSG;

	if (l_get_le16(frame) != sm->group) {
		l_error("SAE: Peer tried to change group -- Reject");
		goto reject_unsupp_group;
	}

	len -= 2;
	frame += 2;

	skip = l_ecc_curve_get_scalar_bytes(sm->curve) * 3;
	if (len < skip)
		return -EBADMSG;

	/* If H2E isn't being used, there should be no IEs in use */
	if (status == 0)
		return 0;

	len -= skip;
	frame += skip;

	ie_tlv_iter_init(&iter, frame, len);

	while (ie_tlv_iter_next(&iter)) {
		switch (ie_tlv_iter_get_tag(&iter)) {
		/*
		 * If the peer's SAE Commit message contains a Rejected Groups
		 * element, the list of rejected groups shall be checked to
		 * ensure that all of the groups in the list are groups that
		 * would be rejected. If any groups in the list would not be
		 * rejected then processing of the SAE Commit message
		 * terminates and the STA shall reject the peer's
		 * authentication.
		 *
		 * NOTE: We currently only support the Initiator role, and so
		 * do not reject any groups.  We should never receive this
		 * element
		 */
		case IE_TYPE_REJECTED_GROUPS:
			l_error("SAE: Unexpected Rejected Groups IE");
			return sae_reject(sm, SAE_STATE_COMMITTED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
		/* We don't request tokens, so we shouldn't get any */
		case IE_TYPE_ANTI_CLOGGING_TOKEN_CONTAINER:
			l_error("SAE: Unexpected Anti-Clogging Container IE");
			return sae_reject(sm, SAE_STATE_COMMITTED,
					MMPDU_STATUS_CODE_UNSPECIFIED);
		}
	}

	return 0;

reject_unsupp_group:
	return sae_reject(sm, SAE_STATE_COMMITTED,
			MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP);
}

/*
 * 802.11-2016 - 12.4.8.6.5 Protocol instance behavior - Confirmed state
 */
static int sae_verify_confirmed(struct sae_sm *sm, uint16_t trans,
					uint16_t status, const uint8_t *frame,
					size_t len)
{
	if (trans == SAE_STATE_CONFIRMED) {
		enum l_checksum_type hash =
			crypto_sae_hash_from_ecc_prime_len(sm->sae_type,
				l_ecc_curve_get_scalar_bytes(sm->curve));
		size_t hash_len = l_checksum_digest_length(hash);

		/* Most likely the password is wrong */
		if (status == MMPDU_STATUS_CODE_UNSPECIFIED && len == 0)
			return -ENOKEY;

		if (status != MMPDU_STATUS_CODE_SUCCESS)
			return -EPROTO;

		if (len < hash_len + 2) {
			l_error("SAE: Confirm packet too short");
			return -EBADMSG;
		}

		return 0;
	}

	/*
	 * Upon receipt of a Com event, the t0 (retransmission) timer shall be
	 * canceled. If the Status is nonzero, the frame shall be silently
	 * discarded, the t0 (retransmission) timer set, and the protocol
	 * instance shall remain in the Confirmed state.
	 */
	if (status != 0)
		return -ENOMSG;

	/*
	 * If Sync is greater than dot11RSNASAESync, the protocol instance
	 * shall send the parent process a Del event and transitions back to
	 * Nothing state.
	 */
	if (sm->sync > SAE_SYNC_MAX)
		return -ETIMEDOUT;

	if (len < 2)
		return -EBADMSG;

	/* frame shall be silently discarded */
	if (l_get_le16(frame) != sm->group)
		return -EBADMSG;

	/*
	 * Because of kernel retransmit behavior on missed ACKs plus hostapd's
	 * incorrect handling of confirm packets while in accepted state the
	 * following can happen:
	 *
	 * 1. Client sends commit, not acked (committed state)
	 * 2. AP receives commit, sends commit reply (committed state)
	 * 3. Client retransmits original commit
	 * 4. Client receives AP's commit, sends confirm (confirmed state)
	 * 5. AP receives clients retransmitted commit, sends only commit
	 * 6. AP receives clients confirm and accepts (accepted state)
	 * 7. Client receives AP's commit and sends both commit + confirm
	 *    (the code below).
	 * 8. AP receives clients commit while in accepted state, and deauths
	 *
	 * Due to this, any commit received while in a confirmed state will be
	 * ignored by IWD since it is probably caused by this retransmission
	 * and sending the commit/confirm below would likely cause hostapd to
	 * deauth us.
	 *
	 * As for non-sta (currently not used) we want to keep with the spec.
	 */
	if (!sm->handshake->authenticator)
		return -EBADMSG;

	/*
	 * the protocol instance shall increment Sync, increment Sc, and
	 * transmit its Commit and Confirm (with the new Sc value) messages.
	 */
	sm->sync++;
	sm->sc++;

	sae_send_commit(sm, true);

	if (!sae_send_confirm(sm))
		return -EPROTO;

	return -EAGAIN;
}

/*
 * 802.11-2016 - 12.4.8.6.6 Protocol instance behavior - Accepted state
 */
static int sae_verify_accepted(struct sae_sm *sm, uint16_t trans,
					uint16_t status, const uint8_t *frame,
					size_t len)
{
	uint16_t sc;

	/*
	 * 12.4.8.6.1 Parent process behavior
	 *
	 * "Upon receipt of an SAE Commit message... and it is in Accepted
	 * state, the scalar in the received frame is checked against the
	 * peer-scalar used in authentication of the existing protocol instance
	 * (in Accepted state). If it is identical, the frame shall be dropped"
	 */
	if (trans == SAE_STATE_COMMITTED) {
		bool drop;
		unsigned int nbytes = l_ecc_curve_get_scalar_bytes(sm->curve);
		struct l_ecc_scalar *p_scalar;

		if (len < nbytes + 2)
			return -EMSGSIZE;

		p_scalar = l_ecc_scalar_new(sm->curve, frame + 2, nbytes);

		drop = l_ecc_scalars_are_equal(sm->p_scalar, p_scalar);
		l_ecc_scalar_free(p_scalar);

		if (drop)
			return -EBADMSG;

		l_error("received transaction %u in accepted state", trans);
		return -EPROTO;
	}

	if (sm->sync > SAE_SYNC_MAX)
		return -ETIMEDOUT;

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

	if (!sae_send_confirm(sm))
		return -EPROTO;

	return -EAGAIN;
}

static const char *sae_state_to_str(enum sae_state state)
{
	switch (state) {
	case SAE_STATE_NOTHING:
		return "nothing";
	case SAE_STATE_COMMITTED:
		return "committed";
	case SAE_STATE_CONFIRMED:
		return "confirmed";
	case SAE_STATE_ACCEPTED:
		return "accepted";
	}

	return "unknown";
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
	return -EPROTO;
}

static int sae_rx_authenticate(struct auth_proto *ap,
				const uint8_t *frame, size_t len)
{
	struct sae_sm *sm = l_container_of(ap, struct sae_sm, ap);
	const struct mmpdu_header *hdr = (const struct mmpdu_header *) frame;
	const struct mmpdu_authentication *auth = mmpdu_body(hdr);
	int ret;
	uint16_t transaction = L_LE16_TO_CPU(auth->transaction_sequence);
	uint16_t status = L_LE16_TO_CPU(auth->status);

	sae_debug("Received frame transaction=%u status=%u state=%s",
			transaction, status, sae_state_to_str(sm->state));

	len -= mmpdu_header_len(hdr);

	ret = sae_verify_packet(sm, transaction, status, auth->ies, len - 6);
	if (ret != 0) {
		if (ret < 0 && ret != -EAGAIN)
			sae_debug("Frame did not verify (%s)", strerror(-ret));

		return ret;
	}

	switch (transaction) {
	case SAE_STATE_COMMITTED:
		return sae_process_commit(sm, hdr->address_2, auth->ies,
						len - 6);
	case SAE_STATE_CONFIRMED:
		return sae_process_confirm(sm, hdr->address_2, auth->ies,
						len - 6);
	default:
		l_error("invalid transaction sequence %u", transaction);
	}

	/* should never get here */
	return -EPROTO;
}

static int sae_rx_associate(struct auth_proto *ap, const uint8_t *frame,
				size_t len)
{
	const struct mmpdu_header *mpdu = (const struct mmpdu_header *)frame;
	const struct mmpdu_association_response *body = mmpdu_body(mpdu);

	if (body->status_code != 0)
		return -EPROTO;

	return 0;
}

static bool sae_start(struct auth_proto *ap)
{
	struct sae_sm *sm = l_container_of(ap, struct sae_sm, ap);

	if (sm->handshake->authenticator)
		memcpy(sm->peer, sm->handshake->spa, 6);
	else
		memcpy(sm->peer, sm->handshake->aa, 6);

	if (sm->sae_type == CRYPTO_SAE_LOOPING && !sm->handshake->passphrase) {
		l_error("SAE: No passphrase set");
		return false;
	}

	if (sae_choose_next_group(sm) < 0)
		return false;

	sm->state = SAE_STATE_COMMITTED;
	return sae_send_commit(sm, false);
}

bool sae_sm_is_h2e(struct auth_proto *ap)
{
	struct sae_sm *sm = l_container_of(ap, struct sae_sm, ap);

	return sm->sae_type != CRYPTO_SAE_LOOPING;
}

static void sae_free(struct auth_proto *ap)
{
	struct sae_sm *sm = l_container_of(ap, struct sae_sm, ap);

	sae_reset_state(sm);

	l_free(sm->token);
	sm->token = NULL;

	if (sm->rejected_groups)
		free(sm->rejected_groups);

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
	const void *rsnxe;

	sm = l_new(struct sae_sm, 1);

	sm->group_retry = -1;

	sm->tx_auth = tx_auth;
	sm->tx_assoc = tx_assoc;
	sm->user_data = user_data;
	sm->handshake = hs;
	sm->state = SAE_STATE_NOTHING;
	sm->force_default_group = hs->force_default_ecc_group;

	sm->ap.start = sae_start;
	sm->ap.free = sae_free;
	sm->ap.rx_authenticate = sae_rx_authenticate;
	sm->ap.rx_associate = sae_rx_associate;
	sm->ap.assoc_timeout = sae_assoc_timeout;

	rsnxe = hs->authenticator ? hs->supplicant_rsnxe :
						hs->authenticator_rsnxe;

	if (ie_rsnxe_capable(rsnxe, IE_RSNX_SAE_H2E) && hs->ecc_sae_pts) {
		sae_debug("Using SAE H2E");
		sm->sae_type = CRYPTO_SAE_HASH_TO_ELEMENT;
	} else {
		sae_debug("Using SAE Hunting and Pecking");
		sm->sae_type = CRYPTO_SAE_LOOPING;
	}

	return &sm->ap;
}

static int sae_init(void)
{
	if (getenv("IWD_SAE_DEBUG"))
		debug = true;

	return 0;
}

static void sae_exit(void)
{
}

IWD_MODULE(sae, sae_init, sae_exit);
