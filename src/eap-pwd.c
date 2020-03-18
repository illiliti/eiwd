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

#include <stdio.h>

#include <ell/ell.h>

#include "src/missing.h"
#include "src/eap.h"
#include "src/eap-private.h"
#include "src/crypto.h"
#include "src/util.h"

#define EAP_PWD_GROUP_DESC	19
#define EAP_PWD_RAND_FN		0x01
#define EAP_PWD_PRF		0x01

/* EAP header + PWD-Exch */
#define EAP_PWD_HDR_LEN		6
#define EAP_PWD_L_BIT		(1 << 7)
#define EAP_PWD_M_BIT		(1 << 6)

enum eap_pwd_prep {
	EAP_PWD_PREP_NONE =	0x00,
	EAP_PWD_PREP_MS =	0x01,
	EAP_PWD_PREP_SASL =	0x02
};

enum eap_pwd_exch {
	EAP_PWD_EXCH_RESERVED = 0,
	EAP_PWD_EXCH_ID,
	EAP_PWD_EXCH_COMMIT,
	EAP_PWD_EXCH_CONFIRM
};

enum eap_pwd_state {
	EAP_PWD_STATE_INIT = 0,
	EAP_PWD_STATE_ID,
	EAP_PWD_STATE_COMMIT,
	EAP_PWD_STATE_CONFIRM
};

struct eap_pwd_handle {
	enum eap_pwd_state state;
	enum eap_pwd_prep prep;
	char *identity;
	char *password;
	const struct l_ecc_curve *curve;
	struct l_ecc_point *pwe;
	struct l_ecc_point *element_s;
	struct l_ecc_point *element_p;
	uint32_t ciphersuite;
	struct l_ecc_scalar *scalar_s;
	struct l_ecc_scalar *scalar_p;
	struct l_ecc_scalar *p_rand;
	uint8_t *rx_frag_buf;
	uint16_t rx_frag_total;
	uint16_t rx_frag_count;
	uint8_t *tx_frag_buf;
	uint8_t *tx_frag_pos;
	uint16_t tx_frag_remaining;
};

/* RFC 5931, Section 2.5 - Key Derivation Function */
static bool kdf(uint8_t *key, size_t key_len, const char *label,
		size_t label_len, void *out, size_t olen)
{
	struct l_checksum *hmac;
	struct iovec iov[4];
	uint16_t ibuf, i = 1;
	uint16_t L = L_CPU_TO_BE16(olen * 8);
	size_t len = 0;

	while (len < olen) {
		int iov_pos = 0;

		hmac = l_checksum_new_hmac(L_CHECKSUM_SHA256, key, key_len);
		if (!hmac)
			return false;

		/* PRF(key, K(i - 1) | i | label | L) */
		if (i > 1) {
			iov[iov_pos].iov_base = out + len - 32;
			iov[iov_pos++].iov_len = 32;
		}

		ibuf = L_CPU_TO_BE16(i);
		iov[iov_pos].iov_base = (void *) &ibuf;
		iov[iov_pos++].iov_len = 2;
		iov[iov_pos].iov_base = (void *)label;
		iov[iov_pos++].iov_len = label_len;
		iov[iov_pos].iov_base = &L;
		iov[iov_pos++].iov_len = 2;

		if (!l_checksum_updatev(hmac, iov, iov_pos)) {
			l_checksum_free(hmac);
			return false;
		}

		l_checksum_get_digest(hmac, out + len, minsize(olen - len, 32));
		l_checksum_free(hmac);

		len += 32;
		i++;
	}

	return true;
}

static bool eap_pwd_reset_state(struct eap_state *eap)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);

	pwd->state = EAP_PWD_STATE_INIT;

	l_free(pwd->tx_frag_buf);
	pwd->tx_frag_buf = NULL;
	pwd->tx_frag_pos = NULL;
	pwd->tx_frag_remaining = 0;

	l_free(pwd->rx_frag_buf);
	pwd->rx_frag_buf = NULL;
	pwd->rx_frag_count = 0;
	pwd->rx_frag_total = 0;

	pwd->prep = EAP_PWD_PREP_NONE;
	pwd->ciphersuite = 0;

	l_ecc_point_free(pwd->pwe);
	pwd->pwe = NULL;
	l_ecc_point_free(pwd->element_p);
	pwd->element_p = NULL;
	l_ecc_point_free(pwd->element_s);
	pwd->element_s = NULL;
	l_ecc_scalar_free(pwd->scalar_p);
	pwd->scalar_p = NULL;
	l_ecc_scalar_free(pwd->scalar_s);
	pwd->scalar_s = NULL;
	l_ecc_scalar_free(pwd->p_rand);
	pwd->p_rand = NULL;

	return true;
}

static void eap_pwd_free(struct eap_state *eap)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);

	eap_pwd_reset_state(eap);
	l_free(pwd->identity);

	if (pwd->password) {
		explicit_bzero(pwd->password, strlen(pwd->password));
		l_free(pwd->password);
	}

	l_free(pwd);

	eap_set_data(eap, NULL);
}

static void eap_pwd_send_response(struct eap_state *eap,
					uint8_t *pkt, size_t len)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);
	size_t mtu = eap_get_mtu(eap);
	uint8_t frag[mtu];
	uint8_t *pos = frag;
	/* first fragment data bytes (mtu - header - Total-Length) */
	uint16_t send_bytes = mtu - EAP_PWD_HDR_LEN - 2;

	/* packet will fit within mtu */
	if (len <= mtu) {
		eap_send_response(eap, EAP_TYPE_PWD, pkt, len);
		return;
	}

	if (pwd->tx_frag_buf) {
		l_error("already processing fragment, cannot send response");
		return;
	}

	/* header */
	memcpy(pos, pkt, 5);
	pos += 5;
	/* PWD-Exch, first frag, so L and M are both set */
	*pos++ = pwd->state | EAP_PWD_L_BIT | EAP_PWD_M_BIT;
	/* Total-Length */
	l_put_be16((uint16_t)len, pos);
	pos += 2;
	/* copy packet data bytes */
	memcpy(pos, pkt + EAP_PWD_HDR_LEN, send_bytes);

	pwd->tx_frag_remaining = len - EAP_PWD_HDR_LEN - send_bytes;

	l_info("sending initial fragment, %zu bytes", mtu);

	eap_send_response(eap, EAP_TYPE_PWD, frag, mtu);

	/* alloc/copy remainder of packet to frag buf */
	pwd->tx_frag_buf = l_malloc(pwd->tx_frag_remaining);

	memcpy(pwd->tx_frag_buf, pkt + EAP_PWD_HDR_LEN + send_bytes,
			pwd->tx_frag_remaining);

	pwd->tx_frag_pos = pwd->tx_frag_buf;
}

static void eap_pwd_handle_id(struct eap_state *eap,
				const uint8_t *pkt, size_t len)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);
	uint16_t group;
	uint8_t rand_fn;
	uint8_t prf;
	uint32_t token;
	uint8_t counter = 0;
	uint8_t resp[15 + strlen(pwd->identity)];
	uint8_t *pos;
	uint8_t pwd_seed[32];
	uint8_t pwd_value[L_ECC_SCALAR_MAX_BYTES];	/* used as X value */
	size_t nbytes;
	bool found = false;

	/*
	 * Group desc (2) + Random func (1) + prf (1) + token (4) + prep (1) +
	 * Identity (at least 1 byte)
	 */
	if (len < 9) {
		l_error("bad packet length");
		goto error;
	}

	if (pwd->state != EAP_PWD_STATE_INIT) {
		l_error("received ID request in invalid state");
		goto error;
	}

	pwd->state = EAP_PWD_STATE_ID;

	group = l_get_be16(pkt);

	pwd->curve = l_ecc_curve_get_ike_group(group);
	if (!pwd->curve) {
		l_error("group %d not supported", group);
		goto error;
	}

	rand_fn = pkt[2];
	if (rand_fn != EAP_PWD_RAND_FN) {
		l_error("rand_fn %d not supported", rand_fn);
		goto error;
	}

	prf = pkt[3];
	if (prf != EAP_PWD_PRF) {
		l_error("PRF function %d not supported", prf);
		goto error;
	}

	/*
	 * RFC 5931 Section 3.2.1
	 * The Group Description, Random Function, and PRF together, and in that
	 * order, comprise the Ciphersuite...
	 */
	pwd->ciphersuite = l_get_u32(pkt);
	token = l_get_u32(pkt + 4);
	pwd->prep = pkt[8];

	if (pwd->prep != EAP_PWD_PREP_NONE) {
		/*
		 * TODO: Support other PW prep types
		 */
		l_error("prep type %d not currently supported", pwd->prep);
		goto error;
	}

	nbytes = l_ecc_curve_get_scalar_bytes(pwd->curve);

	while (counter < 20) {
		struct l_ecc_point *pwe = NULL;

		counter++;

		/* pwd-seed = H(token|peer-ID|server-ID|password|counter) */
		hkdf_extract(L_CHECKSUM_SHA256, NULL, 0, 5, pwd_seed, &token, 4,
				pwd->identity, strlen(pwd->identity), pkt + 9,
				len - 9, pwd->password, strlen(pwd->password),
				&counter, (size_t) 1);

		/*
		 * pwd-value = KDF(pwd-seed, "EAP-pwd Hunting And Pecking",
		 *                 len(p))
		 */
		kdf(pwd_seed, 32, "EAP-pwd Hunting And Pecking",
				strlen("EAP-pwd Hunting And Pecking"),
				pwd_value, nbytes);

		if (!(pwd_seed[31] & 1))
			pwe = l_ecc_point_from_data(pwd->curve,
					L_ECC_POINT_TYPE_COMPRESSED_BIT1,
					pwd_value, nbytes);
		else
			pwe = l_ecc_point_from_data(pwd->curve,
					L_ECC_POINT_TYPE_COMPRESSED_BIT0,
					pwd_value, nbytes);

		if (!pwe)
			continue;

		if (!found) {
			found = true;
			pwd->pwe = pwe;
		} else
			l_ecc_point_free(pwe);
	}

	explicit_bzero(pwd_seed, sizeof(pwd_seed));
	explicit_bzero(pwd_value, sizeof(pwd_value));

	pos = resp + 5; /* header */
	*pos++ = EAP_PWD_EXCH_ID;
	l_put_be16(group, pos);
	pos += 2;
	*pos++ = rand_fn;
	*pos++ = prf;
	l_put_u32(token, pos);
	pos += 4;
	*pos++ = pwd->prep;
	memcpy(pos, pwd->identity, strlen(pwd->identity));
	pos += strlen(pwd->identity);

	eap_pwd_send_response(eap, resp, pos - resp);

	return;

error:
	eap_method_error(eap);
}

static void eap_pwd_handle_commit(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);
	uint8_t resp[L_ECC_POINT_MAX_BYTES + L_ECC_SCALAR_MAX_BYTES + 6];
	uint8_t *pos;
	struct l_ecc_scalar *p_mask;
	struct l_ecc_scalar *order;
	size_t nbytes = l_ecc_curve_get_scalar_bytes(pwd->curve);

	/* [Element (nbytes * 2)][Scalar (nbytes)] */
	if (len != nbytes + nbytes * 2) {
		l_error("bad packet length, expected %zu, got %zu",
				nbytes + nbytes * 2, len);
		goto error;
	}

	if (pwd->state != EAP_PWD_STATE_ID) {
		l_error("received commit request in invalid state");
		goto error;
	}

	pwd->state = EAP_PWD_STATE_COMMIT;

	/*
	 * Commit contains Element_S (nbytes * 2) then Scalar_s (nbytes)
	 */
	pwd->element_s = l_ecc_point_from_data(pwd->curve,
						L_ECC_POINT_TYPE_FULL,
						pkt, nbytes * 2);
	if (!pwd->element_s) {
		l_error("Server sent invalid Element_S during commit");
		goto error;
	}

	pwd->scalar_s = l_ecc_scalar_new(pwd->curve, pkt + nbytes * 2, nbytes);
	if (!pwd->scalar_s) {
		l_error("Server sent invalid Scalar_S during commit");
		goto error;
	}

	pwd->p_rand = l_ecc_scalar_new_random(pwd->curve);
	p_mask = l_ecc_scalar_new_random(pwd->curve);
	pwd->scalar_p = l_ecc_scalar_new(pwd->curve, NULL, 0);

	order = l_ecc_curve_get_order(pwd->curve);

	l_ecc_scalar_add(pwd->scalar_p, pwd->p_rand, p_mask, order);

	l_ecc_scalar_free(order);

	pwd->element_p = l_ecc_point_new(pwd->curve);
	/* p_mask * PWE */
	l_ecc_point_multiply(pwd->element_p, p_mask, pwd->pwe);

	l_ecc_scalar_free(p_mask);

	/* inv(p_mask * PWE) */
	l_ecc_point_inverse(pwd->element_p);

	/* send element_p and scalar_p */
	pos = resp + 5; /* header */
	*pos++ = EAP_PWD_EXCH_COMMIT;
	pos += l_ecc_point_get_data(pwd->element_p, pos, nbytes * 2);
	pos += l_ecc_scalar_get_data(pwd->scalar_p, pos, nbytes);

	eap_pwd_send_response(eap, resp, pos - resp);

	return;

error:
	eap_method_error(eap);
}

static void eap_pwd_handle_confirm(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);
	struct l_ecc_point *kp;
	uint8_t resp[38];
	uint8_t *pos;
	uint8_t confirm_s[32];
	uint8_t confirm_p[32];
	uint8_t expected_confirm_s[32];
	uint8_t mk[32];
	uint8_t msk_emsk[128], session_id[33];
	/* buffers used for the final hash */
	uint8_t kpx[L_ECC_SCALAR_MAX_BYTES];
	uint8_t scalar_s[L_ECC_SCALAR_MAX_BYTES];
	uint8_t scalar_p[L_ECC_SCALAR_MAX_BYTES];
	uint8_t element_s[L_ECC_POINT_MAX_BYTES];
	uint8_t element_p[L_ECC_POINT_MAX_BYTES];
	ssize_t plen, clen;

	if (len != 32) {
		l_error("bad packet length");
		goto error;
	}

	if (pwd->state != EAP_PWD_STATE_COMMIT) {
		l_error("received confirm request in invalid state");
		goto error;
	}

	pwd->state = EAP_PWD_STATE_CONFIRM;

	memcpy(confirm_s, pkt, 32);

	kp = l_ecc_point_new(pwd->curve);

	/* compute KP = (p_rand * (Scalar_S * PWE + Element_S)) */
	l_ecc_point_multiply(kp, pwd->scalar_s, pwd->pwe);

	l_ecc_point_add(kp, kp, pwd->element_s);

	l_ecc_point_multiply(kp, pwd->p_rand, kp);

	/*
	 * We just need to store clen/plen once. Since all these buffers are
	 * created with enough bytes in mind we know these won't fail. Also, all
	 * scalar/point objects were created with the same curve, so it can be
	 * safe to assume the return values will not change from what clen/plen
	 * already are.
	 */
	clen = l_ecc_point_get_x(kp, kpx, sizeof(kpx));
	if (clen < 0)
		goto invalid_point;

	plen = l_ecc_point_get_data(pwd->element_s, element_s,
					sizeof(element_s));
	if (plen < 0)
		goto invalid_point;

	if (l_ecc_point_get_data(pwd->element_p, element_p,
					sizeof(element_p)) < 0)
		goto invalid_point;

	if (l_ecc_scalar_get_data(pwd->scalar_s, scalar_s,
					sizeof(scalar_s)) < 0)
		goto invalid_point;

	if (l_ecc_scalar_get_data(pwd->scalar_p, scalar_p,
					sizeof(scalar_p)) < 0)
		goto invalid_point;

	l_ecc_point_free(kp);

	/*
	 * compute Confirm_P = H(kp | Element_P | Scalar_P |
	 *                       Element_S | Scalar_S | Ciphersuite)
	 */
	hkdf_extract(L_CHECKSUM_SHA256, NULL, 0, 6, confirm_p, kpx, clen,
				element_p, plen, scalar_p, clen, element_s,
				plen, scalar_s, clen, &pwd->ciphersuite,
				(size_t) 4);

	hkdf_extract(L_CHECKSUM_SHA256, NULL, 0, 6, expected_confirm_s, kpx,
				clen, element_s, plen, scalar_s, clen,
				element_p, plen, scalar_p, clen,
				&pwd->ciphersuite, (size_t) 4);

	if (memcmp(confirm_s, expected_confirm_s, 32)) {
		l_error("Confirm_S did not verify");
		goto error;
	}

	pos = resp + 5; /* header */
	*pos++ = EAP_PWD_EXCH_CONFIRM;
	memcpy(pos, confirm_p, 32);
	pos += 32;

	/* derive MK = H(kp | Confirm_P | Confirm_S ) */
	hkdf_extract(L_CHECKSUM_SHA256, NULL, 0, 3, mk, kpx, clen, confirm_p,
			(size_t) 32, confirm_s, (size_t) 32);

	eap_pwd_send_response(eap, resp, pos - resp);

	eap_method_success(eap);

	session_id[0] = 52;
	hkdf_extract(L_CHECKSUM_SHA256, NULL, 0, 3, session_id + 1,
			&pwd->ciphersuite, (size_t) 4, scalar_p, clen,
			scalar_s, clen);

	kdf(mk, 32, (const char *) session_id, 33, msk_emsk, 128);
	eap_set_key_material(eap, msk_emsk, 64, msk_emsk + 64, 64, NULL, 0,
				session_id, sizeof(session_id));

	explicit_bzero(mk, sizeof(mk));
	explicit_bzero(msk_emsk, sizeof(msk_emsk));
	explicit_bzero(kpx, sizeof(kpx));

	return;

invalid_point:
	l_ecc_point_free(kp);

	l_error("invalid point during confirm exchange");
error:
	explicit_bzero(kpx, sizeof(kpx));

	eap_method_error(eap);
}

static void eap_pwd_process(struct eap_state *eap,
				const uint8_t *pkt, size_t len)
{
	uint8_t pwd_exch = util_bit_field(pkt[0], 0, 6);

	if (len < 1)
		return;

	switch (pwd_exch) {
	case EAP_PWD_EXCH_ID:
		eap_pwd_handle_id(eap, pkt + 1, len - 1);
		break;
	case EAP_PWD_EXCH_COMMIT:
		eap_pwd_handle_commit(eap, pkt + 1, len - 1);
		break;
	case EAP_PWD_EXCH_CONFIRM:
		eap_pwd_handle_confirm(eap, pkt + 1, len - 1);
		break;
	}
}

static void eap_pwd_send_ack(struct eap_state *eap)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);
	uint8_t buf[6];

	buf[5] = pwd->state + 1;

	eap_send_response(eap, EAP_TYPE_PWD, buf, 6);
}

#define FRAG_BYTES(mtu, remaining) \
	((mtu - EAP_PWD_HDR_LEN) < remaining) ? (mtu - EAP_PWD_HDR_LEN) : \
			remaining

static void eap_pwd_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_pwd_handle *pwd = eap_get_data(eap);
	uint8_t len_bit = false;
	uint8_t more_bit = false;

	/* ACK from tx fragment, send next fragment */
	if (len == 1 && pwd->tx_frag_buf) {
		size_t mtu = eap_get_mtu(eap);
		uint8_t frag[mtu];
		uint8_t *pos = frag;
		uint16_t frag_bytes = FRAG_BYTES(mtu, pwd->tx_frag_remaining);

		pos += 5; /* header */
		*pos = pwd->state;

		/* more fragments coming, set M bit */
		if (frag_bytes < pwd->tx_frag_remaining)
			*pos |= EAP_PWD_M_BIT;

		pos++;

		memcpy(pos, pwd->tx_frag_pos, frag_bytes);

		pwd->tx_frag_pos += frag_bytes;
		pwd->tx_frag_remaining -= frag_bytes;

		l_info("sending fragment, %d bytes",
				frag_bytes + EAP_PWD_HDR_LEN);

		eap_send_response(eap, EAP_TYPE_PWD, frag,
				frag_bytes + EAP_PWD_HDR_LEN);

		if (!pwd->tx_frag_remaining) {
			/* done sending fragments, free */
			l_free(pwd->tx_frag_buf);
			pwd->tx_frag_buf = NULL;
			pwd->tx_frag_pos = NULL;
			pwd->tx_frag_remaining = 0;
		}

		return;
	}

	if (pwd->tx_frag_buf) {
		l_error("received packet while waiting for ACK!");
		return;
	}

	if (len < 1) {
		l_error("packet is too small");
		return;
	}

	/* set if Total-Length parameter is include (i.e. first fragment) */
	len_bit = util_is_bit_set(pkt[0], 7);
	/* set on all but the last fragment */
	more_bit = util_is_bit_set(pkt[0], 6);

	/* first rx fragment */
	if (len_bit) {
		if (len < 3) {
			l_error("malformed packet");
			return;
		}

		/* remove length of Total-Length parameter (2) */
		pwd->rx_frag_total = l_get_be16(pkt + 1) - 2;
		pwd->rx_frag_buf = l_malloc(pwd->rx_frag_total);

		/* skip copying Total-Length for easier processing later */
		pwd->rx_frag_buf[0] = pkt[0];
		memcpy(pwd->rx_frag_buf + 1, pkt + 3, len - 2);

		pwd->rx_frag_count = len - 2;

		l_info("received first fragment, %d total bytes",
				pwd->rx_frag_total);

		eap_pwd_send_ack(eap);

		return;
	}

	/* more rx fragments */
	if (pwd->rx_frag_buf) {
		/* continue building packet (not including PWD-Exch byte) */
		memcpy(pwd->rx_frag_buf + pwd->rx_frag_count, pkt + 1, len - 1);
		pwd->rx_frag_count += (len - 1);

		l_info("received another fragment, %zu bytes", len);

		/* more fragments coming */
		if (more_bit) {
			eap_pwd_send_ack(eap);
			return;
		}

		if (pwd->rx_frag_count != pwd->rx_frag_total) {
			l_error("fragment length mismatch");
			return;
		}

		/* this was the last fragment, process */
		eap_pwd_process(eap, pwd->rx_frag_buf, pwd->rx_frag_total);

		l_free(pwd->rx_frag_buf);
		pwd->rx_frag_buf = NULL;
		pwd->rx_frag_count = 0;
		pwd->rx_frag_total = 0;

		return;
	}

	/* no fragmentation, process normally */
	eap_pwd_process(eap, pkt, len);
}

static int eap_pwd_check_settings(struct l_settings *settings,
					struct l_queue *secrets,
					const char *prefix,
					struct l_queue **out_missing)
{
	const struct eap_secret_info *secret;
	char identity_key[72];
	char password_key[72];

	L_AUTO_FREE_VAR(char *, identity);
	L_AUTO_FREE_VAR(char *, password) = NULL;

	snprintf(identity_key, sizeof(identity_key), "%sIdentity", prefix);
	snprintf(password_key, sizeof(password_key), "%sPassword", prefix);

	identity = l_settings_get_string(settings, "Security", identity_key);

	if (!identity) {
		secret = l_queue_find(secrets, eap_secret_info_match,
								identity_key);
		if (secret)
			return 0;

		eap_append_secret(out_missing, EAP_SECRET_REMOTE_USER_PASSWORD,
					identity_key, password_key, NULL,
					EAP_CACHE_TEMPORARY);

		return 0;
	}

	password = l_settings_get_string(settings, "Security", password_key);

	if (!password) {
		secret = l_queue_find(secrets, eap_secret_info_match,
								password_key);
		if (secret)
			return 0;

		eap_append_secret(out_missing, EAP_SECRET_REMOTE_PASSWORD,
					password_key, NULL, identity,
					EAP_CACHE_TEMPORARY);
	} else
		explicit_bzero(password, strlen(password));

	return 0;
}

static bool eap_pwd_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_pwd_handle *pwd;
	char setting_key[72];

	pwd = l_new(struct eap_pwd_handle, 1);

	pwd->state = EAP_PWD_STATE_INIT;

	snprintf(setting_key, sizeof(setting_key), "%sIdentity", prefix);
	pwd->identity = l_settings_get_string(settings, "Security",
								setting_key);

	if (!pwd->identity) {
		l_error("'%s' setting is missing", setting_key);
		goto error;
	}

	snprintf(setting_key, sizeof(setting_key), "%sPassword", prefix);
	pwd->password = l_settings_get_string(settings, "Security",
								setting_key);

	if (!pwd->password) {
		snprintf(setting_key, sizeof(setting_key), "%sPassword",
								prefix);
		l_error("'%s' setting is missing", setting_key);
		goto error;
	}

	eap_set_data(eap, pwd);

	return true;

error:
	if (pwd->password) {
		explicit_bzero(pwd->password, strlen(pwd->password));
		l_free(pwd->password);
	}

	l_free(pwd->identity);
	l_free(pwd);

	return false;
}

static struct eap_method eap_pwd = {
	.request_type = EAP_TYPE_PWD,
	.exports_msk = true,
	.name = "PWD",
	.free = eap_pwd_free,
	.handle_request = eap_pwd_handle_request,
	.check_settings = eap_pwd_check_settings,
	.load_settings = eap_pwd_load_settings,
	.reset_state = eap_pwd_reset_state,
};

static int eap_pwd_init(void)
{
	l_debug("");
	return eap_register_method(&eap_pwd);
}

static void eap_pwd_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_pwd);
}

EAP_METHOD_BUILTIN(eap_pwd, eap_pwd_init, eap_pwd_exit)
