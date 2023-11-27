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

#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#include <ell/ell.h>

#include "ell/useful.h"
#include "src/missing.h"
#include "src/iwd.h"
#include "src/module.h"
#include "src/eap-private.h"
#include "src/erp.h"
#include "src/crypto.h"
#include "src/util.h"

#define ERP_DEFAULT_KEY_LIFETIME_US 86400000000

struct erp_cache_entry {
	char *id;
	void *emsk;
	size_t emsk_len;
	void *session_id;
	size_t session_len;
	char *ssid;
	uint64_t expire_time;
	uint32_t ref;
	bool invalid : 1;
};

struct erp_state {
	erp_tx_packet_func_t tx_packet;
	void *user_data;

	struct erp_cache_entry *cache;

	uint8_t rmsk[64];
	uint8_t r_rk[64];
	uint8_t r_ik[64];
	char keyname_nai[254];
	uint16_t seq;
};

enum eap_erp_type {
	ERP_TYPE_REAUTH_START	= 1,
	ERP_TYPE_REAUTH		= 2,
};

enum eap_erp_tlv {
	ERP_TLV_KEYNAME_NAI = 1,
	ERP_TV_RRK_LIFETIME = 2,
	ERP_TV_RMSK_LIFETIME = 3,
	ERP_TLV_DOMAIN_NAME = 4,
	ERP_TLV_CRYPTOSUITES = 5,
	ERP_TLV_AUTH_INDICATION = 6,
	ERP_TLV_CALLED_STATION_ID = 128,
	ERP_TLV_CALLING_STATION_ID = 129,
	ERP_TLV_NAS_IDENTIFIER = 130,
	ERP_TLV_NAS_IP_ADDRESS = 131,
	ERP_TLV_NAS_IPV6_ADDRESS = 132,
};

enum eap_erp_cryptosuite {
	ERP_CRYPTOSUITE_SHA256_64 = 1,
	ERP_CRYPTOSUITE_SHA256_128 = 2,
	ERP_CRYPTOSUITE_SHA256_256 = 3,
};

struct erp_tlv_iter {
	unsigned int max;
	unsigned int pos;
	const unsigned char *tlv;
	unsigned int tag;
	unsigned int len;
	const unsigned char *data;
};

static struct l_queue *key_cache;

static void erp_tlv_iter_init(struct erp_tlv_iter *iter,
				const unsigned char *tlv, unsigned int len)
{
	iter->tlv = tlv;
	iter->max = len;
	iter->pos = 0;
}

static bool erp_tlv_iter_next(struct erp_tlv_iter *iter)
{
	const unsigned char *tlv = iter->tlv + iter->pos;
	const unsigned char *end = iter->tlv + iter->max;
	uint8_t tag;
	uint8_t len;

	if (end - tlv < 2)
		return false;

	tag = *tlv++;

	/*
	 * These two tags are not actually TLVs (they are just type-value).
	 * Both are 32-bit integers.
	 */
	if (tag != ERP_TV_RMSK_LIFETIME && tag != ERP_TV_RRK_LIFETIME)
		len = *tlv++;
	else
		len = 4;

	if (len > end - tlv)
		return false;

	iter->tag = tag;
	iter->len = len;
	iter->data = tlv;

	iter->pos = tlv + len - iter->tlv;

	return true;
}

static void erp_cache_entry_destroy(void *data)
{
	struct erp_cache_entry *entry = data;

	if (entry->ref)
		l_error("ERP entry still has a reference on cleanup!");

	l_free(entry->id);
	l_free(entry->emsk);
	l_free(entry->session_id);
	l_free(entry->ssid);

	l_free(entry);
}

void erp_cache_add(const char *id, const void *session_id,
			size_t session_len, const void *emsk, size_t emsk_len,
			const uint8_t *ssid, size_t ssid_len)
{
	struct erp_cache_entry *entry;

	if (!unlikely(id || session_id || emsk))
		return;

	if (!util_ssid_is_utf8(ssid_len, ssid))
		return;

	if (util_ssid_is_hidden(ssid_len, ssid))
		return;

	entry = l_new(struct erp_cache_entry, 1);

	entry->id = l_strdup(id);
	entry->emsk = l_memdup(emsk, emsk_len);
	entry->emsk_len = emsk_len;
	entry->session_id = l_memdup(session_id, session_len);
	entry->session_len = session_len;
	entry->ssid = l_strndup((char *) ssid, ssid_len);
	entry->expire_time = l_time_offset(l_time_now(),
					ERP_DEFAULT_KEY_LIFETIME_US);

	l_queue_push_head(key_cache, entry);
}

static struct erp_cache_entry *find_keycache(const char *id, const char *ssid)
{
	const struct l_queue_entry *entry;

	if (!id && !ssid)
		return NULL;

	for (entry = l_queue_get_entries(key_cache); entry;
			entry = entry->next) {
		struct erp_cache_entry *cache = entry->data;

		if (cache->invalid)
			continue;

		if (l_time_after(l_time_now(), cache->expire_time)) {
			if (!cache->ref) {
				l_queue_remove(key_cache, cache);
				erp_cache_entry_destroy(cache);
			} else
				cache->invalid = true;

			continue;
		}

		if (id && !strcmp(cache->id, id))
			return cache;

		if (ssid && !strcmp(cache->ssid, ssid))
			return cache;
	}

	return NULL;
}

void erp_cache_remove(const char *id)
{
	struct erp_cache_entry *entry = find_keycache(id, NULL);

	if (!entry)
		return;

	if (entry->ref) {
		entry->invalid = true;
		return;
	}

	l_queue_remove(key_cache, entry);

	erp_cache_entry_destroy(entry);
}

struct erp_cache_entry *erp_cache_get(const char *ssid)
{
	struct erp_cache_entry *cache = find_keycache(NULL, ssid);

	if (!cache)
		return NULL;

	cache->ref++;

	return cache;
}

void erp_cache_put(struct erp_cache_entry *cache)
{
	cache->ref--;

	if (cache->ref)
		return;

	if (!cache->invalid)
		return;

	/*
	 * Cache entry marked as invalid, either it expired or something
	 * attempted to remove it. Either way, it can now be removed.
	 */
	l_queue_remove(key_cache, cache);
	erp_cache_entry_destroy(cache);
}

const char *erp_cache_entry_get_identity(struct erp_cache_entry *cache)
{
	return cache->id;
}

#define ERP_RRK_LABEL	"EAP Re-authentication Root Key@ietf.org"
#define ERP_RIK_LABEL	"Re-authentication Integrity Key@ietf.org"
#define ERP_RMSK_LABEL	"Re-authentication Master Session Key@ietf.org"

/*
 * RFC 5295 - Section 3.2. EMSK and USRK Name Derivation
 */
static bool erp_derive_emsk_name(const uint8_t *session_id, size_t session_len,
					char buf[static 17])
{
	uint8_t hex[8];
	uint16_t eight = L_CPU_TO_BE16(8);
	char *ascii;

	if (!prf_plus(L_CHECKSUM_SHA256, session_id, session_len,
				hex, 8, 2, "EMSK", strlen("EMSK") + 1,
				&eight, sizeof(eight)))
		return false;

	ascii = l_util_hexstring(hex, 8);
	strcpy(buf, ascii);
	l_free(ascii);

	return true;
}

/*
 * RFC 6696 - Section 4.1 and 4.3 - rRK and rIK derivation
 *
 * All reauth keys form a hierarchy, and all ultimately are derived from the
 * EMSK. All keys follow the rule:
 *
 * "The length of the <key> MUST be equal to the length of the parent key used
 *  to derive it."
 *
 * Therefore all keys derived are equal to the EMSK length.
 */
static bool erp_derive_reauth_keys(const uint8_t *emsk, size_t emsk_len,
					void *r_rk, void *r_ik)
{
	uint16_t len = L_CPU_TO_BE16(emsk_len);
	uint8_t cryptosuite = ERP_CRYPTOSUITE_SHA256_128;

	if (!prf_plus(L_CHECKSUM_SHA256, emsk, emsk_len,
				r_rk, emsk_len, 2, ERP_RRK_LABEL,
				strlen(ERP_RRK_LABEL) + 1,
				&len, sizeof(len)))
		return false;

	if (!prf_plus(L_CHECKSUM_SHA256, r_rk, emsk_len,
				r_ik, emsk_len, 3, ERP_RIK_LABEL,
				strlen(ERP_RIK_LABEL) + 1,
				&cryptosuite, 1, &len, sizeof(len)))
		return false;

	return true;
}

struct erp_state *erp_new(struct erp_cache_entry *cache,
				erp_tx_packet_func_t tx_packet,
				void *user_data)
{
	struct erp_state *erp;

	if (!cache)
		return NULL;

	erp = l_new(struct erp_state, 1);

	erp->tx_packet = tx_packet;
	erp->user_data = user_data;
	erp->cache = cache;
	cache->ref++;

	return erp;
}

void erp_free(struct erp_state *erp)
{
	erp_cache_put(erp->cache);

	explicit_bzero(erp->rmsk, sizeof(erp->rmsk));
	explicit_bzero(erp->r_ik, sizeof(erp->r_ik));
	explicit_bzero(erp->r_rk, sizeof(erp->r_rk));

	l_free(erp);
}

bool erp_start(struct erp_state *erp)
{
	uint8_t buf[512];
	uint8_t *ptr = buf;
	char emsk_name[17];
	size_t nai_len;

	if (!erp_derive_emsk_name(erp->cache->session_id,
					erp->cache->session_len, emsk_name))
		return false;

	if (!erp_derive_reauth_keys(erp->cache->emsk, erp->cache->emsk_len,
					erp->r_rk, erp->r_ik))
		return false;

	nai_len = sprintf(erp->keyname_nai, "%s@%s", emsk_name,
				util_get_domain(erp->cache->id));

	*ptr++ = EAP_CODE_INITIATE;
	*ptr++ = 0;
	/* Header (8) + TL (2) + NAI (nai_len) + CS (1) + auth tag (16) */
	l_put_be16(27 + nai_len, ptr);
	ptr += 2;
	*ptr++ = ERP_TYPE_REAUTH;
	*ptr++ = 0;
	l_put_be16(erp->seq, ptr);
	ptr += 2;

	/* keyName-NAI TLV */
	*ptr++ = ERP_TLV_KEYNAME_NAI;
	*ptr++ = nai_len;
	memcpy(ptr, erp->keyname_nai, nai_len);
	ptr += nai_len;

	*ptr++ = ERP_CRYPTOSUITE_SHA256_128;

	hmac_sha256(erp->r_ik, erp->cache->emsk_len, buf, ptr - buf, ptr, 16);
	ptr += 16;

	erp->tx_packet(buf, ptr - buf, erp->user_data);

	return true;
}

int erp_rx_packet(struct erp_state *erp, const uint8_t *pkt, size_t len)
{
	struct erp_tlv_iter iter;
	enum eap_erp_cryptosuite cs;
	uint8_t hash[16];
	const uint8_t *nai = NULL;
	uint8_t type;
	uint16_t seq;
	uint16_t length;
	bool r;

	/*
	 * Not including the TLVs we have:
	 * header (8) + cryptosuite (1) + auth tag (16) = 25 bytes
	 */
	if (len < 25)
		goto eap_failed;

	/*
	 * We can skip code/id/len, since that was already parsed. We just need
	 * the whole packet so we can verify the Auth tag.
	 */
	type = pkt[4];

	if (type != ERP_TYPE_REAUTH)
		goto eap_failed;

	r = test_bit(pkt + 5, 0);
	if (r)
		goto eap_failed;

	/*
	 * TODO: Parse B and L bits. L bit indicates rRK lifetime, but our ERP
	 * cache does not yet support this.
	 */

	seq = l_get_be16(pkt + 6);

	if (seq != erp->seq)
		goto eap_failed;

	/*
	 * The Cryptosuite byte comes after the TLVs. Because of this we cannot
	 * parse the TLVs yet since we don't actually know where they end. There
	 * is really no good way to do this, but (at least for now) we can just
	 * require the 128 bit cryptosuite. If we limit to only this suite we
	 * can work backwards from the end (17 bytes) to get the cryptosuite. If
	 * it is not the 128 bit suite we just fail. If it is, we now know where
	 * the TLVs end;
	 */
	cs = *(pkt + len - 17);

	if (cs != ERP_CRYPTOSUITE_SHA256_128)
		goto eap_failed;

	hmac_sha256(erp->r_ik, erp->cache->emsk_len, pkt, len - 16, hash, 16);

	if (memcmp(hash, pkt + len - 16, 16) != 0) {
		l_debug("Authentication Tag did not verify");
		goto eap_failed;
	}

	erp_tlv_iter_init(&iter, pkt + 8, len - 8 - 17);

	while (erp_tlv_iter_next(&iter)) {
		switch (iter.tag) {
		case ERP_TLV_KEYNAME_NAI:
			if (nai)
				goto eap_failed;

			nai = iter.data;
			break;
		default:
			break;
		}
	}

	/*
	 * RFC 6696 Section 5.3.3
	 *
	 * Exactly one instance of the keyName-NAI attribute SHALL be present
	 * in an EAP-Finish/Re-auth message
	 */
	if (!nai) {
		l_error("AP did not include keyName-NAI in EAP-Finish");
		goto eap_failed;
	}

	if (memcmp(nai, erp->keyname_nai, strlen(erp->keyname_nai))) {
		l_error("keyName-NAI did not match");
		goto eap_failed;
	}

	/*
	 * RFC 6696 Section 4.6 - rMSK Derivation
	 */
	seq = L_CPU_TO_BE16(erp->seq);
	length = L_CPU_TO_BE16(64);

	if (!prf_plus(L_CHECKSUM_SHA256, erp->r_rk, erp->cache->emsk_len,
				erp->rmsk, erp->cache->emsk_len, 3,
				ERP_RMSK_LABEL, strlen(ERP_RMSK_LABEL) + 1,
				&seq, sizeof(seq),
				&length, sizeof(length)))
		goto eap_failed;

	return 0;

eap_failed:
	return -EINVAL;
}

const void *erp_get_rmsk(struct erp_state *erp, size_t *rmsk_len)
{
	if (rmsk_len)
		*rmsk_len = erp->cache->emsk_len;

	return erp->rmsk;
}

static int erp_init(void)
{
	key_cache = l_queue_new();

	return 0;
}

static void erp_exit(void)
{
	l_queue_destroy(key_cache, erp_cache_entry_destroy);
}

IWD_MODULE(erp, erp_init, erp_exit)
