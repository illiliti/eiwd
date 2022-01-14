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
#include "src/anqputil.h"
#include "src/ie.h"
#include "src/util.h"

void anqp_iter_init(struct anqp_iter *iter, const unsigned char *anqp,
			unsigned int len)
{
	iter->anqp = anqp;
	iter->max = len;
	iter->pos = 0;
}

bool anqp_iter_next(struct anqp_iter *iter, uint16_t *id, uint16_t *len,
			const void **data)
{
	const unsigned char *anqp = iter->anqp + iter->pos;
	const unsigned char *end = iter->anqp + iter->max;

	if (iter->pos + 4 >= iter->max)
		return false;

	if (l_get_le16(anqp + 2) > end - anqp)
		return false;

	*id = l_get_le16(anqp);
	anqp += 2;

	*len = l_get_le16(anqp);
	anqp += 2;

	*data = anqp;

	iter->id = *id;
	iter->len = *len;
	iter->data = *data;

	iter->pos = anqp + *len - iter->anqp;

	return true;
}

bool anqp_hs20_parse_osu_provider_nai(const unsigned char *anqp,
					unsigned int len, const char **nai_out)
{
	uint8_t nai_len;
	static char nai[256] = { 0 };

	if (len < 1)
		return false;

	nai_len = *anqp++;
	len--;

	if (len < nai_len)
		return false;

	memcpy(nai, anqp, nai_len);

	*nai_out = nai;

	return true;
}

bool anqp_iter_is_hs20(const struct anqp_iter *iter, uint8_t *stype,
			unsigned int *len, const unsigned char **data)
{
	const unsigned char *anqp = iter->data;
	unsigned int anqp_len = iter->len;
	uint8_t type;

	if (iter->len < 6)
		return false;

	if (memcmp(anqp, wifi_alliance_oui, 3))
		return false;

	anqp += 3;
	anqp_len -= 3;

	type = *anqp++;
	anqp_len--;

	if (type != 0x11)
		return false;

	*stype = *anqp++;
	anqp_len--;

	/* reserved byte */
	anqp++;
	anqp_len--;

	*data = anqp;
	*len = anqp_len;

	return true;
}

char **anqp_parse_nai_realms(const unsigned char *anqp, unsigned int len)
{
	char **realms = NULL;
	uint16_t count;

	if (len < 2)
		return false;

	count = l_get_le16(anqp);

	anqp += 2;
	len -= 2;

	l_debug("");

	while (count--) {
		uint16_t realm_len;
		uint8_t encoding;
		uint8_t nai_len;
		char nai_realm[256] = { 0 };

		/*
		 * The method list is a variable field, so the only way to
		 * reliably increment anqp is by realm_len at the very end since
		 * we don't know how many bytes parse_eap advanced (it does
		 * internal length checking so it should not overflow). We
		 * can't incrementally advance anqp/len, hence the hardcoded
		 * length and pointer adjustments.
		 */

		if (len < 4)
			goto failed;

		realm_len = l_get_le16(anqp);
		anqp += 2;
		len -= 2;

		encoding = anqp[0];

		nai_len = anqp[1];

		if (len - 2 < nai_len)
			goto failed;

		memcpy(nai_realm, anqp + 2, nai_len);

		/*
		 * TODO: Verify NAI encoding in accordance with RFC 4282 ?
		 *
		 * The encoding in RFC 4282 seems to only limit which characters
		 * can be used in an NAI. Since these come in from public
		 * action frames it could have been spoofed, but ultimately if
		 * its bogus the AP won't allow us to connect.
		 */
		if (!test_bit(&encoding, 0))
			l_warn("Not verifying NAI encoding");
		else if (!l_utf8_validate(nai_realm, nai_len, NULL)) {
			l_warn("NAI is not UTF-8");
			goto failed;
		}

		realms = l_strv_append(realms, nai_realm);

		if (len < realm_len)
			goto failed;

		anqp += realm_len;
		len -= realm_len;
	}

	return realms;

failed:
	l_strv_free(realms);
	return NULL;
}
