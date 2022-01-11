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
#include <errno.h>
#include <ell/ell.h>

#include "src/missing.h"
#include "src/eap.h"
#include "src/eap-private.h"

#define EAP_GTC_MAX_PASSWORD_LEN	2048

struct eap_gtc_state {
	char *password;
};

static void eap_gtc_free(struct eap_state *eap)
{
	struct eap_gtc_state *gtc = eap_get_data(eap);

	eap_set_data(eap, NULL);

	if (gtc->password)
		explicit_bzero(gtc->password, strlen(gtc->password));

	l_free(gtc->password);
	l_free(gtc);
}

static void eap_gtc_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_gtc_state *gtc = eap_get_data(eap);
	size_t secret_len = strlen(gtc->password);
	uint8_t response[5 + secret_len];

	if (len < 8 || strncmp((const char *)pkt, "Password", 8))
		l_warn("GTC request not understood, proceeding anyway: %.*s",
				(int) len, (const char *) pkt);

	memcpy(response + 5, gtc->password, secret_len);

	eap_method_respond(eap, response, 5 + secret_len);

	eap_method_success(eap);
}

static int eap_gtc_check_settings(struct l_settings *settings,
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

static bool eap_gtc_load_settings(struct eap_state *eap,
					struct l_settings *settings,
					const char *prefix)
{
	struct eap_gtc_state *gtc;
	char password_key[72];
	char *password;

	snprintf(password_key, sizeof(password_key), "%sPassword", prefix);
	password = l_settings_get_string(settings, "Security", password_key);

	if (!password) {
		snprintf(password_key, sizeof(password_key), "%sGTC-Secret",
									prefix);
		password = l_settings_get_string(settings, "Security",
								password_key);
		if (!password)
			return false;
	}

	/*
	 * Limit length to prevent a stack overflow
	 */
	if (strlen(password) > EAP_GTC_MAX_PASSWORD_LEN) {
		l_free(password);
		return false;
	}

	gtc = l_new(struct eap_gtc_state, 1);
	gtc->password = password;

	eap_set_data(eap, gtc);

	return true;
}

static struct eap_method eap_gtc = {
	.request_type = EAP_TYPE_GTC,
	.exports_msk = false,
	.name = "GTC",
	.free = eap_gtc_free,
	.handle_request = eap_gtc_handle_request,
	.check_settings = eap_gtc_check_settings,
	.load_settings = eap_gtc_load_settings,
};

static int eap_gtc_init(void)
{
	l_debug("");
	return eap_register_method(&eap_gtc);
}

static void eap_gtc_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_gtc);
}

EAP_METHOD_BUILTIN(eap_gtc, eap_gtc_init, eap_gtc_exit)
