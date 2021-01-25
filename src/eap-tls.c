/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2019  Intel Corporation. All rights reserved.
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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ell/ell.h>

#include "src/missing.h"
#include "src/eap.h"
#include "src/eap-private.h"
#include "src/eap-tls-common.h"

static bool eap_tls_tunnel_ready(struct eap_state *eap,
						const char *peer_identity)
{
	uint8_t msk_emsk[128];
	uint8_t iv[64];

	eap_method_success(eap);
	eap_tls_common_set_completed(eap);

	/* MSK, EMSK and IV derivation */
	eap_tls_common_tunnel_prf_get_bytes(eap, true, "client EAP encryption",
								msk_emsk, 128);
	eap_tls_common_tunnel_prf_get_bytes(eap, false, "client EAP encryption",
									iv, 64);

	/* TODO: Derive Session-ID */
	eap_set_key_material(eap, msk_emsk + 0, 64, msk_emsk + 64, 64, iv, 64,
				NULL, 0);
	explicit_bzero(msk_emsk, sizeof(msk_emsk));
	explicit_bzero(iv, sizeof(iv));

	eap_tls_common_send_empty_response(eap);

	return true;
}

static int eap_tls_check_keys_match(struct l_key *priv_key, struct l_cert *cert,
					const char *key_name,
					const char *cert_name)
{
	bool is_public;
	size_t size;
	ssize_t result;
	uint8_t *encrypted, *decrypted;
	struct l_key *pub_key;

	if (!l_key_get_info(priv_key, L_KEY_RSA_PKCS1_V1_5, L_CHECKSUM_NONE,
				&size, &is_public) || is_public) {
		l_error("%s is not a private key or l_key_get_info fails",
			key_name);
		return -EINVAL;
	}

	size /= 8;
	encrypted = alloca(size);
	decrypted = alloca(size);

	pub_key = l_cert_get_pubkey(cert);
	if (!pub_key) {
		l_error("l_cert_get_pubkey fails for %s", cert_name);
		return -EIO;
	}

	result = l_key_encrypt(pub_key, L_KEY_RSA_PKCS1_V1_5, L_CHECKSUM_NONE,
				"", encrypted, 1, size);
	l_key_free(pub_key);

	if (result != (ssize_t) size) {
		l_error("l_key_encrypt fails with %s: %s", cert_name,
			strerror(-result));
		return result;
	}

	result = l_key_decrypt(priv_key, L_KEY_RSA_PKCS1_V1_5, L_CHECKSUM_NONE,
				encrypted, decrypted, size, size);
	if (result < 0) {
		l_error("l_key_decrypt fails with %s: %s", key_name,
			strerror(-result));
		return result;
	}

	if (result != 1 || decrypted[0] != 0) {
		l_error("Private key %s does not match certificate %s", key_name,
			cert_name);
		return -EINVAL;
	}

	return 0;
}

static int eap_tls_settings_check(struct l_settings *settings,
						struct l_queue *secrets,
						const char *prefix,
						struct l_queue **out_missing)
{
	char tls_prefix[32];
	char passphrase_setting[72];
	char client_cert_setting[72];
	char priv_key_setting[72];
	char bundle_setting[72];
	L_AUTO_FREE_VAR(char *, passphrase) = NULL;
	L_AUTO_FREE_VAR(char *, client_cert_value) = NULL;
	L_AUTO_FREE_VAR(char *, priv_key_value) = NULL;
	L_AUTO_FREE_VAR(char *, bundle_value) = NULL;
	struct l_certchain *client_cert = NULL;
	struct l_key *priv_key = NULL;
	const char *error_str;
	bool priv_key_encrypted, cert_encrypted;
	int ret;

	snprintf(tls_prefix, sizeof(tls_prefix), "%sTLS-", prefix);

	ret = eap_tls_common_settings_check(settings, secrets, tls_prefix,
						out_missing);
	if (ret < 0)
		goto done;

	snprintf(client_cert_setting, sizeof(client_cert_setting),
			"%sClientCert", tls_prefix);
	client_cert_value = l_settings_get_string(settings, "Security",
							client_cert_setting);

	snprintf(priv_key_setting, sizeof(priv_key_setting), "%sClientKey",
			tls_prefix);
	priv_key_value = l_settings_get_string(settings, "Security",
						priv_key_setting);

	snprintf(bundle_setting, sizeof(bundle_setting),
			"%sClientKeyBundle", tls_prefix);
	bundle_value = l_settings_get_string(settings, "Security",
						bundle_setting);

	snprintf(passphrase_setting, sizeof(passphrase_setting),
			"%sClientKeyPassphrase", tls_prefix);
	passphrase = l_settings_get_string(settings, "Security",
						passphrase_setting);

	if (!passphrase) {
		const struct eap_secret_info *secret;

		secret = l_queue_find(secrets, eap_secret_info_match,
							passphrase_setting);
		if (secret)
			passphrase = l_strdup(secret->value);
	}

	/*
	 * Check whether the combination of settings that are present/missing
	 * makes sense before validating each setting.
	 */
	if (bundle_value && (priv_key_value || client_cert)) {
		l_error("Either %s or %s/%s can be used, not both",
			bundle_setting, priv_key_setting, client_cert_setting);
		ret = -EEXIST;
		goto done;
	} else if (priv_key_value && !client_cert_value) {
		l_error("%s present but no client certificate (%s)",
			priv_key_setting, client_cert_setting);
		ret = -ENOENT;
		goto done;
	} else if (!priv_key_value && client_cert) {
		l_error("%s present but no client private key (%s)",
			client_cert_setting, priv_key_setting);
		ret = -ENOENT;
		goto done;
	}

	if (!priv_key_value && !bundle_value) {
		if (passphrase) {
			l_error("%s present but no client keys set (%s)",
				passphrase_setting, priv_key_setting);
			ret = -ENOENT;
			goto done;
		}

		ret = 0;
		goto done;
	}

	if (bundle_value &&
			(!l_cert_load_container_file(bundle_value, passphrase,
							&client_cert, &priv_key,
							&priv_key_encrypted) ||
			 !client_cert || !priv_key)) {
		if (client_cert) {
			l_error("No private key loaded from %s", bundle_value);
			ret = -ENOKEY;
			goto done;
		} else if (priv_key) {
			l_error("No certificates loaded from %s", bundle_value);
			ret = -ENOKEY;
			goto done;
		} else if (!priv_key_encrypted) {
			l_error("Error loading %s", bundle_value);
			ret = -EIO;
			goto done;
		} else if (passphrase) {
			l_error("Error loading key pair from encrypted file %s",
				bundle_value);
			ret = -EACCES;
			goto done;
		}

		/*
		 * We've got an encrypted file and passphrase was not saved
		 * in the network settings, need to request the passphrase.
		 */
		eap_append_secret(out_missing,
					EAP_SECRET_LOCAL_PKEY_PASSPHRASE,
					passphrase_setting, NULL,
					bundle_value, EAP_CACHE_TEMPORARY);
		ret = 0;
		goto done;
	}

	if (bundle_value)
		goto validate_keys;

	client_cert = eap_tls_load_client_cert(settings, client_cert_value,
						passphrase, &cert_encrypted);
	if (!client_cert) {
		if (!cert_encrypted) {
			l_error("Failed to load %s", client_cert_value);
			ret = -EIO;
			goto done;
		}

		if (passphrase) {
			l_error("Error loading certificate from encrypted "
				"file %s", client_cert_value);
			ret = -EACCES;
			goto done;
		}

		/*
		 * We've got an encrypted file and passphrase was not saved
		 * in the network settings, need to request the passphrase.
		 */
		eap_append_secret(out_missing,
					EAP_SECRET_LOCAL_PKEY_PASSPHRASE,
					passphrase_setting, NULL,
					client_cert_value, EAP_CACHE_TEMPORARY);
		ret = 0;
		goto done;
	}

	priv_key = eap_tls_load_priv_key(settings, priv_key_value, passphrase,
						&priv_key_encrypted);
	if (!priv_key) {
		if (!priv_key_encrypted) {
			l_error("Error loading client private key %s",
				priv_key_value);
			ret = -EIO;
			goto done;
		}

		if (passphrase) {
			l_error("Error loading encrypted client private key %s",
				priv_key_value);
			ret = -EACCES;
			goto done;
		}

		/*
		 * We've got an encrypted key and passphrase was not saved
		 * in the network settings, need to request the passphrase.
		 */
		eap_append_secret(out_missing,
					EAP_SECRET_LOCAL_PKEY_PASSPHRASE,
					passphrase_setting, NULL,
					priv_key_value, EAP_CACHE_TEMPORARY);
		ret = 0;
		goto done;
	}

validate_keys:
	if (passphrase && !priv_key_encrypted && !cert_encrypted) {
		l_error("%s present but keys are not encrypted",
			passphrase_setting);
		ret = -ENOENT;
		goto done;
	}

	/*
	 * Sanity check that certchain provided is valid.  We do not verify
	 * the certchain against the provided CA since the CA that issued
	 * user certificates might be different from the one that is used
	 * to verify the peer.
	 */
	if (!l_certchain_verify(client_cert, NULL, &error_str)) {
		l_error("Certificate chain %s fails verification: %s",
			client_cert_value, error_str);
		ret = -EINVAL;
		goto done;
	}

	ret = eap_tls_check_keys_match(priv_key,
					l_certchain_get_leaf(client_cert),
					priv_key_value, client_cert_value);

done:
	l_certchain_free(client_cert);
	l_key_free(priv_key);

	if (passphrase)
		explicit_bzero(passphrase, strlen(passphrase));

	return ret;
}

static const struct eap_tls_variant_ops eap_tls_ops = {
	.tunnel_ready = eap_tls_tunnel_ready,
};

static bool eap_tls_settings_load(struct eap_state *eap,
						struct l_settings *settings,
						const char *prefix)
{
	char tls_prefix[32];
	char setting_key[72];
	struct l_certchain *client_cert = NULL;
	struct l_key *client_key = NULL;

	L_AUTO_FREE_VAR(char *, value) = NULL;
	L_AUTO_FREE_VAR(char *, passphrase) = NULL;

	snprintf(tls_prefix, sizeof(tls_prefix), "%sTLS-", prefix);

	if (!eap_tls_common_settings_load(eap, settings, tls_prefix,
						&eap_tls_ops, NULL))
		return false;

	snprintf(setting_key, sizeof(setting_key), "%sClientKeyPassphrase",
			tls_prefix);
	passphrase = l_settings_get_string(settings, "Security", setting_key);

	snprintf(setting_key, sizeof(setting_key), "%sClientCert", tls_prefix);
	value = l_settings_get_string(settings, "Security", setting_key);
	if (value) {
		client_cert = eap_tls_load_client_cert(settings, value,
							passphrase, NULL);
		if (!client_cert)
			goto load_error;
	}

	l_free(value);

	snprintf(setting_key, sizeof(setting_key), "%sClientKey", tls_prefix);
	value = l_settings_get_string(settings, "Security", setting_key);
	if (value) {
		client_key = eap_tls_load_priv_key(settings, value,
							passphrase, NULL);
		if (!client_key)
			goto load_error;
	}

	l_free(value);

	snprintf(setting_key, sizeof(setting_key), "%sClientKeyBundle",
			tls_prefix);
	value = l_settings_get_string(settings, "Security", setting_key);
	if (value && !client_cert && !client_key &&
			(!l_cert_load_container_file(value, passphrase,
							&client_cert,
							&client_key, NULL) ||
			 !client_cert || !client_key)) {
		l_certchain_free(client_cert);
		l_key_free(client_key);
		goto load_error;
	}

	eap_tls_common_set_keys(eap, client_cert, client_key);
	return true;

load_error:
	eap_tls_common_state_free(eap);
	return false;
}

static struct eap_method eap_tls = {
	.request_type = EAP_TYPE_TLS,
	.exports_msk = true,
	.name = "TLS",

	.handle_request = eap_tls_common_handle_request,
	.handle_retransmit = eap_tls_common_handle_retransmit,
	.reset_state = eap_tls_common_state_reset,
	.free = eap_tls_common_state_free,

	.check_settings = eap_tls_settings_check,
	.load_settings = eap_tls_settings_load,
};

static struct eap_method eap_wfa_tls = {
	.request_type = EAP_TYPE_EXPANDED,
	.exports_msk = true,
	.name = "WFA-TLS",

	.handle_request = eap_tls_common_handle_request,
	.handle_retransmit = eap_tls_common_handle_retransmit,
	.reset_state = eap_tls_common_state_reset,
	.free = eap_tls_common_state_free,

	.check_settings = eap_tls_settings_check,
	.load_settings = eap_tls_settings_load,
	.vendor_id = { 0x00, 0x9f, 0x68 },
	.vendor_type = 0x0000000d,
};

static int eap_tls_init(void)
{
	l_debug("");

	if (eap_register_method(&eap_tls) < 0)
		return -EPERM;

	return eap_register_method(&eap_wfa_tls);
}

static void eap_tls_exit(void)
{
	l_debug("");
	eap_unregister_method(&eap_tls);
	eap_unregister_method(&eap_wfa_tls);
}

EAP_METHOD_BUILTIN(eap_tls, eap_tls_init, eap_tls_exit)
