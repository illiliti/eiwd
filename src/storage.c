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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <ell/ell.h>
#include "ell/useful.h"

#include "src/missing.h"
#include "src/common.h"
#include "src/storage.h"
#include "src/crypto.h"

#define STORAGE_DIR_MODE (S_IRUSR | S_IWUSR | S_IXUSR)
#define STORAGE_FILE_MODE (S_IRUSR | S_IWUSR)

#define KNOWN_FREQ_FILENAME ".known_network.freq"
#define TLS_CACHE_FILENAME ".tls-session-cache"

static char *storage_path = NULL;
static char *storage_hotspot_path = NULL;
static uint8_t system_key[32];
static bool system_key_set = false;

static int create_dirs(const char *filename)
{
	struct stat st;
	char *dir;
	const char *prev, *next;
	int err;

	if (filename[0] != '/')
		return -1;

	err = stat(filename, &st);
	if (!err && S_ISREG(st.st_mode))
		return 0;

	dir = l_malloc(strlen(filename) + 1);
	strcpy(dir, "/");

	for (prev = filename; (next = strchr(prev + 1, '/')); prev = next) {
		/* Skip consecutive '/' characters */
		if (next - prev == 1)
			continue;

		strncat(dir, prev + 1, next - prev);

		if (mkdir(dir, STORAGE_DIR_MODE) == -1 && errno != EEXIST) {
			l_free(dir);
			return -1;
		}
	}

	l_free(dir);
	return 0;
}

ssize_t read_file(void *buffer, size_t len, const char *path_fmt, ...)
{
	va_list ap;
	char *path;
	ssize_t r;
	int fd;

	va_start(ap, path_fmt);
	path = l_strdup_vprintf(path_fmt, ap);
	va_end(ap);

	fd = L_TFR(open(path, O_RDONLY));

	l_free(path);

	if (fd == -1)
		return -1;

	r = L_TFR(read(fd, buffer, len));

	L_TFR(close(fd));

	return r;
}

/*
 * Write a buffer to a file in a transactionally safe form
 *
 * Given a buffer, write it to a file named after
 * @path_fmt+args. However, to make sure the file contents are
 * consistent (ie: a crash right after opening or during write()
 * doesn't leave a file half baked), the contents are written to a
 * file with a temporary name and when closed, it is renamed to the
 * specified name (@path_fmt+args).
 */
ssize_t write_file(const void *buffer, size_t len, bool preserve_times,
			const char *path_fmt, ...)
{
	va_list ap;
	char *tmp_path, *path;
	ssize_t r;
	int fd;

	va_start(ap, path_fmt);
	path = l_strdup_vprintf(path_fmt, ap);
	va_end(ap);

	tmp_path = l_strdup_printf("%s.XXXXXX.tmp", path);

	r = -1;
	if (create_dirs(path) != 0)
		goto error_create_dirs;

	fd = L_TFR(mkostemps(tmp_path, 4, O_CLOEXEC));
	if (fd == -1)
		goto error_mkostemps;

	r = L_TFR(write(fd, buffer, len));
	L_TFR(close(fd));

	if (r != (ssize_t) len) {
		r = -1;
		goto error_write;
	}

	if (preserve_times) {
		struct stat st;

		if (stat(path, &st) == 0) {
			struct timespec times[2];

			times[0] = st.st_atim;
			times[1] = st.st_mtim;
			utimensat(0, tmp_path, times, 0);
		}
	}

	/*
	 * Now that the file contents are written, rename to the real
	 * file name; this way we are uniquely sure that the whole
	 * thing is there.
	 * conserve @r's value from 'write'
	 */

	if (rename(tmp_path, path) == -1)
		r = -1;

error_write:
	if (r < 0)
		unlink(tmp_path);
error_mkostemps:
error_create_dirs:
	l_free(tmp_path);
	l_free(path);
	return r;
}

bool storage_create_dirs(void)
{
	const char *state_dir;
	char **state_dirs;

	state_dir = getenv("STATE_DIRECTORY");
	if (!state_dir)
		state_dir = DAEMON_STORAGEDIR;

	l_debug("Using state directory %s", state_dir);

	state_dirs = l_strsplit(state_dir, ':');
	if (!state_dirs[0]) {
		l_strv_free(state_dirs);
		return false;
	}

	storage_path = l_strdup(state_dirs[0]);
	l_strv_free(state_dirs);

	if (create_dirs(storage_path)) {
		l_error("Failed to create %s", storage_path);

		l_free(storage_path);

		return false;
	}

	storage_hotspot_path = l_strdup_printf("%s/hotspot/", storage_path);

	if (create_dirs(storage_hotspot_path)) {
		l_error("Failed to create %s", storage_hotspot_path);

		l_free(storage_path);
		l_free(storage_hotspot_path);

		return false;
	}

	return true;
}

void storage_cleanup_dirs(void)
{
	l_free(storage_path);
	l_free(storage_hotspot_path);
}

char *storage_get_path(const char *format, ...)
{
	va_list args;
	char *fmt, *str;

	if (!format)
		return l_strdup(storage_path);

	fmt = l_strdup_printf("%s/%s", storage_path, format);

	va_start(args, format);
	str = l_strdup_vprintf(fmt, args);
	va_end(args);

	l_free(fmt);
	return str;
}

char *storage_get_hotspot_path(const char *format, ...)
{
	va_list args;
	char *fmt, *str;

	if (!format)
		return l_strdup(storage_hotspot_path);

	fmt = l_strdup_printf("%s/%s", storage_hotspot_path, format);

	va_start(args, format);
	str = l_strdup_vprintf(fmt, args);
	va_end(args);

	l_free(fmt);
	return str;
}

char *storage_get_network_file_path(enum security type, const char *ssid)
{
	char *path;
	const char *c;
	char *hex = NULL;

	for (c = ssid; *c; c++)
		if (!isalnum(*c) && !strchr("-_ ", *c))
			break;

	if (*c) {
		hex = l_util_hexstring((const unsigned char *) ssid,
					strlen(ssid));
		path = storage_get_path("/=%s.%s", hex, security_to_str(type));
		l_free(hex);
	} else
		path = storage_get_path("/%s.%s", ssid, security_to_str(type));

	return path;
}

const char *storage_network_ssid_from_path(const char *path,
							enum security *type)
{
	const char *filename = strrchr(path, '/');
	const char *c, *end;
	char *decoded;
	static char buf[67];

	if (filename)
		filename++;	/* Skip the / */
	else
		filename = path;

	end = strchr(filename, '.');

	if (!end || !security_from_str(end + 1, type))
		return NULL;

	if (filename[0] != '=') {
		if (end == filename || end - filename > 32)
			return NULL;

		for (c = filename; c < end; c++)
			if (!isalnum(*c) && !strchr("-_ ", *c))
				break;

		if (c < end) {
			l_warn("Provisioning file %s contains non-alphanumeric "
				"characters in the name. Please hex-encode. "
				"See man iwd.network", path);
			return NULL;
		}

		memcpy(buf, filename, end - filename);
		buf[end - filename] = '\0';

		return buf;
	}

	if (end - filename <= 1 || end - filename > 65)
		return NULL;

	memcpy(buf, filename + 1, end - filename - 1);
	buf[end - filename - 1] = '0';
	buf[end - filename + 0] = '0';
	buf[end - filename + 1] = '\0';

	decoded = (char *) l_util_from_hexstring(buf, NULL);
	if (!decoded)
		return NULL;

	if (!l_utf8_validate(decoded, (end - filename) / 2, NULL)) {
		l_free(decoded);
		return NULL;
	}

	strcpy(buf, decoded);
	l_free(decoded);

	return buf;
}

/* Groups requiring encryption (if enabled) */
static char *encrypt_groups[] = {
	"Security",
	NULL
};

static bool encrypt_group(const char *group)
{
	char **g;

	for (g = encrypt_groups; *g; g++) {
		if (!strcmp(*g, group))
			return true;
	}

	return false;
}

/*
 * Encrypt needed groups of 'settings' without modifying the object. Returns
 * the entire settings object as data, with encrypted groups as a bytestring
 * set as the value to [Security].EncryptedSecurity. This also includes any
 * embedded groups.
 *
 * Note: If encryption is not enabled or there is no Security group this is
 *       effectively l_settings_to_data.
 */
char *__storage_encrypt(const struct l_settings *settings, const char *name,
				size_t *out_len)
{
	struct iovec ad[2];
	uint8_t salt[32];
	size_t len;
	_auto_(l_settings_free) struct l_settings *to_encrypt = NULL;
	_auto_(l_settings_free) struct l_settings *original = NULL;
	_auto_(l_free) char *plaintext = NULL;
	_auto_(l_free) uint8_t *enc = NULL;
	_auto_(l_strv_free) char **groups = NULL;
	char **i;

	if (!system_key_set || !l_settings_has_group(settings, "Security"))
		return l_settings_to_data(settings, out_len);

	/*
	 * Make two copies of the settings: One will contain only data to be
	 * encrypted (to_encrypt), the other will contain data to be left
	 * unencrypted (original). At the end any encrypted data will be set
	 * into 'original' as EncryptedSecurity.
	 */
	to_encrypt = l_settings_clone(settings);
	original = l_settings_clone(settings);

	groups = l_settings_get_groups(to_encrypt);
	for (i = groups; *i; i++) {
		if (encrypt_group(*i))
			l_settings_remove_group(original, *i);
		else
			l_settings_remove_group(to_encrypt, *i);
	}

	l_settings_remove_embedded_groups(original);

	plaintext = l_settings_to_data(to_encrypt, &len);
	if (!plaintext)
		return NULL;

	l_getrandom(salt, 32);

	ad[0].iov_base = (void *) salt;
	ad[0].iov_len = 32;
	ad[1].iov_base = (void *) name;
	ad[1].iov_len = strlen(name);

	/*
	 * AES-SIV automatically prepends the IV (16 bytes) to the encrypted
	 * data.
	 */
	enc = l_malloc(len + 16);

	if (!aes_siv_encrypt(system_key, sizeof(system_key), plaintext, len,
				ad, 2, enc)) {
		l_error("Could not encrypt [Security] group");
		return NULL;
	}

	l_settings_set_bytes(original, "Security", "EncryptedSalt", salt, 32);
	l_settings_set_bytes(original, "Security", "EncryptedSecurity",
				enc, len + 16);

	return l_settings_to_data(original, out_len);
}

/*
 * Decrypt data in [Security].EncryptedSecurity. This data also includes
 * embedded groups potentially. Once decrypted the data is put back into the
 * object.
 *
 * Note: if encryption is not enabled or there is no Security group settings
 *       is not modified.
 */
int __storage_decrypt(struct l_settings *settings, const char *ssid,
				bool *encrypt)
{
	_auto_(l_free) uint8_t *encrypted = NULL;
	_auto_(l_free) uint8_t *decrypted = NULL;
	_auto_(l_free) uint8_t *salt = NULL;
	_auto_(l_strv_free) char **groups = NULL;
	char **i;
	size_t elen, slen;
	struct iovec ad[2];

	if (!system_key_set)
		goto done;

	if (!l_settings_has_group(settings, "Security"))
		goto done;

	encrypted = l_settings_get_bytes(settings, "Security",
						"EncryptedSecurity", &elen);
	salt = l_settings_get_bytes(settings, "Security",
						"EncryptedSalt", &slen);

	/*
	 * Either profile has never been loaded after enabling encryption or is
	 * missing Encrypted{Salt,Security} values. If either are missing this
	 * profile is corrupted and must be fixed.
	 */
	if (!(encrypted && salt)) {
		/* Profile corrupted */
		if (encrypted || salt) {
			l_warn("Profile %s is corrupted reconfigure manually",
					ssid);
			return -EBADMSG;
		}

		if (encrypt)
			*encrypt = true;

		return 0;
	}

	/*
	 * AES-SIV automatically verifies the IV (16 bytes) and returns only
	 * the decrypted data portion. We add one here for the NULL terminator
	 * since this is always going to be textual data after decryption.
	 */
	decrypted = l_malloc(elen - 16 + 1);

	ad[0].iov_base = (void *)salt;
	ad[0].iov_len = slen;
	ad[1].iov_base = (void *)ssid;
	ad[1].iov_len = strlen(ssid);

	if (!aes_siv_decrypt(system_key, sizeof(system_key), encrypted, elen,
				ad, 2, decrypted)) {
		l_error("Could not decrypt %s profile, did the secret change?",
				ssid);
		return -ENOKEY;
	}

	decrypted[elen - 16] = '\0';

	/*
	 * Remove any groups that are marked as encrypted (plus embedded),
	 * and copy the decrypted groups back into settings.
	 */
	groups = l_settings_get_groups(settings);
	for (i = groups; *i; i++) {
		if (encrypt_group(*i))
			l_settings_remove_group(settings, *i);
	}

	l_settings_remove_embedded_groups(settings);

	/*
	 * Load decrypted data into existing settings. This is not how the API
	 * is indended to be used (since this could result in duplicate groups)
	 * but since the Security group was just removed and EncryptedSecurity
	 * should only contain a Security group its safe to use it this way.
	 */
	if (!l_settings_load_from_data(settings, (const char *) decrypted,
					elen - 16)) {
		l_error("Could not load decrypted security group");
		return -EBADMSG;
	}

done:
	if (encrypt)
		*encrypt = false;

	return 0;
}

/*
 * Decrypts a network profile (if needed). If profile encryption is enabled
 * and the profile is unencrypted it will be encrypted and written back to
 * the file system automatically.
 *
 * 'name' is used for decryption and is used as part of the IV.  Callers
 * should provide a unique identifier here if available.  For example, the
 * SSID, consortium name, etc.
 */
bool storage_decrypt(struct l_settings *settings, const char *path,
			const char *name)
{
	bool needs_encryption;
	_auto_(l_free) char *encrypted = NULL;
	size_t elen;

	if (__storage_decrypt(settings, name, &needs_encryption) < 0)
		return false;

	if (!needs_encryption)
		return true;

	/* Profile never encrypted before. Encrypt and write to disk */
	encrypted = __storage_encrypt(settings, name, &elen);
	if (!encrypted) {
		l_error("Could not encrypt new profile %s", name);
		return false;
	}

	if (write_file(encrypted, elen, false, "%s", path) < 0) {
		l_error("Failed to write out encrypted profile");
		return false;
	}

	l_debug("Encrypted a new profile %s", path);

	return true;
}

struct l_settings *storage_network_open(enum security type, const char *ssid)
{
	struct l_settings *settings;
	_auto_(l_free) char *path = NULL;

	if (ssid == NULL)
		return NULL;

	path = storage_get_network_file_path(type, ssid);

	settings = l_settings_new();

	if (!l_settings_load_from_file(settings, path)) {
		l_error("Error loading %s", path);
		goto error;
	}

	if (type != SECURITY_NONE && !storage_decrypt(settings, path, ssid))
		goto error;

	return settings;

error:
	l_settings_free(settings);
	return NULL;
}

int storage_network_touch(enum security type, const char *ssid)
{
	char *path;
	int ret;

	if (ssid == NULL)
		return -EINVAL;

	path = storage_get_network_file_path(type, ssid);
	ret = utimensat(0, path, NULL, 0);
	l_free(path);

	if (!ret)
		return 0;

	return -errno;
}

void storage_network_sync(enum security type, const char *ssid,
				struct l_settings *settings)
{
	_auto_(l_free) char *data = NULL;
	_auto_(l_free) char *path = NULL;
	size_t length = 0;

	path = storage_get_network_file_path(type, ssid);
	data = __storage_encrypt(settings, ssid, &length);

	if (!data) {
		l_error("Unable to sync profile %s", ssid);
		return;
	}

	write_file(data, length, true, "%s", path);
}

int storage_network_remove(enum security type, const char *ssid)
{
	char *path;
	int ret;

	path = storage_get_network_file_path(type, ssid);
	ret = unlink(path);
	l_free(path);

	return ret < 0 ? -errno : 0;
}

struct l_settings *storage_known_frequencies_load(void)
{
	struct l_settings *known_freqs;
	char *known_freq_file_path;

	known_freqs = l_settings_new();

	known_freq_file_path = storage_get_path("/%s", KNOWN_FREQ_FILENAME);

	if (!l_settings_load_from_file(known_freqs, known_freq_file_path)) {
		l_settings_free(known_freqs);
		known_freqs = NULL;
	}

	l_free(known_freq_file_path);

	return known_freqs;
}

void storage_known_frequencies_sync(struct l_settings *known_freqs)
{
	char *known_freq_file_path;
	char *data;
	size_t len;

	if (!known_freqs)
		return;

	known_freq_file_path = storage_get_path("/%s", KNOWN_FREQ_FILENAME);

	data = l_settings_to_data(known_freqs, &len);
	write_file(data, len, false, "%s", known_freq_file_path);
	l_free(data);

	l_free(known_freq_file_path);
}

struct l_settings *storage_tls_session_cache_load(void)
{
	_auto_(l_settings_free) struct l_settings *cache = l_settings_new();
	_auto_(l_free) char *tls_cache_file_path =
		storage_get_path("%s", TLS_CACHE_FILENAME);

	if (unlikely(!l_settings_load_from_file(cache, tls_cache_file_path)))
		return NULL;

	return l_steal_ptr(cache);
}

void storage_tls_session_cache_sync(struct l_settings *cache)
{
	_auto_(l_free) char *tls_cache_file_path = NULL;
	_auto_(l_free) char *data = NULL;
	size_t len;

	if (!cache)
		return;

	tls_cache_file_path = storage_get_path("%s", TLS_CACHE_FILENAME);
	data = l_settings_to_data(cache, &len);

	/*
	 * Note this data contains cryptographic secrets.  write_file()
	 * happens to set the right permissions on the file.
	 *
	 * TODO: consider encrypting with system_key.
	 */
	write_file(data, len, false, "%s", tls_cache_file_path);
	explicit_bzero(data, len);
}

bool storage_is_file(const char *filename)
{
	char *path;
	struct stat st;
	int err;

	path = storage_get_path("%s", filename);
	err = stat(path, &st);
	l_free(path);

	if (!err && S_ISREG(st.st_mode) != 0)
		return true;

	return false;
}

/*
 * Initialize a systemd encryption key for encrypting/decrypting credentials.
 * This uses the 'extract and expand' concept from RFC 5869 to derive a new
 * fixed length key. Note that a 'zero salt' is used in this derivation which
 * is handled internally in hkdf_extract(). 'TK' denotes the temporary key
 * derived from 'extract' and used as the input to 'expand'.
 *
 * Inputs:
 *	IKM -	Input keying material of arbitrary length. This is the key
 *		obtained directly from systemd.
 * Outputs:
 *	OKM -	Output key material of 32 bytes
 *
 *	TK = HKDF-Extract(<zero>, IKM)
 *	OKM = HKDF-Expand(TK, "System Key", 32)
 */
bool storage_init(const uint8_t *key, size_t key_len)
{
	uint8_t tmp[32];

	if (mlock(system_key, sizeof(system_key)) < 0)
		return false;

	if (!hkdf_extract(L_CHECKSUM_SHA256, NULL, 0, 1, tmp, key, key_len))
		return false;

	system_key_set = hkdf_expand(L_CHECKSUM_SHA256, tmp, sizeof(tmp),
					"System Key",
					system_key, sizeof(system_key));

	explicit_bzero(tmp, sizeof(tmp));
	return system_key_set;
}

void storage_exit(void)
{
	if (system_key_set) {
		explicit_bzero(system_key, sizeof(system_key));
		munlock(system_key, sizeof(system_key));
	}
}
