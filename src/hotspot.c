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

#include <dirent.h>
#include <errno.h>
#include <stdio.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/module.h"
#include "src/common.h"
#include "src/network.h"
#include "src/util.h"
#include "src/ie.h"
#include "src/knownnetworks.h"
#include "src/storage.h"
#include "src/scan.h"

static struct l_dir_watch *hs20_dir_watch;
static struct l_queue *hs20_settings;

struct hs20_config {
	struct network_info super;
	char *filename;
	uint8_t hessid[6];
	char **nai_realms;
	uint8_t *rc; /* roaming consortium */
	size_t rc_len;
	char *object_path;
	char *name;
};

static bool match_filename(const void *a, const void *b)
{
	const struct hs20_config *config = a;
	const char *filename = b;

	if (!strcmp(config->filename, filename))
		return true;

	return false;
}

static void hs20_config_free(void *user_data)
{
	struct hs20_config *config = user_data;

	l_queue_remove(hs20_settings, config);

	l_strv_free(config->nai_realms);
	l_free(config->rc);
	l_free(config->object_path);
	l_free(config->filename);
	l_free(config->name);
	l_free(config);
}

static int hotspot_network_touch(struct network_info *info)
{
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	return l_path_touch(config->filename);
}

static struct l_settings *hotspot_network_open(struct network_info *info)
{
	struct l_settings *settings;
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	settings = l_settings_new();

	if (!l_settings_load_from_file(settings, config->filename))
		goto error;

	if (!storage_decrypt(settings, config->filename, config->name))
		goto error;

	return settings;

error:
	l_settings_free(settings);
	return NULL;
}

static void hotspot_network_sync(struct network_info *info,
					struct l_settings *settings)
{
	char *data;
	size_t length = 0;
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	data = __storage_encrypt(settings, config->name, &length);
	if (!data) {
		l_error("Unable to sync profile %s", config->filename);
		return;
	}

	write_file(data, length, true, "%s", config->filename);
	l_free(data);
}

static void hotspot_network_remove(struct network_info *info)
{
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	unlink(config->filename);
}

static void hotspot_network_free(struct network_info *info)
{
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	hs20_config_free(config);
}

static const char *hotspot_network_get_path(const struct network_info *info)
{
	char *digest;
	struct l_checksum *sha;
	char **realms;
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	if (config->object_path)
		return config->object_path;

	sha = l_checksum_new(L_CHECKSUM_SHA256);

	if (config->nai_realms) {
		realms = config->nai_realms;

		while (*realms) {
			l_checksum_update(sha, *realms, strlen(*realms));
			realms++;
		}
	}

	if (config->rc)
		l_checksum_update(sha, config->rc, config->rc_len);

	if (!l_memeqzero(config->hessid, 6))
		l_checksum_update(sha, config->hessid, 6);

	digest = l_checksum_get_string(sha);
	l_checksum_free(sha);
	config->object_path = l_strdup_printf("/%.8s_hotspot", digest);
	l_free(digest);

	return config->object_path;
}

static const char *hotspot_network_get_name(const struct network_info *info)
{
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	return config->name;
}

static const char *hotspot_network_get_type(const struct network_info *info)
{
	return "hotspot";
}

static bool hotspot_match_hessid(const struct network_info *info,
					const uint8_t *hessid)
{
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	if (l_memeqzero(config->hessid, 6) || !hessid)
		return false;

	return !memcmp(config->hessid, hessid, 6);
}

static const uint8_t *hotspot_match_roaming_consortium(
						const struct network_info *info,
						const uint8_t *rc_ie,
						size_t rc_len,
						size_t *rc_len_out)
{
	const uint8_t *rc1, *rc2, *rc3;
	size_t rc1_len, rc2_len, rc3_len;
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	if (!config->rc || !rc_ie)
		return NULL;

	if (ie_parse_roaming_consortium_from_data(rc_ie, rc_ie[1] + 2, NULL,
						&rc1, &rc1_len, &rc2, &rc2_len,
						&rc3, &rc3_len) < 0)
		return NULL;

	/* rc1 is guaranteed to be set if the above returns success */
	if (rc1_len == config->rc_len && !memcmp(rc1, config->rc, rc1_len)) {
		if (rc_len_out)
			*rc_len_out = rc1_len;
		return rc1;
	}

	if (rc2 && rc2_len == config->rc_len &&
				!memcmp(rc2, config->rc, rc2_len)) {
		if (rc_len_out)
			*rc_len_out = rc2_len;
		return rc2;
	}

	if (rc3 && rc1_len == config->rc_len &&
				!memcmp(rc3, config->rc, rc3_len)) {
		if (rc_len_out)
			*rc_len_out = rc3_len;
		return rc3;
	}

	return NULL;
}

static bool hotspot_match_nai_realms(const struct network_info *info,
					const char **nai_realms)
{
	const char **realms = nai_realms;
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);

	if (!config->nai_realms || !nai_realms)
		return false;

	while (*realms) {
		if (l_strv_contains(config->nai_realms, *realms))
			return true;

		realms++;
	}

	return false;
}

static const struct iovec *hotspot_network_get_ies(
						const struct network_info *info,
						struct scan_bss *bss,
						size_t *num_elems)
{
	static struct iovec iov[2];
	static uint8_t hs20_ie[7];
	static uint8_t rc_buf[11];
	const uint8_t *rc;
	size_t rc_len;
	size_t iov_elems = 0;

	ie_build_hs20_indication(bss->hs20_version, hs20_ie);

	iov[iov_elems].iov_base = hs20_ie;
	iov[iov_elems].iov_len = hs20_ie[1] + 2;
	iov_elems++;

	rc = hotspot_match_roaming_consortium(info, bss->rc_ie,
						bss->rc_ie[1] + 2, &rc_len);
	if (rc) {
		ie_build_roaming_consortium(rc, rc_len, rc_buf);

		iov[iov_elems].iov_base = rc_buf;
		iov[iov_elems].iov_len = rc_buf[1] + 2;
		iov_elems++;
	}

	*num_elems = iov_elems;

	return iov;
}

static char *hotspot_network_get_file_path(const struct network_info *info)
{
	struct hs20_config *config = l_container_of(info, struct hs20_config,
							super);
	return l_strdup(config->filename);
}

static struct network_info_ops hotspot_ops = {
	.open = hotspot_network_open,
	.touch = hotspot_network_touch,
	.sync = hotspot_network_sync,
	.remove = hotspot_network_remove,
	.free = hotspot_network_free,
	.get_path = hotspot_network_get_path,
	.get_name = hotspot_network_get_name,
	.get_type = hotspot_network_get_type,
	.get_extra_ies = hotspot_network_get_ies,
	.get_file_path = hotspot_network_get_file_path,

	.match_hessid = hotspot_match_hessid,
	.match_roaming_consortium = hotspot_match_roaming_consortium,
	.match_nai_realms = hotspot_match_nai_realms,
};

static struct hs20_config *hs20_config_new(struct l_settings *settings,
						char *filename,
						struct network_config *c)
{
	struct hs20_config *config;
	char *hessid_str;
	char **nai_realms = NULL;
	size_t rc_len;
	uint8_t *rc;
	char *name;

	/* One of HESSID, NAI realms, or Roaming Consortium must be included */
	hessid_str = l_settings_get_string(settings, "Hotspot", "HESSID");
	nai_realms = l_settings_get_string_list(settings, "Hotspot",
						"NAIRealmNames", ',');
	rc = l_settings_get_bytes(settings, "Hotspot", "RoamingConsortium",
								&rc_len);

	name = l_settings_get_string(settings, "Hotspot", "Name");

	if ((!hessid_str && !nai_realms && !rc) || !name) {
		l_error("Could not parse hotspot config %s", filename);
		goto free_values;
	}

	if (!storage_decrypt(settings, filename, name)) {
		l_error("Could not open hotspot profile %s", filename);
		goto free_values;
	}

	config = l_new(struct hs20_config, 1);

	if (hessid_str) {
		if (!util_string_to_address(hessid_str, config->hessid)) {
			l_error("Invalid HESSID in settings");
			l_free(config);
			goto free_values;
		}

		l_free(hessid_str);
	}

	if (nai_realms)
		config->nai_realms = nai_realms;

	if (rc) {
		/*
		 * WiFi Alliance Hotspot 2.0 Spec - Section 3.1.4
		 *
		 * "The Consortium OI field is 3 or 5-octet field set to a value
		 * of a roaming consortium OI"
		 */
		if (rc && rc_len != 3 && rc_len != 5) {
			l_warn("invalid RoamingConsortium length %zu", rc_len);
			l_free(rc);
			rc = NULL;
		}

		config->rc = rc;
		config->rc_len = rc_len;
	}

	__network_info_init(&config->super, NULL, SECURITY_8021X, c);
	config->super.is_hotspot = true;
	config->name = name;
	config->filename = l_strdup(filename);
	config->super.ops = &hotspot_ops;

	known_networks_add(&config->super);

	return config;

free_values:
	l_strv_free(nai_realms);
	l_free(hessid_str);
	l_free(name);
	l_free(rc);

	return NULL;
}

static void hs20_dir_watch_cb(const char *filename,
				enum l_dir_watch_event event,
				void *user_data)
{
	struct l_settings *new;
	uint64_t connected_time;
	struct hs20_config *hs20;
	struct network_config config;

	L_AUTO_FREE_VAR(char *, full_path) = NULL;

	/*
	 * Ignore notifications for the actual directory, we can't do
	 * anything about some of them anyway.  Only react to
	 * notifications for files in the storage directory.
	 */
	if (!filename)
		return;

	full_path = storage_get_hotspot_path("%s", filename);

	switch (event) {
	case L_DIR_WATCH_EVENT_CREATED:
		new = l_settings_new();

		if (!l_settings_load_from_file(new, full_path)) {
			l_settings_free(new);
			return;
		}

		__network_config_parse(new, full_path, &config);

		hs20 = hs20_config_new(new, full_path, &config);
		l_settings_free(new);

		if (!hs20)
			return;

		l_queue_push_head(hs20_settings, hs20);
		break;
	case L_DIR_WATCH_EVENT_REMOVED:
		hs20 = l_queue_remove_if(hs20_settings, match_filename,
						full_path);
		if (!hs20)
			return;

		known_networks_remove(&hs20->super);
		break;
	case L_DIR_WATCH_EVENT_MODIFIED:
		hs20 = l_queue_find(hs20_settings, match_filename, full_path);
		if (!hs20)
			return;

		new = l_settings_new();

		if (!l_settings_load_from_file(new, full_path)) {
			l_settings_free(new);
			return;
		}

		__network_config_parse(new, full_path, &config);
		known_network_update(&hs20->super, &config);

		/* TODO: Update hotspot specific settings */

		l_settings_free(new);

		break;
	case L_DIR_WATCH_EVENT_ACCESSED:
		break;
	case L_DIR_WATCH_EVENT_ATTRIB:
		hs20 = l_queue_find(hs20_settings, match_filename, full_path);
		if (!hs20)
			return;

		connected_time = l_path_get_mtime(full_path);
		known_network_set_connected_time(&hs20->super,
							connected_time);
		break;
	}
}

static void hs20_dir_watch_destroy(void *user_data)
{
	hs20_dir_watch = NULL;
}

static int hotspot_init(void)
{
	DIR *dir;
	struct dirent *dirent;

	L_AUTO_FREE_VAR(char *, hs20_dir) = storage_get_hotspot_path(NULL);

	dir = opendir(hs20_dir);
	if (!dir)
		return -ENOENT;

	hs20_settings = l_queue_new();

	while ((dirent = readdir(dir))) {
		struct hs20_config *hs20;
		struct l_settings *s;
		char *filename;
		struct network_config config;

		filename = l_strdup_printf("%s/%s", hs20_dir, dirent->d_name);
		s = l_settings_new();

		if (dirent->d_type == DT_UNKNOWN) {
			if (!storage_is_file(filename))
				goto next;
		} else if (dirent->d_type != DT_REG &&
						dirent->d_type != DT_LNK) {
			goto next;
		}

		if (!l_settings_load_from_file(s, filename))
			goto next;

		__network_config_parse(s, filename, &config);

		hs20 = hs20_config_new(s, filename, &config);
		if (hs20)
			l_queue_push_head(hs20_settings, hs20);

next:
		l_free(filename);
		l_settings_free(s);
	}

	closedir(dir);

	hs20_dir_watch = l_dir_watch_new(hs20_dir, hs20_dir_watch_cb, NULL,
						hs20_dir_watch_destroy);

	return 0;
}

static void hotspot_exit(void)
{
	l_dir_watch_destroy(hs20_dir_watch);

	l_queue_destroy(hs20_settings, NULL);
	hs20_settings = NULL;
}

IWD_MODULE(hotspot, hotspot_init, hotspot_exit)
IWD_MODULE_DEPENDS(hotspot, known_networks)
