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

#include <time.h>

struct l_settings;
enum security;

ssize_t read_file(void *buffer, size_t len, const char *path_fmt, ...)
	__attribute__((format(printf, 3, 4)));

ssize_t write_file(const void *buffer, size_t len, bool preserve_times,
			const char *path_fmt, ...)
	__attribute__((format(printf, 4, 5)));

bool storage_is_file(const char *filename);
bool storage_create_dirs(void);
void storage_cleanup_dirs(void);
char *storage_get_path(const char *format, ...);
char *storage_get_hotspot_path(const char *format, ...);

const char *storage_network_ssid_from_path(const char *path,
							enum security *type);
char *storage_get_network_file_path(enum security type, const char *ssid);

struct l_settings *storage_network_open(enum security type, const char *ssid);
int storage_network_touch(enum security type, const char *ssid);
void storage_network_sync(enum security type, const char *ssid,
				struct l_settings *settings);
int storage_network_remove(enum security type, const char *ssid);

struct l_settings *storage_known_frequencies_load(void);
void storage_known_frequencies_sync(struct l_settings *known_freqs);

struct l_settings *storage_tls_session_cache_load(void);
void storage_tls_session_cache_sync(struct l_settings *cache);

int __storage_decrypt(struct l_settings *settings, const char *ssid,
				bool *changed);
char *__storage_encrypt(const struct l_settings *settings, const char *ssid,
				size_t *out_len);
bool storage_decrypt(struct l_settings *settings, const char *path,
			const char *name);

bool storage_init(const uint8_t *key, size_t key_len);
void storage_exit(void);
