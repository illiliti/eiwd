/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016-2019  Intel Corporation. All rights reserved.
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

#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>

#include <ell/ell.h>

#include "ell/useful.h"
#include "src/iwd.h"
#include "src/module.h"
#include "src/storage.h"
#include "src/common.h"
#include "src/network.h"
#include "src/dbus.h"
#include "src/knownnetworks.h"
#include "src/scan.h"
#include "src/util.h"
#include "src/watchlist.h"
#include "src/band.h"

static struct l_queue *known_networks;
static size_t num_known_hidden_networks;
static struct l_dir_watch *storage_dir_watch;
static struct watchlist known_network_watches;
static struct l_settings *known_freqs;

void __network_config_parse(const struct l_settings *settings,
					const char *full_path,
					struct network_config *config)
{
	bool b;
	const char *value;
	uint8_t new_addr[6];

	memset(config, 0, sizeof(struct network_config));

	config->connected_time = l_path_get_mtime(full_path);

	/* If no entry, default to AutoConnectable=True */
	if (!l_settings_get_bool(settings, NET_AUTOCONNECT, &b))
		b = true;

	config->is_autoconnectable = b;

	if (!l_settings_get_bool(settings, NET_HIDDEN, &b))
		b = false;

	config->is_hidden = b;

	if (!l_settings_get_bool(settings, NET_ALWAYS_RANDOMIZE_ADDRESS, &b))
		b = false;

	config->always_random_addr = b;

	value = l_settings_get_value(settings, NET_ADDRESS_OVERRIDE);
	if (value) {
		if (util_string_to_address(value, new_addr) &&
					util_is_valid_sta_address(new_addr)) {
			config->override_addr = true;
			memcpy(config->sta_addr, new_addr, sizeof(new_addr));
		} else
			l_warn("[%s].%s is not a valid MAC address",
					NET_ADDRESS_OVERRIDE);
	}

	if (config->override_addr && config->always_random_addr) {
		l_warn("Cannot use both [%s].%s and [%s].%s, using latter",
				NET_ALWAYS_RANDOMIZE_ADDRESS,
				NET_ADDRESS_OVERRIDE);
		config->always_random_addr = false;
	}

	if (!l_settings_get_bool(settings, NET_TRANSITION_DISABLE, &b))
		b = false;

	config->have_transition_disable = b;
	if (config->have_transition_disable) {
		unsigned int i;
		char **modes = l_settings_get_string_list(settings,
					NET_TRANSITION_DISABLE_MODES, ' ');

		for (i = 0; modes && modes[i]; i++) {
			if (!strcmp(modes[i], "personal"))
				set_bit(&config->transition_disable, 0);
			else if (!strcmp(modes[i], "enterprise"))
				set_bit(&config->transition_disable, 2);
			else if (!strcmp(modes[i], "open"))
				set_bit(&config->transition_disable, 3);
			else
				l_warn("[%s].%s: Unrecognized value: %s",
						NET_TRANSITION_DISABLE_MODES,
						modes[i]);
		}

		l_strfreev(modes);
	}
}

void __network_info_init(struct network_info *info,
				const char *ssid, enum security security,
				struct network_config *config)
{
	if (ssid)
		strcpy(info->ssid, ssid);

	info->type = security;

	memcpy(&info->config, config, sizeof(struct network_config));

	if (info->config.is_hidden)
		num_known_hidden_networks++;
}

static void network_info_free(void *data)
{
	struct network_info *network = data;

	l_queue_destroy(network->known_frequencies, l_free);

	network->ops->free(network);
}

static int connected_time_compare(const void *a, const void *b, void *user_data)
{
	const struct network_info *ni_a = a;
	const struct network_info *ni_b = b;
	uint64_t ta = ni_a->config.connected_time;
	uint64_t tb = ni_b->config.connected_time;

	if (l_time_after(ta, tb))
		return -1;
	else if (l_time_before(ta, tb))
		return 1;

	return 0;
}

static const char *known_network_get_path(const struct network_info *network)
{
	static char path[256];
	unsigned int pos = 0, i;

	L_WARN_ON((pos = snprintf(path, sizeof(path), "%s/",
					IWD_BASE_PATH)) >= (int) sizeof(path));

	for (i = 0; network->ssid[i] && pos < sizeof(path); i++)
		pos += snprintf(path + pos, sizeof(path) - pos, "%02x",
				(unsigned char)network->ssid[i]);

	if (pos < sizeof(path))
		snprintf(path + pos, sizeof(path) - pos, "_%s",
			security_to_str(network->type));
	path[sizeof(path) - 1] = '\0';

	return path;
}

/*
 * Finds the position n of this network_info in the list of known networks
 * sorted by connected_time.  E.g. an offset of 0 means the most recently
 * used network.  Only networks with seen_count > 0 are considered.  E.g.
 * only networks that appear in scan results on at least one wifi card.
 *
 * Returns -ENOENT if the entry couldn't be found.
 */
int known_network_offset(const struct network_info *target)
{
	const struct l_queue_entry *entry;
	const struct network_info *info;
	int n = 0;

	for (entry = l_queue_get_entries(known_networks); entry;
						entry = entry->next) {
		info = entry->data;
		if (target == info)
			return n;

		if (info->seen_count)
			n += 1;
	}

	return -ENOENT;
}

static void known_network_register_dbus(struct network_info *network)
{
	const char *path = known_network_get_path(network);

	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
					IWD_KNOWN_NETWORK_INTERFACE, network))
		l_info("Unable to register %s interface",
						IWD_KNOWN_NETWORK_INTERFACE);

	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
					L_DBUS_INTERFACE_PROPERTIES, network))
		l_info("Unable to register %s interface",
						L_DBUS_INTERFACE_PROPERTIES);
}

static void known_network_set_autoconnect(struct network_info *network,
							bool autoconnect)
{
	if (network->config.is_autoconnectable == autoconnect)
		return;

	network->config.is_autoconnectable = autoconnect;

	l_dbus_property_changed(dbus_get_bus(), known_network_get_path(network),
				IWD_KNOWN_NETWORK_INTERFACE, "AutoConnect");
}

static int known_network_touch(struct network_info *info)
{
	return storage_network_touch(info->type, info->ssid);
}

static struct l_settings *known_network_open(struct network_info *info)
{
	return storage_network_open(info->type, info->ssid);
}

static void known_network_sync(struct network_info *info,
					struct l_settings *settings)
{
	storage_network_sync(info->type, info->ssid, settings);
}

static void known_network_remove(struct network_info *info)
{
	storage_network_remove(info->type, info->ssid);
}

static void known_network_free(struct network_info *info)
{
	l_free(info);
}

static const char *known_network_get_name(const struct network_info *info)
{
	return info->ssid;
}

static const char *known_network_get_type(const struct network_info *info)
{
	return security_to_str(info->type);
}

static char *known_network_get_file_path(const struct network_info *info)
{
	return storage_get_network_file_path(info->type, info->ssid);
}

static struct network_info_ops known_network_ops = {
	.open = known_network_open,
	.touch = known_network_touch,
	.sync = known_network_sync,
	.remove = known_network_remove,
	.free = known_network_free,
	.get_path = known_network_get_path,
	.get_name = known_network_get_name,
	.get_type = known_network_get_type,
	.get_file_path = known_network_get_file_path,
};

struct l_settings *network_info_open_settings(struct network_info *info)
{
	return info->ops->open(info);
}

int network_info_touch(struct network_info *info)
{
	return info->ops->touch(info);
}

const char *network_info_get_path(const struct network_info *info)
{
	return info->ops->get_path(info);
}

const char *network_info_get_name(const struct network_info *info)
{
	return info->ops->get_name(info);
}

const char *network_info_get_type(const struct network_info *info)
{
	return info->ops->get_type(info);
}

const struct iovec *network_info_get_extra_ies(const struct network_info *info,
						struct scan_bss *bss,
						size_t *num_elems)
{
	if (!info || !info->ops->get_extra_ies)
		return NULL;

	return info->ops->get_extra_ies(info, bss, num_elems);
}

const uint8_t *network_info_get_uuid(struct network_info *info)
{
	char *file_path;
	char *to_hash;
	/*
	 * 16 bytes of randomness. Since we only care about a unique value there
	 * is no need to use any special pre-defined namespace.
	 */
	static const uint8_t nsid[16] = {
		0xfd, 0x88, 0x6f, 0x1e, 0xdf, 0x02, 0xd7, 0x8b,
		0xc4, 0x90, 0x30, 0x59, 0x73, 0x8a, 0x86, 0x0d
	};

	if (info->has_uuid)
		return info->uuid;

	file_path = info->ops->get_file_path(info);

	/*
	 * This will generate a UUID based on file path and mtime. This
	 * is done so we can get a different UUID if the network has
	 * been forgotten.
	 */
	to_hash = l_strdup_printf("%s_%" PRIu64, file_path,
					info->config.connected_time);
	l_uuid_v5(nsid, to_hash, strlen(to_hash), info->uuid);
	l_free(to_hash);
	l_free(file_path);

	info->has_uuid = true;

	return info->uuid;
}

void network_info_set_uuid(struct network_info *info, const uint8_t *uuid)
{
	memcpy(info->uuid, uuid, 16);
	info->has_uuid = true;
}

struct scan_freq_set *network_info_get_roam_frequencies(
					const struct network_info *info,
					uint32_t current_freq,
					uint8_t max)
{
	struct scan_freq_set *freqs;
	const struct l_queue_entry *entry;

	freqs = scan_freq_set_new();

	for (entry = l_queue_get_entries(info->known_frequencies); entry && max;
			entry = entry->next) {
		struct known_frequency *kn = entry->data;

		if (kn->frequency == current_freq)
			continue;

		scan_freq_set_add(freqs, kn->frequency);

		max--;
	}

	if (scan_freq_set_isempty(freqs)) {
		scan_freq_set_free(freqs);
		return NULL;
	}

	return freqs;
}

bool network_info_match_hessid(const struct network_info *info,
				const uint8_t *hessid)
{
	if (!info->ops->match_hessid)
		return false;

	return info->ops->match_hessid(info, hessid);
}

const uint8_t *network_info_match_roaming_consortium(
						const struct network_info *info,
						const uint8_t *rc,
						size_t rc_len,
						size_t *rc_len_out)
{
	if (!info->ops->match_roaming_consortium)
		return NULL;

	return info->ops->match_roaming_consortium(info, rc, rc_len,
							rc_len_out);
}

bool network_info_match_nai_realm(const struct network_info *info,
						const char **nai_realms)
{
	if (!info->ops->match_nai_realms)
		return false;

	return info->ops->match_nai_realms(info, nai_realms);
}

void known_network_set_connected_time(struct network_info *network,
					uint64_t connected_time)
{
	if (network->config.connected_time == connected_time)
		return;

	network->config.connected_time = connected_time;

	l_dbus_property_changed(dbus_get_bus(),
				known_network_get_path(network),
				IWD_KNOWN_NETWORK_INTERFACE,
				"LastConnectedTime");

	l_queue_remove(known_networks, network);
	l_queue_insert(known_networks, network, connected_time_compare, NULL);
}

void known_network_update(struct network_info *network,
					struct network_config *new)
{
	struct network_config *old = &network->config;

	known_network_set_connected_time(network, new->connected_time);

	if (old->is_hidden != new->is_hidden) {
		if (old->is_hidden && !new->is_hidden)
			num_known_hidden_networks--;
		else if (!old->is_hidden && new->is_hidden)
			num_known_hidden_networks++;

		l_dbus_property_changed(dbus_get_bus(),
					known_network_get_path(network),
					IWD_KNOWN_NETWORK_INTERFACE,
					"Hidden");

		old->is_hidden = new->is_hidden;
	}

	known_network_set_autoconnect(network, new->is_autoconnectable);

	memcpy(&network->config, new, sizeof(struct network_config));
}

bool known_networks_foreach(known_networks_foreach_func_t function,
				void *user_data)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(known_networks); entry;
			entry = entry->next)
		if (!function(entry->data, user_data))
			break;

	return !entry;
}

bool known_networks_has_hidden(void)
{
	return num_known_hidden_networks ? true : false;
}

static bool network_info_match(const void *a, const void *b)
{
	const struct network_info *ni_a = a;
	const struct network_info *ni_b = b;

	if (ni_a->type != ni_b->type)
		return false;

	if (strcmp(ni_a->ssid, ni_b->ssid))
		return false;

	return true;
}

struct network_info *known_networks_find(const char *ssid,
						enum security security)
{
	struct network_info query;

	query.type = security;
	strcpy(query.ssid, ssid);

	return l_queue_find(known_networks, network_info_match, &query);
}

struct scan_freq_set *known_networks_get_recent_frequencies(
						uint8_t num_networks_tosearch)
{
	/*
	 * This search function assumes that the known networks are always
	 * sorted by the last connection time with the most recent ones being on
	 * top. Therefore, we just need to get the top NUM of networks from the
	 * list.
	 */
	const struct l_queue_entry *network_entry;
	const struct l_queue_entry *freq_entry;
	struct scan_freq_set *set;

	if (!num_networks_tosearch)
		return NULL;

	set = scan_freq_set_new();

	for (network_entry = l_queue_get_entries(known_networks);
				network_entry && num_networks_tosearch;
				network_entry = network_entry->next,
						num_networks_tosearch--) {
		const struct network_info *network = network_entry->data;

		for (freq_entry = l_queue_get_entries(
						network->known_frequencies);
				freq_entry; freq_entry = freq_entry->next) {
			const struct known_frequency *known_freq =
							freq_entry->data;

			scan_freq_set_add(set, known_freq->frequency);
		}
	}

	return set;
}

static bool known_frequency_match(const void *a, const void *b)
{
	const struct known_frequency *known_freq = a;
	const uint32_t *frequency = b;

	return known_freq->frequency == *frequency;
}

/*
 * Adds a frequency to the 'known' set of frequencies that this network
 * operates on.  The list is sorted according to most-recently seen
 */
int known_network_add_frequency(struct network_info *info, uint32_t frequency)
{
	struct known_frequency *known_freq;

	if (!info->known_frequencies)
		info->known_frequencies = l_queue_new();

	known_freq = l_queue_remove_if(info->known_frequencies,
					known_frequency_match, &frequency);
	if (!known_freq) {
		known_freq = l_new(struct known_frequency, 1);
		known_freq->frequency = frequency;
	}

	l_queue_push_head(info->known_frequencies, known_freq);

	return 0;
}

static struct l_dbus_message *known_network_forget(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct network_info *network = user_data;
	struct l_dbus_message *reply;

	/* Other actions taken care of by the filesystem watch callback */
	network->ops->remove(network);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static bool known_network_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network_info *network = user_data;

	l_dbus_message_builder_append_basic(builder, 's',
						network_info_get_name(network));

	return true;
}

static bool known_network_property_get_type(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network_info *network = user_data;

	l_dbus_message_builder_append_basic(builder, 's',
						network_info_get_type(network));

	return true;
}

static bool known_network_property_get_hidden(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network_info *network = user_data;
	bool is_hidden = network->config.is_hidden;

	l_dbus_message_builder_append_basic(builder, 'b', &is_hidden);

	return true;
}

static bool known_network_property_get_autoconnect(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network_info *network = user_data;
	bool autoconnect = network->config.is_autoconnectable;

	l_dbus_message_builder_append_basic(builder, 'b', &autoconnect);

	return true;
}

static struct l_dbus_message *known_network_property_set_autoconnect(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct network_info *network = user_data;
	struct l_settings *settings;
	bool autoconnect;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &autoconnect))
		return dbus_error_invalid_args(message);

	if (network->config.is_autoconnectable == autoconnect)
		return l_dbus_message_new_method_return(message);

	settings = network->ops->open(network);
	if (!settings)
		return dbus_error_failed(message);

	l_settings_set_bool(settings, NET_AUTOCONNECT, autoconnect);

	network->ops->sync(network, settings);
	l_settings_free(settings);

	return l_dbus_message_new_method_return(message);
}

static bool known_network_property_get_last_connected(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct network_info *network = user_data;
	char datestr[64];
	struct tm tm;
	time_t seconds = l_time_to_secs(network->config.connected_time);

	if (seconds == 0)
		return false;

	gmtime_r(&seconds, &tm);

	if (!strftime(datestr, sizeof(datestr), "%FT%TZ", &tm))
		return false;

	l_dbus_message_builder_append_basic(builder, 's', datestr);

	return true;
}

static void setup_known_network_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Forget", 0,
				known_network_forget, "", "");

	l_dbus_interface_property(interface, "Name", 0, "s",
					known_network_property_get_name, NULL);
	l_dbus_interface_property(interface, "Type", 0, "s",
					known_network_property_get_type, NULL);
	l_dbus_interface_property(interface, "Hidden", 0, "b",
					known_network_property_get_hidden,
					NULL);
	l_dbus_interface_property(interface, "AutoConnect", 0, "b",
					known_network_property_get_autoconnect,
					known_network_property_set_autoconnect);
	l_dbus_interface_property(interface, "LastConnectedTime", 0, "s",
				known_network_property_get_last_connected,
				NULL);
}

void known_networks_remove(struct network_info *network)
{
	if (network->config.is_hidden)
		num_known_hidden_networks--;

	l_queue_remove(known_networks, network);
	l_dbus_unregister_object(dbus_get_bus(),
					known_network_get_path(network));

	WATCHLIST_NOTIFY(&known_network_watches,
				known_networks_watch_func_t,
				KNOWN_NETWORKS_EVENT_REMOVED, network);

	if (known_freqs && network->has_uuid) {
		char uuid[37];

		l_uuid_to_string(network->uuid, uuid, sizeof(uuid));
		l_settings_remove_group(known_freqs, uuid);
		storage_known_frequencies_sync(known_freqs);
	}

	network_info_free(network);
}

void known_networks_add(struct network_info *network)
{
	l_queue_insert(known_networks, network, connected_time_compare, NULL);
	known_network_register_dbus(network);

	WATCHLIST_NOTIFY(&known_network_watches,
				known_networks_watch_func_t,
				KNOWN_NETWORKS_EVENT_ADDED, network);
}

static void known_network_new(const char *ssid, enum security security,
					struct network_config *config)
{
	struct network_info *network;

	network = l_new(struct network_info, 1);
	__network_info_init(network, ssid, security, config);
	network->ops = &known_network_ops;
	known_networks_add(network);
}

static void known_networks_watch_cb(const char *filename,
					enum l_dir_watch_event event,
					void *user_data)
{
	const char *ssid;
	L_AUTO_FREE_VAR(char *, full_path) = NULL;
	enum security security;
	struct network_info *network_before;
	struct l_settings *settings;
	uint64_t connected_time;

	/*
	 * Ignore notifications for the actual directory, we can't do
	 * anything about some of them anyway.  Only react to
	 * notifications for files in the storage directory.
	 */
	if (!filename)
		return;

	ssid = storage_network_ssid_from_path(filename, &security);
	if (!ssid)
		return;

	network_before = known_networks_find(ssid, security);

	full_path = storage_get_network_file_path(security, ssid);

	switch (event) {
	case L_DIR_WATCH_EVENT_CREATED:
	case L_DIR_WATCH_EVENT_REMOVED:
	case L_DIR_WATCH_EVENT_MODIFIED:
		/*
		 * For now treat all the operations the same.  E.g. they may
		 * result in the removal of the network (file moved out, not
		 * readable or invalid) or the creation of a new network (file
		 * created, permissions granted, syntax fixed, etc.)
		 * so we always need to re-read the file.
		 */
		settings = storage_network_open(security, ssid);

		if (settings) {
			struct network_config config;

			__network_config_parse(settings, full_path, &config);

			if (network_before)
				known_network_update(network_before, &config);
			else
				known_network_new(ssid, security, &config);
		} else if (network_before)
			known_networks_remove(network_before);

		l_settings_free(settings);

		break;
	case L_DIR_WATCH_EVENT_ACCESSED:
		break;
	case L_DIR_WATCH_EVENT_ATTRIB:
		if (network_before) {
			connected_time = l_path_get_mtime(full_path);
			known_network_set_connected_time(network_before,
								connected_time);
		}

		break;
	}
}

static void known_networks_watch_destroy(void *user_data)
{
	storage_dir_watch = NULL;
}

static struct l_queue *known_frequencies_from_string(char *freq_set_str)
{
	struct l_queue *known_frequencies;
	struct known_frequency *known_freq;
	uint16_t t;

	if (!freq_set_str)
		return NULL;

	if (*freq_set_str == '\0')
		return NULL;

	known_frequencies = l_queue_new();

	while (*freq_set_str != '\0') {
		errno = 0;

		t = strtoul(freq_set_str, &freq_set_str, 10);

		if (unlikely(errno == ERANGE || !t ||
					!band_freq_to_channel(t, NULL)))
			goto error;

		known_freq = l_new(struct known_frequency, 1);
		known_freq->frequency = t;

		l_queue_push_tail(known_frequencies, known_freq);
	}

	if (l_queue_isempty(known_frequencies))
		goto error;

	return known_frequencies;

error:
	l_queue_destroy(known_frequencies, l_free);

	return NULL;
}

static void known_frequency_to_string(void *data, void *user_data)
{
	struct known_frequency *known_freq = data;
	struct l_string *str = user_data;

	l_string_append_printf(str, " %u", known_freq->frequency);
}

static char *known_frequencies_to_string(struct l_queue *known_frequencies)
{
	struct l_string *str;

	str = l_string_new(100);

	l_queue_foreach(known_frequencies, known_frequency_to_string, str);

	return l_string_unwrap(str);
}

struct hotspot_search {
	struct network_info *info;
	const char *path;
};

static bool match_hotspot_path(const struct network_info *info, void *user_data)
{
	struct hotspot_search *search = user_data;
	char *path;

	if (!info->is_hotspot)
		return true;

	path = info->ops->get_file_path(info);

	if (!strcmp(path, search->path)) {
		l_free(path);
		search->info = (struct network_info *)info;
		return false;
	}

	l_free(path);

	return true;
}

static struct network_info *find_network_info_from_path(const char *path)
{
	enum security security;
	struct hotspot_search search;
	const char *ssid = storage_network_ssid_from_path(path, &security);

	if (ssid)
		return known_networks_find(ssid, security);

	search.info = NULL;
	search.path = path;

	/* Try hotspot */
	known_networks_foreach(match_hotspot_path, &search);

	return search.info;
}

static int known_network_frequencies_load(void)
{
	char **groups;
	struct l_queue *known_frequencies;
	uint32_t i;
	uint8_t uuid[16];

	known_freqs = storage_known_frequencies_load();
	if (!known_freqs) {
		l_debug("No known frequency file found.");
		return 0;
	}

	groups = l_settings_get_groups(known_freqs);

	for (i = 0; groups[i]; i++) {
		struct network_info *info;
		char *freq_list;
		const char *path = l_settings_get_value(known_freqs, groups[i],
							"name");
		if (!path)
			goto invalid_entry;

		info = find_network_info_from_path(path);
		if (!info)
			goto invalid_entry;

		if (info->has_uuid)
			goto invalid_entry;

		freq_list = l_settings_get_string(known_freqs, groups[i],
							"list");
		if (!freq_list)
			goto invalid_entry;

		known_frequencies = known_frequencies_from_string(freq_list);
		l_free(freq_list);

		if (!known_frequencies)
			goto invalid_entry;

		if (!l_uuid_from_string(groups[i], uuid)) {
			l_queue_destroy(known_frequencies, l_free);
			goto invalid_entry;
		}

		network_info_set_uuid(info, uuid);
		info->known_frequencies = known_frequencies;

		continue;

invalid_entry:
		l_settings_remove_group(known_freqs, groups[i]);
	}

	l_strv_free(groups);

	return 0;
}

/*
 * Syncs a single network_info frequency to the global frequency file
 */
void known_network_frequency_sync(struct network_info *info)
{
	char *freq_list_str;
	char *file_path;
	char group[37];

	if (!info->known_frequencies)
		return;

	if (!known_freqs)
		known_freqs = l_settings_new();

	freq_list_str = known_frequencies_to_string(info->known_frequencies);

	file_path = info->ops->get_file_path(info);

	l_uuid_to_string(network_info_get_uuid(info), group, sizeof(group));

	l_settings_set_value(known_freqs, group, "name", file_path);
	l_settings_set_value(known_freqs, group, "list", freq_list_str);
	l_free(file_path);
	l_free(freq_list_str);

	storage_known_frequencies_sync(known_freqs);
}

uint32_t known_networks_watch_add(known_networks_watch_func_t func,
					void *user_data,
					known_networks_destroy_func_t destroy)
{
	return watchlist_add(&known_network_watches, func, user_data, destroy);
}

void known_networks_watch_remove(uint32_t id)
{
	watchlist_remove(&known_network_watches, id);
}

static int known_networks_init(void)
{
	struct l_dbus *dbus = dbus_get_bus();
	DIR *dir;
	struct dirent *dirent;

	L_AUTO_FREE_VAR(char *, storage_dir) = storage_get_path(NULL);

	if (!l_dbus_register_interface(dbus, IWD_KNOWN_NETWORK_INTERFACE,
						setup_known_network_interface,
						NULL, false)) {
		l_info("Unable to register %s interface",
				IWD_KNOWN_NETWORK_INTERFACE);
		return -EPERM;
	}

	dir = opendir(storage_dir);
	if (!dir) {
		l_info("Unable to open %s: %s", storage_dir, strerror(errno));
		l_dbus_unregister_interface(dbus, IWD_KNOWN_NETWORK_INTERFACE);
		return -ENOENT;
	}

	known_networks = l_queue_new();

	while ((dirent = readdir(dir))) {
		const char *ssid;
		enum security security;
		struct l_settings *settings;
		L_AUTO_FREE_VAR(char *, full_path) = NULL;

		if (dirent->d_type == DT_UNKNOWN) {
			if (!storage_is_file(dirent->d_name))
				continue;
		} else if (dirent->d_type != DT_REG &&
						dirent->d_type != DT_LNK) {
			continue;
		}

		ssid = storage_network_ssid_from_path(dirent->d_name,
							&security);
		if (!ssid)
			continue;

		settings = storage_network_open(security, ssid);

		full_path = storage_get_network_file_path(security, ssid);

		if (settings) {
			struct network_config config;

			__network_config_parse(settings, full_path, &config);
			known_network_new(ssid, security, &config);
		}

		l_settings_free(settings);
	}

	closedir(dir);

	storage_dir_watch = l_dir_watch_new(storage_dir,
						known_networks_watch_cb, NULL,
						known_networks_watch_destroy);
	watchlist_init(&known_network_watches, NULL);

	return 0;
}

static void known_networks_exit(void)
{
	struct l_dbus *dbus = dbus_get_bus();

	l_dir_watch_destroy(storage_dir_watch);

	l_queue_destroy(known_networks, network_info_free);
	known_networks = NULL;

	l_dbus_unregister_interface(dbus, IWD_KNOWN_NETWORK_INTERFACE);

	watchlist_destroy(&known_network_watches);
}

IWD_MODULE(known_networks, known_networks_init, known_networks_exit)

static void known_frequencies_exit(void)
{
	l_settings_free(known_freqs);
}

/*
 * Since the known frequency file should only be read in after all known
 * networks are loaded (including hotspots) we need to create another module
 * here which depends on hotspot.
 */
IWD_MODULE(known_frequencies, known_network_frequencies_load, known_frequencies_exit)
IWD_MODULE_DEPENDS(known_frequencies, hotspot)
