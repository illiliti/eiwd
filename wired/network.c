/*
 *
 *  Ethernet daemon for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
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
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ell/ell.h>

#include "src/module.h"
#include "wired/network.h"

#define STORAGEFILE_SUFFIX	".8021x"
#define STORAGEFILE_SUFFIX_LEN	6

struct network {
	char *name;
};

static struct l_queue *network_list;
static struct l_dir_watch *storage_watch;
static char *storage_path;

static char *network_name_from_filename(const char *filename)
{
	if (!l_str_has_suffix(filename, STORAGEFILE_SUFFIX))
		return NULL;

	return l_strndup(filename, strlen(filename) - STORAGEFILE_SUFFIX_LEN);
}

static struct network *network_new(const char *name)
{
	struct network *net;

	l_debug("Creating network '%s'", name);

	net = l_new(struct network, 1);
	net->name = l_strdup(name);

	return net;
}

static void network_free(void *data)
{
	struct network *net = data;

	l_debug("Freeing network '%s'", net->name);

	l_free(net->name);
	l_free(net);
}

static bool network_match(const void *a, const void *b)
{
	const struct network *net = a;
	const char *name = b;

	return !strcmp(net->name, name);
}

static struct network *network_lookup(const char *name)
{
	return l_queue_find(network_list, network_match, name);
}

static void network_create(const char *name)
{
	struct network *net;

	net = network_lookup(name);
	if (net) {
		l_debug("Refresh network '%s'", net->name);
		return;
	}

	net = network_new(name);
	l_queue_push_tail(network_list, net);
}

static void network_remove(const char *name)
{
	struct network *net;

	net = l_queue_remove_if(network_list, network_match, name);
	if (net)
		network_free(net);
}

static void network_reload(const char *name)
{
	struct network *net;

	net = network_lookup(name);
	if (net) {
		l_debug("Refresh network '%s'", net->name);
		return;
	}
}

struct l_settings *network_lookup_security(const char *network)
{
	struct l_settings *conf;
	char *path;

	path = l_strdup_printf("%s/%s%s", storage_path, network,
							STORAGEFILE_SUFFIX);

	l_debug("Loading %s", path);

	conf = l_settings_new();
	if (!l_settings_load_from_file(conf, path)) {
		l_settings_free(conf);
		conf = NULL;
	}

	l_free(path);

	return conf;
}

static void network_storage_watch_cb(const char *filename,
					enum l_dir_watch_event event,
					void *user_data)
{
	char *name;

	name = network_name_from_filename(filename);
	if (!name)
		return;

	switch (event) {
	case L_DIR_WATCH_EVENT_CREATED:
		network_create(name);
		break;
	case L_DIR_WATCH_EVENT_REMOVED:
		network_remove(name);
		break;
	case L_DIR_WATCH_EVENT_MODIFIED:
		network_reload(name);
		break;
	case L_DIR_WATCH_EVENT_ACCESSED:
	case L_DIR_WATCH_EVENT_ATTRIB:
		break;
	}

	l_free(name);
}

static void network_storage_watch_destroy(void *user_data)
{
	storage_watch = NULL;
}

static int network_init(void)
{
	DIR *dir;
	struct dirent *dirent;
	const char *state_dir;
	char **state_dirs;

	state_dir = getenv("STATE_DIRECTORY");
	if (!state_dir)
		state_dir = WIRED_STORAGEDIR;

	l_debug("Using state directory %s", state_dir);

	state_dirs = l_strsplit(state_dir, ':');
	if (!state_dirs[0]) {
		l_strv_free(state_dirs);
		return -EINVAL;
	}

	storage_path = l_strdup(state_dirs[0]);
	l_strv_free(state_dirs);

	dir = opendir(storage_path);
	if (!dir) {
		l_info("Unable to open %s: %s", storage_path, strerror(errno));
		return -EINVAL;
	}

	network_list = l_queue_new();

	while ((dirent = readdir(dir))) {
		struct network *net;
		char *name;

		if (dirent->d_type != DT_REG && dirent->d_type != DT_LNK)
			continue;

		name = network_name_from_filename(dirent->d_name);
		if (!name)
			continue;

		net = network_new(name);
		l_queue_push_tail(network_list, net);

		l_free(name);
	}

	closedir(dir);

	storage_watch = l_dir_watch_new(storage_path,
					network_storage_watch_cb, NULL,
					network_storage_watch_destroy);

	return 0;
}

static void network_exit(void)
{
	l_dir_watch_destroy(storage_watch);

	l_queue_destroy(network_list, network_free);
	network_list = NULL;

	l_free(storage_path);
}

IWD_MODULE(network, network_init, network_exit);
IWD_MODULE_DEPENDS(network, eap);
