/*
 *
 *  Wireless daemon for Linux
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

#include <ell/ell.h>

#include "client/dbus-proxy.h"
#include "client/display.h"
#include "client/network.h"

struct network {
	bool connected;
	char *identity;
	char *name;
	char *type;
	struct l_queue *bss_list;
	const struct proxy_interface *device;
};

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

const struct proxy_interface *network_get_proxy(const char *path)
{
	return proxy_interface_find(IWD_NETWORK_INTERFACE, path);
}

bool network_is_connected(const struct proxy_interface *network_proxy)
{
	const struct network *network = proxy_interface_get_data(network_proxy);

	return network->connected;
}

const char *network_get_type(const struct proxy_interface *network_proxy)
{
	const struct network *network = proxy_interface_get_data(network_proxy);

	return network->type;
}

const char *network_get_name(const struct proxy_interface *network_proxy)
{
	const struct network *network = proxy_interface_get_data(network_proxy);

	return network->name;
}

void network_connect(const struct proxy_interface *proxy)
{
	if (!proxy)
		return;

	proxy_interface_method_call(proxy, "Connect", "",
						check_errors_method_callback);
}

static const char *get_name(const void *data)
{
	const struct network *network = data;

	return network->name;
}

static void update_name(void *data, struct l_dbus_message_iter *variant)
{
	struct network *network = data;
	const char *value;

	l_free(network->name);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		network->name = NULL;

		return;
	}

	network->name = l_strdup(value);
}

static void update_connected(void *data, struct l_dbus_message_iter *variant)
{
	struct network *network = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		network->connected = false;

		return;
	}

	network->connected = value;
}

static void update_device(void *data, struct l_dbus_message_iter *variant)
{
	struct network *network = data;
	const char *path;

	if (!l_dbus_message_iter_get_variant(variant, "o", &path)) {
		network->device = NULL;

		return;
	}

	network->device = proxy_interface_find(IWD_DEVICE_INTERFACE, path);
}

static void update_type(void *data, struct l_dbus_message_iter *variant)
{
	struct network *network = data;
	const char *value;

	l_free(network->type);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		network->type = NULL;

		return;
	}

	network->type = l_strdup(value);
}

static bool match_path(const void *a, const void *user_data)
{
	const char *path1 = a;
	const char *path2 = user_data;

	return !strcmp(path1, path2);
}

static void update_ess(void *data, struct l_dbus_message_iter *variant)
{
	struct network *network = data;
	struct l_dbus_message_iter array;
	const char *path;

	if (!network->bss_list)
		network->bss_list = l_queue_new();

	if (!l_dbus_message_iter_get_variant(variant, "ao", &array))
		return;

	while (l_dbus_message_iter_next_entry(&array, &path)) {
		l_free(l_queue_remove_if(network->bss_list, match_path, path));
		l_queue_push_head(network->bss_list, l_strdup(path));
	}
}

static const char *get_ess(const void *data)
{
	const struct network *network = data;
	static char count[10];

	snprintf(count, 10, "Count %u", l_queue_length(network->bss_list));

	return count;
}

struct l_queue *network_get_bss_list(
				const struct proxy_interface *network_proxy)
{
	const struct network *network = proxy_interface_get_data(network_proxy);
	if (!network)
		return NULL;

	return network->bss_list;
}

static const struct proxy_interface_property network_properties[] = {
	{ "Name",       "s", update_name, get_name },
	{ "Connected",  "b", update_connected},
	{ "Device",     "o", update_device},
	{ "Type",       "s", update_type},
	{ "ExtendedServiceSet",  "ao", update_ess, get_ess },
	{ }
};

static const char *network_identity(void *data)
{
	struct network *network = data;

	if (!network->identity)
		network->identity =
			l_strdup_printf("%s %s", network->name, network->type);

	return network->identity;
}

static void network_display_inline(const char *margin, const void *data)
{
	const struct network *network = data;

	display("%s%s %s %s\n", margin, network->name ? network->name : "",
			network->type ? network->type : "",
			network->connected ? "connected" : "diconnected");
}

static void *network_create(void)
{
	return l_new(struct network, 1);
}

static void network_destroy(void *data)
{
	struct network *network = data;

	l_free(network->name);
	l_free(network->type);
	l_free(network->identity);
	l_queue_destroy(network->bss_list, l_free);

	network->device = NULL;

	l_free(network);
}

static const struct proxy_interface_type_ops ops = {
	.create = network_create,
	.destroy = network_destroy,
	.display = network_display_inline,
	.identity = network_identity,
};

static struct proxy_interface_type network_interface_type = {
	.interface = IWD_NETWORK_INTERFACE,
	.properties = network_properties,
	.ops = &ops,
};

struct completion_search_parameters {
	const char *text;
	const struct proxy_interface *device;
};

static bool match_by_partial_name(const void *a, const void *b)
{
	const struct network *network = a;
	const struct completion_search_parameters *params = b;
	const char *name;
	const char *text;

	if (!proxy_interface_is_same(network->device, params->device))
		return false;

	for (text = params->text, name = network->name; *text && *name;
							name++, text++) {
		if (*name == *text)
			continue;

		return false;
	}

	if (*text)
		return false;

	return true;
}

char *network_name_completion(const struct proxy_interface *device,
						const char *text, int state)
{
	const struct completion_search_parameters params = {
		.text = text, .device = device,
	};

	return proxy_property_str_completion(&network_interface_type,
						match_by_partial_name, "Name",
						&params, state, NULL);
}

struct network_search_parameters {
	const struct network_args *args;
	const struct proxy_interface *device;
};

static bool match_by_device_and_args(const void *a, const void *b)
{
	const struct network *network = a;
	const struct network_search_parameters *params = b;

	if (!proxy_interface_is_same(network->device, params->device))
		return false;

	if (strcmp(network->name, params->args->name))
		return false;

	if (params->args->type && strcmp(network->type, params->args->type))
		return false;

	return true;
}

struct l_queue *network_match_by_device_and_args(
					const struct proxy_interface *device,
					const struct network_args *args)
{
	struct network_search_parameters params = {
		.args = args, .device = device
	};

	return proxy_interface_find_all(network_interface_type.interface,
					match_by_device_and_args, &params);
}

static int network_interface_init(void)
{
	proxy_interface_type_register(&network_interface_type);

	return 0;
}

static void network_interface_exit(void)
{
	proxy_interface_type_unregister(&network_interface_type);
}

INTERFACE_TYPE(network_interface_type, network_interface_init,
						network_interface_exit)
