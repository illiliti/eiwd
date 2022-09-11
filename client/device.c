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

#include "client/command.h"
#include "client/dbus-proxy.h"
#include "client/device.h"
#include "client/display.h"
#include "client/network.h"
#include "client/properties.h"

struct device {
	bool powered;
	bool wds;
	char *address;
	char *name;
	char *mode;
	const struct proxy_interface *adapter;
};

static void display_device(const struct proxy_interface *proxy)
{
	const struct device *device = proxy_interface_get_data(proxy);
	char *caption = l_strdup_printf("%s: %s", "Device", device->name);

	proxy_properties_display(proxy, caption, MARGIN, 20, 47);

	l_free(caption);

	if (device->adapter) {
		display_table_row(MARGIN, 3, 8, "", 20, "Adapter", 47,
				proxy_interface_get_identity_str(
						device->adapter) ? : "");

	}

	display_table_footer();
}

static const char *get_name(const void *data)
{
	const struct device *device = data;

	return device->name;
}

static void update_name(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	const char *value;

	l_free(device->name);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		device->name = NULL;

		return;
	}

	device->name = l_strdup(value);
}

static const char *device_mode_opts[] = { "ad-hoc", "ap", "station", NULL };

static const char *get_mode(const void *data)
{
	const struct device *device = data;

	return device->mode;
}

static void update_mode(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	const char *value;

	l_free(device->mode);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		device->mode = NULL;

		return;
	}

	device->mode = l_strdup(value);
}

static bool builder_append_string_variant(
					struct l_dbus_message_builder *builder,
					const char *value_str)
{
	return l_dbus_message_builder_append_basic(builder, 's', value_str);
}

static const char *get_address(const void *data)
{
	const struct device *device = data;

	return device->address;
}

static void update_address(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	const char *value;

	l_free(device->address);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		device->address = NULL;

		return;
	}

	device->address = l_strdup(value);
}

static const char *get_powered_tostr(const void *data)
{
	const struct device *device = data;

	return device->powered ? "on" : "off";
}

static void update_powered(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		device->powered = false;

		return;
	}

	device->powered = value;
}

static void update_adapter(void *data, struct l_dbus_message_iter *variant)
{
	struct device *device = data;
	const char *path;

	if (!l_dbus_message_iter_get_variant(variant, "o", &path)) {
		device->adapter = NULL;

		return;
	}

	device->adapter = proxy_interface_find(IWD_ADAPTER_INTERFACE, path);
}

static const struct proxy_interface_property device_properties[] = {
	{ "Name",     "s", update_name,     get_name },
	{ "Mode",     "s", update_mode,     get_mode,          true,
		builder_append_string_variant, device_mode_opts },
	{ "Powered",  "b", update_powered,  get_powered_tostr, true,
		properties_builder_append_on_off_variant,
		properties_on_off_opts },
	{ "Adapter",  "o", update_adapter },
	{ "Address",  "s", update_address,  get_address },
	{ }
};

static void *device_create(void)
{
	return l_new(struct device, 1);
}

static void device_destroy(void *data)
{
	struct device *device = data;

	l_free(device->address);
	l_free(device->name);
	l_free(device->mode);

	device->adapter = NULL;

	l_free(device);
}

static void display_device_inline(const char *margin, const void *data)
{
	const struct device *device = data;
	const char *adapter_str;

	if (device->adapter &&
			proxy_interface_get_identity_str(device->adapter))
		adapter_str = proxy_interface_get_identity_str(device->adapter);
	else
		adapter_str = "-";

	display_table_row(margin, 5, 20, device->name ? : "",
				20, device->address ? : "",
				10, get_powered_tostr(device),
				10, adapter_str,
				10, device->mode);
}

static const char *device_identity(void *data)
{
	const struct device *device = data;

	return device->name;
}

static const struct proxy_interface_type_ops device_ops = {
	.create = device_create,
	.destroy = device_destroy,
	.identity = device_identity,
	.display = display_device_inline,
};

static struct proxy_interface_type device_interface_type = {
	.interface = IWD_DEVICE_INTERFACE,
	.properties = device_properties,
	.ops = &device_ops,
};

static bool match_by_name(const void *a, const void *b)
{
	const struct device *device = a;
	const char *name = b;

	return !strcmp(device->name, name);
}

static bool match_by_partial_name(const void *a, const void *b)
{
	const struct device *device = a;
	const char *text = b;

	return !strncmp(device->name, text, strlen(text));
}

const struct proxy_interface *device_proxy_find_by_name(const char *name)
{
	struct l_queue *match;
	struct proxy_interface *proxy = NULL;

	if (!name)
		return NULL;

	match = proxy_interface_find_all(device_interface_type.interface,
						match_by_name, name);

	if (l_queue_length(match))
		proxy = l_queue_pop_head(match);
	else
		display("Device %s not found.\n", name);

	l_queue_destroy(match, NULL);

	return proxy;
}

const struct proxy_interface *device_proxy_find(const char *device_name,
							const char *interface)
{
	const struct proxy_interface *device_i =
					device_proxy_find_by_name(device_name);
	const struct proxy_interface *proxy;

	if (!device_i)
		return NULL;

	proxy = proxy_interface_find(interface,
					proxy_interface_get_path(device_i));
	if (!proxy)
		return NULL;

	return proxy;
}

static enum cmd_status cmd_show(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *proxy =
					device_proxy_find_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_ARGS;

	display_device(proxy);

	return CMD_STATUS_DONE;
}

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static enum cmd_status cmd_list(const char *device_name,
						char **argv, int argc)
{
	display_table_header("Devices", MARGIN "%-*s  %-*s  %-*s  %-*s  %-*s",
				20, "Name", 20, "Address", 10, "Powered",
				10, "Adapter", 10, "Mode");

	proxy_interface_display_list(device_interface_type.interface);

	display_table_footer();

	return CMD_STATUS_DONE;
}

static enum cmd_status cmd_set_property(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *proxy =
					device_proxy_find_by_name(device_name);

	if (!proxy)
		return CMD_STATUS_INVALID_VALUE;

	if (argc != 2)
		return CMD_STATUS_INVALID_ARGS;

	if (!proxy_property_set(proxy, argv[0], argv[1],
						check_errors_method_callback))
		return CMD_STATUS_INVALID_VALUE;

	return CMD_STATUS_TRIGGERED;
}

static char *set_property_cmd_arg_completion(const char *text, int state,
						const char *device_name)
{
	return proxy_property_completion(device_properties, text, state);
}

static const struct command device_commands[] = {
	{ NULL,     "list",     NULL,   cmd_list, "List devices",     true },
	{ "<wlan>", "show",     NULL,   cmd_show, "Show device info", true },
	{ "<wlan>", "set-property",
				"<name> <value>",
					cmd_set_property,
						"Set property",       false,
		set_property_cmd_arg_completion },
	{ }
};

char *device_arg_completion(const char *text, int state,
				const struct command *commands,
				const char *extra_interface)
{
	static bool first_pass;
	static size_t index;
	static size_t len;
	const char *cmd;

	if (!state) {
		index = 0;
		len = strlen(text);
		first_pass = true;
	}

	while ((cmd = commands[index].cmd)) {
		if (commands[index++].entity)
			continue;

		if (!strncmp(cmd, text, len))
			return l_strdup(cmd);
	}

	if (first_pass) {
		state = 0;
		first_pass = false;
	}

	return proxy_property_str_completion(&device_interface_type,
						match_by_partial_name, "Name",
						text, state, extra_interface);
}

static char *family_arg_completion(const char *text, int state)
{
	return device_arg_completion(text, state, device_commands, NULL);
}

static char *entity_arg_completion(const char *text, int state)
{
	return command_entity_arg_completion(text, state, device_commands);
}

static struct command_family device_command_family = {
	.caption = "Devices",
	.name = "device",
	.command_list = device_commands,
	.family_arg_completion = family_arg_completion,
	.entity_arg_completion = entity_arg_completion,
};

static int device_command_family_init(void)
{
	command_family_register(&device_command_family);

	return 0;
}

static void device_command_family_exit(void)
{
	command_family_unregister(&device_command_family);
}

COMMAND_FAMILY(device_command_family, device_command_family_init,
						device_command_family_exit)

static int device_interface_init(void)
{
	proxy_interface_type_register(&device_interface_type);

	return 0;
}

static void device_interface_exit(void)
{
	proxy_interface_type_unregister(&device_interface_type);
}

INTERFACE_TYPE(device_interface_type, device_interface_init,
						device_interface_exit)
