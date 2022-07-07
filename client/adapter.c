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
#include "client/display.h"
#include "client/properties.h"

struct adapter {
	bool powered;
	char *model;
	char *name;
	char *vendor;
	char *supported_modes_str;
};

static const char *get_name(const void *data)
{
	const struct adapter *adapter = data;

	return adapter->name;
}

static void update_name(void *data, struct l_dbus_message_iter *variant)
{
	struct adapter *adapter = data;
	const char *value;

	l_free(adapter->name);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		adapter->name = NULL;

		return;
	}

	adapter->name = l_strdup(value);
}

static void update_vendor(void *data, struct l_dbus_message_iter *variant)
{
	struct adapter *adapter = data;
	const char *value;

	l_free(adapter->vendor);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		adapter->vendor = NULL;

		return;
	}

	adapter->vendor = l_strdup(value);
}

static const char *get_vendor(const void *data)
{
	const struct adapter *adapter = data;

	return adapter->vendor;
}

static void update_model(void *data, struct l_dbus_message_iter *variant)
{
	struct adapter *adapter = data;
	const char *value;

	l_free(adapter->model);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		adapter->model = NULL;

		return;
	}

	adapter->model = l_strdup(value);
}

static const char *get_model(const void *data)
{
	const struct adapter *adapter = data;

	return adapter->model;
}

static const char *get_powered_tostr(const void *data)
{
	const struct adapter *adapter = data;

	return adapter->powered ? "on" : "off";
}

static void update_powered(void *data, struct l_dbus_message_iter *variant)
{
	struct adapter *adapter = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		adapter->powered = false;

		return;
	}

	adapter->powered = value;
}

static void update_supported_modes(void *data,
					struct l_dbus_message_iter *variant)
{
	struct adapter *adapter = data;
	struct l_string *buf;
	struct l_dbus_message_iter iter;
	const char *mode;

	if (!l_dbus_message_iter_get_variant(variant, "as", &iter))
		return;

	l_free(adapter->supported_modes_str);

	buf = l_string_new(128);

	while (l_dbus_message_iter_next_entry(&iter, &mode))
		l_string_append_printf(buf, "%s ", mode);

	adapter->supported_modes_str = l_string_unwrap(buf);
}

static const char *get_supported_modes_tostr(const void *data)
{
	const struct adapter *adapter = data;

	return adapter->supported_modes_str;
}

static const struct proxy_interface_property adapter_properties[] = {
	{ "Name",     "s", update_name,     get_name },
	{ "Powered",  "b", update_powered,  get_powered_tostr, true,
		properties_builder_append_on_off_variant,
		properties_on_off_opts },
	{ "Vendor",   "s", update_vendor,   get_vendor },
	{ "Model",    "s", update_model,    get_model },
	{ "SupportedModes", "as", update_supported_modes,
		get_supported_modes_tostr },
	{ }
};

static void display_adapter(const struct proxy_interface *proxy)
{
	const struct adapter *adapter = proxy_interface_get_data(proxy);
	char *caption = l_strdup_printf("%s: %s", "Adapter", adapter->name);

	proxy_properties_display(proxy, caption, MARGIN, 17, 50);

	l_free(caption);

	display_table_footer();
}

static void display_adapter_inline(const char *margin, const void *data)
{
	const struct adapter *adapter = data;

	display_table_row(margin, 4, 8, adapter->name ? : "-",
				8, get_powered_tostr(adapter),
				20, adapter->vendor ? : "-",
				20, adapter->model ? : "-");
}

static void *adapter_create(void)
{
	return l_new(struct adapter, 1);
}

static void adapter_destroy(void *data)
{
	struct adapter *adapter = data;

	l_free(adapter->model);
	l_free(adapter->vendor);
	l_free(adapter->name);
	l_free(adapter->supported_modes_str);

	l_free(adapter);
}

static const char *adapter_identity(void *data)
{
	const struct adapter *adapter = data;

	return adapter->name;
}

static const struct proxy_interface_type_ops adapter_ops = {
	.create = adapter_create,
	.destroy = adapter_destroy,
	.display = display_adapter_inline,
	.identity = adapter_identity,
};

static struct proxy_interface_type adapter_interface_type = {
	.interface = IWD_ADAPTER_INTERFACE,
	.properties = adapter_properties,
	.ops = &adapter_ops,
};

static bool match_by_name(const void *a, const void *b)
{
	const struct adapter *adapter = a;
	const char *name = b;

	return !strcmp(adapter->name, name);
}

static bool match_by_partial_name(const void *a, const void *b)
{
	const struct adapter *adapter = a;
	const char *text = b;

	return !strncmp(adapter->name, text, strlen(text));
}

static const struct proxy_interface *get_adapter_proxy_by_name(
						const char *adapter_name)
{
	struct l_queue *match;
	struct proxy_interface *proxy = NULL;

	if (!adapter_name)
		return NULL;

	match = proxy_interface_find_all(adapter_interface_type.interface,
						match_by_name, adapter_name);

	if (l_queue_length(match))
		proxy = l_queue_pop_head(match);
	else
		display("Adapter '%s' not found\n", adapter_name);

	l_queue_destroy(match, NULL);

	return proxy;
}

static enum cmd_status cmd_list(const char *adapter_name,
						char **argv, int argc)
{
	display_table_header("Adapters", MARGIN "%-*s  %-*s  %-*s  %-*s",
				8, "Name", 8, "Powered",
				20, "Vendor", 20, "Model");

	proxy_interface_display_list(adapter_interface_type.interface);

	display_table_footer();

	return CMD_STATUS_DONE;
}

static enum cmd_status cmd_show(const char *adapter_name,
						char **argv, int argc)
{
	const struct proxy_interface *proxy =
					get_adapter_proxy_by_name(adapter_name);

	if (!proxy)
		return CMD_STATUS_INVALID_ARGS;

	display_adapter(proxy);

	return CMD_STATUS_DONE;
}

static void property_set_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static enum cmd_status cmd_set_property(const char *adapter_name,
						char **argv, int argc)
{
	const struct proxy_interface *proxy =
					get_adapter_proxy_by_name(adapter_name);

	if (!proxy)
		return CMD_STATUS_INVALID_VALUE;

	if (argc != 2)
		return CMD_STATUS_INVALID_ARGS;

	if (!proxy_property_set(proxy, argv[0], argv[1],
						property_set_callback))
		return CMD_STATUS_INVALID_VALUE;

	return CMD_STATUS_TRIGGERED;
}

static char *set_property_cmd_arg_completion(const char *text, int state)
{
	return proxy_property_completion(adapter_properties, text, state);
}

static const struct command adapter_commands[] = {
	{ NULL,    "list",         NULL, cmd_list,       "List adapters",
									true },
	{ "<phy>", "show",         NULL, cmd_show,       "Show adapter info",
									true },
	{ "<phy>", "set-property", "<name> <value>",
					cmd_set_property, "Set property",
									false,
		set_property_cmd_arg_completion },
	{ }
};

static char *family_arg_completion(const char *text, int state)
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

	while ((cmd = adapter_commands[index].cmd)) {
		if (adapter_commands[index++].entity)
			continue;

		if (strncmp(cmd, text, len))
			continue;

		return l_strdup(cmd);
	}

	if (first_pass) {
		state = 0;
		first_pass = false;
	}

	return proxy_property_str_completion(&adapter_interface_type,
						match_by_partial_name, "Name",
						text, state, NULL);
}

static char *entity_arg_completion(const char *text, int state)
{
	return command_entity_arg_completion(text, state, adapter_commands);
}

static struct command_family adapter_command_family = {
	.caption = "Adapters",
	.name = "adapter",
	.family_arg_completion = family_arg_completion,
	.entity_arg_completion = entity_arg_completion,
	.command_list = adapter_commands,
};

static int adapter_command_family_init(void)
{
	command_family_register(&adapter_command_family);

	return 0;
}

static void adapter_command_family_exit(void)
{
	command_family_unregister(&adapter_command_family);
}

COMMAND_FAMILY(adapter_command_family, adapter_command_family_init,
						adapter_command_family_exit)

static int adapter_interface_init(void)
{
	proxy_interface_type_register(&adapter_interface_type);

	return 0;
}

static void adapter_interface_exit(void)
{
	proxy_interface_type_unregister(&adapter_interface_type);
}

INTERFACE_TYPE(adapter_interface_type, adapter_interface_init,
						adapter_interface_exit)
