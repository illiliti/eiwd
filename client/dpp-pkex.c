/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2023  Locus Robotics. All rights reserved.
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
#include <linux/limits.h>

#include <ell/ell.h>

#include "client/command.h"
#include "client/dbus-proxy.h"
#include "client/device.h"
#include "client/display.h"
#include "src/util.h"

struct pkex {
	bool started;
	char *role;
};

static void *pkex_create(void)
{
	return l_new(struct pkex, 1);
}

static void pkex_destroy(void *data)
{
	struct pkex *pkex = data;

	l_free(pkex->role);
	l_free(pkex);
}

static void display_pkex_inline(const char *margin, const void *data)
{
	const struct proxy_interface *pkex_i = data;
	struct proxy_interface *device_i =
		proxy_interface_find(IWD_DEVICE_INTERFACE,
					proxy_interface_get_path(pkex_i));
	const char *identity;

	if (!device_i)
		return;

	identity = proxy_interface_get_identity_str(device_i);
	if (!identity)
		return;

	display("%s%-*s\n", margin, 20, identity);
}

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static enum cmd_status cmd_list(const char *device_name, char **argv, int argc)
{
	const struct l_queue_entry *entry;
	struct l_queue *match =
		proxy_interface_find_all(IWD_DPP_PKEX_INTERFACE, NULL, NULL);

	display_table_header("DPP-PKEX-capable Devices",
				MARGIN "%-*s", 20, "Name");

	if (!match) {
		display("No DPP-PKEX-capable devices available\n");
		display_table_footer();

		return CMD_STATUS_DONE;
	}

	for (entry = l_queue_get_entries(match); entry; entry = entry->next) {
		const struct proxy_interface *pkex = entry->data;
		display_pkex_inline(MARGIN, pkex);
	}

	display_table_footer();

	l_queue_destroy(match, NULL);

	return CMD_STATUS_DONE;
}

static enum cmd_status cmd_enroll_or_configure(const char *device_name,
						char **argv, int argc,
						const char *method)
{
	const struct proxy_interface *pkex;
	const char *code;
	const char *id = NULL;

	pkex = device_proxy_find(device_name, IWD_DPP_PKEX_INTERFACE);
	if (!pkex) {
		display("No pkex pkex on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	if (argc < 1)
		return CMD_STATUS_INVALID_ARGS;

	code = argv[0];

	if (argc > 1)
		id = argv[1];

	if (id)
		proxy_interface_method_call(pkex, method, "a{sv}",
					check_errors_method_callback, 2,
					"Code", "s", code,
					"Identifier", "s", id);
	else
		proxy_interface_method_call(pkex, method, "a{sv}",
					check_errors_method_callback, 1,
					"Code", "s", code);

	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_enroll(const char *device_name,
					char **argv, int argc)
{
	return cmd_enroll_or_configure(device_name, argv, argc,
					"StartEnrollee");
}

static enum cmd_status cmd_configure(const char *device_name,
					char **argv, int argc)
{
	return cmd_enroll_or_configure(device_name, argv, argc,
					"ConfigureEnrollee");
}

static enum cmd_status cmd_stop(const char *device_name, char **argv, int argc)
{
	const struct proxy_interface *pkex_i =
		device_proxy_find(device_name, IWD_DPP_PKEX_INTERFACE);

	if (!pkex_i) {
		display("No pkex on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(pkex_i, "Stop", "",
						check_errors_method_callback);

	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_show(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *proxy =
			device_proxy_find(device_name, IWD_DPP_PKEX_INTERFACE);
	char *caption = l_strdup_printf("%s: %s", "DPP-PKEX", device_name);

	if (!proxy) {
		display("No DPP-PKEX interface on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_properties_display(proxy, caption, MARGIN, 20, 47);
	l_free(caption);

	display_table_footer();

	return CMD_STATUS_DONE;
}

static const struct command pkex_commands[] = {
	{ NULL, "list", NULL, cmd_list,
				"List shared code capable devices", true },
	{ "<wlan>", "stop", NULL, cmd_stop, "Aborts shared code operations" },
	{ "<wlan>", "show", NULL, cmd_show,
				"Shows the shared code state", true },
	{ "<wlan>", "enroll", "key [identifier]",
				cmd_enroll, "Start a shared code enrollee"},
	{ "<wlan>", "configure", "key [identifier]",
				cmd_configure,
				"Start a shared code configurator"},
	{ }
};

static char *family_arg_completion(const char *text, int state)
{
	return device_arg_completion(text, state, pkex_commands,
						IWD_DPP_PKEX_INTERFACE);
}

static char *entity_arg_completion(const char *text, int state)
{
	return command_entity_arg_completion(text, state, pkex_commands);
}

static void update_started(void *data, struct l_dbus_message_iter *variant)
{
	struct pkex *pkex = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		pkex->started = false;
		return;
	}

	pkex->started = value;
}

static const char *started_tostr(const void *data)
{
	const struct pkex *pkex = data;

	return pkex->started ? "yes" : "no";
}

static void update_role(void *data, struct l_dbus_message_iter *variant)
{
	struct pkex *pkex = data;
	const char *value;

	if (pkex->role)
		l_free(pkex->role);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		pkex->role = NULL;
		return;
	}

	pkex->role = l_strdup(value);
}

static const char *role_tostr(const void *data)
{
	const struct pkex *pkex = data;

	return pkex->role;
}

static const struct proxy_interface_property pkex_properties[] = {
	{ "Started",	"b", update_started,	started_tostr },
	{ "Role",	"s", update_role, 	role_tostr },
	{ }
};

static const struct proxy_interface_type_ops pkex_ops = {
	.create = pkex_create,
	.destroy = pkex_destroy,
};

static struct proxy_interface_type pkex_interface_type = {
	.interface = IWD_DPP_PKEX_INTERFACE,
	.properties = pkex_properties,
	.ops = &pkex_ops,
};


static struct command_family pkex_command_family = {
	.caption = "Shared Code Device Provisioning (PKEX)",
	.name = "pkex",
	.command_list = pkex_commands,
	.family_arg_completion = family_arg_completion,
	.entity_arg_completion = entity_arg_completion,
};

static int pkex_command_family_init(void)
{
	command_family_register(&pkex_command_family);

	return 0;
}

static void pkex_command_family_exit(void)
{
	command_family_unregister(&pkex_command_family);
}

COMMAND_FAMILY(pkex_command_family, pkex_command_family_init,
						pkex_command_family_exit)

static int pkex_interface_init(void)
{
	proxy_interface_type_register(&pkex_interface_type);

	return 0;
}

static void pkex_interface_exit(void)
{
	proxy_interface_type_unregister(&pkex_interface_type);
}

INTERFACE_TYPE(pkex_interface_type, pkex_interface_init, pkex_interface_exit)
