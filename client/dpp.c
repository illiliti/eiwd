/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
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

static struct proxy_interface_type dpp_interface_type = {
	.interface = IWD_DPP_INTERFACE,
};

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static void get_uri_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	FILE *f;
	L_AUTO_FREE_VAR(char *, cmd) = NULL;
	char *uri;
	char readbuf[PATH_MAX];
	char *s = readbuf;

	if (dbus_message_has_error(message))
		return;

	if (!l_dbus_message_get_arguments(message, "s", &uri)) {
		display("Error getting URI");
		return;
	}

	display("%s\n\n", uri);

	if (system("which qrencode > /dev/null 2>&1"))
		return;

	cmd = l_strdup_printf("qrencode -t UTF8 -o - \"%s\"", uri);

	f = popen(cmd, "r");

	while ((s = fgets(s, PATH_MAX, f)))
		display("%s", s);

	display("\n");

	pclose(f);
}

static void display_dpp_inline(const char *margin, const void *data)
{
	const struct proxy_interface *dpp_i = data;
	struct proxy_interface *device_i =
		proxy_interface_find(IWD_DEVICE_INTERFACE,
					proxy_interface_get_path(dpp_i));
	const char *identity;

	if (!device_i)
		return;

	identity = proxy_interface_get_identity_str(device_i);
	if (!identity)
		return;

	display("%s%-*s\n", margin, 20, identity);
}

static enum cmd_status cmd_list(const char *device_name, char **argv, int argc)
{
	const struct l_queue_entry *entry;
	struct l_queue *match =
		proxy_interface_find_all(IWD_DPP_INTERFACE, NULL, NULL);

	display_table_header("DPP-capable Devices", MARGIN "%-*s", 20, "Name");

	if (!match) {
		display("No DPP-capable devices available\n");
		display_table_footer();

		return CMD_STATUS_DONE;
	}

	for (entry = l_queue_get_entries(match); entry; entry = entry->next) {
		const struct proxy_interface *dpp = entry->data;
		display_dpp_inline(MARGIN, dpp);
	}

	display_table_footer();

	l_queue_destroy(match, NULL);

	return CMD_STATUS_DONE;
}

static enum cmd_status cmd_start_enrollee(const char *device_name,
							char **argv, int argc)
{
	const struct proxy_interface *dpp_i;

	dpp_i = device_proxy_find(device_name, IWD_DPP_INTERFACE);
	if (!dpp_i) {
		display("No dpp on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(dpp_i, "StartEnrollee", "",
					get_uri_method_callback);

	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_start_configurator(const char *device_name,
							char **argv, int argc)
{
	const struct proxy_interface *dpp_i;

	dpp_i = device_proxy_find(device_name, IWD_DPP_INTERFACE);
	if (!dpp_i) {
		display("No dpp on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(dpp_i, "StartConfigurator", "",
					get_uri_method_callback);

	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_stop(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *dpp_i =
		device_proxy_find(device_name, IWD_DPP_INTERFACE);

	if (!dpp_i) {
		display("No dpp on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(dpp_i, "Stop", "",
						check_errors_method_callback);

	return CMD_STATUS_TRIGGERED;
}

static const struct command dpp_commands[] = {
	{ NULL, "list", NULL, cmd_list, "List DPP-capable devices", true },
	{ "<wlan>", "start-enrollee", NULL, cmd_start_enrollee,
							"Starts a DPP Enrollee" },
	{ "<wlan>", "start-configurator", NULL, cmd_start_configurator,
							"Starts a DPP Configurator" },
	{ "<wlan>", "stop", NULL, cmd_stop, "Aborts DPP operations" },
	{ }
};

static char *family_arg_completion(const char *text, int state)
{
	return device_arg_completion(text, state, dpp_commands,
						IWD_DPP_INTERFACE);
}

static char *entity_arg_completion(const char *text, int state)
{
	return command_entity_arg_completion(text, state, dpp_commands);
}

static struct command_family dpp_command_family = {
	.caption = "Device Provisioning",
	.name = "dpp",
	.command_list = dpp_commands,
	.family_arg_completion = family_arg_completion,
	.entity_arg_completion = entity_arg_completion,
};

static int dpp_command_family_init(void)
{
	command_family_register(&dpp_command_family);

	return 0;
}

static void dpp_command_family_exit(void)
{
	command_family_unregister(&dpp_command_family);
}

COMMAND_FAMILY(dpp_command_family, dpp_command_family_init,
						dpp_command_family_exit)

static int dpp_interface_init(void)
{
	proxy_interface_type_register(&dpp_interface_type);

	return 0;
}

static void dpp_interface_exit(void)
{
	proxy_interface_type_unregister(&dpp_interface_type);
}

INTERFACE_TYPE(dpp_interface_type, dpp_interface_init, dpp_interface_exit)
