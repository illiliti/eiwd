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

static struct proxy_interface_type wsc_interface_type = {
	.interface = IWD_WSC_INTERFACE,
};

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static void generate_pin_callback(struct l_dbus_message *message,
								void *user_data)
{
	const struct proxy_interface *proxy = user_data;
	const char *pin;

	if (dbus_message_has_error(message))
		return;

	if (!l_dbus_message_get_arguments(message, "s", &pin)) {
		l_error("Failed to parse 'generate pin' callback message");

		return;
	}

	if (!pin)
		return;

	proxy_interface_method_call(proxy, "StartPin", "s",
					check_errors_method_callback, pin);
}

static void display_wsc_inline(const char *margin, const void *data)
{
	const struct proxy_interface *wsc_i = data;
	struct proxy_interface *device_i =
		proxy_interface_find(IWD_DEVICE_INTERFACE,
					proxy_interface_get_path(wsc_i));
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
		proxy_interface_find_all(IWD_WSC_INTERFACE, NULL, NULL);

	display_table_header("WSC-capable Devices", MARGIN "%-*s", 20, "Name");

	if (!match) {
		display("No WSC-capable devices available\n");
		display_table_footer();

		return CMD_STATUS_DONE;
	}

	for (entry = l_queue_get_entries(match); entry; entry = entry->next) {
		const struct proxy_interface *wsc = entry->data;
		display_wsc_inline(MARGIN, wsc);
	}

	display_table_footer();

	l_queue_destroy(match, NULL);

	return CMD_STATUS_DONE;
}

static enum cmd_status cmd_push_button(const char *device_name,
							char **argv, int argc)
{
	const struct proxy_interface *wsc_i =
		device_proxy_find(device_name, IWD_WSC_INTERFACE);

	if (!wsc_i) {
		display("No wsc on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(wsc_i, "PushButton", "",
						check_errors_method_callback);

	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_start_user_pin(const char *device_name,
							char **argv, int argc)
{
	const struct proxy_interface *wsc_i;

	if (argc != 1)
		return CMD_STATUS_INVALID_ARGS;

	wsc_i = device_proxy_find(device_name, IWD_WSC_INTERFACE);
	if (!wsc_i) {
		display("No wsc on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(wsc_i, "StartPin", "s",
					check_errors_method_callback, argv[0]);

	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_start_pin(const char *device_name,
							char **argv, int argc)
{
	const struct proxy_interface *wsc_i =
		device_proxy_find(device_name, IWD_WSC_INTERFACE);

	if (!wsc_i) {
		display("No wsc on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(wsc_i, "GeneratePin", "",
							generate_pin_callback);

	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_cancel(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *wsc_i =
		device_proxy_find(device_name, IWD_WSC_INTERFACE);

	if (!wsc_i) {
		display("No wsc on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(wsc_i, "Cancel", "",
						check_errors_method_callback);

	return CMD_STATUS_TRIGGERED;
}

static const struct command wsc_commands[] = {
	{ NULL, "list", NULL, cmd_list, "List WSC-capable devices", true },
	{ "<wlan>", "push-button", NULL, cmd_push_button, "PushButton mode" },
	{ "<wlan>", "start-user-pin", "<PIN>", cmd_start_user_pin,
							"PIN mode" },
	{ "<wlan>", "start-pin", NULL, cmd_start_pin,
		"PIN mode with generated 8 digit PIN" },
	{ "<wlan>", "cancel", NULL,   cmd_cancel, "Aborts WSC operations" },
	{ }
};

static char *family_arg_completion(const char *text, int state)
{
	return device_arg_completion(text, state, wsc_commands,
						IWD_WSC_INTERFACE);
}

static char *entity_arg_completion(const char *text, int state)
{
	return command_entity_arg_completion(text, state, wsc_commands);
}

static struct command_family wsc_command_family = {
	.caption = "WiFi Simple Configuration",
	.name = "wsc",
	.command_list = wsc_commands,
	.family_arg_completion = family_arg_completion,
	.entity_arg_completion = entity_arg_completion,
};

static int wsc_command_family_init(void)
{
	command_family_register(&wsc_command_family);

	return 0;
}

static void wsc_command_family_exit(void)
{
	command_family_unregister(&wsc_command_family);
}

COMMAND_FAMILY(wsc_command_family, wsc_command_family_init,
						wsc_command_family_exit)

static int wsc_interface_init(void)
{
	proxy_interface_type_register(&wsc_interface_type);

	return 0;
}

static void wsc_interface_exit(void)
{
	proxy_interface_type_unregister(&wsc_interface_type);
}

INTERFACE_TYPE(wsc_interface_type, wsc_interface_init, wsc_interface_exit)
