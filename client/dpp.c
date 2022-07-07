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

struct dpp {
	bool started;
	char *role;
	char *uri;
};

static void *dpp_create(void)
{
	return l_new(struct dpp, 1);
}

static void dpp_destroy(void *data)
{
	struct dpp *dpp = data;

	if (dpp->role)
		l_free(dpp->role);
	if (dpp->uri)
		l_free(dpp->uri);

	l_free(dpp);
}

static void update_started(void *data, struct l_dbus_message_iter *variant)
{
	struct dpp *dpp = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		dpp->started = false;
		return;
	}

	dpp->started = value;
}

static const char *started_tostr(const void *data)
{
	const struct dpp *dpp = data;

	return dpp->started ? "yes" : "no";
}

static void update_role(void *data, struct l_dbus_message_iter *variant)
{
	struct dpp *dpp = data;
	const char *value;

	if (dpp->role)
		l_free(dpp->role);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		dpp->role = NULL;
		return;
	}

	dpp->role = l_strdup(value);
}

static const char *role_tostr(const void *data)
{
	const struct dpp *dpp = data;

	return dpp->role;
}

static void update_uri(void *data, struct l_dbus_message_iter *variant)
{
	struct dpp *dpp = data;
	const char *value;

	if (dpp->uri)
		l_free(dpp->uri);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		dpp->uri = NULL;
		return;
	}

	dpp->uri = l_strdup(value);
}

static const char *uri_tostr(const void *data)
{
	const struct dpp *dpp = data;

	return dpp->uri;
}

static const struct proxy_interface_property dpp_properties[] = {
	{ "Started",	"b", update_started,	started_tostr },
	{ "Role",	"s", update_role, 	role_tostr },
	{ "URI",	"s", update_uri,	uri_tostr },
	{ }
};

static const struct proxy_interface_type_ops dpp_ops = {
	.create = dpp_create,
	.destroy = dpp_destroy,
};

static struct proxy_interface_type dpp_interface_type = {
	.interface = IWD_DPP_INTERFACE,
	.properties = dpp_properties,
	.ops = &dpp_ops,
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

static enum cmd_status cmd_show(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *proxy =
			device_proxy_find(device_name, IWD_DPP_INTERFACE);
	char *caption = l_strdup_printf("%s: %s", "DPP", device_name);

	proxy_properties_display(proxy, caption, MARGIN, 20, 47);
	l_free(caption);

	display_table_footer();

	return CMD_STATUS_DONE;
}

static const struct command dpp_commands[] = {
	{ NULL, "list", NULL, cmd_list, "List DPP-capable devices", true },
	{ "<wlan>", "start-enrollee", NULL, cmd_start_enrollee,
							"Starts a DPP Enrollee" },
	{ "<wlan>", "start-configurator", NULL, cmd_start_configurator,
							"Starts a DPP Configurator" },
	{ "<wlan>", "stop", NULL, cmd_stop, "Aborts DPP operations" },
	{ "<wlan>", "show", NULL, cmd_show, "Shows the DPP state", true },
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
