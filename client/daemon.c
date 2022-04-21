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

#include <errno.h>
#include <ell/ell.h>
#include <unistd.h>

#include "client/dbus-proxy.h"
#include "client/display.h"
#include "client/command.h"
#include "client/daemon.h"

static bool netconfig_enabled;

#define IWD_DAEMON_PATH "/net/connman/iwd"

int daemon_netconfig_enabled()
{
	const struct proxy_interface *proxy =
		proxy_interface_find(IWD_DAEMON_INTERFACE, IWD_DAEMON_PATH);

	if (!proxy)
		return -ENOENT;

	return netconfig_enabled;
}

static void get_info_callback(struct l_dbus_message *message, void *user_data)
{
	struct l_dbus_message_iter iter;
	struct l_dbus_message_iter variant;
	const char *key;

	if (dbus_message_has_error(message))
		return;

	if (!l_dbus_message_get_arguments(message, "a{sv}", &iter))
		goto parse_failed;

	while (l_dbus_message_iter_next_entry(&iter, &key, &variant)) {
		if (strcmp(key, "NetworkConfigurationEnabled"))
			continue;

		if (!l_dbus_message_iter_get_variant(&variant, "b",
							&netconfig_enabled))
			goto parse_failed;

		break;
	}

	if (!command_is_interactive_mode())
		return;

	if (!l_dbus_message_get_arguments(message, "a{sv}", &iter))
		goto parse_failed;

	display("NetworkConfigurationEnabled: %s\n",
				netconfig_enabled ? "enabled" : "disabled");

	while (l_dbus_message_iter_next_entry(&iter, &key, &variant)) {
		if (!strcmp(key, "Version") ||
					!strcmp(key, "StateDirectory")) {
			const char *sval;

			if (!l_dbus_message_iter_get_variant(&variant, "s",
								&sval))
				continue;

			display("%s: %s\n", key, sval);
		}
	}

	return;

parse_failed:
	l_error("Failed to parse GetInfo message");
	return;
}

static bool daemon_get_info(void)
{
	const struct proxy_interface *proxy =
		proxy_interface_find(IWD_DAEMON_INTERFACE, IWD_DAEMON_PATH);

	if (!proxy)
		return false;

	proxy_interface_method_call(proxy, "GetInfo", "", get_info_callback);

	return true;
}

static void *daemon_create(void)
{
	daemon_get_info();
	return NULL;
}

static void daemon_destroy(void *data)
{
}

static const struct proxy_interface_type_ops daemon_ops = {
	.create = daemon_create,
	.destroy = daemon_destroy,
};

static struct proxy_interface_type daemon_interface_type = {
	.interface = IWD_DAEMON_INTERFACE,
	.ops = &daemon_ops,
};

static int daemon_interface_init(void)
{
	proxy_interface_type_register(&daemon_interface_type);

	return 0;
}

static void daemon_interface_exit(void)
{
	proxy_interface_type_unregister(&daemon_interface_type);
}

INTERFACE_TYPE(daemon_interface_type, daemon_interface_init,
						daemon_interface_exit)
