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

#include <ell/ell.h>

#include "src/dbus.h"
#include "src/netdev.h"
#include "src/module.h"

static uint32_t netdev_watch;

struct dpp_sm {
	struct netdev *netdev;
};

static void dpp_free(struct dpp_sm *dpp)
{
	l_free(dpp);
}

static void dpp_create(struct netdev *netdev)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct dpp_sm *dpp = l_new(struct dpp_sm, 1);

	dpp->netdev = netdev;

	l_dbus_object_add_interface(dbus, netdev_get_path(netdev),
					IWD_DPP_INTERFACE, dpp);
}

static void dpp_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_NEW:
	case NETDEV_WATCH_EVENT_UP:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_STATION &&
				netdev_get_is_up(netdev))
			dpp_create(netdev);
		break;
	case NETDEV_WATCH_EVENT_DEL:
	case NETDEV_WATCH_EVENT_DOWN:
		l_dbus_object_remove_interface(dbus_get_bus(),
						netdev_get_path(netdev),
						IWD_DPP_INTERFACE);
		break;
	default:
		break;
	}
}

static struct l_dbus_message *dpp_dbus_start_enrollee(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	return dbus_error_not_supported(message);
}

static struct l_dbus_message *dpp_dbus_stop(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	return dbus_error_not_supported(message);
}

static void dpp_setup_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "StartEnrollee", 0,
				dpp_dbus_start_enrollee, "s", "", "uri");
	l_dbus_interface_method(interface, "Stop", 0,
				dpp_dbus_stop, "", "");
}

static void dpp_destroy_interface(void *user_data)
{
	struct dpp_sm *dpp = user_data;

	dpp_free(dpp);
}

static int dpp_init(void)
{
	netdev_watch = netdev_watch_add(dpp_netdev_watch, NULL, NULL);

	l_dbus_register_interface(dbus_get_bus(), IWD_DPP_INTERFACE,
					dpp_setup_interface,
					dpp_destroy_interface, false);
	return 0;
}

static void dpp_exit(void)
{
	l_debug("");

	netdev_watch_remove(netdev_watch);
}

IWD_MODULE(dpp, dpp_init, dpp_exit);
IWD_MODULE_DEPENDS(dpp, netdev);
