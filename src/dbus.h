/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2019  Intel Corporation. All rights reserved.
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
#include <stdbool.h>
#include "ell/dbus.h"
#include "ell/dbus-service.h"

#define IWD_SERVICE "net.connman.iwd"

#define IWD_DAEMON_INTERFACE "net.connman.iwd.Daemon"
#define IWD_AGENT_MANAGER_INTERFACE "net.connman.iwd.AgentManager"
#define IWD_WIPHY_INTERFACE "net.connman.iwd.Adapter"
#define IWD_DEVICE_INTERFACE "net.connman.iwd.Device"
#define IWD_NETWORK_INTERFACE "net.connman.iwd.Network"
#define IWD_AGENT_INTERFACE "net.connman.iwd.Agent"
#define IWD_WSC_INTERFACE "net.connman.iwd.SimpleConfiguration"
#define IWD_KNOWN_NETWORK_INTERFACE "net.connman.iwd.KnownNetwork"
#define IWD_SIGNAL_AGENT_INTERFACE "net.connman.iwd.SignalLevelAgent"
#define IWD_AP_INTERFACE "net.connman.iwd.AccessPoint"
#define IWD_ADHOC_INTERFACE "net.connman.iwd.AdHoc"
#define IWD_STATION_INTERFACE "net.connman.iwd.Station"
#define IWD_P2P_INTERFACE "net.connman.iwd.p2p.Device"
#define IWD_P2P_PEER_INTERFACE "net.connman.iwd.p2p.Peer"
#define IWD_P2P_SERVICE_MANAGER_INTERFACE "net.connman.iwd.p2p.ServiceManager"
#define IWD_P2P_WFD_INTERFACE "net.connman.iwd.p2p.Display"
#define IWD_STATION_DIAGNOSTIC_INTERFACE "net.connman.iwd.StationDiagnostic"
#define IWD_AP_DIAGNOSTIC_INTERFACE "net.connman.iwd.AccessPointDiagnostic"
#define IWD_STATION_DEBUG_INTERFACE "net.connman.iwd.StationDebug"
#define IWD_DPP_INTERFACE "net.connman.iwd.DeviceProvisioning"
#define IWD_NETCONFIG_AGENT_INTERFACE \
	"net.connman.iwd.NetworkConfigurationAgent"

#define IWD_BASE_PATH "/net/connman/iwd"
#define IWD_AGENT_MANAGER_PATH IWD_BASE_PATH
#define IWD_P2P_SERVICE_MANAGER_PATH IWD_BASE_PATH

struct l_dbus;

struct l_dbus *dbus_get_bus(void);

void dbus_pending_reply(struct l_dbus_message **msg,
				struct l_dbus_message *reply);
bool dbus_append_dict_basic(struct l_dbus_message_builder *builder,
				const char *name, char type,
				const void *data);

struct l_dbus_message *dbus_error_busy(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_failed(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_aborted(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_available(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_invalid_args(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_invalid_format(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_already_exists(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_found(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_supported(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_no_agent(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_connected(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_configured(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_implemented(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_service_set_overlap(
						struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_already_provisioned(
						struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_hidden(struct l_dbus_message *msg);

struct l_dbus_message *dbus_error_from_errno(int err,
						struct l_dbus_message *msg);

bool dbus_init(struct l_dbus *dbus);
void dbus_exit(void);
void dbus_shutdown(void);

#ifndef HAVE_DBUS
bool fake_dbus_register_interface(const char *interface,
                                  l_dbus_interface_setup_func_t setup_func,
                                  l_dbus_destroy_func_t destroy);
bool fake_dbus_unregister_interface(const char *interface);
bool fake_dbus_object_add_interface(const char *object, const char *interface, void *user_data);
bool fake_dbus_object_remove_interface(const char *object, const char *interface);

#define l_dbus_register_interface(dbus, interface, setup_func, destroy, handle_old_style_properties) \
    fake_dbus_register_interface(interface, setup_func, destroy)
#define l_dbus_unregister_interface(dbus, interface) fake_dbus_unregister_interface(interface)
#define l_dbus_object_add_interface(dbus, object, interface, user_data) fake_dbus_object_add_interface(object, interface, user_data)
#define l_dbus_object_remove_interface(dbus, object, interface) fake_dbus_object_remove_interface(object, interface)

/* Stub dbus-service.h */
#define l_dbus_interface_method(...) (false)
#define l_dbus_interface_signal(...) (false)
#define l_dbus_interface_property(...) (false)
#define l_dbus_property_changed(...) (false)
#endif
