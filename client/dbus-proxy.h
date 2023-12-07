/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
 *  Copyright (C) 2023, Locus Robotics
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

#include <stdio.h>

struct proxy_interface;

#define IWD_ADAPTER_INTERFACE            "net.connman.iwd.Adapter"
#define IWD_ACCESS_POINT_INTERFACE       "net.connman.iwd.AccessPoint"
#define IWD_AD_HOC_INTERFACE             "net.connman.iwd.AdHoc"
#define IWD_AGENT_MANAGER_INTERFACE      "net.connman.iwd.AgentManager"
#define IWD_DEVICE_INTERFACE             "net.connman.iwd.Device"
#define IWD_KNOWN_NETWORK_INTREFACE      "net.connman.iwd.KnownNetwork"
#define IWD_NETWORK_INTERFACE            "net.connman.iwd.Network"
#define IWD_WSC_INTERFACE                "net.connman.iwd.SimpleConfiguration"
#define IWD_STATION_INTERFACE            "net.connman.iwd.Station"
#define IWD_STATION_DIAGNOSTIC_INTERFACE "net.connman.iwd.StationDiagnostic"
#define IWD_STATION_DEBUG_INTERFACE      "net.connman.iwd.StationDebug"
#define IWD_AP_DIAGNOSTIC_INTERFACE      "net.connman.iwd.AccessPointDiagnostic"
#define IWD_DAEMON_INTERFACE             "net.connman.iwd.Daemon"
#define IWD_DPP_INTERFACE                "net.connman.iwd.DeviceProvisioning"
#define IWD_DPP_PKEX_INTERFACE \
				"net.connman.iwd.SharedCodeDeviceProvisioning"

typedef bool (*proxy_property_match_func_t) (const void *a, const void *b);

struct proxy_interface_property {
	const char *name;
	const char *type;
	void (*update)(void *data, struct l_dbus_message_iter *variant);
	const char *(*tostr)(const void *data);
	const bool is_read_write;
	bool (*append)(struct l_dbus_message_builder *builder,
							const char *value_str);
	const char **options;
};

struct proxy_interface_type_ops {
	void *(*create)(void);
	void (*destroy)(void *data);
	const char *(*identity)(void *data);
	void (*display)(const char *margin, const void *data);
};

struct proxy_interface_type {
	const char *interface;
	const struct proxy_interface_property *properties;
	const struct proxy_interface_type_ops *ops;
};

char *proxy_property_completion(
			const struct proxy_interface_property *properties,
			const char *text, int state);

bool proxy_property_set(const struct proxy_interface *proxy, const char *name,
			const char *value_str, l_dbus_message_func_t callback);

struct proxy_interface *proxy_interface_find(const char *interface,
							const char *path);

struct l_queue *proxy_interface_find_all(const char *interface,
					proxy_property_match_func_t function,
					const void *value);

bool proxy_interface_is_same(const struct proxy_interface *a,
					const struct proxy_interface *b);

bool dbus_message_has_error(struct l_dbus_message *message);

bool proxy_interface_method_call(const struct proxy_interface *proxy,
					const char *name, const char *signature,
					l_dbus_message_func_t callback, ...);

void proxy_properties_display(const struct proxy_interface *proxy,
				const char *caption, const char *margin,
				unsigned int name_column_width,
				unsigned int value_column_width);

char *proxy_property_str_completion(const struct proxy_interface_type *type,
					proxy_property_match_func_t function,
					const char *property_name,
					const void *value, int state,
					const char *extra_interface);

void *proxy_interface_get_data(const struct proxy_interface *proxy);
const char *proxy_interface_get_interface(const struct proxy_interface *proxy);
const char *proxy_interface_get_path(const struct proxy_interface *proxy);
const char *proxy_interface_get_identity_str(
					const struct proxy_interface *proxy);

void proxy_interface_display_list(const char *interface);

void proxy_interface_type_register(
			const struct proxy_interface_type *interface_type);
void proxy_interface_type_unregister(
			const struct proxy_interface_type *interface_type);

struct l_dbus *dbus_get_bus(void);

struct interface_type_desc {
	const char *interface;
	int (*init)(void);
	void (*exit)(void);
} __attribute__((aligned(8)));

#define INTERFACE_TYPE(interface, init, exit)				\
	_Pragma("GCC diagnostic push")					\
	_Pragma("GCC diagnostic ignored \"-Wattributes\"")		\
	static struct interface_type_desc __interface_type_ ## interface\
		__attribute__((used, retain, section("__interface"),	\
					aligned(8))) = {		\
			#interface, init, exit				\
		};							\
	_Pragma("GCC diagnostic pop")

bool dbus_proxy_init(void);
bool dbus_proxy_exit(void);
