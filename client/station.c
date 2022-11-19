/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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

#include <arpa/inet.h>
#include <ifaddrs.h>

#include <ell/ell.h>

#include "client/command.h"
#include "client/dbus-proxy.h"
#include "client/device.h"
#include "client/network.h"
#include "client/display.h"
#include "client/diagnostic.h"
#include "client/daemon.h"

struct station {
	bool scanning;
	char *state;
	const struct proxy_interface *connected_network;
};

static void *station_create(void)
{
	return l_new(struct station, 1);
}

static void station_destroy(void *data)
{
	struct station *station = data;

	l_free(station->state);
	station->connected_network = NULL;

	l_free(station);
}

static const struct proxy_interface_type_ops station_ops = {
	.create = station_create,
	.destroy = station_destroy,
};

static const char *get_scanning_tostr(const void *data)
{
	const struct station *station = data;

	return station->scanning ? "yes" : "no";
}

static void update_scanning(void *data, struct l_dbus_message_iter *variant)
{
	struct station *station = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		station->scanning = false;
		return;
	}

	station->scanning = value;
}

static const char *get_state(const void *data)
{
	const struct station *station = data;

	return station->state;
}

static void update_state(void *data, struct l_dbus_message_iter *variant)
{
	struct station *station = data;
	const char *value;

	l_free(station->state);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		station->state = NULL;
		return;
	}

	station->state = l_strdup(value);
}

static void update_connected_network(void *data,
					struct l_dbus_message_iter *variant)
{
	struct station *station = data;
	const char *path;

	if (!l_dbus_message_iter_get_variant(variant, "o", &path)) {
		station->connected_network = NULL;

		return;
	}

	station->connected_network = proxy_interface_find(IWD_NETWORK_INTERFACE,
									path);
}

static const struct proxy_interface_property station_properties[] = {
	{ "Scanning",  "b", update_scanning,  get_scanning_tostr },
	{ "State",    "s", update_state,    get_state },
	{ "ConnectedNetwork",
			"o", update_connected_network },
	{ }
};

static struct proxy_interface_type station_interface_type = {
	.interface = IWD_STATION_INTERFACE,
	.properties = station_properties,
	.ops = &station_ops,
};

static struct proxy_interface_type station_diagnostic_interface = {
	.interface = IWD_STATION_DIAGNOSTIC_INTERFACE,
};

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static void display_addresses(const char *device_name)
{
	struct ifaddrs *ifa;
	struct ifaddrs *cur;
	bool have_address = false;
	char addrstr[INET6_ADDRSTRLEN];
	int r;

	if (getifaddrs(&ifa) == -1)
		return;

	for (cur = ifa; cur; cur = cur->ifa_next) {
		if (cur->ifa_addr == NULL)
			continue;

		if (strcmp(cur->ifa_name, device_name))
			continue;

		if (cur->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *si6 =
					(struct sockaddr_in6 *) cur->ifa_addr;

			if (IN6_IS_ADDR_LINKLOCAL(&si6->sin6_addr))
				continue;

			if (!inet_ntop(AF_INET6, &si6->sin6_addr,
						addrstr, sizeof(addrstr)))
				continue;

			have_address = true;
			display("%s%*s  %-*s%-*s\n", MARGIN, 8, "", 20,
				"IPv6 address", 47, addrstr);
		} else if (cur->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *si =
					(struct sockaddr_in *) cur->ifa_addr;

			if (!inet_ntop(AF_INET, &si->sin_addr,
					addrstr, sizeof(addrstr)))
				continue;

			have_address = true;
			display_table_row(MARGIN, 3, 8, "", 20, "IPv4 address", 47, addrstr);
		}
	}

	freeifaddrs(ifa);

	if (have_address)
		return;

	r = daemon_netconfig_enabled();
	if (r < 0 || r == 1)
		return;

	display_table_row(MARGIN, 3, 8, "", 20, "No IP addresses", 47, "Is DHCP client configured?");
}


static void display_station(const char *device_name,
					const struct proxy_interface *proxy)
{
	const struct station *station = proxy_interface_get_data(proxy);
	char *caption = l_strdup_printf("%s: %s", "Station", device_name);

	proxy_properties_display(proxy, caption, MARGIN, 20, 47);
	l_free(caption);

	if (station->connected_network) {
		display_table_row(MARGIN, 3, 8, "", 20, "Connected network",
			47, network_get_name(station->connected_network));

		display_addresses(device_name);
	}

	/* The table footer is handled by cmd_show. */
}

static void display_station_inline(const char *margin, const void *data)
{
	const struct proxy_interface *station_i = data;
	const struct station *station = proxy_interface_get_data(station_i);
	struct proxy_interface *device_i =
		proxy_interface_find(IWD_DEVICE_INTERFACE,
					proxy_interface_get_path(station_i));
	const char *identity;

	if (!device_i)
		return;

	identity = proxy_interface_get_identity_str(device_i);
	if (!identity)
		return;

	display_table_row(margin, 3, 20, identity, 15, station->state ? : "",
				8, station->scanning ? "scanning" : "");
}

static enum cmd_status cmd_list(const char *device_name, char **argv, int argc)
{
	const struct l_queue_entry *entry;
	struct l_queue *match =
		proxy_interface_find_all(IWD_STATION_INTERFACE, NULL, NULL);

	display_table_header("Devices in Station Mode",
				MARGIN "%-*s  %-*s  %-*s",
				20, "Name", 15, "State", 8, "Scanning");

	if (!match) {
		display("No devices in Station mode available.\n");
		display_table_footer();

		return CMD_STATUS_DONE;
	}

	for (entry = l_queue_get_entries(match); entry; entry = entry->next) {
		const struct proxy_interface *station = entry->data;
		display_station_inline(MARGIN, station);
	}

	display_table_footer();

	l_queue_destroy(match, NULL);

	return CMD_STATUS_DONE;
}

static char *connect_cmd_arg_completion(const char *text, int state,
					const char *device_name)
{
	const struct proxy_interface *device = device_proxy_find(device_name,
							IWD_STATION_INTERFACE);

	if (!device)
		return NULL;

	return network_name_completion(device, text, state);
}

static enum cmd_status cmd_connect(const char *device_name,
						char **argv, int argc)
{
	struct network_args network_args;
	struct l_queue *match;
	const struct proxy_interface *network_proxy;
	const struct proxy_interface *device_proxy;

	if (argc < 1)
		return CMD_STATUS_INVALID_ARGS;

	device_proxy = device_proxy_find_by_name(device_name);
	if (!device_proxy)
		return CMD_STATUS_INVALID_VALUE;

	network_args.name = argv[0];
	network_args.type = argc >= 2 ? argv[1] : NULL;

	match = network_match_by_device_and_args(device_proxy, &network_args);
	if (!match) {
		display("Invalid network name '%s'\n", network_args.name);
		return CMD_STATUS_INVALID_VALUE;
	}

	if (l_queue_length(match) > 1) {
		if (!network_args.type) {
			display("Provided network name is ambiguous. "
				"Please specify security type.\n");
		}

		l_queue_destroy(match, NULL);

		return CMD_STATUS_INVALID_VALUE;
	}

	network_proxy = l_queue_pop_head(match);
	l_queue_destroy(match, NULL);
	network_connect(network_proxy);

	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_connect_hidden_network(const char *device_name,
							char **argv,
							int argc)
{
	const struct proxy_interface *station_i;

	if (argc != 1)
		return CMD_STATUS_INVALID_ARGS;

	station_i = device_proxy_find(device_name, IWD_STATION_INTERFACE);
	if (!station_i) {
		display("No station on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(station_i, "ConnectHiddenNetwork", "s",
					check_errors_method_callback,
					argv[0]);

	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_disconnect(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *station_i =
			device_proxy_find(device_name, IWD_STATION_INTERFACE);

	if (!station_i) {
		display("No station on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(station_i, "Disconnect", "",
						check_errors_method_callback);

	return CMD_STATUS_TRIGGERED;
}

struct ordered_network {
	char *network_path;
	int16_t signal_strength;
};

static void ordered_networks_destroy(void *data)
{
	struct ordered_network *network = data;

	l_free(network->network_path);
	l_free(network);
}

static const char *dbms_tostars(int16_t dbms)
{
	if (dbms >= -6000)
		return "****";

	if (dbms >= -6700)
		return "***" COLOR_BOLDGRAY("*");

	if (dbms >= -7500)
		return "**" COLOR_BOLDGRAY("**");

	return "*" COLOR_BOLDGRAY("***");
}

#define RSSI_DBMS "rssi-dbms"
#define RSSI_BARS "rssi-bars"

static const struct {
	const char *option;
} ordered_networks_arg_options[] = {
	{ RSSI_DBMS },
	{ RSSI_BARS },
	{ }
};

static bool display_signal_as_dbms;

static void ordered_networks_display(struct l_queue *ordered_networks)
{
	char *dbms = NULL;
	const struct l_queue_entry *entry;

	display_table_header("Available networks", "%s%-*s  %-*s  %-*s  %*s",
					MARGIN, 2, "", 32, "Network name",
					18, "Security", 6, "Signal");

	if (!l_queue_length(ordered_networks)) {
		display("No networks available\n");
		display_table_footer();

		return;
	}

	for (entry = l_queue_get_entries(ordered_networks);
						entry; entry = entry->next) {
		struct ordered_network *network = entry->data;
		const struct proxy_interface *network_i =
				network_get_proxy(network->network_path);
		const char *network_name = network_get_name(network_i);
		const char *network_type = network_get_type(network_i);

		if (!strcmp(network_type, "wep"))
			network_type = "wep (unsupported)";

		if (display_signal_as_dbms)
			dbms = l_strdup_printf("%d", network->signal_strength);

		display_table_row(MARGIN, 4, 2,
				network_is_connected(network_i) ?
				COLOR_BOLDGRAY("> ") : "",
				32, network_name, 18, network_type, 6,
				display_signal_as_dbms ? dbms :
				dbms_tostars(network->signal_strength));

		if (display_signal_as_dbms) {
			l_free(dbms);
			dbms = NULL;
		}
	}

	display_table_footer();
}

static void ordered_networks_callback(struct l_dbus_message *message,
								void *proxy)
{
	struct l_queue *networks = NULL;
	struct ordered_network network;
	struct l_dbus_message_iter iter;

	if (dbus_message_has_error(message))
		return;

	if (!l_dbus_message_get_arguments(message, "a(on)", &iter)) {
		l_error("Failed to parse ordered networks callback message");

		return;
	}

	while (l_dbus_message_iter_next_entry(&iter,
						&network.network_path,
						&network.signal_strength)) {
		struct ordered_network *net = l_new(struct ordered_network, 1);

		if (!networks)
			networks = l_queue_new();

		net->network_path = l_strdup(network.network_path);
		net->signal_strength = network.signal_strength;

		l_queue_push_tail(networks, net);
	}

	ordered_networks_display(networks);

	l_queue_destroy(networks, ordered_networks_destroy);
}

static char *get_networks_cmd_arg_completion(const char *text, int state,
						const char *device_name)
{
	static int index;
	static int len;
	const char *arg;

	if (!state) {
		index = 0;
		len = strlen(text);
	}

	while ((arg = ordered_networks_arg_options[index++].option)) {
		if (!strncmp(arg, text, len))
			return l_strdup(arg);
	}

	return NULL;
}

static enum cmd_status cmd_get_networks(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *station_i =
			device_proxy_find(device_name, IWD_STATION_INTERFACE);

	if (!station_i) {
		display("No station on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	if (!argc)
		goto proceed;

	if (!strcmp(argv[0], RSSI_DBMS))
		display_signal_as_dbms = true;
	else
		display_signal_as_dbms = false;

proceed:
	proxy_interface_method_call(station_i, "GetOrderedNetworks", "",
					ordered_networks_callback);

	return CMD_STATUS_TRIGGERED;
}

struct hidden_access_point {
	char *address;
	int16_t signal_strength;
	char *type;
};

static void hidden_access_point_destroy(void *data)
{
	struct hidden_access_point *ap = data;

	l_free(ap->address);
	l_free(ap->type);
	l_free(ap);
}

static void hidden_access_points_display(struct l_queue *access_points)
{
	const struct l_queue_entry *entry;

	display_table_header("Available hidden APs", MARGIN "%-*s  %-*s  %*s",
				20, "Address", 10, "Security", 6, "Signal");

	if (l_queue_isempty(access_points)) {
		display("No hidden APs are available.\n");
		display_table_footer();

		return;
	}

	for (entry = l_queue_get_entries(access_points); entry;
							entry = entry->next) {
		const struct hidden_access_point *ap = entry->data;
		L_AUTO_FREE_VAR(char *, dbms) = NULL;

		if (display_signal_as_dbms)
			dbms = l_strdup_printf("%d", ap->signal_strength);

		display_table_row(MARGIN, 3, 20, ap->address, 10, ap->type, 6,
				dbms ? : dbms_tostars(ap->signal_strength));
	}

	display_table_footer();
}

static void hidden_access_points_callback(struct l_dbus_message *message,
								void *proxy)
{
	struct l_queue *access_points = NULL;
	struct l_dbus_message_iter iter;
	const char *address;
	uint16_t strength;
	const char *type;

	if (dbus_message_has_error(message))
		return;

	if (!l_dbus_message_get_arguments(message, "a(sns)", &iter)) {
		l_error("Failed to parse hidden stations callback message");

		return;
	}

	while (l_dbus_message_iter_next_entry(&iter, &address,
						&strength, &type)) {
		struct hidden_access_point *ap =
			l_new(struct hidden_access_point, 1);

		if (!access_points)
			access_points = l_queue_new();

		ap->address = l_strdup(address);
		ap->signal_strength = strength;
		ap->type = l_strdup(type);

		l_queue_push_tail(access_points, ap);
	}

	hidden_access_points_display(access_points);

	l_queue_destroy(access_points, hidden_access_point_destroy);
}

static enum cmd_status cmd_get_hidden_access_points(const char *device_name,
							char **argv, int argc)
{
	const struct proxy_interface *station_i =
			device_proxy_find(device_name, IWD_STATION_INTERFACE);

	if (!station_i) {
		display("Device '%s' is not in station mode.\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	if (!argc)
		goto proceed;

	if (!strcmp(argv[0], RSSI_DBMS))
		display_signal_as_dbms = true;
	else
		display_signal_as_dbms = false;

proceed:
	proxy_interface_method_call(station_i, "GetHiddenAccessPoints", "",
						hidden_access_points_callback);

	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_scan(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *station_i =
			device_proxy_find(device_name, IWD_STATION_INTERFACE);

	if (!station_i) {
		display("No station on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(station_i, "Scan", "",
						check_errors_method_callback);

	return CMD_STATUS_TRIGGERED;
}

static void get_diagnostics_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message_iter iter;

	if (dbus_message_has_error(message))
		return;

	if (!l_dbus_message_get_arguments(message, "a{sv}", &iter)) {
		l_error("Failed to parse GetDiagnostics message");
		goto done;
	}

	diagnostic_display(&iter, MARGIN, 20, 47);

done:
	/* Finish the table started by cmd_show */
	display_table_footer();
}

static enum cmd_status cmd_show(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *station =
			device_proxy_find(device_name, IWD_STATION_INTERFACE);
	const struct proxy_interface *diagnostic =
					device_proxy_find(device_name,
					IWD_STATION_DIAGNOSTIC_INTERFACE);

	if (!station) {
		display("No station on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	display_station(device_name, station);

	/*
	 * No need to query additional diagnostic information if IWD has
	 * no diagnostic interface.
	 */
	if (!diagnostic) {
		display_table_footer();
		return CMD_STATUS_DONE;
	}

	proxy_interface_method_call(diagnostic, "GetDiagnostics", "",
					get_diagnostics_callback);

	/* Don't display table footer, this will be done in the callback */
	return CMD_STATUS_TRIGGERED;
}

static const struct command station_commands[] = {
	{ NULL, "list", NULL, cmd_list, "List devices in Station mode", true },
	{ "<wlan>", "connect",
				"<\"network name\"> [security]",
					cmd_connect,
						"Connect to network", false,
		connect_cmd_arg_completion },
	{ "<wlan>", "connect-hidden",
				"<\"network name\">",
					cmd_connect_hidden_network,
						"Connect to hidden network",
									false },
	{ "<wlan>", "disconnect",
				NULL,   cmd_disconnect, "Disconnect" },
	{ "<wlan>", "get-networks",
				"[rssi-dbms/rssi-bars]",
					cmd_get_networks,
						"Get networks",       true,
			get_networks_cmd_arg_completion },
	{ "<wlan>", "get-hidden-access-points", "[rssi-dbms]",
					cmd_get_hidden_access_points,
						"Get hidden APs", true },
	{ "<wlan>", "scan",     NULL,   cmd_scan, "Scan for networks" },
	{ "<wlan>", "show",     NULL,   cmd_show, "Show station info", true },
	{ }
};

static char *family_arg_completion(const char *text, int state)
{
	return device_arg_completion(text, state, station_commands,
							IWD_STATION_INTERFACE);
}

static char *entity_arg_completion(const char *text, int state)
{
	return command_entity_arg_completion(text, state, station_commands);
}

static struct command_family station_command_family = {
	.caption = "Station",
	.name = "station",
	.command_list = station_commands,
	.family_arg_completion = family_arg_completion,
	.entity_arg_completion = entity_arg_completion,
};

static int station_command_family_init(void)
{
	command_family_register(&station_command_family);

	return 0;
}

static void station_command_family_exit(void)
{
	command_family_unregister(&station_command_family);
}

COMMAND_FAMILY(station_command_family, station_command_family_init,
						station_command_family_exit)

static int station_interface_init(void)
{
	proxy_interface_type_register(&station_interface_type);
	proxy_interface_type_register(&station_diagnostic_interface);

	return 0;
}

static void station_interface_exit(void)
{
	proxy_interface_type_unregister(&station_interface_type);
	proxy_interface_type_unregister(&station_diagnostic_interface);
}

INTERFACE_TYPE(station_interface_type,
				station_interface_init, station_interface_exit)
