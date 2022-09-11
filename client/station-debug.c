#include <ell/ell.h>
#include "ell/useful.h"

#include "client/command.h"
#include "client/dbus-proxy.h"
#include "client/device.h"
#include "client/display.h"
#include "client/properties.h"
#include "client/network.h"
#include "src/util.h"

struct station_debug {
	struct l_queue *network_list;
	bool autoconnect;
};

struct network {
	char *ssid;
	struct l_queue *bss_list;
};

struct bss {
	char addr[18];
	uint32_t frequency;
	int8_t rssi;
	int32_t rank;
	uint8_t mde[3];
};

static void network_free(void *data)
{
	struct network *network = data;

	l_queue_destroy(network->bss_list, l_free);
}

static void *station_debug_create(void)
{
	struct station_debug *debug = l_new(struct station_debug, 1);

	debug->network_list = l_queue_new();

	return debug;
}

static void station_debug_destroy(void *data)
{
	struct station_debug *debug = data;

	l_queue_destroy(debug->network_list, network_free);

	l_free(debug);
}

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static enum cmd_status cmd_debug_connect(const char *device_name,
						char **argv, int argc)
{

	const struct proxy_interface *debug_i;
	uint8_t addr[6];

	if (argc < 1)
		return CMD_STATUS_INVALID_ARGS;

	debug_i = device_proxy_find(device_name, IWD_STATION_DEBUG_INTERFACE);
	if (!debug_i) {
		display_error("IWD not in developer mode");
		return CMD_STATUS_INVALID_VALUE;
	}

	if (!util_string_to_address(argv[0], addr))
		return CMD_STATUS_INVALID_ARGS;

	proxy_interface_method_call(debug_i, "ConnectBssid", "ay",
					check_errors_method_callback, 6,
					addr[0], addr[1], addr[2],
					addr[3], addr[4], addr[5]);
	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_debug_roam(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *debug_i;
	uint8_t addr[6];

	if (argc < 1)
		return CMD_STATUS_INVALID_ARGS;

	debug_i = device_proxy_find(device_name, IWD_STATION_DEBUG_INTERFACE);
	if (!debug_i) {
		display_error("IWD not in developer mode");
		return CMD_STATUS_INVALID_VALUE;
	}

	if (!util_string_to_address(argv[0], addr))
		return CMD_STATUS_INVALID_ARGS;

	proxy_interface_method_call(debug_i, "Roam", "ay",
					check_errors_method_callback, 6,
					addr[0], addr[1], addr[2],
					addr[3], addr[4], addr[5]);
	return CMD_STATUS_TRIGGERED;
}

static void get_byte_array(struct l_dbus_message_iter *variant, uint8_t *out,
				unsigned int len)
{
	struct l_dbus_message_iter array;
	uint32_t elems = 6;
	uint8_t *a;

	if (!l_dbus_message_iter_get_variant(variant, "ay", &array))
		goto error;

	if (!l_dbus_message_iter_get_fixed_array(&array, &a, &elems))
		goto error;

	if (elems != len)
		goto error;

	memcpy(out, a, len);

	return;

error:
	display_error("Invalid Address element");
}

static void get_address(struct l_dbus_message_iter *variant,
			char addr_out[static 18])
{
	char *s;

	if (!l_dbus_message_iter_get_variant(variant, "s", &s))
		goto error;

	if (strlen(s) != 17)
		goto error;

	strcpy(addr_out, s);

	return;

error:
	display_error("Invalid Address element");
}

static uint32_t get_u32(struct l_dbus_message_iter *variant)
{
	uint32_t u32 = 0;

	if (!l_dbus_message_iter_get_variant(variant, "u", &u32))
		display_error("Invalid Frequency element");

	return u32;
}

static uint32_t get_u16(struct l_dbus_message_iter *variant)
{
	uint32_t u16 = 0;

	if (!l_dbus_message_iter_get_variant(variant, "q", &u16))
		display_error("Invalid Frequency element");

	return u16;
}

static uint32_t get_i32(struct l_dbus_message_iter *variant)
{
	int32_t i32 = 0;

	if (!l_dbus_message_iter_get_variant(variant, "i", &i32))
		display_error("Invalid Frequency element");

	return i32;
}

static void display_bss(struct bss *bss)
{
	char row[128];

	sprintf(row, "%s%-*s  %s  %-*i  %-*u  %-*i  %02x%02x%02x",
		MARGIN MARGIN, 4, "", bss->addr, 4, bss->rssi,
		6, bss->frequency, 8, bss->rank,
		bss->mde[0], bss->mde[1], bss->mde[2]);

	display("%s\n", row);

	return;
}

static void get_networks_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	struct proxy_interface *debug_i = user_data;
	struct station_debug *debug = proxy_interface_get_data(debug_i);
	struct l_dbus_message_iter iter;
	struct l_dbus_message_iter variant;
	struct l_dbus_message_iter array;
	struct l_dbus_message_iter dict;
	const char *key;

	if (dbus_message_has_error(message))
		return;

	if (!l_dbus_message_get_arguments(message, "a{oaa{sv}}", &iter)) {
		l_error("Failed to parse GetDiagnostics message");
		return;
	}

	display_table_header("Available Networks (debug)",
				"%s%-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s",
				"", 2, "", 4, "SSID", 17, "BSSID", 4, "RSSI",
				6, "Freq", 8, "Rank", 10, "MDE");

	while (l_dbus_message_iter_next_entry(&iter, &key, &array)) {
		struct network *network = l_new(struct network, 1);
		const struct proxy_interface *net_i = network_get_proxy(key);

		network->ssid = l_strdup(network_get_name(net_i));
		network->bss_list = l_queue_new();

		display_table_row(MARGIN MARGIN, 3, 32, network->ssid,
					18, "", 6, "");

		while (l_dbus_message_iter_next_entry(&array, &dict)) {
			struct bss *bss = l_new(struct bss, 1);

			while (l_dbus_message_iter_next_entry(&dict, &key,
								&variant)) {
				if (!strcmp(key, "Address"))
					get_address(&variant, bss->addr);
				else if (!strcmp(key, "Frequency"))
					bss->frequency = get_u32(&variant);
				else if (!strcmp(key, "RSSI"))
					bss->rssi = get_i32(&variant);
				else if (!strcmp(key, "Rank"))
					bss->rank = get_u16(&variant);
				else if (!strcmp(key, "MDE"))
					get_byte_array(&variant, bss->mde, 3);
			}

			display_bss(bss);

			l_queue_push_tail(network->bss_list, bss);
		}

		l_queue_push_tail(debug->network_list, network);
	}

	display_table_footer();
}

static enum cmd_status cmd_debug_get_networks(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *debug_i;

	debug_i = device_proxy_find(device_name, IWD_STATION_DEBUG_INTERFACE);
	if (!debug_i) {
		display_error("IWD not in developer mode");
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(debug_i, "GetNetworks", "",
					get_networks_method_callback);

	return CMD_STATUS_TRIGGERED;
}

static char *connect_debug_cmd_arg_completion(const char *text, int state,
						const char *device_name)
{
	const struct proxy_interface *debug_i;
	struct station_debug *debug;
	static const struct l_queue_entry *n_entry;
	static const struct l_queue_entry *b_entry;
	size_t len = strlen(text);

	debug_i = device_proxy_find(device_name, IWD_STATION_DEBUG_INTERFACE);
	if (!debug_i)
		return NULL;

	debug = proxy_interface_get_data(debug_i);

	if (!state)
		n_entry = l_queue_get_entries(debug->network_list);

	while (n_entry) {
		struct network *network = n_entry->data;

		n_entry = n_entry->next;

		if (!b_entry)
			b_entry = l_queue_get_entries(network->bss_list);

		while (b_entry) {
			struct bss *bss = b_entry->data;

			b_entry = b_entry->next;

			if (len > strlen(bss->addr))
				return NULL;

			if (strncmp(text, bss->addr, len))
				continue;

			return l_strdup_printf(MAC, MAC_STR(bss->addr));
		}
	}

	return NULL;
}

static const char *get_autoconnect_tostr(const void *data)
{
	const struct station_debug *debug = data;

	return debug->autoconnect ? "on" : "off";
}

static void update_autoconnect(void *data, struct l_dbus_message_iter *variant)
{
	struct station_debug *debug = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		debug->autoconnect = false;

		return;
	}

	debug->autoconnect = value;
}

static const struct proxy_interface_property debug_properties[] = {
	{ "AutoConnect",  "b", update_autoconnect,  get_autoconnect_tostr, true,
			properties_builder_append_on_off_variant,
			properties_on_off_opts },
	{ }
};

static enum cmd_status cmd_debug_set_autoconnect(const char *device_name,
						char **argv, int argc)
{
	const struct proxy_interface *proxy = device_proxy_find(device_name,
						IWD_STATION_DEBUG_INTERFACE);

	if (!proxy) {
		display_error("IWD not in developer mode");
		return CMD_STATUS_INVALID_VALUE;
	}

	if (argc != 1)
		return CMD_STATUS_INVALID_ARGS;

	if (!proxy_property_set(proxy, "AutoConnect", argv[0],
						check_errors_method_callback))
		return CMD_STATUS_INVALID_VALUE;

	return CMD_STATUS_TRIGGERED;
}

static const struct command station_debug_commands[] = {
	{ "<wlan>", "connect", "<bssid>", cmd_debug_connect,
					"Connect to a specific BSS", false,
					connect_debug_cmd_arg_completion },
	{ "<wlan>", "roam", "<bssid>", cmd_debug_roam,
					"Roam to a BSS", false },
	{ "<wlan>", "get-networks", NULL, cmd_debug_get_networks,
					"Get networks", true },
	{ "<wlan>", "autoconnect", "on|off", cmd_debug_set_autoconnect,
					"Set AutoConnect property", false },
	{ }
};

static char *family_debug_arg_completion(const char *text, int state)
{
	return device_arg_completion(text, state, station_debug_commands,
						IWD_STATION_DEBUG_INTERFACE);
}

static char *entity_debug_arg_completion(const char *text, int state)
{
	return command_entity_arg_completion(text, state,
						station_debug_commands);
}

static struct command_family station_debug_command_family = {
	.caption = "Station Debug",
	.name = "debug",
	.command_list = station_debug_commands,
	.family_arg_completion = family_debug_arg_completion,
	.entity_arg_completion = entity_debug_arg_completion,
};

static int station_debug_command_family_init(void)
{
	command_family_register(&station_debug_command_family);

	return 0;
}

static void station_debug_command_family_exit(void)
{
	command_family_unregister(&station_debug_command_family);
}

COMMAND_FAMILY(station_debug_command_family, station_debug_command_family_init,
					station_debug_command_family_exit)

static const struct proxy_interface_type_ops station_debug_ops = {
	.create = station_debug_create,
	.destroy = station_debug_destroy,
};

static struct proxy_interface_type station_debug_interface_type = {
	.interface = IWD_STATION_DEBUG_INTERFACE,
	.ops = &station_debug_ops,
	.properties = debug_properties,
};

static int station_debug_interface_init(void)
{
	proxy_interface_type_register(&station_debug_interface_type);

	return 0;
}

static void station_debug_interface_exit(void)
{
	proxy_interface_type_unregister(&station_debug_interface_type);
}

INTERFACE_TYPE(station_debug_interface_type, station_debug_interface_init,
					station_debug_interface_exit)
