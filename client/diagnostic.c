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

#include <ell/ell.h>

#include "client/diagnostic.h"
#include "client/display.h"

typedef bool (*display_dict_custom_func_t)(struct l_dbus_message_iter *variant,
				const char *key, const char *margin,
				int name_column_width, int value_column_width);

/*
 * Maps dictionary keys to types/units. 'type' should be a valid DBus type, or
 * zero for displaying in a custom fashion. When the display needs to be
 * customized 'units' should point to a custom display function of the form
 * display_dict_custom_func_t which should display the entire value as well
 * as any units required.
 */
struct diagnostic_dict_mapping {
	const char *key;
	char type;
	const char *units;
	display_dict_custom_func_t custom;
};

static const struct diagnostic_dict_mapping *find_mapping(const char *key,
				const struct diagnostic_dict_mapping *mapping)
{
	int idx = 0;

	while (mapping[idx].key) {
		if (!strcmp(mapping[idx].key, key))
			return &mapping[idx];

		idx++;
	}

	return NULL;
}

static bool display_bitrate_100kbps(struct l_dbus_message_iter *variant,
				const char *key, const char *margin,
				int name_column_width, int value_column_width)
{
	uint32_t rate;
	char str[50];

	if (!l_dbus_message_iter_get_variant(variant, "u", &rate))
		return false;

	sprintf(str, "%u Kbit/s", rate * 100);
	display_table_row(margin, 3, 8, "", name_column_width, key, value_column_width, str);

	return true;
}

static const struct diagnostic_dict_mapping diagnostic_mapping[] = {
	{ "Address", 's' },
	{ "ConnectedBss", 's' },
	{ "RxMode", 's' },
	{ "TxMode", 's' },
	{ "RxBitrate", 0, NULL, display_bitrate_100kbps },
	{ "TxBitrate", 0, NULL, display_bitrate_100kbps },
	{ "ExpectedThroughput", 'u', "Kbit/s" },
	{ "RSSI", 'n', "dBm" },
	{ "AverageRSSI", 'n', "dBm" },
	{ "RxMCS", 'y' },
	{ "TxMCS", 'y' },
	{ "Frequency", 'u' },
	{ "Security", 's' },
	{ NULL }
};

void diagnostic_display(struct l_dbus_message_iter *dict,
			const char *margin, int name_column_width,
			int value_column_width)
{
	struct l_dbus_message_iter variant;
	const char *key;
	const struct diagnostic_dict_mapping *map;
	char display_text[160];

	while (l_dbus_message_iter_next_entry(dict, &key, &variant)) {
		const char *s_value;
		uint32_t u_value;
		int16_t n_value;
		uint8_t y_value;
		int bytes;

		map = find_mapping(key, diagnostic_mapping);
		if (!map)
			continue;

		switch (map->type) {
		case 0:
			if (!map->custom)
				continue;

			if (!map->custom(&variant, key, margin, name_column_width,
					value_column_width))
				goto parse_error;

			/* custom should handle any units, so continue */
			continue;

		case 's':
			if (!l_dbus_message_iter_get_variant(&variant, "s",
							&s_value))
				goto parse_error;

			bytes = sprintf(display_text, "%s", s_value);
			break;

		case 'u':
			if (!l_dbus_message_iter_get_variant(&variant, "u",
							&u_value))
				goto parse_error;

			bytes = sprintf(display_text, "%u", u_value);
			break;

		case 'n':
			if (!l_dbus_message_iter_get_variant(&variant, "n",
							&n_value))
				goto parse_error;

			bytes = sprintf(display_text, "%i", n_value);
			break;

		case 'y':
			if (!l_dbus_message_iter_get_variant(&variant, "y",
							&y_value))
				goto parse_error;

			bytes = sprintf(display_text, "%u", y_value);
			break;

		default:
			display("type %c not handled\n", map->type);
			continue;
		}

		if (map->units)
			sprintf(display_text + bytes, " %s", map->units);

		display_table_row(margin, 3, 8, "", name_column_width,
					key, value_column_width, display_text);
	}

	return;

parse_error:
	display_error("Error parsing dignostics");
}
