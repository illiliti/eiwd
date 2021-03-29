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

#include "src/diagnostic.h"
#include "src/dbus.h"
#include "src/ie.h"

/*
 * Appends values from diagnostic_station_info into a DBus dictionary. This
 * assumes the DBus dictionary array has already been 'entered', and expects the
 * caller to 'leave' once called. This does not append the station address
 * since the dictionary key name may be different depending on the caller.
 */
bool diagnostic_info_to_dict(const struct diagnostic_station_info *info,
				struct l_dbus_message_builder *builder)
{
	int16_t rssi = (int16_t)info->cur_rssi;
	int16_t avg_rssi = (int16_t)info->avg_rssi;

	if (info->have_cur_rssi)
		dbus_append_dict_basic(builder, "RSSI", 'n', &rssi);

	if (info->have_avg_rssi)
		dbus_append_dict_basic(builder, "AverageRSSI", 'n', &avg_rssi);

	if (info->have_rx_mcs) {
		switch (info->rx_mcs_type) {
		case DIAGNOSTIC_MCS_TYPE_HT:
			dbus_append_dict_basic(builder, "RxMode", 's',
						"802.11n");
			dbus_append_dict_basic(builder, "RxMCS", 'y',
						&info->rx_mcs);
			break;
		case DIAGNOSTIC_MCS_TYPE_VHT:
			dbus_append_dict_basic(builder, "RxMode", 's',
						"802.11ac");
			dbus_append_dict_basic(builder, "RxMCS", 'y',
						&info->rx_mcs);
			break;
		case DIAGNOSTIC_MCS_TYPE_HE:
			dbus_append_dict_basic(builder, "RxMode", 's',
						"802.11ax");
			dbus_append_dict_basic(builder, "RxMCS", 'y',
						&info->rx_mcs);
			break;
		default:
			break;
		}
	}

	if (info->have_tx_mcs) {
		switch (info->tx_mcs_type) {
		case DIAGNOSTIC_MCS_TYPE_HT:
			dbus_append_dict_basic(builder, "TxMode", 's',
						"802.11n");
			dbus_append_dict_basic(builder, "TxMCS", 'y',
						&info->tx_mcs);
			break;
		case DIAGNOSTIC_MCS_TYPE_VHT:
			dbus_append_dict_basic(builder, "TxMode", 's',
						"802.11ac");
			dbus_append_dict_basic(builder, "TxMCS", 'y',
						&info->tx_mcs);
			break;
		case DIAGNOSTIC_MCS_TYPE_HE:
			dbus_append_dict_basic(builder, "TxMode", 's',
						"802.11ax");
			dbus_append_dict_basic(builder, "TxMCS", 'y',
						&info->tx_mcs);
			break;
		default:
			break;
		}
	}

	if (info->have_tx_bitrate)
		dbus_append_dict_basic(builder, "TxBitrate", 'u',
					&info->tx_bitrate);

	if (info->have_rx_bitrate)
		dbus_append_dict_basic(builder, "RxBitrate", 'u',
					&info->rx_bitrate);

	if (info->have_expected_throughput)
		dbus_append_dict_basic(builder, "ExpectedThroughput", 'u',
					&info->expected_throughput);

	return true;
}

const char *diagnostic_akm_suite_to_security(enum ie_rsn_akm_suite akm,
						bool wpa)
{
	switch (akm) {
	case IE_RSN_AKM_SUITE_8021X:
	case IE_RSN_AKM_SUITE_8021X_SHA256:
		return "WPA2-Enterprise";
	case IE_RSN_AKM_SUITE_PSK:
		if (wpa)
			return "WPA1-Personal";

		/* Fall through */
	case IE_RSN_AKM_SUITE_PSK_SHA256:
		return "WPA2-Personal";
	case IE_RSN_AKM_SUITE_FT_OVER_8021X:
	case IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384:
		return "WPA2-Enterprise + FT";
	case IE_RSN_AKM_SUITE_FT_USING_PSK:
		return "WPA2-Personal + FT";
	case IE_RSN_AKM_SUITE_SAE_SHA256:
		return "WPA3-Personal";
	case IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256:
		return "WPA3-Personal + FT";
	case IE_RSN_AKM_SUITE_OWE:
		return "OWE";
	case IE_RSN_AKM_SUITE_FILS_SHA256:
	case IE_RSN_AKM_SUITE_FILS_SHA384:
		return "FILS";
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256:
	case IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384:
		return "FILS + FT";
	case IE_RSN_AKM_SUITE_OSEN:
		return "OSEN";
	default:
		return NULL;
	}
}
