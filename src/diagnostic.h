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

enum ie_rsn_akm_suite;

enum diagnostic_mcs_type {
	DIAGNOSTIC_MCS_TYPE_NONE,
	DIAGNOSTIC_MCS_TYPE_HT,
	DIAGNOSTIC_MCS_TYPE_VHT,
	DIAGNOSTIC_MCS_TYPE_HE,
};

struct diagnostic_station_info {
	uint8_t addr[6];
	int8_t cur_rssi;
	int8_t avg_rssi;

	enum diagnostic_mcs_type rx_mcs_type;
	uint32_t rx_bitrate;
	uint8_t rx_mcs;
	enum diagnostic_mcs_type tx_mcs_type;
	uint32_t tx_bitrate;
	uint8_t tx_mcs;

	uint32_t expected_throughput;

	bool have_cur_rssi : 1;
	bool have_avg_rssi : 1;
	bool have_rx_mcs : 1;
	bool have_tx_mcs : 1;
	bool have_rx_bitrate : 1;
	bool have_tx_bitrate : 1;
	bool have_expected_throughput : 1;
};

bool diagnostic_info_to_dict(const struct diagnostic_station_info *info,
				struct l_dbus_message_builder *builder);

const char *diagnostic_akm_suite_to_security(enum ie_rsn_akm_suite suite,
						bool wpa);
