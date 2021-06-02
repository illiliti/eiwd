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

enum ofdm_channel_width {
	OFDM_CHANNEL_WIDTH_20MHZ = 0,
	OFDM_CHANNEL_WIDTH_40MHZ,
	OFDM_CHANNEL_WIDTH_80MHZ,
	OFDM_CHANNEL_WIDTH_160MHZ,
};

struct band {
	uint8_t vht_mcs_set[8];
	uint8_t vht_capabilities[4];
	bool vht_supported : 1;
	uint8_t ht_mcs_set[16];
	uint8_t ht_capabilities[2];
	bool ht_supported : 1;
	uint16_t supported_rates_len;
	uint8_t supported_rates[];
};

void band_free(struct band *band);

bool band_ofdm_rate(uint8_t index, enum ofdm_channel_width width,
			int32_t rssi, uint8_t nss, bool sgi,
			uint64_t *data_rate);
