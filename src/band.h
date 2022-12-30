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

enum band_chandef_width {
	BAND_CHANDEF_WIDTH_20NOHT = 0,
	BAND_CHANDEF_WIDTH_20,
	BAND_CHANDEF_WIDTH_40,
	BAND_CHANDEF_WIDTH_80,
	BAND_CHANDEF_WIDTH_80P80,
	BAND_CHANDEF_WIDTH_160,
};

enum band_freq {
	BAND_FREQ_2_4_GHZ = 0x1,
	BAND_FREQ_5_GHZ = 0x2,
	BAND_FREQ_6_GHZ = 0x4,
};

struct band_chandef {
	uint32_t frequency;
	uint32_t channel_width;
	uint32_t center1_frequency;
	uint32_t center2_frequency;
};

struct band_he_capabilities {
	uint32_t iftypes;
	uint8_t he_phy_capa[11];
	uint8_t he_mcs_set[12];
};

struct band_freq_attrs {
	uint8_t tx_power;
	bool supported : 1;
	bool disabled : 1;
	bool no_ir : 1;
	bool no_ht40_plus : 1;
	bool no_ht40_minus : 1;
	bool no_80mhz : 1;
	bool no_160mhz : 1;
	bool no_he : 1;
} __attribute__ ((packed));

struct band {
	enum band_freq freq;
	struct band_freq_attrs *freq_attrs;
	size_t freqs_len;
	/* Each entry is type struct band_he_capabilities */
	struct l_queue *he_capabilities;
	uint8_t vht_mcs_set[8];
	uint8_t vht_capabilities[4];
	bool vht_supported : 1;
	uint8_t ht_mcs_set[16];
	uint8_t ht_capabilities[2];
	uint8_t ht_ampdu_params;
	bool ht_supported : 1;
	uint16_t supported_rates_len;
	uint8_t supported_rates[];
};

void band_free(struct band *band);

bool band_ofdm_rate(uint8_t index, enum ofdm_channel_width width,
			int32_t rssi, uint8_t nss, bool sgi,
			uint64_t *data_rate);
int band_estimate_he_rx_rate(const struct band *band, const uint8_t *hec,
				int32_t rssi, uint64_t *out_dat_rate);
int band_estimate_vht_rx_rate(const struct band *band,
				const uint8_t *vhtc, const uint8_t *vhto,
				const uint8_t *htc, const uint8_t *hto,
				int32_t rssi, uint64_t *out_data_rate);
int band_estimate_ht_rx_rate(const struct band *band,
				const uint8_t *htc, const uint8_t *hto,
				int32_t rssi, uint64_t *out_data_rate);
int band_estimate_nonht_rate(const struct band *band,
				const uint8_t *supported_rates,
				const uint8_t *ext_supported_rates,
				int32_t rssi, uint64_t *out_data_rate);
int band_freq_to_ht_chandef(uint32_t freq, const struct band_freq_attrs *attr,
				struct band_chandef *chandef);

int oci_to_frequency(uint32_t operating_class, uint32_t channel);

int oci_verify(const uint8_t oci[static 3], const struct band_chandef *own);
int oci_from_chandef(const struct band_chandef *own, uint8_t oci[static 3]);

uint8_t band_freq_to_channel(uint32_t freq, enum band_freq *out_band);
uint32_t band_channel_to_freq(uint8_t channel, enum band_freq band);
enum band_freq band_oper_class_to_band(const uint8_t *country,
					uint8_t oper_class);
const char *band_chandef_width_to_string(enum band_chandef_width width);
