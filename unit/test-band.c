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
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <ell/ell.h>

#include "src/band.h"
#include "src/netdev.h"
#include "src/ie.h"

static struct band *new_band()
{
	/* Band with VHT/80, short GI, NSS:2 and VHT MCS 0-9 */
	static const uint8_t vht_mcs_set[] = {
		0xfa, 0xff, 0x00, 0x00, 0xfa, 0xff, 0x00, 0x20,
	};
	static const uint8_t vht_capabilities[] = {
		0xa0, 0x71, 0x80, 0x03,
	};
	static const uint8_t ht_mcs_set[] = {
		0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x2c, 0x01, 0x01, 0x00, 0x00, 0x00,
	};
	static const uint8_t ht_capabilities[] = {
		0xee, 0x11,
	};
	/* band + 8 basic rates */
	struct band *band = l_malloc(sizeof(struct band) + 8);

	memset(band, 0, sizeof(struct band) + 8);

	band->supported_rates_len = 8;
	band->supported_rates[0] = 12;
	band->supported_rates[1] = 18;
	band->supported_rates[2] = 24;
	band->supported_rates[3] = 36;
	band->supported_rates[4] = 48;
	band->supported_rates[5] = 72;
	band->supported_rates[6] = 96;
	band->supported_rates[7] = 108;

	band->ht_supported = true;
	band->vht_supported = true;

	memcpy(band->vht_mcs_set, vht_mcs_set, sizeof(band->vht_mcs_set));
	memcpy(band->vht_capabilities, vht_capabilities,
					sizeof(band->vht_capabilities));
	memcpy(band->ht_mcs_set, ht_mcs_set, sizeof(band->ht_mcs_set));
	memcpy(band->ht_capabilities, ht_capabilities,
					sizeof(band->ht_capabilities));

	return band;
}

static void band_test_nonht_1(const void *data)
{
	uint8_t supported_rates[] = { 1, 8,
			0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c };
	struct band *band = new_band();
	uint64_t data_rate;
	int ret;

	ret = band_estimate_nonht_rate(band, supported_rates, NULL,
							-50, &data_rate);
	assert(ret == 0);
	assert(data_rate == 54000000);

	ret = band_estimate_nonht_rate(band, supported_rates, NULL,
							-66, &data_rate);
	assert(ret == 0);
	assert(data_rate == 48000000);

	ret = band_estimate_nonht_rate(band, supported_rates, NULL,
							-70, &data_rate);
	assert(ret == 0);
	assert(data_rate == 36000000);

	ret = band_estimate_nonht_rate(band, supported_rates, NULL,
							-74, &data_rate);
	assert(ret == 0);
	assert(data_rate == 24000000);

	ret = band_estimate_nonht_rate(band, supported_rates, NULL,
							-77, &data_rate);
	assert(ret == 0);
	assert(data_rate == 18000000);

	ret = band_estimate_nonht_rate(band, supported_rates, NULL,
							-79, &data_rate);
	assert(ret == 0);
	assert(data_rate == 12000000);

	ret = band_estimate_nonht_rate(band, supported_rates, NULL,
							-81, &data_rate);
	assert(ret == 0);
	assert(data_rate == 9000000);

	ret = band_estimate_nonht_rate(band, supported_rates, NULL,
							-82, &data_rate);
	assert(ret == 0);
	assert(data_rate == 6000000);

	ret = band_estimate_nonht_rate(band, supported_rates, NULL,
							-83, &data_rate);
	assert(ret < 0);

	band_free(band);
}

static void band_test_ht_1(const void *data)
{
	/* HT40 */
	uint8_t hto[] = { 61, 22,
				0x95, 0x0d, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	/* HT40, MCS 0-23, 40/20Mhz SGI */
	uint8_t htc[] = { 45, 26,
				0xef, 0x09, 0x17, 0xff, 0xff, 0xff, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00 };
	struct band *band = new_band();
	uint64_t data_rate;
	int ret;

	ret = band_estimate_ht_rx_rate(band, htc, hto, -51, &data_rate);
	assert(ret == 0);
	assert(data_rate == 300000000);

	ret = band_estimate_ht_rx_rate(band, htc, hto, -62, &data_rate);
	assert(ret == 0);
	assert(data_rate == 270000000);

	ret = band_estimate_ht_rx_rate(band, htc, hto, -63, &data_rate);
	assert(ret == 0);
	assert(data_rate == 240000000);

	ret = band_estimate_ht_rx_rate(band, htc, hto, -66, &data_rate);
	assert(ret == 0);
	assert(data_rate == 180000000);

	ret = band_estimate_ht_rx_rate(band, htc, hto, -71, &data_rate);
	assert(ret == 0);
	assert(data_rate == 120000000);

	ret = band_estimate_ht_rx_rate(band, htc, hto, -74, &data_rate);
	assert(ret == 0);
	assert(data_rate == 90000000);

	ret = band_estimate_ht_rx_rate(band, htc, hto, -76, &data_rate);
	assert(ret == 0);
	assert(data_rate == 60000000);

	ret = band_estimate_ht_rx_rate(band, htc, hto, -79, &data_rate);
	assert(ret == 0);
	assert(data_rate == 30000000);

	/* We should now fall back to HT20 */
	ret = band_estimate_ht_rx_rate(band, htc, hto, -82, &data_rate);
	assert(ret == 0);
	assert(data_rate == 14444440);

	ret = band_estimate_ht_rx_rate(band, htc, hto, -83, &data_rate);
	assert(ret < 0);

	band_free(band);
}

static void band_test_vht_1(const void *data)
{
	/* VHT operating on 80 Mhz */
	uint8_t vhto[] = { 192, 5, 0x01, 0x9b, 0x00, 0x00, 0x00 };
	/* VHT80, NSS:3, MCS 0-9, 80Mhz SGI */
	uint8_t vhtc[] = { 191, 12,
				0xb2, 0x59, 0x82, 0x0f, 0xea, 0xff, 0x00, 0x00,
				0xea, 0xff, 0x00, 0x00 };
	/* HT40 */
	uint8_t hto[] = { 61, 22,
				0x95, 0x0d, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	/* HT40, MCS 0-23, 40/20Mhz SGI */
	uint8_t htc[] = { 45, 26,
				0xef, 0x09, 0x17, 0xff, 0xff, 0xff, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00 };
	struct band *band = new_band();
	uint64_t data_rate;
	int ret;

	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-51, &data_rate);
	assert(ret == 0);
	assert(data_rate == 866666660);

	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-53, &data_rate);
	assert(ret == 0);
	assert(data_rate == 780000000);

	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-56, &data_rate);
	assert(ret == 0);
	assert(data_rate == 650000000);

	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-59, &data_rate);
	assert(ret == 0);
	assert(data_rate == 585000000);

	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-60, &data_rate);
	assert(ret == 0);
	assert(data_rate == 520000000);

	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-63, &data_rate);
	assert(ret == 0);
	assert(data_rate == 390000000);

	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-67, &data_rate);
	assert(ret == 0);
	assert(data_rate == 260000000);

	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-70, &data_rate);
	assert(ret == 0);
	assert(data_rate == 195000000);

	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-73, &data_rate);
	assert(ret == 0);
	assert(data_rate == 130000000);

	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-76, &data_rate);
	assert(ret == 0);
	assert(data_rate == 65000000);

	/* We should now fall back to HT40 */
	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-79, &data_rate);
	assert(ret == 0);
	assert(data_rate == 30000000);

	/* And only enough for HT20 */
	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-82, &data_rate);
	assert(ret == 0);
	assert(data_rate == 14444440);

	ret = band_estimate_vht_rx_rate(band, vhtc, vhto, htc, hto,
					-83, &data_rate);
	assert(ret < 0);

	band_free(band);
}

struct he_test_data {
	enum band_freq freq;
	int32_t rssi;
	uint64_t expected_rate;
	int expected_return;
	/* Own capabilities */
	struct band_he_capabilities capabilities;
	/* Peer HE Capabilities IE */
	uint8_t he_capabilities[31];

};

/* IWD doesn't look at this */
#define HE_MAC_CAPA 0, 0, 0, 0, 0, 0
/* IWD only cares about the width set byte */
#define HE_PHY_CAPA(wset) wset, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

#define MCS7		0
#define MCS9		1
#define MCS11		2
#define MCS_UNSUP	0xff, 0xff
/* A readable macro for defining MCS sets */
#define HE_MCS_SET(mcs, nss) \
	(nss >= 1 ? mcs << 0 : 3 << 0) | \
	(nss >= 2 ? mcs << 2 : 3 << 2) | \
	(nss >= 3 ? mcs << 4 : 3 << 4) | \
	(nss >= 4 ? mcs << 6 : 3 << 6),  \
	(nss >= 5 ? mcs << 0 : 3 << 0) | \
	(nss >= 6 ? mcs << 2 : 3 << 2) | \
	(nss >= 7 ? mcs << 4 : 3 << 4) | \
	(nss >= 8 ? mcs << 6 : 3 << 6)

/* 2.4GHz, 20MHz, MCS 7, NSS 1 */
const struct he_test_data he_test_2_4_20mhz_mcs_7_nss_1 = {
	.freq = BAND_FREQ_2_4_GHZ,
	.rssi = -20,
	.expected_rate = 86000000ULL,
	.capabilities = {
		.he_mcs_set = { HE_MCS_SET(MCS7, 1), MCS_UNSUP },
		.he_phy_capa = { HE_PHY_CAPA(0x00) },
		.iftypes = 1 << NETDEV_IFTYPE_STATION,
	},
	.he_capabilities = {
		22, IE_TYPE_HE_CAPABILITIES - 256, HE_MAC_CAPA,
		HE_PHY_CAPA(0x00), MCS_UNSUP, HE_MCS_SET(MCS7, 1),
	},
};

/* 2.4GHz, 40MHz, MCS 7, NSS 1 */
const struct he_test_data he_test_2_4_40mhz_mcs_7_nss_1 = {
	.freq = BAND_FREQ_2_4_GHZ,
	.rssi = -20,
	.expected_rate = 172000000ULL,
	.capabilities = {
		.he_mcs_set = { HE_MCS_SET(MCS7, 1), MCS_UNSUP },
		.he_phy_capa = { HE_PHY_CAPA(0x02) },
		.iftypes = 1 << NETDEV_IFTYPE_STATION,
	},
	.he_capabilities = {
		22, IE_TYPE_HE_CAPABILITIES - 256, HE_MAC_CAPA,
		HE_PHY_CAPA(0x02), MCS_UNSUP, HE_MCS_SET(MCS7, 1),
	},
};

/* 5GHz, 20MHz, MCS 7, NSS 1 */
const struct he_test_data he_test_5_20mhz_mcs_7_nss_1 = {
	.freq = BAND_FREQ_5_GHZ,
	.rssi = -20,
	.expected_rate = 86000000ULL,
	.capabilities = {
		.he_mcs_set = { HE_MCS_SET(MCS7, 1), MCS_UNSUP },
		.he_phy_capa = { HE_PHY_CAPA(0x00) },
		.iftypes = 1 << NETDEV_IFTYPE_STATION,
	},
	.he_capabilities = {
		22, IE_TYPE_HE_CAPABILITIES - 256, HE_MAC_CAPA,
		HE_PHY_CAPA(0x00), MCS_UNSUP, HE_MCS_SET(MCS7, 1)
	},
};

/* 5GHz, 80MHz, MCS 7, NSS 1 */
const struct he_test_data he_test_5_80mhz_mcs_7_nss_1 = {
	.freq = BAND_FREQ_5_GHZ,
	.rssi = -20,
	.expected_rate = 360300000ULL,
	.capabilities = {
		.he_mcs_set = { HE_MCS_SET(MCS7, 1), MCS_UNSUP },
		.he_phy_capa = { HE_PHY_CAPA(0x04) },
		.iftypes = 1 << NETDEV_IFTYPE_STATION,
	},
	.he_capabilities = {
		22, IE_TYPE_HE_CAPABILITIES - 256, HE_MAC_CAPA,
		HE_PHY_CAPA(0x04), MCS_UNSUP, HE_MCS_SET(MCS7, 1)
	},
};

/* 5GHz, 160MHz, MCS 7, NSS 1 */
const struct he_test_data he_test_5_160mhz_mcs_7_nss_1 = {
	.freq = BAND_FREQ_5_GHZ,
	.rssi = -20,
	.expected_rate = 720600000ULL,
	.capabilities = {
		.he_mcs_set = { HE_MCS_SET(MCS7, 1), MCS_UNSUP,
				HE_MCS_SET(MCS7, 1), MCS_UNSUP },
		.he_phy_capa = { HE_PHY_CAPA(0x0c) },
		.iftypes = 1 << NETDEV_IFTYPE_STATION,
	},
	.he_capabilities = {
		26, IE_TYPE_HE_CAPABILITIES - 256, HE_MAC_CAPA,
		HE_PHY_CAPA(0x0c), MCS_UNSUP, HE_MCS_SET(MCS7, 1),
				MCS_UNSUP, HE_MCS_SET(MCS7, 1)
	},
};

/* 5GHz, 160/80+80MHz, MCS 7, NSS 1 */
const struct he_test_data he_test_5_160_80_P_80_mhz_mcs_7_nss_1 = {
	.freq = BAND_FREQ_5_GHZ,
	.rssi = -20,
	.expected_rate = 720600000ULL,
	.capabilities = {
		.he_mcs_set = { HE_MCS_SET(MCS7, 1), MCS_UNSUP,
				HE_MCS_SET(MCS7, 1), MCS_UNSUP,
				HE_MCS_SET(MCS7, 1), MCS_UNSUP },
		.he_phy_capa = { HE_PHY_CAPA(0x1c) },
		.iftypes = 1 << NETDEV_IFTYPE_STATION,
	},
	.he_capabilities = {
		30, IE_TYPE_HE_CAPABILITIES - 256, HE_MAC_CAPA,
		HE_PHY_CAPA(0x1c), MCS_UNSUP, HE_MCS_SET(MCS7, 1),
				MCS_UNSUP, HE_MCS_SET(MCS7, 1),
				MCS_UNSUP, HE_MCS_SET(MCS7, 1)
	},
};

/* 5GHz, max data rate */
const struct he_test_data he_test_5_max_data_rate = {
	.freq = BAND_FREQ_5_GHZ,
	.rssi = -20,
	.expected_rate = 1201000000ULL * 8ULL,
	.capabilities = {
		.he_mcs_set = { HE_MCS_SET(MCS11, 8), MCS_UNSUP,
				HE_MCS_SET(MCS11, 8), MCS_UNSUP,
				HE_MCS_SET(MCS11, 8), MCS_UNSUP },
		.he_phy_capa = { HE_PHY_CAPA(0x1c) },
		.iftypes = 1 << NETDEV_IFTYPE_STATION,
	},
	.he_capabilities = {
		30, IE_TYPE_HE_CAPABILITIES - 256, HE_MAC_CAPA,
		HE_PHY_CAPA(0x1c), MCS_UNSUP, HE_MCS_SET(MCS11, 8),
				MCS_UNSUP, HE_MCS_SET(MCS11, 8),
				MCS_UNSUP, HE_MCS_SET(MCS11, 8)
	},
};

const struct he_test_data he_all_mcs_unsupported = {
	.freq = BAND_FREQ_5_GHZ,
	.rssi = -20,
	.expected_rate = 1201000000ULL * 8ULL,
	.expected_return = -EBADMSG,
	.capabilities = {
		.he_mcs_set = { MCS_UNSUP, MCS_UNSUP,
				MCS_UNSUP, MCS_UNSUP,
				MCS_UNSUP, MCS_UNSUP },
		.he_phy_capa = { HE_PHY_CAPA(0x1c) },
		.iftypes = 1 << NETDEV_IFTYPE_STATION,
	},
	.he_capabilities = {
		30, IE_TYPE_HE_CAPABILITIES - 256, HE_MAC_CAPA,
		HE_PHY_CAPA(0x1c), MCS_UNSUP, MCS_UNSUP,
				MCS_UNSUP, MCS_UNSUP,
				MCS_UNSUP, MCS_UNSUP
	},
};

/* 5GHz, max data rate, low-rssi */
const struct he_test_data he_test_5_low_rssi = {
	.freq = BAND_FREQ_5_GHZ,
	.rssi = -80, /* Should force 20MHz/MCS0 width to be used */
	.expected_rate = 8600000ULL * 8ULL,
	.capabilities = {
		.he_mcs_set = { HE_MCS_SET(MCS11, 8), MCS_UNSUP,
				HE_MCS_SET(MCS11, 8), MCS_UNSUP,
				HE_MCS_SET(MCS11, 8), MCS_UNSUP },
		.he_phy_capa = { HE_PHY_CAPA(0x1c) },
		.iftypes = 1 << NETDEV_IFTYPE_STATION,
	},
	.he_capabilities = {
		30, IE_TYPE_HE_CAPABILITIES - 256, HE_MAC_CAPA,
		HE_PHY_CAPA(0x1c), MCS_UNSUP, HE_MCS_SET(MCS11, 8),
				MCS_UNSUP, HE_MCS_SET(MCS11, 8),
				MCS_UNSUP, HE_MCS_SET(MCS11, 8)
	},
};

static void band_test_he(const void *data)
{
	const struct he_test_data *he_data = data;
	struct band *band;
	uint64_t rate = 0;
	int ret;

	band = new_band();
	band->freq = he_data->freq;
	band->he_capabilities = l_queue_new();

	l_queue_push_tail(band->he_capabilities,
				(void*)&(he_data->capabilities));

	assert(ie_validate_he_capabilities(he_data->he_capabilities + 2,
					he_data->he_capabilities[0]));

	ret = band_estimate_he_rx_rate(band, he_data->he_capabilities + 2,
					he_data->rssi, &rate);
	assert(ret == he_data->expected_return);

	if (ret == 0)
		assert(rate == he_data->expected_rate);

	l_queue_destroy(band->he_capabilities, NULL);
	l_free(band);
}

struct oci2freq_data {
	unsigned int op;
	unsigned int chan;
	int expected_freq;
};

static const struct oci2freq_data oci2freq_data_1 = { 129, 100, 5500 };
static const struct oci2freq_data oci2freq_data_2 = { 129, 108, 5540 };
static const struct oci2freq_data oci2freq_data_3 = { 129, 106, -EINVAL };
static const struct oci2freq_data oci2freq_data_4 = { 81, 1, 2412 };
static const struct oci2freq_data oci2freq_data_5 = { 82, 1, -EINVAL };
static const struct oci2freq_data oci2freq_data_6 = { 82, 14, 2484 };
static const struct oci2freq_data oci2freq_data_7 = { 88, 0, -ENOENT };
static const struct oci2freq_data oci2freq_data_8 = { 128, 161, 5805 };

static void test_oci2freq(const void *data)
{
	const struct oci2freq_data *test = data;
	int r;

	r = oci_to_frequency(test->op, test->chan);
	assert(r == test->expected_freq);
}

static const struct band_chandef cd_1 = {
	.frequency = 5540,
	.channel_width = BAND_CHANDEF_WIDTH_160,
	.center1_frequency = 5570,
};

static const struct band_chandef cd_2 = {
	.frequency = 5180,
	.channel_width = BAND_CHANDEF_WIDTH_80P80,
	.center1_frequency = 5210,
	.center2_frequency = 5775,
};

static const struct band_chandef cd_3 = {
	.frequency = 2437,
	.channel_width = BAND_CHANDEF_WIDTH_20NOHT,
	.center1_frequency = 2437,
};

static const struct band_chandef cd_4 = {
	.frequency = 2437,
	.channel_width = BAND_CHANDEF_WIDTH_40,
	.center1_frequency = 2427,
};

static const struct band_chandef cd_5 = {
	.frequency = 6235,
	.channel_width = BAND_CHANDEF_WIDTH_20,
};

static const struct band_chandef cd_6 = {
	.frequency = 6235,
	.channel_width =  BAND_CHANDEF_WIDTH_40,
};

static const struct band_chandef cd_7 = {
	.frequency = 6235,
	.channel_width =  BAND_CHANDEF_WIDTH_80,
};

static const struct band_chandef cd_8 = {
	.frequency = 6235,
	.channel_width =  BAND_CHANDEF_WIDTH_160,
};

static const struct band_chandef cd_9 = {
	.frequency = 6235,
	.channel_width =  BAND_CHANDEF_WIDTH_80P80,
	.center1_frequency = 6145,
	.center2_frequency = 6225,
};

struct oci_data {
	const struct band_chandef *cd;
	uint8_t oci[3];
	int expected_verify_error;
};

static const struct oci_data oci_data_1 = { &cd_1, { 129, 108, 0 } };
static const struct oci_data oci_data_2 = { &cd_2, { 130, 36, 155 } };
static const struct oci_data oci_data_3 = { &cd_3, { 81, 6, 0 } };
static const struct oci_data oci_data_4 = { &cd_4, { 84, 6, 0 } };
static const struct oci_data oci_data_5 = { &cd_5, { 131, 57, 0 } };
static const struct oci_data oci_data_6 = { &cd_6, { 132, 57, 0 } };
static const struct oci_data oci_data_7 = { &cd_7, { 133, 57, 0 } };
static const struct oci_data oci_data_8 = { &cd_8, { 134, 57, 0 } };
static const struct oci_data oci_data_9 = { &cd_9, { 135, 57, 55 } };

static const struct oci_data oci_err_1 = { &cd_1, { 129, 36, 0 }, -EPERM };
static const struct oci_data oci_err_2 = { &cd_1, { 121, 108, 0 }, -EPERM };
static const struct oci_data oci_err_3 = { &cd_1, { 130, 36, 155 }, -EPERM };
static const struct oci_data oci_err_4 = { &cd_3, { 81, 5 }, -EPERM };
static const struct oci_data oci_err_5 = { &cd_3, { 80, 1 }, -ENOENT };
static const struct oci_data oci_err_6 = { &cd_3, { 81, 15 }, -EINVAL };
static const struct oci_data oci_err_7 = { &cd_4, { 84, 5 }, -EPERM };
static const struct oci_data oci_err_8 = { &cd_4, { 83, 6 }, -EPERM };

static void test_oci_verify(const void *data)
{
	const struct oci_data *test = data;
	int r;

	r = oci_verify(test->oci, test->cd);
	assert(r == test->expected_verify_error);
}

static void test_oci_from_chandef(const void *data)
{
	const struct oci_data *test = data;
	uint8_t oci[3];
	int r;

	r = oci_from_chandef(test->cd, oci);
	assert(!r);

	assert(!memcmp(oci, test->oci, sizeof(oci)));
}

static void test_6ghz_channels(const void *data)
{
	unsigned int i;

	/* Test all channels for 6GHz */
	for (i = 1; i <= 233; i += 4)
		assert(band_channel_to_freq(i, BAND_FREQ_6_GHZ) != 0);
}

static void test_6ghz_freqs(const void *data)
{
	uint32_t i;
	enum band_freq band;

	for (i = 5955; i <= 7115; i += 20) {
		assert(band_freq_to_channel(i, &band) != 0);
		assert(band == BAND_FREQ_6_GHZ);
	}
}

static void test_conversions(const void *data)
{
	/*
	 * Test a few invalid channels/frequencies that appear valid but are
	 * not in the E-4 table. The checks in band.c seem to cover 2.4GHz and
	 * 6GHz very well since there are no gaps, but the 5GHz band has some
	 * segmentation.
	 */

	/* Gap in 5GHz channels between 68 and 96 */
	assert(!band_channel_to_freq(72, BAND_FREQ_5_GHZ));
	assert(!band_freq_to_channel(5360, NULL));

	/* Invalid channel using 4000mhz starting frequency */
	assert(!band_channel_to_freq(183, BAND_FREQ_5_GHZ));
	assert(!band_freq_to_channel(4915, NULL));

	assert(!band_channel_to_freq(192, BAND_FREQ_5_GHZ));
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/band/non-HT/test1", band_test_nonht_1, NULL);

	l_test_add("/band/HT/test1", band_test_ht_1, NULL);

	l_test_add("/band/VHT/test1", band_test_vht_1, NULL);

	l_test_add("/band/HE/test/2.4GHz/20MHz/MCS7/NSS1", band_test_he,
					&he_test_2_4_20mhz_mcs_7_nss_1);
	l_test_add("/band/HE/test/2.4GHz/40MHz/MCS7/NSS1", band_test_he,
					&he_test_2_4_40mhz_mcs_7_nss_1);
	l_test_add("/band/HE/test/5GHz/20MHz/MCS7/NSS1", band_test_he,
					&he_test_5_20mhz_mcs_7_nss_1);
	l_test_add("/band/HE/test/5GHz/80MHz/MCS7/NSS1", band_test_he,
					&he_test_5_80mhz_mcs_7_nss_1);
	l_test_add("/band/HE/test/5GHz/160MHz/MCS7/NSS1", band_test_he,
					&he_test_5_160mhz_mcs_7_nss_1);
	l_test_add("/band/HE/test/5GHz/160/80+80MHz/MCS7/NSS1", band_test_he,
					&he_test_5_160_80_P_80_mhz_mcs_7_nss_1);
	l_test_add("/band/HE/test/5GHz/max data rate", band_test_he,
					&he_test_5_max_data_rate);
	l_test_add("/band/HE/test/all MCS unsupported", band_test_he,
					&he_all_mcs_unsupported);
	l_test_add("/band/HE/test/low RSSI", band_test_he,
					&he_test_5_low_rssi);

	l_test_add("/band/oci2freq 1", test_oci2freq, &oci2freq_data_1);
	l_test_add("/band/oci2freq 2", test_oci2freq, &oci2freq_data_2);
	l_test_add("/band/oci2freq 3", test_oci2freq, &oci2freq_data_3);
	l_test_add("/band/oci2freq 4", test_oci2freq, &oci2freq_data_4);
	l_test_add("/band/oci2freq 5", test_oci2freq, &oci2freq_data_5);
	l_test_add("/band/oci2freq 6", test_oci2freq, &oci2freq_data_6);
	l_test_add("/band/oci2freq 7", test_oci2freq, &oci2freq_data_7);
	l_test_add("/band/oci2freq 8", test_oci2freq, &oci2freq_data_8);

	l_test_add("/band/oci/verify 1", test_oci_verify, &oci_data_1);
	l_test_add("/band/oci/verify 2", test_oci_verify, &oci_data_2);
	l_test_add("/band/oci/verify 3", test_oci_verify, &oci_data_3);
	l_test_add("/band/oci/verify 4", test_oci_verify, &oci_data_4);
	l_test_add("/band/oci/verify 5", test_oci_verify, &oci_data_5);
	l_test_add("/band/oci/verify 6", test_oci_verify, &oci_data_6);
	l_test_add("/band/oci/verify 7", test_oci_verify, &oci_data_7);
	l_test_add("/band/oci/verify 8", test_oci_verify, &oci_data_8);
	l_test_add("/band/oci/verify 9", test_oci_verify, &oci_data_9);

	l_test_add("/band/oci/noverify 1", test_oci_verify, &oci_err_1);
	l_test_add("/band/oci/noverify 2", test_oci_verify, &oci_err_2);
	l_test_add("/band/oci/noverify 3", test_oci_verify, &oci_err_3);
	l_test_add("/band/oci/noverify 4", test_oci_verify, &oci_err_4);
	l_test_add("/band/oci/noverify 5", test_oci_verify, &oci_err_5);
	l_test_add("/band/oci/noverify 6", test_oci_verify, &oci_err_6);
	l_test_add("/band/oci/noverify 7", test_oci_verify, &oci_err_7);
	l_test_add("/band/oci/noverify 8", test_oci_verify, &oci_err_8);

	l_test_add("/band/oci/chandef 1", test_oci_from_chandef, &oci_data_1);
	l_test_add("/band/oci/chandef 2", test_oci_from_chandef, &oci_data_2);
	l_test_add("/band/oci/chandef 3", test_oci_from_chandef, &oci_data_3);
	l_test_add("/band/oci/chandef 4", test_oci_from_chandef, &oci_data_4);

	l_test_add("/band/6ghz/channels", test_6ghz_channels, NULL);
	l_test_add("/band/6ghz/freq", test_6ghz_freqs, NULL);

	l_test_add("/band/conversions", test_conversions, NULL);

	return l_test_run();
}
