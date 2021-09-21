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

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/band/non-HT/test1", band_test_nonht_1, NULL);

	l_test_add("/band/HT/test1", band_test_ht_1, NULL);

	l_test_add("/band/VHT/test1", band_test_vht_1, NULL);

	l_test_add("/band/oci2freq 1", test_oci2freq, &oci2freq_data_1);
	l_test_add("/band/oci2freq 2", test_oci2freq, &oci2freq_data_2);
	l_test_add("/band/oci2freq 3", test_oci2freq, &oci2freq_data_3);
	l_test_add("/band/oci2freq 4", test_oci2freq, &oci2freq_data_4);
	l_test_add("/band/oci2freq 5", test_oci2freq, &oci2freq_data_5);
	l_test_add("/band/oci2freq 6", test_oci2freq, &oci2freq_data_6);
	l_test_add("/band/oci2freq 7", test_oci2freq, &oci2freq_data_7);
	l_test_add("/band/oci2freq 8", test_oci2freq, &oci2freq_data_8);

	return l_test_run();
}
