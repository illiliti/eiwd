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

#include <stdbool.h>
#include <stdint.h>

#include <ell/ell.h>

#include "band.h"

void band_free(struct band *band)
{
	l_free(band);
}

/*
 * Base RSSI values for 20MHz (both HT and VHT) channel. These values can be
 * used to calculate the minimum RSSI values for all other channel widths. HT
 * MCS indexes are grouped into ranges of 8 (per spatial stream) where VHT are
 * grouped in chunks of 10. This just means HT will not use the last two
 * index's of this array.
 */
static const int32_t ht_vht_base_rssi[] = {
	-82, -79, -77, -74, -70, -66, -65, -64, -59, -57
};

/*
 * Data Rate for HT/VHT is obtained according to this formula:
 * Nsd * Nbpscs * R * Nss / (Tdft + Tgi)
 *
 * Where Nsd is [52, 108, 234, 468] for 20/40/80/160 Mhz respectively
 * Nbpscs is [1, 2, 4, 6, 8] for BPSK/QPSK/16QAM/64QAM/256QAM
 * R is [1/2, 2/3, 3/4, 5/6] depending on the MCS index
 * Nss is the number of spatial streams
 * Tdft = 3.2 us
 * Tgi = Long/Short GI of 0.8/0.4 us
 *
 * Short GI rate can be easily obtained by multiplying by (10 / 9)
 *
 * The table was pre-computed using the following python snippet:
 * rfactors = [ 1/2, 1/2, 3/4, 1/2, 3/4, 2/3, 3/4, 5/6, 3/4, 5/6 ]
 * nbpscs = [1, 2, 2, 4, 4, 6, 6, 6, 8, 8 ]
 * nsds = [52, 108, 234, 468]
 *
 * for nsd in nsds:
 * 	rates = []
 * 	for i in xrange(0, 10):
 * 		data_rate = (nsd * rfactors[i] * nbpscs[i]) / 0.004
 * 		rates.append(int(data_rate) * 1000)
 * 	print('rates for nsd: ' + nsd + ': ' + rates)
 */

static const uint64_t ht_vht_rates[4][10] = {
	[OFDM_CHANNEL_WIDTH_20MHZ] = {
		6500000ULL, 13000000ULL, 19500000ULL, 26000000ULL,
		39000000ULL, 52000000ULL, 58500000ULL, 65000000ULL,
		78000000ULL, 86666000ULL },
	[OFDM_CHANNEL_WIDTH_40MHZ] = {
		13500000ULL, 27000000ULL, 40500000ULL, 54000000ULL,
		81000000ULL, 108000000ULL, 121500000ULL, 135000000ULL,
		162000000ULL, 180000000ULL, },
	[OFDM_CHANNEL_WIDTH_80MHZ] = {
		29250000ULL, 58500000ULL, 87750000ULL, 117000000ULL,
		175500000ULL, 234000000ULL, 263250000ULL, 292500000ULL,
		351000000ULL, 390000000ULL, },
	[OFDM_CHANNEL_WIDTH_160MHZ] = {
		58500000ULL, 117000000ULL, 175500000ULL, 234000000ULL,
		351000000ULL, 468000000ULL, 526500000ULL, 585000000ULL,
		702000000ULL, 780000000ULL,
	}
};

/*
 * Both HT and VHT rates are calculated in the same fashion. The only difference
 * is a relative MCS index is used for HT since, for each NSS, the formula
 * is the same with relative index's. This is why this is called with index % 8
 * for HT, but not VHT.
 */
bool band_ofdm_rate(uint8_t index, enum ofdm_channel_width width,
			int32_t rssi, uint8_t nss, bool sgi,
			uint64_t *data_rate)
{
	uint64_t rate;
	int32_t width_adjust = width * 3;

	if (rssi < ht_vht_base_rssi[index] + width_adjust)
		return false;

	rate = ht_vht_rates[width][index];

	if (sgi)
		rate = rate / 9 * 10;

	rate *= nss;

	*data_rate = rate;
	return true;
}
