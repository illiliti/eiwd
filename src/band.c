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
#include <errno.h>

#include <ell/ell.h>

#include "ell/useful.h"

#include "src/band.h"
#include "src/netdev.h"

void band_free(struct band *band)
{
	if (band->he_capabilities)
		l_queue_destroy(band->he_capabilities, l_free);

	l_free(band->freq_attrs);

	l_free(band);
}

/*
 * Rates are stored as they are encoded in the Supported Rates IE.
 * This data was taken from 802.11 Section 17.3.10.2 Table 17-18 and
 * Table 17-4. Together we have minimum RSSI required for a given data rate.
 */
static const struct {
	int32_t rssi;
	uint8_t rate;
} rate_rssi_map[] = {
	{ -90, 2 },  /* Make something up for 11b rates */
	{ -88, 4 },
	{ -86, 11 },
	{ -84, 22 },
	{ -82, 12 },
	{ -81, 18 },
	{ -79, 24 },
	{ -77, 36 },
	{ -74, 48 },
	{ -70, 72 },
	{ -66, 96 },
	{ -65, 108 },
};

static bool peer_supports_rate(const uint8_t *rates, uint8_t rate)
{
	int i;

	if (rates && rates[1]) {
		for (i = 0; i < rates[1]; i++) {
			uint8_t r = rates[i + 2] & 0x7f;

			if (r == rate)
				return true;
		}
	}

	return false;
}

int band_estimate_nonht_rate(const struct band *band,
				const uint8_t *supported_rates,
				const uint8_t *ext_supported_rates,
				int32_t rssi, uint64_t *out_data_rate)
{
	int nrates = L_ARRAY_SIZE(rate_rssi_map);
	uint8_t max_rate = 0;
	int i;

	if (!supported_rates && !ext_supported_rates)
		return -EINVAL;

	/*
	 * Start at the back of the array.  Rates are generally given in
	 * ascending order, starting at 11b rates, then 11g rates.  More often
	 * than not we'll pick the highest rate and avoid unneeded processing
	 */
	for (i = band->supported_rates_len - 1; i >= 0; i--) {
		uint8_t rate = band->supported_rates[i];
		int j;

		if (max_rate >= rate)
			continue;

		/* Can this rate be used at the peer's RSSI? */
		for (j = 0; j < nrates; j++)
			if (rate_rssi_map[j].rate == rate)
				break;

		if (j == nrates)
			continue;

		if (rssi < rate_rssi_map[j].rssi)
			continue;

		if (peer_supports_rate(supported_rates, rate) ||
				peer_supports_rate(ext_supported_rates, rate))
			max_rate = rate;
	}

	if (!max_rate)
		return -ENETUNREACH;

	*out_data_rate = max_rate * 500000;
	return 0;
}

/*
 * Base RSSI values for 20MHz (HT, VHT and HE) channel. These values can be
 * used to calculate the minimum RSSI values for all other channel widths. HT
 * MCS indexes are grouped into ranges of 8 (per spatial stream), VHT in groups
 * of 10 and HE in groups of 12. This just means HT will not use the last four
 * index's of this array, and VHT won't use the last two.
 *
 * Note: The values here are not based on anything from 802.11 but data
 *       found elsewhere online (presumably from testing, we hope). The two
 *       indexes for HE (MCS 11/12) are not based on any data, but just
 *       increased by 3dB compared to the previous value. We consider this good
 *       enough for its purpose to estimate the date rate for network/BSS
 *       preference.
 */
static const int32_t ht_vht_he_base_rssi[] = {
	-82, -79, -77, -74, -70, -66, -65, -64, -59, -57, -54, -51
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
 *	rates = []
 *	for i in xrange(0, 10):
 *		data_rate = (nsd * rfactors[i] * nbpscs[i]) / 0.004
 *		rates.append(int(data_rate) * 1000)
 *	print('rates for nsd: ' + nsd + ': ' + rates)
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

	if (rssi < ht_vht_he_base_rssi[index] + width_adjust)
		return false;

	rate = ht_vht_rates[width][index];

	if (sgi)
		rate = rate / 9 * 10;

	rate *= nss;

	*data_rate = rate;
	return true;
}

static bool find_best_mcs_ht(const struct band *band,
				const uint8_t *tx_mcs_set,
				uint8_t max_mcs, enum ofdm_channel_width width,
				int32_t rssi, bool sgi,
				uint64_t *out_data_rate)
{
	int i;

	/*
	 * TODO: Support MCS values 32 - 76
	 *
	 * The MCS values > 31 use an unequal modulation, and the number of
	 * supported MCS indexes per NSS differs.  We do not consider them
	 * here for now to keep things simple(r).
	 */
	for (i = max_mcs; i >= 0; i--) {
		if (!test_bit(band->ht_mcs_set, i))
			continue;

		if (!test_bit(tx_mcs_set, i))
			continue;

		if (band_ofdm_rate(i % 8, width, rssi,
					(i / 8) + 1, sgi, out_data_rate))
			return true;
	}

	return false;
}

int band_estimate_ht_rx_rate(const struct band *band,
				const uint8_t *htc, const uint8_t *hto,
				int32_t rssi, uint64_t *out_data_rate)
{
	uint8_t channel_offset;
	int max_mcs = 31;
	bool sgi;
	uint8_t unequal_tx_mcs_set[16];
	const uint8_t *tx_mcs_set;

	if (!band->ht_supported)
		return -ENOTSUP;

	if (!htc || !hto)
		return -ENOTSUP;

	memset(unequal_tx_mcs_set, 0, sizeof(unequal_tx_mcs_set));

	tx_mcs_set = htc + 5;

	/*
	 * Check 'Tx MCS Set Defined' at bit 96 and 'Tx MCS Set Unequal' at
	 * bit 97 of the Supported MCS Set field.  Also extract 'Tx Maximum
	 * Number of Spatial Streams Supported' field at bits 98 and 99.
	 *
	 * Note 44 on page 1662 of 802.11-2016 states:
	 * "How a non-AP STA determines an AP's HT MCS transmission support,
	 * if the Tx MCS Set subfield in the HT Capabilities element
	 * advertised by the AP is equal to 0 or if he Tx Rx MCS Set Not Equal
	 * subfield in that element is equal to 1, is implementation dependent.
	 * The non-AP STA might conservatively use the basic HT-MCS set, or it
	 * might use knowledge of past transmissions by the AP, or it might
	 * use other means.
	 */
	if (test_bit(tx_mcs_set, 96)) {
		if (test_bit(tx_mcs_set, 97)) {
			uint8_t max_nss = bit_field(tx_mcs_set[12], 2, 2);

			max_mcs = max_nss * 4 + 7;

			/*
			 * For purposes of finding the best MCS below, assume
			 * the AP can send any MCS up to max_nss (i.e 0-7 for
			 * 1 nss, 0-15 for 2 nss, 0-23 for 3 nss, 0-31 for 4
			 */
			memset(unequal_tx_mcs_set, 0xff, max_nss + 1);
			tx_mcs_set = unequal_tx_mcs_set;
		}
	} else
		max_mcs = 7;

	/* Test for 40 Mhz operation */
	channel_offset = bit_field(hto[3], 0, 2);
	if (test_bit(hto + 3, 2) &&
			(channel_offset == 1 || channel_offset == 3)) {
		sgi = test_bit(band->ht_capabilities, 6) &&
						test_bit(htc + 2, 6);

		if (find_best_mcs_ht(band, tx_mcs_set, max_mcs,
					OFDM_CHANNEL_WIDTH_40MHZ,
					rssi, sgi, out_data_rate))
			return 0;
	}

	sgi = test_bit(band->ht_capabilities, 5) && test_bit(htc + 2, 5);

	if (find_best_mcs_ht(band, tx_mcs_set, max_mcs,
				OFDM_CHANNEL_WIDTH_20MHZ,
				rssi, sgi, out_data_rate))
		return 0;

	return -ENETUNREACH;
}

static bool find_best_mcs_vht(uint8_t max_index, enum ofdm_channel_width width,
				int32_t rssi, uint8_t nss, bool sgi,
				uint64_t *out_data_rate)
{
	int i;

	/*
	 * Iterate over all available MCS indexes to find the best one
	 * we can use.  Note that band_ofdm_rate() will return false if a
	 * given combination cannot be used due to rssi being too low.
	 *
	 * Also, Certain MCS/Width/NSS combinations are not valid,
	 * refer to IEEE 802.11-2016 Section 21.5 for more details
	 */

	for (i = max_index; i >= 0; i--)
		if (band_ofdm_rate(i, width, rssi, nss, sgi, out_data_rate))
			return true;

	return false;
}

static bool find_best_mcs_nss(const uint8_t *rx_map, const uint8_t *tx_map,
				uint8_t value0, uint8_t value1, uint8_t value2,
				uint32_t *mcs_out, uint32_t *nss_out)
{
	uint32_t nss = 0;
	uint32_t max_mcs = 0;
	int bitoffset;

	for (bitoffset = 14; bitoffset >= 0; bitoffset -= 2) {
		uint8_t rx_val = bit_field(rx_map[bitoffset / 8],
							bitoffset % 8, 2);
		uint8_t tx_val = bit_field(tx_map[bitoffset / 8],
							bitoffset % 8, 2);

		/*
		 * 0 indicates support for MCS 0 - value0
		 * 1 indicates support for MCS 0 - value1
		 * 2 indicates support for MCS 0 - value2
		 * 3 indicates no support
		 */

		if (rx_val == 3 || tx_val == 3)
			continue;

		/* rx_val/tx_val tells us which value# to use */
		max_mcs = minsize(rx_val, tx_val);
		switch (max_mcs) {
		case 0:
			max_mcs = value0;
			break;
		case 1:
			max_mcs = value1;
			break;
		case 2:
			max_mcs = value2;
			break;
		}

		nss = bitoffset / 2 + 1;
		break;
	}

	if (!nss)
		return false;

	*nss_out = nss;
	*mcs_out = max_mcs;

	return true;
}
/*
 * IEEE 802.11 - Table 9-250
 *
 * For simplicity, we are ignoring the Extended BSS BW support, per NOTE 11:
 *
 * NOTE 11-A receiving STA in which dot11VHTExtendedNSSCapable is false will
 * ignore the Extended NSS BW Support subfield and effectively evaluate this
 * table only at the entries where Extended NSS BW Support is 0.
 *
 * This also allows us to group the 160/80+80 widths together, since they are
 * the same when Extended NSS BW is zero.
 */
int band_estimate_vht_rx_rate(const struct band *band,
				const uint8_t *vhtc, const uint8_t *vhto,
				const uint8_t *htc, const uint8_t *hto,
				int32_t rssi, uint64_t *out_data_rate)
{
	uint32_t nss = 0;
	uint32_t max_mcs = 7; /* MCS 0-7 for NSS:1 is always supported */
	const uint8_t *rx_mcs_map;
	const uint8_t *tx_mcs_map;
	uint8_t chan_width;
	uint8_t channel_offset;
	bool sgi;

	if (!band->vht_supported || !band->ht_supported)
		return -ENOTSUP;

	if (!vhtc || !vhto || !htc || !hto)
		return -ENOTSUP;

	if (vhto[2] > 3)
		return -EBADMSG;

	/*
	 * Find the highest NSS/MCS index combination.  Since this is used by
	 * STAs, we try to estimate our 'download' speed from the AP/peer.
	 * Hence we look at the TX MCS map of the peer and our own RX MCS map
	 * to find an overlapping combination that works
	 */
	rx_mcs_map = band->vht_mcs_set;
	tx_mcs_map = vhtc + 2 + 8;

	if (!find_best_mcs_nss(rx_mcs_map, tx_mcs_map, 7, 8, 9, &max_mcs, &nss))
		return -EBADMSG;

	/*
	 * There is no way to know whether a peer would send us packets using
	 * the short guard interval (SGI.)  SGI capability is only used to
	 * indicate whether the peer can accept packets that we send this way.
	 * Here we make the assumption that if the peer has the capability to
	 * accept packets using SGI and we have the capability to do so, then
	 * SGI will be used
	 *
	 * Also, we assume that the highest bandwidth will result in the
	 * highest rate for any given rssi.  Even accounting for invalid
	 * MCS/Width/NSS combinations, the higher channel width results
	 * in better data rate at [mcs index - 2] compared to [mcs index] of
	 * a next lower bandwidth.
	 */

	/* See if 160 Mhz operation is available */
	chan_width = bit_field(band->vht_capabilities[0], 2, 2);
	if (chan_width != 1 && chan_width != 2)
		goto try_vht80;

	/*
	 * Channel Width is set to 2 or 3, or 1 and
	 * channel center frequency segment 1 is non-zero
	 */
	if (vhto[2] == 2 || vhto[2] == 3 || (vhto[2] == 1 && vhto[4])) {
		sgi = test_bit(band->vht_capabilities, 6) &&
						test_bit(vhtc + 2, 6);

		if (find_best_mcs_vht(max_mcs, OFDM_CHANNEL_WIDTH_160MHZ,
					rssi, nss, sgi, out_data_rate))
			return 0;
	}

try_vht80:
	if (vhto[2] == 1) {
		sgi = test_bit(band->vht_capabilities, 5) &&
						test_bit(vhtc + 2, 5);

		if (find_best_mcs_vht(max_mcs, OFDM_CHANNEL_WIDTH_80MHZ,
					rssi, nss, sgi, out_data_rate))
			return 0;
	} /* Otherwise, assume 20/40 Operation */

	channel_offset = bit_field(hto[3], 0, 2);

	/* Test for 40 Mhz operation */
	if (test_bit(hto + 3, 2) &&
			(channel_offset == 1 || channel_offset == 3)) {
		sgi = test_bit(band->ht_capabilities, 6) &&
						test_bit(htc + 2, 6);

		if (find_best_mcs_vht(max_mcs, OFDM_CHANNEL_WIDTH_40MHZ,
					rssi, nss, sgi, out_data_rate))
			return 0;
	}

	sgi = test_bit(band->ht_capabilities, 5) && test_bit(htc + 2, 5);

	if (find_best_mcs_vht(max_mcs, OFDM_CHANNEL_WIDTH_20MHZ,
				rssi, nss, sgi, out_data_rate))
		return 0;

	return -ENETUNREACH;
}

/*
 * Data Rate for HE is much the same as HT/VHT but some additional MCS indexes
 * were added. This mean rfactors, and nbpscs will contain two additional
 * values:
 *
 * rfactors.extend([3/4, 5/6])
 * nbpscs.extend([10, 10])
 *
 * The guard interval also differs:
 *
 * Tdft = 12.8us
 * Tgi = 0.8, 1.6 or 2.3us
 *
 * The Nsd values for HE are:
 *
 * Nsd = [234, 468, 980, 1960]
 *
 * The formula is identical to HT/VHT:
 *
 * Nsd * Nbpscs * R * Nss / (Tdft + Tgi)
 *
 * Note: The table below assumes a 0.8us GI. There isn't any way to know what
 *       GI will be used for an actual connection, so assume the best.
 */
static uint64_t he_rates[4][12] = {
	[OFDM_CHANNEL_WIDTH_20MHZ] = {
		8600000ULL, 17200000ULL, 25800000ULL, 34400000ULL,
		51600000ULL, 68800000ULL, 77400000ULL, 86000000ULL,
		103200000ULL, 114700000ULL, 129000000ULL, 143300000ULL,
	},
	[OFDM_CHANNEL_WIDTH_40MHZ] = {
		17200000ULL, 34400000ULL, 51600000ULL, 68800000ULL,
		103200000ULL, 137600000ULL, 154900000ULL, 172000000ULL,
		206500000ULL, 229400000ULL, 258000000ULL, 286800000ULL,
	},
	[OFDM_CHANNEL_WIDTH_80MHZ] = {
		36000000ULL, 72000000ULL, 108000000ULL, 144100000ULL,
		216200000ULL, 288200000ULL, 324300000ULL, 360300000ULL,
		432400000ULL, 480400000ULL, 540400000ULL, 600500000ULL,
	},
	[OFDM_CHANNEL_WIDTH_160MHZ] = {
		72000000ULL, 144100000ULL, 216200000ULL, 288200000ULL,
		432400000ULL, 576500000ULL, 648500000ULL, 720600000ULL,
		864700000ULL, 960800000ULL, 1080900000ULL, 1201000000ULL,
	},
};

static bool band_he_rate(uint8_t index, enum ofdm_channel_width width,
			int32_t rssi, uint8_t nss, uint64_t *data_rate)
{
	uint64_t rate;
	int32_t width_adjust;

	width_adjust = width * 3;

	if (rssi < ht_vht_he_base_rssi[index] + width_adjust)
		return false;

	rate = he_rates[width][index];

	rate *= nss;

	*data_rate = rate;
	return true;
}

static bool find_rate_he(const uint8_t *rx_map, const uint8_t *tx_map,
				enum ofdm_channel_width width, int32_t rssi,
				uint64_t *out_data_rate)
{
	uint32_t nss;
	uint32_t max_mcs;
	int i;

	if (!find_best_mcs_nss(rx_map, tx_map, 7, 9, 11,
				&max_mcs, &nss))
		return false;

	for (i = max_mcs; i >= 0; i--)
		if (band_he_rate(i, width, rssi, nss, out_data_rate))
			return true;

	return false;
}

/*
 * HE data rate is calculated based on 802.11ax - Section 27.5
 */
int band_estimate_he_rx_rate(const struct band *band, const uint8_t *hec,
				int32_t rssi, uint64_t *out_data_rate)
{
	enum ofdm_channel_width width = OFDM_CHANNEL_WIDTH_20MHZ;
	int i;
	const struct band_he_capabilities *he_cap = NULL;
	const struct l_queue_entry *entry;
	const uint8_t *rx_map;
	const uint8_t *tx_map;
	uint64_t rate = 0;
	uint64_t new_rate = 0;
	uint8_t width_set;

	if (!hec || !band->he_capabilities)
		return -EBADMSG;

	for (entry = l_queue_get_entries(band->he_capabilities);
						entry; entry = entry->next) {
		const struct band_he_capabilities *cap = entry->data;

		/*
		 * TODO: Station type is assumed here since it is the only
		 *       consumer of these data rate estimation APIs. If this
		 *       changes the iftype would need to be passed in.
		 */
		if (cap->iftypes & (1 << NETDEV_IFTYPE_STATION)) {
			he_cap = cap;
			break;
		}
	}

	if (!he_cap)
		return -ENOTSUP;

	/* AND the width sets, giving the widths supported by both */
	width_set = bit_field(he_cap->he_phy_capa[0], 1, 7) &
				bit_field((hec + 6)[0], 1, 7);

	/*
	 * The HE-MCS maps are 17 bytes into the HE Capabilities IE, and
	 * alternate RX/TX every 2 bytes. Start the TX map 17 + 2 bytes
	 * into the MCS set. For each MCS set find the best data rate.
	 */
	rx_map = he_cap->he_mcs_set;
	tx_map = hec + 19;

	/*
	 * 802.11ax Table 9-322b
	 *
	 * B3 indicates support for 80+80MHz MCS set
	 */
	if (test_bit(&width_set, 3)) {
		if (find_rate_he(rx_map + 8, tx_map + 8,
					OFDM_CHANNEL_WIDTH_160MHZ,
					rssi, &new_rate))
			rate = new_rate;
	}

	/* B2 indicates support for 160MHz MCS set */
	if (test_bit(&width_set, 2)) {
		if (find_rate_he(rx_map + 4, tx_map + 4,
					OFDM_CHANNEL_WIDTH_160MHZ,
					rssi, &new_rate) && new_rate > rate)
			rate = new_rate;
	}

	/* B1 indicates support for 80MHz */
	if (test_bit(&width_set, 1))
		width = OFDM_CHANNEL_WIDTH_80MHZ;

	/* B0 indicates support for 40MHz */
	if (test_bit(&width_set, 0))
		width = OFDM_CHANNEL_WIDTH_40MHZ;

	/* <= 80MHz MCS set */
	for (i = width; i >= OFDM_CHANNEL_WIDTH_20MHZ; i--) {
		if (find_rate_he(rx_map, tx_map, i, rssi, &new_rate)) {
			if (new_rate > rate)
				rate = new_rate;

			break;
		}
	}

	if (!rate)
		return -EBADMSG;

	*out_data_rate = rate;

	return 0;
}

static int band_channel_info_get_bandwidth(const struct band_chandef *info)
{
	switch (info->channel_width) {
	case BAND_CHANDEF_WIDTH_20NOHT:
	case BAND_CHANDEF_WIDTH_20:
		return 20;
	case BAND_CHANDEF_WIDTH_40:
		return 40;
	case BAND_CHANDEF_WIDTH_80:
		return 80;
	case BAND_CHANDEF_WIDTH_80P80:
	case BAND_CHANDEF_WIDTH_160:
		return 160;
	default:
		break;
	}

	return -ENOTSUP;
}

struct operating_class_info {
	uint32_t starting_frequency;
	uint32_t flags;
	uint8_t channel_set[60];
	uint8_t center_frequencies[30];
	uint16_t channel_spacing;
	uint8_t operating_class;
};

enum operating_class_flags {
	PRIMARY_CHANNEL_UPPER = 0x1,
	PRIMARY_CHANNEL_LOWER = 0x2,
	PLUS80 = 0x4,
};

static const struct operating_class_info e4_operating_classes[] = {
	{
		.operating_class = 81,
		.starting_frequency = 2407,
		.channel_set = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 },
		.channel_spacing = 20,
	},
	{
		.operating_class = 82,
		.starting_frequency = 2414,
		.channel_set = { 14 },
		.channel_spacing = 20,
	},
	{
		.operating_class = 83,
		.starting_frequency = 2407,
		.channel_set = { 1, 2, 3, 4, 5, 6, 7, 8, 9 },
		.channel_spacing = 40,
		.flags = PRIMARY_CHANNEL_LOWER,
	},
	{
		.operating_class = 84,
		.starting_frequency = 2407,
		.channel_set = { 5, 6, 7, 8, 9, 10, 11, 12, 13 },
		.channel_spacing = 40,
		.flags = PRIMARY_CHANNEL_UPPER,
	},
	{
		.operating_class = 115,
		.starting_frequency = 5000,
		.channel_set = { 36, 40, 44, 48},
		.channel_spacing = 20,
	},
	{
		.operating_class = 116,
		.starting_frequency = 5000,
		.channel_set = { 36, 44 },
		.channel_spacing = 40,
		.flags = PRIMARY_CHANNEL_LOWER,
	},
	{
		.operating_class = 117,
		.starting_frequency = 5000,
		.channel_set = { 40, 48 },
		.channel_spacing = 40,
		.flags = PRIMARY_CHANNEL_UPPER,
	},
	{
		.operating_class = 118,
		.starting_frequency = 5000,
		.channel_set = { 52, 56, 60, 64},
		.channel_spacing = 20,
	},
	{
		.operating_class = 119,
		.starting_frequency = 5000,
		.channel_set = { 52, 60 },
		.channel_spacing = 40,
		.flags = PRIMARY_CHANNEL_LOWER,
	},
	{
		.operating_class = 120,
		.starting_frequency = 5000,
		.channel_set = { 56, 64 },
		.channel_spacing = 40,
		.flags = PRIMARY_CHANNEL_UPPER,
	},
	{
		.operating_class = 121,
		.starting_frequency = 5000,
		.channel_set = { 100, 104, 108, 112, 116, 120,
					124, 128, 132, 136, 140, 144 },
		.channel_spacing = 20,
	},
	{
		.operating_class = 122,
		.starting_frequency = 5000,
		.channel_set = { 100, 108, 116, 124, 132, 140},
		.channel_spacing = 40,
		.flags = PRIMARY_CHANNEL_LOWER,
	},
	{
		.operating_class = 123,
		.starting_frequency = 5000,
		.channel_set = { 104, 112, 120, 128, 136, 144 },
		.channel_spacing = 40,
		.flags = PRIMARY_CHANNEL_UPPER,
	},
	{
		.operating_class = 124,
		.starting_frequency = 5000,
		.channel_set = { 149, 153, 157, 161 },
		.channel_spacing = 20,
	},
	{
		.operating_class = 125,
		.starting_frequency = 5000,
		.channel_set = { 149, 153, 157, 161, 165, 169, 173, 177 },
		.channel_spacing = 20,
	},
	{
		.operating_class = 126,
		.starting_frequency = 5000,
		.channel_set = { 149, 157, 165, 173 },
		.channel_spacing = 40,
		.flags = PRIMARY_CHANNEL_LOWER,
	},
	{
		.operating_class = 127,
		.starting_frequency = 5000,
		.channel_set = { 153, 161, 169, 177 },
		.channel_spacing = 40,
		.flags = PRIMARY_CHANNEL_UPPER,
	},
	{
		.operating_class = 128,
		.starting_frequency = 5000,
		.channel_spacing = 80,
		.center_frequencies = { 42, 58, 106, 122, 138, 155, 171 },
	},
	{
		.operating_class = 129,
		.starting_frequency = 5000,
		.channel_spacing = 160,
		.center_frequencies = { 50, 114, 163 },
	},
	{
		.operating_class = 130,
		.starting_frequency = 5000,
		.channel_spacing = 80,
		.center_frequencies = { 42, 58, 106, 122, 138, 155, 171 },
		.flags = PLUS80,
	},
	{
		.operating_class = 131,
		.starting_frequency = 5950,
		.channel_spacing = 20,
		.channel_set = { 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45,
				49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93,
				97, 101, 105, 109, 113, 117, 121, 125, 129, 133,
				137, 141, 145, 149, 153, 157, 161, 165, 169,
				173, 177, 181, 185, 189, 193, 197, 201, 205,
				209, 213, 217, 221, 225, 229, 233 },
	},
	{
		.operating_class = 132,
		.starting_frequency = 5950,
		.channel_spacing = 40,
		.center_frequencies = { 3, 11, 19, 27, 35, 43, 51, 59, 67, 75,
					83, 91, 99, 107, 115, 123, 131, 139,
					147, 155, 163, 171, 179, 187, 195, 203,
					211, 219, 227 },
	},
	{
		.operating_class = 133,
		.starting_frequency = 5950,
		.channel_spacing = 80,
		.center_frequencies = { 7, 23, 39, 55, 71, 87, 103, 119, 135,
					151, 167, 183, 199, 215 },
	},
	{
		.operating_class = 134,
		.starting_frequency = 5950,
		.channel_spacing = 160,
		.center_frequencies = { 15, 47, 79, 111, 143, 175, 207 },
	},
	{
		.operating_class = 135,
		.starting_frequency = 5950,
		.channel_spacing = 80,
		.center_frequencies = { 7, 23, 39, 55, 71, 87, 102, 119, 135,
					151, 167, 183, 199, 215 },
		.flags = PLUS80,
	},
	{
		.operating_class = 136,
		.starting_frequency = 5950,
		.channel_spacing = 20,
		.center_frequencies = { 2 },
	}
};

static const struct operating_class_info *e4_find_opclass(uint32_t opclass)
{
	unsigned int i;

	for (i = 0; i < L_ARRAY_SIZE(e4_operating_classes); i++) {
		if (e4_operating_classes[i].operating_class != opclass)
			continue;

		return &e4_operating_classes[i];
	}

	return NULL;
}

static int e4_channel_to_frequency(const struct operating_class_info *info,
					uint32_t channel)
{
	unsigned int i;
	unsigned int offset;

	for (i = 0; info->channel_set[i] &&
				i < L_ARRAY_SIZE(info->channel_set); i++) {
		if (info->channel_set[i] != channel)
			continue;

		return channel * 5 + info->starting_frequency;
	}

	/*
	 * Only classes in Table E4 with center frequencies are 128-130,
	 * which use 20 Mhz wide channels.  Since E4 gives a center frequency,
	 * calculate the channel offset based on channel spacing.
	 *
	 * Typically +/- 6 for 80 Mhz channels and +/- 14 for 160 Mhz channels
	 */
	offset = (info->channel_spacing - 20) / 5 / 2;

	/*
	 * Check that the channel is in the frequency range given by one of
	 * the center frequencies listed for the operating class.  The channel
	 * must be a valid channel for a lower operating class and spaced
	 * 20 mhz apart
	 */
	for (i = 0; info->center_frequencies[i] &&
			i < L_ARRAY_SIZE(info->center_frequencies); i++) {

		unsigned int upper = info->center_frequencies[i] + offset;
		unsigned int j = info->center_frequencies[i] - offset;

		while (j <= upper && channel >= j) {
			if (channel == j)
				return channel * 5 + info->starting_frequency;

			j += 4;
		}
	}

	return -EINVAL;
}

static int e4_frequency_to_channel(const struct operating_class_info *info,
					uint32_t frequency)
{
	return (frequency - info->starting_frequency) / 5;
}

static int e4_has_frequency(const struct operating_class_info *info,
				uint32_t frequency)
{
	unsigned int i;
	unsigned int channel = e4_frequency_to_channel(info, frequency);

	for (i = 0; info->channel_set[i] &&
				i < L_ARRAY_SIZE(info->channel_set); i++) {
		if (info->channel_set[i] != channel)
			continue;

		return 0;
	}

	return -ENOENT;
}

static int e4_has_ccfi(const struct operating_class_info *info,
				uint32_t center_frequency)
{
	unsigned int i;
	unsigned int ccfi = e4_frequency_to_channel(info, center_frequency);

	for (i = 0; info->center_frequencies[i] &&
			i < L_ARRAY_SIZE(info->center_frequencies); i++) {
		if (info->center_frequencies[i] != ccfi)
			continue;

		return 0;
	}

	return -ENOENT;
}

static int e4_class_matches(const struct operating_class_info *info,
					const struct band_chandef *chandef)
{
	int own_bandwidth = band_channel_info_get_bandwidth(chandef);
	int r;

	if (own_bandwidth < 0)
		return own_bandwidth;

	switch (chandef->channel_width) {
	case BAND_CHANDEF_WIDTH_20NOHT:
	case BAND_CHANDEF_WIDTH_20:
	case BAND_CHANDEF_WIDTH_40:
		if (own_bandwidth != info->channel_spacing)
			return -ENOENT;

		if (own_bandwidth == 40) {
			uint32_t behavior;

			if (chandef->center1_frequency > chandef->frequency)
				behavior = PRIMARY_CHANNEL_LOWER;
			else
				behavior = PRIMARY_CHANNEL_UPPER;

			if ((info->flags & behavior) != behavior)
				return -ENOENT;
		}

		return e4_has_frequency(info, chandef->frequency);
	case BAND_CHANDEF_WIDTH_80:
	case BAND_CHANDEF_WIDTH_160:
		if (info->flags & PLUS80)
			return -ENOENT;

		if (own_bandwidth != info->channel_spacing)
			return -ENOENT;

		return e4_has_ccfi(info, chandef->center1_frequency);
	case BAND_CHANDEF_WIDTH_80P80:
		if (!(info->flags & PLUS80))
			return -ENOENT;

		r = e4_has_ccfi(info, chandef->center1_frequency);
		if (r < 0)
			return r;

		return e4_has_ccfi(info, chandef->center2_frequency);
	default:
		break;
	}

	return -ENOTSUP;
}

int oci_to_frequency(uint32_t operating_class, uint32_t channel)
{
	const struct operating_class_info *info;

	info = e4_find_opclass(operating_class);
	if (!info)
		return -ENOENT;

	return e4_channel_to_frequency(info, channel);
}

int oci_verify(const uint8_t oci[static 3], const struct band_chandef *own)
{
	const struct operating_class_info *info;
	int oci_frequency;
	int own_bandwidth;
	int oci_bandwidth;

	info = e4_find_opclass(oci[0]);
	if (!info)
		return -ENOENT;

	/*
	 * 802.11-2020, 12.2.9:
	 * Verifying that the maximum bandwidth used by the STA to transmit or
	 * receive PPDUs to/from the peer STA from which the OCI was received
	 * is no greater than the bandwidth of the operating class specified
	 * in the Operating Class field of the received OCI
	 */
	own_bandwidth = band_channel_info_get_bandwidth(own);
	if (own_bandwidth < 0)
		return own_bandwidth;

	oci_bandwidth = info->channel_spacing;
	if (info->flags & PLUS80)
		oci_bandwidth *= 2;

	if (own_bandwidth > oci_bandwidth)
		return -EPERM;

	/*
	 * 802.11-2020, 12.2.9:
	 * Verifying that the primary channel used by the STA to transmit or
	 * receive PPDUs to/from the peer STA from which the OCI was received
	 * is equal to the Primary Channel Number field (for the corresponding
	 * operating class)
	 */
	oci_frequency = e4_channel_to_frequency(info, oci[1]);
	if (oci_frequency < 0)
		return oci_frequency;

	if (oci_frequency != (int) own->frequency)
		return -EPERM;

	/*
	 * 802.11-2020, 12.2.9:
	 * Verifying that, when 40 MHz bandwidth is used by the STA to transmit
	 * or receive PPDUs to/from the peer STA from which the OCI was
	 * received, the nonprimary 20 MHz used matches the operating class
	 * (i.e., upper/lower behavior) specified in the Operating Class field
	 * of the received OCI
	 *
	 * NOTE: For now we only check this if the STA and peer are operating
	 * on 40 Mhz channels.  If the STA is operating on 40 Mhz while the
	 * peer is operating on 80 or 160 Mhz wide channels, then only the
	 * primary channel validation is performed
	 *
	 * With 6GHz operating classes there is no concept of upper/lower 40mhz
	 * channels, therefore this special handling list not needed.
	 */
	if (own_bandwidth == 40 && oci_bandwidth == 40 &&
						info->operating_class < 131) {
		uint32_t behavior;

		/*
		 * - Primary Channel Upper Behavior -> Secondary channel below
		 *   primary channel.  Or HT40MINUS.
		 * - Primary Channel Lower Behavior -> Secondary channel above
		 *   primary channel.  Or HT40PLUS.
		 */
		if (own->center1_frequency > own->frequency)
			behavior = PRIMARY_CHANNEL_LOWER;
		else
			behavior = PRIMARY_CHANNEL_UPPER;

		if ((info->flags & behavior) != behavior)
			return -EPERM;
	}

	/*
	 * 802.11-2020, 12.2.9:
	 * Verifying that, if operating an 80+80 MHz operating class, the
	 * frequency segment 1 channel number used by the STA to transmit or
	 * receive PPDUs to/from the peer STA from which the OCI was received
	 * is equal to the Frequency Segment 1 Channel Number field of the OCI.
	 */
	if (own->channel_width == BAND_CHANDEF_WIDTH_80P80) {
		uint32_t freq_segment1_chan_num;

		if (!(info->flags & PLUS80))
			return -EPERM;

		freq_segment1_chan_num =
			e4_frequency_to_channel(info, own->center2_frequency);

		if (freq_segment1_chan_num != oci[2])
			return -EPERM;
	}

	return 0;
}

int oci_from_chandef(const struct band_chandef *own, uint8_t oci[static 3])
{
	unsigned int i;

	for (i = 0; i < L_ARRAY_SIZE(e4_operating_classes); i++) {
		const struct operating_class_info *info =
						&e4_operating_classes[i];

		if (e4_class_matches(info, own) < 0)
			continue;

		oci[0] = info->operating_class;
		oci[1] = e4_frequency_to_channel(info, own->frequency);

		if (own->center2_frequency)
			oci[2] = e4_frequency_to_channel(info,
							own->center2_frequency);
		else
			oci[2] = 0;

		return 0;
	}

	return -ENOENT;
}

/* Find an HT chandef for the frequency */
int band_freq_to_ht_chandef(uint32_t freq, const struct band_freq_attrs *attr,
				struct band_chandef *chandef)
{
	enum band_freq band;
	enum band_chandef_width width;
	unsigned int i;
	const struct operating_class_info *best = NULL;

	if (attr->disabled || !attr->supported)
		return -EINVAL;

	if (!band_freq_to_channel(freq, &band))
		return -EINVAL;

	for (i = 0; i < L_ARRAY_SIZE(e4_operating_classes); i++) {
		const struct operating_class_info *info =
						&e4_operating_classes[i];
		enum band_chandef_width w;

		if (e4_has_frequency(info, freq) < 0)
			continue;

		/* Any restrictions for this channel width? */
		switch (info->channel_spacing) {
		case 20:
			w = BAND_CHANDEF_WIDTH_20;
			break;
		case 40:
			w = BAND_CHANDEF_WIDTH_40;

			/* 6GHz remove the upper/lower 40mhz channel concept */
			if (band == BAND_FREQ_6_GHZ)
				break;

			if (info->flags & PRIMARY_CHANNEL_UPPER &&
						attr->no_ht40_plus)
				continue;

			if (info->flags & PRIMARY_CHANNEL_LOWER &&
						attr->no_ht40_minus)
				continue;

			break;
		default:
			continue;
		}

		if (!best || best->channel_spacing < info->channel_spacing) {
			best = info;
			width = w;
		}
	}

	if (!best)
		return -ENOENT;

	chandef->frequency = freq;
	chandef->channel_width = width;

	/*
	 * Choose a secondary channel frequency:
	 * - 20mhz no secondary
	 * - 40mhz we can base the selection off the channel flags, either
	 *   higher or lower.
	 */
	switch (width) {
	case BAND_CHANDEF_WIDTH_20:
		return 0;
	case BAND_CHANDEF_WIDTH_40:
		if (band == BAND_FREQ_6_GHZ)
			return 0;

		if (best->flags & PRIMARY_CHANNEL_UPPER)
			chandef->center1_frequency = freq - 10;
		else
			chandef->center1_frequency = freq + 10;

		return 0;
	default:
		/* Should never happen */
		return -EINVAL;
	}

	return 0;
}

uint8_t band_freq_to_channel(uint32_t freq, enum band_freq *out_band)
{
	uint32_t channel = 0;

	if (freq >= 2412 && freq <= 2484) {
		if (freq == 2484)
			channel = 14;
		else {
			channel = freq - 2407;

			if (channel % 5)
				return 0;

			channel /= 5;
		}

		if (out_band)
			*out_band = BAND_FREQ_2_4_GHZ;

		return channel;
	}

	if (freq >= 5005 && freq < 5900) {
		if (freq % 5)
			return 0;

		channel = (freq - 5000) / 5;

		if (out_band)
			*out_band = BAND_FREQ_5_GHZ;

		return channel;
	}

	if (freq >= 4905 && freq < 5000) {
		if (freq % 5)
			return 0;

		channel = (freq - 4000) / 5;

		if (out_band)
			*out_band = BAND_FREQ_5_GHZ;

		return channel;
	}

	if (freq > 5950 && freq <= 7115) {
		if (freq % 5)
			return 0;

		channel = (freq - 5950) / 5;

		if (out_band)
			*out_band = BAND_FREQ_6_GHZ;

		return channel;
	}

	if (freq == 5935) {
		if (out_band)
			*out_band = BAND_FREQ_6_GHZ;

		return 2;
	}

	return 0;
}

uint32_t band_channel_to_freq(uint8_t channel, enum band_freq band)
{
	if (band == BAND_FREQ_2_4_GHZ) {
		if (channel >= 1 && channel <= 13)
			return 2407 + 5 * channel;

		if (channel == 14)
			return 2484;
	}

	if (band == BAND_FREQ_5_GHZ) {
		if (channel >= 1 && channel <= 179)
			return 5000 + 5 * channel;

		if (channel >= 181 && channel <= 199)
			return 4000 + 5 * channel;
	}

	if (band == BAND_FREQ_6_GHZ) {
		/* operating class 136 */
		if (channel == 2)
			return 5935;

		/* Channels increment by 4, starting with 1 */
		if (channel % 4 != 1)
			return 0;

		if (channel < 1 || channel > 233)
			return 0;

		/* operating classes 131, 132, 133, 134, 135 */
		return 5950 + 5 * channel;
	}

	return 0;
}

static const char *const oper_class_us_codes[] = {
	"US", "CA"
};

static const char *const oper_class_eu_codes[] = {
	"AL", "AM", "AT", "AZ", "BA", "BE", "BG", "BY", "CH", "CY", "CZ", "DE",
	"DK", "EE", "EL", "ES", "FI", "FR", "GE", "HR", "HU", "IE", "IS", "IT",
	"LI", "LT", "LU", "LV", "MD", "ME", "MK", "MT", "NL", "NO", "PL", "PT",
	"RO", "RS", "RU", "SE", "SI", "SK", "TR", "UA", "UK"
};

/* Annex E, table E-1 */
static const uint8_t oper_class_us_to_global[] = {
	[1]  = 115, [2]  = 118, [3]  = 124, [4]  = 121,
	[5]  = 125, [6]  = 103, [7]  = 103, [8]  = 102,
	[9]  = 102, [10] = 101, [11] = 101, [12] = 81,
	[13] = 94,  [14] = 95,  [15] = 96,  [22] = 116,
	[23] = 119, [24] = 122, [25] = 126, [26] = 126,
	[27] = 117, [28] = 120, [29] = 123, [30] = 127,
	[31] = 127, [32] = 83,  [33] = 84,  [34] = 180,
	/* 128 - 130 is a 1 to 1 mapping */
};

/* Annex E, table E-2 */
static const uint8_t oper_class_eu_to_global[] = {
	[1]  = 115, [2]  = 118, [3]  = 121, [4]  = 81,
	[5]  = 116, [6]  = 119, [7]  = 122, [8]  = 117,
	[9]  = 120, [10] = 123, [11] = 83,  [12] = 84,
	[17] = 125, [18] = 130,
	/* 128 - 130 is a 1 to 1 mapping */
};

/* Annex E, table E-3 */
static const uint8_t oper_class_jp_to_global[] = {
	[1]  = 115, [2]  = 112, [3]  = 112, [4]  = 112,
	[5]  = 112, [6]  = 112, [7]  = 109, [8]  = 109,
	[9]  = 109, [10] = 109, [11] = 109, [12] = 113,
	[13] = 113, [14] = 113, [15] = 113, [16] = 110,
	[17] = 110, [18] = 110, [19] = 110, [20] = 110,
	[21] = 114, [22] = 114, [23] = 114, [24] = 114,
	[25] = 111, [26] = 111, [27] = 111, [28] = 111,
	[29] = 111, [30] = 81,  [31] = 82,  [32] = 118,
	[33] = 118, [34] = 121, [35] = 121, [36] = 116,
	[37] = 119, [38] = 119, [39] = 122, [40] = 122,
	[41] = 117, [42] = 120, [43] = 120, [44] = 123,
	[45] = 123, [46] = 104, [47] = 104, [48] = 104,
	[49] = 104, [50] = 104, [51] = 105, [52] = 105,
	[53] = 105, [54] = 105, [55] = 105, [56] = 83,
	[57] = 84,  [58] = 121, [59] = 180,
	/* 128 - 130 is a 1 to 1 mapping */
};

/* Annex E, table E-4 (only 2.4GHz, 4.9 / 5GHz, and 6GHz bands) */
static const enum band_freq oper_class_to_band_global[] = {
	[81 ... 84]   = BAND_FREQ_2_4_GHZ,
	[104 ... 130] = BAND_FREQ_5_GHZ,
	[131 ... 136] = BAND_FREQ_6_GHZ,
};

/* Annex E, table E-5 */
static const uint8_t oper_class_cn_to_global[] = {
	[1]  = 115, [2]  = 118, [3]  = 125, [4]  = 116,
	[5]  = 119, [6]  = 126, [7]  = 81,  [8]  = 83,
	[9]  = 84,
	/* 128 - 130 is a 1 to 1 mapping */
};

enum band_freq band_oper_class_to_band(const uint8_t *country,
					uint8_t oper_class)
{
	unsigned int i;
	int table = 0;

	if (country && country[2] >= 1 && country[2] <= 5)
		table = country[2];
	else if (country) {
		for (i = 0; i < L_ARRAY_SIZE(oper_class_us_codes); i++)
			if (!memcmp(oper_class_us_codes[i], country, 2)) {
				/* Use table E-1 */
				table = 1;
				break;
			}

		for (i = 0; i < L_ARRAY_SIZE(oper_class_eu_codes); i++)
			if (!memcmp(oper_class_eu_codes[i], country, 2)) {
				/* Use table E-2 */
				table = 2;
				break;
			}

		if (!memcmp("JP", country, 2))
			/* Use table E-3 */
			table = 3;

		if (!memcmp("CN", country, 2))
			/* Use table E-5 */
			table = 5;
	}

	switch (table) {
	case 1:
		if (oper_class < L_ARRAY_SIZE(oper_class_us_to_global))
			oper_class = oper_class_us_to_global[oper_class];
		break;
	case 2:
		if (oper_class < L_ARRAY_SIZE(oper_class_eu_to_global))
			oper_class = oper_class_eu_to_global[oper_class];
		break;
	case 3:
		if (oper_class < L_ARRAY_SIZE(oper_class_jp_to_global))
			oper_class = oper_class_jp_to_global[oper_class];
		break;
	case 5:
		if (oper_class < L_ARRAY_SIZE(oper_class_cn_to_global))
			oper_class = oper_class_cn_to_global[oper_class];
		break;
	}

	if (oper_class < L_ARRAY_SIZE(oper_class_to_band_global))
		return oper_class_to_band_global[oper_class];
	else
		return 0;
}

const char *band_chandef_width_to_string(enum band_chandef_width width)
{
	switch (width) {
	case BAND_CHANDEF_WIDTH_20NOHT:
		return "20MHz (no-HT)";
	case BAND_CHANDEF_WIDTH_20:
		return "20MHz";
	case BAND_CHANDEF_WIDTH_40:
		return "40MHz";
	case BAND_CHANDEF_WIDTH_80:
		return "80MHz";
	case BAND_CHANDEF_WIDTH_80P80:
		return "80+80MHz";
	case BAND_CHANDEF_WIDTH_160:
		return "160MHz";
	}

	return NULL;
}
