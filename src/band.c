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

#include "band.h"

void band_free(struct band *band)
{
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
		if (band_ofdm_rate(i, width, rssi,
						nss, sgi, out_data_rate))
			return true;

	return false;
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
	int bitoffset;
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

	for (bitoffset = 14; bitoffset >= 0; bitoffset -= 2) {
		uint8_t rx_val = bit_field(rx_mcs_map[bitoffset / 8],
							bitoffset % 8, 2);
		uint8_t tx_val = bit_field(tx_mcs_map[bitoffset / 8],
							bitoffset % 8, 2);

		/*
		 * 0 indicates support for MCS 0-7
		 * 1 indicates support for MCS 0-8
		 * 2 indicates support for MCS 0-9
		 * 3 indicates no support
		 */

		if (rx_val == 3 || tx_val == 3)
			continue;

		/* 7 + rx_val/tx_val gives us the maximum mcs index */
		max_mcs = minsize(rx_val, tx_val) + 7;
		nss = bitoffset / 2 + 1;
		break;
	}

	if (!nss)
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
	uint8_t channel_set[20];
	uint8_t center_frequencies[8];
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
		.channel_set = { 149, 153, 157, 161, 165, 169, 173},
		.channel_spacing = 20,
	},
	{
		.operating_class = 126,
		.starting_frequency = 5000,
		.channel_set = { 149, 157, 165},
		.channel_spacing = 40,
		.flags = PRIMARY_CHANNEL_LOWER,
	},
	{
		.operating_class = 127,
		.starting_frequency = 5000,
		.channel_set = { 153, 161, 169 },
		.channel_spacing = 40,
		.flags = PRIMARY_CHANNEL_UPPER,
	},
	{
		.operating_class = 128,
		.starting_frequency = 5000,
		.channel_spacing = 80,
		.center_frequencies = { 42, 58, 106, 122, 138, 155 },
	},
	{
		.operating_class = 129,
		.starting_frequency = 5000,
		.channel_spacing = 160,
		.center_frequencies = { 50, 114 },
	},
	{
		.operating_class = 130,
		.starting_frequency = 5000,
		.channel_spacing = 80,
		.center_frequencies = { 42, 58, 106, 122, 138, 155 },
		.flags = PLUS80,
	},
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
	 */
	if (own_bandwidth == 40 && oci_bandwidth == 40) {
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

		freq_segment1_chan_num = (own->center2_frequency -
						info->starting_frequency) / 5;

		if (freq_segment1_chan_num != oci[2])
			return -EPERM;
	}

	return 0;
}
