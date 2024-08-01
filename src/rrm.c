/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

#include <stdint.h>
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "ell/useful.h"
#include "src/module.h"
#include "src/mpdu.h"
#include "src/netdev.h"
#include "src/iwd.h"
#include "src/ie.h"
#include "src/util.h"
#include "src/station.h"
#include "src/scan.h"
#include "src/nl80211util.h"
#include "src/wiphy.h"
#include "src/frame-xchg.h"
#include "src/band.h"

#include "linux/nl80211.h"

/* Limit requests per second */
#define MAX_REQUESTS_PER_SEC		2ULL
/* Microseconds between requests */
#define MIN_MICROS_BETWEEN_REQUESTS	(1000000ULL / MAX_REQUESTS_PER_SEC)

/* 802.11-2016 Table 9-90 */
#define REPORT_DETAIL_NO_FIELDS_OR_ELEMS		0
#define REPORT_DETAIL_ALL_FIELDS_AND_ANY_REQUEST_ELEMS	1
#define REPORT_DETAIL_ALL_FIELDS_AND_ELEMS		2

/* 802.11-2016 Table 9-192 */
#define REPORT_REJECT_LATE	(1 << 0)
#define REPORT_REJECT_INCAPABLE	(1 << 1)
#define REPORT_REJECT_REFUSED	(1 << 2)

/* 802.11-2016 Table 9-87 */
enum rrm_beacon_req_mode {
	RRM_BEACON_REQ_MODE_PASSIVE =	0,
	RRM_BEACON_REQ_MODE_ACTIVE =	1,
	RRM_BEACON_REQ_MODE_TABLE =	2,
};

/* 802.11-2016 Table 9-88 */
enum rrm_beacon_req_subelem_id {
	RRM_BEACON_REQ_SUBELEM_ID_SSID			= 0,
	RRM_BEACON_REQ_SUBELEM_ID_BEACON_REPORTING	= 1,
	RRM_BEACON_REQ_SUBELEM_ID_REPORTING_DETAIL	= 2,
	/* 3 - 9 reserved */
	RRM_BEACON_REQ_SUBELEM_ID_REQUEST		= 10,
	RRM_BEACON_REQ_SUBELEM_ID_EXT_REQUEST		= 11,
	/* 12 - 50 reserved */
	RRM_BEACON_REQ_SUBELEM_ID_AP_CHAN_REPORT	= 51,
	/* 52 - 162 reserved */
	RRM_BEACON_REQ_SUBELEM_ID_WIDE_BAND_SWITCH	= 163,
	/* 164 - 220 reserved */
	RRM_BEACON_REQ_SUBELEM_ID_VENDOR		= 221,
	/* 222 - 255 reserved */
};

/* 802.11-2016 Annex C - dot11PHYType */
enum rrm_phy_type {
	RRM_PHY_TYPE_DSSS	= 2,
	RRM_PHY_TYPE_OFDM	= 4,
	RRM_PHY_TYPE_HRDSSS	= 5,
	RRM_PHY_TYPE_ERP	= 6,
	RRM_PHY_TYPE_HT		= 7,
	RRM_PHY_TYPE_DMG	= 8,
	RRM_PHY_TYPE_VHT	= 9,
	RRM_PHY_TYPE_TVHT	= 10,
};

struct rrm_request_info {
	uint8_t dialog_token;	/* dialog token in Radio Measurement Request */
	uint8_t mtoken;		/* token in measurement request element */
	uint8_t mode;
	uint8_t type;		/* request type (only beacon supported) */
};

struct rrm_beacon_req_info {
	struct rrm_request_info info;
	uint8_t oper_class;
	uint8_t channel;	/* The single channel provided in request */
	uint16_t duration;
	uint8_t bssid[6];		/* Request filtered by BSSID */
	char ssid[SSID_MAX_SIZE + 1];	/* Request filtered by SSID */
	bool has_ssid;
	uint32_t scan_id;
	uint64_t scan_start_time;
};

/* Per-netdev state */
struct rrm_state {
	struct station *station;
	uint32_t watch_id;
	uint32_t ifindex;
	uint64_t wdev_id;
	struct rrm_request_info *pending;

	uint64_t last_request;
};

/* 802.11, Section 9.4.2.22.7 */
struct rrm_beacon_report {
	uint8_t oper_class;
	uint8_t channel;
	__le64 scan_start_time;
	__le16 duration;
	uint8_t frame_info;
	uint8_t rcpi;
	uint8_t rsni;
	uint8_t bssid[6];
	uint8_t antenna_id;
	__le32 parent_tsf;
	uint8_t subelements[];
} __attribute__ ((packed));

static struct l_queue *states;
static struct l_genl_family *nl80211;
static uint32_t netdev_watch;

static void rrm_info_destroy(void *data)
{
	struct rrm_request_info *info = data;
	/* TODO: once more request types are added, check type */
	struct rrm_beacon_req_info *beacon = l_container_of(info,
						struct rrm_beacon_req_info,
						info);

	l_free(beacon);
}

static uint8_t rrm_phy_type(struct scan_bss *bss)
{
	if (bss->vht_capable)
		return RRM_PHY_TYPE_VHT;

	if (bss->ht_capable)
		return RRM_PHY_TYPE_HT;

	/*
	 * Default to 802.11g phy type. You can get quite fancy here determining
	 * the phy type by looking at the frequency and operator class among
	 * other things. Since 802.11a/b are so old, defaulting to 802.11g just
	 * removes a lot of complexity. Above, HT/VHT are easy as all you need
	 * to look for is the presence of the IE.
	 */
	return RRM_PHY_TYPE_ERP;
}

static void rrm_send_response_cb(struct l_genl_msg *msg, void *user_data)
{
	int err = l_genl_msg_get_error(msg);

	if (err < 0)
		l_error("Error sending response: %d", err);
}

static bool rrm_send_response(struct rrm_state *rrm,
				const uint8_t *frame, size_t len)
{
	struct netdev *netdev = netdev_find(rrm->ifindex);
	const uint8_t *own_addr = netdev_get_address(netdev);
	struct scan_bss *bss = station_get_connected_bss(rrm->station);
	struct l_genl_msg *msg;
	struct iovec iov;

	iov.iov_base = (void *)frame;
	iov.iov_len = len;

	msg = nl80211_build_cmd_frame(rrm->ifindex, 0x00d0, own_addr, bss->addr,
					bss->frequency, &iov, 1);

	if (!l_genl_family_send(nl80211, msg, rrm_send_response_cb,
					NULL, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Failed to send report for "MAC,
				MAC_STR(bss->addr));
		return false;
	}

	return true;
}

static void rrm_reject_measurement_request(struct rrm_state *rrm,
						uint8_t mode)
{
	struct rrm_request_info *info = rrm->pending;
	uint8_t frame[8];

	frame[0] = 0x05; /* Category: Radio Measurement */
	frame[1] = 0x01; /* Action: Radio Measurement Report */
	frame[2] = info->dialog_token;
	frame[3] = IE_TYPE_MEASUREMENT_REPORT;
	frame[4] = 3;
	frame[5] = info->mtoken;
	frame[6] = mode;
	frame[7] = info->type;

	if (!rrm_send_response(rrm, frame, sizeof(frame)))
		l_error("failed to send rejection");

	rrm_info_destroy(info);
	rrm->pending = NULL;
}

static void rrm_build_measurement_report(struct rrm_request_info *info,
				const void *report, size_t report_len,
				uint8_t *to)
{
	*to++ = IE_TYPE_MEASUREMENT_REPORT;
	*to++ = 3 + report_len;
	*to++ = info->mtoken;
	*to++ = 0;
	*to++ = info->type;

	if (report)
		memcpy(to, report, report_len);
}

/* 802.11 Table 9-154 */
static uint8_t mdb_to_rcpi(int32_t mdb)
{
	if (mdb <= -10950)
		return 0;
	else if (mdb >= -10950 && mdb < 0)
		return (2 * (mdb + 11000)) / 100;
	else
		return 220;
}

/*
 * 802.11-2016 11.11.9.1 Beacon report
 *
 * "If the stored beacon information is based on a measurement made by
 *  the reporting STA, and if the actual measurement start time,
 *  measurement duration, and Parent TSF are available for this
 *  measurement, then the beacon report shall include the actual
 *  measurement start time, measurement duration, and Parent TSF;
 *  otherwise the actual measurement start time, measurement duration,
 *  and Parent TSF shall be set to 0. The RCPI and RSNI for that stored
 *  beacon measurement may be included in the beacon report; otherwise
 *  the beacon report shall indicate that RCPI and RSNI measurements
 *  are not available"
 *
 * Since accurate timing is unreliable we are setting start/duration/TSF time to
 * zero for all cases (table, passive, active).
 */
static size_t build_report_for_bss(struct rrm_beacon_req_info *beacon,
					struct scan_bss *bss,
					uint8_t *to)
{
	struct rrm_beacon_report *report = (struct rrm_beacon_report *) to;

	report->oper_class = beacon->oper_class;
	report->channel = band_freq_to_channel(bss->frequency, NULL);
	report->scan_start_time = L_CPU_TO_LE64(beacon->scan_start_time);
	report->duration = L_CPU_TO_LE16(beacon->duration);
	report->frame_info = rrm_phy_type(bss);
	report->rcpi = mdb_to_rcpi(bss->signal_strength);

	/* RSNI not available (could get this from GET_SURVEY) */
	report->rsni = 255;
	memcpy(report->bssid, bss->addr, 6);
	/* Antenna identifier unknown */
	report->antenna_id = 0;

	/*
	 * 802.11 9.4.2.22.7 Beacon report
	 *
	 * "The Parent TSF field contains the lower 4 octets of the measuring
	 *  STA's TSF timer value"
	 */
	report->parent_tsf = L_CPU_TO_LE32(bss->parent_tsf);

	/*
	 * TODO: Support optional subelements
	 *
	 * (see "TODO: Support Reported Frame Body..." below)
	 */

	return sizeof(struct rrm_beacon_report);
}

static bool bss_in_request_range(struct rrm_beacon_req_info *beacon,
					struct scan_bss *bss)
{
	uint8_t channel = band_freq_to_channel(bss->frequency, NULL);

	/* Must be a table measurement */
	if (beacon->channel == 0 || beacon->channel == 255)
		return true;

	if (beacon->channel == channel)
		return true;

	return false;
}

static bool rrm_report_beacon_results(struct rrm_state *rrm,
					struct l_queue *bss_list)
{
	struct rrm_beacon_req_info *beacon = l_container_of(rrm->pending,
						struct rrm_beacon_req_info,
						info);
	bool wildcard = util_is_broadcast_address(beacon->bssid);
	const struct l_queue_entry *entry;
	uint8_t frame[512];
	uint8_t *ptr = frame;

	*ptr++ = 0x05; /* Category: Radio Measurement */
	*ptr++ = 0x01; /* Action: Radio Measurement Report */
	*ptr++ = beacon->info.dialog_token;

	for (entry = l_queue_get_entries(bss_list); entry;
							entry = entry->next) {
		struct scan_bss *bss = entry->data;
		uint8_t report[257];
		size_t report_len;

		/* If request included a specific BSSID match only this BSS */
		if (!wildcard && memcmp(bss->addr, beacon->bssid, 6) != 0)
			continue;

		/* If request was for a certain SSID, match only this SSID */
		if (beacon->has_ssid && strncmp(beacon->ssid,
							(const char *)bss->ssid,
							sizeof(bss->ssid)) != 0)
			continue;

		/*
		 * The kernel may have returned a cached scan, so we have to
		 * sort out any non-matching frequencies before building the
		 * report
		 */
		if (!bss_in_request_range(beacon, bss))
			continue;

		report_len = build_report_for_bss(beacon, bss, report);

		rrm_build_measurement_report(&beacon->info, report,
						report_len, ptr);

		ptr += report_len + 5;
	}

	rrm_info_destroy(&beacon->info);
	rrm->pending = NULL;

	return rrm_send_response(rrm, frame, ptr - frame);
}

static void rrm_handle_beacon_table(struct rrm_state *rrm,
					struct rrm_beacon_req_info *beacon)
{
	struct l_queue *bss_list;

	bss_list = station_get_bss_list(rrm->station);
	if (!bss_list) {
		rrm_reject_measurement_request(rrm, REPORT_REJECT_INCAPABLE);
		return;
	}

	if (!rrm_report_beacon_results(rrm, bss_list))
		l_error("Error reporting beacon table results");
}

static bool rrm_scan_results(int err, struct l_queue *bss_list,
				const struct scan_freq_set *freqs,
				void *userdata)
{
	struct rrm_state *rrm = userdata;
	struct rrm_beacon_req_info *beacon = l_container_of(rrm->pending,
						struct rrm_beacon_req_info,
						info);

	beacon->scan_id = 0;

	l_debug("RRM scan results for %u APs", l_queue_length(bss_list));

	rrm_report_beacon_results(rrm, bss_list);
	/* We aren't saving this BSS list */
	return false;
}

static void rrm_scan_triggered(int err, void *userdata)
{
	struct rrm_state *rrm = userdata;
	struct rrm_beacon_req_info *beacon = l_container_of(rrm->pending,
						struct rrm_beacon_req_info,
						info);

	if (err < 0) {
		l_error("Could not start RRM scan");
		rrm_reject_measurement_request(rrm, REPORT_REJECT_INCAPABLE);
		return;
	}

	beacon->scan_start_time = scan_get_triggered_time(rrm->wdev_id,
							beacon->scan_id);
}

static void rrm_handle_beacon_scan(struct rrm_state *rrm,
					struct rrm_beacon_req_info *beacon,
					bool passive)
{
	struct scan_freq_set *freqs = scan_freq_set_new();
	struct scan_parameters params = {
		.freqs = freqs,
		.flush = true,
		.duration = beacon->duration,
		.duration_mandatory = test_bit(&beacon->info.mode, 4),
	};
	enum band_freq band = band_oper_class_to_band(NULL, beacon->oper_class);
	uint32_t freq;

	freq = band_channel_to_freq(beacon->channel, band);
	scan_freq_set_add(freqs, freq);

	if (!wiphy_constrain_freq_set(wiphy_find_by_wdev(rrm->wdev_id), freqs))
		goto free_freqs;

	if (passive)
		beacon->scan_id = scan_passive_full(rrm->wdev_id, &params,
						rrm_scan_triggered,
						rrm_scan_results, rrm,
						NULL);
	else
		beacon->scan_id = scan_active_full(rrm->wdev_id, &params,
						rrm_scan_triggered,
						rrm_scan_results, rrm,
						NULL);

free_freqs:
	scan_freq_set_free(freqs);

	if (beacon->scan_id)
		return;

	rrm_reject_measurement_request(rrm, REPORT_REJECT_INCAPABLE);
}

static bool rrm_verify_beacon_request(const uint8_t *request, size_t len)
{
	if (len < 13)
		return false;

	if (request[6] != RRM_BEACON_REQ_MODE_TABLE) {
		/*
		 * Rejecting any iterative measurements, only accepting explicit
		 * channels and operating classes except for table measurements.
		 */
		if (request[0] == 0 || request[0] == 255 ||
					request[1] == 0 || request[1] == 255)
			return false;

		/*
		 * Not handling random interval requests. We can omit this
		 * check for table requests since we just return whatever we
		 * have cached.
		 */
		if (!l_memeqzero(request + 2, 2))
			return false;
	}

	/* Check this is a valid operating class */
	if (!band_oper_class_to_band(NULL, request[0]))
		return false;

	return true;
}

static void rrm_handle_beacon_request(struct rrm_state *rrm,
					uint8_t dialog_token,
					const uint8_t *request, size_t len)
{
	struct wiphy *wiphy = station_get_wiphy(rrm->station);
	struct rrm_beacon_req_info *beacon;
	struct ie_tlv_iter iter;
	/*
	 * 802.11-2016 - Table 9-90
	 *
	 * "All fixed-length fields and elements (default, used when Reporting
	 *  Detail subelement is not included in a Beacon request)"
	 */
	uint8_t detail = REPORT_DETAIL_NO_FIELDS_OR_ELEMS;

	beacon = l_new(struct rrm_beacon_req_info, 1);

	beacon->info.dialog_token = dialog_token;
	beacon->info.mtoken = request[0];
	beacon->info.mode = request[1];
	beacon->info.type = request[2];

	rrm->pending = &beacon->info;
	/*
	 * 802.11-2016 11.11.8
	 *
	 * "A STA may also refuse to enable triggered autonomous
	 * reporting. In this case a Measurement Report element shall be
	 * returned to the requesting STA with the refused bit set to 1"
	 *
	 * At least for the time being, we will not support autonomous
	 * reporting, so decline any request to do so.
	 */
	if (test_bit(&beacon->info.mode, 1))
		goto reject_refused;

	/*
	 * Some drivers (non mac80211) do not allow setting a duration/mandatory
	 * bit in scan requests. The actual duration value can be ignored in
	 * this case but if the requests includes the duration mandatory bit we
	 * must reject this request.
	 */
	if (!wiphy_has_ext_feature(wiphy, NL80211_EXT_FEATURE_SET_SCAN_DWELL)
			&& test_bit(&beacon->info.mode, 4))
		goto reject_incapable;

	/* advance to beacon request */
	request += 3;
	len -= 3;

	if (!rrm_verify_beacon_request(request, len))
		goto reject_refused;

	beacon->oper_class = request[0];
	beacon->channel = request[1];
	beacon->duration = l_get_le16(request + 4);
	memcpy(beacon->bssid, request + 7, 6);

	ie_tlv_iter_init(&iter, request + 13, len - 13);

	while (ie_tlv_iter_next(&iter)) {
		uint8_t length = ie_tlv_iter_get_length(&iter);
		const unsigned char *data = ie_tlv_iter_get_data(&iter);

		switch (ie_tlv_iter_get_tag(&iter)) {
		case RRM_BEACON_REQ_SUBELEM_ID_SSID:
			if (beacon->has_ssid)
				continue;
			/*
			 * Zero length is wildcard SSID, which has the same
			 * effect as no SSID.
			 */
			if (length > 0 && length <= 32) {
				memcpy(beacon->ssid, data, length);
				beacon->has_ssid = true;
			}

			break;
		case RRM_BEACON_REQ_SUBELEM_ID_REPORTING_DETAIL:
			if (length < 1) {
				l_error("Invalid length in reporting detail");
				goto reject_refused;
			}

			detail = l_get_u8(data);
			break;
		case RRM_BEACON_REQ_SUBELEM_ID_BEACON_REPORTING:
			if (length < 2) {
				l_error("Invalid length in Beacon Reporting");
				goto reject_refused;
			}

			/*
			 * 802.11-2016 9.4.2.21.7
			 *
			 * "The Beacon reporting subelement is optionally
			 *  present in a Beacon request for repeated
			 *  measurements; otherwise it is not present"
			 *
			 * However, some implementations send an all-zero
			 * Beacon Reporting subelement.  Reporting Condition
			 * of zero is 'default, used when the Beacon Reporting
			 * subelement is not included in a Beacon request).'
			 * Treat such elements as if they're not present.
			 *
			 * Otherwise, since repeated measurements are not
			 * supported we can reject this request now.
			 */
			if (l_get_u8(data) != 0)
				goto reject_incapable;

			break;
		case RRM_BEACON_REQ_SUBELEM_ID_AP_CHAN_REPORT:
			/*
			 * Only supporting single channel requests
			 */
			goto reject_incapable;
		}
	}

	/*
	 * TODO: Support Reported Frame Body of 1 and 2. This requires that all
	 * fixed length fields are available from the scan request. Currently
	 * scan.c parses out only the details we care about. There is also
	 * limitations on length, and some IEs are treated specially and
	 * truncated. This adds quite a bit of complexity. For now skip these
	 * types of frame body reports.
	 */
	if (detail != REPORT_DETAIL_NO_FIELDS_OR_ELEMS) {
		l_debug("Unsupported report detail");
		goto reject_incapable;
	}

	/* Mode */
	switch (request[6]) {
	case RRM_BEACON_REQ_MODE_PASSIVE:
		rrm_handle_beacon_scan(rrm, beacon, true);
		return;
	case RRM_BEACON_REQ_MODE_ACTIVE:
		rrm_handle_beacon_scan(rrm, beacon, false);
		return;
	case RRM_BEACON_REQ_MODE_TABLE:
		rrm_handle_beacon_table(rrm, beacon);
		return;
	default:
		l_error("Unknown beacon mode %u", request[6]);
		/* fall through to refused */
	}

reject_refused:
	rrm_reject_measurement_request(rrm, REPORT_REJECT_REFUSED);
	return;

reject_incapable:
	rrm_reject_measurement_request(rrm, REPORT_REJECT_INCAPABLE);
}

static void rrm_cancel_pending(struct rrm_state *rrm)
{
	if (rrm->pending) {
		struct rrm_beacon_req_info *beacon;

		beacon = l_container_of(rrm->pending,
						struct rrm_beacon_req_info,
						info);
		if (beacon->scan_id)
			scan_cancel(rrm->wdev_id, beacon->scan_id);

		rrm_info_destroy(rrm->pending);
		rrm->pending = NULL;
	}
}

static void rrm_station_watch_cb(enum station_state state, void *userdata)
{
	struct rrm_state *rrm = userdata;

	switch (state) {
	case STATION_STATE_DISCONNECTING:
	case STATION_STATE_DISCONNECTED:
		rrm_cancel_pending(rrm);
		break;
	default:
		return;
	}
}

static void rrm_station_watch_destroy(void *user_data)
{
	struct rrm_state *rrm = user_data;

	l_debug("");

	rrm_cancel_pending(rrm);
	rrm->watch_id = 0;
	rrm->station = NULL;
}

static void rrm_frame_watch_cb(const struct mmpdu_header *mpdu,
				const void *body, size_t body_len,
				int rssi, void *user_data)
{
	struct rrm_state *rrm = user_data;
	const uint8_t *request = body;
	uint8_t dialog_token;
	struct ie_tlv_iter iter;
	struct scan_bss *bss;

	if (!rrm->station) {
		/*
		 * Most likely this is the first RRM request, find the station
		 * interface and save it off for future use
		 */
		rrm->station = station_find(rrm->ifindex);

		if (!rrm->station) {
			l_error("station interface could not be found");
			return;
		}

		rrm->watch_id = station_add_state_watch(rrm->station,
						rrm_station_watch_cb, rrm,
						rrm_station_watch_destroy);
	}

	/*
	 * Ignore if not connected or already have an outstanding request
	 */
	if (station_get_state(rrm->station) != STATION_STATE_CONNECTED ||
				rrm->pending)
		return;

	bss = station_get_connected_bss(rrm->station);

	if (memcmp(bss->addr, mpdu->address_2, 6))
		return;

	if (body_len < 5)
		return;

	if (request[0] != 0x05)
		return;

	if (request[1] != 0x00)
		return;

	/*
	 * We have reached our max requests per second, no point in continuing
	 */
	if (l_time_now() - rrm->last_request < MIN_MICROS_BETWEEN_REQUESTS) {
		l_debug("Max requests per second reached, ignoring request");
		return;
	}

	dialog_token = request[2];

	/* Update time regardless of success */
	rrm->last_request = l_time_now();

	ie_tlv_iter_init(&iter, request + 5, body_len - 5);

	while (ie_tlv_iter_next(&iter)) {
		const uint8_t *req;
		size_t req_len;

		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_MEASUREMENT_REQUEST)
			continue;

		req = ie_tlv_iter_get_data(&iter);
		req_len = ie_tlv_iter_get_length(&iter);

		if (req_len < 3)
			return;

		switch (req[2]) {
		case 5: /* beacon */
			rrm_handle_beacon_request(rrm, dialog_token, req,
							req_len);
			break;
		default:
			return;
		}
	}
}

static void rrm_state_destroy(void *data)
{
	struct rrm_state *rrm = data;

	l_warn("RRM states still exist on exit!");

	l_free(rrm);
}

static void rrm_add_frame_watches(struct rrm_state *rrm)
{
	static const uint16_t frame_type = 0x00d0;
	static const uint8_t prefix[] = { 0x05, 0x00 };

	l_debug("");

	frame_watch_add(rrm->wdev_id, 0, frame_type, prefix, sizeof(prefix),
					rrm_frame_watch_cb, rrm, NULL);
}

static struct rrm_state *rrm_new_state(struct netdev *netdev)
{
	struct rrm_state *rrm;

	rrm = l_new(struct rrm_state, 1);

	rrm->last_request = l_time_now();
	rrm->ifindex = netdev_get_ifindex(netdev);
	rrm->wdev_id = netdev_get_wdev_id(netdev);

	l_queue_push_head(states, rrm);

	return rrm;
}

static bool match_ifindex(const void *a, const void *b)
{
	const struct rrm_state *rrm = a;
	uint32_t ifindex = L_PTR_TO_UINT(b);

	return rrm->ifindex == ifindex;
}

static void rrm_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *user_data)
{
	struct rrm_state *rrm;
	uint32_t ifindex = netdev_get_ifindex(netdev);

	switch (event) {
	case NETDEV_WATCH_EVENT_NEW:
		rrm = rrm_new_state(netdev);

		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_STATION)
			rrm_add_frame_watches(rrm);

		break;
	case NETDEV_WATCH_EVENT_DEL:
		/*
		 * This event is triggered by the netdev being removed, which
		 * causes all frame watches to be unregistered by the kernel.
		 * Given the above, there's no need to unregister anything
		 * manually.
		 */
		rrm = l_queue_remove_if(states, match_ifindex,
						L_UINT_TO_PTR(ifindex));
		if (rrm) {
			if (rrm->station && rrm->watch_id)
				station_remove_state_watch(rrm->station,
								rrm->watch_id);

			l_free(rrm);
		}

		break;
	case NETDEV_WATCH_EVENT_IFTYPE_CHANGE:
		rrm = l_queue_find(states, match_ifindex,
						L_UINT_TO_PTR(ifindex));

		if (rrm && netdev_get_iftype(netdev) == NETDEV_IFTYPE_STATION)
			rrm_add_frame_watches(rrm);

		break;
	default:
		break;
	}
}

static int rrm_init(void)
{
	struct l_genl *genl = iwd_get_genl();

	states = l_queue_new();

	nl80211 = l_genl_family_new(genl, NL80211_GENL_NAME);

	netdev_watch = netdev_watch_add(rrm_netdev_watch, NULL, NULL);

	return 0;
}

static void rrm_exit(void)
{
	l_genl_family_free(nl80211);
	nl80211 = NULL;

	netdev_watch_remove(netdev_watch);

	l_queue_destroy(states, rrm_state_destroy);
}

IWD_MODULE(rrm, rrm_init, rrm_exit);
IWD_MODULE_DEPENDS(rrm, netdev);
IWD_MODULE_DEPENDS(rrm, frame_xchg);
