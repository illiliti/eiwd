/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2014-2019  Intel Corporation. All rights reserved.
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

#include <limits.h>
#include <errno.h>

#include <ell/ell.h>

#include "src/ie.h"
#include "src/mpdu.h"

/* 802.11-2020 section 9.3.3.5 */
static const enum ie_type association_request_ie_order[] = {
	IE_TYPE_SSID,
	IE_TYPE_SUPPORTED_RATES,
	IE_TYPE_EXTENDED_SUPPORTED_RATES,
	IE_TYPE_POWER_CAPABILITY,
	IE_TYPE_SUPPORTED_CHANNELS,
	IE_TYPE_RSN,
	IE_TYPE_QOS_CAPABILITY,
	IE_TYPE_RM_ENABLED_CAPABILITIES,
	IE_TYPE_MOBILITY_DOMAIN,
	IE_TYPE_SUPPORTED_OPERATING_CLASSES,
	IE_TYPE_HT_CAPABILITIES,
	IE_TYPE_BSS_COEXISTENCE,
	IE_TYPE_EXTENDED_CAPABILITIES,
	IE_TYPE_QOS_TRAFFIC_CAPABILITY,
	IE_TYPE_TIM_BROADCAST_REQUEST,
	IE_TYPE_INTERWORKING,
	IE_TYPE_MULTIBAND,
	IE_TYPE_DMG_CAPABILITIES,
	IE_TYPE_MULTIPLE_MAC_SUBLAYERS,
	IE_TYPE_VHT_CAPABILITIES,
	IE_TYPE_OPERATING_MODE_NOTIFICATION,
	IE_TYPE_FILS_SESSION,
	IE_TYPE_FILS_PUBLIC_KEY,
	IE_TYPE_FILS_KEY_CONFIRMATION,
	IE_TYPE_FILS_HLP_CONTAINER,
	IE_TYPE_FILS_IP_ADDRESS,
	IE_TYPE_TWT,
	IE_TYPE_AID_REQUEST,
	IE_TYPE_S1G_CAPABILITIES,
	IE_TYPE_EL_OPERATION,
	IE_TYPE_S1G_RELAY,
	IE_TYPE_BSS_MAX_IDLE_PERIOD,
	IE_TYPE_HEADER_COMPRESSION,
	IE_TYPE_MAD,
	IE_TYPE_REACHABLE_ADDRESS,
	IE_TYPE_S1G_RELAY_ACTIVATION,
	IE_TYPE_CDMG_CAPABILITIES,
	IE_TYPE_CMMG_CAPABILITIES,
	IE_TYPE_GLK_GCR_PARAMETER_SET,
	IE_TYPE_FAST_BSS_TRANSITION,
	IE_TYPE_RSNX,
	IE_TYPE_SUPPLEMENTAL_CLASS_2_CAPABILITIES,
	IE_TYPE_MSCS_DESCRIPTOR,
	IE_TYPE_VENDOR_SPECIFIC,
};

/* 802.11-2020 section 9.3.3.6 */
static const enum ie_type association_response_ie_order[] = {
	IE_TYPE_AID,
	IE_TYPE_SUPPORTED_RATES,
	IE_TYPE_EXTENDED_SUPPORTED_RATES,
	IE_TYPE_EDCA_PARAMETER_SET,
	IE_TYPE_RCPI,
	IE_TYPE_RSNI,
	IE_TYPE_RM_ENABLED_CAPABILITIES,
	IE_TYPE_RSN,
	IE_TYPE_MOBILITY_DOMAIN,
	IE_TYPE_FAST_BSS_TRANSITION,
	IE_TYPE_DSE_REGISTERED_LOCATION,
	IE_TYPE_TIMEOUT_INTERVAL,
	IE_TYPE_HT_CAPABILITIES,
	IE_TYPE_HT_OPERATION,
	IE_TYPE_BSS_COEXISTENCE,
	IE_TYPE_OVERLAPPING_BSS_SCAN_PARAMETERS,
	IE_TYPE_EXTENDED_CAPABILITIES,
	IE_TYPE_BSS_MAX_IDLE_PERIOD,
	IE_TYPE_TIM_BROADCAST_RESPONSE,
	IE_TYPE_QOS_MAP_SET,
	IE_TYPE_QMF_POLICY,
	IE_TYPE_MULTIBAND,
	IE_TYPE_DMG_CAPABILITIES,
	IE_TYPE_DMG_OPERATION,
	IE_TYPE_MULTIPLE_MAC_SUBLAYERS,
	IE_TYPE_NEIGHBOR_REPORT,
	IE_TYPE_VHT_CAPABILITIES,
	IE_TYPE_VHT_OPERATION,
	IE_TYPE_OPERATING_MODE_NOTIFICATION,
	IE_TYPE_FUTURE_CHANNEL_GUIDANCE,
	IE_TYPE_FILS_SESSION,
	IE_TYPE_FILS_PUBLIC_KEY,
	IE_TYPE_FILS_KEY_CONFIRMATION,
	IE_TYPE_FILS_HLP_CONTAINER,
	IE_TYPE_FILS_IP_ADDRESS,
	IE_TYPE_KEY_DELIVERY,
	IE_TYPE_S1G_SECTOR_OPERATION,
	IE_TYPE_TWT,
	IE_TYPE_TSF_TIMER_ACCURACY,
	IE_TYPE_S1G_CAPABILITIES,
	IE_TYPE_S1G_OPERATION,
	IE_TYPE_AID_RESPONSE,
	IE_TYPE_SECTORIZED_GROUP_ID_LIST,
	IE_TYPE_S1G_RELAY,
	IE_TYPE_HEADER_COMPRESSION,
	IE_TYPE_SST_OPERATION,
	IE_TYPE_MAD,
	IE_TYPE_S1G_RELAY_ACTIVATION,
	IE_TYPE_CDMG_CAPABILITIES,
	IE_TYPE_CMMG_CAPABILITIES,
	IE_TYPE_CMMG_OPERATION,
	IE_TYPE_GLK_GCR_PARAMETER_SET,
	IE_TYPE_RSNX,
	IE_TYPE_MSCS_DESCRIPTOR,
	IE_TYPE_VENDOR_SPECIFIC,
};

/* 802.11-2020 section 9.3.3.7 */
static const enum ie_type reassociation_request_ie_order[] = {
	IE_TYPE_SSID,
	IE_TYPE_SUPPORTED_RATES,
	IE_TYPE_EXTENDED_SUPPORTED_RATES,
	IE_TYPE_POWER_CAPABILITY,
	IE_TYPE_SUPPORTED_CHANNELS,
	IE_TYPE_RSN,
	IE_TYPE_QOS_CAPABILITY,
	IE_TYPE_RM_ENABLED_CAPABILITIES,
	IE_TYPE_MOBILITY_DOMAIN,
	IE_TYPE_FAST_BSS_TRANSITION,
	IE_TYPE_RIC_DATA,
	IE_TYPE_SUPPORTED_OPERATING_CLASSES,
	IE_TYPE_HT_CAPABILITIES,
	IE_TYPE_BSS_COEXISTENCE,
	IE_TYPE_EXTENDED_CAPABILITIES,
	IE_TYPE_QOS_TRAFFIC_CAPABILITY,
	IE_TYPE_TIM_BROADCAST_REQUEST,
	IE_TYPE_FMS_REQUEST,
	IE_TYPE_DMS_REQUEST,
	IE_TYPE_INTERWORKING,
	IE_TYPE_MULTIBAND,
	IE_TYPE_DMG_CAPABILITIES,
	IE_TYPE_MULTIPLE_MAC_SUBLAYERS,
	IE_TYPE_VHT_CAPABILITIES,
	IE_TYPE_OPERATING_MODE_NOTIFICATION,
	IE_TYPE_FILS_SESSION,
	IE_TYPE_FILS_PUBLIC_KEY,
	IE_TYPE_FILS_KEY_CONFIRMATION,
	IE_TYPE_FILS_HLP_CONTAINER,
	IE_TYPE_FILS_IP_ADDRESS,
	IE_TYPE_TWT,
	IE_TYPE_AID_REQUEST,
	IE_TYPE_S1G_CAPABILITIES,
	IE_TYPE_EL_OPERATION,
	IE_TYPE_BSS_MAX_IDLE_PERIOD,
	IE_TYPE_S1G_RELAY,
	IE_TYPE_HEADER_COMPRESSION,
	IE_TYPE_MAD,
	IE_TYPE_REACHABLE_ADDRESS,
	IE_TYPE_S1G_RELAY_ACTIVATION,
	IE_TYPE_CDMG_CAPABILITIES,
	IE_TYPE_CMMG_CAPABILITIES,
	IE_TYPE_OCI,
	IE_TYPE_GLK_GCR_PARAMETER_SET,
	IE_TYPE_RSNX,
	IE_TYPE_SUPPLEMENTAL_CLASS_2_CAPABILITIES,
	IE_TYPE_MSCS_DESCRIPTOR,
	IE_TYPE_VENDOR_SPECIFIC,
};

/* 802.11-2020 section 9.3.3.8 */
static const enum ie_type reassociation_response_ie_order[] = {
	IE_TYPE_AID,
	IE_TYPE_SUPPORTED_RATES,
	IE_TYPE_EXTENDED_SUPPORTED_RATES,
	IE_TYPE_EDCA_PARAMETER_SET,
	IE_TYPE_RCPI,
	IE_TYPE_RSNI,
	IE_TYPE_RM_ENABLED_CAPABILITIES,
	IE_TYPE_RSN,
	IE_TYPE_MOBILITY_DOMAIN,
	IE_TYPE_FAST_BSS_TRANSITION,
	IE_TYPE_RIC_DATA,
	IE_TYPE_DSE_REGISTERED_LOCATION,
	IE_TYPE_TIMEOUT_INTERVAL,
	IE_TYPE_HT_CAPABILITIES,
	IE_TYPE_HT_OPERATION,
	IE_TYPE_BSS_COEXISTENCE,
	IE_TYPE_OVERLAPPING_BSS_SCAN_PARAMETERS,
	IE_TYPE_EXTENDED_CAPABILITIES,
	IE_TYPE_BSS_MAX_IDLE_PERIOD,
	IE_TYPE_TIM_BROADCAST_RESPONSE,
	IE_TYPE_FMS_RESPONSE,
	IE_TYPE_DMS_RESPONSE,
	IE_TYPE_QOS_MAP_SET,
	IE_TYPE_QMF_POLICY,
	IE_TYPE_MULTIBAND,
	IE_TYPE_DMG_CAPABILITIES,
	IE_TYPE_DMG_OPERATION,
	IE_TYPE_MULTIPLE_MAC_SUBLAYERS,
	IE_TYPE_NEIGHBOR_REPORT,
	IE_TYPE_VHT_CAPABILITIES,
	IE_TYPE_VHT_OPERATION,
	IE_TYPE_OPERATING_MODE_NOTIFICATION,
	IE_TYPE_FUTURE_CHANNEL_GUIDANCE,
	IE_TYPE_FILS_SESSION,
	IE_TYPE_FILS_PUBLIC_KEY,
	IE_TYPE_FILS_KEY_CONFIRMATION,
	IE_TYPE_FILS_HLP_CONTAINER,
	IE_TYPE_FILS_IP_ADDRESS,
	IE_TYPE_KEY_DELIVERY,
	IE_TYPE_S1G_SECTOR_OPERATION,
	IE_TYPE_TWT,
	IE_TYPE_TSF_TIMER_ACCURACY,
	IE_TYPE_S1G_CAPABILITIES,
	IE_TYPE_S1G_OPERATION,
	IE_TYPE_AID_RESPONSE,
	IE_TYPE_SECTORIZED_GROUP_ID_LIST,
	IE_TYPE_S1G_RELAY,
	IE_TYPE_HEADER_COMPRESSION,
	IE_TYPE_SST_OPERATION,
	IE_TYPE_MAD,
	IE_TYPE_S1G_RELAY_ACTIVATION,
	IE_TYPE_CDMG_CAPABILITIES,
	IE_TYPE_CMMG_CAPABILITIES,
	IE_TYPE_CMMG_OPERATION,
	IE_TYPE_OCI,
	IE_TYPE_GLK_GCR_PARAMETER_SET,
	IE_TYPE_RSNX,
	IE_TYPE_MSCS_DESCRIPTOR,
	IE_TYPE_VENDOR_SPECIFIC,
};

/* 802.11-2020 section 9.3.3.9 */
static const enum ie_type probe_request_ie_order[] = {
	IE_TYPE_SSID,
	IE_TYPE_SUPPORTED_RATES,
	IE_TYPE_REQUEST,
	IE_TYPE_EXTENDED_SUPPORTED_RATES,
	IE_TYPE_DSSS_PARAMETER_SET,
	IE_TYPE_SUPPORTED_OPERATING_CLASSES,
	IE_TYPE_HT_CAPABILITIES,
	IE_TYPE_BSS_COEXISTENCE,
	IE_TYPE_EXTENDED_CAPABILITIES,
	IE_TYPE_SSID_LIST,
	IE_TYPE_CHANNEL_USAGE,
	IE_TYPE_INTERWORKING,
	IE_TYPE_MESH_ID,
	IE_TYPE_MULTIBAND,
	IE_TYPE_DMG_CAPABILITIES,
	IE_TYPE_MULTIPLE_MAC_SUBLAYERS,
	IE_TYPE_VHT_CAPABILITIES,
	IE_TYPE_ESTIMATED_SERVICE_PARAMETERS,
	IE_TYPE_EXTENDED_REQUEST,
	IE_TYPE_FILS_REQUEST_PARAMETERS,
	IE_TYPE_AP_CSN,
	IE_TYPE_CHANGE_SEQUENCE,
	IE_TYPE_S1G_RELAY_DISCOVERY,
	IE_TYPE_PV1_PROBE_RESPONSE_OPTION,
	IE_TYPE_S1G_CAPABILITIES,
	IE_TYPE_EL_OPERATION,
	IE_TYPE_MAD,
	IE_TYPE_VENDOR_SPECIFIC_REQUEST,
	IE_TYPE_CDMG_CAPABILITIES,
	IE_TYPE_CLUSTER_PROBE,
	IE_TYPE_CMMG_CAPABILITIES,
	IE_TYPE_ESTIMATED_SERVICE_PARAMETERS_OUT,
	IE_TYPE_SUPPLEMENTAL_CLASS_2_CAPABILITIES,
	IE_TYPE_VENDOR_SPECIFIC,
};

static bool validate_mgmt_header(const struct mmpdu_header *mpdu,
					int len, int *offset)
{
	/* Duration + Address1 + Address 2 + Address 3 + SeqCntrl */
	if (len < *offset + 22)
		return false;

	*offset += 22;

	if (!mpdu->fc.order)
		return true;

	if (len < *offset + 4)
		return false;

	*offset += 4;

	return true;
}

/* 802.11-2016 13.11.2 */
static bool skip_resource_req_resp(struct ie_tlv_iter *iter)
{
	struct ie_tlv_iter tmp;

	/*
	 * This is called when we've seen an RDE so we only need to validate
	 * and skip IEs representing one or more Resource Descriptors up to
	 * the end of this Resource Request or Resource Response.
	 *
	 * Since the Resource Descriptor specification is complex and,
	 * especially in the case of a Vendor Specific descriptor and
	 * in the case of a Resource Response to a failed request (with
	 * the optional information), there seems to be no strict definition
	 * of where one request/response ends and the next begins, allow
	 * any combination of any of the IEs listed in 13.11.2 until an
	 * IE that doesn't seem to be part of this RDE.
	 */

	memcpy(&tmp, iter, sizeof(tmp));

	while (ie_tlv_iter_next(&tmp)) {
		switch (ie_tlv_iter_get_tag(&tmp)) {
		case IE_TYPE_TSPEC:
		case IE_TYPE_TCLAS:
		case IE_TYPE_TCLAS_PROCESSING:
		case IE_TYPE_EXPEDITED_BANDWIDTH_REQUEST:
		case IE_TYPE_SCHEDULE:
		case IE_TYPE_TS_DELAY:
		case IE_TYPE_RIC_DESCRIPTOR:
		case IE_TYPE_VENDOR_SPECIFIC:
			memcpy(iter, &tmp, sizeof(tmp));
			continue;
		default:
			break;
		}
		break;
	}

	return true;
}

static bool validate_mgmt_ies(const uint8_t *ies, size_t ies_len,
				const enum ie_type tag_order[], int tag_count)
{
	struct ie_tlv_iter iter;
	enum ie_type tag;

	ie_tlv_iter_init(&iter, ies, ies_len);

	while (ie_tlv_iter_next(&iter)) {
		int i = 0;
		tag = ie_tlv_iter_get_tag(&iter);

		/* Check that the tag is part of the valid set */
		while (i < tag_count && tag_order[i] != tag)
			i += 1;

		/*
		 * 802.11-2016 section 9.3.3.2:
		 * "All fields and elements are mandatory unless stated
		 * otherwise and appear in the specified, relative order.
		 * STAs that encounter an element ID they do not recognize
		 * in the frame body of a received Management frame ignore
		 * that element and continue to parse the remainder of the
		 * management frame body (if any) for additional elements
		 * with recognizable element IDs."
		 */
		if (i == tag_count)
			continue;

		/* Tag found, make sure no duplicates present unless allowed */
		if (tag != IE_TYPE_VENDOR_SPECIFIC &&
				tag != IE_TYPE_RIC_DATA &&
				tag != IE_TYPE_TRANSMIT_POWER_ENVELOPE &&
				tag != IE_TYPE_MCCAOP_ADVERTISEMENT &&
				tag != IE_TYPE_EMERGENCY_ALERT_IDENTIFIER &&
				tag != IE_TYPE_MULTIPLE_BSSID &&
				tag != IE_TYPE_NEIGHBOR_REPORT &&
				tag != IE_TYPE_QUIET_CHANNEL &&
				tag != IE_TYPE_FILS_HLP_CONTAINER) {
			struct ie_tlv_iter clone;

			memcpy(&clone, &iter, sizeof(clone));

			while (ie_tlv_iter_next(&clone)) {
				if (ie_tlv_iter_get_tag(&clone) != tag)
					continue;

				return false;
			}
		}

		if (tag == IE_TYPE_RIC_DATA && !skip_resource_req_resp(&iter))
			return false;
	}

	return true;
}

static bool validate_association_request_mmpdu(const struct mmpdu_header *mpdu,
						int len, int *offset)
{
	const struct mmpdu_association_request *body =
		(const void *) mpdu + *offset;

	if (len < *offset + (int) sizeof(struct mmpdu_association_request))
		return false;

	*offset += sizeof(struct mmpdu_association_request);

	return validate_mgmt_ies(body->ies, len - *offset,
				association_request_ie_order,
				L_ARRAY_SIZE(association_request_ie_order));
}

static bool validate_association_response_mmpdu(const struct mmpdu_header *mpdu,
						int len, int *offset)
{
	const struct mmpdu_association_response *body =
		(const void *) mpdu + *offset;

	if (len < *offset + (int) sizeof(struct mmpdu_association_response))
		return false;

	*offset += sizeof(struct mmpdu_association_response);

	return validate_mgmt_ies(body->ies, len - *offset,
				association_response_ie_order,
				L_ARRAY_SIZE(association_response_ie_order));
}

static bool validate_reassociation_request_mmpdu(
						const struct mmpdu_header *mpdu,
						int len, int *offset)
{
	const struct mmpdu_reassociation_request *body =
		(const void *) mpdu + *offset;

	if (len < *offset + (int) sizeof(struct mmpdu_reassociation_request))
		return false;

	*offset += sizeof(struct mmpdu_reassociation_request);

	return validate_mgmt_ies(body->ies, len - *offset,
				reassociation_request_ie_order,
				L_ARRAY_SIZE(reassociation_request_ie_order));
}

static bool validate_reassociation_response_mmpdu(
						const struct mmpdu_header *mpdu,
						int len, int *offset)
{
	const struct mmpdu_reassociation_response *body =
		(const void *) mpdu + *offset;

	if (len < *offset + (int) sizeof(struct mmpdu_reassociation_response))
		return false;

	*offset += sizeof(struct mmpdu_reassociation_response);

	return validate_mgmt_ies(body->ies, len - *offset,
				reassociation_response_ie_order,
				L_ARRAY_SIZE(reassociation_response_ie_order));
}

static bool validate_probe_request_mmpdu(const struct mmpdu_header *mpdu,
						int len, int *offset)
{
	const struct mmpdu_probe_request *body = (const void *) mpdu + *offset;

	if (len < *offset + (int) sizeof(struct mmpdu_probe_request))
		return false;

	*offset += sizeof(struct mmpdu_probe_request);

	return validate_mgmt_ies(body->ies, len - *offset,
				probe_request_ie_order,
				L_ARRAY_SIZE(probe_request_ie_order));
}

/* 802.11-2016 section 9.3.3.11 */
static bool validate_probe_response_mmpdu(const struct mmpdu_header *mpdu,
						int len, int *offset)
{
	/*
	 * If this is a response to a frame that could have contained a
	 * Request or an Extended Request element, then, after all of the
	 * "Elements that would have been included even in the absence of
	 * the Request element or Extended Request element" (802.11-2016
	 * section 11.1.4.3.5) basically any Element ID may appear with the
	 * only requirement being an ascending order of the numerical values
	 * of the IDs.
	 *
	 * Given the above, and the fact that nobody on the planet seems
	 * to order IEs properly inside the Management frames, we simply skip
	 * any checking here and return true.
	 */

	return true;
}

/* 802.11-2020 section 9.3.3.15 */
static bool validate_timing_advertisement_mmpdu(const struct mmpdu_header *mpdu,
						int len, int *offset)
{
	const struct mmpdu_timing_advertisement *body =
		(const void *) mpdu + *offset;
	static const enum ie_type ie_order[] = {
		IE_TYPE_COUNTRY,
		IE_TYPE_POWER_CONSTRAINT,
		IE_TYPE_TIME_ADVERTISEMENT,
		IE_TYPE_EXTENDED_CAPABILITIES,
		IE_TYPE_VENDOR_SPECIFIC,
	};

	if (len < *offset + (int) sizeof(struct mmpdu_timing_advertisement))
		return false;

	*offset += sizeof(struct mmpdu_timing_advertisement);

	return validate_mgmt_ies(body->ies, len - *offset, ie_order,
					L_ARRAY_SIZE(ie_order));
}

/* 802.11-2020 section 9.3.3.2 */
static bool validate_beacon_mmpdu(const struct mmpdu_header *mpdu,
					int len, int *offset)
{
	const struct mmpdu_beacon *body = (const void *) mpdu + *offset;
	static const enum ie_type ie_order[] = {
		IE_TYPE_SSID,
		IE_TYPE_SUPPORTED_RATES,
		IE_TYPE_DSSS_PARAMETER_SET,
		IE_TYPE_CF_PARAMETER_SET,
		IE_TYPE_IBSS_PARAMETER_SET,
		IE_TYPE_TIM,
		IE_TYPE_COUNTRY,
		IE_TYPE_POWER_CONSTRAINT,
		IE_TYPE_CHANNEL_SWITCH_ANNOUNCEMENT,
		IE_TYPE_QUIET,
		IE_TYPE_IBSS_DFS,
		IE_TYPE_TPC_REPORT,
		IE_TYPE_ERP,
		IE_TYPE_EXTENDED_SUPPORTED_RATES,
		IE_TYPE_RSN,
		IE_TYPE_BSS_LOAD,
		IE_TYPE_EDCA_PARAMETER_SET,
		IE_TYPE_QOS_CAPABILITY,
		IE_TYPE_AP_CHANNEL_REPORT,
		IE_TYPE_BSS_AVERAGE_ACCESS_DELAY,
		IE_TYPE_ANTENNA,
		IE_TYPE_BSS_AVAILABLE_ADMISSION_CAPACITY,
		IE_TYPE_BSS_AC_ACCESS_DELAY,
		IE_TYPE_MEASUREMENT_PILOT_TRANSMISSION,
		IE_TYPE_MULTIPLE_BSSID,
		IE_TYPE_RM_ENABLED_CAPABILITIES,
		IE_TYPE_MOBILITY_DOMAIN,
		IE_TYPE_DSE_REGISTERED_LOCATION,
		IE_TYPE_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT,
		IE_TYPE_SUPPORTED_OPERATING_CLASSES,
		IE_TYPE_HT_CAPABILITIES,
		IE_TYPE_HT_OPERATION,
		IE_TYPE_BSS_COEXISTENCE,
		IE_TYPE_OVERLAPPING_BSS_SCAN_PARAMETERS,
		IE_TYPE_EXTENDED_CAPABILITIES,
		IE_TYPE_FMS_DESCRIPTOR,
		IE_TYPE_QOS_TRAFFIC_CAPABILITY,
		IE_TYPE_TIME_ADVERTISEMENT,
		IE_TYPE_INTERWORKING,
		IE_TYPE_ADVERTISEMENT_PROTOCOL,
		IE_TYPE_ROAMING_CONSORTIUM,
		IE_TYPE_EMERGENCY_ALERT_IDENTIFIER,
		IE_TYPE_MESH_ID,
		IE_TYPE_MESH_CONFIGURATION,
		IE_TYPE_MESH_AWAKE_WINDOW,
		IE_TYPE_BEACON_TIMING,
		IE_TYPE_MCCAOP_ADVERTISEMENT_OVERVIEW,
		IE_TYPE_MCCAOP_ADVERTISEMENT,
		IE_TYPE_MESH_CHANNEL_SWITCH_PARAMETERS,
		IE_TYPE_QMF_POLICY,
		IE_TYPE_QLOAD_REPORT,
		IE_TYPE_HCCA_TXOP_UPDATE_COUNT,
		IE_TYPE_MULTIBAND,
		IE_TYPE_VHT_CAPABILITIES,
		IE_TYPE_VHT_OPERATION,
		IE_TYPE_TRANSMIT_POWER_ENVELOPE,
		IE_TYPE_CHANNEL_SWITCH_WRAPPER,
		IE_TYPE_EXTENDED_BSS_LOAD,
		IE_TYPE_QUIET_CHANNEL,
		IE_TYPE_OPERATING_MODE_NOTIFICATION,
		IE_TYPE_REDUCED_NEIGHBOR_REPORT,
		IE_TYPE_TVHT_OPERATION,
		IE_TYPE_ESTIMATED_SERVICE_PARAMETERS,
		IE_TYPE_FUTURE_CHANNEL_GUIDANCE,
		IE_TYPE_CAG_NUMBER,
		IE_TYPE_FILS_INDICATION,
		IE_TYPE_AP_CSN,
		IE_TYPE_DILS,
		IE_TYPE_MAX_CHANNEL_SWITCH_TIME,
		IE_TYPE_ESTIMATED_SERVICE_PARAMETERS_OUT,
		IE_TYPE_SERVICE_HINT,
		IE_TYPE_SERVICE_HASH,
		IE_TYPE_RSNX,
		IE_TYPE_VENDOR_SPECIFIC,
	};

	if (len < *offset + (int) sizeof(struct mmpdu_beacon))
		return false;

	*offset += sizeof(struct mmpdu_beacon);

	return validate_mgmt_ies(body->ies, len - *offset, ie_order,
					L_ARRAY_SIZE(ie_order));
}

static bool validate_atim_mmpdu(const struct mmpdu_header *mpdu,
				int len, int *offset)
{
	return *offset == len;
}

static bool validate_disassociation_mmpdu(const struct mmpdu_header *mpdu,
						int len, int *offset)
{
	*offset += 2;
	return *offset <= len;
}

static bool validate_authentication_mmpdu(const struct mmpdu_header *mpdu,
						int len, int *offset)
{
	uint16_t transaction_sequence;
	const struct mmpdu_authentication *body = (const void *) mpdu + *offset;
	static const enum ie_type ie_order_shared_key[] = {
		IE_TYPE_CHALLENGE_TEXT,
		IE_TYPE_MULTIBAND,
		IE_TYPE_VENDOR_SPECIFIC,
	};
	static const enum ie_type ie_order_ft[] = {
		IE_TYPE_RSN,
		IE_TYPE_MOBILITY_DOMAIN,
		IE_TYPE_FAST_BSS_TRANSITION,
		IE_TYPE_TIMEOUT_INTERVAL,
		IE_TYPE_RIC_DATA,
		IE_TYPE_FAST_BSS_TRANSITION,
		IE_TYPE_MULTIBAND,
		IE_TYPE_VENDOR_SPECIFIC,
	};
	static const enum ie_type ie_order_error[] = {
		IE_TYPE_NEIGHBOR_REPORT,
		IE_TYPE_VENDOR_SPECIFIC,
	};
	static const enum ie_type ie_order_fils[] = {
		IE_TYPE_FILS_SESSION,
		IE_TYPE_FILS_WRAPPED_DATA,
	};

	if (len < *offset + 6)
		return false;

	*offset += 6;

	if (L_LE16_TO_CPU(L_LE16_TO_CPU(body->status)) != 0)
		return validate_mgmt_ies(body->ies, len - *offset,
						ie_order_error,
						L_ARRAY_SIZE(ie_order_error));

	switch (L_LE16_TO_CPU(body->algorithm)) {
	case MMPDU_AUTH_ALGO_OPEN_SYSTEM:
		return *offset <= len;
	case MMPDU_AUTH_ALGO_SHARED_KEY:
		transaction_sequence =
			L_LE16_TO_CPU(body->transaction_sequence);

		if (transaction_sequence < 2 || transaction_sequence > 3)
			return *offset <= len;

		return validate_mgmt_ies(body->ies, len - *offset,
					ie_order_shared_key,
					L_ARRAY_SIZE(ie_order_shared_key));
	case MMPDU_AUTH_ALGO_FT:
		return validate_mgmt_ies(body->ies, len - *offset, ie_order_ft,
						L_ARRAY_SIZE(ie_order_ft));
	case MMPDU_AUTH_ALGO_SAE:
		return *offset <= len;
	case MMPDU_AUTH_ALGO_FILS_SK:
	case MMPDU_AUTH_ALGO_FILS_SK_PFS:
		return validate_mgmt_ies(body->ies, len - *offset,
						ie_order_fils,
						L_ARRAY_SIZE(ie_order_fils));
	default:
		return false;
	}

	return false;
}

static bool validate_deauthentication_mmpdu(const struct mmpdu_header *mpdu,
						int len, int *offset)
{
	*offset += 2;
	return *offset <= len;
}

static bool validate_mgmt_mpdu(const struct mmpdu_header *mpdu, int len,
				int *offset)
{
	if (!validate_mgmt_header(mpdu, len, offset))
		return false;

	switch (mpdu->fc.subtype) {
	case MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST:
		return validate_association_request_mmpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_RESPONSE:
		return validate_association_response_mmpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_REQUEST:
		return validate_reassociation_request_mmpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_RESPONSE:
		return validate_reassociation_response_mmpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_PROBE_REQUEST:
		return validate_probe_request_mmpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_PROBE_RESPONSE:
		return validate_probe_response_mmpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_TIMING_ADVERTISEMENT:
		return validate_timing_advertisement_mmpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_BEACON:
		return validate_beacon_mmpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_ATIM:
		return validate_atim_mmpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_DISASSOCIATION:
		return validate_disassociation_mmpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION:
		return validate_authentication_mmpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION:
		return validate_deauthentication_mmpdu(mpdu, len, offset);
	case MPDU_MANAGEMENT_SUBTYPE_ACTION:
	case MPDU_MANAGEMENT_SUBTYPE_ACTION_NO_ACK:
		return *offset + 1 <= len;
	default:
		return false;
	}

	return true;
}

const struct mmpdu_header *mpdu_validate(const uint8_t *frame, int len)
{
	const struct mpdu_fc *fc;
	const struct mmpdu_header *mmpdu;
	int offset;

	if (!frame)
		return NULL;

	if (len < 2)
		return NULL;

	offset = 2;
	fc = (const struct mpdu_fc *) frame;

	switch (fc->type) {
	case MPDU_TYPE_MANAGEMENT:
		mmpdu = (const struct mmpdu_header *) frame;

		if (validate_mgmt_mpdu(mmpdu, len, &offset))
			return mmpdu;

		return NULL;
	default:
		return NULL;
	}
}

size_t mmpdu_header_len(const struct mmpdu_header *mmpdu)
{
	return mmpdu->fc.order == 0 ? 24 : 28;
}

const void *mmpdu_body(const struct mmpdu_header *mmpdu)
{
	return ((const uint8_t *) mmpdu + mmpdu_header_len(mmpdu));
}

struct ie_sort_info {
	const enum ie_type *ie_order;
	size_t n_elem;
};

static struct ie_sort_info sortinfo;

static unsigned int ie_order_find(const struct iovec *iov)
{
	const uint8_t *ie = iov->iov_base;
	enum ie_type type = ie[0];
	unsigned int i;

	if (ie[0] == IE_TYPE_EXTENSION)
		type = 256 + ie[2];

	for (i = 0; i < sortinfo.n_elem; i++) {
		if (sortinfo.ie_order[i] != type)
			continue;

		return i;
	}

	return UINT_MAX;
}

static int ie_order_compare(const void *a, const void *b)
{
	const struct iovec *iova = a;
	const struct iovec *iovb = b;
	unsigned int ia = ie_order_find(iova);
	unsigned int ib = ie_order_find(iovb);

	if (ia < ib)
		return -1;
	if (ia > ib)
		return 1;
	return 0;
}

int mpdu_sort_ies(enum mpdu_management_subtype type,
				struct iovec *iov, size_t n_iovs)
{
	switch (type) {
	case MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST:
		sortinfo.ie_order = association_request_ie_order;
		sortinfo.n_elem = L_ARRAY_SIZE(association_request_ie_order);
		break;
	case MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_RESPONSE:
		sortinfo.ie_order = association_response_ie_order;
		sortinfo.n_elem = L_ARRAY_SIZE(association_response_ie_order);
		break;
	case MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_REQUEST:
		sortinfo.ie_order = reassociation_request_ie_order;
		sortinfo.n_elem = L_ARRAY_SIZE(reassociation_request_ie_order);
		break;
	case MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_RESPONSE:
		sortinfo.ie_order = reassociation_response_ie_order;
		sortinfo.n_elem = L_ARRAY_SIZE(reassociation_response_ie_order);
		break;
	case MPDU_MANAGEMENT_SUBTYPE_PROBE_REQUEST:
		sortinfo.ie_order = probe_request_ie_order;
		sortinfo.n_elem = L_ARRAY_SIZE(probe_request_ie_order);
		break;
	default:
		return -ENOTSUP;
	}

	/*
	 * qsort_r would be better, but it is still missing on some non-glibc
	 * implementations, and since iwd is not multi-threaded, qsort is
	 * just as good
	 */
	qsort(iov, n_iovs, sizeof(struct iovec), ie_order_compare);
	return 0;
}
