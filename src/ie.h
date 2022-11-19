/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2019  Intel Corporation. All rights reserved.
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
#include <stddef.h>
#include <unistd.h>

/*
 * Information elements, IEEE Std 802.11-2012 ch. 8.4.2 and
 * 802.11-2016 ch. 9.4.2.
 */
enum ie_type {
	IE_TYPE_SSID                                 = 0,
	IE_TYPE_SUPPORTED_RATES                      = 1,
	IE_TYPE_FH_PARAMETER_SET                     = 2,
	IE_TYPE_DSSS_PARAMETER_SET                   = 3,
	IE_TYPE_CF_PARAMETER_SET                     = 4,
	IE_TYPE_TIM                                  = 5,
	IE_TYPE_IBSS_PARAMETER_SET                   = 6,
	IE_TYPE_COUNTRY                              = 7,
	IE_TYPE_HOPPING_PATTERN_PARAMETERS           = 8,
	IE_TYPE_HOPPING_PATTERN_TABLE                = 9,
	IE_TYPE_REQUEST                              = 10,
	IE_TYPE_BSS_LOAD                             = 11,
	IE_TYPE_EDCA_PARAMETER_SET                   = 12,
	IE_TYPE_TSPEC                                = 13,
	IE_TYPE_TCLAS                                = 14,
	IE_TYPE_SCHEDULE                             = 15,
	IE_TYPE_CHALLENGE_TEXT                       = 16,
	/* Reserved 17 - 31 */
	IE_TYPE_POWER_CONSTRAINT                     = 32,
	IE_TYPE_POWER_CAPABILITY                     = 33,
	IE_TYPE_TPC_REQUEST                          = 34,
	IE_TYPE_TPC_REPORT                           = 35,
	IE_TYPE_SUPPORTED_CHANNELS                   = 36,
	IE_TYPE_CHANNEL_SWITCH_ANNOUNCEMENT          = 37,
	IE_TYPE_MEASUREMENT_REQUEST                  = 38,
	IE_TYPE_MEASUREMENT_REPORT                   = 39,
	IE_TYPE_QUIET                                = 40,
	IE_TYPE_IBSS_DFS                             = 41,
	IE_TYPE_ERP                                  = 42,
	IE_TYPE_TS_DELAY                             = 43,
	IE_TYPE_TCLAS_PROCESSING                     = 44,
	IE_TYPE_HT_CAPABILITIES                      = 45,
	IE_TYPE_QOS_CAPABILITY                       = 46,
	/* Reserved 47 */
	IE_TYPE_RSN                                  = 48,
	/* Reserved 49 */
	IE_TYPE_EXTENDED_SUPPORTED_RATES             = 50,
	IE_TYPE_AP_CHANNEL_REPORT                    = 51,
	IE_TYPE_NEIGHBOR_REPORT                      = 52,
	IE_TYPE_RCPI                                 = 53,
	IE_TYPE_MOBILITY_DOMAIN                      = 54,
	IE_TYPE_FAST_BSS_TRANSITION                  = 55,
	IE_TYPE_TIMEOUT_INTERVAL                     = 56,
	IE_TYPE_RIC_DATA                             = 57,
	IE_TYPE_DSE_REGISTERED_LOCATION              = 58,
	IE_TYPE_SUPPORTED_OPERATING_CLASSES          = 59,
	IE_TYPE_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT = 60,
	IE_TYPE_HT_OPERATION                         = 61,
	IE_TYPE_SECONDARY_CHANNEL_OFFSET             = 62,
	IE_TYPE_BSS_AVERAGE_ACCESS_DELAY             = 63,
	IE_TYPE_ANTENNA                              = 64,
	IE_TYPE_RSNI                                 = 65,
	IE_TYPE_MEASUREMENT_PILOT_TRANSMISSION       = 66,
	IE_TYPE_BSS_AVAILABLE_ADMISSION_CAPACITY     = 67,
	IE_TYPE_BSS_AC_ACCESS_DELAY                  = 68,
	IE_TYPE_TIME_ADVERTISEMENT                   = 69,
	IE_TYPE_RM_ENABLED_CAPABILITIES              = 70,
	IE_TYPE_MULTIPLE_BSSID                       = 71,
	IE_TYPE_BSS_COEXISTENCE                      = 72,
	IE_TYPE_BSS_INTOLERANT_CHANNEL_REPORT        = 73,
	IE_TYPE_OVERLAPPING_BSS_SCAN_PARAMETERS      = 74,
	IE_TYPE_RIC_DESCRIPTOR                       = 75,
	IE_TYPE_MANAGEMENT_MIC                       = 76,
	IE_TYPE_EVENT_REQUEST                        = 78,
	IE_TYPE_EVENT_REPORT                         = 79,
	IE_TYPE_DIAGNOSTIC_REQUEST                   = 80,
	IE_TYPE_DIAGNOSTIC_REPORT                    = 81,
	IE_TYPE_LOCATION_PARAMETERS                  = 82,
	IE_TYPE_NONTRANSMITTED_BSSID_CAPABILITY      = 83,
	IE_TYPE_SSID_LIST                            = 84,
	IE_TYPE_MULTIPLE_BSSID_INDEX                 = 85,
	IE_TYPE_FMS_DESCRIPTOR                       = 86,
	IE_TYPE_FMS_REQUEST                          = 87,
	IE_TYPE_FMS_RESPONSE                         = 88,
	IE_TYPE_QOS_TRAFFIC_CAPABILITY               = 89,
	IE_TYPE_BSS_MAX_IDLE_PERIOD                  = 90,
	IE_TYPE_TFS_REQUEST                          = 91,
	IE_TYPE_TFS_RESPONSE                         = 92,
	IE_TYPE_WNM_SLEEP_MODE                       = 93,
	IE_TYPE_TIM_BROADCAST_REQUEST                = 94,
	IE_TYPE_TIM_BROADCAST_RESPONSE               = 95,
	IE_TYPE_COLLOCATED_INTERFERENCE_REPORT       = 96,
	IE_TYPE_CHANNEL_USAGE                        = 97,
	IE_TYPE_TIME_ZONE                            = 98,
	IE_TYPE_DMS_REQUEST                          = 99,
	IE_TYPE_DMS_RESPONSE                         = 100,
	IE_TYPE_LINK_IDENTIFIER                      = 101,
	IE_TYPE_WAKEUP_SCHEDULE                      = 102,
	IE_TYPE_CHANNEL_SWITCH_TIMING                = 104,
	IE_TYPE_PTI_CONTROL                          = 105,
	IE_TYPE_TPU_BUFFER_STATUS                    = 106,
	IE_TYPE_INTERWORKING                         = 107,
	IE_TYPE_ADVERTISEMENT_PROTOCOL               = 108,
	IE_TYPE_EXPEDITED_BANDWIDTH_REQUEST          = 109,
	IE_TYPE_QOS_MAP_SET                          = 110,
	IE_TYPE_ROAMING_CONSORTIUM                   = 111,
	IE_TYPE_EMERGENCY_ALERT_IDENTIFIER           = 112,
	IE_TYPE_MESH_CONFIGURATION                   = 113,
	IE_TYPE_MESH_ID                              = 114,
	IE_TYPE_MESH_LINK_METRIC_REPORT              = 115,
	IE_TYPE_CONGESTION_NOTIFICATION              = 116,
	IE_TYPE_MESH_PEERING_MANAGEMENT              = 117,
	IE_TYPE_MESH_CHANNEL_SWITCH_PARAMETERS       = 118,
	IE_TYPE_MESH_AWAKE_WINDOW                    = 119,
	IE_TYPE_BEACON_TIMING                        = 120,
	IE_TYPE_MCCAOP_SETUP_REQUEST                 = 121,
	IE_TYPE_MCCAOP_SETUP_REPLY                   = 122,
	IE_TYPE_MCCAOP_ADVERTISEMENT                 = 123,
	IE_TYPE_MCCAOP_TEARDOWN                      = 124,
	IE_TYPE_GANN                                 = 125,
	IE_TYPE_RANN                                 = 126,
	IE_TYPE_EXTENDED_CAPABILITIES                = 127,
	/* Reserved 128 - 129 */
	IE_TYPE_PREQ                                 = 130,
	IE_TYPE_PREP                                 = 131,
	IE_TYPE_PERR                                 = 132,
	/* Reserved 133 - 136 */
	IE_TYPE_PXU                                  = 137,
	IE_TYPE_PXUC                                 = 138,
	IE_TYPE_AUTHENTICATED_MESH_PEERING_EXCHANGE  = 139,
	IE_TYPE_MIC                                  = 140,
	IE_TYPE_DESTINATION_URI                      = 141,
	IE_TYPE_U_APSD_COEXISTENCE                   = 142,
	IE_TYPE_DMG_WAKEUP_SCHEDULE                  = 143,
	IE_TYPE_EXTENDED_SCHEDULE                    = 144,
	IE_TYPE_STA_AVAILABILITY                     = 145,
	IE_TYPE_DMG_TSPEC                            = 146,
	IE_TYPE_NEXT_DMG_ATI                         = 147,
	IE_TYPE_DMG_CAPABILITIES                     = 148,
	/* Reserved 149 - 150 */
	IE_TYPE_DMG_OPERATION                        = 151,
	IE_TYPE_DMG_BSS_PARAMETER_CHANGE             = 152,
	IE_TYPE_DMG_BEAM_REFINEMENT                  = 153,
	IE_TYPE_CHANNEL_MEASUREMENT_FEEDBACK         = 154,
	/* Reserved 155 - 156 */
	IE_TYPE_AWAKE_WINDOW                         = 157,
	IE_TYPE_MULTIBAND                            = 158,
	IE_TYPE_ADDBA_EXTENSION                      = 159,
	IE_TYPE_NEXTPCP_LIST                         = 160,
	IE_TYPE_PCP_HANDOVER                         = 161,
	IE_TYPE_DMG_LINK_MARGIN                      = 162,
	IE_TYPE_SWITCHING_STREAM                     = 163,
	IE_TYPE_SESSION_TRANSITION                   = 164,
	IE_TYPE_DYNAMIC_TONE_PAIRING_REPORT          = 165,
	IE_TYPE_CLUSTER_REPORT                       = 166,
	IE_TYPE_RELAY_CAPABILITIES                   = 167,
	IE_TYPE_RELAY_TRANSFER_PARAMETER_SET         = 168,
	IE_TYPE_BEAMLINK_MAINTENANCE                 = 169,
	IE_TYPE_MULTIPLE_MAC_SUBLAYERS               = 170,
	IE_TYPE_UPID                                 = 171,
	IE_TYPE_DMG_LINK_ADAPTATION_ACKNOWLEDGEMENT  = 172,
	/* Reserved 173 */
	IE_TYPE_MCCAOP_ADVERTISEMENT_OVERVIEW        = 174,
	IE_TYPE_QUIET_PERIOD_REQUEST                 = 175,
	/* Reserved 176 */
	IE_TYPE_QUIET_PERIOD_RESPONSE                = 177,
	/* Reserved 178-180 */
	IE_TYPE_QMF_POLICY                           = 181,
	IE_TYPE_ECAPC_POLICY                         = 182,
	IE_TYPE_CLUSTER_TIME_OFFSET                  = 183,
	IE_TYPE_INTRAACCESS_CATEGORY_PRIORITY        = 184,
	IE_TYPE_SCS_DESCRIPTOR                       = 185,
	IE_TYPE_QLOAD_REPORT                         = 186,
	IE_TYPE_HCCA_TXOP_UPDATE_COUNT               = 187,
	IE_TYPE_HIGHER_LAYER_STREAM_ID               = 188,
	IE_TYPE_GCR_GROUP_ADDRESS                    = 189,
	IE_TYPE_ANTENNA_SECTOR_ID_PATTERN            = 190,
	IE_TYPE_VHT_CAPABILITIES                     = 191,
	IE_TYPE_VHT_OPERATION                        = 192,
	IE_TYPE_EXTENDED_BSS_LOAD                    = 193,
	IE_TYPE_WIDE_BANDWIDTH_CHANNEL_SWITCH        = 194,
	IE_TYPE_TRANSMIT_POWER_ENVELOPE              = 195,
	IE_TYPE_CHANNEL_SWITCH_WRAPPER               = 196,
	IE_TYPE_AID                                  = 197,
	IE_TYPE_QUIET_CHANNEL                        = 198,
	IE_TYPE_OPERATING_MODE_NOTIFICATION          = 199,
	IE_TYPE_UPSIM                                = 200,
	IE_TYPE_REDUCED_NEIGHBOR_REPORT              = 201,
	IE_TYPE_TVHT_OPERATION                       = 202,
	/* Reserved 203 */
	IE_TYPE_DEVICE_LOCATION                      = 204,
	IE_TYPE_WHITE_SPACE_MAP                      = 205,
	IE_TYPE_FINE_TIMING_MEASUREMENT_PARAMETERS   = 206,
	IE_TYPE_S1G_OPEN_LOOP_LINK_MARGIN_INDEX      = 207,
	IE_TYPE_RPS                                  = 208,
	IE_TYPE_PAGE_SLICE                           = 209,
	IE_TYPE_AID_REQUEST                          = 210,
	IE_TYPE_AID_RESPONSE                         = 211,
	IE_TYPE_S1G_SECTOR_OPERATION                 = 212,
	IE_TYPE_S1G_BEACON_COMPATIBILITY             = 213,
	IE_TYPE_SHORT_BEACON_INTERVAL                = 214,
	IE_TYPE_CHANGE_SEQUENCE                      = 215,
	IE_TYPE_TWT                                  = 216,
	IE_TYPE_S1G_CAPABILITIES                     = 217,
	/* Reserved 218 - 219 */
	IE_TYPE_SUBCHANNEL_SELECTIVE_TRANSMISSION    = 220,
	IE_TYPE_VENDOR_SPECIFIC                      = 221,
	IE_TYPE_AUTHENTICATION_CONTROL               = 222,
	IE_TYPE_TSF_TIMER_ACCURACY                   = 223,
	IE_TYPE_S1G_RELAY                            = 224,
	IE_TYPE_REACHABLE_ADDRESS                    = 225,
	IE_TYPE_S1G_RELAY_DISCOVERY                  = 226,
	/* Reserved 227 */
	IE_TYPE_AID_ANNOUNCEMENT                     = 228,
	IE_TYPE_PV1_PROBE_RESPONSE_OPTION            = 229,
	IE_TYPE_EL_OPERATION                         = 230,
	IE_TYPE_SECTORIZED_GROUP_ID_LIST             = 231,
	IE_TYPE_S1G_OPERATION                        = 232,
	IE_TYPE_HEADER_COMPRESSION                   = 233,
	IE_TYPE_SST_OPERATION                        = 234,
	IE_TYPE_MAD                                  = 235,
	IE_TYPE_S1G_RELAY_ACTIVATION                 = 236,
	IE_TYPE_CAG_NUMBER                           = 237,
	/* Reserved 238 */
	IE_TYPE_AP_CSN                               = 239,
	IE_TYPE_FILS_INDICATION                      = 240,
	IE_TYPE_DILS                                 = 241,
	IE_TYPE_FRAGMENT                             = 242,
	/* Reserved 243 */
	IE_TYPE_RSNX                                 = 244,
	/* Reserved 245 - 254 */
	IE_TYPE_EXTENSION                            = 255,

	IE_TYPE_FILS_REQUEST_PARAMETERS              = 256 + 2,
	IE_TYPE_FILS_KEY_CONFIRMATION                = 256 + 3,
	IE_TYPE_FILS_SESSION                         = 256 + 4,
	IE_TYPE_FILS_HLP_CONTAINER                   = 256 + 5,
	IE_TYPE_FILS_IP_ADDRESS                      = 256 + 6,
	IE_TYPE_KEY_DELIVERY                         = 256 + 7,
	IE_TYPE_FILS_WRAPPED_DATA                    = 256 + 8,
	IE_TYPE_FTM_SYNCHRONIZATION_INFORMATION      = 256 + 9,
	IE_TYPE_EXTENDED_REQUEST                     = 256 + 10,
	IE_TYPE_ESTIMATED_SERVICE_PARAMETERS         = 256 + 11,
	IE_TYPE_FILS_PUBLIC_KEY                      = 256 + 12,
	IE_TYPE_FILS_NONCE                           = 256 + 13,
	IE_TYPE_FUTURE_CHANNEL_GUIDANCE              = 256 + 14,
	IE_TYPE_SERVICE_HINT                         = 256 + 15,
	IE_TYPE_SERVICE_HASH                         = 256 + 16,
	IE_TYPE_CDMG_CAPABILITIES                    = 256 + 17,
	IE_TYPE_CLUSTER_PROBE                        = 256 + 21,
	IE_TYPE_CMMG_CAPABILITIES                    = 256 + 27,
	IE_TYPE_CMMG_OPERATION                       = 256 + 28,
	IE_TYPE_OWE_DH_PARAM                         = 256 + 32,
	IE_TYPE_PASSWORD_IDENTIFIER                  = 256 + 33,
	IE_TYPE_GLK_GCR_PARAMETER_SET                = 256 + 34,
	IE_TYPE_HE_CAPABILITIES                      = 256 + 35,
	IE_TYPE_HE_OPERATION                         = 256 + 36,
	IE_TYPE_UORA_PARAMETER_SET                   = 256 + 37,
	IE_TYPE_MU_EDCA_PARAMETER_SET                = 256 + 38,
	IE_TYPE_SPATIAL_REUSE_PARAMETER_SET          = 256 + 39,
	/* Reserved 40 */
	IE_TYPE_NDP_FEEDBACK_REPORT_PARAMETER        = 256 + 41,
	IE_TYPE_BSS_COLOR_CHANGE_ANNOUNCEMENT        = 256 + 42,
	IE_TYPE_QUIET_TIME_PERIOD                    = 256 + 43,
	IE_TYPE_VENDOR_SPECIFIC_REQUEST              = 256 + 44,
	IE_TYPE_ESS_REPORT                           = 256 + 45,
	IE_TYPE_OPS                                  = 256 + 46,
	IE_TYPE_HE_BSS_LOAD                          = 256 + 47,
	IE_TYPE_MAX_CHANNEL_SWITCH_TIME              = 256 + 52,
	IE_TYPE_ESTIMATED_SERVICE_PARAMETERS_OUT     = 256 + 53,
	IE_TYPE_OCI                                  = 256 + 54,
	IE_TYPE_MULTIPLE_BSSID_CONFIGURATION         = 256 + 55,
	/* Reserved 56 */
	IE_TYPE_KNOWN_BSSID                          = 256 + 57,
	IE_TYPE_SHORT_SSID_LIST                      = 256 + 58,
	IE_TYPE_HE_6GHZ_BAND_CAPABILITIES            = 256 + 59,
	IE_TYPE_UL_MU_POWER_CAPABILITIES             = 256 + 60,
	/* Reserved 61 - 87 */
	IE_TYPE_MSCS_DESCRIPTOR                      = 256 + 88,
	IE_TYPE_SUPPLEMENTAL_CLASS_2_CAPABILITIES    = 256 + 90,
	IE_TYPE_REJECTED_GROUPS                      = 256 + 92,
	IE_TYPE_ANTI_CLOGGING_TOKEN_CONTAINER        = 256 + 93,
};

/*
 * WiFi Alliance Hotspot 2.0 Specification - Section 3.1 Elements Definitions
 */
enum ie_vendor_wfa_oi_type {
	IE_WFA_OI_HS20_INDICATION = 0x10,
	IE_WFA_OI_OSEN = 0x12,
	IE_WFA_OI_OWE_TRANSITION = 0x1c,
	IE_WFA_OI_ROAMING_SELECTION = 0x1d,
	IE_WFA_OI_CONFIGURATOR_CONNECTIVITY = 0x1e,
};

enum ie_advertisement_id {
	IE_ADVERTISEMENT_ANQP			= 0,
	IE_ADVERTISEMENT_MIH_SERVICE		= 1,
	IE_ADVERTISEMENT_MIH_DISCOVERY		= 2,
	IE_ADVERTISEMENT_EAS			= 3,
	IE_ADVERTISEMENT_RLQP			= 4,
	IE_ADVERTISEMENT_VENDOR_SPECIFIC	= 221,
};

enum ie_rsn_cipher_suite {
	IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER	= 0x0001,
	IE_RSN_CIPHER_SUITE_WEP40		= 0x0002,
	IE_RSN_CIPHER_SUITE_TKIP		= 0x0004,
	IE_RSN_CIPHER_SUITE_CCMP		= 0x0008,
	IE_RSN_CIPHER_SUITE_WEP104		= 0x0010,
	IE_RSN_CIPHER_SUITE_BIP_CMAC		= 0x0020,
	IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC	= 0x0040,
	IE_RSN_CIPHER_SUITE_GCMP		= 0x0080,
	IE_RSN_CIPHER_SUITE_GCMP_256		= 0x0100,
	IE_RSN_CIPHER_SUITE_CCMP_256		= 0x0200,
	IE_RSN_CIPHER_SUITE_BIP_GMAC		= 0x0400,
	IE_RSN_CIPHER_SUITE_BIP_GMAC_256	= 0x0800,
	IE_RSN_CIPHER_SUITE_BIP_CMAC_256	= 0x1000,
};

enum ie_rsn_akm_suite {
	IE_RSN_AKM_SUITE_8021X			= 0x0001,
	IE_RSN_AKM_SUITE_PSK			= 0x0002,
	IE_RSN_AKM_SUITE_FT_OVER_8021X		= 0x0004,
	IE_RSN_AKM_SUITE_FT_USING_PSK		= 0x0008,
	IE_RSN_AKM_SUITE_8021X_SHA256		= 0x0010,
	IE_RSN_AKM_SUITE_PSK_SHA256		= 0x0020,
	IE_RSN_AKM_SUITE_TDLS			= 0x0040,
	IE_RSN_AKM_SUITE_SAE_SHA256		= 0x0080,
	IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256	= 0x0100,
	IE_RSN_AKM_SUITE_AP_PEER_KEY_SHA256	= 0x0200,
	IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA256	= 0x0400,
	IE_RSN_AKM_SUITE_8021X_SUITE_B_SHA384	= 0x0800,
	IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384	= 0x1000,
	IE_RSN_AKM_SUITE_OWE			= 0x2000,
	IE_RSN_AKM_SUITE_FILS_SHA256		= 0x4000,
	IE_RSN_AKM_SUITE_FILS_SHA384		= 0x8000,
	IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256	= 0x10000,
	IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384	= 0x20000,
	IE_RSN_AKM_SUITE_OSEN			= 0x40000,
};

static inline bool IE_AKM_IS_SAE(uint32_t akm)
{
	return akm & (IE_RSN_AKM_SUITE_SAE_SHA256 |
			IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256);
}

static inline bool IE_AKM_IS_FT(uint32_t akm)
{
	return akm & (IE_RSN_AKM_SUITE_FT_OVER_8021X |
			IE_RSN_AKM_SUITE_FT_USING_PSK |
			IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256 |
			IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384 |
			IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256 |
			IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384);
}

static inline bool IE_AKM_IS_FILS(uint32_t akm)
{
	return (akm) & (IE_RSN_AKM_SUITE_FILS_SHA256 |
			IE_RSN_AKM_SUITE_FILS_SHA384 |
			IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA256 |
			IE_RSN_AKM_SUITE_FT_OVER_FILS_SHA384);
}

static inline bool IE_AKM_IS_8021X(uint32_t akm)
{
	return akm & (IE_RSN_AKM_SUITE_8021X |
			IE_RSN_AKM_SUITE_FT_OVER_8021X |
			IE_RSN_AKM_SUITE_8021X_SHA256 |
			IE_RSN_AKM_SUITE_FT_OVER_8021X_SHA384);
}

static inline bool IE_CIPHER_IS_GCMP_CCMP(uint32_t cipher_suite)
{
	return cipher_suite & (IE_RSN_CIPHER_SUITE_CCMP |
				IE_RSN_CIPHER_SUITE_CCMP_256 |
				IE_RSN_CIPHER_SUITE_GCMP |
				IE_RSN_CIPHER_SUITE_GCMP_256);
}

#define IE_GROUP_CIPHERS		\
(					\
	IE_RSN_CIPHER_SUITE_TKIP |	\
	IE_RSN_CIPHER_SUITE_CCMP |	\
	IE_RSN_CIPHER_SUITE_GCMP |	\
	IE_RSN_CIPHER_SUITE_GCMP_256 |	\
	IE_RSN_CIPHER_SUITE_CCMP_256	\
)

/*
 * Since WEP is unsupported we can just use the group cipher list with
 * "Use group cipher" appended
 */
#define IE_PAIRWISE_CIPHERS			\
(						\
	IE_GROUP_CIPHERS |			\
	IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER	\
)

#define IE_LEN(ie) \
	((ie) ? (ie)[1] + 2 : 0)

struct ie_tlv_iter {
	unsigned int max;
	unsigned int pos;
	const unsigned char *tlv;
	unsigned int tag;
	unsigned int len;
	const unsigned char *data;
};

#define MAX_BUILDER_SIZE (8 * 1024)

struct ie_tlv_builder {
	unsigned char buf[MAX_BUILDER_SIZE];

	unsigned int max;
	unsigned int pos;
	unsigned char *tlv;
	struct ie_tlv_builder *parent;

	unsigned int tag;
	unsigned int len;
};

struct ie_rsn_info {
	enum ie_rsn_cipher_suite group_cipher;
	uint16_t pairwise_ciphers;
	uint32_t akm_suites;
	bool preauthentication:1;
	bool no_pairwise:1;
	uint8_t ptksa_replay_counter:2;
	uint8_t gtksa_replay_counter:2;
	bool mfpr:1;
	bool mfpc:1;
	bool peerkey_enabled:1;
	bool spp_a_msdu_capable:1;
	bool spp_a_msdu_required:1;
	bool pbac:1;
	bool extended_key_id:1;
	bool ocvc:1;
	uint8_t num_pmkids;
	const uint8_t *pmkids;
	enum ie_rsn_cipher_suite group_management_cipher;
};

/* IEEE 802.11-2016, Section 9.4.1.4 */
enum ie_bss_capability {
	IE_BSS_CAP_ESS			= 0x0001,
	IE_BSS_CAP_IBSS			= 0x0002,
	IE_BSS_CAP_CF_POLLABLE		= 0x0004,
	IE_BSS_CAP_CF_POLL_REQ		= 0x0008,
	IE_BSS_CAP_PRIVACY		= 0x0010,
	IE_BSS_CAP_SHORT_PREAMBLE	= 0x0020,
	IE_BSS_CAP_SPECTRUM_MANAGEMENT	= 0x0100,
	IE_BSS_CAP_QOS			= 0x0200,
	IE_BSS_CAP_SHORT_SLOT_TIME	= 0x0400,
	IE_BSS_CAP_APSD			= 0x0800,
	IE_BSS_CAP_RM			= 0x1000,
	IE_BSS_CAP_DELAYED_BLOCK_ACK	= 0x4000,
	IE_BSS_CAP_IMMEDIATE_BLOCK_ACK	= 0x8000,
};

struct ie_ft_info {
	uint8_t mic_element_count;
	bool rsnxe_used : 1;
	uint8_t mic[24];
	uint8_t anonce[32];
	uint8_t snonce[32];
	uint8_t r0khid[48];
	size_t r0khid_len;
	uint8_t r1khid[6];
	bool r1khid_present:1;
	uint8_t gtk_key_id;
	uint8_t gtk_len;
	uint8_t gtk_rsc[8];
	uint8_t gtk[40];
	uint16_t igtk_key_id;
	uint8_t igtk_ipn[6];
	uint8_t igtk_len;
	uint8_t igtk[24];
	bool oci_present:1;
	uint8_t oci[3];
};

/* See chapter 8.4.2.47 for radio measurement capability details */
enum ie_rm_capability {
	IE_RM_CAP_NEIGHBOR_REPORT = 0x0002,
};

struct ie_neighbor_report_info {
	uint8_t addr[6];
	uint8_t reachable;
	bool spectrum_mgmt : 1;
	bool qos : 1;
	bool apsd : 1;
	bool rm : 1;
	bool delayed_block_ack : 1;
	bool immediate_block_ack : 1;
	bool security : 1;
	bool key_scope : 1;
	bool md : 1;
	bool ht : 1;
	uint8_t oper_class;
	uint8_t channel_num;
	uint8_t phy_type;
	uint8_t bss_transition_pref;
	bool bss_transition_pref_present : 1;
};

struct ie_fils_ip_addr_request_info {
	bool ipv4 : 1;
	uint32_t ipv4_requested_addr;		/* Zero if none */
	bool ipv6 : 1;
	uint8_t ipv6_requested_addr[16];	/* Zero if none */
	bool dns : 1;
};

struct ie_fils_ip_addr_response_info {
	bool response_pending : 1;
	uint8_t response_timeout;	/* Seconds */
	uint32_t ipv4_addr;		/* Zero if not provided */
	uint8_t ipv4_prefix_len;
	uint32_t ipv4_gateway;		/* Zero if not provided */
	uint8_t ipv4_gateway_mac[6];
	uint32_t ipv4_dns;		/* Zero if not provided */
	uint8_t ipv4_dns_mac[6];	/* Zero if not provided */
	uint8_t ipv4_lifetime;		/* Zero if not provided */
	uint8_t ipv6_addr[16];		/* Zero if not provided */
	uint8_t ipv6_prefix_len;
	uint8_t ipv6_gateway[16];	/* Zero if not provided */
	uint8_t ipv6_gateway_mac[6];
	uint8_t ipv6_dns[16];		/* Zero if not provided */
	uint8_t ipv6_dns_mac[6];	/* Zero if not provided */
	uint8_t ipv6_lifetime;		/* Zero if not provided */
};

struct ie_owe_transition_info {
	uint8_t bssid[6];
	uint8_t ssid[32];
	size_t ssid_len;
	uint8_t oper_class;
	uint8_t channel;
};

extern const unsigned char ieee_oui[3];
extern const unsigned char microsoft_oui[3];
extern const unsigned char wifi_alliance_oui[3];

void ie_tlv_iter_init(struct ie_tlv_iter *iter, const unsigned char *tlv,
			unsigned int len);
void ie_tlv_iter_recurse(struct ie_tlv_iter *iter,
			struct ie_tlv_iter *recurse);
bool ie_tlv_iter_next(struct ie_tlv_iter *iter);

static inline unsigned int ie_tlv_iter_get_tag(struct ie_tlv_iter *iter)
{
	return iter->tag;
}

static inline unsigned int ie_tlv_iter_get_length(struct ie_tlv_iter *iter)
{
	return iter->len;
}

static inline const unsigned char *ie_tlv_iter_get_data(
						struct ie_tlv_iter *iter)
{
	return iter->data;
}

void *ie_tlv_extract_wsc_payload(const uint8_t *ies, size_t len,
							ssize_t *out_len);
void *ie_tlv_encapsulate_wsc_payload(const uint8_t *data, size_t len,
							size_t *out_len);

void *ie_tlv_extract_p2p_payload(const uint8_t *ies, size_t len,
							ssize_t *out_len);
void *ie_tlv_encapsulate_p2p_payload(const uint8_t *data, size_t len,
							size_t *out_len);

void *ie_tlv_extract_wfd_payload(const unsigned char *ies, size_t len,
							ssize_t *out_len);

bool ie_tlv_builder_init(struct ie_tlv_builder *builder, unsigned char *buf,
				size_t len);
bool ie_tlv_builder_set_length(struct ie_tlv_builder *builder,
			unsigned int new_len);
bool ie_tlv_builder_next(struct ie_tlv_builder *builder, unsigned int new_tag);
unsigned char *ie_tlv_builder_get_data(struct ie_tlv_builder *builder);
bool ie_tlv_builder_set_data(struct ie_tlv_builder *builder,
				const void *data, size_t len);
bool ie_tlv_builder_recurse(struct ie_tlv_builder *builder,
			struct ie_tlv_builder *recurse);
unsigned char *ie_tlv_builder_finalize(struct ie_tlv_builder *builder,
					size_t *out_len);

uint32_t ie_rsn_cipher_suite_to_cipher(enum ie_rsn_cipher_suite suite);
const char *ie_rsn_cipher_suite_to_string(enum ie_rsn_cipher_suite suite);

int ie_parse_rsne(struct ie_tlv_iter *iter, struct ie_rsn_info *info);
int ie_parse_rsne_from_data(const uint8_t *data, size_t len,
				struct ie_rsn_info *info);
bool ie_build_rsne(const struct ie_rsn_info *info, uint8_t *to);
bool ie_rsne_is_wpa3_personal(const struct ie_rsn_info *info);

int ie_parse_wpa(struct ie_tlv_iter *iter, struct ie_rsn_info *out_info);
int ie_parse_wpa_from_data(const uint8_t *data, size_t len,
						struct ie_rsn_info *info);
bool is_ie_wfa_ie(const uint8_t *data, uint8_t len, uint8_t oi_type);
bool is_ie_wpa_ie(const uint8_t *data, uint8_t len);
bool is_ie_default_sae_group_oui(const uint8_t *data, uint16_t len);

bool ie_build_wpa(const struct ie_rsn_info *info, uint8_t *to);

int ie_parse_bss_load(struct ie_tlv_iter *iter, uint16_t *out_sta_count,
			uint8_t *out_channel_utilization,
			uint16_t *out_admission_capacity);
int ie_parse_bss_load_from_data(const uint8_t *data, uint8_t len,
				uint16_t *out_sta_count,
				uint8_t *out_channel_utilization,
				uint16_t *out_admission_capacity);

int ie_parse_mobility_domain(struct ie_tlv_iter *iter, uint16_t *mdid,
				bool *ft_over_ds, bool *resource_req);
int ie_parse_mobility_domain_from_data(const uint8_t *data, uint8_t len,
				uint16_t *mdid,
				bool *ft_over_ds, bool *resource_req);
bool ie_build_mobility_domain(uint16_t mdid, bool ft_over_ds,
				bool resource_req, uint8_t *to);

int ie_parse_fast_bss_transition(struct ie_tlv_iter *iter,
					uint32_t mic_len,
					struct ie_ft_info *info);
int ie_parse_fast_bss_transition_from_data(const uint8_t *data, uint8_t len,
						uint32_t mic_len,
						struct ie_ft_info *info);
bool ie_build_fast_bss_transition(const struct ie_ft_info *info,
					uint32_t mic_len, uint8_t *to);

int ie_parse_neighbor_report(struct ie_tlv_iter *iter,
				struct ie_neighbor_report_info *info);

int ie_parse_osen_from_data(const uint8_t *data, size_t len,
				struct ie_rsn_info *info);
int ie_parse_osen(struct ie_tlv_iter *iter, struct ie_rsn_info *out_info);

bool ie_build_osen(const struct ie_rsn_info *info, uint8_t *to);

int ie_parse_roaming_consortium(struct ie_tlv_iter *iter, size_t *num_anqp_out,
				const uint8_t **oi1_out, size_t *oi1_len_out,
				const uint8_t **oi2_out, size_t *oi2_len_out,
				const uint8_t **oi3_out, size_t *oi3_len_out);

int ie_parse_roaming_consortium_from_data(const uint8_t *data, size_t len,
				size_t *num_anqp_out, const uint8_t **oi1_out,
				size_t *oi1_len_out, const uint8_t **oi2_out,
				size_t *oi2_len_out, const uint8_t **oi3_out,
				size_t *oi3_len_out);

int ie_build_roaming_consortium(const uint8_t *rc, size_t rc_len, uint8_t *to);

int ie_parse_hs20_indication(struct ie_tlv_iter *iter, uint8_t *version,
				uint16_t *pps_mo_id, uint8_t *domain_id,
				bool *dgaf_disable);
int ie_parse_hs20_indication_from_data(const uint8_t *data, size_t len,
					uint8_t *version, uint16_t *pps_mo_id,
					uint8_t *domain_id, bool *dgaf_disable);
int ie_build_hs20_indication(uint8_t version, uint8_t *to);

enum ie_rsnx_capability {
	IE_RSNX_PROTECTED_TWT                                = 4,
	IE_RSNX_SAE_H2E                                      = 5,
};

bool ie_rsnxe_capable(const uint8_t *rsnxe, unsigned int bit);

int ie_parse_fils_ip_addr_request(struct ie_tlv_iter *iter,
				struct ie_fils_ip_addr_request_info *out);
void ie_build_fils_ip_addr_request(
				const struct ie_fils_ip_addr_request_info *info,
				uint8_t *to);
int ie_parse_fils_ip_addr_response(struct ie_tlv_iter *iter,
				struct ie_fils_ip_addr_response_info *out);
void ie_build_fils_ip_addr_response(
			const struct ie_fils_ip_addr_response_info *info,
			uint8_t *to);

int ie_parse_network_cost(const void *data, size_t len,
				uint16_t *flags, uint16_t *level);

int ie_parse_owe_transition(const void *data, size_t len,
				struct ie_owe_transition_info *info);

int ie_parse_oci(const void *data, size_t len, const uint8_t **oci);

bool ie_validate_he_capabilities(const void *data, size_t len);
