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

#include <stdint.h>

#include "src/defs.h"
#include "src/wscutil.h"

struct l_queue;

/* Wi-Fi P2P Technical Specification v1.7, Section 4.1.1, Table 6 */
enum p2p_attr {
	P2P_ATTR_STATUS = 0,
	P2P_ATTR_MINOR_REASON_CODE = 1,
	P2P_ATTR_P2P_CAPABILITY = 2,
	P2P_ATTR_P2P_DEVICE_ID = 3,
	P2P_ATTR_GO_INTENT = 4,
	P2P_ATTR_CONFIGURATION_TIMEOUT = 5,
	P2P_ATTR_LISTEN_CHANNEL = 6,
	P2P_ATTR_P2P_GROUP_BSSID = 7,
	P2P_ATTR_EXTENDED_LISTEN_TIMING = 8,
	P2P_ATTR_INTENDED_P2P_INTERFACE_ADDR = 9,
	P2P_ATTR_P2P_MANAGEABILITY = 10,
	P2P_ATTR_CHANNEL_LIST = 11,
	P2P_ATTR_NOTICE_OF_ABSENCE = 12,
	P2P_ATTR_P2P_DEVICE_INFO = 13,
	P2P_ATTR_P2P_GROUP_INFO = 14,
	P2P_ATTR_P2P_GROUP_ID = 15,
	P2P_ATTR_P2P_INTERFACE = 16,
	P2P_ATTR_OPERATING_CHANNEL = 17,
	P2P_ATTR_INVITATION_FLAGS = 18,
	P2P_ATTR_OOB_GO_NEGOTIATION_CHANNEL = 19,
	P2P_ATTR_SVC_HASH = 21,
	P2P_ATTR_SESSION_INFO_DATA_INFO = 22,
	P2P_ATTR_CONNECTION_CAPABILITY_INFO = 23,
	P2P_ATTR_ADVERTISEMENT_ID_INFO = 24,
	P2P_ATTR_ADVERTISED_SVC_INFO = 25,
	P2P_ATTR_SESSION_ID_INFO = 26,
	P2P_ATTR_FEATURE_CAPABILITY = 27,
	P2P_ATTR_PERSISTENT_GROUP_INFO = 28,
	P2P_ATTR_VENDOR_SPECIFIC_ATTR = 221,
};

/* Table 8 */
enum p2p_attr_status_code {
	P2P_STATUS_SUCCESS = 0,
	P2P_STATUS_FAIL_INFO_NOT_AVAIL = 1,
	P2P_STATUS_FAIL_INCOMPATIBLE_PARAMS = 2,
	P2P_STATUS_FAIL_LIMIT_REACHED = 3,
	P2P_STATUS_FAIL_INVALID_PARAMS = 4,
	P2P_STATUS_FAIL_UNABLE_TO_ACCOMMODATE_REQUEST = 5,
	P2P_STATUS_FAIL_PREV_PROTOCOL_ERROR = 6,
	P2P_STATUS_FAIL_NO_COMMON_CHANNELS = 7,
	P2P_STATUS_FAIL_UNKNOWN_P2P_GROUP = 8,
	P2P_STATUS_FAIL_INTENT_15_IN_GO_NEGOTIATION = 9,
	P2P_STATUS_FAIL_INCOMPATIBLE_PROVISIONING = 10,
	P2P_STATUS_FAIL_REJECTED_BY_USER = 11,
	P2P_STATUS_SUCCESS_ACCEPTED_BY_USER = 12,
};

/* Table 12 */
enum p2p_device_capability_bitmap {
	P2P_DEVICE_CAP_SVC_DISCOVERY		= 0x01,
	P2P_DEVICE_CAP_CLIENT_DISCOVERABILITY	= 0x02,
	P2P_DEVICE_CAP_CONCURRENT_OP		= 0x04,
	P2P_DEVICE_CAP_INFRASTRUCTURE_MANAGED	= 0x08,
	P2P_DEVICE_CAP_DEVICE_LIMIT		= 0x10,
	P2P_DEVICE_CAP_INVITATION_PROCEDURE	= 0x20,
};

/* Table 13 */
enum p2p_group_capability_bitmap {
	P2P_GROUP_CAP_GO			= 0x01,
	P2P_GROUP_CAP_PERSISTENT_GROUP		= 0x02,
	P2P_GROUP_CAP_GROUP_LIMIT		= 0x04,
	P2P_GROUP_CAP_INTRA_BSS_DISTRIBUTION	= 0x08,
	P2P_GROUP_CAP_CROSS_CONNECT		= 0x10,
	P2P_GROUP_CAP_PERSISTENT_RECONNECT	= 0x20,
	P2P_GROUP_CAP_GROUP_FORMATION		= 0x40,
	P2P_GROUP_CAP_IP_ALLOCATION		= 0x80,
};

/* Table 23 */
enum p2p_manageability_bitmap {
	P2P_MANAGEABILITY_DEVICE_MGMT		= 0x01,
	P2P_MANAGEABILITY_CROSS_CONNECT		= 0x02,
	P2P_MANAGEABILITY_COEXIST_OPTIONAL	= 0x04,
};

/* Table 61 */
enum p2p_public_action_frame_type {
	P2P_ACTION_GO_NEGOTIATION_REQ		= 0,
	P2P_ACTION_GO_NEGOTIATION_RESP		= 1,
	P2P_ACTION_GO_NEGOTIATION_CONFIRM	= 2,
	P2P_ACTION_INVITATION_REQ		= 3,
	P2P_ACTION_INVITATION_RESP		= 4,
	P2P_ACTION_DEVICE_DISCOVERABILITY_REQ	= 5,
	P2P_ACTION_DEVICE_DISCOVERABILITY_RESP	= 6,
	P2P_ACTION_PROVISION_DISCOVERY_REQ	= 7,
	P2P_ACTION_PROVISION_DISCOVERY_RESP	= 8,
};

/* Table 75 */
enum p2p_action_frame_type {
	P2P_ACTION_NOTICE_OF_ABSENCE		= 0,
	P2P_ACTION_PRESENCE_REQ			= 1,
	P2P_ACTION_PRESENCE_RESP		= 2,
	P2P_ACTION_GO_DISCOVERABILITY_REQ	= 3,
};

struct p2p_attr_iter {
	const uint8_t *pos;
	const uint8_t *end;
	enum p2p_attr type;
	size_t len;
};

void p2p_attr_iter_init(struct p2p_attr_iter *iter, const uint8_t *pdu,
			size_t len);
bool p2p_attr_iter_next(struct p2p_attr_iter *iter);

static inline enum p2p_attr p2p_attr_iter_get_type(struct p2p_attr_iter *iter)
{
	return iter->type;
}

static inline size_t p2p_attr_iter_get_length(struct p2p_attr_iter *iter)
{
	return iter->len;
}

static inline const uint8_t *p2p_attr_iter_get_data(struct p2p_attr_iter *iter)
{
	return iter->pos + 3;
}

/* Wi-Fi Display Technical Specification v2.1.0 Table 27 */
enum wfd_subelem_type {
	WFD_SUBELEM_WFD_DEVICE_INFORMATION	= 0,
	WFD_SUBELEM_ASSOCIATED_BSSID		= 1,
	WFD_SUBELEM_COUPLED_SINK_INFORMATION	= 6,
	WFD_SUBELEM_EXTENDED_CAPABILITY		= 7,
	WFD_SUBELEM_LOCAL_IP_ADDRESS		= 8,
	WFD_SUBELEM_SESION_INFORMATION		= 9,
	WFD_SUBELEM_ALTERNATIVE_MAC_ADDRESS	= 10,
	WFD_SUBELEM_R2_DEVICE_INFORMATION	= 11,
};

enum wfd_dev_info_bits {
	WFD_DEV_INFO_DEVICE_TYPE		= 0x0003,
	WFD_DEV_INFO_COUPLED_SINK_AT_SOURCE_OK	= 0x0004,
	WFD_DEV_INFO_COUPLED_SINK_AT_SINK_OK	= 0x0008,
	WFD_DEV_INFO_SESSION_AVAILABILITY	= 0x0030,
	WFD_DEV_INFO_SERVICE_DISCOVERY_SUPPORT	= 0x0040,
	WFD_DEV_INFO_PREFER_TDLS_CONNECTIVITY	= 0x0080,
	WFD_DEV_INFO_CONTENT_PROTECTION_SUPPORT	= 0x0100,
	WFD_DEV_INFO_8021AS_TIME_SYNC_SUPPORT	= 0x0200,
	WFD_DEV_INFO_NO_AUDIO_AT_PRIMARY_SINK	= 0x0400,
	WFD_DEV_INFO_AUDIO_ONLY_AT_SOURCE	= 0x0800,
	WFD_DEV_INFO_TDLS_PERSISTENT_GROUP	= 0x1000,
	WFD_DEV_INFO_REINVOKE_TDLS_GROUP	= 0x2000,
};

enum wfd_dev_info_type {
	WFD_DEV_INFO_TYPE_SOURCE		= 0x0000,
	WFD_DEV_INFO_TYPE_PRIMARY_SINK		= 0x0001,
	WFD_DEV_INFO_TYPE_SECONDARY_SINK	= 0x0002,
	WFD_DEV_INFO_TYPE_DUAL_ROLE		= 0x0003,
};

enum wfd_dev_info_session_availability {
	WFD_DEV_INFO_SESSION_NOT_AVAILABLE	= 0x0000,
	WFD_DEV_INFO_SESSION_AVAILABLE		= 0x0010,
};

struct wfd_subelem_iter {
	const uint8_t *pos;
	const uint8_t *end;
	enum wfd_subelem_type type;
	size_t len;
};

void wfd_subelem_iter_init(struct wfd_subelem_iter *iter, const uint8_t *pdu,
				size_t len);
bool wfd_subelem_iter_next(struct wfd_subelem_iter *iter);

static inline enum wfd_subelem_type wfd_subelem_iter_get_type(
						struct wfd_subelem_iter *iter)
{
	return iter->type;
}

static inline size_t wfd_subelem_iter_get_length(struct wfd_subelem_iter *iter)
{
	return iter->len;
}

static inline const uint8_t *wfd_subelem_iter_get_data(
						struct wfd_subelem_iter *iter)
{
	return iter->pos + 3;
}

struct p2p_capability_attr {
	uint8_t device_caps;
	uint8_t group_caps;
};

struct p2p_config_timeout_attr {
	uint8_t go_config_timeout;
	uint8_t client_config_timeout;
};

struct p2p_channel_attr {
	char country[3];
	uint8_t oper_class;
	uint8_t channel_num;
};

struct p2p_extended_listen_timing_attr {
	uint16_t avail_period_ms;
	uint16_t avail_interval_ms;
};

struct p2p_channel_entries {
	uint8_t oper_class;
	int n_channels;
	uint8_t channels[];
};

struct p2p_channel_list_attr {
	char country[3];
	struct l_queue *channel_entries;
};

struct p2p_notice_of_absence_desc {
	uint8_t count_type;
	uint32_t duration;
	uint32_t interval;
	uint32_t start_time;
};

struct p2p_notice_of_absence_attr {
	uint8_t index;
	bool opp_ps;
	uint8_t ct_window;
	struct l_queue *descriptors;
};

struct p2p_device_info_attr {
	uint8_t device_addr[6];
	uint16_t wsc_config_methods;
	struct wsc_primary_device_type primary_device_type;
	struct l_queue *secondary_device_types;
	char device_name[33];
};

struct p2p_client_info_descriptor {
	uint8_t device_addr[6];
	uint8_t interface_addr[6];
	uint8_t device_caps;
	uint16_t wsc_config_methods;
	struct wsc_primary_device_type primary_device_type;
	struct l_queue *secondary_device_types;
	char device_name[33];
};

struct p2p_group_id_attr {
	uint8_t device_addr[6];
	char ssid[SSID_MAX_SIZE + 1];
};

struct p2p_interface_attr {
	uint8_t device_addr[6];
	struct l_queue *interface_addrs;
};

struct p2p_session_info_data_attr {
	size_t data_len;
	uint8_t data[144];
};

struct p2p_advertisement_id_info_attr {
	uint32_t advertisement_id;
	uint8_t service_mac_addr[6];
};

struct p2p_advertised_service_descriptor {
	uint32_t advertisement_id;
	uint16_t wsc_config_methods;
	char *service_name;
};

struct p2p_session_id_info_attr {
	uint32_t session_id;
	uint8_t session_mac_addr[6];
};

enum p2p_asp_coordination_transport_protocol {
	P2P_ASP_TRANSPORT_UNKNOWN = 0,
	P2P_ASP_TRANSPORT_UDP,
};

struct p2p_beacon {
	struct p2p_capability_attr capability;
	uint8_t device_addr[6];
	struct p2p_notice_of_absence_attr notice_of_absence;
};

struct p2p_probe_req {
	struct p2p_capability_attr capability;
	uint8_t device_addr[6];
	struct p2p_channel_attr listen_channel;
	struct p2p_extended_listen_timing_attr listen_availability;
	struct p2p_device_info_attr device_info;
	struct p2p_channel_attr operating_channel;
	struct l_queue *service_hashes;
};

struct p2p_probe_resp {
	struct p2p_capability_attr capability;
	struct p2p_extended_listen_timing_attr listen_availability;
	struct p2p_notice_of_absence_attr notice_of_absence;
	struct p2p_device_info_attr device_info;
	struct l_queue *group_clients;
	struct l_queue *advertised_svcs;
};

struct p2p_association_req {
	struct p2p_capability_attr capability;
	struct p2p_extended_listen_timing_attr listen_availability;
	struct p2p_device_info_attr device_info;
	struct p2p_interface_attr interface;
};

struct p2p_association_resp {
	enum p2p_attr_status_code status;
	struct p2p_extended_listen_timing_attr listen_availability;
};

struct p2p_deauthentication {
	uint8_t minor_reason_code;
};

struct p2p_disassociation {
	uint8_t minor_reason_code;
};

struct p2p_go_negotiation_req {
	uint8_t dialog_token;
	struct p2p_capability_attr capability;
	uint8_t go_intent;
	bool go_tie_breaker;
	struct p2p_config_timeout_attr config_timeout;
	struct p2p_channel_attr listen_channel;
	struct p2p_extended_listen_timing_attr listen_availability;
	uint8_t intended_interface_addr[6];
	struct p2p_channel_list_attr channel_list;
	struct p2p_device_info_attr device_info;
	struct p2p_channel_attr operating_channel;
	enum wsc_device_password_id device_password_id;
	uint8_t *wfd;
	ssize_t wfd_size;
};

struct p2p_go_negotiation_resp {
	uint8_t dialog_token;
	enum p2p_attr_status_code status;
	struct p2p_capability_attr capability;
	uint8_t go_intent;
	bool go_tie_breaker;
	struct p2p_config_timeout_attr config_timeout;
	struct p2p_channel_attr operating_channel;
	uint8_t intended_interface_addr[6];
	struct p2p_channel_list_attr channel_list;
	struct p2p_device_info_attr device_info;
	struct p2p_group_id_attr group_id;
	enum wsc_device_password_id device_password_id;
	uint8_t *wfd;
	ssize_t wfd_size;
};

struct p2p_go_negotiation_confirmation {
	uint8_t dialog_token;
	enum p2p_attr_status_code status;
	struct p2p_capability_attr capability;
	struct p2p_channel_attr operating_channel;
	struct p2p_channel_list_attr channel_list;
	struct p2p_group_id_attr group_id;
	uint8_t *wfd;
	ssize_t wfd_size;
};

struct p2p_invitation_req {
	uint8_t dialog_token;
	struct p2p_config_timeout_attr config_timeout;
	bool reinvoke_persistent_group;
	struct p2p_channel_attr operating_channel;
	uint8_t group_bssid[6];
	struct p2p_channel_list_attr channel_list;
	struct p2p_group_id_attr group_id;
	struct p2p_device_info_attr device_info;
	enum wsc_device_password_id device_password_id;
	uint8_t *wfd;
	ssize_t wfd_size;
};

struct p2p_invitation_resp {
	uint8_t dialog_token;
	enum p2p_attr_status_code status;
	struct p2p_config_timeout_attr config_timeout;
	struct p2p_channel_attr operating_channel;
	uint8_t group_bssid[6];
	struct p2p_channel_list_attr channel_list;
	uint8_t *wfd;
	ssize_t wfd_size;
};

struct p2p_device_discoverability_req {
	uint8_t dialog_token;
	uint8_t device_addr[6];
	struct p2p_group_id_attr group_id;
};

struct p2p_device_discoverability_resp {
	uint8_t dialog_token;
	enum p2p_attr_status_code status;
};

struct p2p_provision_discovery_req {
	uint8_t dialog_token;
	struct p2p_capability_attr capability;
	struct p2p_device_info_attr device_info;
	struct p2p_group_id_attr group_id;
	uint8_t intended_interface_addr[6];
	enum p2p_attr_status_code status;
	struct p2p_channel_attr operating_channel;
	struct p2p_channel_list_attr channel_list;
	struct p2p_session_info_data_attr session_info;
	uint8_t connection_capability;
	struct p2p_advertisement_id_info_attr advertisement_id;
	struct p2p_config_timeout_attr config_timeout;
	struct p2p_channel_attr listen_channel;
	struct p2p_session_id_info_attr session_id;
	enum p2p_asp_coordination_transport_protocol transport_protocol;
	struct p2p_group_id_attr persistent_group_info;
	uint16_t wsc_config_method;
	uint8_t *wfd;
	ssize_t wfd_size;
};

struct p2p_provision_discovery_resp {
	uint8_t dialog_token;
	enum p2p_attr_status_code status;
	struct p2p_capability_attr capability;
	struct p2p_device_info_attr device_info;
	struct p2p_group_id_attr group_id;
	uint8_t intended_interface_addr[6];
	struct p2p_channel_attr operating_channel;
	struct p2p_channel_list_attr channel_list;
	uint8_t connection_capability;
	struct p2p_advertisement_id_info_attr advertisement_id;
	struct p2p_config_timeout_attr config_timeout;
	struct p2p_session_id_info_attr session_id;
	enum p2p_asp_coordination_transport_protocol transport_protocol;
	struct p2p_group_id_attr persistent_group_info;
	struct p2p_session_info_data_attr session_info;
	uint16_t wsc_config_method;
	uint8_t *wfd;
	ssize_t wfd_size;
};

struct p2p_notice_of_absence {
	struct p2p_notice_of_absence_attr notice_of_absence;
};

struct p2p_presence_req {
	uint8_t dialog_token;
	struct p2p_notice_of_absence_attr notice_of_absence;
};

struct p2p_presence_resp {
	uint8_t dialog_token;
	enum p2p_attr_status_code status;
	struct p2p_notice_of_absence_attr notice_of_absence;
};

int p2p_parse_beacon(const uint8_t *pdu, size_t len,
			struct p2p_beacon *out);
int p2p_parse_probe_req(const uint8_t *pdu, size_t len,
			struct p2p_probe_req *out);
int p2p_parse_probe_resp(const uint8_t *pdu, size_t len,
				struct p2p_probe_resp *out);
int p2p_parse_association_req(const uint8_t *pdu, size_t len,
				struct p2p_association_req *out);
int p2p_parse_association_resp(const uint8_t *pdu, size_t len,
				struct p2p_association_resp *out);
int p2p_parse_deauthentication(const uint8_t *pdu, size_t len,
				struct p2p_deauthentication *out);
int p2p_parse_disassociation(const uint8_t *pdu, size_t len,
				struct p2p_disassociation *out);
int p2p_parse_go_negotiation_req(const uint8_t *pdu, size_t len,
					struct p2p_go_negotiation_req *out);
int p2p_parse_go_negotiation_resp(const uint8_t *pdu, size_t len,
					struct p2p_go_negotiation_resp *out);
int p2p_parse_go_negotiation_confirmation(const uint8_t *pdu, size_t len,
				struct p2p_go_negotiation_confirmation *out);
int p2p_parse_invitation_req(const uint8_t *pdu, size_t len,
				struct p2p_invitation_req *out);
int p2p_parse_invitation_resp(const uint8_t *pdu, size_t len,
				struct p2p_invitation_resp *out);
int p2p_parse_device_disc_req(const uint8_t *pdu, size_t len,
				struct p2p_device_discoverability_req *out);
int p2p_parse_device_disc_resp(const uint8_t *pdu, size_t len,
				struct p2p_device_discoverability_resp *out);
int p2p_parse_provision_disc_req(const uint8_t *pdu, size_t len,
				struct p2p_provision_discovery_req *out);
int p2p_parse_provision_disc_resp(const uint8_t *pdu, size_t len,
				struct p2p_provision_discovery_resp *out);
int p2p_parse_notice_of_absence(const uint8_t *pdu, size_t len,
				struct p2p_notice_of_absence *out);
int p2p_parse_presence_req(const uint8_t *pdu, size_t len,
				struct p2p_presence_req *out);
int p2p_parse_presence_resp(const uint8_t *pdu, size_t len,
				struct p2p_presence_resp *out);
int p2p_parse_go_disc_req(const uint8_t *pdu, size_t len);

void p2p_clear_beacon(struct p2p_beacon *data);
void p2p_clear_probe_req(struct p2p_probe_req *data);
void p2p_clear_probe_resp(struct p2p_probe_resp *data);
void p2p_clear_association_req(struct p2p_association_req *data);
void p2p_clear_association_resp(struct p2p_association_resp *data);
void p2p_clear_go_negotiation_req(struct p2p_go_negotiation_req *data);
void p2p_clear_go_negotiation_resp(struct p2p_go_negotiation_resp *data);
void p2p_clear_go_negotiation_confirmation(
				struct p2p_go_negotiation_confirmation *data);
void p2p_clear_invitation_req(struct p2p_invitation_req *data);
void p2p_clear_invitation_resp(struct p2p_invitation_resp *data);
void p2p_clear_provision_disc_req(struct p2p_provision_discovery_req *data);
void p2p_clear_provision_disc_resp(struct p2p_provision_discovery_resp *data);
void p2p_clear_notice_of_absence(struct p2p_notice_of_absence *data);
void p2p_clear_presence_req(struct p2p_presence_req *data);
void p2p_clear_presence_resp(struct p2p_presence_resp *data);

uint8_t *p2p_build_beacon(const struct p2p_beacon *data, size_t *out_len);
uint8_t *p2p_build_probe_req(const struct p2p_probe_req *data, size_t *out_len);
uint8_t *p2p_build_probe_resp(const struct p2p_probe_resp *data,
				size_t *out_len);
uint8_t *p2p_build_association_req(const struct p2p_association_req *data,
					size_t *out_len);
uint8_t *p2p_build_association_resp(const struct p2p_association_resp *data,
					size_t *out_len);
uint8_t *p2p_build_deauthentication(const struct p2p_deauthentication *data,
					size_t *out_len);
uint8_t *p2p_build_disassociation(const struct p2p_disassociation *data,
					size_t *out_len);
uint8_t *p2p_build_go_negotiation_req(const struct p2p_go_negotiation_req *data,
					size_t *out_len);
uint8_t *p2p_build_go_negotiation_resp(
				const struct p2p_go_negotiation_resp *data,
				size_t *out_len);
uint8_t *p2p_build_go_negotiation_confirmation(
			const struct p2p_go_negotiation_confirmation *data,
			size_t *out_len);
uint8_t *p2p_build_invitation_req(const struct p2p_invitation_req *data,
					size_t *out_len);
uint8_t *p2p_build_invitation_resp(const struct p2p_invitation_resp *data,
					size_t *out_len);
uint8_t *p2p_build_device_disc_req(
			const struct p2p_device_discoverability_req *data,
			size_t *out_len);
uint8_t *p2p_build_device_disc_resp(
			const struct p2p_device_discoverability_resp *data,
			size_t *out_len);
uint8_t *p2p_build_provision_disc_req(
				const struct p2p_provision_discovery_req *data,
				size_t *out_len);
uint8_t *p2p_build_provision_disc_resp(
				const struct p2p_provision_discovery_resp *data,
				size_t *out_len);
uint8_t *p2p_build_notice_of_absence(const struct p2p_notice_of_absence *data,
					size_t *out_len);
uint8_t *p2p_build_presence_req(const struct p2p_presence_req *data,
				size_t *out_len);
uint8_t *p2p_build_presence_resp(const struct p2p_presence_resp *data,
					size_t *out_len);
uint8_t *p2p_build_go_disc_req(size_t *out_len);

void p2p_get_random_string(char *buf, size_t len);
