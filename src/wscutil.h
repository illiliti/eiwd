/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2015-2019  Intel Corporation. All rights reserved.
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

#include "src/defs.h"

struct iovec;

/* Wi-Fi Simple Configuration Technical Specification v2.0.5, Section 12 */
enum wsc_attr {
	WSC_ATTR_8021X_ENABLED					= 0x1062,
	WSC_ATTR_AP_CHANNEL					= 0x1001,
	WSC_ATTR_AP_SETUP_LOCKED				= 0x1057,
	WSC_ATTR_APPLICATION_EXTENTION				= 0x1058,
	WSC_ATTR_APP_SESSION_KEY				= 0x1063,
	WSC_ATTR_ASSOCIATION_STATE				= 0x1002,
	WSC_ATTR_AUTHENTICATION_TYPE				= 0x1003,
	WSC_ATTR_AUTHENTICATION_TYPE_FLAGS			= 0x1004,
	WSC_ATTR_AUTHENTICATOR					= 0x1005,
	WSC_ATTR_CONFIGURATION_ERROR				= 0x1009,
	WSC_ATTR_CONFIGURATION_METHODS				= 0x1008,
	WSC_ATTR_CONFIRMATION_URL4				= 0x100A,
	WSC_ATTR_CONFIRMATION_URL6				= 0x100B,
	WSC_ATTR_CONNECTION_TYPE				= 0x100C,
	WSC_ATTR_CONNECTION_TYPE_FLAGS				= 0x100D,
	WSC_ATTR_CREDENTIAL					= 0x100E,
	WSC_ATTR_DEVICE_NAME					= 0x1011,
	WSC_ATTR_DEVICE_PASSWORD_ID				= 0x1012,
	WSC_ATTR_EAP_IDENTITY					= 0x104D,
	WSC_ATTR_EAP_TYPE					= 0x1059,
	WSC_ATTR_E_HASH1					= 0x1014,
	WSC_ATTR_E_HASH2					= 0x1015,
	WSC_ATTR_ENCRYPTED_SETTINGS				= 0x1018,
	WSC_ATTR_ENCRYPTION_TYPE				= 0x100F,
	WSC_ATTR_ENCRYPTION_TYPE_FLAGS				= 0x1010,
	WSC_ATTR_ENROLLEE_NONCE					= 0x101A,
	WSC_ATTR_E_SNONCE1					= 0x1016,
	WSC_ATTR_E_SNONCE2					= 0x1017,
	WSC_ATTR_FEATURE_ID					= 0x101B,
	WSC_ATTR_IDENTITY					= 0x101C,
	WSC_ATTR_IDENTITY_PROOF					= 0x101D,
	WSC_ATTR_INITIALIZATION_VECTOR				= 0x1060,
	WSC_ATTR_KEY_IDENTIFIER					= 0x101F,
	WSC_ATTR_KEY_LIFETIME					= 0x1051,
	WSC_ATTR_KEY_PROVIDED_AUTOMATICALLY			= 0x1061,
	WSC_ATTR_KEY_WRAP_AUTHENTICATOR				= 0x101E,
	WSC_ATTR_MAC_ADDRESS					= 0x1020,
	WSC_ATTR_MANUFACTURER					= 0x1021,
	WSC_ATTR_MESSAGE_COUNTER				= 0x104E,
	WSC_ATTR_MESSAGE_TYPE					= 0x1022,
	WSC_ATTR_MODEL_NAME					= 0x1023,
	WSC_ATTR_MODEL_NUMBER					= 0x1024,
	WSC_ATTR_NETWORK_INDEX					= 0x1026,
	WSC_ATTR_NETWORK_KEY					= 0x1027,
	WSC_ATTR_NETWORK_KEY_INDEX				= 0x1028,
	WSC_ATTR_NEW_DEVICE_NAME				= 0x1029,
	WSC_ATTR_NEW_PASSWORD					= 0x102A,
	WSC_ATTR_OOB_DEVICE_PASSWORD				= 0x102C,
	WSC_ATTR_OS_VERSION					= 0x102D,
	WSC_ATTR_PERMITTED_CONFIGURATION_METHODS		= 0x1052,
	WSC_ATTR_PORTABLE_DEVICE				= 0x1056,
	WSC_ATTR_POWER_LEVEL					= 0x102F,
	WSC_ATTR_PRIMARY_DEVICE_TYPE				= 0x1054,
	WSC_ATTR_PSK_CURRENT					= 0x1030,
	WSC_ATTR_PSK_MAX					= 0x1031,
	WSC_ATTR_PUBLIC_KEY					= 0x1032,
	WSC_ATTR_PUBLIC_KEY_HASH				= 0x104F,
	WSC_ATTR_RADIO_ENABLED					= 0x1033,
	WSC_ATTR_REBOOT						= 0x1034,
	WSC_ATTR_REGISTRAR_CURRENT				= 0x1035,
	WSC_ATTR_REGISTRAR_ESTABLISHED				= 0x1036,
	WSC_ATTR_REGISTRAR_LIST					= 0x1037,
	WSC_ATTR_REGISTRAR_MAX					= 0x1038,
	WSC_ATTR_REGISTRAR_NONCE				= 0x1039,
	WSC_ATTR_REKEY_KEY					= 0x1050,
	WSC_ATTR_REQUEST_TYPE					= 0x103A,
	WSC_ATTR_REQUESTED_DEVICE_TYPE				= 0x106A,
	WSC_ATTR_RESPONSE_TYPE					= 0x103B,
	WSC_ATTR_RF_BANDS					= 0x103C,
	WSC_ATTR_R_HASH1					= 0x103D,
	WSC_ATTR_R_HASH2					= 0x103E,
	WSC_ATTR_R_SNONCE1					= 0x103F,
	WSC_ATTR_R_SNONCE2					= 0x1040,
	WSC_ATTR_SECONDARY_DEVICE_TYPE_LIST			= 0x1055,
	WSC_ATTR_SELECTED_REGISTRAR				= 0x1041,
	WSC_ATTR_SELECTED_REGISTRAR_CONFIGURATION_METHODS	= 0x1053,
	WSC_ATTR_SERIAL_NUMBER					= 0x1042,
	WSC_ATTR_SSID						= 0x1045,
	WSC_ATTR_TOTAL_NETWORKS					= 0x1046,
	WSC_ATTR_UUID_E						= 0x1047,
	WSC_ATTR_UUID_R						= 0x1048,
	WSC_ATTR_VENDOR_EXTENSION				= 0x1049,
	WSC_ATTR_VERSION					= 0x104A,
	WSC_ATTR_WEP_TRANSMIT_KEY				= 0x1064,
	WSC_ATTR_WSC_STATE					= 0x1044,
	WSC_ATTR_X509_CERTIFICATE_REQUEST			= 0x104B,
	WSC_ATTR_X509_CERTIFICATE				= 0x104C,
	WSC_ATTR_INVALID					= 0x0000,
};

/* Table 29 */
enum wsc_wfa_extension {
	WSC_WFA_EXTENSION_VERSION2				= 0x00,
	WSC_WFA_EXTENSION_AUTHORIZED_MACS			= 0x01,
	WSC_WFA_EXTENSION_NETWORK_KEY_SHAREABLE			= 0x02,
	WSC_WFA_EXTENSION_REQUEST_TO_ENROLL			= 0x03,
	WSC_WFA_EXTENSION_SETTINGS_DELAY_TIME			= 0x04,
	WSC_WFA_EXTENSION_REGISTRAR_CONFIGRATION_METHODS	= 0x05,
};

/* Table 31 */
enum wsc_association_state {
	WSC_ASSOCIATION_STATE_NOT_ASSOCIATED			= 0,
	WSC_ASSOCIATION_STATE_CONNECTION_SUCCESS		= 1,
	WSC_ASSOCIATION_STATE_CONFIGURATION_FAILURE		= 2,
	WSC_ASSOCIATION_STATE_ASSOCIATION_FAILURE		= 3,
	WSC_ASSOCIATION_STATE_IP_FAILURE			= 4,
};

/* Table 32 */
enum wsc_authentication_type {
	WSC_AUTHENTICATION_TYPE_OPEN			= 0x0001,
	WSC_AUTHENTICATION_TYPE_WPA_PERSONAL		= 0x0002,
	WSC_AUTHENTICATION_TYPE_SHARED			= 0x0004,
	WSC_AUTHENTICATION_TYPE_WPA_ENTERPRISE		= 0x0008,
	WSC_AUTHENTICATION_TYPE_WPA2_ENTERPRISE		= 0x0010,
	WSC_AUTHENTICATION_TYPE_WPA2_PERSONAL		= 0x0020,
};

/* Table 33 */
enum wsc_configration_method {
	WSC_CONFIGURATION_METHOD_USBA			= 0x0001,
	WSC_CONFIGURATION_METHOD_ETHERNET		= 0x0002,
	WSC_CONFIGURATION_METHOD_LABEL			= 0x0004,
	WSC_CONFIGURATION_METHOD_DISPLAY		= 0x0008,
	WSC_CONFIGURATION_METHOD_EXTERNAL_NFC_TOKEN	= 0x0010,
	WSC_CONFIGURATION_METHOD_INTEGRATED_NFC_TOKEN	= 0x0020,
	WSC_CONFIGURATION_METHOD_NFC_INTERFACE		= 0x0040,
	WSC_CONFIGURATION_METHOD_PUSH_BUTTON		= 0x0080,
	WSC_CONFIGURATION_METHOD_KEYPAD			= 0x0100,
	WSC_CONFIGURATION_METHOD_VIRTUAL_PUSH_BUTTON	= 0x0280,
	WSC_CONFIGURATION_METHOD_PHYSICAL_PUSH_BUTTON	= 0x0480,
	WSC_CONFIGURATION_METHOD_P2P			= 0x1000,
	WSC_CONFIGURATION_METHOD_VIRTUAL_DISPLAY_PIN	= 0x2008,
	WSC_CONFIGURATION_METHOD_PHYSICAL_DISPLAY_PIN	= 0x4008,
};

/* Table 34 */
enum wsc_configuration_error {
	WSC_CONFIGURATION_ERROR_NO_ERROR				= 0,
	WSC_CONFIGURATION_ERROR_OOB_INTERFACE_READ_ERROR		= 1,
	WSC_CONFIGURATION_ERROR_DECRYPTION_CRC_FAILURE			= 2,
	WSC_CONFIGURATION_ERROR_2_4_CHANNEL_NOT_SUPPORTED		= 3,
	WSC_CONFIGURATION_ERROR_5_0_CHANNEL_NOT_SUPPORTED		= 4,
	WSC_CONFIGURATION_ERROR_SIGNAL_TOO_WEAK				= 5,
	WSC_CONFIGURATION_ERROR_NETWORK_AUTH_FAILURE			= 6,
	WSC_CONFIGURATION_ERROR_NETWORK_ASSOCIATION_FAILURE		= 7,
	WSC_CONFIGURATION_ERROR_NO_DHCP_RESPONSE			= 8,
	WSC_CONFIGURATION_ERROR_FAILED_DHCP_CONFIG			= 9,
	WSC_CONFIGURATION_ERROR_IP_ADDRESS_CONFILICT			= 10,
	WSC_CONFIGURATION_ERROR_COULD_NOT_CONNECT_TO_REGISTRAR		= 11,
	WSC_CONFIGURATION_ERROR_MULTIPLE_PBC_SESSIONS_DETECTED		= 12,
	WSC_CONFIGURATION_ERROR_ROGUE_ACTIVITY_SUSPECTED		= 13,
	WSC_CONFIGURATION_ERROR_DEVICE_BUSY				= 14,
	WSC_CONFIGURATION_ERROR_SETUP_LOCKED				= 15,
	WSC_CONFIGURATION_ERROR_MESSAGE_TIMEOUT				= 16,
	WSC_CONFIGURATION_ERROR_REGISTRATION_SESSION_TIMEOUT		= 17,
	WSC_CONFIGURATION_ERROR_DEVICE_PASSWORD_AUTH_FAILURE		= 18,
	WSC_CONFIGURATION_ERROR_60_GHZ_CHANNEL_NOT_SUPPORTED		= 19,
	WSC_CONFIGURATION_ERROR_PUBLIC_KEY_HASH_MISMATCH		= 20,
};

/* Table 35 */
enum wsc_connection_type {
	WSC_CONNECTION_TYPE_ESS		= 0x1,
	WSC_CONNECTION_TYPE_IBSS	= 0x2,
};

/* Table 37 */
enum wsc_device_password_id {
	WSC_DEVICE_PASSWORD_ID_DEFAULT			= 0x0000,
	WSC_DEVICE_PASSWORD_ID_USER_SPECIFIED		= 0x0001,
	WSC_DEVICE_PASSWORD_ID_MACHINE_SPECIFIED	= 0x0002,
	WSC_DEVICE_PASSWORD_ID_REKEY			= 0x0003,
	WSC_DEVICE_PASSWORD_ID_PUSH_BUTTON		= 0x0004,
	WSC_DEVICE_PASSWORD_ID_REGISTRAR_SPECIFIED	= 0x0005,
	WSC_DEVICE_PASSWORD_ID_NFC_CONNECTION_HANDOVER	= 0x0007,
};

/* Table 38 */
enum wsc_encryption_type {
	WSC_ENCRYPTION_TYPE_NONE		= 0x0001,
	WSC_ENCRYPTION_TYPE_WEP			= 0x0002,
	WSC_ENCRYPTION_TYPE_TKIP		= 0x0004,
	WSC_ENCRYPTION_TYPE_AES			= 0x0008,
	WSC_ENCRYPTION_TYPE_AES_TKIP		= 0x000C,
};

/* Table 39 */
enum wsc_message_type {
	WSC_MESSAGE_TYPE_BEACON			= 0x01,
	WSC_MESSAGE_TYPE_PROBE_REQUEST		= 0x02,
	WSC_MESSAGE_TYPE_PROBE_RESPONSE		= 0x03,
	WSC_MESSAGE_TYPE_M1			= 0x04,
	WSC_MESSAGE_TYPE_M2			= 0x05,
	WSC_MESSAGE_TYPE_M2D			= 0x06,
	WSC_MESSAGE_TYPE_M3			= 0x07,
	WSC_MESSAGE_TYPE_M4			= 0x08,
	WSC_MESSAGE_TYPE_M5			= 0x09,
	WSC_MESSAGE_TYPE_M6			= 0x0A,
	WSC_MESSAGE_TYPE_M7			= 0x0B,
	WSC_MESSAGE_TYPE_M8			= 0x0C,
	WSC_MESSAGE_TYPE_WSC_ACK		= 0x0D,
	WSC_MESSAGE_TYPE_WSC_NACK		= 0x0E,
	WSC_MESSAGE_TYPE_WSC_DONE		= 0x0F,
};

/* Table 42 */
enum wsc_request_type {
	WSC_REQUEST_TYPE_ENROLLEE_INFO		= 0x00,
	WSC_REQUEST_TYPE_ENROLLEE_OPEN_8021X	= 0x01,
	WSC_REQUEST_TYPE_REGISTRAR		= 0x02,
	WSC_REQUEST_TYPE_WLAN_MANAGER_REGISTRAR	= 0x03,
};

/* Table 43 */
enum wsc_response_type {
	WSC_RESPONSE_TYPE_ENROLLEE_INFO		= 0x00,
	WSC_RESPONSE_TYPE_ENROLLEE_OPEN_8021X	= 0x01,
	WSC_RESPONSE_TYPE_REGISTRAR		= 0x02,
	WSC_RESPONSE_TYPE_AP			= 0x03,
};

/* Table 44 */
enum wsc_rf_band {
	WSC_RF_BAND_2_4_GHZ			= 0x01,
	WSC_RF_BAND_5_0_GHZ			= 0x02,
	WSC_RF_BAND_60_GHZ			= 0x04,
};

/* Table 45 */
enum wsc_state {
	WSC_STATE_NOT_CONFIGURED	= 0x01,
	WSC_STATE_CONFIGURED		= 0x02,
};

extern const unsigned char wsc_wfa_oui[3];

struct wsc_wfa_ext_iter {
	unsigned short max;
	unsigned short pos;
	const unsigned char *pdu;
	unsigned char type;
	unsigned char len;
	const unsigned char *data;
};

void wsc_wfa_ext_iter_init(struct wsc_wfa_ext_iter *iter,
				const unsigned char *pdu, unsigned short len);
bool wsc_wfa_ext_iter_next(struct wsc_wfa_ext_iter *iter);

static inline unsigned char wsc_wfa_ext_iter_get_type(
						struct wsc_wfa_ext_iter *iter)
{
	return iter->type;
}

static inline unsigned char wsc_wfa_ext_iter_get_length(
						struct wsc_wfa_ext_iter *iter)
{
	return iter->len;
}

static inline const unsigned char *wsc_wfa_ext_iter_get_data(
						struct wsc_wfa_ext_iter *iter)
{
	return iter->data;
}

struct wsc_attr_iter {
	unsigned int max;
	unsigned int pos;
	const unsigned char *pdu;
	unsigned short type;
	unsigned short len;
	const unsigned char *data;
};

void wsc_attr_iter_init(struct wsc_attr_iter *iter, const unsigned char *pdu,
			unsigned int len);
bool wsc_attr_iter_next(struct wsc_attr_iter *iter);
bool wsc_attr_iter_recurse_wfa_ext(struct wsc_attr_iter *iter,
					struct wsc_wfa_ext_iter *wfa_iter);

static inline unsigned int wsc_attr_iter_get_type(struct wsc_attr_iter *iter)
{
	return iter->type;
}

static inline unsigned int wsc_attr_iter_get_length(struct wsc_attr_iter *iter)
{
	return iter->len;
}

static inline const unsigned char *wsc_attr_iter_get_data(
						struct wsc_attr_iter *iter)
{
	return iter->data;
}

static inline unsigned int wsc_attr_iter_get_pos(struct wsc_attr_iter *iter)
{
	return iter->pos;
}

struct wsc_credential {
	uint8_t ssid[SSID_MAX_SIZE];
	uint8_t ssid_len;
	uint16_t auth_type;
	uint16_t encryption_type;
	uint8_t network_key[65];	/* max 64 + space for null terminator */
	uint8_t network_key_len;
	uint8_t addr[6];
};

struct wsc_primary_device_type {
	uint16_t category;
	uint8_t oui[3];
	uint8_t oui_type;
	uint16_t subcategory;
};

struct wsc_beacon {
	bool version2;
	enum wsc_state state;
	bool ap_setup_locked;
	bool selected_registrar;
	enum wsc_device_password_id device_password_id;
	uint16_t selected_reg_config_methods;
	uint8_t uuid_e[16];
	uint8_t rf_bands;
	uint8_t authorized_macs[30];
	uint16_t reg_config_methods;
};

struct wsc_probe_response {
	bool version2;
	enum wsc_state state;
	bool ap_setup_locked;
	bool selected_registrar;
	enum wsc_device_password_id device_password_id;
	uint16_t selected_reg_config_methods;
	enum wsc_response_type response_type;
	uint8_t uuid_e[16];
	char manufacturer[65];
	char model_name[33];
	char model_number[33];
	char serial_number[33];
	struct wsc_primary_device_type primary_device_type;
	char device_name[33];
	uint16_t config_methods;
	uint8_t rf_bands;
	uint8_t authorized_macs[30];
	uint16_t reg_config_methods;
};

struct wsc_probe_request {
	bool version2;
	enum wsc_request_type request_type;
	uint16_t config_methods;
	uint8_t uuid_e[16];
	struct wsc_primary_device_type primary_device_type;
	uint8_t rf_bands;
	enum wsc_association_state association_state;
	enum wsc_configuration_error configuration_error;
	enum wsc_device_password_id device_password_id;
	char manufacturer[65];
	char model_name[33];
	char model_number[33];
	char serial_number[33];
	char device_name[33];
	bool request_to_enroll;
	struct wsc_primary_device_type requested_device_type;
};

struct wsc_association_request {
	bool version2;
	enum wsc_request_type request_type;
};

struct wsc_association_response {
	bool version2;
	enum wsc_response_type response_type;
};

struct wsc_m1 {
	bool version2;
	uint8_t uuid_e[16];
	uint8_t addr[6];
	uint8_t enrollee_nonce[16];
	uint8_t public_key[192];
	uint16_t auth_type_flags;
	uint16_t encryption_type_flags;
	uint8_t connection_type_flags;
	uint16_t config_methods;
	enum wsc_state state;
	char manufacturer[65];
	char model_name[33];
	char model_number[33];
	char serial_number[33];
	struct wsc_primary_device_type primary_device_type;
	char device_name[33];
	uint8_t rf_bands;
	enum wsc_association_state association_state;
	enum wsc_device_password_id device_password_id;
	enum wsc_configuration_error configuration_error;
	uint32_t os_version;
	bool request_to_enroll;
};

struct wsc_m2 {
	bool version2;
	uint8_t enrollee_nonce[16];
	uint8_t registrar_nonce[16];
	uint8_t uuid_r[16];
	uint8_t public_key[192];
	uint16_t auth_type_flags;
	uint16_t encryption_type_flags;
	uint8_t connection_type_flags;
	uint16_t config_methods;
	char manufacturer[65];
	char model_name[33];
	char model_number[33];
	char serial_number[33];
	struct wsc_primary_device_type primary_device_type;
	char device_name[33];
	uint8_t rf_bands;
	enum wsc_association_state association_state;
	enum wsc_configuration_error configuration_error;
	enum wsc_device_password_id device_password_id;
	uint32_t os_version;
	uint8_t authenticator[8];
};

struct wsc_m3 {
	bool version2;
	uint8_t registrar_nonce[16];
	uint8_t e_hash1[32];
	uint8_t e_hash2[32];
	uint8_t authenticator[8];
};

struct wsc_m4 {
	bool version2;
	uint8_t enrollee_nonce[16];
	uint8_t r_hash1[32];
	uint8_t r_hash2[32];
	uint8_t authenticator[8];
};

struct wsc_m4_encrypted_settings {
	uint8_t r_snonce1[16];
	uint8_t authenticator[8];
};

struct wsc_m5 {
	bool version2;
	uint8_t registrar_nonce[16];
	uint8_t authenticator[8];
};

struct wsc_m5_encrypted_settings {
	uint8_t e_snonce1[16];
	uint8_t authenticator[8];
};

struct wsc_m6 {
	bool version2;
	uint8_t enrollee_nonce[16];
	uint8_t authenticator[8];
};

struct wsc_m6_encrypted_settings {
	uint8_t r_snonce2[16];
	uint8_t authenticator[8];
};

struct wsc_m7 {
	bool version2;
	uint8_t registrar_nonce[16];
	uint8_t authenticator[8];
};

struct wsc_m7_encrypted_settings {
	uint8_t e_snonce2[16];
	uint8_t authenticator[8];
};

struct wsc_m8 {
	bool version2;
	uint8_t enrollee_nonce[16];
	uint8_t authenticator[8];
};

struct wsc_m8_encrypted_settings {
	uint8_t new_password[64];
	uint8_t new_password_len;
	enum wsc_device_password_id device_password_id;
	uint8_t authenticator[8];
};

struct wsc_ack {
	bool version2;
	uint8_t enrollee_nonce[16];
	uint8_t registrar_nonce[16];
};

struct wsc_nack {
	bool version2;
	uint8_t enrollee_nonce[16];
	uint8_t registrar_nonce[16];
	enum wsc_configuration_error configuration_error;
};

struct wsc_done {
	bool version2;
	uint8_t enrollee_nonce[16];
	uint8_t registrar_nonce[16];
};

int wsc_parse_primary_device_type(const uint8_t *pdu, size_t len,
					struct wsc_primary_device_type *out);

enum wsc_attr_flag {
	WSC_ATTR_FLAG_REQUIRED  = 0x1,  /* Always required */
	WSC_ATTR_FLAG_VERSION2  = 0x2,  /* Included if Version2 is present */
	WSC_ATTR_FLAG_REGISTRAR = 0x4,  /* Included if Selected Registrar is true */
};

int wsc_parse_attrs(const unsigned char *pdu, unsigned int len,
			bool *out_version2, struct wsc_wfa_ext_iter *ext_iter,
			enum wsc_attr authenticator_type,
			uint8_t *authenticator, int type, ...);

int wsc_parse_credential(const uint8_t *pdu, uint32_t len,
						struct wsc_credential *out);

int wsc_parse_beacon(const unsigned char *pdu, unsigned int len,
				struct wsc_beacon *out);
int wsc_parse_probe_response(const unsigned char *pdu, unsigned int len,
				struct wsc_probe_response *out);
int wsc_parse_probe_request(const unsigned char *pdu, unsigned int len,
				struct wsc_probe_request *out);
int wsc_parse_association_request(const uint8_t *pdu, uint32_t len,
					struct wsc_association_request *out);
int wsc_parse_association_response(const uint8_t *pdu, uint32_t len,
					struct wsc_association_response *out);

int wsc_parse_m1(const uint8_t *pdu, uint32_t len, struct wsc_m1 *out);
int wsc_parse_m2(const uint8_t *pdu, uint32_t len, struct wsc_m2 *out);
int wsc_parse_m3(const uint8_t *pdu, uint32_t len, struct wsc_m3 *out);
int wsc_parse_m4(const uint8_t *pdu, uint32_t len, struct wsc_m4 *out,
						struct iovec *out_encrypted);
int wsc_parse_m4_encrypted_settings(const uint8_t *pdu, uint32_t len,
					struct wsc_m4_encrypted_settings *out);
int wsc_parse_m5(const uint8_t *pdu, uint32_t len, struct wsc_m5 *out,
						struct iovec *out_encrypted);
int wsc_parse_m5_encrypted_settings(const uint8_t *pdu, uint32_t len,
					struct wsc_m5_encrypted_settings *out);
int wsc_parse_m6(const uint8_t *pdu, uint32_t len, struct wsc_m6 *out,
						struct iovec *out_encrypted);
int wsc_parse_m6_encrypted_settings(const uint8_t *pdu, uint32_t len,
					struct wsc_m6_encrypted_settings *out);
int wsc_parse_m7(const uint8_t *pdu, uint32_t len, struct wsc_m7 *out,
						struct iovec *out_encrypted);
int wsc_parse_m7_encrypted_settings(const uint8_t *pdu, uint32_t len,
					struct wsc_m7_encrypted_settings *out);
int wsc_parse_m8(const uint8_t *pdu, uint32_t len, struct wsc_m8 *out,
						struct iovec *out_encrypted);
int wsc_parse_m8_encrypted_settings(const uint8_t *pdu, uint32_t len,
					struct wsc_m8_encrypted_settings *out,
					struct iovec *iov, size_t *iovcnt);

int wsc_parse_wsc_ack(const uint8_t *pdu, uint32_t len, struct wsc_ack *out);
int wsc_parse_wsc_nack(const uint8_t *pdu, uint32_t len, struct wsc_nack *out);

int wsc_parse_wsc_done(const uint8_t *pdu, uint32_t len, struct wsc_done *out);

uint8_t *wsc_build_credential(const struct wsc_credential *in, size_t *out_len);

uint8_t *wsc_build_beacon(const struct wsc_beacon *beacon, size_t *out_len);
uint8_t *wsc_build_probe_request(const struct wsc_probe_request *probe_request,
				size_t *out_len);
uint8_t *wsc_build_probe_response(
		const struct wsc_probe_response *probe_response,
		size_t *out_len);
uint8_t *wsc_build_association_request(
		const struct wsc_association_request *association_request,
		size_t *out_len);
uint8_t *wsc_build_association_response(
		const struct wsc_association_response *association_response,
		size_t *out_len);

uint8_t *wsc_build_m1(const struct wsc_m1 *m1, size_t *out_len);
uint8_t *wsc_build_m2(const struct wsc_m2 *m2, size_t *out_len);
uint8_t *wsc_build_m3(const struct wsc_m3 *m3, size_t *out_len);
uint8_t *wsc_build_m4(const struct wsc_m4 *m4, const uint8_t *encrypted,
			size_t encrypted_len, size_t *out_len);
uint8_t *wsc_build_m4_encrypted_settings(
				const struct wsc_m4_encrypted_settings *in,
				size_t *out_len);
uint8_t *wsc_build_m5(const struct wsc_m5 *m5, const uint8_t *encrypted,
			size_t encrypted_len, size_t *out_len);
uint8_t *wsc_build_m5_encrypted_settings(
				const struct wsc_m5_encrypted_settings *in,
				size_t *out_len);
uint8_t *wsc_build_m6(const struct wsc_m6 *m6, const uint8_t *encrypted,
			size_t encrypted_len, size_t *out_len);
uint8_t *wsc_build_m6_encrypted_settings(
				const struct wsc_m6_encrypted_settings *in,
				size_t *out_len);
uint8_t *wsc_build_m7(const struct wsc_m7 *m7, const uint8_t *encrypted,
			size_t encrypted_len, size_t *out_len);
uint8_t *wsc_build_m7_encrypted_settings(
				const struct wsc_m7_encrypted_settings *in,
				size_t *out_len);
uint8_t *wsc_build_m8(const struct wsc_m8 *m8, const uint8_t *encrypted,
			size_t encrypted_len, size_t *out_len);
uint8_t *wsc_build_m8_encrypted_settings(
				const struct wsc_m8_encrypted_settings *in,
				const struct wsc_credential *creds,
				unsigned int creds_cnt, size_t *out_len);

uint8_t *wsc_build_wsc_ack(const struct wsc_ack *ack, size_t *out_len);
uint8_t *wsc_build_wsc_nack(const struct wsc_nack *nack, size_t *out_len);

uint8_t *wsc_build_wsc_done(const struct wsc_done *done, size_t *out_len);

struct wsc_p2p_attrs {
	bool version;
	bool version2;
	enum wsc_device_password_id device_password_id;
	uint16_t config_methods;
};

uint8_t *wsc_build_p2p_attrs(const struct wsc_p2p_attrs *attrs,
				size_t *out_len);

bool wsc_uuid_from_addr(const uint8_t addr[], uint8_t *out_uuid);

struct wsc_session_key {
	uint8_t auth_key[32];
	uint8_t keywrap_key[16];
	uint8_t emsk[32];
} __attribute__ ((packed));

bool wsc_kdf(const void *kdk, void *output, size_t size);

bool wsc_pin_is_valid(const char *pin);
bool wsc_pin_is_checksum_valid(const char *pin);
bool wsc_pin_generate(char *pin);

bool wsc_device_type_to_dbus_str(const struct wsc_primary_device_type *val,
					const char **category_str,
					const char **subcategory_str);
bool wsc_device_type_from_subcategory_str(struct wsc_primary_device_type *out,
						const char *subcategory_str);
bool wsc_device_type_from_setting_str(const char *value,
					struct wsc_primary_device_type *out);
