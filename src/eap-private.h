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

#include <stdint.h>
#include <stdbool.h>
#include <asm/byteorder.h>
#include <linux/types.h>

struct eap_state;

/* EAP method API */

enum eap_type {
	EAP_TYPE_IDENTITY	= 1,
	EAP_TYPE_NOTIFICATION	= 2,
	EAP_TYPE_NAK		= 3,
	__EAP_TYPE_MIN_METHOD	= 4,
	EAP_TYPE_MD5_CHALLENGE	= 4,
	EAP_TYPE_GTC		= 6,
	EAP_TYPE_TLS		= 13,
	EAP_TYPE_SIM		= 18,
	EAP_TYPE_TTLS		= 21,
	EAP_TYPE_AKA		= 23,
	EAP_TYPE_PEAP		= 25,
	EAP_TYPE_EXTENSIONS	= 33,
	EAP_TYPE_AKA_PRIME	= 50,
	EAP_TYPE_MSCHAPV2	= 26,
	EAP_TYPE_PWD		= 52,
	EAP_TYPE_EXPANDED	= 254,
};

enum eap_code {
	EAP_CODE_REQUEST	= 1,
	EAP_CODE_RESPONSE	= 2,
	EAP_CODE_SUCCESS	= 3,
	EAP_CODE_FAILURE	= 4,
	EAP_CODE_INITIATE	= 5,
	EAP_CODE_FINISH		= 6,
};

struct eap_method {
	enum eap_type request_type;
	uint8_t vendor_id[3];
	uint32_t vendor_type;
	bool exports_msk;
	const char *name;

	int (*check_settings)(struct l_settings *settings,
				struct l_queue *secrets, const char *prefix,
				struct l_queue **out_missing);

	bool (*load_settings)(struct eap_state *eap,
				struct l_settings *settings,
				const char *prefix);

	/* Reset the internal state back to initial conditions */
	bool (*reset_state)(struct eap_state *eap);
	void (*free)(struct eap_state *eap);

	void (*handle_request)(struct eap_state *eap,
				const uint8_t *pkt, size_t len);
	void (*handle_retransmit)(struct eap_state *eap,
				const uint8_t *pkt, size_t len);
	const char *(*get_identity)(struct eap_state *eap);

	bool (*validate_identity)(struct eap_state *eap, const char *identity);
	void (*handle_response)(struct eap_state *eap,
				const uint8_t *pkt, size_t len);
};

struct eap_method_desc {
	const char *name;
	int (*init)(void);
	void (*exit)(void);
} __attribute__((aligned(8)));

#define EAP_METHOD_BUILTIN(name, init, exit)				\
	_Pragma("GCC diagnostic push")					\
	_Pragma("GCC diagnostic ignored \"-Wattributes\"")		\
	static struct eap_method_desc __eap_builtin_ ## name		\
		__attribute__((used, retain, section("__eap"),		\
			       aligned(8))) = {				\
			#name, init, exit				\
		};							\
	_Pragma("GCC diagnostic pop")

int eap_register_method(struct eap_method *method);
int eap_unregister_method(struct eap_method *method);

/* Private EAP API */

int __eap_check_settings(struct l_settings *settings, struct l_queue *secrets,
				const char *prefix, bool set_key_material,
				struct l_queue **missing);
void __eap_handle_request(struct eap_state *eap, uint16_t id,
						const uint8_t *pkt, size_t len);

void eap_discard_success_and_failure(struct eap_state *eap, bool discard);

void eap_set_data(struct eap_state *eap, void *data);
void *eap_get_data(struct eap_state *eap);

enum eap_type eap_get_method_type(struct eap_state *eap);
const char *eap_get_method_name(struct eap_state *eap);

void eap_set_key_material(struct eap_state *eap,
				const uint8_t *msk_data, size_t msk_len,
				const uint8_t *emsk_data, size_t emsk_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *session_id, size_t session_len);

void eap_start_complete_timeout(struct eap_state *eap);

void eap_method_respond(struct eap_state *eap, uint8_t *buf, size_t len);
void eap_method_new_request(struct eap_state *eap, uint8_t *buf, size_t len);
bool eap_method_is_success(struct eap_state *eap);
void eap_method_success(struct eap_state *eap);
void eap_method_error(struct eap_state *eap);
void eap_method_event(struct eap_state *eap, unsigned int type,
							const void *data);

void eap_save_last_id(struct eap_state *eap, uint8_t *last_id);
void eap_restore_last_id(struct eap_state *eap, uint8_t last_id);
