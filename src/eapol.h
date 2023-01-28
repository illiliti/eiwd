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
#include "src/eapolutil.h"

struct eapol_sm;
struct handshake_state;
struct preauth_sm;
enum handshake_kde;
enum ie_rsn_akm_suite;

typedef int (*eapol_tx_packet_func_t)(uint32_t ifindex,
					const uint8_t *dest, uint16_t proto,
					const struct eapol_frame *ef,
					bool noencrypt,
					void *user_data);
typedef void (*eapol_rekey_offload_func_t)(uint32_t ifindex,
					const uint8_t *kek,
					const uint8_t *kck,
					uint64_t replay_counter,
					void *user_data);
typedef void (*eapol_sm_event_func_t)(unsigned int event,
							const void *event_data,
							void *user_data);
typedef void (*eapol_preauth_cb_t)(const uint8_t *pmk, void *user_data);
typedef void (*eapol_preauth_destroy_func_t)(void *user_data);
typedef void (*eapol_frame_watch_func_t)(uint16_t proto, const uint8_t *from,
						const struct eapol_frame *frame,
						bool noencrypt,
						void *user_data);
typedef void (*eapol_install_pmk_func_t)(struct handshake_state *hs,
						const uint8_t *pmk,
						size_t pmk_len);

bool eapol_calculate_mic(enum ie_rsn_akm_suite akm, const uint8_t *kck,
				const struct eapol_key *frame, uint8_t *mic,
				size_t mic_len);
bool eapol_verify_mic(enum ie_rsn_akm_suite akm, const uint8_t *kck,
			const struct eapol_key *frame, size_t mic_len);

uint8_t *eapol_decrypt_key_data(enum ie_rsn_akm_suite akm, const uint8_t *kek,
				const struct eapol_key *frame,
				size_t *decrypted_size, size_t mic_len);

bool eapol_verify_ptk_1_of_4(const struct eapol_key *ek, size_t mic_len,
				bool ptk_complete);
bool eapol_verify_ptk_2_of_4(const struct eapol_key *ek, bool ptk_complete);
bool eapol_verify_ptk_3_of_4(const struct eapol_key *ek, bool is_wpa,
				size_t mic_len);
bool eapol_verify_ptk_4_of_4(const struct eapol_key *ek, bool is_wpa);
bool eapol_verify_gtk_1_of_2(const struct eapol_key *ek, bool is_wpa,
				size_t mic_len);
bool eapol_verify_gtk_2_of_2(const struct eapol_key *ek, bool is_wpa);

struct eapol_key *eapol_create_ptk_2_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				const uint8_t snonce[],
				size_t extra_len,
				const uint8_t *extra_data,
				bool is_wpa,
				size_t mic_len,
				bool secure);

struct eapol_key *eapol_create_ptk_4_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				bool is_wpa,
				size_t mic_len);

struct eapol_key *eapol_create_gtk_2_of_2(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				size_t extra_len,
				const uint8_t *extra_data,
				bool is_wpa, uint8_t wpa_key_id,
				size_t mic_len);

void __eapol_rx_packet(uint32_t ifindex, const uint8_t *src, uint16_t proto,
			const uint8_t *frame, size_t len, bool noencrypt);
void __eapol_tx_packet(uint32_t ifindex, const uint8_t *dst, uint16_t proto,
			const struct eapol_frame *frame, bool noencrypt);
void __eapol_set_tx_packet_func(eapol_tx_packet_func_t func);
void __eapol_set_tx_user_data(void *user_data);

void __eapol_set_install_pmk_func(eapol_install_pmk_func_t func);

void __eapol_set_rekey_offload_func(eapol_rekey_offload_func_t func);
void __eapol_update_replay_counter(uint32_t ifindex, const uint8_t *spa,
				const uint8_t *aa, uint64_t replay_counter);
void __eapol_set_config(struct l_settings *config);

struct eapol_sm *eapol_sm_new(struct handshake_state *hs);
void eapol_sm_free(struct eapol_sm *sm);

void eapol_sm_set_protocol_version(struct eapol_sm *sm,
				enum eapol_protocol_version protocol_version);

void eapol_sm_set_use_eapol_start(struct eapol_sm *sm, bool enabled);
void eapol_sm_set_require_handshake(struct eapol_sm *sm, bool enabled);
void eapol_sm_set_listen_interval(struct eapol_sm *sm, uint16_t interval);
void eapol_sm_set_user_data(struct eapol_sm *sm, void *user_data);

void eapol_register(struct eapol_sm *sm);
bool eapol_start(struct eapol_sm *sm);

struct preauth_sm *eapol_preauth_start(const uint8_t *aa,
					const struct handshake_state *hs,
					eapol_preauth_cb_t cb, void *user_data,
					eapol_preauth_destroy_func_t destroy);
void eapol_preauth_cancel(uint32_t ifindex);

int eapol_init(void);
void eapol_exit(void);
