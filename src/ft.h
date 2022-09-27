/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
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

struct handshake_state;
struct scan_bss;

typedef int (*ft_tx_frame_func_t)(uint32_t ifindex, uint16_t frame_type,
					uint32_t frequency,
					const uint8_t *dest, struct iovec *iov,
					size_t iov_len);

typedef void (*ft_tx_authenticate_func_t)(struct iovec *iov, size_t iov_len,
					void *user_data);

typedef int (*ft_tx_associate_func_t)(uint32_t ifindex, uint32_t freq,
					const uint8_t *prev_bssid,
					struct iovec *ie_iov, size_t iov_len);
typedef int (*ft_get_oci)(void *user_data);

typedef void (*ft_ds_free_func_t)(void *user_data);

struct ft_ds_info {
	uint8_t spa[6];
	uint8_t aa[6];
	uint8_t snonce[32];
	uint8_t mde[3];
	uint8_t *fte;
	uint8_t *authenticator_ie;

	struct ie_ft_info ft_info;

	void (*free)(struct ft_ds_info *s);
};

void ft_ds_info_free(struct ft_ds_info *info);

bool ft_build_authenticate_ies(struct handshake_state *hs, bool ocvc,
				const uint8_t *new_snonce, uint8_t *buf,
				size_t *len);

int ft_over_ds_parse_action_response(const uint8_t *frame, size_t frame_len,
					const uint8_t **spa_out,
					const uint8_t **aa_out,
					const uint8_t **ies_out,
					size_t *ies_len);
bool ft_over_ds_parse_action_ies(struct ft_ds_info *info,
					struct handshake_state *hs,
					const uint8_t *ies,
					size_t ies_len);

struct auth_proto *ft_over_air_sm_new(struct handshake_state *hs,
				ft_tx_authenticate_func_t tx_auth,
				ft_tx_associate_func_t tx_assoc,
				ft_get_oci get_oci,
				void *user_data);

struct auth_proto *ft_over_ds_sm_new(struct handshake_state *hs,
				ft_tx_associate_func_t tx_assoc,
				void *user_data);

bool ft_over_ds_prepare_handshake(struct ft_ds_info *info,
					struct handshake_state *hs);

void __ft_set_tx_frame_func(ft_tx_frame_func_t func);
void __ft_set_tx_associate_func(ft_tx_associate_func_t func);
int __ft_rx_associate(uint32_t ifindex, const uint8_t *frame,
			size_t frame_len);
void __ft_rx_action(uint32_t ifindex, const uint8_t *frame, size_t frame_len);

void ft_clear_authentications(uint32_t ifindex);
int ft_action(uint32_t ifindex, uint32_t freq, const struct scan_bss *target);
int ft_associate(uint32_t ifindex, const uint8_t *addr);
