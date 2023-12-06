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

struct scan_bss;

typedef int (*ft_tx_frame_func_t)(uint32_t ifindex, uint16_t frame_type,
					uint32_t frequency,
					const uint8_t *dest, struct iovec *iov,
					size_t iov_len);

typedef int (*ft_tx_associate_func_t)(uint32_t ifindex, uint32_t freq,
					const uint8_t *prev_bssid,
					struct iovec *ie_iov, size_t iov_len);

void __ft_set_tx_frame_func(ft_tx_frame_func_t func);
void __ft_set_tx_associate_func(ft_tx_associate_func_t func);
int __ft_rx_associate(uint32_t ifindex, const uint8_t *frame,
			size_t frame_len);
void __ft_rx_action(uint32_t ifindex, const uint8_t *frame, size_t frame_len);
void __ft_rx_authenticate(uint32_t ifindex, const uint8_t *frame,
				size_t frame_len);

int ft_handshake_setup(uint32_t ifindex, const uint8_t *target);

void ft_clear_authentications(uint32_t ifindex);
int ft_action(uint32_t ifindex, uint32_t freq, const struct scan_bss *target);
int ft_associate(uint32_t ifindex, const uint8_t *addr);
int ft_authenticate(uint32_t ifindex, const struct scan_bss *target);
int ft_authenticate_onchannel(uint32_t ifindex, const struct scan_bss *target);
