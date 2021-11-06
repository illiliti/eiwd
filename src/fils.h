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

struct fils_sm;
struct handshake_state;

typedef void (*fils_tx_authenticate_func_t)(const uint8_t *data,
						size_t len,
						void *user_data);
typedef void (*fils_tx_associate_func_t)(struct iovec *iov, size_t iov_len,
					const uint8_t *kek, size_t kek_len,
					const uint8_t *nonces, size_t nonces_len,
					void *user_data);
typedef int (*fils_get_oci_func_t)(void *user_data);

struct auth_proto *fils_sm_new(struct handshake_state *hs,
				fils_tx_authenticate_func_t auth,
				fils_tx_associate_func_t assoc,
				fils_get_oci_func_t get_oci,
				void *user_data);
