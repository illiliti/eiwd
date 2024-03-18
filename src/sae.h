/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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

struct auth_proto;
struct sae_sm;
struct handshake_state;

typedef void (*sae_tx_authenticate_func_t)(const uint8_t *data, size_t len,
						void *user_data);
typedef void (*sae_tx_associate_func_t)(void *user_data);

bool sae_sm_is_h2e(struct auth_proto *ap);

struct auth_proto *sae_sm_new(struct handshake_state *hs,
				sae_tx_authenticate_func_t tx_auth,
				sae_tx_associate_func_t tx_assoc,
				void *user_data);
