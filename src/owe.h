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

struct owe_sm;
struct handshake_state;

struct owe_sm *owe_sm_new(struct handshake_state *hs);
void owe_sm_free(struct owe_sm *sm);

void owe_build_dh_ie(struct owe_sm *sm, uint8_t *buf, size_t *len_out);
int owe_process_dh_ie(struct owe_sm *sm, const uint8_t *dh, size_t len);
bool owe_next_group(struct owe_sm *sm);
