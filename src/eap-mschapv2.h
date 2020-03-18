/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016  Markus Ongyerth. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

bool mschapv2_get_asymmetric_start_key(const uint8_t master_key[static 16],
				uint8_t *session_key, size_t session_len,
				bool server, bool send);

bool mschapv2_get_master_key(const uint8_t pw_hash_hash[static 16],
					const uint8_t nt_response[static 24],
					uint8_t master_key[static 16]);
