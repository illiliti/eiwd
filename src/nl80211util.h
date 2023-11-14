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

#include <ell/ell.h>

struct band_chandef;
struct scan_freq_set;
struct band_freq_attrs;

int nl80211_parse_attrs(struct l_genl_msg *msg, int tag, ...);

struct l_genl_msg *nl80211_build_deauthenticate(uint32_t ifindex,
						const uint8_t addr[static 6],
						uint16_t reason_code);
struct l_genl_msg *nl80211_build_disconnect(uint32_t ifindex,
							uint16_t reason_code);

struct l_genl_msg *nl80211_build_del_station(uint32_t ifindex,
						const uint8_t addr[static 6],
						uint16_t reason_code,
						uint8_t subtype);

struct l_genl_msg *nl80211_build_new_key_group(uint32_t ifindex,
					uint32_t cipher, uint8_t key_id,
					const uint8_t *key, size_t key_len,
					const uint8_t *ctr, size_t ctr_len,
					const uint8_t *addr);
struct l_genl_msg *nl80211_build_new_key_pairwise(uint32_t ifindex,
						uint32_t cipher,
						const uint8_t addr[static 6],
						const uint8_t *tk,
						size_t tk_len,
						uint8_t key_id);

struct l_genl_msg *nl80211_build_set_station_authorized(uint32_t ifindex,
							const uint8_t *addr);

struct l_genl_msg *nl80211_build_set_station_associated(uint32_t ifindex,
							const uint8_t *addr);

struct l_genl_msg *nl80211_build_set_station_unauthorized(uint32_t ifindex,
							const uint8_t *addr);

struct l_genl_msg *nl80211_build_set_key(uint32_t ifindex, uint8_t key_index);

struct l_genl_msg *nl80211_build_get_key(uint32_t ifindex, uint8_t key_index);

const void *nl80211_parse_get_key_seq(struct l_genl_msg *msg);

struct l_genl_msg *nl80211_build_cmd_frame(uint32_t ifindex,
						uint16_t frame_type,
						const uint8_t *addr,
						const uint8_t *to,
						uint32_t freq,
						struct iovec *iov,
						size_t iov_len);

int nl80211_parse_chandef(struct l_genl_msg *msg, struct band_chandef *out);
int nl80211_parse_supported_frequencies(struct l_genl_attr *band_freqs,
					struct scan_freq_set *supported_list,
					struct band_freq_attrs *list,
					size_t num_channels);
