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

struct wsc_credentials_info {
	char ssid[SSID_MAX_SIZE + 1];
	enum security security;
	union {
		uint8_t psk[32];
		char passphrase[64];
	};
	uint8_t addr[6];
	bool has_passphrase;
};

struct wsc_enrollee;

typedef void (*wsc_done_cb_t)(int err, struct wsc_credentials_info *creds,
				unsigned int n_creds, void *user_data);

struct wsc_enrollee *wsc_enrollee_new(struct netdev *netdev,
					struct scan_bss *target,
					const char *pin,
					struct iovec *ies, unsigned int ies_num,
					wsc_done_cb_t done_cb, void *user_data);
void wsc_enrollee_cancel(struct wsc_enrollee *wsce, bool defer_cb);
void wsc_enrollee_free(struct wsc_enrollee *wsce);

struct wsc_dbus {
	struct l_dbus_message *pending_connect;
	struct l_dbus_message *pending_cancel;

	const char *(*get_path)(struct wsc_dbus *wsc);
	void (*connect)(struct wsc_dbus *wsc, const char *pin);
	void (*cancel)(struct wsc_dbus *wsc);
	void (*remove)(struct wsc_dbus *wsc);
};

bool wsc_dbus_add_interface(struct wsc_dbus *wsc);
void wsc_dbus_remove_interface(struct wsc_dbus *wsc);
