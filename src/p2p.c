/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
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

#include <stdlib.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/wiphy.h"
#include "src/scan.h"
#include "src/p2putil.h"
#include "src/ie.h"
#include "src/util.h"
#include "src/dbus.h"
#include "src/netdev.h"
#include "src/mpdu.h"
#include "src/common.h"
#include "src/wsc.h"
#include "src/handshake.h"
#include "src/crypto.h"
#include "src/module.h"
#include "src/frame-xchg.h"
#include "src/nl80211util.h"
#include "src/p2p.h"

struct p2p_device {
	uint64_t wdev_id;
	uint8_t addr[6];
	struct wiphy *wiphy;
	unsigned int connections_left;

	struct l_queue *peer_list;
};

struct p2p_peer {
	struct scan_bss *bss;
	struct p2p_device *dev;
	char *name;
};

static struct l_queue *p2p_device_list;

static bool p2p_device_match(const void *a, const void *b)
{
	const struct p2p_device *dev = a;
	const uint64_t *wdev_id = b;

	return dev->wdev_id == *wdev_id;
}

struct p2p_device *p2p_device_find(uint64_t wdev_id)
{
	return l_queue_find(p2p_device_list, p2p_device_match, &wdev_id);
}

static const char *p2p_device_get_path(const struct p2p_device *dev)
{
	return wiphy_get_path(dev->wiphy);
}

static const char *p2p_peer_get_path(const struct p2p_peer *peer)
{
	static char path[256];

	snprintf(path, sizeof(path),
			"%s/p2p_peers/%02x_%02x_%02x_%02x_%02x_%02x",
			p2p_device_get_path(peer->dev),
			peer->bss->addr[0], peer->bss->addr[1],
			peer->bss->addr[2], peer->bss->addr[3],
			peer->bss->addr[4], peer->bss->addr[5]);
	return path;
}

static void p2p_peer_free(void *user_data)
{
	struct p2p_peer *peer = user_data;

	scan_bss_free(peer->bss);
	l_free(peer->name);
	l_free(peer);
}

static void p2p_peer_put(void *user_data)
{
	struct p2p_peer *peer = user_data;

	l_dbus_unregister_object(dbus_get_bus(), p2p_peer_get_path(peer));
	p2p_peer_free(peer);
}

struct p2p_device *p2p_device_update_from_genl(struct l_genl_msg *msg,
						bool create)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint8_t *ifaddr = NULL;
	const uint64_t *wdev_id = NULL;
	struct wiphy *wiphy = NULL;
	struct p2p_device *dev;

	if (!l_genl_attr_init(&attr, msg))
		return NULL;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WDEV:
			if (len != sizeof(uint64_t)) {
				l_warn("Invalid wdev index attribute");
				return NULL;
			}

			wdev_id = data;
			break;

		case NL80211_ATTR_WIPHY:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid wiphy attribute");
				return NULL;
			}

			wiphy = wiphy_find(*((uint32_t *) data));
			break;

		case NL80211_ATTR_IFTYPE:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid interface type attribute");
				return NULL;
			}

			if (*((uint32_t *) data) != NL80211_IFTYPE_P2P_DEVICE)
				return NULL;

			break;

		case NL80211_ATTR_MAC:
			if (len != ETH_ALEN) {
				l_warn("Invalid interface address attribute");
				return NULL;
			}

			ifaddr = data;
			break;
		}
	}

	if (!wiphy || !wdev_id || !ifaddr) {
		l_warn("Unable to parse interface information");
		return NULL;
	}

	if (create) {
		if (p2p_device_find(*wdev_id)) {
			l_debug("Duplicate p2p device %" PRIx64, *wdev_id);
			return NULL;
		}
	} else {
		dev = p2p_device_find(*wdev_id);
		if (!dev)
			return NULL;

		memcpy(dev->addr, ifaddr, ETH_ALEN);
		return NULL;
	}

	dev = l_new(struct p2p_device, 1);
	dev->wdev_id = *wdev_id;
	memcpy(dev->addr, ifaddr, ETH_ALEN);
	dev->wiphy = wiphy;
	dev->connections_left = 1;

	l_queue_push_tail(p2p_device_list, dev);

	l_debug("Created P2P device %" PRIx64, dev->wdev_id);

	if (!l_dbus_object_add_interface(dbus_get_bus(),
						p2p_device_get_path(dev),
						IWD_P2P_INTERFACE, dev))
		l_info("Unable to add the %s interface to %s",
			IWD_P2P_INTERFACE, p2p_device_get_path(dev));

	return dev;
}

static void p2p_device_free(void *user_data)
{
	struct p2p_device *dev = user_data;

	l_dbus_unregister_object(dbus_get_bus(), p2p_device_get_path(dev));
	l_queue_destroy(dev->peer_list, p2p_peer_put);
	l_free(dev);
}

bool p2p_device_destroy(struct p2p_device *dev)
{
	if (!l_queue_remove(p2p_device_list, dev))
		return false;

	p2p_device_free(dev);
	return true;
}

static bool p2p_device_get_avail_conns(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct p2p_device *dev = user_data;
	uint16_t avail_conns = dev->connections_left;

	l_dbus_message_builder_append_basic(builder, 'q', &avail_conns);
	return true;
}

static struct l_dbus_message *p2p_device_get_peers(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct p2p_device *dev = user_data;
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;
	const struct l_queue_entry *entry;

	if (!l_dbus_message_get_arguments(message, ""))
		return dbus_error_invalid_args(message);

	reply = l_dbus_message_new_method_return(message);
	builder = l_dbus_message_builder_new(reply);

	l_dbus_message_builder_enter_array(builder, "(on)");

	for (entry = l_queue_get_entries(dev->peer_list); entry;
			entry = entry->next) {
		const struct p2p_peer *peer = entry->data;
		int16_t signal_strength = peer->bss->signal_strength;

		l_dbus_message_builder_enter_struct(builder, "on");
		l_dbus_message_builder_append_basic(builder, 'o',
						p2p_peer_get_path(peer));
		l_dbus_message_builder_append_basic(builder, 'n',
							&signal_strength);
		l_dbus_message_builder_leave_struct(builder);
	}

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;
}

static void p2p_interface_setup(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, "AvailableConnections", 0, "q",
					p2p_device_get_avail_conns, NULL);
	l_dbus_interface_method(interface, "GetPeers", 0,
				p2p_device_get_peers, "a(on)", "", "peers");
}

static bool p2p_peer_get_name(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct p2p_peer *peer = user_data;

	l_dbus_message_builder_append_basic(builder, 's', peer->name);
	return true;
}

static bool p2p_peer_get_connected(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	bool connected = false;

	l_dbus_message_builder_append_basic(builder, 'b', &connected);
	return true;
}

static void p2p_peer_interface_setup(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, "Name", 0, "s",
					p2p_peer_get_name, NULL);
	l_dbus_interface_property(interface, "Connected", 0, "b",
					p2p_peer_get_connected, NULL);
}

static int p2p_init(void)
{
	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_P2P_INTERFACE,
					p2p_interface_setup,
					NULL, false))
		l_error("Unable to register the %s interface",
			IWD_P2P_INTERFACE);

	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_P2P_PEER_INTERFACE,
					p2p_peer_interface_setup,
					NULL, false))
		l_error("Unable to register the %s interface",
			IWD_P2P_PEER_INTERFACE);

	p2p_device_list = l_queue_new();

	return 0;
}

static void p2p_exit(void)
{
	l_dbus_unregister_interface(dbus_get_bus(), IWD_P2P_INTERFACE);
	l_dbus_unregister_interface(dbus_get_bus(), IWD_P2P_PEER_INTERFACE);
	l_queue_destroy(p2p_device_list, p2p_device_free);
	p2p_device_list = NULL;
}

IWD_MODULE(p2p, p2p_init, p2p_exit)
IWD_MODULE_DEPENDS(p2p, wiphy)
IWD_MODULE_DEPENDS(p2p, scan)
