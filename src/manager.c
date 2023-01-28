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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <fnmatch.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/nl80211util.h"
#include "src/iwd.h"
#include "src/module.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/util.h"
#include "src/common.h"
#include "src/nl80211cmd.h"
#include "src/p2p.h"

static struct l_genl_family *nl80211 = NULL;
static char **whitelist_filter;
static char **blacklist_filter;
static bool randomize;
static bool use_default;
static unsigned int config_watch;

struct wiphy_setup_state {
	uint32_t id;
	struct wiphy *wiphy;
	unsigned int pending_cmd_count;
	bool aborted;
	bool retry;

	/*
	 * Data we may need if the driver does not seem to support interface
	 * manipulation and we fall back to using the driver-created default
	 * interface.
	 */
	bool use_default;
	struct l_queue *default_interfaces;
};

static struct l_queue *pending_wiphys;

static void wiphy_setup_state_free(void *data)
{
	struct wiphy_setup_state *state = data;

	l_queue_destroy(state->default_interfaces,
				(l_queue_destroy_func_t) l_genl_msg_unref);

	L_WARN_ON(state->pending_cmd_count);
	l_free(state);
}

static void wiphy_setup_state_destroy(struct wiphy_setup_state *state)
{
	l_queue_remove(pending_wiphys, state);
	wiphy_setup_state_free(state);
}

static bool manager_use_default(struct wiphy_setup_state *state)
{
	uint8_t addr_buf[6];
	uint8_t *addr = NULL;
	const struct l_queue_entry *entry;

	l_debug("");

	if (!state->default_interfaces) {
		l_error("No default interface for wiphy %u",
			(unsigned int) state->id);
		state->retry = true;
		return false;
	}

	entry = l_queue_get_entries(state->default_interfaces);
	while (entry) {
		struct l_genl_msg *msg = entry->data;

		if (randomize) {
			wiphy_generate_random_address(state->wiphy, addr_buf);
			addr = addr_buf;
		}

		netdev_create_from_genl(msg, addr);
		entry = entry->next;
	}

	return true;
}

static void manager_new_station_interface_cb(struct l_genl_msg *msg,
						void *user_data)
{
	struct wiphy_setup_state *state = user_data;
	uint8_t addr_buf[6];
	uint8_t *addr = NULL;
	int error;

	l_debug("");

	if (state->aborted)
		return;

	error = l_genl_msg_get_error(msg);
	if (error < 0) {
		l_error("NEW_INTERFACE failed: %s",
			strerror(-l_genl_msg_get_error(msg)));

		/*
		 * If we receive an EBUSY most likely the wiphy is still
		 * initializing, the default interface has not been created
		 * yet and the wiphy needs some time.  Retry when we
		 * receive a NEW_INTERFACE event.
		 */
		if (error == -EBUSY) {
			state->retry = true;
			return;
		}

		/*
		 * Nothing we can do to use this wiphy since by now we
		 * will have successfully deleted any default interface
		 * there may have been.
		 */
		return;
	}

	if (randomize && !wiphy_has_feature(state->wiphy,
					NL80211_FEATURE_MAC_ON_CREATE)) {
		wiphy_generate_random_address(state->wiphy, addr_buf);
		addr = addr_buf;
	}

	netdev_create_from_genl(msg, addr);
}

static void manager_new_p2p_interface_cb(struct l_genl_msg *msg,
						void *user_data)
{
	struct wiphy_setup_state *state = user_data;

	l_debug("");

	if (state->aborted)
		return;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("NEW_INTERFACE failed for p2p-device: %s",
			strerror(-l_genl_msg_get_error(msg)));
		return;
	}

	p2p_device_update_from_genl(msg, true);
}

static void manager_new_interface_done(void *user_data)
{
	struct wiphy_setup_state *state = user_data;

	state->pending_cmd_count--;

	if (!state->pending_cmd_count && !state->retry)
		wiphy_setup_state_destroy(state);
}

static void manager_create_interfaces(struct wiphy_setup_state *state)
{
	struct l_genl_msg *msg;
	char ifname[10];
	uint32_t iftype;
	unsigned int cmd_id;

	if (state->aborted)
		return;

	if (state->use_default) {
		manager_use_default(state);

		/*
		 * Some drivers don't let us touch the default interface
		 * but still allow us to create/destroy P2P interfaces, so
		 * give it a chance.
		 */
		goto try_create_p2p;
	}

	/*
	 * Current policy: we maintain one netdev per wiphy for station,
	 * AP and Ad-Hoc modes, one optional p2p-device and zero or more
	 * p2p-GOs or p2p-clients.  The P2P-client/GO interfaces will be
	 * created on request.
	 */

	/* To be improved */
	snprintf(ifname, sizeof(ifname), "wlan%i", (int) state->id);
	l_debug("creating %s", ifname);
	iftype = NL80211_IFTYPE_STATION;

	msg = l_genl_msg_new(NL80211_CMD_NEW_INTERFACE);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY, 4, &state->id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFTYPE, 4, &iftype);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFNAME,
				strlen(ifname) + 1, ifname);
	l_genl_msg_append_attr(msg, NL80211_ATTR_4ADDR, 1, "\0");
	l_genl_msg_append_attr(msg, NL80211_ATTR_SOCKET_OWNER, 0, "");

	if (randomize && wiphy_has_feature(state->wiphy,
					NL80211_FEATURE_MAC_ON_CREATE)) {
		uint8_t random_addr[6];

		wiphy_generate_random_address(state->wiphy, random_addr);
		l_debug("Creating interface on phy: %s with random addr: "MAC,
						wiphy_get_name(state->wiphy),
						MAC_STR(random_addr));
		l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, random_addr);
	}

	cmd_id = l_genl_family_send(nl80211, msg,
					manager_new_station_interface_cb, state,
					manager_new_interface_done);

	if (!cmd_id) {
		l_error("Error sending NEW_INTERFACE for %s", ifname);
		return;
	}

	state->pending_cmd_count++;

try_create_p2p:
	/*
	 * Require the MAC on create feature so we can send our desired
	 * interface address during GO Negotiation before actually creating
	 * the local Client/GO interface.  Could be worked around if needed.
	 */
	if (!wiphy_supports_iftype(state->wiphy, NL80211_IFTYPE_P2P_DEVICE) ||
			!wiphy_supports_iftype(state->wiphy,
						NL80211_IFTYPE_P2P_CLIENT) ||
			!wiphy_has_feature(state->wiphy,
						NL80211_FEATURE_MAC_ON_CREATE))
		return;

	/*
	 * Use wlan%i-p2p for now.  We might want to use
	 * <default_interface's_name>-p2p here (in case state->use_default
	 * is true) but the risk is that we'd go over the interface name
	 * length limit.
	 */
	snprintf(ifname, sizeof(ifname), "wlan%i-p2p", (int) state->id);
	l_debug("creating %s", ifname);
	iftype = NL80211_IFTYPE_P2P_DEVICE;

	msg = l_genl_msg_new(NL80211_CMD_NEW_INTERFACE);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY, 4, &state->id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFTYPE, 4, &iftype);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFNAME,
				strlen(ifname) + 1, ifname);
	l_genl_msg_append_attr(msg, NL80211_ATTR_4ADDR, 1, "\0");
	l_genl_msg_append_attr(msg, NL80211_ATTR_SOCKET_OWNER, 0, "");
	cmd_id = l_genl_family_send(nl80211, msg,
					manager_new_p2p_interface_cb, state,
					manager_new_interface_done);

	if (!cmd_id) {
		l_error("Error sending NEW_INTERFACE for %s", ifname);
		return;
	}

	state->pending_cmd_count++;
}

static bool manager_wiphy_check_setup_done(struct wiphy_setup_state *state)
{
	if (state->pending_cmd_count || state->retry)
		return false;

	manager_create_interfaces(state);

	return !state->pending_cmd_count && !state->retry;
}

static void manager_setup_cmd_done(void *user_data)
{
	struct wiphy_setup_state *state = user_data;

	state->pending_cmd_count--;

	if (manager_wiphy_check_setup_done(state))
		wiphy_setup_state_destroy(state);
}

static void manager_del_interface_cb(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy_setup_state *state = user_data;
	int err;

	l_debug("");

	if (state->aborted)
		return;

	err = l_genl_msg_get_error(msg);

	if (err == -ENODEV)
		return;
	else if (err < 0) {
		l_error("DEL_INTERFACE failed: %s",
			strerror(-l_genl_msg_get_error(msg)));
		state->use_default = true;
	}
}

static void manager_get_interface_cb(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy_setup_state *state = user_data;
	uint32_t wiphy;
	uint32_t ifindex;
	uint32_t iftype;
	uint64_t wdev;
	const char *ifname;
	struct l_genl_msg *del_msg;
	unsigned int cmd_id;
	char *pattern;
	unsigned int i;
	bool whitelisted = false, blacklisted = false;

	l_debug("");

	if (state->aborted)
		return;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV, &wdev,
					NL80211_ATTR_WIPHY, &wiphy,
					NL80211_ATTR_IFTYPE, &iftype,
					NL80211_ATTR_UNSPEC) < 0)
		return;

	if (wiphy != state->id) {
		l_debug("Wiphy attribute mismatch, wanted: %u, got %u",
				state->id, wiphy);
		return;
	}

	if (nl80211_parse_attrs(msg, NL80211_ATTR_IFINDEX, &ifindex,
					NL80211_ATTR_IFNAME, &ifname,
					NL80211_ATTR_UNSPEC) < 0)
		goto delete_interface;

	if (whitelist_filter) {
		for (i = 0; (pattern = whitelist_filter[i]); i++) {
			if (fnmatch(pattern, ifname, 0) != 0)
				continue;

			whitelisted = true;
			break;
		}
	}

	if (blacklist_filter) {
		for (i = 0; (pattern = blacklist_filter[i]); i++) {
			if (fnmatch(pattern, ifname, 0) != 0)
				continue;

			blacklisted = true;
			break;
		}
	}

	/*
	 * If this interface is usable as our default netdev in case the
	 * driver does not support interface manipulation, save the message
	 * just in case.
	 */
	if ((iftype == NL80211_IFTYPE_ADHOC ||
				iftype == NL80211_IFTYPE_STATION ||
				iftype == NL80211_IFTYPE_AP) &&
			(!whitelist_filter || whitelisted) &&
			!blacklisted) {
		if (!state->default_interfaces)
			state->default_interfaces = l_queue_new();

		l_queue_push_head(state->default_interfaces,
							l_genl_msg_ref(msg));
	}

delete_interface:
	if (state->use_default)
		return;

	del_msg = l_genl_msg_new(NL80211_CMD_DEL_INTERFACE);
	l_genl_msg_append_attr(del_msg, NL80211_ATTR_WDEV, 8, &wdev);
	l_genl_msg_append_attr(del_msg, NL80211_ATTR_WIPHY, 4, &state->id);
	cmd_id = l_genl_family_send(nl80211, del_msg,
					manager_del_interface_cb, state,
					manager_setup_cmd_done);

	if (!cmd_id) {
		l_error("Sending DEL_INTERFACE for wdev: %" PRIu64" failed",
				wdev);
		state->use_default = true;
		return;
	}

	l_debug("");
	state->pending_cmd_count++;
}

static bool manager_wiphy_state_match(const void *a, const void *b)
{
	const struct wiphy_setup_state *state = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return (state->id == id);
}

static struct wiphy_setup_state *manager_find_pending(uint32_t id)
{
	return l_queue_find(pending_wiphys, manager_wiphy_state_match,
				L_UINT_TO_PTR(id));
}

static uint32_t manager_parse_wiphy_id(struct l_genl_msg *msg)
{
	uint32_t wiphy;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_WIPHY, &wiphy,
					NL80211_ATTR_UNSPEC) < 0)
		return -1;

	return wiphy;
}

static void manager_del_wiphy_event(struct l_genl_msg *msg)
{
	struct wiphy_setup_state *state;
	struct wiphy *wiphy;
	uint32_t id;

	id = manager_parse_wiphy_id(msg);

	state = manager_find_pending(id);
	if (state) {
		if (state->pending_cmd_count)
			state->aborted = true;
		else
			wiphy_setup_state_destroy(state);
	}

	wiphy = wiphy_find(id);
	if (wiphy)
		wiphy_destroy(wiphy);
}

static void manager_interface_dump_callback(struct l_genl_msg *msg,
						void *user_data)
{
	struct wiphy_setup_state *state;

	l_debug("");

	state = manager_find_pending(manager_parse_wiphy_id(msg));
	if (!state)
		return;

	manager_get_interface_cb(msg, state);
}

static void manager_filtered_interface_dump_done(void *user_data)
{
	struct wiphy_setup_state *state = user_data;

	l_debug("");

	if (!manager_wiphy_check_setup_done(state))
		return;

	/* We decided to keep the the default interface(s) */
	l_debug("Wiphy setup complete: %s", wiphy_get_name(state->wiphy));
	wiphy_setup_state_destroy(state);
}

static bool manager_check_create_interfaces(void *data, void *user_data)
{
	struct wiphy_setup_state *state = data;

	if (!manager_wiphy_check_setup_done(state))
		return false;

	wiphy_setup_state_free(state);
	return true;
}

static void manager_interface_dump_done(void *user_data)
{
	l_debug("");

	l_queue_foreach_remove(pending_wiphys,
				manager_check_create_interfaces, NULL);
}

/* We are dumping multiple wiphys for the very first time */
static void manager_wiphy_dump_callback(struct l_genl_msg *msg, void *user_data)
{
	uint32_t id;
	const char *name;
	struct wiphy *wiphy;
	struct wiphy_setup_state *state;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_WIPHY, &id,
					NL80211_ATTR_WIPHY_NAME, &name,
					NL80211_ATTR_UNSPEC) < 0)
		return;

	/*
	 * A Wiphy split dump can generate many (6+) NEW_WIPHY messages
	 * We need to parse attributes from all of them, but only perform
	 * initialization steps once for each new wiphy detected
	 */
	wiphy = wiphy_find(id);
	if (wiphy)
		goto done;

	wiphy = wiphy_create(id, name);
	if (!wiphy || wiphy_is_blacklisted(wiphy))
		return;

	state = l_new(struct wiphy_setup_state, 1);
	state->id = id;
	state->wiphy = wiphy;

	l_debug("New wiphy %s added (%d)", name, id);

	l_queue_push_tail(pending_wiphys, state);

done:
	wiphy_update_from_genl(wiphy, msg);
}

/* We are dumping a single wiphy, due to a NEW_WIPHY event */
static void manager_wiphy_filtered_dump_callback(struct l_genl_msg *msg,
								void *user_data)
{
	struct wiphy_setup_state *state = user_data;

	wiphy_update_from_genl(state->wiphy, msg);
}

static void manager_filtered_wiphy_dump_done(void *user_data)
{
	struct wiphy_setup_state *state = user_data;

	l_debug("");

	wiphy_create_complete(state->wiphy);
	state->use_default = use_default;

	/*
	 * If whitelist/blacklist were given only try to use existing
	 * interfaces same as when the driver does not support
	 * NEW_INTERFACE or DEL_INTERFACE, otherwise the interface
	 * names will become meaningless after we've created our own
	 * interface(s).  Optimally phy name white/blacklists should
	 * be used.
	 */
	if (whitelist_filter || blacklist_filter)
		state->use_default = true;

	if (!state->use_default)
		state->use_default = wiphy_uses_default_if(state->wiphy);

	if (state->use_default)
		l_info("Wiphy %s will only use the default interface",
			wiphy_get_name(state->wiphy));
}

static void manager_wiphy_dump_done(void *user_data)
{
	const struct l_queue_entry *e;

	l_debug("");

	for (e = l_queue_get_entries(pending_wiphys); e; e = e->next)
		manager_filtered_wiphy_dump_done(e->data);
}

static int manager_wiphy_filtered_dump(uint32_t wiphy_id,
					l_genl_msg_func_t cb,
					struct wiphy_setup_state *state)
{
	struct l_genl_msg *msg;
	unsigned int wiphy_cmd_id;
	unsigned int iface_cmd_id;
	l_genl_destroy_func_t wiphy_done = manager_wiphy_dump_done;
	l_genl_destroy_func_t interface_done = manager_interface_dump_done;

	/* If state is provided, don't try to process other pending states */
	if (state) {
		wiphy_done = manager_filtered_wiphy_dump_done;
		interface_done = manager_filtered_interface_dump_done;
	}

	/*
	 * Until fixed, a NEW_WIPHY event will not include all the information
	 * that may be available, but a dump will. Because of this we do both
	 * GET_WIPHY/GET_INTERFACE, same as we would during initialization.
	 */
	msg = l_genl_msg_new_sized(NL80211_CMD_GET_WIPHY, 128);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP, 0, NULL);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY, 4, &wiphy_id);

	wiphy_cmd_id = l_genl_family_dump(nl80211, msg, cb, state, wiphy_done);
	if (!wiphy_cmd_id) {
		l_error("Could not dump wiphy %u", wiphy_id);
		l_genl_msg_unref(msg);
		return -EIO;
	}

	/*
	 * As the first step after new wiphy is detected we will query
	 * the initial interface setup, delete the default interfaces
	 * and create interfaces for our own use with NL80211_ATTR_SOCKET_OWNER
	 * on them.  After that if new interfaces are created outside of
	 * IWD, or removed outside of IWD, we don't touch them and will
	 * try to minimally adapt to handle the removals correctly.  It's
	 * a very unlikely situation in any case but it wouldn't make
	 * sense to try to continually enforce our setup fighting against
	 * some other process, and it wouldn't make sense to try to
	 * manage and use additional interfaces beyond the one or two
	 * we need for our operations.
	 */
	msg = l_genl_msg_new(NL80211_CMD_GET_INTERFACE);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY, 4, &wiphy_id);

	iface_cmd_id = l_genl_family_dump(nl80211, msg,
					manager_interface_dump_callback,
					state, interface_done);
	if (!iface_cmd_id) {
		l_error("Could not dump interface for wiphy %u", wiphy_id);
		l_genl_family_cancel(nl80211, wiphy_cmd_id);
		l_genl_msg_unref(msg);
		return -EIO;
	}

	return 0;
}

static void manager_config_notify(struct l_genl_msg *msg, void *user_data)
{
	uint8_t cmd;
	uint32_t wiphy_id;
	struct wiphy_setup_state *state;

	if (!pending_wiphys)
		return;

	cmd = l_genl_msg_get_command(msg);

	l_debug("Notification of command %s(%u)",
					nl80211cmd_to_string(cmd), cmd);

	switch (cmd) {
	case NL80211_CMD_NEW_WIPHY:
	{
		const char *name;
		struct wiphy *wiphy;

		if (nl80211_parse_attrs(msg, NL80211_ATTR_WIPHY, &wiphy_id,
					NL80211_ATTR_WIPHY_NAME, &name,
					NL80211_ATTR_UNSPEC) < 0)
			return;

		/*
		 * NEW_WIPHY events are sent in three cases:
		 *	1. New wiphy is detected
		 *	2. Wiphy is moved to a new namespace
		 *	3. Wiphy is renamed
		 *
		 * Take care of case 3 here without re-parsing the entire
		 * wiphy structure, potentially causing leaks, etc.
		 */
		wiphy = wiphy_find(wiphy_id);
		if (wiphy) {
			wiphy_update_name(wiphy, name);
			return;
		}

		wiphy = wiphy_create(wiphy_id, name);
		if (!wiphy || wiphy_is_blacklisted(wiphy))
			return;

		state = l_new(struct wiphy_setup_state, 1);
		state->id = wiphy_id;
		state->wiphy = wiphy;

		if (manager_wiphy_filtered_dump(wiphy_id,
					manager_wiphy_filtered_dump_callback,
					state) < 0) {
			wiphy_setup_state_free(state);
			return;
		}

		l_queue_push_tail(pending_wiphys, state);
		return;
	}

	case NL80211_CMD_DEL_WIPHY:
		manager_del_wiphy_event(msg);
		return;

	case NL80211_CMD_NEW_INTERFACE:
		/*
		 * Interfaces are normally dumped on the NEW_WIPHY events and
		 * we have nothing to do here.  But check if by any chance
		 * we've queried this wiphy and it was still busy initialising,
		 * in that case retry the setup now that an interface, likely
		 * the initial default one, has been added.
		 */
		wiphy_id = manager_parse_wiphy_id(msg);
		state = manager_find_pending(wiphy_id);

		if (state && state->retry) {
			state->retry = false;
			l_debug("Retrying setup of wiphy %u", state->id);

			manager_get_interface_cb(msg, state);

			if (manager_wiphy_check_setup_done(state))
				wiphy_setup_state_destroy(state);

			return;
		}

		if (!wiphy_find(wiphy_id)) {
			l_warn("Received a NEW_INTERFACE for a wiphy id"
				" that isn't tracked.  This is most likely a"
				" kernel bug where NEW_WIPHY events that are"
				" too large are dropped on the floor."
				"  Attempting a workaround...");
			manager_wiphy_filtered_dump(wiphy_id,
						manager_wiphy_dump_callback,
						NULL);
			return;
		}

		return;

	case NL80211_CMD_DEL_INTERFACE:
	{
		uint32_t ifindex;

		if (nl80211_parse_attrs(msg, NL80211_ATTR_IFINDEX, &ifindex,
					NL80211_ATTR_UNSPEC) < 0) {
			uint64_t wdev_id;
			struct p2p_device *p2p_device;

			if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV,
						&wdev_id,
						NL80211_ATTR_UNSPEC) < 0)
				return;

			p2p_device = p2p_device_find(wdev_id);
			if (!p2p_device)
				return;

			p2p_device_destroy(p2p_device);
		} else {
			struct netdev *netdev = netdev_find(ifindex);

			if (!netdev)
				return;

			netdev_destroy(netdev);
		}

		return;
	}
	}
}

static void manager_set_reg_cb(struct l_genl_msg *msg, void *user_data)
{
	int err = l_genl_msg_get_error(msg);

	if (err < 0)
		l_error("Failed to set country (%d)", err);
}

static int manager_init(void)
{
	struct l_genl *genl = iwd_get_genl();
	const struct l_settings *config = iwd_get_config();
	struct l_genl_msg *msg;
	unsigned int wiphy_dump;
	unsigned int interface_dump;
	const char *randomize_str;
	const char *if_whitelist = iwd_get_iface_whitelist();
	const char *if_blacklist = iwd_get_iface_blacklist();
	const char *cc;

	nl80211 = l_genl_family_new(genl, NL80211_GENL_NAME);

	if (if_whitelist)
		whitelist_filter = l_strsplit(if_whitelist, ',');

	if (if_blacklist)
		blacklist_filter = l_strsplit(if_blacklist, ',');

	pending_wiphys = l_queue_new();

	config_watch = l_genl_family_register(nl80211, "config",
						manager_config_notify,
						NULL, NULL);
	if (!config_watch) {
		l_error("Registering for config notifications failed");
		goto error;
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_GET_WIPHY, 128);
	l_genl_msg_append_attr(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP, 0, NULL);
	wiphy_dump = l_genl_family_dump(nl80211, msg,
						manager_wiphy_dump_callback,
						NULL,
						manager_wiphy_dump_done);
	if (!wiphy_dump) {
		l_error("Initial wiphy information dump failed");
		l_genl_msg_unref(msg);
		goto error;
	}

	msg = l_genl_msg_new(NL80211_CMD_GET_INTERFACE);
	interface_dump = l_genl_family_dump(nl80211, msg,
						manager_interface_dump_callback,
						NULL,
						manager_interface_dump_done);
	if (!interface_dump) {
		l_error("Initial interface information dump failed");
		l_genl_msg_unref(msg);
		l_genl_family_cancel(nl80211, wiphy_dump);
		goto error;
	}

	cc = l_settings_get_value(config, "General", "Country");
	if (cc) {
		if (strlen(cc) != 2 || !l_ascii_isalpha(cc[0]) ||
					!l_ascii_isalpha(cc[1])) {
			l_warn("[General].Country=%s is invalid. Country will "
				"not be set", cc);
		} else {
			msg = l_genl_msg_new(NL80211_CMD_REQ_SET_REG);
			l_genl_msg_append_attr(msg, NL80211_ATTR_REG_ALPHA2,
						2, cc);
			if (!l_genl_family_send(nl80211, msg,
						manager_set_reg_cb,
						NULL, NULL))
				l_warn("Failed to set country");
		}
	}

	randomize_str = l_settings_get_value(config, "General",
							"AddressRandomization");
	if (randomize_str) {
		if (!strcmp(randomize_str, "once"))
			randomize = true;
		else if (!strcmp(randomize_str, "disabled"))
			randomize = false;
	}

	if (!l_settings_get_bool(config, "General",
				"UseDefaultInterface", &use_default))
		use_default = false;

	return 0;

error:
	l_queue_destroy(pending_wiphys, NULL);
	pending_wiphys = NULL;

	l_genl_family_free(nl80211);
	nl80211 = NULL;

	return -EIO;
}

static void manager_exit(void)
{
	l_strfreev(whitelist_filter);
	l_strfreev(blacklist_filter);

	l_genl_family_unregister(nl80211, config_watch);

	l_queue_destroy(pending_wiphys, wiphy_setup_state_free);
	pending_wiphys = NULL;

	l_genl_family_free(nl80211);
	nl80211 = NULL;
	randomize = false;
}

IWD_MODULE(manager, manager_init, manager_exit);
