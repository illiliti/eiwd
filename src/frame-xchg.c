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

#include <errno.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <linux/genetlink.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "ell/useful.h"
#include "src/iwd.h"
#include "src/module.h"
#include "src/mpdu.h"
#include "src/util.h"
#include "src/watchlist.h"
#include "src/nl80211util.h"
#include "src/netdev.h"
#include "src/frame-xchg.h"
#include "src/wiphy.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

struct watch_group {
	/*
	 * Group IDs, except 0, are per wdev for user's convenience.
	 * I.e. group 1 can be used for P2P discovery and be removed as
	 * soon as the scan is over on a given device without interfering
	 * with scans on other devices.  This means a module can name
	 * all the groups it's going to need in a static enum.
	 * Group 0 is the default group and uses the iwd_get_genl() netlink
	 * socket shared with all its other users, meaning that it can not
	 * be closed through the watch API.  It is to be used for watches
	 * that don't need to be unregistered before the virtual interface
	 * type change or destruction, which are the two events that
	 * implicitly unregister all existing watches.
	 */
	uint32_t id;
	uint64_t wdev_id;
	uint32_t unicast_watch_id;
	struct l_io *io;
	uint32_t nl_pid;
	uint32_t nl_seq;
	struct l_queue *write_queue;
	struct watchlist watches;
};

struct frame_watch {
	uint64_t wdev_id;
	uint16_t frame_type;
	uint8_t *prefix;
	size_t prefix_len;
	struct watch_group *group;
	struct watchlist_item super;
};

static struct l_queue *watch_groups;

struct wdev_info {
	uint64_t id;
	uint32_t iftype;
};

static struct l_queue *wdevs;

struct frame_xchg_data {
	uint64_t wdev_id;
	uint32_t freq;
	struct mmpdu_header *tx_mpdu;
	size_t tx_mpdu_len;
	bool tx_acked;
	uint64_t cookie;
	bool have_cookie;
	bool early_status;
	struct {
		struct mmpdu_header *mpdu;
		const void *body;
		size_t body_len;
		int rssi;
	} early_frame;
	struct l_timeout *timeout;
	struct l_queue *rx_watches;
	frame_xchg_cb_t cb;
	frame_xchg_destroy_func_t destroy;
	void *user_data;
	uint32_t group_id;
	unsigned int retry_cnt;
	unsigned int retry_interval;
	unsigned int resp_timeout;
	unsigned int retries_on_ack;
	struct wiphy_radio_work_item work;
	bool no_cck_rates;
	unsigned int tx_cmd_id;
};

struct frame_xchg_watch_data {
	struct frame_xchg_prefix *prefix;
	frame_xchg_resp_cb_t cb;
};

static struct l_queue *frame_xchgs;
static struct l_genl_family *nl80211;
static uint32_t nl80211_id;

struct frame_prefix_info {
	uint16_t frame_type;
	const uint8_t *body;
	size_t body_len;
	uint64_t wdev_id;
};

static bool frame_watch_match_prefix(const void *a, const void *b)
{
	const struct watchlist_item *item = a;
	const struct frame_watch *watch =
		l_container_of(item, struct frame_watch, super);
	const struct frame_prefix_info *info = b;

	return watch->frame_type == info->frame_type &&
		watch->prefix_len <= info->body_len &&
		(watch->prefix_len == 0 ||
		 !memcmp(watch->prefix, info->body, watch->prefix_len)) &&
		info->wdev_id == watch->wdev_id;
}

static void frame_watch_unicast_notify(struct l_genl_msg *msg, void *user_data)
{
	struct watch_group *group = user_data;
	const uint64_t *wdev_id = NULL;
	const uint32_t *ifindex = NULL;
	struct l_genl_attr attr;
	uint16_t type, len, frame_len;
	const void *data;
	const struct mmpdu_header *mpdu = NULL;
	const uint8_t *body;
	struct frame_prefix_info info;
	int rssi = 0;	/* No-RSSI flag value */

	if (l_genl_msg_get_command(msg) != NL80211_CMD_FRAME)
		return;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WDEV:
			if (len != 8)
				break;

			wdev_id = data;
			break;

		case NL80211_ATTR_IFINDEX:
			if (len != 4)
				break;

			ifindex = data;
			break;

		case NL80211_ATTR_FRAME:
			mpdu = mpdu_validate(data, len);
			if (!mpdu) {
				l_warn("Frame didn't validate as MMPDU");
				return;
			}

			frame_len = len;
			break;

		case NL80211_ATTR_RX_SIGNAL_DBM:
			if (len != 4)
				break;

			rssi = *(const int32_t *) data;
		}
	}

	if (!wdev_id || (group->wdev_id && group->wdev_id != *wdev_id)) {
		l_warn("Bad wdev attribute");
		return;
	}

	if (!mpdu) {
		l_warn("Missing frame data");
		return;
	}

	body = mmpdu_body(mpdu);

	if (ifindex) {
		struct netdev *netdev = netdev_find(*ifindex);

		if (netdev && memcmp(mpdu->address_1,
					netdev_get_address(netdev), 6) &&
				!util_is_broadcast_address(mpdu->address_1))
			return;
	}

	/* Only match the frame type and subtype like the kernel does */
#define FC_FTYPE_STYPE_MASK 0x00fc
	info.frame_type = l_get_le16(mpdu) & FC_FTYPE_STYPE_MASK;
	info.body = (const uint8_t *) body;
	info.body_len = (const uint8_t *) mpdu + frame_len - body;
	info.wdev_id = *wdev_id;

	WATCHLIST_NOTIFY_MATCHES(&group->watches, frame_watch_match_prefix,
					&info, frame_watch_cb_t, mpdu,
					info.body, info.body_len, rssi);

	/* Has frame_watch_group_destroy been called inside a frame CB? */
	if (group->watches.pending_destroy)
		l_free(group);
}

static void frame_watch_group_destroy(void *data)
{
	struct watch_group *group = data;

	if (group->unicast_watch_id)
		l_genl_remove_unicast_watch(iwd_get_genl(),
						group->unicast_watch_id);

	l_io_destroy(group->io);
	l_queue_destroy(group->write_queue,
			(l_queue_destroy_func_t) l_genl_msg_unref);

	/*
	 * We may be inside a frame notification but even then use
	 * watchlist_destroy to prevent any more notifications from
	 * being dispatched.
	 */
	watchlist_destroy(&group->watches);
	if (group->watches.in_notify)
		return;

	l_free(group);
}

static void frame_watch_free(struct watchlist_item *item)
{
	struct frame_watch *watch =
		l_container_of(item, struct frame_watch, super);

	l_free(watch->prefix);
	l_free(watch);
}

static const struct watchlist_ops frame_watch_ops = {
	.item_free = frame_watch_free,
};

static bool frame_watch_group_io_write(struct l_io *io, void *user_data)
{
	struct watch_group *group = user_data;
	struct l_genl_msg *msg;
	const void *msg_data;
	size_t msg_size;
	ssize_t bytes_written;

	msg = l_queue_pop_head(group->write_queue);
	if (!msg)
		return false;

	msg_data = l_genl_msg_to_data(msg, nl80211_id, NLM_F_REQUEST,
					++group->nl_seq, group->nl_pid,
					&msg_size);
	bytes_written = send(l_io_get_fd(group->io), msg_data, msg_size, 0);
	l_genl_msg_unref(msg);

	if (bytes_written < 0) {
		l_error("Frame watch group socket write error: %s (%i)",
			strerror(errno), errno);

		l_queue_push_head(group->write_queue, msg);
		return false;
	}

	return !l_queue_isempty(group->write_queue);
}

static bool frame_watch_group_io_read(struct l_io *io, void *user_data)
{
	struct watch_group *group = user_data;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	unsigned char buf[8192];
	unsigned char control[32];
	ssize_t bytes_read;
	struct nlmsghdr *nlmsg;
	size_t nlmsg_len;
	uint32_t nlmsg_group = 0;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	bytes_read = recvmsg(l_io_get_fd(group->io), &msg, 0);
	if (bytes_read < 0) {
		if (errno != EAGAIN && errno != EINTR) {
			l_error("Frame watch group socket read error: %s (%i)",
				strerror(errno), errno);
			return false;
		}

		return true;
	}

	nlmsg_len = bytes_read;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		struct nl_pktinfo pktinfo;

		if (cmsg->cmsg_level != SOL_NETLINK)
			continue;

		if (cmsg->cmsg_type != NETLINK_PKTINFO)
			continue;

		memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));

		nlmsg_group = pktinfo.group;
	}

	if (nlmsg_group) /* Ignore multicast */
		return true;

	for (nlmsg = iov.iov_base; NLMSG_OK(nlmsg, nlmsg_len);
				nlmsg = NLMSG_NEXT(nlmsg, nlmsg_len)) {
		struct l_genl_msg *genl_msg;

		if (nlmsg->nlmsg_type != nl80211_id) /* Ignore other families */
			continue;

		if (nlmsg->nlmsg_seq)	/* Ignore responses */
			continue;

		genl_msg = l_genl_msg_new_from_data((void *) nlmsg,
							nlmsg->nlmsg_len);
		if (!genl_msg)
			continue;

		frame_watch_unicast_notify(genl_msg, group);
		l_genl_msg_unref(genl_msg);
	}

	return true;
}

static struct watch_group *frame_watch_group_new(uint64_t wdev_id, uint32_t id)
{
	struct watch_group *group = l_new(struct watch_group, 1);
	struct sockaddr_nl addr;
	socklen_t addrlen = sizeof(addr);
	int fd = -1, pktinfo = 1;

	group->id = id;
	group->wdev_id = wdev_id;
	watchlist_init(&group->watches, &frame_watch_ops);

	if (id == 0) {
		group->unicast_watch_id = l_genl_add_unicast_watch(
						iwd_get_genl(),
						NL80211_GENL_NAME,
						frame_watch_unicast_notify,
						group, NULL);
		if (unlikely(!group->unicast_watch_id)) {
			l_error("Registering for unicast notification failed");
			goto err;
		}

		return group;
	}

	/*
	 * If we need to add groups using genl sockets other than our main
	 * genl socket (iwd_get_genl()), use raw io instead of l_genl.  This
	 * way we don't have to query the genl families -- we already know
	 * nl80211 is present -- and the handling is simpler, and l_genl,
	 * while it would work, is not meant to have multiple instances
	 * per program.
	 */
	fd = socket(PF_NETLINK,
			SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
			NETLINK_GENERIC);
	if (unlikely(fd < 0))
		goto err;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;

	if (unlikely(bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0))
		goto err;

	if (unlikely(getsockname(fd, (struct sockaddr *) &addr, &addrlen) < 0))
		goto err;

	group->nl_pid = addr.nl_pid;

	if (unlikely(setsockopt(fd, SOL_NETLINK, NETLINK_PKTINFO,
					&pktinfo, sizeof(pktinfo)) < 0))
		goto err;

	group->io = l_io_new(fd);
	if (unlikely(!group->io))
		goto err;

	l_io_set_close_on_destroy(group->io, true);
	l_io_set_read_handler(group->io, frame_watch_group_io_read, group,
				NULL);
	group->write_queue = l_queue_new();

	return group;

err:
	if (fd > -1)
		close(fd);

	frame_watch_group_destroy(group);
	return NULL;
}

struct watch_group_match_info {
	uint64_t wdev_id;
	uint32_t id;
};

static bool frame_watch_group_match(const void *a, const void *b)
{
	const struct watch_group *group = a;
	const struct watch_group_match_info *info = b;

	return group->wdev_id == info->wdev_id && group->id == info->id;
}

static struct watch_group *frame_watch_group_get(uint64_t wdev_id, uint32_t id)
{
	struct watch_group_match_info info = { id == 0 ? 0 : wdev_id, id };
	struct watch_group *group = l_queue_find(watch_groups,
						frame_watch_group_match, &info);

	if (!group) {
		group = frame_watch_group_new(wdev_id, id);
		l_queue_push_tail(watch_groups, group);
	}

	return group;
}

static void frame_watch_register_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("Could not register frame watch type %04x: %i",
			L_PTR_TO_UINT(user_data), l_genl_msg_get_error(msg));
}

static void frame_watch_notify_empty(const struct mmpdu_header *mpdu,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
}

struct frame_duplicate_info {
	uint64_t wdev_id;
	uint16_t frame_type;
	const uint8_t *prefix;
	size_t prefix_len;
	frame_watch_cb_t handler;
	void *user_data;
	bool duplicate : 1;
	bool registered : 1;
};

static bool frame_watch_check_duplicate(void *data, void *user_data)
{
	struct watchlist_item *super = data;
	struct frame_watch *watch =
		l_container_of(super, struct frame_watch, super);
	struct frame_duplicate_info *info = user_data;
	int common_len = info->prefix_len < watch->prefix_len ?
		info->prefix_len : watch->prefix_len;

	if (info->wdev_id != watch->wdev_id ||
			info->frame_type != watch->frame_type ||
			(common_len &&
			 memcmp(info->prefix, watch->prefix, common_len)))
		/* No match */
		return false;

	if (info->prefix_len >= watch->prefix_len)
		/*
		 * A matching shorter prefix is already registered with
		 * the kernel, no need to register the new prefix.
		 */
		info->registered = true;

	/*
	 * If we previously had a watch registered on this socket,
	 * with the same or a more specific prefix, we can now forget
	 * its entry as the new watch is going to hold enough
	 * information to keep us from registering redundant prefixes
	 * in the future.
	 */
	if (info->prefix_len <= watch->prefix_len &&
			watch->super.notify == frame_watch_notify_empty)
		goto drop;

	if (info->handler != watch->super.notify ||
			info->user_data != watch->super.notify_data)
		return false;

	/*
	 * If we already have a watch with the exact same callback and
	 * user_data and a matching prefix (longer or shorter), drop
	 * either the existing watch, or the new watch, so as to preserve
	 * the set of frames that trigger the callback but avoid
	 * calling back twice with the same user_data.
	 */
	if (info->prefix_len >= watch->prefix_len) {
		info->duplicate = true;
		return false;
	}

drop:
	/*
	 * Drop the existing watch as a duplicate of the new one. If we are in
	 * the watchlist notify loop, just mark this item as stale and it will
	 * be cleaned up afterwards
	 */
	if (watch->group->watches.in_notify) {
		super->id = 0;
		watch->group->watches.stale_items = true;
		return false;
	}

	frame_watch_free(&watch->super);
	return true;
}

bool frame_watch_add(uint64_t wdev_id, uint32_t group_id, uint16_t frame_type,
			const uint8_t *prefix, size_t prefix_len,
			frame_watch_cb_t handler, void *user_data,
			frame_xchg_destroy_func_t destroy)
{
	struct watch_group *group = frame_watch_group_get(wdev_id, group_id);
	struct frame_watch *watch;
	struct l_genl_msg *msg;
	struct frame_duplicate_info info = {
		wdev_id, frame_type, prefix, prefix_len,
		handler, user_data, false, false
	};

	if (!group)
		return false;

	l_queue_foreach_remove(group->watches.items,
				frame_watch_check_duplicate, &info);

	if (info.duplicate)
		return true;

	watch = l_new(struct frame_watch, 1);
	watch->frame_type = frame_type;
	watch->prefix = prefix_len ? l_memdup(prefix, prefix_len) : NULL;
	watch->prefix_len = prefix_len;
	watch->wdev_id = wdev_id;
	watch->group = group;
	watchlist_link(&group->watches, &watch->super, handler, user_data,
			destroy);

	if (info.registered)
		return true;

	msg = l_genl_msg_new_sized(NL80211_CMD_REGISTER_FRAME, 32 + prefix_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME_TYPE, 2, &frame_type);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME_MATCH,
				prefix_len, prefix);

	if (group->id == 0)
		l_genl_family_send(nl80211, msg, frame_watch_register_cb,
					L_UINT_TO_PTR(frame_type), NULL);
	else {
		l_queue_push_tail(group->write_queue, msg);
		l_io_set_write_handler(group->io, frame_watch_group_io_write,
					group, NULL);
	}

	return true;
}

bool frame_watch_group_remove(uint64_t wdev_id, uint32_t group_id)
{
	struct watch_group_match_info info = { wdev_id, group_id };
	struct watch_group *group = l_queue_remove_if(watch_groups,
						frame_watch_group_match, &info);

	if (!group)
		return false;

	frame_watch_group_destroy(group);
	return true;
}

static bool frame_watch_item_remove_wdev(void *data, void *user_data)
{
	struct frame_watch *watch =
		l_container_of(data, struct frame_watch, super);
	const uint64_t *wdev_id = user_data;

	if (watch->wdev_id != *wdev_id)
		return false;

	if (watch->super.destroy)
		watch->super.destroy(watch->super.notify_data);

	frame_watch_free(&watch->super);
	return true;
}

static bool frame_watch_group_remove_wdev(void *data, void *user_data)
{
	struct watch_group *group = data;
	const uint64_t *wdev_id = user_data;

	if (group->wdev_id == *wdev_id) {
		frame_watch_group_destroy(group);
		return true;
	}

	if (group->id != 0)
		return false;

	/*
	 * Have to be careful here because we're messing with watchlist
	 * internals.
	 */
	l_queue_foreach_remove(group->watches.items,
				frame_watch_item_remove_wdev, user_data);
	return false;
}

bool frame_watch_wdev_remove(uint64_t wdev_id)
{
	return l_queue_foreach_remove(watch_groups, frame_watch_group_remove_wdev,
					&wdev_id) > 0;
}

struct frame_watch_handler_check_info {
	uint64_t wdev_id;
	frame_watch_cb_t handler;
	void *user_data;
};

static bool frame_watch_item_remove_by_handler(void *data, void *user_data)
{
	struct frame_watch *watch =
		l_container_of(data, struct frame_watch, super);
	struct frame_watch_handler_check_info *info = user_data;

	if (watch->wdev_id != info->wdev_id ||
			watch->super.notify != info->handler ||
			watch->super.notify_data != info->user_data)
		return false;

	if (watch->super.destroy) {
		watch->super.destroy(watch->super.notify_data);
		watch->super.destroy = NULL;
	}

	/*
	 * Keep the entry, with a dummy callback, in order to keep us from
	 * re-registering its prefix in future frame_watch_add calls.  We
	 * can drop the entry in some circumstances but checking the
	 * conditions for this costs more than it is worth right now.
	 */
	watch->super.notify = frame_watch_notify_empty;
	return false;
}

/*
 * Note this one doesn't interact with the kernel watches, only forgets our
 * struct frame_watch instances.
 *
 * Also note empty groups are not automatically destroyed because right now
 * this is not desired in frame_xchg_reset -- the only user of this function.
 */
static bool frame_watch_remove_by_handler(uint64_t wdev_id, uint32_t group_id,
						frame_watch_cb_t handler,
						void *user_data)
{
	struct watch_group_match_info group_info = {
				group_id == 0 ? 0 : wdev_id, group_id };
	struct frame_watch_handler_check_info handler_info = {
					wdev_id, handler, user_data };
	struct watch_group *group = l_queue_find(watch_groups,
						frame_watch_group_match,
						&group_info);

	if (!group)
		return false;

	return l_queue_foreach_remove(group->watches.items,
					frame_watch_item_remove_by_handler,
					&handler_info) > 0;
}

static bool frame_xchg_tx_retry(struct wiphy_radio_work_item *item);
static bool frame_xchg_resp_handle(const struct mmpdu_header *mpdu,
					const void *body, size_t body_len,
					int rssi, void *user_data);
static void frame_xchg_resp_cb(const struct mmpdu_header *mpdu,
				const void *body, size_t body_len,
				int rssi, void *user_data);

static void frame_xchg_wait_cancel(struct frame_xchg_data *fx)
{
	struct l_genl_msg *msg;

	if (!fx->have_cookie)
		return;

	l_debug("");

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME_WAIT_CANCEL, 32);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &fx->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_COOKIE, 8, &fx->cookie);
	l_genl_family_send(nl80211, msg, NULL, NULL, NULL);

	fx->have_cookie = false;
}

static void frame_xchg_reset(struct frame_xchg_data *fx)
{
	frame_xchg_wait_cancel(fx);

	if (fx->timeout)
		l_timeout_remove(fx->timeout);

	if (fx->tx_cmd_id) {
		l_genl_family_cancel(nl80211, fx->tx_cmd_id);
		fx->tx_cmd_id = 0;
	}

	l_free(fx->early_frame.mpdu);
	fx->early_frame.mpdu = NULL;
	l_queue_destroy(fx->rx_watches, l_free);
	fx->rx_watches = NULL;
	l_free(fx->tx_mpdu);
	fx->tx_mpdu = NULL;
	frame_watch_remove_by_handler(fx->wdev_id, fx->group_id,
					frame_xchg_resp_cb, fx);
}

static void frame_xchg_destroy(struct wiphy_radio_work_item *item)
{
	struct frame_xchg_data *fx = l_container_of(item,
						struct frame_xchg_data, work);

	if (fx->destroy)
		fx->destroy(fx->user_data);

	frame_xchg_reset(fx);
	l_free(fx);
}

static void frame_xchg_done(struct frame_xchg_data *fx, int err)
{
	l_queue_remove(frame_xchgs, fx);

	if (fx->cb)
		fx->cb(err, fx->user_data);

	wiphy_radio_work_done(wiphy_find_by_wdev(fx->wdev_id), fx->work.id);
}

static void frame_xchg_timeout_destroy(void *user_data)
{
	struct frame_xchg_data *fx = user_data;

	fx->timeout = NULL;
}

static void frame_xchg_timeout_cb(struct l_timeout *timeout,
					void *user_data)
{
	struct frame_xchg_data *fx = user_data;

	l_timeout_remove(fx->timeout);
	frame_xchg_tx_retry(&fx->work);
}

static void frame_xchg_listen_end_cb(struct l_timeout *timeout,
					void *user_data)
{
	struct frame_xchg_data *fx = user_data;

	if (!fx->retries_on_ack) {
		frame_xchg_done(fx, 0);
		return;
	}

	l_timeout_remove(fx->timeout);
	fx->retries_on_ack--;
	fx->retry_cnt = 0;
	frame_xchg_tx_retry(&fx->work);
}

static void frame_xchg_tx_status(struct frame_xchg_data *fx, bool acked)
{
	if (!acked) {
		frame_xchg_wait_cancel(fx);

		if (!fx->retry_interval || fx->retry_cnt >= 15) {
			if (!fx->resp_timeout)
				fx->have_cookie = false;

			l_error("Frame tx retry limit reached");
			frame_xchg_done(fx, -ECOMM);
			return;
		}

		l_free(fx->early_frame.mpdu);
		fx->early_frame.mpdu = NULL;
		fx->timeout = l_timeout_create_ms(fx->retry_interval,
						frame_xchg_timeout_cb, fx,
						frame_xchg_timeout_destroy);
		return;
	}

	if (!fx->resp_timeout) {
		/* No listen period to cancel */
		fx->have_cookie = false;
		frame_xchg_done(fx, 0);
		return;
	}

	fx->tx_acked = true;

	/* Process frames received early for strange drivers */
	if (fx->early_frame.mpdu) {
		/* The command is now over so no need to cancel it */
		fx->have_cookie = false;

		l_debug("Processing an early frame");

		if (frame_xchg_resp_handle(fx->early_frame.mpdu,
						fx->early_frame.body,
						fx->early_frame.body_len,
						fx->early_frame.rssi, fx))
			return;

		frame_xchg_listen_end_cb(NULL, fx);
		return;
	}

	/* Txed frame ACKed, listen for response frames */
	fx->timeout = l_timeout_create_ms(fx->resp_timeout,
						frame_xchg_listen_end_cb, fx,
						frame_xchg_timeout_destroy);
}

static void frame_xchg_tx_cb(struct l_genl_msg *msg, void *user_data)
{
	struct frame_xchg_data *fx = user_data;
	int error = l_genl_msg_get_error(msg);
	uint64_t cookie;
	bool early_status;

	fx->tx_cmd_id = 0;

	if (error < 0) {
		if (error == -EBUSY) {
			fx->timeout = l_timeout_create_ms(fx->retry_interval,
						frame_xchg_timeout_cb, fx,
						frame_xchg_timeout_destroy);
			return;
		}

		l_error("Frame tx failed: %s (%i)", strerror(-error), -error);
		goto error;
	}

	if (L_WARN_ON(nl80211_parse_attrs(msg, NL80211_ATTR_COOKIE, &cookie,
						NL80211_ATTR_UNSPEC) < 0)) {
		error = -EINVAL;
		goto error;
	}

	l_debug("Frame sent, cookie: %"PRIu64" obtained", cookie);

	early_status = fx->early_status && cookie == fx->cookie;
	fx->tx_acked = early_status && fx->tx_acked;
	fx->have_cookie = true;
	fx->cookie = cookie;

	if (early_status)
		frame_xchg_tx_status(fx, fx->tx_acked);

	return;
error:
	frame_xchg_done(fx, error);
}

static bool frame_xchg_tx_retry(struct wiphy_radio_work_item *item)
{
	struct frame_xchg_data *fx = l_container_of(item,
						struct frame_xchg_data, work);
	struct l_genl_msg *msg;
	uint32_t duration = fx->resp_timeout;

	/*
	 * TODO: in Station, AP, P2P-Client, GO or Ad-Hoc modes if we're
	 * transmitting the frame on the BSS's operating channel we can skip
	 * NL80211_ATTR_DURATION and we should still receive the frames
	 * without potentially interfering with other operations.
	 *
	 * TODO: we may want to react to NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL
	 * in the group socket's unicast handler.
	 */

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME, 128 + fx->tx_mpdu_len);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &fx->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &fx->freq);
	l_genl_msg_append_attr(msg, NL80211_ATTR_OFFCHANNEL_TX_OK, 0, NULL);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME,
				fx->tx_mpdu_len, fx->tx_mpdu);

	if (fx->no_cck_rates)
		l_genl_msg_append_attr(msg, NL80211_ATTR_TX_NO_CCK_RATE, 0,
					NULL);

	if (duration)
		l_genl_msg_append_attr(msg, NL80211_ATTR_DURATION, 4,
					&duration);

	fx->tx_cmd_id = l_genl_family_send(nl80211, msg, frame_xchg_tx_cb, fx,
						NULL);
	if (!fx->tx_cmd_id) {
		l_error("Error sending frame");
		l_genl_msg_unref(msg);
		frame_xchg_done(fx, -EIO);
		return true;
	}

	fx->tx_acked = false;
	fx->have_cookie = false;
	fx->early_status = false;
	fx->retry_cnt++;

	return false;
}

static bool frame_xchg_match_ptr(const void *a, const void *b)
{
	return a == b;
}

static bool frame_xchg_resp_handle(const struct mmpdu_header *mpdu,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	struct frame_xchg_data *fx = user_data;
	const struct l_queue_entry *entry;
	size_t hdr_len;

	l_debug("");

	if (memcmp(mpdu->address_1, fx->tx_mpdu->address_2, 6))
		return false;

	if (memcmp(mpdu->address_2, fx->tx_mpdu->address_1, 6))
		return false;

	/*
	 * BSSID (address_3) check not practical because some Linux
	 * drivers report all-zero values and some remote devices send
	 * wrong addresses.  But the frame callback is free to perform
	 * its own check.
	 */

	for (entry = l_queue_get_entries(fx->rx_watches);
			entry; entry = entry->next) {
		struct frame_xchg_watch_data *watch = entry->data;
		bool done;

		if (body_len < watch->prefix->len ||
				memcmp(body, watch->prefix->data,
					watch->prefix->len))
			continue;

		if (!fx->tx_acked)
			goto early_frame;

		done = watch->cb(mpdu, body, body_len, rssi, fx->user_data);

		if (!l_queue_find(frame_xchgs, frame_xchg_match_ptr, fx))
			return true;

		if (done) {
			/* NULL callback here since the caller is done */
			fx->cb = NULL;
			frame_xchg_done(fx, 0);
			return true;
		}
	}

	return false;

early_frame:
	/*
	 * Work around the strange order of events seen with the brcmfmac
	 * driver where we receive the response frames before the frame
	 * Tx status, which in turn is receive before the Tx callback with
	 * the operation cookie... rather then the reverse.
	 * Save the response frame to be processed in the Tx done callback.
	 */
	if (fx->early_frame.mpdu)
		return false;

	hdr_len = (const uint8_t *) body - (const uint8_t *) mpdu;
	fx->early_frame.mpdu = l_memdup(mpdu, body_len + hdr_len);
	fx->early_frame.body = (const uint8_t *) fx->early_frame.mpdu + hdr_len;
	fx->early_frame.body_len = body_len;
	fx->early_frame.rssi = rssi;
	return false;
}

static void frame_xchg_resp_cb(const struct mmpdu_header *mpdu,
				const void *body, size_t body_len,
				int rssi, void *user_data)
{
	frame_xchg_resp_handle(mpdu, body, body_len, rssi, user_data);
}

static bool frame_xchg_match_running(const void *a, const void *b)
{
	const struct frame_xchg_data *fx = a;
	const uint64_t *wdev_id = b;

	return fx->retry_cnt > 0 && fx->wdev_id == *wdev_id;
}

/*
 * Send an action frame described by @frame.  If @retry_interval is
 * non-zero and we receive no ACK from @peer to any of the retransmissions
 * done in the kernel (at a high rate), retry after @retry_interval
 * milliseconds from the time the kernel gave up.  If no ACK is received
 * after all the retransmissions, call @cb with a non-zero error number.
 * Otherwise, if @resp_timeout is non-zero, remain on the same channel
 * and report any response frames from the frame's destination address
 * that match provided prefixes, to the corresponding callbacks.  Do so
 * for @resp_timeout milliseconds from the ACK receival or until a frame
 * callback returns @true.  Call @cb when @resp_timeout runs out and
 * no frame callback returned @true, or immediately after the ACK if
 * @resp_timeout was 0.  @frame is an iovec array terminated by an iovec
 * struct with NULL-iov_base.
 */
uint32_t frame_xchg_start(uint64_t wdev_id, struct iovec *frame, uint32_t freq,
			unsigned int retry_interval, unsigned int resp_timeout,
			unsigned int retries_on_ack, uint32_t group_id,
			frame_xchg_cb_t cb, void *user_data,
			frame_xchg_destroy_func_t destroy, ...)
{
	uint32_t id;
	va_list args;

	va_start(args, destroy);
	id = frame_xchg_startv(wdev_id, frame, freq, retry_interval, resp_timeout,
				retries_on_ack, group_id, cb, user_data,
				destroy, args);
	va_end(args);
	return id;
}

static const struct wiphy_radio_work_item_ops work_ops = {
	.do_work = frame_xchg_tx_retry,
	.destroy = frame_xchg_destroy,
};

static bool frame_xchg_wdev_match(const void *a, const void *b)
{
	const struct wdev_info *wdev = a;
	const uint64_t *id = b;

	return wdev->id == *id;
}

uint32_t frame_xchg_startv(uint64_t wdev_id, struct iovec *frame, uint32_t freq,
			unsigned int retry_interval, unsigned int resp_timeout,
			unsigned int retries_on_ack, uint32_t group_id,
			frame_xchg_cb_t cb, void *user_data,
			frame_xchg_destroy_func_t destroy, va_list resp_args)
{
	struct frame_xchg_data *fx;
	size_t frame_len;
	struct iovec *iov;
	uint8_t *ptr;
	struct wdev_info *wdev;

	for (frame_len = 0, iov = frame; iov->iov_base; iov++)
		frame_len += iov->iov_len;

	/*
	 * This assumes that the first iovec at least contains the mmpdu_fc
	 * portion of the header used to calculate the minimum length.
	 */
	if (frame[0].iov_len >= 2 && frame_len <
				mmpdu_header_len((const struct mmpdu_header *)
				frame[0].iov_base)) {
		l_error("Frame too short");
		cb(-EMSGSIZE, user_data);
		return 0;
	}

	fx = l_new(struct frame_xchg_data, 1);

	if (!frame_xchgs)
		frame_xchgs = l_queue_new();

	fx->wdev_id = wdev_id;
	fx->freq = freq;
	fx->retry_interval = retry_interval;
	fx->resp_timeout = resp_timeout;
	fx->retries_on_ack = retries_on_ack;
	fx->cb = cb;
	fx->destroy = destroy;
	fx->user_data = user_data;
	fx->group_id = group_id;

	fx->tx_mpdu = l_malloc(frame_len);
	fx->tx_mpdu_len = frame_len;
	ptr = (uint8_t *) fx->tx_mpdu;

	for (iov = frame; iov->iov_base; ptr += iov->iov_len, iov++)
		memcpy(ptr, iov->iov_base, iov->iov_len);

	wdev = l_queue_find(wdevs, frame_xchg_wdev_match, &wdev_id);
	fx->no_cck_rates = wdev &&
		(wdev->iftype == NL80211_IFTYPE_P2P_DEVICE ||
		 wdev->iftype == NL80211_IFTYPE_P2P_CLIENT ||
		 wdev->iftype == NL80211_IFTYPE_P2P_GO);

	/*
	 * Subscribe to the response frames now instead of in the ACK
	 * callback to save ourselves race condition considerations.
	 */
	while (1) {
		struct frame_xchg_prefix *prefix;
		struct frame_xchg_watch_data *watch;

		prefix = va_arg(resp_args, struct frame_xchg_prefix *);
		if (!prefix)
			break;

		watch = l_new(struct frame_xchg_watch_data, 1);
		watch->prefix = prefix;
		watch->cb = va_arg(resp_args, void *);
		frame_watch_add(wdev_id, group_id, prefix->frame_type,
				prefix->data, prefix->len,
				frame_xchg_resp_cb, fx, NULL);

		if (!fx->rx_watches)
			fx->rx_watches = l_queue_new();

		l_queue_push_tail(fx->rx_watches, watch);
	}

	fx->retry_cnt = 0;

	l_queue_push_tail(frame_xchgs, fx);

	/*
	 * TODO: Assume any offchannel frames are a high priority (0). This may
	 * need to be re-examined in the future if other operations (e.g.
	 * wait on channel) are introduced.
	 */
	return wiphy_radio_work_insert(wiphy_find_by_wdev(wdev_id),
					&fx->work, WIPHY_WORK_PRIORITY_FRAME,
					&work_ops);
}

static bool frame_xchg_cancel_by_wdev(void *data, void *user_data)
{
	struct frame_xchg_data *fx = data;
	const uint64_t *wdev_id = user_data;

	if (fx->wdev_id != *wdev_id)
		return false;

	wiphy_radio_work_done(wiphy_find_by_wdev(fx->wdev_id), fx->work.id);
	return true;
}

void frame_xchg_stop_wdev(uint64_t wdev_id)
{
	l_queue_foreach_remove(frame_xchgs, frame_xchg_cancel_by_wdev,
				&wdev_id);
}

static bool frame_xchg_match_id(const void *a, const void *b)
{
	const struct frame_xchg_data *fx = a;
	const uint32_t *id = b;

	return fx->work.id == *id;
}

void frame_xchg_cancel(uint32_t id)
{
	struct frame_xchg_data *fx =
		l_queue_remove_if(frame_xchgs, frame_xchg_match_id, &id);

	if (!fx)
		return;

	wiphy_radio_work_done(wiphy_find_by_wdev(fx->wdev_id), id);
}

static void frame_xchg_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	uint64_t wdev_id;
	struct frame_xchg_data *fx;
	uint64_t cookie;
	bool ack;
	uint8_t cmd = l_genl_msg_get_command(msg);

	switch (cmd) {
	case NL80211_CMD_FRAME_TX_STATUS:
		if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV, &wdev_id,
					NL80211_ATTR_COOKIE, &cookie,
					NL80211_ATTR_ACK, &ack,
					NL80211_ATTR_UNSPEC) < 0)
			return;

		fx = l_queue_find(frame_xchgs, frame_xchg_match_running,
					&wdev_id);
		if (!fx)
			return;

		l_debug("Received %s for cookie: %"PRIu64,
				ack ? "an ACK" : "no ACK", cookie);

		if (fx->have_cookie && cookie == fx->cookie && !fx->tx_acked)
			frame_xchg_tx_status(fx, ack);
		else if (!fx->have_cookie && !fx->tx_acked) {
			/*
			 * Save the information about the frame's ACK status
			 * to be processed in frame_xchg_tx_cb if we were
			 * called before it (happens on brcmfmac).
			 */
			fx->tx_acked = ack;
			fx->cookie = cookie;
			fx->early_status = true;
		}

		break;
	}
}

static void frame_xchg_config_notify(struct l_genl_msg *msg, void *user_data)
{
	uint64_t wdev_id;
	uint32_t iftype;
	struct wdev_info *wdev;

	switch (l_genl_msg_get_command(msg)) {
	case NL80211_CMD_NEW_INTERFACE:
	case NL80211_CMD_SET_INTERFACE:
		if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV, &wdev_id,
					NL80211_ATTR_IFTYPE, &iftype,
					NL80211_ATTR_UNSPEC) < 0)
			break;

		wdev = l_queue_find(wdevs, frame_xchg_wdev_match, &wdev_id);

		if (!wdev) {
			wdev = l_new(struct wdev_info, 1);
			wdev->id = wdev_id;

			if (!wdevs)
				wdevs = l_queue_new();

			l_queue_push_tail(wdevs, wdev);
			break;
		}

		wdev->iftype = iftype;
		break;

	case NL80211_CMD_DEL_INTERFACE:
		if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV, &wdev_id,
					NL80211_ATTR_UNSPEC) < 0)
			break;

		wdev = l_queue_remove_if(wdevs, frame_xchg_wdev_match, &wdev_id);
		if (!wdev)
			break;

		l_free(wdev);
		frame_watch_wdev_remove(wdev_id);
		break;
	}
}

static int frame_xchg_init(void)
{
	struct watch_group *default_group;
	const struct l_genl_family_info *info;

	nl80211 = l_genl_family_new(iwd_get_genl(), NL80211_GENL_NAME);
	if (!nl80211) {
		l_error("Failed to obtain nl80211");
		return -EIO;
	}

	info = l_genl_family_get_info(nl80211);
	nl80211_id = l_genl_family_info_get_id(info);

	default_group = frame_watch_group_new(0, 0);
	if (!default_group)
		goto error;

	if (!l_genl_family_register(nl80211, "config", frame_xchg_config_notify,
					NULL, NULL)) {
		l_error("Registering for config notifications failed");
		goto error;
	}

	if (!l_genl_family_register(nl80211, "mlme", frame_xchg_mlme_notify,
					NULL, NULL)) {
		l_error("Registering for MLME notification failed");
		goto error;
	}

	watch_groups = l_queue_new();
	l_queue_push_tail(watch_groups, default_group);

	return 0;

error:
	if (nl80211) {
		l_genl_family_free(nl80211);
		nl80211 = NULL;
	}

	if (default_group)
		frame_watch_group_destroy(default_group);

	return -EIO;
}

static void destroy_xchg_data(void *user_data)
{
	struct frame_xchg_data *fx = user_data;

	wiphy_radio_work_done(wiphy_find_by_wdev(fx->wdev_id), fx->work.id);
}

static void frame_xchg_exit(void)
{
	struct l_queue *groups = watch_groups;
	struct l_queue *xchgs = frame_xchgs;

	frame_xchgs = NULL;
	l_queue_destroy(xchgs, destroy_xchg_data);

	watch_groups = NULL;
	l_queue_destroy(groups, frame_watch_group_destroy);

	l_genl_family_free(nl80211);
	nl80211 = NULL;

	l_queue_destroy(wdevs, l_free);
	wdevs = NULL;
}

IWD_MODULE(frame_xchg, frame_xchg_init, frame_xchg_exit);
IWD_MODULE_DEPENDS(frame_xchg, wiphy)
