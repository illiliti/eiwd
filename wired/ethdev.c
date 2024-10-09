/*
 *
 *  Ethernet daemon for Linux
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fnmatch.h>
#include <net/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include <ell/ell.h>

#include "src/module.h"
#include "src/eap.h"
#include "wired/dbus.h"
#include "wired/network.h"
#include "wired/ethdev.h"

#define ADAPTER_INTERFACE	"net.connman.ead.Adapter"
#define ADAPTER_BASEPATH	EAD_BASE_PATH "/adapter"

#define PROP_NAME		"Name"
#define PROP_ADDRESS		"Address"
#define PROP_ACTIVE		"Active"
#define PROP_CONNECTED		"Connected"
#define PROP_AUTHENTICATED	"Authenticated"

struct ethdev {
	uint32_t index;
	char ifname[IFNAMSIZ];
	uint8_t addr[ETH_ALEN];
	bool active;
	bool lower_up;
	bool auth_done;
	struct l_queue *eapol_sessions;
	char *path;
};

struct eapol {
	struct ethdev *dev;
	uint8_t addr[ETH_ALEN];
	struct eap_state *eap;
	struct l_settings *cred;
};

static struct l_netlink *rtnl = NULL;
static struct l_queue *ethdev_list = NULL;
static char **whitelist_filter = NULL;
static char **blacklist_filter = NULL;

static struct l_io *pae_io;

struct eapol_hdr {
	uint8_t proto_ver;
	uint8_t pkt_type;
	__be16  pkt_len;
} __attribute__ ((packed));

static const uint8_t eapol_start[] = { 0x01, 0x01, 0x00, 0x00 };
static const uint8_t pae_group_addr[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };

static bool pae_write(struct ethdev *dev, const uint8_t *addr,
					const uint8_t *frame, size_t len)
{
	int fd = l_io_get_fd(pae_io);
	struct sockaddr_ll sll;
	ssize_t res;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = dev->index;
	sll.sll_protocol = htons(ETH_P_PAE);
	sll.sll_halen = ETH_ALEN;
	memcpy(sll.sll_addr, addr, ETH_ALEN);

	res = sendto(fd, frame, len, 0,
				(struct sockaddr *) &sll, sizeof(sll));
	if (res < 0)
		return false;

	return true;
}

static void eapol_free(void *data)
{
	struct eapol *eapol = data;

	l_debug("Freeing EAPoL session");

	eap_free(eapol->eap);
	l_settings_free(eapol->cred);
	l_free(eapol);
}

static bool eapol_match(const void *a, const void *b)
{
	const struct eapol *eapol = a;

	return !memcmp(eapol->addr, b, ETH_ALEN);
}

static struct eapol *eapol_lookup(struct ethdev *dev, const uint8_t *addr)
{
	return l_queue_find(dev->eapol_sessions, eapol_match, addr);
}

static bool ethdev_match(const void *a, const void *b)
{
	const struct ethdev *dev = a;
	uint32_t index = L_PTR_TO_UINT(b);

	return (dev->index == index);
}

static struct ethdev *ethdev_lookup(uint32_t index)
{
	return l_queue_find(ethdev_list, ethdev_match, L_UINT_TO_PTR(index));
}

static void eap_tx_packet(const uint8_t *eap_data, size_t len, void *user_data)
{
	struct eapol *eapol = user_data;
	uint8_t frame[1500];

	l_put_u8(0x01, frame);
	l_put_u8(0x00, frame + 1);
	l_put_be16(len, frame + 2);
	memcpy(frame + 4, eap_data, len);

	/*
	 * The supplicant / client always uses the PAE group address for
	 * sending the EAP packets.
	 */
	pae_write(eapol->dev, pae_group_addr, frame, len + 4);
}

static void eap_complete(enum eap_result result, void *user_data)
{
	struct eapol *eapol = user_data;
	struct ethdev *dev = eapol->dev;

	l_debug("result %u", result);

	if (result == EAP_RESULT_SUCCESS) {
		if (!dev->auth_done) {
			dev->auth_done = true;
			l_dbus_property_changed(dbus_app_get(), dev->path,
							ADAPTER_INTERFACE,
							PROP_AUTHENTICATED);
		}
	}

	l_queue_remove(dev->eapol_sessions, eapol);
	eapol_free(eapol);
}

static void eap_key_material(const uint8_t *msk_data, size_t msk_len,
				const uint8_t *emsk_data, size_t emsk_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *session_id, size_t session_len,
				void *user_data)
{
	l_debug("EAP key material received");
}

static void eap_event(unsigned int event, const void *event_data,
							void *user_data)
{
	l_debug("event %u", event);
}

static void rx_packet(struct ethdev *dev, const uint8_t *addr,
					const void *frame, size_t len)
{
	const struct eapol_hdr *hdr = frame;
	struct eapol *eapol;
	uint16_t pkt_len;

	if (len < 4) {
		l_error("Too short EAPoL packet with %zu bytes", len);
		return;
	}

	pkt_len = L_BE16_TO_CPU(hdr->pkt_len);

	/*
	 * EAPoL packet frames might contain padding at the end and so just
	 * ensure that at least packet body length worth of packet body is
	 * actually present.
	 */
	if (len - 4 < pkt_len) {
		l_error("Missing %zu bytes from EAPoL packet",
							pkt_len - (len - 4));
		return;
	}

	switch (hdr->pkt_type) {
	case 0x00:	/* EAP-Packet */
		eapol = eapol_lookup(dev, addr);
		if (!eapol) {
			eapol = l_new(struct eapol, 1);
			eapol->dev = dev;
			memcpy(eapol->addr, addr, ETH_ALEN);
			eapol->eap = eap_new(eap_tx_packet,
							eap_complete, eapol);
			if (!eapol->eap) {
				l_error("Failed to create EAP instance");
				l_free(eapol);
				return;
			}

			l_debug("Created new EAPoL session");

			eapol->cred = network_lookup_security("default");
			if (!eapol->cred || !eap_load_settings(eapol->eap,
						eapol->cred, "EAP-")) {
				l_error("Failed to load EAP settings");
				eapol_free(eapol);
				return;
			}

			l_queue_push_tail(dev->eapol_sessions, eapol);

			eap_set_key_material_func(eapol->eap, eap_key_material);
			eap_set_event_func(eapol->eap, eap_event);
		}
		eap_rx_packet(eapol->eap, frame + 4, pkt_len);
		break;
	}
}

/*
 * BPF filter to match skb->dev->type == 1 (ARPHRD_ETHER) and
 * match skb->protocol == 0x888e (PAE).
 */
static struct sock_filter pae_filter[] = {
	{ 0x28,  0,  0, 0xfffff01c },	/* ldh #hatype		*/
	{ 0x15,  0,  3, 0x00000001 },	/* jne #1, drop		*/
	{ 0x28,  0,  0, 0xfffff000 },	/* ldh #proto		*/
	{ 0x15,  0,  1, 0x0000888e },	/* jne #0x888e, drop	*/
	{ 0x06,  0,  0, 0xffffffff },	/* keep: ret #-1	*/
	{ 0x06,  0,  0, 0000000000 },	/* drop: ret #0		*/
};

static const struct sock_fprog pae_fprog = { .len = 6, .filter = pae_filter };

static bool pae_read(struct l_io *io, void *user_data)
{
	int fd = l_io_get_fd(io);
	struct ethdev *dev;
	struct sockaddr_ll sll;
	socklen_t sll_len;
	ssize_t bytes;
	uint8_t frame[1500];

	memset(&sll, 0, sizeof(sll));
	sll_len = sizeof(sll);

	bytes = recvfrom(fd, frame, sizeof(frame), 0,
					(struct sockaddr *) &sll, &sll_len);
	if (bytes <= 0) {
		l_error("Reading from PAE socket failed: %s", strerror(errno));
		return false;
	}

	if (sll.sll_hatype != ARPHRD_ETHER)
		return true;

	if (sll.sll_halen != ETH_ALEN)
		return true;

	if (ntohs(sll.sll_protocol) != ETH_P_PAE)
		return true;

	if (sll.sll_pkttype != PACKET_HOST &&
					sll.sll_pkttype != PACKET_MULTICAST)
		return true;

	dev = ethdev_lookup(sll.sll_ifindex);
	if (!dev)
		return true;

	rx_packet(dev, sll.sll_addr, frame, bytes);

	return true;
}

static void pae_destroy()
{
	pae_io = NULL;
}

static bool pae_open(void)
{
	int fd;

	fd = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
							htons(ETH_P_ALL));
	if (fd < 0)
		return false;

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
					&pae_fprog, sizeof(pae_fprog)) < 0) {
		close(fd);
		return false;
	}

	pae_io = l_io_new(fd);
	l_io_set_close_on_destroy(pae_io, true);

	l_debug("Opened PAE socket");

	l_io_set_read_handler(pae_io, pae_read, NULL, pae_destroy);

	return true;
}

static void pae_close(void)
{
	l_io_destroy(pae_io);
	pae_io = NULL;

	l_debug("Closed PAE socket");
}

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static char *read_devtype_from_uevent(const char *ifname)
{
	char line[128], *filename, *devtype = NULL;
	FILE *f;

	if (!ifname)
		return NULL;

	filename = l_strdup_printf("/sys/class/net/%s/uevent", ifname);
	f = fopen(filename, "re");
	l_free(filename);

	if (!f)
		return NULL;

	while (fgets(line, sizeof(line), f)) {
		char *pos;

		pos = strchr(line, '\n');
		if (!pos)
			continue;
		pos[0] = '\0';

		if (!strncmp(line, "DEVTYPE=", 8)) {
			devtype = l_strdup(line + 8);
			break;
		}
	}

	fclose(f);

	return devtype;
}

static int modify_membership(uint32_t index, int optname)
{
	struct packet_mreq mreq;
	int fd;

	fd = l_io_get_fd(pae_io);
	if (fd < 0)
		return -1;

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = index;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETH_ALEN;
	memcpy(mreq.mr_address, pae_group_addr, ETH_ALEN);

	return setsockopt(fd, SOL_PACKET, optname, &mreq, sizeof(mreq));
}

static void ethdev_free(void *data)
{
	struct ethdev *dev = data;

	l_debug("Freeing device %s", dev->ifname);

	if (modify_membership(dev->index, PACKET_DROP_MEMBERSHIP) < 0)
		l_error("Failed to drop membership");

	l_queue_destroy(dev->eapol_sessions, eapol_free);

	l_dbus_object_remove_interface(dbus_app_get(), dev->path,
							ADAPTER_INTERFACE);

	l_free(dev->path);
	l_free(dev);
}

static bool is_ifname_valid(const char *ifname)
{
	char *pattern;
	unsigned int i;

	if (!whitelist_filter)
		goto check_blacklist;

	for (i = 0; (pattern = whitelist_filter[i]); i++) {
		if (fnmatch(pattern, ifname, 0))
			continue;

		goto check_blacklist;
	}

	return false;

check_blacklist:
	if (!blacklist_filter)
		return true;

	for (i = 0; (pattern = blacklist_filter[i]); i++) {
		if (!fnmatch(pattern, ifname, 0))
			return false;
	}

	return true;
}

static void newlink_notify(const struct ifinfomsg *ifi, int bytes)
{
	uint32_t index = ifi->ifi_index;
	struct ethdev *dev;
	const struct rtattr *attr;
	uint8_t *addr = NULL;
	const char *ifname = NULL;
	uint8_t linkmode = 0, operstate = 0;
	bool active, lower_up, lower_changed = false;

	if (ifi->ifi_type != ARPHRD_ETHER)
		return;

	active = ifi->ifi_flags & IFF_UP;
	lower_up = ifi->ifi_flags & IFF_LOWER_UP;

	for (attr = IFLA_RTA(ifi); RTA_OK(attr, bytes);
						attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFLA_ADDRESS:
			if (RTA_PAYLOAD(attr) == ETH_ALEN)
				addr = RTA_DATA(attr);
			break;
		case IFLA_IFNAME:
			ifname = RTA_DATA(attr);
			break;
		case IFLA_LINKMODE:
			linkmode = l_get_u8(RTA_DATA(attr));
			break;
		case IFLA_OPERSTATE:
			operstate = l_get_u8(RTA_DATA(attr));
			break;
		}
	}

	if (!addr || !ifname)
		return;

	l_debug("%s: linkmode %u operstate %u", ifname, linkmode, operstate);

	if (!is_ifname_valid(ifname)) {
		l_debug("Ignoring device with interface name %s", ifname);
		return;
	}

	dev = ethdev_lookup(index);
	if (!dev) {
		char *devtype;

		/*
		 * If there is no existing Ethernet device structure, then
		 * first check uevent if this is wired Ethernet or not.
		 */
		devtype = read_devtype_from_uevent(ifname);
		if (devtype) {
			l_free(devtype);
			return;
		}

		if (l_queue_isempty(ethdev_list)) {
			if (!pae_open()) {
				l_error("Failed to open PAE port");
				return;
			}
		}

		if (modify_membership(index, PACKET_ADD_MEMBERSHIP) < 0) {
			l_error("Failed to add membership");
			return;
		}

		dev = l_new(struct ethdev, 1);
		dev->index = index;
		dev->active = active;
		dev->lower_up = lower_up;
		dev->auth_done = false;
		dev->eapol_sessions = l_queue_new();
		dev->path = l_strdup_printf("%s/%u", ADAPTER_BASEPATH,
								dev->index);

		l_debug("Creating device %u", dev->index);

		l_dbus_object_add_interface(dbus_app_get(), dev->path,
						ADAPTER_INTERFACE, dev);

		l_dbus_object_add_interface(dbus_app_get(), dev->path,
					L_DBUS_INTERFACE_PROPERTIES, NULL);

		l_queue_push_tail(ethdev_list, dev);

		lower_changed = true;
	}

	if (ifname)
		strcpy(dev->ifname, ifname);

	memcpy(dev->addr, addr, ETH_ALEN);

	if (active != dev->active) {
		dev->active = active;
		l_dbus_property_changed(dbus_app_get(), dev->path,
					ADAPTER_INTERFACE, PROP_ACTIVE);
	}

	if (lower_up != dev->lower_up) {
		if (!lower_up) {
			dev->auth_done = false;
			l_dbus_property_changed(dbus_app_get(), dev->path,
					ADAPTER_INTERFACE, PROP_AUTHENTICATED);
		}

		dev->lower_up = lower_up;
		l_dbus_property_changed(dbus_app_get(), dev->path,
					ADAPTER_INTERFACE, PROP_CONNECTED);

		lower_changed = true;
	}

	if (lower_changed) {
		if (dev->lower_up)
			pae_write(dev, pae_group_addr,
					eapol_start, sizeof(eapol_start));
		else
			l_queue_clear(dev->eapol_sessions, eapol_free);
	}
}

static void dellink_notify(const struct ifinfomsg *ifi, int bytes)
{
	uint32_t index = ifi->ifi_index;
	struct ethdev *dev;

	if (ifi->ifi_type != ARPHRD_ETHER)
		return;

	dev = l_queue_remove_if(ethdev_list, ethdev_match,
						L_UINT_TO_PTR(index));
	if (!dev)
		return;

	l_debug("Removing device %u", dev->index);

	ethdev_free(dev);

	if (l_queue_isempty(ethdev_list))
		pae_close();
}

static void link_notify(uint16_t type, const void *data, uint32_t len,
							void *user_data)
{
	const struct ifinfomsg *ifi = data;
	unsigned int bytes;

	if (ifi->ifi_type != ARPHRD_ETHER)
		return;

	bytes = len - NLMSG_ALIGN(sizeof(struct ifinfomsg));

	switch (type) {
	case RTM_NEWLINK:
		newlink_notify(ifi, bytes);
		break;
	case RTM_DELLINK:
		dellink_notify(ifi, bytes);
		break;
	}
}

static void getlink_callback(int error, uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const struct ifinfomsg *ifi = data;
	unsigned int bytes;

	if (error) {
		l_error("Failure with link information dump (%d)", error);
		return;
	}

	if (type != RTM_NEWLINK)
		return;

	bytes = len - NLMSG_ALIGN(sizeof(struct ifinfomsg));

	newlink_notify(ifi, bytes);
}

static bool property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct ethdev *dev = user_data;

	l_dbus_message_builder_append_basic(builder, 's', dev->ifname);
	return true;
}

static bool property_get_address(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct ethdev *dev = user_data;
        char str[18];

	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
				dev->addr[0], dev->addr[1], dev->addr[2],
				dev->addr[3], dev->addr[4], dev->addr[5]);

	l_dbus_message_builder_append_basic(builder, 's', str);
	return true;
}

static bool property_get_active(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct ethdev *dev = user_data;
	bool active = dev->active;

	l_dbus_message_builder_append_basic(builder, 'b', &active);
	return true;
}

static bool property_get_connected(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct ethdev *dev = user_data;
	bool connected = dev->lower_up;

	l_dbus_message_builder_append_basic(builder, 'b', &connected);
	return true;
}

static bool property_get_authenticated(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct ethdev *dev = user_data;
	bool authenticated = dev->auth_done;

	l_dbus_message_builder_append_basic(builder, 'b', &authenticated);
	return true;
}

static void setup_adapter_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, PROP_NAME, 0, "s",
					property_get_name, NULL);
	l_dbus_interface_property(interface, PROP_ADDRESS, 0, "s",
					property_get_address, NULL);
	l_dbus_interface_property(interface, PROP_ACTIVE, 0, "b",
					property_get_active, NULL);
	l_dbus_interface_property(interface, PROP_CONNECTED, 0, "b",
					property_get_connected, NULL);
	l_dbus_interface_property(interface, PROP_AUTHENTICATED, 0, "b",
					property_get_authenticated, NULL);
}

bool ethdev_init(const char *whitelist, const char *blacklist)
{
	struct ifinfomsg ifi;
	struct l_netlink_message *nlm;

	if (rtnl)
		return false;

	l_debug("Opening route netlink socket");

	rtnl = l_netlink_new(NETLINK_ROUTE);
	if (!rtnl) {
		l_error("Failed to open route netlink socket");
		return false;
	}

	if (getenv("EAD_RTNL_DEBUG"))
		l_netlink_set_debug(rtnl, do_debug, "[RTNL] ", NULL);

	if (!l_netlink_register(rtnl, RTNLGRP_LINK, link_notify, NULL, NULL)) {
		l_error("Failed to register for RTNL link notifications");
		l_netlink_destroy(rtnl);
		return false;
	}

	ethdev_list = l_queue_new();

	if (!l_dbus_register_interface(dbus_app_get(), ADAPTER_INTERFACE,
					setup_adapter_interface, NULL, false)) {
		l_error("Unable to register the adapter interface");
		l_netlink_destroy(rtnl);
		return false;
	}

	if (whitelist)
		whitelist_filter = l_strsplit(whitelist, ',');

	if (blacklist)
		blacklist_filter = l_strsplit(blacklist, ',');

	memset(&ifi, 0, sizeof(ifi));
	nlm = l_netlink_message_new_sized(RTM_GETLINK, NLM_F_DUMP, sizeof(ifi));
	l_netlink_message_add_header(nlm, &ifi, sizeof(ifi));

	l_netlink_send(rtnl, nlm, getlink_callback, NULL, NULL);

	return true;
}

void ethdev_exit(void)
{
	if (!rtnl)
		return;

	l_dbus_unregister_interface(dbus_app_get(), ADAPTER_INTERFACE);

	pae_close();

	l_strfreev(whitelist_filter);
	l_strfreev(blacklist_filter);

	l_debug("Closing route netlink socket");
	l_netlink_destroy(rtnl);
	rtnl = NULL;

	l_queue_destroy(ethdev_list, ethdev_free);
	ethdev_list = NULL;
}
