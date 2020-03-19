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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/mpdu.h"
#include "src/nl80211util.h"

static struct l_genl *genl;
static struct l_genl_family *nl80211;
static int exit_status;
static uint64_t wdev_id;
static uint8_t wdev_addr[6];
static uint32_t freq;

static const uint8_t probe_req_body[] = {
	/* SSID */
	0x00, 0x07, 'D', 'I', 'R', 'E', 'C', 'T', '-',
	/* Supported Rates */
	0x01, 0x08, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c,
	/* DS Parameter Set */
	0x03, 0x01, 0x00,
	/* HT Capabilities */
	0x2d, 0x1a, 0xef, 0x11, 0x17, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x2c, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	/* WPS */
	0xdd, 0x6c, 0x00, 0x50, 0xf2, 0x04,
	/* > Version */
	0x10, 0x4a, 0x00, 0x01, 0x10,
	/* > Request Type */
	0x10, 0x3a, 0x00, 0x01, 0x00,
	/* > Config Methods */
	0x10, 0x08, 0x00, 0x02, 0x13, 0x80,
	/* > UUID E */
	0x10, 0x47, 0x00, 0x10, 0x46, 0x92, 0x49, 0x6f, 0xce, 0x1e, 0x5f, 0xd1,
	0xa5, 0x45, 0x9b, 0x1c, 0xa5, 0xde, 0xb9, 0x41,
	/* > Primary Device Type */
	0x10, 0x54, 0x00, 0x08, 0x00, 0x01, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01,
	/* > RF Bands */
	0x10, 0x3c, 0x00, 0x01, 0x01,
	/* > Association State */
	0x10, 0x02, 0x00, 0x02, 0x00, 0x00,
	/* > Configuration Error */
	0x10, 0x09, 0x00, 0x02, 0x00, 0x00,
	/* > Device Password ID */
	0x10, 0x12, 0x00, 0x02, 0x00, 0x00,
	/* > Manufacturer */
	0x10, 0x21, 0x00, 0x01, 0x20,
	/* > Model Name */
	0x10, 0x23, 0x00, 0x01, 0x20,
	/* > Model Numbers */
	0x10, 0x24, 0x00, 0x01, 0x20,
	/* > Device Name */
	0x10, 0x11, 0x00, 0x04, 't', 'e', 's', 't',
	/* > Vendor Extension > Version2 */
	0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20,
	/* P2P */
	0xdd, 0x11, 0x50, 0x6f, 0x9a, 0x09,
	/* > P2P Capability */
	0x02, 0x02, 0x00, 0x04, 0x00,
	/* > Listen Channel */
	0x06, 0x05, 0x00, 'X', 'X', 0x04, 0x51, 0x01,
};

static void frame_cb(struct l_genl_msg *msg, void *user_data)
{
	int err = l_genl_msg_get_error(msg);

	if (err < 0) {
		l_error("CMD_FRAME failed: %s (%i)", strerror(-err), -err);
		exit_status = EXIT_FAILURE;
	} else {
		l_info("Frame queued");
		exit_status = EXIT_SUCCESS;
	}

	l_main_quit();
}

static void get_interface_callback(struct l_genl_msg *msg, void *user_data)
{
	uint32_t ifindex;
	uint32_t iftype;
	const char *ifname;
	const uint8_t *ifaddr;
	uint64_t cur_wdev_id;
	struct ifreq ifr;
	int sock;
	int r;

	/*
	 * For now hoose the first interface with iftype station, require it
	 * to be UP and have an ifindex.
	 */

	if (wdev_id)
		return;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_IFINDEX, &ifindex,
					NL80211_ATTR_WDEV, &cur_wdev_id,
					NL80211_ATTR_IFTYPE, &iftype,
					NL80211_ATTR_IFNAME, &ifname,
					NL80211_ATTR_MAC, &ifaddr,
					NL80211_ATTR_UNSPEC) < 0)
		return;

	if (iftype != NL80211_IFTYPE_STATION)
		return;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1)
		return;

	memset(&ifr, 0, sizeof(ifr));
	l_strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	r = ioctl(sock, SIOCGIFFLAGS, &ifr);
	close(sock);

	/* IFF_RUNNING not required */
	if (r == -1 || !(ifr.ifr_flags & IFF_UP))
		return;

	l_info("Selected interface %s", ifname);
	wdev_id = cur_wdev_id;
	memcpy(wdev_addr, ifaddr, 6);
}

static void get_interface_done(void *user_data)
{
	struct l_genl_msg *msg;
	uint8_t frame_buf[256] __attribute__ ((aligned));
	struct mmpdu_header *hdr = (void *) frame_buf;
	static const uint8_t bcast_addr[6] =
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	size_t frame_len;

	if (!wdev_id) {
		l_error("No suitable interface found");
		exit_status = EXIT_FAILURE;
		l_main_quit();
		return;
	}

	memset(frame_buf, 0, sizeof(*hdr));
	hdr->fc.protocol_version = 0;
	hdr->fc.type = MPDU_TYPE_MANAGEMENT;
	hdr->fc.subtype = MPDU_MANAGEMENT_SUBTYPE_PROBE_REQUEST;
	memcpy(hdr->address_1, bcast_addr, 6);	/* DA */
	memcpy(hdr->address_2, wdev_addr, 6);	/* SA */
	memcpy(hdr->address_3, bcast_addr, 6);	/* BSSID */
	frame_len = (uint8_t *) mmpdu_body(hdr) - (uint8_t *) hdr;

	memcpy((void *) mmpdu_body(hdr), probe_req_body, sizeof(probe_req_body));
	frame_len += sizeof(probe_req_body);

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME, 128 + frame_len);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &wdev_id);

	if (freq) {
		l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &freq);
		l_genl_msg_append_attr(msg, NL80211_ATTR_OFFCHANNEL_TX_OK, 0,
					NULL);
	}

	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME, frame_len, frame_buf);
	l_genl_msg_append_attr(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK, 0, NULL);
	l_genl_msg_append_attr(msg, NL80211_ATTR_TX_NO_CCK_RATE, 0, NULL);

	if (!l_genl_family_send(nl80211, msg, frame_cb, user_data, NULL)) {
		l_error("l_genl_family_send failed");
		exit_status = EXIT_FAILURE;
		l_main_quit();
		return;
	}
}

static void dump_interfaces(void)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new(NL80211_CMD_GET_INTERFACE);
	if (!l_genl_family_dump(nl80211, msg, get_interface_callback,
				NULL, get_interface_done)) {
		l_genl_msg_unref(msg);
		l_error("Getting nl80211 interface information failed");
		exit_status = EXIT_FAILURE;
		l_main_quit();
		return;
	}
}

static void family_discovered(const struct l_genl_family_info *info,
							void *user_data)
{
	if (!strcmp(l_genl_family_info_get_name(info), NL80211_GENL_NAME))
		nl80211 = l_genl_family_new(genl, NL80211_GENL_NAME);
}

static void discovery_done(void *user_data)
{
	if (!nl80211) {
		l_error("nl80211 doesn't exist.\n"
			"Load it manually using modprobe cfg80211");
		goto quit;
	}

	dump_interfaces();
	return;

quit:
	exit_status = EXIT_FAILURE;
	l_main_quit();
}

int main(int argc, char *argv[])
{
	if (argc >= 2) {
		char *endp;

		if (!strcmp(argv[1], "-h")) {
			fprintf(stderr,
				"Usage: %s [<frequency>]\n\n"
				"Send out a broadcast Probe Request frame.  "
				"A wireless interface must be UP.  If a "
				"frequency is not given, the frame is "
				"transmitted on the current channel.\n",
				argv[0]);
			return EXIT_SUCCESS;
		}

		freq = strtol(argv[1], &endp, 0);

		if (*endp != '\0') {
			fprintf(stderr, "Can't parse '%s'\n", endp);
			return EXIT_FAILURE;
		}
	}

	if (!l_main_init())
		return EXIT_FAILURE;

	l_log_set_stderr();
	exit_status = EXIT_FAILURE;

	genl = l_genl_new();
	if (!genl) {
		l_error("Failed to initialize generic netlink");
		goto done;
	}

	if (!l_genl_discover_families(genl, family_discovered, NULL,
						discovery_done)) {
		l_error("Unable to start family discovery");
		l_genl_unref(genl);
		goto done;
	}

	l_main_run();

	l_genl_family_free(nl80211);
	l_genl_unref(genl);

done:
	l_main_exit();

	return exit_status;
}
