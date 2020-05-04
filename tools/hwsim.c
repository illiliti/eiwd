/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2019  Intel Corporation. All rights reserved.
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
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/util.h"
#include "src/storage.h"
#include "src/mpdu.h"
#include "src/crypto.h"

#define HWSIM_SERVICE "net.connman.hwsim"

#define HWSIM_RADIO_MANAGER_INTERFACE HWSIM_SERVICE ".RadioManager"
#define HWSIM_RADIO_INTERFACE HWSIM_SERVICE ".Radio"
#define HWSIM_INTERFACE_INTERFACE HWSIM_SERVICE ".Interface"
#define HWSIM_RULE_MANAGER_INTERFACE HWSIM_SERVICE ".RuleManager"
#define HWSIM_RULE_INTERFACE HWSIM_SERVICE ".Rule"

enum {
	HWSIM_CMD_UNSPEC,
	HWSIM_CMD_REGISTER,
	HWSIM_CMD_FRAME,
	HWSIM_CMD_TX_INFO_FRAME,
	HWSIM_CMD_NEW_RADIO,
	HWSIM_CMD_DEL_RADIO,
	HWSIM_CMD_GET_RADIO,
	__HWSIM_CMD_MAX,
};
#define HWSIM_CMD_MAX (__HWSIM_CMD_MAX - 1)

enum {
	HWSIM_ATTR_UNSPEC,
	HWSIM_ATTR_ADDR_RECEIVER,
	HWSIM_ATTR_ADDR_TRANSMITTER,
	HWSIM_ATTR_FRAME,
	HWSIM_ATTR_FLAGS,
	HWSIM_ATTR_RX_RATE,
	HWSIM_ATTR_SIGNAL,
	HWSIM_ATTR_TX_INFO,
	HWSIM_ATTR_COOKIE,
	HWSIM_ATTR_CHANNELS,
	HWSIM_ATTR_RADIO_ID,
	HWSIM_ATTR_REG_HINT_ALPHA2,
	HWSIM_ATTR_REG_CUSTOM_REG,
	HWSIM_ATTR_REG_STRICT_REG,
	HWSIM_ATTR_SUPPORT_P2P_DEVICE,
	HWSIM_ATTR_USE_CHANCTX,
	HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
	HWSIM_ATTR_RADIO_NAME,
	HWSIM_ATTR_NO_VIF,
	HWSIM_ATTR_FREQ,
	HWSIM_ATTR_PAD,
	HWSIM_ATTR_TX_INFO_FLAGS,
	HWSIM_ATTR_PERM_ADDR,
	HWSIM_ATTR_IFTYPE_SUPPORT,
	HWSIM_ATTR_CIPHER_SUPPORT,
	__HWSIM_ATTR_MAX,
};
#define HWSIM_ATTR_MAX (__HWSIM_ATTR_MAX - 1)

/*
 * Should be kept in sync with HWSIM_IFTYPE_SUPPORT_MASK in mac80211_hwsim
 */
#define HWSIM_DEFAULT_IFTYPES \
	( \
		(1 << NL80211_IFTYPE_STATION) | \
		(1 << NL80211_IFTYPE_AP) | \
		(1 << NL80211_IFTYPE_P2P_CLIENT) | \
		(1 << NL80211_IFTYPE_P2P_GO) | \
		(1 << NL80211_IFTYPE_ADHOC) | \
		(1 << NL80211_IFTYPE_MESH_POINT) \
	)

enum hwsim_tx_control_flags {
	HWSIM_TX_CTL_REQ_TX_STATUS		= 1 << 0,
	HWSIM_TX_CTL_NO_ACK			= 1 << 1,
	HWSIM_TX_STAT_ACK			= 1 << 2,
};

#define IEEE80211_TX_RATE_TABLE_SIZE	4

struct hwsim_rule {
	unsigned int id;
	uint8_t source[ETH_ALEN];
	uint8_t destination[ETH_ALEN];
	bool source_any : 1;
	bool destination_any : 1;
	bool bidirectional : 1;
	bool drop : 1;
	uint32_t frequency;
	int priority;
	int signal;
};

struct hwsim_support {
	const char *name;
	uint32_t value;
};

static struct l_genl *genl;
static struct l_genl_family *hwsim;
static struct l_genl_family *nl80211;
static struct l_netlink *rtnl;

static const char *options;
static int exit_status;

static enum action {
	ACTION_NONE,
	ACTION_CREATE,
	ACTION_DESTROY,
	ACTION_LIST,
} action;

static bool no_vif_attr;
static bool p2p_attr;
static const char *radio_name_attr;
static struct l_dbus *dbus;
static struct l_queue *rules;
static unsigned int next_rule_id;

static uint32_t hwsim_iftypes = HWSIM_DEFAULT_IFTYPES;
static const uint32_t hwsim_supported_ciphers[] = {
	CRYPTO_CIPHER_WEP40,
	CRYPTO_CIPHER_WEP104,
	CRYPTO_CIPHER_TKIP,
	CRYPTO_CIPHER_CCMP,
	CRYPTO_CIPHER_BIP,
};
static uint32_t hwsim_ciphers[L_ARRAY_SIZE(hwsim_supported_ciphers)];
static int hwsim_num_ciphers = 0;

/* list of disableable iftypes */
static const struct hwsim_support iftype_map[] = {
	{ "station", 1 << NL80211_IFTYPE_STATION },
	{ "ap", 1 << NL80211_IFTYPE_AP },
	{ "adhoc", 1 << NL80211_IFTYPE_ADHOC },
	{ "p2p_client", 1 << NL80211_IFTYPE_P2P_CLIENT },
	{ "p2p_go", 1 << NL80211_IFTYPE_P2P_GO },
	{ "mesh_point", 1 << NL80211_IFTYPE_MESH_POINT },
	{ }
};

static const struct hwsim_support cipher_map[] = {
	{ "wep40", CRYPTO_CIPHER_WEP40 },
	{ "wep104", CRYPTO_CIPHER_WEP104 },
	{ "tkip", CRYPTO_CIPHER_TKIP },
	{ "ccmp", CRYPTO_CIPHER_CCMP },
	{ "bip", CRYPTO_CIPHER_BIP },
	{ }
};

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void create_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint32_t radio_id = 0;

	/*
	 * Note that the radio id is returned in the error field of
	 * the returned message.
	 */
	if (!l_genl_attr_init(&attr, msg)) {
		int err = l_genl_msg_get_error(msg);

		if (err < 0) {
			l_warn("Failed to initialize create return attributes"
				" [%d/%s]", -err, strerror(-err));
			exit_status = EXIT_FAILURE;
			goto done;
		}

		radio_id = err;

		l_info("Created new radio with id %u", radio_id);
	} else {
		l_warn("Failed to get create return value");
		exit_status = EXIT_FAILURE;
		goto done;
	}

done:
	l_main_quit();
}

static void destroy_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;

	if (!l_genl_attr_init(&attr, msg)) {
		int err = l_genl_msg_get_error(msg);

		if (err < 0) {
			l_warn("Failed to destroy radio [%d/%s]",
				-err, strerror(-err));
			exit_status = EXIT_FAILURE;
			goto done;
		}

		l_info("Destroyed radio");
		goto done;
	}

	while (l_genl_attr_next(&attr, &type, &len, &data))
	;

done:
	l_main_quit();
}

static void list_callback_done(void *user_data)
{
	l_main_quit();
}

static void list_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint32_t idx = 0, channels = 0, custom_reg = 0;
	bool reg_strict = false, p2p = false, chanctx = false;
	char alpha2[2] = { };
	char *hwname = NULL;

	if (!l_genl_attr_init(&attr, msg)) {
		int err = l_genl_msg_get_error(msg);

		if (err < 0) {
			l_warn("Failed to list radio [%d/%s]",
				-err, strerror(-err));
			exit_status = EXIT_FAILURE;
			return;
		}
	}

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case HWSIM_ATTR_RADIO_ID:
			if (len == 4)
				idx = *(int *)data;
			break;

		case HWSIM_ATTR_CHANNELS:
			if (len == 4)
				channels = *(uint32_t *)data;
			break;

		case HWSIM_ATTR_REG_HINT_ALPHA2:
			if (len == 2)
				memcpy(&alpha2, data, len);
			break;

		case HWSIM_ATTR_REG_CUSTOM_REG:
			if (len == 4)
				custom_reg = *(uint32_t *)data;
			break;

		case HWSIM_ATTR_REG_STRICT_REG:
			reg_strict = true;
			break;

		case HWSIM_ATTR_SUPPORT_P2P_DEVICE:
			p2p = true;
			break;

		case HWSIM_ATTR_USE_CHANCTX:
			chanctx = true;
			break;

		case HWSIM_ATTR_RADIO_NAME:
			if (!hwname) {
				hwname = l_new(char, len + 1);

				strncpy(hwname, data, len);
			}

			break;

		default:
			break;
		}
	}

	printf("%s radio id %d channels %d alpha2 %d %d custom reg %d "
		"reg strict %d p2p %d chanctx %d\n",
		hwname, idx, channels, alpha2[0], alpha2[1], custom_reg,
		reg_strict, p2p, chanctx);

	if (hwname)
		l_free(hwname);
}

struct radio_info_rec {
	uint32_t id;
	uint32_t wiphy_id;
	char alpha2[2];
	bool p2p;
	bool custom_regdom;
	uint32_t regdom_idx;
	int channels;
	uint8_t addrs[2][ETH_ALEN];
	char *name;
};

struct interface_info_rec {
	uint32_t id;
	struct radio_info_rec *radio_rec;
	uint8_t addr[ETH_ALEN];
	char *name;
};

static struct l_queue *radio_info;
static struct l_queue *interface_info;

static struct l_dbus_message *pending_create_msg;
static uint32_t pending_create_radio_id;

static void radio_free(void *user_data)
{
	struct radio_info_rec *rec = user_data;

	l_free(rec->name);
	l_free(rec);
}

static void interface_free(void *user_data)
{
	struct interface_info_rec *rec = user_data;

	l_free(rec->name);
	l_free(rec);
}

static void hwsim_radio_cache_cleanup(void)
{
	l_queue_destroy(radio_info, radio_free);
	l_queue_destroy(interface_info, interface_free);
	radio_info = NULL;
	interface_info = NULL;
}

static bool radio_info_match_id(const void *a, const void *b)
{
	const struct radio_info_rec *rec = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return rec->id == id;
}

static bool radio_info_match_wiphy_id(const void *a, const void *b)
{
	const struct radio_info_rec *rec = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return rec->wiphy_id == id;
}

static bool radio_info_match_addr0(const void *a, const void *b)
{
	const struct radio_info_rec *rec = a;
	const uint8_t *addr0 = b;

	return !memcmp(rec->addrs[0], addr0, ETH_ALEN);
}

static bool radio_info_match_addr1(const void *a, const void *b)
{
	const struct radio_info_rec *rec = a;
	const uint8_t *addr1 = b;

	return !memcmp(rec->addrs[1], addr1, ETH_ALEN);
}

static bool interface_info_match_id(const void *a, const void *b)
{
	const struct interface_info_rec *rec = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return rec->id == id;
}

static const char *radio_get_path(const struct radio_info_rec *rec)
{
	static char path[15];

	snprintf(path, sizeof(path), "/radio%u", rec->id);
	return path;
}

static const char *interface_get_path(const struct interface_info_rec *rec)
{
	static char path[25];

	snprintf(path, sizeof(path), "%s/%u",
			radio_get_path(rec->radio_rec), rec->id);
	return path;
}

static struct l_dbus_message *dbus_error_busy(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, HWSIM_SERVICE ".InProgress",
					"Operation already in progress");
}

static struct l_dbus_message *dbus_error_failed(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, HWSIM_SERVICE ".Failed",
					"Operation failed");
}

static struct l_dbus_message *dbus_error_invalid_args(
						struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, HWSIM_SERVICE ".InvalidArgs",
					"Argument type is wrong");
}

static void dbus_pending_reply(struct l_dbus_message **msg,
				struct l_dbus_message *reply)
{
	l_dbus_send(dbus, reply);
	l_dbus_message_unref(*msg);
	*msg = NULL;
}

static const char *rule_get_path(struct hwsim_rule *rule)
{
	static char path[16];

	snprintf(path, sizeof(path), "/rule%u", rule->id);

	return path;
}

static bool parse_addresses(const uint8_t *buf, size_t len,
				struct radio_info_rec *rec)
{
	unsigned int pos = 0, addr_idx = 0;

	while (pos < len) {
		int start_pos = pos;
		char addr[20];

		/* Find first word start and end */
		while (pos < len && !l_ascii_isspace(buf[pos]))
			pos++;

		if (pos - start_pos > sizeof(addr) - 1) {
			l_error("Can't parse a %s address from sysfs",
				rec->name);
			return false;
		}

		memcpy(addr, buf + start_pos, pos - start_pos);
		addr[pos - start_pos] = '\0';

		if (addr_idx >= 2) {
			l_error("Hwsim wiphy %s has too many addresses listed "
				" in sysfs - only 2 supported", rec->name);
			return false;
		}

		if (!util_string_to_address(addr, rec->addrs[addr_idx])) {
			l_error("Can't parse hwsim wiphy %s address from sysfs",
				rec->name);
			return false;
		}

		addr_idx++;

		/* Skip until the start of the next word */
		while (pos < len && l_ascii_isspace(buf[pos]))
			pos++;
	}

	if (addr_idx < 2) {
		l_error("Hwsim wiphy %s has too few addresses listed "
			" in sysfs - only 2 supported", rec->name);
		return false;
	}

	return true;
}

static void get_radio_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const char *name = NULL;
	const uint32_t *id = NULL;
	size_t name_len = 0;
	struct radio_info_rec *rec;
	uint8_t file_buffer[128];
	int bytes, consumed;
	unsigned int uintval;
	bool old;
	struct radio_info_rec prev_rec;
	bool name_change = false;
	const char *path;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case HWSIM_ATTR_RADIO_ID:
			if (len != 4)
				break;

			id = data;
			break;

		case HWSIM_ATTR_RADIO_NAME:
			name = data;
			name_len = len;
			break;
		}
	}

	if (!id || !name)
		return;

	rec = l_queue_find(radio_info, radio_info_match_id, L_UINT_TO_PTR(*id));
	if (rec) {
		old = true;
		memcpy(&prev_rec, rec, sizeof(prev_rec));

		if (strlen(rec->name) != name_len ||
				memcmp(rec->name, name, name_len))
			name_change = true;

		l_free(rec->name);
	} else {
		old = false;
		rec = l_new(struct radio_info_rec, 1);
		rec->id = *id;
	}

	rec->name = l_strndup(name, name_len);

	l_genl_attr_init(&attr, msg);

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case HWSIM_ATTR_CHANNELS:
			if (len != 4)
				break;

			rec->channels = *(uint32_t *) data;
			break;

		case HWSIM_ATTR_REG_HINT_ALPHA2:
			if (len != 2)
				break;

			memcpy(rec->alpha2, data, 2);

			break;

		case HWSIM_ATTR_SUPPORT_P2P_DEVICE:
			rec->p2p = true;
			break;

		case HWSIM_ATTR_REG_CUSTOM_REG:
			if (len != 4)
				break;

			rec->custom_regdom = true;
			rec->regdom_idx = *(uint32_t *) data;
			break;
		}
	}

	/*
	 * Assuming that the radio name is the wiphy name read the wiphy index
	 * associated with the radio and the wiphy's hardware addresses from
	 * sysfs.  The index could be obtained through NL80211_CMD_GET_WIPHY
	 * but that is costly and reading the index synchronously simplifies
	 * the job a lot.  We have to resort to sysfs anyway to obtain the
	 * radio addresses.
	 */

	bytes = read_file((char *) file_buffer, sizeof(file_buffer) - 1,
				"/sys/class/ieee80211/%s/index", rec->name);
	if (bytes < 0) {
		l_error("Error reading index for %s from sysfs", rec->name);
		goto err_free_radio;
	}

	file_buffer[bytes] = '\0';
	if (sscanf((char *) file_buffer, "%u %n", &uintval, &consumed) != 1 ||
			consumed != bytes) {
		l_error("Error parsing index for %s from sysfs", rec->name);
		goto err_free_radio;
	}

	rec->wiphy_id = uintval;

	bytes = read_file(file_buffer, sizeof(file_buffer),
				"/sys/class/ieee80211/%s/addresses", rec->name);
	if (bytes < 0) {
		l_error("Error reading addresses for %s from sysfs", rec->name);
		goto err_free_radio;
	}

	if (!parse_addresses(file_buffer, bytes, rec))
		goto err_free_radio;

	if (!radio_info)
		radio_info = l_queue_new();

	if (!old)
		l_queue_push_tail(radio_info, rec);

	path = radio_get_path(rec);

	if (!old) {
		/* Create Dbus object */

		if (!l_dbus_object_add_interface(dbus, path,
						HWSIM_RADIO_INTERFACE, rec))
			l_info("Unable to add the %s interface to %s",
					HWSIM_RADIO_INTERFACE, path);

		if (!l_dbus_object_add_interface(dbus, path,
						L_DBUS_INTERFACE_PROPERTIES,
						NULL))
			l_info("Unable to add the %s interface to %s",
					L_DBUS_INTERFACE_PROPERTIES, path);
	} else {
		/* Emit property change events */

		if (memcmp(&prev_rec.addrs, &rec->addrs, sizeof(rec->addrs)))
			l_dbus_property_changed(dbus, path,
						HWSIM_RADIO_INTERFACE,
						"Addresses");

		if (name_change)
			l_dbus_property_changed(dbus, path,
						HWSIM_RADIO_INTERFACE, "Name");
	}

	/* Send pending CreateRadio reply */
	if (pending_create_msg && pending_create_radio_id == rec->id) {
		struct l_dbus_message *reply =
			l_dbus_message_new_method_return(pending_create_msg);

		l_dbus_message_set_arguments(reply, "o", path);
		dbus_pending_reply(&pending_create_msg, reply);
	}

	return;

err_free_radio:
	if (!old)
		radio_free(rec);

	if (pending_create_msg && pending_create_radio_id == *id)
		dbus_pending_reply(&pending_create_msg,
					dbus_error_failed(pending_create_msg));
}

static void get_wiphy_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const char *name = NULL;
	uint16_t name_len = 0;
	const uint32_t *id = NULL;
	struct radio_info_rec *rec;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WIPHY:
			id = data;
			break;
		case NL80211_ATTR_WIPHY_NAME:
			name = data;
			name_len = len;
			break;
		}
	}

	if (!name || !id)
		return;

	rec = l_queue_find(radio_info, radio_info_match_wiphy_id,
				L_UINT_TO_PTR(*id));
	if (!rec)
		return;

	if (strlen(rec->name) == name_len && !memcmp(rec->name, name, name_len))
		return;

	l_free(rec->name);
	rec->name = l_strndup(name, name_len);

	l_dbus_property_changed(dbus, radio_get_path(rec),
				HWSIM_RADIO_INTERFACE, "Name");
}

static void get_interface_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint8_t *addr = NULL;
	const uint32_t *wiphy_id = NULL;
	const uint32_t *ifindex = NULL;
	const char *ifname = NULL;
	size_t ifname_len = 0;
	struct interface_info_rec *rec;
	struct radio_info_rec *radio_rec;
	bool old;
	const char *path;
	struct interface_info_rec prev_rec;
	bool name_change = false;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_MAC:
			if (len != ETH_ALEN)
				break;

			addr = data;
			break;

		case NL80211_ATTR_WIPHY:
			if (len != 4)
				break;

			wiphy_id = data;
			break;

		case NL80211_ATTR_IFINDEX:
			if (len != 4)
				break;

			ifindex = data;
			break;

		case NL80211_ATTR_IFNAME:
			ifname = data;
			ifname_len = len;
			break;
		}
	}

	if (!addr || !wiphy_id || !ifindex || !ifname)
		return;

	radio_rec = l_queue_find(radio_info, radio_info_match_wiphy_id,
				L_UINT_TO_PTR(*wiphy_id));
	if (!radio_rec)
		/* This is not a hwsim interface, don't track it */
		return;

	rec = l_queue_find(interface_info, interface_info_match_id,
				L_UINT_TO_PTR(*ifindex));
	if (rec) {
		old = true;

		memcpy(&prev_rec, rec, sizeof(prev_rec));

		if (strlen(rec->name) != ifname_len ||
				memcmp(rec->name, ifname, ifname_len))
			name_change = true;

		l_free(rec->name);
	} else {
		old = false;

		rec = l_new(struct interface_info_rec, 1);

		rec->id = *ifindex;
		rec->radio_rec = radio_rec;
	}

	memcpy(rec->addr, addr, ETH_ALEN);
	rec->name = l_strndup(ifname, ifname_len);

	if (!interface_info)
		interface_info = l_queue_new();

	if (!old)
		l_queue_push_tail(interface_info, rec);

	path = interface_get_path(rec);

	if (!old) {
		/* Create Dbus object */

		if (!l_dbus_object_add_interface(dbus, path,
						HWSIM_INTERFACE_INTERFACE, rec))
			l_info("Unable to add the %s interface to %s",
					HWSIM_INTERFACE_INTERFACE, path);

		if (!l_dbus_object_add_interface(dbus, path,
						L_DBUS_INTERFACE_PROPERTIES,
						NULL))
			l_info("Unable to add the %s interface to %s",
					L_DBUS_INTERFACE_PROPERTIES, path);
	} else {
		/* Emit property change events */

		if (memcmp(prev_rec.addr, rec->addr, ETH_ALEN))
			l_dbus_property_changed(dbus, path,
						HWSIM_INTERFACE_INTERFACE,
						"Address");

		if (name_change)
			l_dbus_property_changed(dbus, path,
						HWSIM_INTERFACE_INTERFACE,
						"Name");
	}
}

static bool interface_info_destroy_by_radio(void *data, void *user_data)
{
	struct interface_info_rec *rec = data;
	struct radio_info_rec *radio_rec = user_data;

	if (rec->radio_rec != radio_rec)
		return false;

	l_dbus_unregister_object(dbus, interface_get_path(rec));
	interface_free(rec);

	return true;
}

static void del_radio_event(struct l_genl_msg *msg)
{
	struct radio_info_rec *radio;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint32_t *id = NULL;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case HWSIM_ATTR_RADIO_ID:
			if (len != 4)
				break;

			id = data;

			break;
		}
	}

	if (!id)
		return;

	radio = l_queue_find(radio_info, radio_info_match_id,
				L_UINT_TO_PTR(*id));
	if (!radio)
		return;

	l_queue_foreach_remove(interface_info, interface_info_destroy_by_radio,
				radio);
	l_dbus_unregister_object(dbus, radio_get_path(radio));
	l_queue_remove(radio_info, radio);
	radio_free(radio);
}

static void del_interface_event(struct l_genl_msg *msg)
{
	struct interface_info_rec *interface;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint32_t *ifindex = NULL;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_IFINDEX:
			if (len != 4)
				break;

			ifindex = data;
			break;
		}
	}

	if (!ifindex)
		return;

	interface = l_queue_find(interface_info, interface_info_match_id,
					L_UINT_TO_PTR(*ifindex));
	if (!interface)
		return;

	l_dbus_unregister_object(dbus, interface_get_path(interface));
	l_queue_remove(interface_info, interface);
	interface_free(interface);
}

static void hwsim_config(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	l_debug("Config changed cmd %u", cmd);

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data))
		l_debug("\tattr type %d len %d", type, len);

	switch (cmd) {
	case HWSIM_CMD_NEW_RADIO:
		get_radio_callback(msg, NULL);
		break;
	case HWSIM_CMD_DEL_RADIO:
		del_radio_event(msg);
		break;
	}
}

static void nl80211_config_notify(struct l_genl_msg *msg, void *user_data)
{
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	l_debug("Notification of command %u", cmd);

	switch (cmd) {
	case NL80211_CMD_NEW_WIPHY:
		get_wiphy_callback(msg, NULL);
		break;
	case NL80211_CMD_NEW_INTERFACE:
		get_interface_callback(msg, NULL);
		break;
	case NL80211_CMD_DEL_INTERFACE:
		del_interface_event(msg);
		break;
	}
}

static void rtnl_newlink_notify(const struct ifinfomsg *ifi, int bytes)
{
	struct rtattr *attr;
	struct interface_info_rec *rec;
	bool addr_change = false, name_change = false;
	const char *path;

	rec = l_queue_find(interface_info, interface_info_match_id,
				L_UINT_TO_PTR(ifi->ifi_index));
	if (!rec)
		return;

	for (attr = IFLA_RTA(ifi); RTA_OK(attr, bytes);
			attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFLA_IFNAME:
			if (!strcmp(rec->name, RTA_DATA(attr)))
				continue;

			name_change = true;
			l_free(rec->name);
			rec->name = l_strdup(RTA_DATA(attr));
			break;
		case IFLA_ADDRESS:
			if (RTA_PAYLOAD(attr) < ETH_ALEN)
				break;

			if (!memcmp(rec->addr, RTA_DATA(attr), ETH_ALEN))
				continue;

			addr_change = true;
			memcpy(rec->addr, RTA_DATA(attr), ETH_ALEN);
			break;
		}
	}

	if (!addr_change && !name_change)
		return;

	path = interface_get_path(rec);

	if (addr_change)
		l_dbus_property_changed(dbus, path, HWSIM_INTERFACE_INTERFACE,
					"Address");

	if (name_change)
		l_dbus_property_changed(dbus, path, HWSIM_INTERFACE_INTERFACE,
					"Name");
}

static void rtnl_link_notify(uint16_t type, const void *data, uint32_t len,
				void *user_data)
{
	const struct ifinfomsg *ifi = data;
	unsigned int bytes;

	if (ifi->ifi_type != ARPHRD_ETHER)
		return;

	bytes = len - NLMSG_ALIGN(sizeof(struct ifinfomsg));

	switch (type) {
	case RTM_NEWLINK:
		rtnl_newlink_notify(ifi, bytes);
		break;
	}
}

struct hwsim_tx_info {
	int8_t idx;
	uint8_t count;
};

struct hwsim_frame {
	int refcount;
	uint8_t src_ether_addr[ETH_ALEN];
	uint8_t dst_ether_addr[ETH_ALEN];
	struct radio_info_rec *src_radio;
	struct radio_info_rec *ack_radio;
	uint32_t flags;
	const uint64_t *cookie;
	int32_t signal;
	uint32_t frequency;
	uint16_t tx_info_len;
	const struct hwsim_tx_info *tx_info;
	uint16_t payload_len;
	const uint8_t *payload;
	bool acked;
	struct l_genl_msg *msg;
	int pending_callback_count;
};

static bool radio_match_addr(const struct radio_info_rec *radio,
				const uint8_t *addr)
{
	if (!radio || util_is_broadcast_address(addr))
		return !radio && util_is_broadcast_address(addr);

	return !memcmp(addr, radio->addrs[0], ETH_ALEN) ||
		!memcmp(addr, radio->addrs[1], ETH_ALEN);
}

static void process_rules(const struct radio_info_rec *src_radio,
				const struct radio_info_rec *dst_radio,
				struct hwsim_frame *frame, bool *drop)
{
	const struct l_queue_entry *rule_entry;

	for (rule_entry = l_queue_get_entries(rules); rule_entry;
			rule_entry = rule_entry->next) {
		struct hwsim_rule *rule = rule_entry->data;

		if (!rule->source_any &&
				!radio_match_addr(src_radio, rule->source) &&
				(!rule->bidirectional ||
				 !radio_match_addr(dst_radio, rule->source)))
			continue;

		if (!rule->destination_any &&
				!radio_match_addr(dst_radio,
							rule->destination) &&
				(!rule->bidirectional ||
				 !radio_match_addr(src_radio,
							rule->destination)))
			continue;

		/*
		 * If source matches only because rule->bidirectional was
		 * true, make sure destination is "any" or matches source
		 * radio's address.
		 */
		if (!rule->source_any && rule->bidirectional &&
				radio_match_addr(dst_radio, rule->source))
			if (!rule->destination_any &&
					!radio_match_addr(dst_radio,
							rule->destination))
				continue;

		if (rule->frequency && rule->frequency != frame->frequency)
			continue;

		/* Rule deemed to match frame, apply any changes */

		if (rule->signal)
			frame->signal = rule->signal / 100;

		*drop = rule->drop;
	}
}

struct send_frame_info {
	struct hwsim_frame *frame;
	struct radio_info_rec *radio;
	void *user_data;
};

static bool send_frame_tx_info(struct hwsim_frame *frame)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(HWSIM_CMD_TX_INFO_FRAME,
					128 + frame->tx_info_len);
	l_genl_msg_append_attr(msg, HWSIM_ATTR_ADDR_TRANSMITTER, ETH_ALEN,
				frame->src_radio->addrs[1]);
	l_genl_msg_append_attr(msg, HWSIM_ATTR_FLAGS, 4, &frame->flags);
	l_genl_msg_append_attr(msg, HWSIM_ATTR_SIGNAL, 4, &frame->signal);
	l_genl_msg_append_attr(msg, HWSIM_ATTR_COOKIE, 8, frame->cookie);
	l_genl_msg_append_attr(msg, HWSIM_ATTR_TX_INFO, frame->tx_info_len,
				frame->tx_info);

	if (!l_genl_family_send(hwsim, msg, NULL, NULL, NULL)) {
		l_error("Sending HWSIM_CMD_TX_INFO_FRAME failed");
		return false;
	}

	return true;
}

static bool send_frame(struct send_frame_info *info,
			l_genl_msg_func_t callback,
			l_genl_destroy_func_t destroy)
{
	struct l_genl_msg *msg;
	uint32_t rx_rate = 2;
	unsigned int id;

	msg = l_genl_msg_new_sized(HWSIM_CMD_FRAME,
					128 + info->frame->payload_len);
	l_genl_msg_append_attr(msg, HWSIM_ATTR_ADDR_RECEIVER, ETH_ALEN,
				info->radio->addrs[1]);
	l_genl_msg_append_attr(msg, HWSIM_ATTR_FRAME, info->frame->payload_len,
				info->frame->payload);
	l_genl_msg_append_attr(msg, HWSIM_ATTR_RX_RATE, 4,
				&rx_rate);
	l_genl_msg_append_attr(msg, HWSIM_ATTR_SIGNAL, 4,
				&info->frame->signal);
	l_genl_msg_append_attr(msg, HWSIM_ATTR_FREQ, 4,
				&info->frame->frequency);

	id = l_genl_family_send(hwsim, msg, callback, info, destroy);
	if (!id) {
		l_error("Sending HWSIM_CMD_FRAME failed");
		return false;
	}

	return true;
}

static struct hwsim_frame *hwsim_frame_ref(struct hwsim_frame *frame)
{
	__sync_fetch_and_add(&frame->refcount, 1);

	return frame;
}

static void hwsim_frame_unref(struct hwsim_frame *frame)
{
	if (__sync_sub_and_fetch(&frame->refcount, 1))
		return;

	if (!frame->pending_callback_count) {
		/*
		 * Apparently done with this frame, send tx info and signal
		 * the returning of an ACK frame in the opposite direction.
		 */

		if (!(frame->flags & HWSIM_TX_CTL_NO_ACK) && frame->acked) {
			bool drop = false;

			process_rules(frame->ack_radio, frame->src_radio,
					frame, &drop);

			if (!drop)
				frame->flags |= HWSIM_TX_STAT_ACK;
		}

		if (frame->src_radio)
			send_frame_tx_info(frame);
	}

	l_genl_msg_unref(frame->msg);
	l_free(frame);
}

static void send_frame_callback(struct l_genl_msg *msg, void *user_data)
{
	struct send_frame_info *info = user_data;

	if (l_genl_msg_get_error(msg) < 0)
		/* Radio address or frequency didn't match */
		l_debug("HWSIM_CMD_FRAME failed for destination %s",
			util_address_to_string(info->radio->addrs[0]));
	else {
		info->frame->acked = true;
		info->frame->ack_radio = info->radio;
	}

	info->frame->pending_callback_count--;
}

static void send_frame_destroy(void *user_data)
{
	struct send_frame_info *info = user_data;

	hwsim_frame_unref(info->frame);
	l_free(info);
}

static void send_custom_frame_callback(struct l_genl_msg *msg, void *user_data)
{
	struct send_frame_info *info = user_data;
	struct l_dbus_message *message = info->user_data;
	struct l_dbus_message *reply;

	info->user_data = NULL;

	if (l_genl_msg_get_error(msg) < 0) {
		/* Radio address or frequency didn't match */
		l_debug("HWSIM_CMD_FRAME failed for destination %s: %d",
				util_address_to_string(info->radio->addrs[0]),
				l_genl_msg_get_error(msg));
		dbus_pending_reply(&message, dbus_error_invalid_args(message));
		return;
	}

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");
	dbus_pending_reply(&message, reply);
}

static void send_custom_frame_destroy(void *user_data)
{
	struct send_frame_info *info = user_data;

	if (info->user_data)
		l_dbus_message_unref(info->user_data);

	l_free(info->frame);
	l_free(info);
}

static bool send_custom_frame(const uint8_t *addr, uint32_t freq,
		int32_t signal, const void *payload, uint32_t len,
		void *user_data)
{
	struct hwsim_frame *frame = l_new(struct hwsim_frame, 1);
	struct send_frame_info *info = l_new(struct send_frame_info, 1);

	frame->frequency = freq;
	frame->signal = signal;
	frame->payload_len = len;
	frame->payload = payload;

	info->frame = frame;
	info->user_data = user_data;

	info->radio = l_queue_find(radio_info, radio_info_match_addr0, addr) ?:
		l_queue_find(radio_info, radio_info_match_addr1, addr);
	if (!info->radio)
		goto error;

	if (!send_frame(info, send_custom_frame_callback,
			send_custom_frame_destroy))
		goto error;

	return true;

error:
	l_free(frame);
	l_free(info);

	return false;
}

struct interface_match_data {
	struct radio_info_rec *radio;
	const uint8_t *addr;
};

static bool interface_info_match_dst(const void *a, const void *b)
{
	const struct interface_info_rec *rec = a;
	const struct interface_match_data *dst = b;

	return rec->radio_rec == dst->radio &&
		!memcmp(rec->addr, dst->addr, ETH_ALEN);
}

static void frame_delay_callback(struct l_timeout *timeout, void *user_data)
{
	struct send_frame_info *send_info = user_data;

	if (send_frame(send_info, send_frame_callback,
					send_frame_destroy))
		send_info->frame->pending_callback_count++;
	else
		send_frame_destroy(send_info);

	l_timeout_remove(timeout);
}

/*
 * Process frames in a similar way to how the kernel built-in hwsim medium
 * does this, with an additional optimization for unicast frames and
 * additional modifications to frames decided by user-configurable rules.
 */
static void process_frame(struct hwsim_frame *frame)
{
	const struct l_queue_entry *entry;
	bool drop_mcast = false;

	if (util_is_broadcast_address(frame->dst_ether_addr))
		process_rules(frame->src_radio, NULL, frame, &drop_mcast);

	for (entry = l_queue_get_entries(radio_info); entry;
			entry = entry->next) {
		struct radio_info_rec *radio = entry->data;
		struct send_frame_info *send_info;
		bool drop = drop_mcast;

		if (radio == frame->src_radio)
			continue;

		/*
		 * The kernel hwsim medium passes multicast frames to all
		 * radios that are on the same frequency as this frame but
		 * the netlink medium API only lets userspace pass frames to
		 * radios by known hardware address.  It does check that the
		 * receiving radio is on the same frequency though so we can
		 * send to all known addresses.
		 *
		 * If the frame's Receiver Address (RA) is a multicast
		 * address, then send the frame to every radio that is
		 * registered.  If it's a unicast address then optimize
		 * by only forwarding the frame to the radios that have
		 * at least one interface with this specific address.
		 */
		if (!util_is_broadcast_address(frame->dst_ether_addr)) {
			struct interface_match_data match_data = {
				radio,
				frame->dst_ether_addr,
			};
			struct interface_info_rec *interface =
				l_queue_find(interface_info,
						interface_info_match_dst,
						&match_data);

			if (!interface)
				continue;
		}

		process_rules(frame->src_radio, radio, frame, &drop);

		if (drop)
			continue;

		send_info = l_new(struct send_frame_info, 1);
		send_info->radio = radio;
		send_info->frame = hwsim_frame_ref(frame);

		if (!l_timeout_create_ms(1, frame_delay_callback,
						send_info, NULL)) {
			l_error("Error delaying frame, frame will be dropped");
			send_frame_destroy(send_info);
		}
	}

	hwsim_frame_unref(frame);
}

static void unicast_handler(struct l_genl_msg *msg, void *user_data)
{
	struct hwsim_frame *frame;
	const struct mmpdu_header *mpdu;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const uint8_t *transmitter = NULL, *freq = NULL, *flags = NULL;

	if (l_genl_msg_get_command(msg) != HWSIM_CMD_FRAME)
		return;

	if (!l_genl_attr_init(&attr, msg))
		return;

	frame = l_new(struct hwsim_frame, 1);

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case HWSIM_ATTR_ADDR_TRANSMITTER:
			if (len != ETH_ALEN)
				break;

			transmitter = data;
			break;

		case HWSIM_ATTR_FREQ:
			if (len != 4)
				break;

			freq = data;
			break;

		case HWSIM_ATTR_FLAGS:
			if (len != 4)
				break;

			flags = data;
			break;

		case HWSIM_ATTR_COOKIE:
			if (len != 8)
				break;

			frame->cookie = (const uint64_t *) data;
			break;

		case HWSIM_ATTR_FRAME:
			if (len > IEEE80211_MAX_DATA_LEN)
				break;

			/* Duration + Address1 + Address2 + Address3 + SeqCtl */
			if (len < sizeof(struct mpdu_fc) + 22) {
				l_error("Frame payload too short for header");
				break;
			}

			frame->payload_len = len;
			frame->payload = data;

			break;

		case HWSIM_ATTR_TX_INFO:
			if (len > sizeof(struct hwsim_tx_info) *
					IEEE80211_TX_RATE_TABLE_SIZE)
				break;

			frame->tx_info_len = len;
			frame->tx_info = data;

			break;

		default:
			if (type >= __HWSIM_ATTR_MAX)
				l_warn("Unknown attribute type: %u", type);
			break;
		}
	}

	if (!frame->payload || !frame->tx_info || !frame->cookie ||
			!flags || !freq || !transmitter) {
		l_error("Incomplete HWSIM_CMD_FRAME");
		l_free(frame);
		return;
	}

	frame->signal = -30;
	frame->msg = l_genl_msg_ref(msg);
	frame->refcount = 1;

	frame->src_radio = l_queue_find(radio_info, radio_info_match_addr1,
					transmitter);
	if (!frame->src_radio) {
		l_error("Unknown transmitter address %s, probably need to "
			"update radio dump code for this kernel",
			util_address_to_string(transmitter));
		hwsim_frame_unref(frame);
		return;
	}

	frame->frequency = *(uint32_t *) freq;
	frame->flags = *(uint32_t *) flags;

	mpdu = (const struct mmpdu_header *) frame->payload;

	memcpy(frame->src_ether_addr, mpdu->address_2, ETH_ALEN);
	memcpy(frame->dst_ether_addr, mpdu->address_1, ETH_ALEN);

	process_frame(frame);
}

static void radio_manager_create_callback(struct l_genl_msg *msg,
						void *user_data)
{
	struct l_dbus_message *reply;
	struct l_genl_attr attr;
	struct radio_info_rec *radio;
	int err;

	/*
	 * Note that the radio id is returned in the error field of
	 * the returned message.
	 */
	if (l_genl_attr_init(&attr, msg))
		goto error;

	err = l_genl_msg_get_error(msg);
	if (err < 0)
		goto error;

	pending_create_radio_id = err;

	/*
	 * If the NEW_RADIO event has been received we'll have added the
	 * radio to radio_info already but we can send the method return
	 * only now that we know the ID returned by our command.
	 */
	radio = l_queue_find(radio_info, radio_info_match_id,
				L_UINT_TO_PTR(pending_create_radio_id));
	if (radio) {
		const char *path = radio_get_path(radio);

		reply = l_dbus_message_new_method_return(pending_create_msg);
		l_dbus_message_set_arguments(reply, "o", path);
		dbus_pending_reply(&pending_create_msg, reply);
	}

	return;

error:
	reply = dbus_error_failed(pending_create_msg);
	dbus_pending_reply(&pending_create_msg, reply);
}

static struct l_dbus_message *radio_manager_create(struct l_dbus *dbus,
					struct l_dbus_message *message,
					void *user_data)
{
	struct l_genl_msg *new_msg;
	const char *name;
	bool p2p;

	if (pending_create_msg)
		return dbus_error_busy(message);

	if (!l_dbus_message_get_arguments(message, "sb", &name, &p2p))
		return dbus_error_invalid_args(message);

	new_msg = l_genl_msg_new_sized(HWSIM_CMD_NEW_RADIO, 16 + strlen(name));
	l_genl_msg_append_attr(new_msg, HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
				0, NULL);

	if (name[0])
		l_genl_msg_append_attr(new_msg, HWSIM_ATTR_RADIO_NAME,
					strlen(name) + 1, name);

	if (p2p)
		l_genl_msg_append_attr(new_msg, HWSIM_ATTR_SUPPORT_P2P_DEVICE,
					0, NULL);

	l_genl_family_send(hwsim, new_msg, radio_manager_create_callback,
				pending_create_msg, NULL);

	pending_create_msg = l_dbus_message_ref(message);
	pending_create_radio_id = 0;

	return NULL;
}

static void setup_radio_manager_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "CreateRadio", 0,
				radio_manager_create, "o", "sb",
				"path", "name", "p2p_device");
}

static void radio_destroy_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_dbus_message *message = user_data;
	struct l_dbus_message *reply;
	struct l_genl_attr attr;
	int err;

	if (l_genl_attr_init(&attr, msg))
		goto error;

	err = l_genl_msg_get_error(msg);
	if (err < 0)
		goto error;

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");
	dbus_pending_reply(&message, reply);

	return;

error:
	reply = dbus_error_failed(message);
	dbus_pending_reply(&message, reply);
}

static struct l_dbus_message *radio_destroy(struct l_dbus *dbus,
					struct l_dbus_message *message,
					void *user_data)
{
	struct l_genl_msg *del_msg;
	struct radio_info_rec *radio = user_data;

	del_msg = l_genl_msg_new_sized(HWSIM_CMD_DEL_RADIO, 8);

	l_genl_msg_append_attr(del_msg, HWSIM_ATTR_RADIO_ID, 4, &radio->id);

	l_genl_family_send(hwsim, del_msg, radio_destroy_callback,
				l_dbus_message_ref(message), NULL);

	return NULL;
}

static bool radio_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct radio_info_rec *rec = user_data;

	l_dbus_message_builder_append_basic(builder, 's', rec->name);

	return true;
}

static bool radio_property_get_addresses(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct radio_info_rec *rec = user_data;
	unsigned int i;

	l_dbus_message_builder_enter_array(builder, "s");

	for (i = 0; i < sizeof(rec->addrs) / ETH_ALEN; i++) {
		const char *str = util_address_to_string(rec->addrs[i]);

		l_dbus_message_builder_append_basic(builder, 's', str);
	}

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool radio_property_get_channels(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct radio_info_rec *rec = user_data;
	uint16_t val = rec->channels;

	l_dbus_message_builder_append_basic(builder, 'q', &val);

	return true;
}

static bool radio_property_get_alpha2(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct radio_info_rec *rec = user_data;

	if (rec->alpha2[0] == 0 || rec->alpha2[1] == 0)
		return false;

	l_dbus_message_builder_enter_struct(builder, "yy");
	l_dbus_message_builder_append_basic(builder, 'y', &rec->alpha2[0]);
	l_dbus_message_builder_append_basic(builder, 'y', &rec->alpha2[1]);
	l_dbus_message_builder_leave_struct(builder);

	return true;
}

static bool radio_property_get_p2p(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct radio_info_rec *rec = user_data;
	bool val = rec->p2p;

	l_dbus_message_builder_append_basic(builder, 'b', &val);

	return true;
}

static bool radio_property_get_regdom(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct radio_info_rec *rec = user_data;

	if (!rec->custom_regdom)
		return false;

	l_dbus_message_builder_append_basic(builder, 'u', &rec->regdom_idx);

	return true;
}

static void setup_radio_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Destroy", 0, radio_destroy, "", "");

	l_dbus_interface_property(interface, "Name", 0, "s",
					radio_property_get_name, NULL);
	l_dbus_interface_property(interface, "Addresses", 0, "as",
					radio_property_get_addresses, NULL);
	l_dbus_interface_property(interface, "Channels", 0, "q",
					radio_property_get_channels, NULL);
	l_dbus_interface_property(interface, "Alpha2", 0, "(yy)",
					radio_property_get_alpha2, NULL);
	l_dbus_interface_property(interface, "P2PDevice", 0, "b",
					radio_property_get_p2p, NULL);
	l_dbus_interface_property(interface, "RegulatoryDomainIndex", 0, "u",
					radio_property_get_regdom, NULL);
}

static struct l_dbus_message *interface_send_frame(struct l_dbus *dbus,
		struct l_dbus_message *message,
		void *user_data)
{
	struct l_dbus_message_iter addr;
	struct l_dbus_message_iter data;
	const void *frame;
	const uint8_t *receiver;
	uint32_t len;
	uint32_t freq;
	int32_t signal;

	if (!l_dbus_message_get_arguments(message, "ayuiay", &addr, &freq,
			&signal, &data))
		goto invalid_args;

	if (!l_dbus_message_iter_get_fixed_array(&addr,
			(const void **)&receiver, &len))
		goto invalid_args;

	if (len != 6)
		goto invalid_args;

	if (!l_dbus_message_iter_get_fixed_array(&data, &frame, &len))
		goto invalid_args;

	if (!send_custom_frame(receiver, freq, signal, frame, len,
			l_dbus_message_ref(message))) {
		l_dbus_message_unref(message);
		goto invalid_args;
	}

	return NULL;

invalid_args:
	return dbus_error_invalid_args(message);
}

static bool interface_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct interface_info_rec *rec = user_data;

	l_dbus_message_builder_append_basic(builder, 's', rec->name);

	return true;
}

static bool interface_property_get_address(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct interface_info_rec *rec = user_data;
	const char *str = util_address_to_string(rec->addr);

	l_dbus_message_builder_append_basic(builder, 's', str);

	return true;
}

static void setup_interface_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "SendFrame", 0,
			interface_send_frame, "", "ayuiay", "station",
			"frequency", "signal", "frame");

	l_dbus_interface_property(interface, "Name", 0, "s",
					interface_property_get_name, NULL);
	l_dbus_interface_property(interface, "Address", 0, "s",
					interface_property_get_address, NULL);
}

static int rule_compare_priority(const void *a, const void *b, void *user)
{
	const struct hwsim_rule *rule_a = a;
	const struct hwsim_rule *rule_b = b;

	return rule_a->priority - rule_b->priority;
}

static struct l_dbus_message *rule_add(struct l_dbus *dbus,
					struct l_dbus_message *message,
					void *user_data)
{
	struct hwsim_rule *rule;
	const char *path;
	struct l_dbus_message *reply;

	rule = l_new(struct hwsim_rule, 1);
	rule->id = next_rule_id++;
	rule->source_any = true;
	rule->destination_any = true;

	if (!rules)
		rules = l_queue_new();

	l_queue_insert(rules, rule, rule_compare_priority, NULL);
	path = rule_get_path(rule);

	if (!l_dbus_object_add_interface(dbus, path,
					HWSIM_RULE_INTERFACE, rule))
		l_info("Unable to add the %s interface to %s",
				HWSIM_RULE_INTERFACE, path);

	if (!l_dbus_object_add_interface(dbus, path,
					L_DBUS_INTERFACE_PROPERTIES, NULL))
		l_info("Unable to add the %s interface to %s",
				L_DBUS_INTERFACE_PROPERTIES, path);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "o", path);

	return reply;
}

static void setup_rule_manager_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "AddRule", 0,
				rule_add, "o", "", "path");
}

static struct l_dbus_message *rule_remove(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct hwsim_rule *rule = user_data;
	const char *path;

	path = rule_get_path(rule);
	l_queue_remove(rules, rule);
	l_free(rule);
	l_dbus_unregister_object(dbus, path);

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_source(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	const char *str;

	if (rule->source_any)
		str = "any";
	else
		str = util_address_to_string(rule->source);

	l_dbus_message_builder_append_basic(builder, 's', str);

	return true;
}

static struct l_dbus_message *rule_property_set_source(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	const char *str;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &str))
		return dbus_error_invalid_args(message);

	if (!strcmp(str, "any"))
		rule->source_any = true;
	else {
		if (!util_string_to_address(str, rule->source))
			return dbus_error_invalid_args(message);

		rule->source_any = false;
	}

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_destination(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	const char *str;

	if (rule->destination_any)
		str = "any";
	else if (util_is_broadcast_address(rule->destination))
		str = "multicast";
	else
		str = util_address_to_string(rule->destination);

	l_dbus_message_builder_append_basic(builder, 's', str);

	return true;
}

static struct l_dbus_message *rule_property_set_destination(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	const char *str;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &str))
		return dbus_error_invalid_args(message);

	if (!strcmp(str, "any"))
		rule->destination_any = true;
	else if (!strcmp(str, "multicast")) {
		rule->destination[0] = 0x80;
		rule->destination_any = false;
	} else {
		if (!util_string_to_address(str, rule->destination))
			return dbus_error_invalid_args(message);

		rule->destination_any = false;
	}

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_bidirectional(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	bool bval = rule->bidirectional;

	l_dbus_message_builder_append_basic(builder, 'b', &bval);

	return true;
}

static struct l_dbus_message *rule_property_set_bidirectional(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	bool bval;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &bval))
		return dbus_error_invalid_args(message);

	rule->bidirectional = bval;

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_frequency(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;

	l_dbus_message_builder_append_basic(builder, 'u', &rule->frequency);

	return true;
}

static struct l_dbus_message *rule_property_set_frequency(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;

	if (!l_dbus_message_iter_get_variant(new_value, "u", &rule->frequency))
		return dbus_error_invalid_args(message);

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_priority(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	int16_t intval = rule->priority;

	l_dbus_message_builder_append_basic(builder, 'n', &intval);

	return true;
}

static struct l_dbus_message *rule_property_set_priority(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	int16_t intval;

	if (!l_dbus_message_iter_get_variant(new_value, "n", &intval))
		return dbus_error_invalid_args(message);

	rule->priority = intval;
	l_queue_remove(rules, rule);
	l_queue_insert(rules, rule, rule_compare_priority, NULL);

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_signal(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	int16_t intval = rule->signal;

	l_dbus_message_builder_append_basic(builder, 'n', &intval);

	return true;
}

static struct l_dbus_message *rule_property_set_signal(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	int16_t intval;

	if (!l_dbus_message_iter_get_variant(new_value, "n", &intval) ||
			intval > 0 || intval < -10000)
		return dbus_error_invalid_args(message);

	rule->signal = intval;

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_drop(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	bool bval = rule->drop;

	l_dbus_message_builder_append_basic(builder, 'b', &bval);

	return true;
}

static struct l_dbus_message *rule_property_set_drop(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	bool bval;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &bval))
		return dbus_error_invalid_args(message);

	rule->drop = bval;

	return l_dbus_message_new_method_return(message);
}

static void setup_rule_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Remove", 0, rule_remove, "", "");

	l_dbus_interface_property(interface, "Source",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "s",
					rule_property_get_source,
					rule_property_set_source);
	l_dbus_interface_property(interface, "Destination",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "s",
					rule_property_get_destination,
					rule_property_set_destination);
	l_dbus_interface_property(interface, "Bidirectional",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "b",
					rule_property_get_bidirectional,
					rule_property_set_bidirectional);
	l_dbus_interface_property(interface, "Frequency",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "u",
					rule_property_get_frequency,
					rule_property_set_frequency);
	l_dbus_interface_property(interface, "Priority",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "n",
					rule_property_get_priority,
					rule_property_set_priority);
	l_dbus_interface_property(interface, "SignalStrength",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "n",
					rule_property_get_signal,
					rule_property_set_signal);
	l_dbus_interface_property(interface, "Drop",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "b",
					rule_property_get_drop,
					rule_property_set_drop);
}

static void request_name_callback(struct l_dbus *dbus, bool success,
					bool queued, void *user_data)
{
	if (!success)
		l_error("Name request failed");
}

static void ready_callback(void *user_data)
{
	l_dbus_name_acquire(dbus, HWSIM_SERVICE, false, false, true,
				request_name_callback, NULL);

	if (!l_dbus_object_manager_enable(dbus, "/"))
		l_info("Unable to register the ObjectManager");
}

static void disconnect_callback(void *user_data)
{
	l_info("D-Bus disconnected, quitting...");
	l_main_quit();
}

static bool setup_dbus_hwsim(void)
{
	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	if (!dbus) {
		l_error("Unable to connect to Dbus");
		return false;
	}

	if (!l_dbus_register_interface(dbus, HWSIM_RADIO_MANAGER_INTERFACE,
					setup_radio_manager_interface,
					NULL, false)) {
		l_error("Unable to register the %s interface",
			HWSIM_RADIO_MANAGER_INTERFACE);
		return false;
	}

	if (!l_dbus_register_interface(dbus, HWSIM_RADIO_INTERFACE,
					setup_radio_interface, NULL, false)) {
		l_error("Unable to register the %s interface",
			HWSIM_RADIO_INTERFACE);
		return false;
	}

	if (!l_dbus_register_interface(dbus, HWSIM_INTERFACE_INTERFACE,
					setup_interface_interface,
					NULL, false)) {
		l_error("Unable to register the %s interface",
			HWSIM_INTERFACE_INTERFACE);
		return false;
	}

	if (!l_dbus_register_interface(dbus, HWSIM_RULE_MANAGER_INTERFACE,
					setup_rule_manager_interface,
					NULL, false)) {
		l_error("Unable to register the %s interface",
			HWSIM_RULE_MANAGER_INTERFACE);
		return false;
	}

	if (!l_dbus_register_interface(dbus, HWSIM_RULE_INTERFACE,
					setup_rule_interface, NULL, false)) {
		l_error("Unable to register the %s interface",
			HWSIM_RULE_INTERFACE);
		return false;
	}

	if (!l_dbus_object_add_interface(dbus, "/",
						HWSIM_RADIO_MANAGER_INTERFACE,
						NULL)) {
		l_info("Unable to add the %s interface to /",
			HWSIM_RADIO_MANAGER_INTERFACE);
		return false;
	}

	if (!l_dbus_object_add_interface(dbus, "/",
						HWSIM_RULE_MANAGER_INTERFACE,
						NULL)) {
		l_info("Unable to add the %s interface to /",
			HWSIM_RULE_MANAGER_INTERFACE);
		return false;
	}

	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	return true;
}

static void register_callback(struct l_genl_msg *msg, void *user_data)
{
	int err = l_genl_msg_get_error(msg);

	if (err < 0) {
		l_error("HWSIM_CMD_REGISTER failed: %s (%d)",
			strerror(-err), -err);

		exit_status = EXIT_FAILURE;
		l_main_quit();
		return;
	}

	l_info("Registered as a transmission medium");
}

static void get_interface_done_initial(void *user_data)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(HWSIM_CMD_REGISTER, 4);
	l_genl_family_send(hwsim, msg, register_callback, NULL, NULL);
}

static void get_radio_done_initial(void *user_data)
{
	struct l_genl_msg *msg;

	/*
	 * Query interfaces now that we know we have all the radio data
	 * for radio lookups inside get_interface_callback, and we know
	 * nl80211_ready has already been called.
	 */
	msg = l_genl_msg_new(NL80211_CMD_GET_INTERFACE);
	if (!l_genl_family_dump(nl80211, msg, get_interface_callback,
				NULL, get_interface_done_initial)) {
		l_error("Getting nl80211 interface information failed");
		goto error;
	}

	if (!l_genl_family_register(nl80211, "config", nl80211_config_notify,
					NULL, NULL)) {
		l_error("Registering for nl80211 config notification "
			"failed");
		goto error;
	}

	rtnl = l_netlink_new(NETLINK_ROUTE);
	if (!rtnl) {
		l_error("Failed to open route netlink socket");
		goto error;
	}

	if (!l_netlink_register(rtnl, RTNLGRP_LINK,
				rtnl_link_notify, NULL, NULL)) {
		l_error("Failed to register for RTNL link notifications");
		goto error;
	}

	return;

error:
	exit_status = EXIT_FAILURE;
	l_main_quit();
}

static void hwsim_ready(void)
{
	struct l_genl_msg *msg;
	size_t msg_size;
	uint32_t radio_id;

	switch (action) {
	case ACTION_LIST:
		msg = l_genl_msg_new_sized(HWSIM_CMD_GET_RADIO,
					options ? 8 : 4);

		if (options) {
			radio_id = atoi(options);

			l_genl_msg_append_attr(msg, HWSIM_ATTR_RADIO_ID,
					4, &radio_id);
			l_genl_family_send(hwsim, msg, list_callback,
						NULL, list_callback_done);
		} else {
			l_genl_family_dump(hwsim, msg, list_callback,
						NULL, list_callback_done);
		}

		break;

	case ACTION_CREATE:
		msg_size = 0;

		if (radio_name_attr)
			msg_size += strlen(radio_name_attr) + 8;

		if (no_vif_attr)
			msg_size += 4;

		if (p2p_attr)
			msg_size += 4;

		msg = l_genl_msg_new_sized(HWSIM_CMD_NEW_RADIO, msg_size);

		if (radio_name_attr)
			l_genl_msg_append_attr(msg, HWSIM_ATTR_RADIO_NAME,
						strlen(radio_name_attr) + 1,
							radio_name_attr);

		if (no_vif_attr)
			l_genl_msg_append_attr(msg, HWSIM_ATTR_NO_VIF, 0, NULL);

		if (p2p_attr)
			l_genl_msg_append_attr(msg,
						HWSIM_ATTR_SUPPORT_P2P_DEVICE,
						0, NULL);

		if (hwsim_iftypes != HWSIM_DEFAULT_IFTYPES)
			l_genl_msg_append_attr(msg, HWSIM_ATTR_IFTYPE_SUPPORT,
						4, &hwsim_iftypes);

		if (hwsim_num_ciphers)
			l_genl_msg_append_attr(msg, HWSIM_ATTR_CIPHER_SUPPORT,
					sizeof(uint32_t) * hwsim_num_ciphers,
					hwsim_ciphers);

		l_genl_family_send(hwsim, msg, create_callback, NULL, NULL);

		break;

	case ACTION_DESTROY:
		radio_id = atoi(options);

		msg = l_genl_msg_new_sized(HWSIM_CMD_DEL_RADIO, 8);
		l_genl_msg_append_attr(msg, HWSIM_ATTR_RADIO_ID, 4, &radio_id);
		l_genl_family_send(hwsim, msg, destroy_callback, NULL, NULL);

		break;

	case ACTION_NONE:
		if (!setup_dbus_hwsim())
			goto error;

		if (!l_genl_family_register(hwsim, "config", hwsim_config,
						NULL, NULL)) {
			l_error("Failed to create hwsim config listener\n");
			goto error;
		}

		msg = l_genl_msg_new(HWSIM_CMD_GET_RADIO);
		if (!l_genl_family_dump(hwsim, msg, get_radio_callback,
					NULL, get_radio_done_initial)) {
			l_error("Getting hwsim radio information failed");
			goto error;
		}

		if (!l_genl_add_unicast_watch(genl, "MAC80211_HWSIM",
						unicast_handler, NULL, NULL)) {
			l_error("Failed to set unicast handler");
			goto error;
		}

		break;
	}

	return;

error:
	exit_status = EXIT_FAILURE;
	l_main_quit();
}

static void hwsim_disable_support(char *disable,
		const struct hwsim_support *map, uint32_t *mask)
{
	char **list = l_strsplit(disable, ',');
	char **iter = list;
	int i;

	while (*iter) {
		for (i = 0; map[i].name; i++) {
			if (!strcmp(map[i].name, *iter))
				*mask &= ~(map[i].value);
		}

		iter++;
	}

	l_strfreev(list);
}

static bool is_cipher_disabled(char *args, enum crypto_cipher cipher)
{
	char **list = l_strsplit(args, ',');
	char **iter = list;
	int i;

	while (*iter) {
		for (i = 0; cipher_map[i].name; i++) {
			if (!strcmp(*iter, cipher_map[i].name) &&
					cipher == cipher_map[i].value) {
				printf("disable cipher: %s\n", cipher_map[i].name);
				l_strfreev(list);
				return true;
			}
		}

		iter++;
	}

	l_strfreev(list);

	return false;
}

static void hwsim_disable_ciphers(char *disable)
{
	uint8_t i;

	for (i = 0; i < L_ARRAY_SIZE(hwsim_supported_ciphers); i++) {
		if (is_cipher_disabled(disable, hwsim_supported_ciphers[i]))
			continue;

		hwsim_ciphers[hwsim_num_ciphers] = hwsim_supported_ciphers[i];
		hwsim_num_ciphers++;
	}
}

static void family_discovered(const struct l_genl_family_info *info,
							void *user_data)
{
	if (!strcmp(l_genl_family_info_get_name(info), "MAC80211_HWSIM"))
		hwsim = l_genl_family_new(genl, "MAC80211_HWSIM");
	else if (!strcmp(l_genl_family_info_get_name(info), NL80211_GENL_NAME))
		nl80211 = l_genl_family_new(genl, NL80211_GENL_NAME);
}

static void discovery_done(void *user_data)
{
	if (!hwsim) {
		fprintf(stderr, "MAC80211_HWSIM doesn't exist.\n"
			"Load it manually using modprobe mac80211_hwsim\n");
		goto quit;
	}

	if (!nl80211) {
		fprintf(stderr, "nl80211 doesn't exist.\n"
			"Load it manually using modprobe cfg80211\n");
		goto quit;
	}

	hwsim_ready();

	return;

quit:
	exit_status = EXIT_FAILURE;
	l_main_quit();
}

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_main_quit();
		break;
	}
}

static void usage(void)
{
	printf("hwsim - Wireless simulator\n"
		"Usage:\n");
	printf("\thwsim [options]\n");
	printf("Options:\n"
		"\t-L, --list [id]        List simulated radios\n"
		"\t-C, --create           Create new simulated radio\n"
		"\t-D, --destroy <id>     Destroy existing radio\n"
		"\t-n, --name <name>      Name of a radio to be created\n"
		"\t-i, --nointerface      Do not create VIF\n"
		"\t-p, --p2p              Support P2P\n"
		"\t-t, --iftype-disable   List of disabled iftypes\n"
		"\t-c, --cipher-disable   List of disabled ciphers\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "list",	 optional_argument,	NULL, 'L' },
	{ "create",	 no_argument,		NULL, 'C' },
	{ "destroy",	 required_argument,	NULL, 'D' },
	{ "name",	 required_argument,	NULL, 'n' },
	{ "nointerface", no_argument,		NULL, 'i' },
	{ "p2p",	 no_argument,		NULL, 'p' },
	{ "version",	 no_argument,		NULL, 'v' },
	{ "iftype-disable", required_argument,	NULL, 't' },
	{ "cipher-disable", required_argument,	NULL, 'c' },
	{ "help",	 no_argument,		NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	int actions = 0;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, ":L:CD:kndetc:ipvh", main_options,
									NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case ':':
			if (optopt == 'L') {
				action = ACTION_LIST;
				actions++;
			} else {
				printf("option '-%c' requires an argument\n",
					optopt);
				return EXIT_FAILURE;
			}
			break;
		case 'L':
			action = ACTION_LIST;
			options = optarg;
			actions++;
			break;
		case 'C':
			action = ACTION_CREATE;
			actions++;
			break;
		case 'D':
			action = ACTION_DESTROY;
			options = optarg;
			actions++;
			break;
		case 'n':
			radio_name_attr = optarg;
			break;
		case 'i':
			no_vif_attr = true;
			break;
		case 'p':
			p2p_attr = true;
			break;
		case 't':
			hwsim_disable_support(optarg, iftype_map,
						&hwsim_iftypes);
			break;
		case 'c':
			hwsim_disable_ciphers(optarg);
			break;
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			printf("unrecognized argument '%s'\n",
				argv[optind - 1]);
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	if (actions > 1) {
		fprintf(stderr, "Only one action can be specified\n");
		return EXIT_FAILURE;
	}

	if (!l_main_init())
		return EXIT_FAILURE;

	l_log_set_stderr();
	exit_status = EXIT_FAILURE;

	printf("Wireless simulator ver %s\n", VERSION);

	genl = l_genl_new();
	if (!genl) {
		fprintf(stderr, "Failed to initialize generic netlink\n");
		goto done;
	}

	if (getenv("HWSIM_DEBUG"))
		l_genl_set_debug(genl, do_debug, "[GENL] ", NULL);

	if (!l_genl_discover_families(genl, family_discovered, NULL,
						discovery_done)) {
		fprintf(stderr, "Unable to start family discovery\n");
		l_genl_unref(genl);
		goto done;
	}

	exit_status = l_main_run_with_signal(signal_handler, NULL);

	l_genl_family_free(hwsim);
	l_genl_family_free(nl80211);
	l_genl_unref(genl);

	if (pending_create_msg)
		l_dbus_message_unref(pending_create_msg);

	l_dbus_destroy(dbus);
	hwsim_radio_cache_cleanup();
	l_queue_destroy(rules, l_free);

	l_netlink_destroy(rtnl);

done:
	l_main_exit();

	return exit_status;
}
