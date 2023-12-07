/*
 *
 *  Wireless daemon for Linux
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
#include <ctype.h>
#include <stdio.h>
#include <errno.h>

#include <ell/ell.h>

#include "src/dbus.h"
#include "src/simauth.h"
#include "src/module.h"
#include "src/iwd.h"

/*
 * This plugin takes care of all the communication with ofono in order to
 * provide the needed algorithms for EAP-SIM/AKA/AKA'. Once this plugin is
 * started it will start the initial "discovery" stage i.e.
 *
 * 1. Find ofono DBus service
 * 2. Find all modems (and listen for Added/Removed signal)
 * 3. For each modem see if SimAuthentication interface exists and get apps
 *    and NAI
 * 4. Create simauth provider for modem if the above succeeds
 *
 * These steps are chained, as to avoid the complexity of concurrent method
 * calls. Once the chain of methods has completed, a new simauth provider is
 * created for the modem. Only then will the EAP methods be able to run the
 * authentication algorithms ofono provides.
 *
 * If at any time the above conditions change e.g. SimAuthentication disappears,
 * ofono disappears, the modem simauth provider will unregister itself from
 * simauth, not allowing any future authentication algorithms to be run until
 * the start conditions are met again.
 */

#define OFONO_SIM_AUTHENTICATION_IFACE	"org.ofono.SimAuthentication"
#define OFONO_SIM_MANAGER_IFACE		"org.ofono.SimManager"
#define OFONO_MODEM_IFACE		"org.ofono.Modem"
#define OFONO_USIM_APPLICATION_IFACE	"org.ofono.USimApplication"
#define OFONO_ISIM_APPLICATION_IFACE	"org.ofono.ISimApplication"

struct sa_data {
	char *umts_app_path;
	char *ims_app_path;

	struct user_cb *pending;
	uint32_t serial;
};

struct ofono_modem {
	char *path;
	int props_watch;

	uint32_t props_serial;
	uint32_t apps_serial;

	bool sim_auth_found : 1;

	struct iwd_sim_auth *auth;
};

struct user_cb {
	void *cb;
	void *data;
	bool is_gsm : 1;
};

static uint32_t ofono_watch;
static uint32_t modem_add_watch;
static uint32_t modem_removed_watch;
static struct l_queue *modems;

static struct user_cb *new_cb(void *func, void *data, bool is_gsm)
{
	struct user_cb *cbd = l_new(struct user_cb, 1);

	cbd->cb = func;
	cbd->data = data;
	cbd->is_gsm = is_gsm;

	return cbd;
}

static void free_cb(void *ptr)
{
	struct sa_data *sa_data = ptr;

	l_free(sa_data->pending);
	sa_data->pending = NULL;
	sa_data->serial = 0;
}

/*
 * Copy a byte array ("ay") from array into buf
 */
static bool get_byte_array(struct l_dbus_message_iter *array, uint8_t *buf,
		int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (!l_dbus_message_iter_next_entry(array, buf + i))
			return false;
	}

	return true;
}

/*
 * Append a byte array ("ay") to a DBus message builder
 */
static bool append_byte_array(struct l_dbus_message_builder *builder,
		const uint8_t *data, int len)
{
	int i;

	if (!l_dbus_message_builder_enter_array(builder, "y"))
		return false;

	for (i = 0; i < len; i++)
		if (!l_dbus_message_builder_append_basic(builder, 'y',
				data + i))
			return false;

	if (!l_dbus_message_builder_leave_array(builder))
		return false;

	return true;
}

static void ims_auth_cb(struct l_dbus_message *reply, void *user_data)
{
	struct sa_data *sa_data = user_data;
	struct user_cb *cbd = sa_data->pending;
	sim_auth_check_milenage_cb_t cb = cbd->cb;
	struct l_dbus_message_iter properties;
	struct l_dbus_message_iter value;
	const char *prop;
	uint8_t res[8];
	uint8_t ck[16];
	uint8_t ik[16];
	uint8_t auts[16];

	if (l_dbus_message_is_error(reply)) {
		l_debug("ImsAuthenticate error");
		goto end;
	}

	if (!l_dbus_message_get_arguments(reply, "a{say}", &properties))
		goto end;

	while (l_dbus_message_iter_next_entry(&properties, &prop, &value)) {
		if (!strcmp(prop, "RES")) {
			if (!get_byte_array(&value, res, 8))
				goto end;
		} else if (!strcmp(prop, "CK")) {
			if (!get_byte_array(&value, ck, 16))
				goto end;
		} else if (!strcmp(prop, "IK")) {
			if (!get_byte_array(&value, ik, 16))
				goto end;
		} else if (!strcmp(prop, "AUTS")) {
			if (!get_byte_array(&value, auts, 14))
				goto end;

			cb(NULL, NULL, NULL, auts, cbd->data);

			return;
		}
	}

	cb(res, ck, ik, NULL, cbd->data);

	return;

end:
	cb(NULL, NULL, NULL, NULL, cbd->data);
}

static void gsm_auth_cb(struct l_dbus_message *reply, void *user_data)
{
	struct sa_data *sa_data = user_data;
	struct user_cb *cbd = sa_data->pending;
	sim_auth_run_gsm_cb_t cb = cbd->cb;
	struct l_dbus_message_iter array;
	struct l_dbus_message_iter val;
	struct l_dbus_message_iter dict;
	const char *prop;
	int sres_pos = 0;
	int kc_pos = 0;
	uint8_t kc[NUM_RANDS_MAX][EAP_SIM_KC_LEN];
	uint8_t sres[NUM_RANDS_MAX][EAP_SIM_SRES_LEN];

	if (l_dbus_message_is_error(reply)) {
		l_debug("GsmAuthenticate error");
		goto end;
	}

	if (!l_dbus_message_get_arguments(reply, "aa{say}", &array))
		goto end;

	while (l_dbus_message_iter_next_entry(&array, &dict)) {
		while (l_dbus_message_iter_next_entry(&dict, &prop, &val)) {
			if (sres_pos > NUM_RANDS_MAX || kc_pos > NUM_RANDS_MAX)
				goto end;

			if (!strcmp(prop, "SRES")) {
				if (!get_byte_array(&val, sres[sres_pos++],
						EAP_SIM_SRES_LEN))
					goto end;
			} else if (!strcmp(prop, "Kc")) {
				if (!get_byte_array(&val, kc[kc_pos++],
						EAP_SIM_KC_LEN))
					goto end;
			}
		}
	}

	cb((const uint8_t *)sres, (const uint8_t *)kc, cbd->data);

	return;

end:
	cb(NULL, NULL, cbd->data);
}

static int ofono_sim_auth_run_gsm(struct iwd_sim_auth *auth,
		const uint8_t *rands, int num_rands, sim_auth_run_gsm_cb_t cb,
		void *data)
{
	struct sa_data *sa_data = iwd_sim_auth_get_data(auth);
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *message;
	struct l_dbus_message_builder *builder;
	int i;

	if (num_rands > NUM_RANDS_MAX) {
		l_debug("Max number of RAND's is %d", NUM_RANDS_MAX);
		return -EINVAL;
	}

	if (sa_data->pending) {
		l_debug("Modem already has outstanding auth request");
		return -EBUSY;
	}

	sa_data->pending = new_cb(cb, data, true);

	message = l_dbus_message_new_method_call(dbus, "org.ofono",
			sa_data->umts_app_path, OFONO_USIM_APPLICATION_IFACE,
			"GsmAuthenticate");

	builder = l_dbus_message_builder_new(message);

	if (!l_dbus_message_builder_enter_array(builder, "ay"))
		goto error;

	for (i = 0; i < num_rands; i++) {
		if (!append_byte_array(builder, rands + (i * 16), 16))
			goto error;
	}

	if (!l_dbus_message_builder_leave_array(builder))
		goto error;

	if (!l_dbus_message_builder_finalize(builder))
		goto error;

	sa_data->serial = l_dbus_send_with_reply(dbus, message, gsm_auth_cb,
			sa_data, free_cb);
	if (!sa_data->serial)
		goto error;

	l_dbus_message_builder_destroy(builder);

	return 0;

error:
	l_dbus_message_builder_destroy(builder);
	l_free(sa_data->pending);
	sa_data->pending = NULL;

	return -EIO;
}

static int ofono_sim_auth_check_milenage(struct iwd_sim_auth *auth,
		const uint8_t *rand, const uint8_t *autn,
		sim_auth_check_milenage_cb_t cb, void *data)
{
	struct sa_data *sa_data = iwd_sim_auth_get_data(auth);
	const char *iface = OFONO_ISIM_APPLICATION_IFACE;
	const char *method = "ImsAuthenticate";
	const char *path;
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *message;
	struct l_dbus_message_builder *builder;

	if (sa_data->pending) {
		l_debug("Modem already has outstanding auth request");
		return -EBUSY;
	}

	sa_data->pending = new_cb(cb, data, false);

	/*
	 * If ISIM is not available, run on USIM application
	 */
	if (!sa_data->ims_app_path && sa_data->umts_app_path) {
		iface = OFONO_USIM_APPLICATION_IFACE;
		method = "UmtsAuthenticate";
		path = sa_data->umts_app_path;
	} else {
		path = sa_data->ims_app_path;
	}

	message = l_dbus_message_new_method_call(dbus, "org.ofono", path,
			iface, method);

	builder = l_dbus_message_builder_new(message);

	if (!append_byte_array(builder, rand, 16))
		goto error;

	if (!append_byte_array(builder, autn, 16))
		goto error;

	if (!l_dbus_message_builder_finalize(builder))
		goto error;

	sa_data->serial = l_dbus_send_with_reply(dbus, message, ims_auth_cb,
			sa_data, free_cb);
	if (!sa_data->serial)
		goto error;

	l_dbus_message_builder_destroy(builder);

	return 0;

error:
	l_dbus_message_builder_destroy(builder);
	l_free(sa_data->pending);
	sa_data->pending = NULL;

	return -EIO;
}

static void ofono_sim_auth_cancel_request(struct iwd_sim_auth *auth, int id)
{
	struct sa_data *sa_data = iwd_sim_auth_get_data(auth);

	if (sa_data->pending) {
		l_dbus_cancel(dbus_get_bus(), sa_data->serial);
		sa_data->pending = NULL;
	}
}

static void ofono_sim_auth_remove(struct iwd_sim_auth *auth)
{
	struct sa_data *sa_data = iwd_sim_auth_get_data(auth);

	l_debug("removing auth data %p", sa_data);

	if (sa_data->pending) {
		struct user_cb *cbd = sa_data->pending;

		if (cbd->is_gsm) {
			sim_auth_run_gsm_cb_t cb = cbd->cb;

			cb(NULL, NULL, cbd->data);
		} else {
			sim_auth_check_milenage_cb_t cb = cbd->cb;

			cb(NULL, NULL, NULL, NULL, cbd->data);
		}

		l_dbus_cancel(dbus_get_bus(), sa_data->serial);
	}

	l_free(sa_data->ims_app_path);
	l_free(sa_data->umts_app_path);
	l_free(sa_data);
}

static struct iwd_sim_auth_driver ofono_driver = {
		.name = "oFono SimAuth driver",
		.check_milenage = ofono_sim_auth_check_milenage,
		.run_gsm = ofono_sim_auth_run_gsm,
		.cancel_request = ofono_sim_auth_cancel_request,
		.remove = ofono_sim_auth_remove
};

static void modem_destroy(void *data)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct ofono_modem *modem = data;

	if (modem->auth) {
		/*
		 * If an auth instance has been created, simauth will call
		 * the driver's remove which cleanups the sa_data object
		 */
		iwd_sim_auth_remove(modem->auth);
	}

	l_debug("removing modem %s", modem->path);

	if (modem->apps_serial)
		l_dbus_cancel(dbus, modem->apps_serial);

	if (modem->props_serial)
		l_dbus_cancel(dbus, modem->props_serial);

	l_free(modem->path);
	l_dbus_remove_watch(dbus, modem->props_watch);
	l_free(modem);
}

static void get_auth_apps_cb(struct l_dbus_message *reply,
		void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct sa_data *sa_data = iwd_sim_auth_get_data(modem->auth);
	struct l_dbus_message_iter array;
	struct l_dbus_message_iter dict;
	struct l_dbus_message_iter variant;
	bool sim_supported = false;
	bool aka_supported = false;

	const char *path;

	modem->apps_serial = 0;

	if (l_dbus_message_is_error(reply)) {
		l_debug("GetApplications error");
		goto error;
	}

	if (!l_dbus_message_get_arguments(reply, "a{oa{sv}}", &array))
		goto error;

	while (l_dbus_message_iter_next_entry(&array, &path, &dict)) {
		const char *type;
		const char *label;
		const char *key;

		while (l_dbus_message_iter_next_entry(&dict, &key, &variant)) {
			if (strcmp(key, "Type"))
				continue;

			if (!l_dbus_message_iter_get_variant(&variant, "s",
					&type, &label))
				goto error;

			if (!strcmp(type, "Umts")) {
				sa_data->umts_app_path = l_strdup(path);
				sim_supported = true;
				aka_supported = true;
			} else if (!strcmp(type, "Ims")) {
				sa_data->ims_app_path = l_strdup(path);
				aka_supported = true;
			}
		}
	}

	if (sa_data->umts_app_path || sa_data->ims_app_path) {
		iwd_sim_auth_set_capabilities(modem->auth, sim_supported,
				aka_supported);

		iwd_sim_auth_register(modem->auth);

		l_debug("modem %s successfully loaded, sim=%u, aka=%u",
				modem->path, sim_supported, aka_supported);
		return;
	}

	/* non supported type */
	l_debug("unsupported modem auth capabilities");

error:
	iwd_sim_auth_remove(modem->auth);
}

static void get_applications(struct ofono_modem *modem)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *message;

	message = l_dbus_message_new_method_call(dbus,
			"org.ofono", modem->path,
			OFONO_SIM_AUTHENTICATION_IFACE,
			"GetApplications");

	l_dbus_message_set_arguments(message, "");

	modem->apps_serial = l_dbus_send_with_reply(dbus, message,
			get_auth_apps_cb, modem, NULL);
}

static void get_auth_props_cb(struct l_dbus_message *reply,
		void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct l_dbus_message_iter array;
	struct l_dbus_message_iter variant;
	const char *key;

	modem->props_serial = 0;

	if (l_dbus_message_is_error(reply)) {
		l_debug("GetProperties error");
		goto error;
	}

	if (!l_dbus_message_get_arguments(reply, "a{sv}", &array))
		goto error;

	while (l_dbus_message_iter_next_entry(&array, &key, &variant)) {
		if (!strcmp(key, "NetworkAccessIdentity")) {
			struct sa_data *sa_data;
			const char *id;

			if (!l_dbus_message_iter_get_variant(&variant,
					"s", &id))
				goto error;

			modem->auth = iwd_sim_auth_create(&ofono_driver);

			sa_data = l_new(struct sa_data, 1);

			iwd_sim_auth_set_data(modem->auth, sa_data);
			iwd_sim_auth_set_nai(modem->auth, id);

			get_applications(modem);

			return;
		}
	}

error:
	if (modem->auth)
		iwd_sim_auth_remove(modem->auth);
}

static void get_properties(struct ofono_modem *modem)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *message;

	message = l_dbus_message_new_method_call(dbus,
			"org.ofono", modem->path,
			OFONO_SIM_AUTHENTICATION_IFACE,
			"GetProperties");

	l_dbus_message_set_arguments(message, "");

	modem->props_serial = l_dbus_send_with_reply(dbus, message,
			get_auth_props_cb, modem, NULL);
}

static void parse_interfaces(struct l_dbus_message_iter *prop,
		struct ofono_modem *modem)
{
	struct l_dbus_message_iter ifaces;
	const char *str;

	if (!l_dbus_message_iter_get_variant(prop, "as", &ifaces)) {
		l_warn("error parsing modem %s interfaces", modem->path);
		return;
	}

	while (l_dbus_message_iter_next_entry(&ifaces, &str)) {
		if (!strcmp(OFONO_SIM_AUTHENTICATION_IFACE, str)) {
			if (modem->sim_auth_found)
				return;

			modem->sim_auth_found = true;

			get_properties(modem);

			return;
		}
	}

	/* SimAuthentication disappeared */
	if (modem->sim_auth_found) {
		/* Remove auth provider, this will free the sa_data object */
		if (modem->auth)
			iwd_sim_auth_remove(modem->auth);

		/* put modem back into a 'discovery' state */
		modem->sim_auth_found = false;
	}
}

static void interfaces_changed_cb(struct l_dbus_message *message,
		void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct l_dbus_message_iter value;
	const char *key;

	if (!l_dbus_message_get_arguments(message, "sv", &key, &value))
		return;

	if (!strcmp(key, "Interfaces"))
		parse_interfaces(&value, modem);
}

static bool match_modem_by_path(const void *a, const void *b)
{
	struct ofono_modem *modem = (struct ofono_modem *)a;

	if (strcmp(modem->path, (const char *)b))
		return false;

	return true;
}

static void parse_modem(const char *path, struct l_dbus_message_iter *props)
{
	struct l_dbus_message_iter value;
	const char *key;
	struct ofono_modem *modem;

	l_debug("modem found: %s", path);

	if (l_queue_find(modems, match_modem_by_path, path)) {
		/* should never happen */
		l_error("modem %s already found", path);

		return;
	}

	modem = l_new(struct ofono_modem, 1);
	modem->path = l_strdup(path);

	while (l_dbus_message_iter_next_entry(props, &key, &value)) {
		if (!strcmp(key, "Interfaces"))
			parse_interfaces(&value, modem);
	}

	/*
	 * add watch in case SimAuthentication goes away
	 */
	modem->props_watch = l_dbus_add_signal_watch(dbus_get_bus(),
			"org.ofono", path, OFONO_MODEM_IFACE,
			"PropertyChanged", L_DBUS_MATCH_ARGUMENT(0),
			"Interfaces", L_DBUS_MATCH_NONE,
			interfaces_changed_cb, modem);

	l_queue_push_tail(modems, modem);
}

static void modem_added_cb(struct l_dbus_message *message, void *user_data)
{
	struct l_dbus_message_iter props;
	const char *path;

	l_debug("");

	if (!l_dbus_message_get_arguments(message, "oa{sv}", &path, &props))
		return;

	parse_modem(path, &props);
}

static void modem_removed_cb(struct l_dbus_message *message, void *user_data)
{
	const char *path;
	struct ofono_modem *modem;

	if (!l_dbus_message_get_arguments(message, "o", &path))
		return;

	modem = l_queue_remove_if(modems, match_modem_by_path, path);
	if (!modem) {
		l_warn("Cannot remove modem %s, not found", path);
		return;
	}

	modem_destroy(modem);
}

static void get_modems_cb(struct l_dbus_message *reply, void *user_data)
{
	struct l_dbus_message_iter props;
	struct l_dbus_message_iter modem_list;
	const char *path = NULL;

	if (l_dbus_message_is_error(reply)) {
		l_debug("Error discovering modems");
		return;
	}

	modems = l_queue_new();

	if (l_dbus_message_get_arguments(reply, "a(oa{sv})", &modem_list)) {
		while (l_dbus_message_iter_next_entry(&modem_list, &path,
									&props))
			parse_modem(path, &props);
	}

	/* watch for modems being added/removed */
	modem_add_watch = l_dbus_add_signal_watch(dbus_get_bus(),
			"org.ofono", "/", "org.ofono.Manager", "ModemAdded",
			L_DBUS_MATCH_NONE, modem_added_cb, NULL);

	modem_removed_watch = l_dbus_add_signal_watch(dbus_get_bus(),
			"org.ofono", "/", "org.ofono.Manager", "ModemRemoved",
			L_DBUS_MATCH_NONE, modem_removed_cb, NULL);
}

static void ofono_found(struct l_dbus *dbus, void *user_data)
{
	struct l_dbus_message *message;

	l_debug("");

	/* start by getting all current modems */
	message = l_dbus_message_new_method_call(dbus, "org.ofono", "/",
			"org.ofono.Manager", "GetModems");

	l_dbus_message_set_arguments(message, "");

	l_dbus_send_with_reply(dbus, message, get_modems_cb, NULL, NULL);
}

static void ofono_disappeared(struct l_dbus *dbus, void *user_data)
{
	l_debug("");

	if (modems) {
		l_queue_destroy(modems, modem_destroy);
		modems = NULL;

		l_dbus_remove_watch(dbus, modem_add_watch);
		l_dbus_remove_watch(dbus, modem_removed_watch);
	}
}

static int ofono_init(void)
{
	struct l_dbus *dbus = dbus_get_bus();

	ofono_watch = l_dbus_add_service_watch(dbus, "org.ofono", ofono_found,
			ofono_disappeared, NULL, NULL);

	return 0;
}

static void ofono_exit(void)
{
	struct l_dbus *dbus = dbus_get_bus();

	if (modems)
		ofono_disappeared(dbus, NULL);

	l_dbus_remove_watch(dbus, ofono_watch);
}

IWD_MODULE(ofono, ofono_init, ofono_exit);
IWD_MODULE_DEPENDS(ofono, simauth);
