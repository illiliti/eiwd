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

#include <errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/module.h"
#include "src/dbus.h"
#include "src/netconfig.h"
#include "src/resolve.h"

struct resolve_ops {
	void (*set_dns)(struct resolve *resolve, char **dns_list);
	void (*set_domains)(struct resolve *resolve, char **domain_list);
	void (*set_mdns)(struct resolve *resolve, const char *mdns);
	void (*revert)(struct resolve *resolve);
	void (*destroy)(struct resolve *resolve);
};

struct resolve {
	const struct resolve_ops *ops;
	uint32_t ifindex;
};

static inline void _resolve_init(struct resolve *resolve, uint32_t ifindex,
					const struct resolve_ops *ops)
{
	resolve->ifindex = ifindex;
	resolve->ops = ops;
}

void resolve_set_dns(struct resolve *resolve, char **dns_list)
{
	if (!dns_list || !*dns_list)
		return;

	if (!resolve->ops->set_dns)
		return;

	resolve->ops->set_dns(resolve, dns_list);
}

void resolve_set_domains(struct resolve *resolve, char **domain_list)
{
	if (!domain_list)
		return;

	if (!resolve->ops->set_domains)
		return;

	resolve->ops->set_domains(resolve, domain_list);
}

void resolve_set_mdns(struct resolve *resolve, const char *mdns)
{
	if (!mdns)
		return;

	if (!resolve->ops->set_mdns)
		return;

	resolve->ops->set_mdns(resolve, mdns);
}

void resolve_revert(struct resolve *resolve)
{
	if (!resolve->ops->revert)
		return;

	resolve->ops->revert(resolve);
}

void resolve_free(struct resolve *resolve)
{
	resolve->ops->destroy(resolve);
}

struct resolve_method_ops {
	int (*init)(void);
	void (*exit)(void);
	struct resolve *(*alloc)(uint32_t ifindex);
};

#define SYSTEMD_RESOLVED_SERVICE           "org.freedesktop.resolve1"
#define SYSTEMD_RESOLVED_MANAGER_PATH      "/org/freedesktop/resolve1"
#define SYSTEMD_RESOLVED_MANAGER_INTERFACE "org.freedesktop.resolve1.Manager"

struct systemd_method_state {
	uint32_t service_watch;
	bool is_ready:1;
};

struct systemd_method_state systemd_state;

struct systemd {
	struct resolve super;
};

static void systemd_link_generic_reply(struct l_dbus_message *message,
								void *user_data)
{
	const char *type = user_data;
	const char *name;
	const char *text;

	if (!l_dbus_message_get_error(message, &name, &text))
		return;

	l_error("resolve-systemd: Failed to modify the %s entries. %s: %s",
							type, name, text);
}

static bool systemd_builder_add_dns(struct l_dbus_message_builder *builder,
							const char *dns)
{
	uint8_t buf[16];
	uint8_t buf_size;
	uint8_t i;
	int t;

	l_debug("installing DNS: %s", dns);

	if (inet_pton(AF_INET, dns, buf) == 1) {
		t = AF_INET;
		buf_size = 4;
	} else if (inet_pton(AF_INET6, dns, buf) == 1) {
		t = AF_INET6;
		buf_size = 16;
	} else
		return false;

	l_dbus_message_builder_append_basic(builder, 'i', &t);
	l_dbus_message_builder_enter_array(builder, "y");

	for (i = 0; i < buf_size; i++)
		l_dbus_message_builder_append_basic(builder, 'y', &buf[i]);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static void resolve_systemd_set_dns(struct resolve *resolve, char **dns_list)
{
	struct l_dbus_message_builder *builder;
	struct l_dbus_message *message;

	l_debug("ifindex: %u", resolve->ifindex);

	if (L_WARN_ON(!systemd_state.is_ready))
		return;

	message = l_dbus_message_new_method_call(dbus_get_bus(),
					SYSTEMD_RESOLVED_SERVICE,
					SYSTEMD_RESOLVED_MANAGER_PATH,
					SYSTEMD_RESOLVED_MANAGER_INTERFACE,
					"SetLinkDNS");

	if (!message)
		return;

	builder = l_dbus_message_builder_new(message);
	if (!builder) {
		l_dbus_message_unref(message);
		return;
	}

	l_dbus_message_builder_append_basic(builder, 'i', &resolve->ifindex);

	l_dbus_message_builder_enter_array(builder, "(iay)");

	for (; *dns_list; dns_list++) {
		l_dbus_message_builder_enter_struct(builder, "iay");

		if (systemd_builder_add_dns(builder, *dns_list)) {
			l_dbus_message_builder_leave_struct(builder);
			continue;
		}

		l_dbus_message_builder_destroy(builder);
		l_dbus_message_unref(message);

		return;
	}

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	l_dbus_send_with_reply(dbus_get_bus(), message,
				systemd_link_generic_reply, "DNS", NULL);
}

static void resolve_systemd_set_domains(struct resolve *resolve,
						char **domain_list)
{
	struct l_dbus_message *message;
	struct l_dbus_message_builder *builder;
	bool f = false;

	l_debug("ifindex: %u", resolve->ifindex);

	if (L_WARN_ON(!systemd_state.is_ready))
		return;

	message = l_dbus_message_new_method_call(dbus_get_bus(),
					SYSTEMD_RESOLVED_SERVICE,
					SYSTEMD_RESOLVED_MANAGER_PATH,
					SYSTEMD_RESOLVED_MANAGER_INTERFACE,
					"SetLinkDomains");

	if (!message)
		return;

	builder = l_dbus_message_builder_new(message);
	if (!builder) {
		l_dbus_message_unref(message);
		return;
	}

	l_dbus_message_builder_append_basic(builder, 'i', &resolve->ifindex);
	l_dbus_message_builder_enter_array(builder, "(sb)");

	for (; *domain_list; domain_list++) {
		l_dbus_message_builder_enter_struct(builder, "sb");
		l_dbus_message_builder_append_basic(builder, 's', *domain_list);
		l_dbus_message_builder_append_basic(builder, 'b', &f);
		l_dbus_message_builder_leave_struct(builder);
	}

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	l_dbus_send_with_reply(dbus_get_bus(), message,
				systemd_link_generic_reply, "domains", NULL);
}

static void resolve_systemd_set_mdns(struct resolve *resolve, const char *mdns)
{
	struct l_dbus_message *message;

	l_debug("ifindex: %u", resolve->ifindex);

	if (L_WARN_ON(!systemd_state.is_ready))
		return;

	message = l_dbus_message_new_method_call(dbus_get_bus(),
					SYSTEMD_RESOLVED_SERVICE,
					SYSTEMD_RESOLVED_MANAGER_PATH,
					SYSTEMD_RESOLVED_MANAGER_INTERFACE,
					"SetLinkMulticastDNS");

	if (!message)
		return;

	l_dbus_message_set_arguments(message, "is", resolve->ifindex, mdns);
	l_dbus_send_with_reply(dbus_get_bus(), message,
				systemd_link_generic_reply,
				"MulticastDNS", NULL);
}

static void resolve_systemd_revert(struct resolve *resolve)
{
	struct l_dbus_message *message;

	l_debug("ifindex: %u", resolve->ifindex);

	if (L_WARN_ON(!systemd_state.is_ready))
		return;

	message = l_dbus_message_new_method_call(dbus_get_bus(),
					SYSTEMD_RESOLVED_SERVICE,
					SYSTEMD_RESOLVED_MANAGER_PATH,
					SYSTEMD_RESOLVED_MANAGER_INTERFACE,
					"RevertLink");
	if (!message)
		return;

	l_dbus_message_set_arguments(message, "i", resolve->ifindex);
	l_dbus_send_with_reply(dbus_get_bus(), message,
				systemd_link_generic_reply, "DNS", NULL);
}

static void resolve_systemd_destroy(struct resolve *resolve)
{
	struct systemd *sd = l_container_of(resolve, struct systemd, super);

	l_free(sd);
}

static const struct resolve_ops systemd_ops = {
	.set_dns = resolve_systemd_set_dns,
	.set_domains = resolve_systemd_set_domains,
	.set_mdns = resolve_systemd_set_mdns,
	.revert = resolve_systemd_revert,
	.destroy = resolve_systemd_destroy,
};

static void systemd_appeared(struct l_dbus *dbus, void *user_data)
{
	systemd_state.is_ready = true;
}

static void systemd_disappeared(struct l_dbus *dbus, void *user_data)
{
	systemd_state.is_ready = false;
}

static int resolve_systemd_init(void)
{
	systemd_state.service_watch =
				l_dbus_add_service_watch(dbus_get_bus(),
						SYSTEMD_RESOLVED_SERVICE,
						systemd_appeared,
						systemd_disappeared,
						NULL, NULL);

	return 0;
}

static void resolve_systemd_exit(void)
{
	l_dbus_remove_watch(dbus_get_bus(), systemd_state.service_watch);
	memset(&systemd_state, 0, sizeof(systemd_state));
}

static struct resolve *resolve_systemd_alloc(uint32_t ifindex)
{
	struct systemd *sd = l_new(struct systemd, 1);

	_resolve_init(&sd->super, ifindex, &systemd_ops);

	return &sd->super;
}

static const struct resolve_method_ops resolve_method_systemd_ops = {
	.init = resolve_systemd_init,
	.exit = resolve_systemd_exit,
	.alloc = resolve_systemd_alloc,
};

char *resolvconf_path;

static bool resolvconf_invoke(const char *ifname, const char *type,
						const char *content)
{
	FILE *resolvconf;
	L_AUTO_FREE_VAR(char *, cmd) = NULL;
	int error;

	if (content) {
		cmd = l_strdup_printf("%s -a %s.%s", resolvconf_path,
						ifname, type);
		resolvconf = popen(cmd, "w");
	} else {
		cmd = l_strdup_printf("%s -d %s.%s", resolvconf_path,
						ifname, type);
		resolvconf = popen(cmd, "r");
	}

	if (!resolvconf) {
		l_error("resolve: Failed to start %s (%s).", resolvconf_path,
							strerror(errno));
		return false;
	}

	if (content && fprintf(resolvconf, "%s", content) < 0)
		l_error("resolve: Failed to print into %s stdin.",
							resolvconf_path);

	error = pclose(resolvconf);
	if (error < 0)
		l_error("resolve: Failed to close pipe to %s (%s).",
					resolvconf_path, strerror(errno));
	else if (error > 0)
		l_info("resolve: %s exited with status (%d).", resolvconf_path,
									error);

	return !error;
}

struct resolvconf {
	struct resolve super;
	bool have_domain : 1;
	bool have_dns : 1;
	char *ifname;
};

static void resolve_resolvconf_set_dns(struct resolve *resolve, char **dns_list)
{
	struct resolvconf *rc =
			l_container_of(resolve, struct resolvconf, super);
	struct l_string *content;
	L_AUTO_FREE_VAR(char *, str) = NULL;

	if (L_WARN_ON(!resolvconf_path))
		return;

	if (!dns_list || !dns_list[0]) {
		if (rc->have_dns)
			resolvconf_invoke(rc->ifname, "dns", NULL);

		rc->have_dns = false;
		return;
	}

	content = l_string_new(0);

	for (; *dns_list; dns_list++)
		l_string_append_printf(content, "nameserver %s\n", *dns_list);

	str = l_string_unwrap(content);

	if (resolvconf_invoke(rc->ifname, "dns", str))
		rc->have_dns = true;
}

static void resolve_resolvconf_set_domains(struct resolve *resolve,
							char **domain_list)
{
	struct resolvconf *rc =
			l_container_of(resolve, struct resolvconf, super);
	struct l_string *content;
	L_AUTO_FREE_VAR(char *, str) = NULL;

	if (L_WARN_ON(!resolvconf_path))
		return;

	if (!domain_list || !domain_list[0]) {
		if (rc->have_domain)
			resolvconf_invoke(rc->ifname, "domain", NULL);

		rc->have_domain = false;
		return;
	}

	content = l_string_new(0);

	for (; *domain_list; domain_list++)
		l_string_append_printf(content, "search %s\n", *domain_list);

	str = l_string_unwrap(content);

	if (resolvconf_invoke(rc->ifname, "domain", str))
		rc->have_domain = true;
}

static void resolve_resolvconf_revert(struct resolve *resolve)
{
	struct resolvconf *rc =
			l_container_of(resolve, struct resolvconf, super);

	if (rc->have_dns)
		resolvconf_invoke(rc->ifname, "dns", NULL);

	if (rc->have_domain)
		resolvconf_invoke(rc->ifname, "domain", NULL);

	rc->have_dns = false;
	rc->have_domain = false;
}

static void resolve_resolvconf_destroy(struct resolve *resolve)
{
	struct resolvconf *rc =
			l_container_of(resolve, struct resolvconf, super);

	l_free(rc->ifname);
	l_free(rc);
}

static struct resolve_ops resolvconf_ops = {
	.set_dns = resolve_resolvconf_set_dns,
	.set_domains = resolve_resolvconf_set_domains,
	.revert = resolve_resolvconf_revert,
	.destroy = resolve_resolvconf_destroy,
};

static int resolve_resolvconf_init(void)
{
	static const char *default_path = "/sbin:/usr/sbin";
	const char *path;

	l_debug("Trying to find resolvconf in $PATH");

	path = getenv("PATH");
	if (path)
		resolvconf_path = l_path_find("resolvconf", path, X_OK);

	if (!resolvconf_path) {
		l_debug("Trying to find resolvconf in default paths");
		resolvconf_path = l_path_find("resolvconf", default_path, X_OK);
	}

	if (!resolvconf_path) {
		l_error("No usable resolvconf found on system");
		/* return -ENOENT; */
		return 0;
	}

	l_debug("resolvconf found as: %s", resolvconf_path);
	return 0;
}

static void resolve_resolvconf_exit(void)
{
	l_free(resolvconf_path);
	resolvconf_path = NULL;
}

static struct resolve *resolve_resolvconf_alloc(uint32_t ifindex)
{
	struct resolvconf *rc = l_new(struct resolvconf, 1);

	_resolve_init(&rc->super, ifindex, &resolvconf_ops);

	rc->ifname = l_net_get_name(ifindex);
	if (!rc->ifname)
		rc->ifname = l_strdup_printf("%u", ifindex);

	return &rc->super;
}

static const struct resolve_method_ops resolve_method_resolvconf_ops = {
	.init = resolve_resolvconf_init,
	.exit = resolve_resolvconf_exit,
	.alloc = resolve_resolvconf_alloc,
};

static void resolve_none_destroy(struct resolve *resolve)
{
	l_free(resolve);
}

static struct resolve_ops none_ops = {
	.destroy = resolve_none_destroy,
};

static int resolve_none_init(void)
{
	return 0;
}

static void resolve_none_exit(void)
{
}

static struct resolve *resolve_none_alloc(uint32_t ifindex)
{
	struct resolve *r = l_new(struct resolve, 1);

	_resolve_init(r, ifindex, &none_ops);
	return r;
}

static const struct resolve_method_ops resolve_method_none_ops = {
	.init = resolve_none_init,
	.exit = resolve_none_exit,
	.alloc = resolve_none_alloc,
};

static const struct resolve_method_ops *configured_method;

struct resolve *resolve_new(uint32_t ifindex)
{
	if (L_WARN_ON(!configured_method))
		return NULL;

	return configured_method->alloc(ifindex);
}

static const struct {
	const char *name;
	const struct resolve_method_ops *method_ops;
} resolve_method_ops_list[] = {
#ifdef HAVE_DBUS
	{ "systemd", &resolve_method_systemd_ops },
#endif
	{ "resolvconf", &resolve_method_resolvconf_ops },
	{ "none", &resolve_method_none_ops },
	{ }
};

static int resolve_init(void)
{
	const char *method_name;
	uint8_t i;

	if (!netconfig_enabled())
		return 0;

	method_name = l_settings_get_value(iwd_get_config(), "Network",
						"NameResolvingService");
	if (!method_name)
		method_name = "resolvconf";

	for (i = 0; resolve_method_ops_list[i].name; i++) {
		if (strcmp(resolve_method_ops_list[i].name, method_name))
			continue;

		configured_method = resolve_method_ops_list[i].method_ops;
		break;
	}

	if (!configured_method) {
		l_error("Unknown resolution method: %s", method_name);
		return -EINVAL;
	}

	return configured_method->init();
}

static void resolve_exit(void)
{
	if (!configured_method)
		return;

	configured_method->exit();
	configured_method = NULL;
}

IWD_MODULE(resolve, resolve_init, resolve_exit)
