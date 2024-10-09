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

#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <ell/ell.h>

#include "src/agent.h"
#include "src/iwd.h"
#include "src/dbus.h"

static struct l_dbus *g_dbus = NULL;

struct l_dbus_message *dbus_error_busy(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".InProgress",
					"Operation already in progress");
}

struct l_dbus_message *dbus_error_failed(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".Failed",
					"Operation failed");
}

struct l_dbus_message *dbus_error_aborted(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".Aborted",
					"Operation aborted");
}

struct l_dbus_message *dbus_error_not_available(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".NotAvailable",
					"Operation not available");
}

struct l_dbus_message *dbus_error_invalid_args(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".InvalidArguments",
					"Argument type is wrong");
}

struct l_dbus_message *dbus_error_invalid_format(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".InvalidFormat",
					"Argument format is invalid");
}

struct l_dbus_message *dbus_error_already_exists(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".AlreadyExists",
					"Object already exists");
}

struct l_dbus_message *dbus_error_not_found(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".NotFound",
					"Object not found");
}

struct l_dbus_message *dbus_error_not_supported(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".NotSupported",
					"Operation not supported");
}

struct l_dbus_message *dbus_error_no_agent(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".NoAgent",
					"No Agent registered");
}

struct l_dbus_message *dbus_error_not_connected(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".NotConnected",
					"Not connected");
}

struct l_dbus_message *dbus_error_not_configured(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".NotConfigured",
					"Not configured");
}

struct l_dbus_message *dbus_error_not_implemented(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".NotImplemented",
					"Not implemented");
}

struct l_dbus_message *dbus_error_service_set_overlap(
						struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".ServiceSetOverlap",
					"Service set overlap");
}

struct l_dbus_message *dbus_error_already_provisioned(
						struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".AlreadyProvisioned",
					"Already provisioned");
}

struct l_dbus_message *dbus_error_not_hidden(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".NotHidden",
					"Not hidden");
}

struct l_dbus_message *dbus_error_permission_denied(struct l_dbus_message *msg)
{
	return l_dbus_message_new_error(msg, IWD_SERVICE ".PermissionDenied",
					"Permission Denied");
}

struct l_dbus_message *dbus_error_from_errno(int err,
						struct l_dbus_message *msg)
{
	switch (err) {
	case -EBUSY:
		return dbus_error_busy(msg);
	case -ECANCELED:
		return dbus_error_aborted(msg);
	case -ERFKILL:
		return dbus_error_not_available(msg);
	case -EINVAL:
		return dbus_error_invalid_args(msg);
	case -EBADMSG:
		return dbus_error_invalid_format(msg);
	case -EEXIST:
		return dbus_error_already_exists(msg);
	case -ENOENT:
		return dbus_error_not_found(msg);
	case -ENOTSUP:
		return dbus_error_not_supported(msg);
	/* TODO: no_agent */
	case -ENOKEY:
		return dbus_error_not_configured(msg);
	case -ENOTCONN:
		return dbus_error_not_connected(msg);
	case -ENOSYS:
		return dbus_error_not_implemented(msg);
	default:
		break;
	}

	return dbus_error_failed(msg);
}

void dbus_pending_reply(struct l_dbus_message **msg,
				struct l_dbus_message *reply)
{
	struct l_dbus *dbus = dbus_get_bus();

	l_dbus_send(dbus, reply);
	l_dbus_message_unref(*msg);
	*msg = NULL;
}

/*
 * Convenience helper for appending a dictionary "{sv}". This only works when
 * the variant is a basic type.
 */
bool dbus_append_dict_basic(struct l_dbus_message_builder *builder,
				const char *name, char type,
				const void *data)
{
	char strtype[] = { type, '\0' };

	if (!l_dbus_message_builder_enter_dict(builder, "sv"))
		return false;
	if (!l_dbus_message_builder_append_basic(builder, 's', name))
		return false;
	if (!l_dbus_message_builder_enter_variant(builder, strtype))
		return false;
	if (!l_dbus_message_builder_append_basic(builder, type, data))
		return false;
	if (!l_dbus_message_builder_leave_variant(builder))
		return false;
	if (!l_dbus_message_builder_leave_dict(builder))
		return false;

	return true;
}

struct l_dbus *dbus_get_bus(void)
{
	return g_dbus;
}

bool dbus_init(struct l_dbus *dbus)
{
	g_dbus = dbus;
	return true;
}

void dbus_exit(void)
{
	g_dbus = NULL;
}

void dbus_shutdown(void)
{
	/* Allow AgentManager to send a Release call before disconnecting */
	agent_shutdown();
}
