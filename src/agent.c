/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2015-2019  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>
#include "src/dbus.h"
#include "src/netconfig.h"
#include "src/agent.h"
#include "src/iwd.h"
#include "src/module.h"

static unsigned int next_request_id = 0;

enum agent_request_type {
	AGENT_REQUEST_TYPE_PASSPHRASE,
	AGENT_REQUEST_TYPE_USER_NAME_PASSWD,
};

/* Agent dbus request is done from iwd towards the agent */
struct agent_request {
	enum agent_request_type type;
	struct l_dbus_message *message;
	unsigned int id;
	void *user_data;
	void *user_callback;
	struct l_dbus_message *trigger;
	agent_request_destroy_func_t destroy;
};

struct agent {
	char *owner;
	char *path;
	unsigned int disconnect_watch;
	uint32_t pending_id;
	struct l_timeout *timeout;
	int timeout_secs;
	struct l_queue *requests;
};

static struct l_queue *agents;

/*
 * How long we wait for user to input things.
 * Return value is in seconds.
 *
 * This should probably be configurable by user via
 * config file/command line option/env variable.
 */
static unsigned int agent_timeout_input_request(void)
{
	return 120;
}

static void send_cancel_request(void *user_data, int reason)
{
	struct agent *agent = user_data;
	struct l_dbus_message *message;
	const char *reasonstr;

	switch (reason) {
	case -ECANCELED:
		reasonstr = "user-canceled";
		break;
	case -ETIMEDOUT:
		reasonstr = "timed-out";
		break;
	case -ERANGE:
		reasonstr = "out-of-range";
		break;
	case -ESHUTDOWN:
		reasonstr = "shutdown";
		break;
	default:
		reasonstr = "unknown";
	}

	l_debug("send a Cancel(%s) to %s %s", reasonstr,
			agent->owner, agent->path);

	message = l_dbus_message_new_method_call(dbus_get_bus(),
							agent->owner,
							agent->path,
							IWD_AGENT_INTERFACE,
							"Cancel");

	l_dbus_message_set_arguments(message, "s", reasonstr);
	l_dbus_message_set_no_reply(message, true);

	l_dbus_send(dbus_get_bus(), message);
}

static void agent_request_free(void *user_data)
{
	struct agent_request *request = user_data;

	l_dbus_message_unref(request->message);

	if (request->trigger)
		dbus_pending_reply(&request->trigger,
					dbus_error_aborted(request->trigger));

	if (request->destroy)
		request->destroy(request->user_data);

	l_free(request);
}

static void passphrase_reply(struct l_dbus_message *reply,
					struct agent_request *request)
{
	const char *error, *text;
	char *passphrase = NULL;
	enum agent_result result = AGENT_RESULT_FAILED;
	agent_request_passphrase_func_t user_callback = request->user_callback;

	if (l_dbus_message_get_error(reply, &error, &text))
		goto done;

	if (!l_dbus_message_get_arguments(reply, "s", &passphrase))
		goto done;

	result = AGENT_RESULT_OK;

done:
	user_callback(result, passphrase, request->trigger, request->user_data);
}

static void user_name_passwd_reply(struct l_dbus_message *reply,
					struct agent_request *request)
{
	const char *error, *text;
	char *username = NULL;
	char *passwd = NULL;
	enum agent_result result = AGENT_RESULT_FAILED;
	agent_request_user_name_passwd_func_t user_callback =
		request->user_callback;

	if (l_dbus_message_get_error(reply, &error, &text))
		goto done;

	if (!l_dbus_message_get_arguments(reply, "ss", &username, &passwd))
		goto done;

	result = AGENT_RESULT_OK;

done:
	user_callback(result, username, passwd,
			request->trigger, request->user_data);
}

static void agent_finalize_pending(struct agent *agent,
						struct l_dbus_message *reply)
{
	struct agent_request *pending;

	if (agent->timeout) {
		l_timeout_remove(agent->timeout);
		agent->timeout = NULL;
	}

	pending = l_queue_pop_head(agent->requests);

	switch (pending->type) {
	case AGENT_REQUEST_TYPE_PASSPHRASE:
		passphrase_reply(reply, pending);
		break;
	case AGENT_REQUEST_TYPE_USER_NAME_PASSWD:
		user_name_passwd_reply(reply, pending);
		break;
	}

	if (pending->trigger) {
		l_dbus_message_unref(pending->trigger);
		pending->trigger = NULL;
	}

	agent_request_free(pending);
}

static void agent_free(void *data)
{
	struct agent *agent = data;

	l_debug("agent free %p", agent);

	if (agent->timeout)
		l_timeout_remove(agent->timeout);

	if (agent->pending_id)
		l_dbus_cancel(dbus_get_bus(), agent->pending_id);

	l_queue_destroy(agent->requests, agent_request_free);

	if (agent->disconnect_watch)
		l_dbus_remove_watch(dbus_get_bus(), agent->disconnect_watch);

	l_free(agent->owner);
	l_free(agent->path);
	l_free(agent);
}

static void agent_send_next_request(struct agent *agent);

static void request_timeout(struct l_timeout *timeout, void *user_data)
{
	struct agent *agent = user_data;

	l_dbus_cancel(dbus_get_bus(), agent->pending_id);

	send_cancel_request(agent, -ETIMEDOUT);

	agent_finalize_pending(agent, NULL);

	agent_send_next_request(agent);
}

static void agent_receive_reply(struct l_dbus_message *message,
							void *user_data)
{
	struct agent *agent = user_data;

	l_debug("agent %p request id %u", agent, agent->pending_id);

	agent->pending_id = 0;

	agent_finalize_pending(agent, message);

	if (!agent->pending_id)
		agent_send_next_request(agent);
}

static void agent_send_next_request(struct agent *agent)
{
	struct agent_request *pending;

	pending = l_queue_peek_head(agent->requests);
	if (!pending)
		return;

	agent->timeout = l_timeout_create(agent->timeout_secs,
						request_timeout,
						agent, NULL);

	l_debug("send request to %s %s", agent->owner, agent->path);

	agent->pending_id = l_dbus_send_with_reply(dbus_get_bus(),
							pending->message,
							agent_receive_reply,
							agent, NULL);

	pending->message = NULL;
}

static unsigned int agent_queue_request(struct agent *agent,
					enum agent_request_type type,
					struct l_dbus_message *message,
					int timeout, void *callback,
					struct l_dbus_message *trigger,
					void *user_data,
					agent_request_destroy_func_t destroy)
{
	struct agent_request *request;

	request = l_new(struct agent_request, 1);

	request->type = type;
	request->message = message;
	request->id = ++next_request_id;
	request->user_data = user_data;
	request->user_callback = callback;
	request->trigger = l_dbus_message_ref(trigger);
	request->destroy = destroy;

	agent->timeout_secs = timeout;

	l_queue_push_tail(agent->requests, request);

	if (l_queue_length(agent->requests) == 1)
		agent_send_next_request(agent);

	return request->id;
}

static struct agent *agent_lookup(const char *owner)
{
	const struct l_queue_entry *entry;

	if (!owner)
		return NULL;

	for (entry = l_queue_get_entries(agents); entry; entry = entry->next) {
		struct agent *agent = entry->data;

		if (strcmp(agent->owner, owner))
			continue;

		return agent;
	}

	return NULL;
}

static struct agent *get_agent(const char *owner)
{
	struct agent *agent = agent_lookup(owner);

	if (agent)
		return agent;

	return l_queue_peek_head(agents);
}

/**
 * agent_request_passphrase:
 * @path: object path related to this request (like network object path)
 * @callback: user callback called when the request is ready
 * @trigger: Message associated with (e.g. that triggered) this request
 * @user_data: user defined data
 * @destroy: callback to release @user_data when this request finishes
 *
 * Called when a passphrase information is needed from the user. Returns an
 * id that can be used to cancel the request.
 *
 * If @trigger is not NULL, then a reference is taken automatically.  If
 * agent_cancel_request is called subsequently, a dbus_aborted error is
 * automatically generated for @trigger.  Otherwise, after @callback is
 * called, the reference to @trigger is dropped.  It is assumed that the
 * caller will take ownership of @trigger in the callback if needed.
 */
unsigned int agent_request_passphrase(const char *path,
				agent_request_passphrase_func_t callback,
				struct l_dbus_message *trigger,
				void *user_data,
				agent_request_destroy_func_t destroy)
{
	struct agent *agent = get_agent(l_dbus_message_get_sender(trigger));
	struct l_dbus_message *message;

	if (!agent || !callback)
		return 0;

	l_debug("agent %p owner %s path %s", agent, agent->owner, agent->path);

	message = l_dbus_message_new_method_call(dbus_get_bus(),
							agent->owner,
							agent->path,
							IWD_AGENT_INTERFACE,
							"RequestPassphrase");

	l_dbus_message_set_arguments(message, "o", path);

	return agent_queue_request(agent, AGENT_REQUEST_TYPE_PASSPHRASE,
					message, agent_timeout_input_request(),
					callback, trigger, user_data, destroy);
}

unsigned int agent_request_pkey_passphrase(const char *path,
				agent_request_passphrase_func_t callback,
				struct l_dbus_message *trigger,
				void *user_data,
				agent_request_destroy_func_t destroy)
{
	struct agent *agent = get_agent(l_dbus_message_get_sender(trigger));
	struct l_dbus_message *message;

	if (!agent || !callback)
		return 0;

	l_debug("agent %p owner %s path %s", agent, agent->owner, agent->path);

	message = l_dbus_message_new_method_call(dbus_get_bus(),
						agent->owner, agent->path,
						IWD_AGENT_INTERFACE,
						"RequestPrivateKeyPassphrase");

	l_dbus_message_set_arguments(message, "o", path);

	return agent_queue_request(agent, AGENT_REQUEST_TYPE_PASSPHRASE,
					message, agent_timeout_input_request(),
					callback, trigger, user_data, destroy);
}

unsigned int agent_request_user_name_password(const char *path,
				agent_request_user_name_passwd_func_t callback,
				struct l_dbus_message *trigger,
				void *user_data,
				agent_request_destroy_func_t destroy)
{
	struct agent *agent = get_agent(l_dbus_message_get_sender(trigger));
	struct l_dbus_message *message;

	if (!agent || !callback)
		return 0;

	l_debug("agent %p owner %s path %s", agent, agent->owner, agent->path);

	message = l_dbus_message_new_method_call(dbus_get_bus(),
						agent->owner, agent->path,
						IWD_AGENT_INTERFACE,
						"RequestUserNameAndPassword");

	l_dbus_message_set_arguments(message, "o", path);

	return agent_queue_request(agent, AGENT_REQUEST_TYPE_USER_NAME_PASSWD,
					message, agent_timeout_input_request(),
					callback, trigger, user_data, destroy);
}

unsigned int agent_request_user_password(const char *path, const char *user,
				agent_request_passphrase_func_t callback,
				struct l_dbus_message *trigger, void *user_data,
				agent_request_destroy_func_t destroy)
{
	struct agent *agent = get_agent(l_dbus_message_get_sender(trigger));
	struct l_dbus_message *message;

	if (!agent || !callback)
		return 0;

	l_debug("agent %p owner %s path %s", agent, agent->owner, agent->path);

	message = l_dbus_message_new_method_call(dbus_get_bus(),
						agent->owner, agent->path,
						IWD_AGENT_INTERFACE,
						"RequestUserPassword");

	l_dbus_message_set_arguments(message, "os", path, user ?: "");

	return agent_queue_request(agent, AGENT_REQUEST_TYPE_PASSPHRASE,
					message, agent_timeout_input_request(),
					callback, trigger, user_data, destroy);
}

static bool find_request(const void *a, const void *b)
{
	const struct agent_request *request = a;
	unsigned int id = L_PTR_TO_UINT(b);

	return request->id == id;
}

bool agent_request_cancel(unsigned int req_id, int reason)
{
	struct agent_request *request = NULL;
	struct agent *agent;
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(agents); entry; entry = entry->next) {
		agent = entry->data;

		request = l_queue_remove_if(agent->requests, find_request,
							L_UINT_TO_PTR(req_id));
		if (request)
			break;
	}

	if (!request)
		return false;

	if (!request->message) {
		send_cancel_request(agent, reason);

		l_dbus_cancel(dbus_get_bus(), agent->pending_id);

		agent->pending_id = 0;

		if (agent->timeout) {
			l_timeout_remove(agent->timeout);
			agent->timeout = NULL;
		}

		agent_send_next_request(agent);
	}

	agent_request_free(request);

	return true;
}

static void agent_disconnect(struct l_dbus *dbus, void *user_data)
{
	struct agent *agent = user_data;

	l_debug("agent %s disconnected", agent->owner);

	if (agent->pending_id)
		agent_finalize_pending(agent, NULL);

	l_queue_remove(agents, agent);

	l_idle_oneshot(agent_free, agent, NULL);
}

static struct agent *agent_create(struct l_dbus *dbus, const char *name,
							const char *path)
{
	struct agent *agent;

	agent = l_new(struct agent, 1);

	agent->owner = l_strdup(name);
	agent->path = l_strdup(path);
	agent->requests = l_queue_new();
	agent->disconnect_watch = l_dbus_add_disconnect_watch(dbus, name,
							agent_disconnect,
							agent, NULL);
	return agent;
}

static struct l_dbus_message *agent_register(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct agent *agent = agent_lookup(l_dbus_message_get_sender(message));
	struct l_dbus_message *reply;
	const char *path;

	if (agent)
		return dbus_error_already_exists(message);

	l_debug("agent register called");

	if (!l_dbus_message_get_arguments(message, "o", &path))
		return dbus_error_invalid_args(message);

	agent = agent_create(dbus, l_dbus_message_get_sender(message), path);
	if (!agent)
		return dbus_error_failed(message);

	l_queue_push_tail(agents, agent);

	l_debug("agent %s path %s", agent->owner, agent->path);

	reply = l_dbus_message_new_method_return(message);

	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static struct l_dbus_message *agent_unregister(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct agent *agent = agent_lookup(l_dbus_message_get_sender(message));
	struct l_dbus_message *reply;

	l_debug("agent unregister");

	if (!agent)
		return dbus_error_not_found(message);

	l_queue_remove(agents, agent);

	agent_free(agent);

	reply = l_dbus_message_new_method_return(message);

	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static struct l_dbus_message *netconfig_agent_register(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct l_dbus_message *reply;
	const char *path;
	int r;

	l_debug("");

	if (!l_dbus_message_get_arguments(message, "o", &path))
		return dbus_error_invalid_args(message);

	if (!netconfig_enabled())
		return dbus_error_not_supported(message);

	r = netconfig_register_agent(l_dbus_message_get_sender(message), path);
	if (r)
		return dbus_error_from_errno(r, message);

	l_debug("agent %s path %s",
		l_dbus_message_get_sender(message), path);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");
	return reply;
}

static struct l_dbus_message *netconfig_agent_unregister(struct l_dbus *dbus,
						struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *reply;
	const char *path;
	int r;

	l_debug("");

	if (!l_dbus_message_get_arguments(message, "o", &path))
		return dbus_error_invalid_args(message);

	if (!netconfig_enabled())
		return dbus_error_not_supported(message);

	r = netconfig_unregister_agent(l_dbus_message_get_sender(message),
					path);
	if (r)
		return dbus_error_from_errno(r, message);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");
	return reply;
}

static void setup_agent_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "RegisterAgent", 0,
				agent_register,
				"", "o", "path");
	l_dbus_interface_method(interface, "UnregisterAgent", 0,
				agent_unregister,
				"", "o", "path");

	l_dbus_interface_method(interface,
				"RegisterNetworkConfigurationAgent", 0,
				netconfig_agent_register, "", "o", "path");
	l_dbus_interface_method(interface,
				"UnregisterNetworkConfigurationAgent", 0,
				netconfig_agent_unregister, "", "o", "path");
}

static bool release_agent(void *data, void *user_data)
{
	struct agent *agent = data;
	struct l_dbus_message *message;

	l_debug("send Release to %s %s", agent->owner, agent->path);

	message = l_dbus_message_new_method_call(dbus_get_bus(),
							agent->owner,
							agent->path,
							IWD_AGENT_INTERFACE,
							"Release");

	l_dbus_message_set_arguments(message, "");
	l_dbus_message_set_no_reply(message, true);
	l_dbus_send(dbus_get_bus(), message);

	agent_free(agent);

	return true;
}

static int agent_init(void)
{
	struct l_dbus *dbus = dbus_get_bus();

	agents = l_queue_new();

	if (!l_dbus_register_interface(dbus, IWD_AGENT_MANAGER_INTERFACE,
						setup_agent_interface,
						NULL, false)) {
		l_info("Unable to register %s interface",
				IWD_AGENT_MANAGER_INTERFACE);
		return -EIO;
	}

	if (!l_dbus_object_add_interface(dbus, IWD_AGENT_MANAGER_PATH,
						IWD_AGENT_MANAGER_INTERFACE,
						NULL)) {
		l_info("Unable to register the agent manager object on '%s'",
				IWD_AGENT_MANAGER_PATH);
		l_dbus_unregister_interface(dbus, IWD_AGENT_MANAGER_INTERFACE);
		return -EIO;
	}

	return 0;
}

static void agent_exit(void)
{
	struct l_dbus *dbus = dbus_get_bus();

	l_dbus_unregister_interface(dbus, IWD_AGENT_MANAGER_INTERFACE);

	l_queue_destroy(agents, agent_free);
	agents = NULL;
}

void agent_shutdown(void)
{
	l_queue_foreach_remove(agents, release_agent, NULL);
}

IWD_MODULE(agent, agent_init, agent_exit);
