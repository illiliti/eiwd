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

#include <ell/ell.h>

#include "client/agent.h"
#include "client/dbus-proxy.h"
#include "client/display.h"
#include "client/command.h"

#define IWD_AGENT_INTERFACE "net.connman.iwd.Agent"

#define PROMPT_USERNAME  "Username:"
#define PROMPT_PASSWORD   "Password:"
#define PROMPT_PASSPHRASE "Passphrase:"

enum AGENT_OP_TYPE {
	AGENT_OP_TYPE_PASSPHRASE = 1,
	AGENT_OP_TYPE_PASSWORD,
	AGENT_OP_TYPE_UNAME_PASSWORD,
};

static struct l_dbus_message *pending_message;
static struct pending_op {
	enum AGENT_OP_TYPE type;
	char *last_label;
	struct l_queue *saved_input;
} pending_op;

static struct l_dbus_message *agent_reply_canceled(
						struct l_dbus_message *message,
						const char *text)
{
	return l_dbus_message_new_error(message,
					IWD_AGENT_INTERFACE ".Error.Canceled",
					"Error: %s", text);
}

static struct l_dbus_message *agent_reply_failed(struct l_dbus_message *message,
							const char *text)
{
	return l_dbus_message_new_error(message,
					IWD_AGENT_INTERFACE ".Error.Failed",
					"Error: %s", text);
}

static struct l_dbus_message *agent_error(struct l_dbus_message *message,
							const char *text)
{
	display_error(text);

	if (!command_is_interactive_mode()) {
		command_set_exit_status(EXIT_FAILURE);

		l_main_quit();
	}

	return agent_reply_canceled(message, text);
}

static struct l_dbus_message *release_method_call(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	display_agent_prompt_release(pending_op.last_label);

	l_dbus_message_unref(pending_message);
	pending_message = NULL;

	return l_dbus_message_new_method_return(message);
}

static struct l_dbus_message *request_passphrase_command_option(
						struct l_dbus_message *message)
{
	struct l_dbus_message *reply;
	const char *passphrase = NULL;

	command_option_get(COMMAND_OPTION_PASSPHRASE, &passphrase);
	if (!passphrase)
		return NULL;

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "s", passphrase);

	return reply;
}

static struct l_dbus_message *request_passphrase_method_call(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	const struct proxy_interface *proxy;
	struct l_dbus_message *reply;
	const char *path;

	reply = request_passphrase_command_option(message);
	if (reply)
		return reply;

	if (command_option_get(COMMAND_OPTION_DONTASK, NULL))
		return agent_error(message, "No passphrase is provided as "
					"'--"COMMAND_OPTION_PASSPHRASE"' "
						"command-line option.\n");

	if (!l_dbus_message_get_arguments(message, "o", &path))
		return agent_reply_failed(message, "Invalid argument");

	if (!path)
		return agent_reply_failed(message, "Invalid argument");

	proxy = proxy_interface_find(IWD_NETWORK_INTERFACE, path);
	if (!proxy)
		return agent_reply_failed(message, "Invalid network object");

	display("Type the network passphrase for %s.\n",
				proxy_interface_get_identity_str(proxy));
	display_agent_prompt(PROMPT_PASSPHRASE, true);

	pending_op.type = AGENT_OP_TYPE_PASSPHRASE;
	pending_op.last_label = PROMPT_PASSPHRASE;

	pending_message = l_dbus_message_ref(message);

	return NULL;
}

static struct l_dbus_message *request_private_key_passphrase_method_call(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	const struct proxy_interface *proxy;
	struct l_dbus_message *reply;
	const char *path;

	reply = request_passphrase_command_option(message);
	if (reply)
		return reply;

	if (command_option_get(COMMAND_OPTION_DONTASK, NULL))
		return agent_error(message, "No passphrase is provided as "
					"'--"COMMAND_OPTION_PASSPHRASE"' "
						"command-line option.\n");

	if (!l_dbus_message_get_arguments(message, "o", &path))
		return agent_reply_failed(message, "Invalid argument");

	if (!path)
		return agent_reply_failed(message, "Invalid argument");

	proxy = proxy_interface_find(IWD_NETWORK_INTERFACE, path);
	if (!proxy)
		return agent_reply_failed(message, "Invalid network object");

	display("Type the passphrase for the network encrypted private key for "
			"%s.\n", proxy_interface_get_identity_str(proxy));
	display_agent_prompt(PROMPT_PASSPHRASE, true);

	pending_op.type = AGENT_OP_TYPE_PASSPHRASE;
	pending_op.last_label = PROMPT_PASSPHRASE;

	pending_message = l_dbus_message_ref(message);

	return NULL;
}

static struct l_dbus_message *request_username_and_password_command_option(
						struct l_dbus_message *message)
{
	struct l_dbus_message *reply;
	const char *username = NULL;
	const char *password = NULL;

	command_option_get(COMMAND_OPTION_USERNAME, &username);
	if (!username)
		return NULL;

	command_option_get(COMMAND_OPTION_PASSWORD, &password);
	if (!password)
		return NULL;

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "ss", username, password);

	return reply;
}

static struct l_dbus_message *request_username_and_password_method_call(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	const struct proxy_interface *proxy;
	struct l_dbus_message *reply;
	const char *path;

	reply = request_username_and_password_command_option(message);
	if (reply)
		return reply;

	if (command_option_get(COMMAND_OPTION_DONTASK, NULL))
		return agent_error(message, "No username or password is "
					"provided as "
					"'--"COMMAND_OPTION_USERNAME"' or "
					"'--"COMMAND_OPTION_PASSWORD"' "
						"command-line option.\n");

	if (!l_dbus_message_get_arguments(message, "o", &path))
		return agent_reply_failed(message, "Invalid argument");

	if (!path)
		return agent_reply_failed(message, "Invalid argument");

	proxy = proxy_interface_find(IWD_NETWORK_INTERFACE, path);
	if (!proxy)
		return agent_reply_failed(message, "Invalid network object");

	display("Type the network credentials for %s.\n",
				proxy_interface_get_identity_str(proxy));
	display_agent_prompt(PROMPT_USERNAME, false);

	pending_op.type = AGENT_OP_TYPE_UNAME_PASSWORD;
	pending_op.last_label = PROMPT_USERNAME;

	pending_message = l_dbus_message_ref(message);

	return NULL;
}

static struct l_dbus_message *request_user_password_command_option(
						struct l_dbus_message *message)
{
	struct l_dbus_message *reply;
	const char *password = NULL;

	command_option_get(COMMAND_OPTION_PASSWORD, &password);
	if (!password)
		return NULL;

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "s", password);

	return reply;
}

static struct l_dbus_message *request_user_password_method_call(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	const struct proxy_interface *proxy;
	struct l_dbus_message *reply;
	const char *path;
	const char *username;
	char *username_prompt;

	reply = request_user_password_command_option(message);
	if (reply)
		return reply;

	if (command_option_get(COMMAND_OPTION_DONTASK, NULL))
		return agent_error(message, "No password is provided as "
					"'--"COMMAND_OPTION_PASSWORD"' "
					"command-line option.\n");

	if (!l_dbus_message_get_arguments(message, "os", &path, &username))
		return agent_reply_failed(message, "Invalid arguments");

	if (!path || !username)
		return agent_reply_failed(message, "Invalid argument");

	proxy = proxy_interface_find(IWD_NETWORK_INTERFACE, path);
	if (!proxy)
		return agent_reply_failed(message, "Invalid network object");

	display("Type the network password for %s.\n",
				proxy_interface_get_identity_str(proxy));

	username_prompt = l_strdup_printf(COLOR_BLUE(PROMPT_USERNAME " ")
						"%s\n", username);
	display("%s", username_prompt);
	l_free(username_prompt);

	display_agent_prompt(PROMPT_PASSWORD, true);

	pending_op.type = AGENT_OP_TYPE_PASSWORD;
	pending_op.last_label = PROMPT_PASSWORD;

	pending_message = l_dbus_message_ref(message);

	return NULL;
}

static struct l_dbus_message *cancel_method_call(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	display_agent_prompt_release(pending_op.last_label);

	l_dbus_message_unref(pending_message);
	pending_message = NULL;

	return l_dbus_message_new_method_return(message);
}

static void setup_agent_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Release", 0, release_method_call,
									"", "");

	l_dbus_interface_method(interface, "RequestPassphrase", 0,
				request_passphrase_method_call, "s", "o",
						"passphrase", "network");

	l_dbus_interface_method(interface, "RequestPrivateKeyPassphrase", 0,
				request_private_key_passphrase_method_call,
				"s", "o", "private_key_path", "network");

	l_dbus_interface_method(interface, "RequestUserNameAndPassword", 0,
				request_username_and_password_method_call,
				"ss", "o", "user", "password", "network");

	l_dbus_interface_method(interface, "RequestUserPassword", 0,
				request_user_password_method_call, "s", "os",
						"password", "network", "user");

	l_dbus_interface_method(interface, "Cancel", 0, cancel_method_call,
							"", "s", "reason");
}

static void agent_send_reply(struct l_dbus_message *reply)
{
	l_dbus_send(dbus_get_bus(), reply);

	l_dbus_message_unref(pending_message);
	pending_message = NULL;
}

static void process_input_username_password(const char *prompt)
{
	struct l_dbus_message *reply;
	char *username;

	if (!prompt || !strlen(prompt)) {
		reply = agent_reply_canceled(pending_message,
							"Canceled by user");

		l_queue_clear(pending_op.saved_input, l_free);

		goto send_reply;
	}

	if (l_queue_isempty(pending_op.saved_input)) {
		/* received username */
		l_queue_push_tail(pending_op.saved_input, l_strdup(prompt));

		display_agent_prompt(PROMPT_PASSWORD, true);
		pending_op.last_label = PROMPT_PASSWORD;

		return;
	}

	username = l_queue_pop_head(pending_op.saved_input);

	reply = l_dbus_message_new_method_return(pending_message);
	l_dbus_message_set_arguments(reply, "ss", username, prompt);

	l_free(username);

send_reply:
	agent_send_reply(reply);
}

static void process_input_passphrase(const char *prompt)
{
	struct l_dbus_message *reply;

	if (!prompt || !strlen(prompt)) {
		reply = agent_reply_canceled(pending_message,
							"Canceled by user");
		goto send_reply;
	}

	reply = l_dbus_message_new_method_return(pending_message);
	l_dbus_message_set_arguments(reply, "s", prompt);

send_reply:
	agent_send_reply(reply);
}

static void process_input_password(const char *prompt)
{
	struct l_dbus_message *reply;

	if (!prompt || !strlen(prompt)) {
		reply = agent_reply_canceled(pending_message,
							"Canceled by user");
		goto send_reply;
	}

	reply = l_dbus_message_new_method_return(pending_message);
	l_dbus_message_set_arguments(reply, "s", prompt);

send_reply:
	agent_send_reply(reply);
}

bool agent_prompt(const char *prompt)
{
	if (!pending_message)
		return false;

	display_agent_prompt_release(pending_op.last_label);

	switch (pending_op.type) {
	case AGENT_OP_TYPE_UNAME_PASSWORD:
		process_input_username_password(prompt);
		break;
	case AGENT_OP_TYPE_PASSPHRASE:
		process_input_passphrase(prompt);
		break;
	case AGENT_OP_TYPE_PASSWORD:
		process_input_password(prompt);
		break;
	}

	return true;
}

bool agent_init(const char *path)
{
	struct l_dbus *dbus = dbus_get_bus();

	if (!l_dbus_register_interface(dbus, IWD_AGENT_INTERFACE,
					setup_agent_interface, NULL, false)) {
		l_info("Unable to register %s interface", IWD_AGENT_INTERFACE);

		return false;
	}

	if (!l_dbus_object_add_interface(dbus, path, IWD_AGENT_INTERFACE,
									NULL)) {
		l_info("Unable to register the agent manager object on '%s'",
								path);
		l_dbus_unregister_interface(dbus, IWD_AGENT_INTERFACE);

		return false;
	}

	pending_op.saved_input = l_queue_new();

	return true;
}

bool agent_exit(const char *path)
{
	struct l_dbus *dbus = dbus_get_bus();

	if (pending_message) {
		l_dbus_message_unref(pending_message);
		display_agent_prompt_release(pending_op.last_label);
	}

	l_queue_destroy(pending_op.saved_input, l_free);

	l_dbus_unregister_object(dbus, path);
	l_dbus_unregister_interface(dbus, IWD_AGENT_INTERFACE);

	return true;
}
