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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <ell/ell.h>
#include <readline/readline.h>

#include "client/command.h"
#include "client/display.h"

static struct l_queue *command_families;
static struct l_queue *command_options;
static int exit_status;
static bool interactive_mode;
static struct command_noninteractive {
	char **argv;
	int argc;
} command_noninteractive;

struct command_option {
	const char *name;
	char *value;
};

static void command_options_destroy(void *data)
{
	struct command_option *option = data;

	l_free(option->value);
	l_free(option);
}

bool command_option_get(const char *name, const char **value_out)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(command_options); entry;
							entry = entry->next) {
		const struct command_option *option = entry->data;

		if (strcmp(option->name, name))
			continue;

		if (value_out)
			*value_out = option->value;

		return true;
	}

	return false;
}

bool command_needs_no_agent(void)
{
	return command_option_get(COMMAND_OPTION_DONTASK, NULL) &&
					(l_queue_length(command_options) == 1);
}

static enum cmd_status cmd_version(const char *entity,
						char **argv, int argc)
{
	display("IWD version %s\n", VERSION);

	return CMD_STATUS_DONE;
}

static enum cmd_status cmd_quit(const char *entity,
					char **argv, int argc)
{
	display_quit();

	l_main_quit();

	return CMD_STATUS_DONE;
}

static const struct command misc_commands[] = {
	{ NULL, "version", NULL, cmd_version, "Display version" },
	{ NULL, "quit",    NULL, cmd_quit,    "Quit program" },
	{ NULL, "exit",    NULL, cmd_quit },
	{ NULL, "help" },
	{ }
};

static char *cmd_generator(const char *text, int state)
{
	static const struct l_queue_entry *entry;
	static size_t index;
	static size_t len;
	const char *cmd;

	if (!state) {
		len = strlen(text);
		index = 0;
		entry = l_queue_get_entries(command_families);
	}

	while (entry) {
		const struct command_family *family = entry->data;

		entry = entry->next;

		if (strncmp(family->name, text, len))
			continue;

		return l_strdup(family->name);
	}

	while ((cmd = misc_commands[index].cmd)) {
		index++;

		if (strncmp(cmd, text, len))
			continue;

		return l_strdup(cmd);
	}

	return NULL;
}

static bool cmd_completion_cmd_has_arg(const char *cmd,
					const struct command_family *family)
{
	size_t i;
	char **matches = NULL;
	bool status;

	for (i = 0; family->command_list[i].cmd; i++) {
		if (strcmp(family->command_list[i].cmd, cmd))
			continue;

		return family->command_list[i].arg ? true : false;
	}

	if (!family->family_arg_completion)
		return false;

	matches = rl_completion_matches(cmd, family->family_arg_completion);
	if (!matches)
		return false;

	status = false;

	for (i = 0; matches[i]; i++) {
		if (strcmp(matches[i], cmd))
			continue;

		status = true;

		break;
	}

	l_strfreev(matches);

	return status;
}

static bool find_next_token(int *i, const char *token, int token_len)
{
	char *line = rl_line_buffer;

	while (*i && line[*i] == ' ')
		(*i)--;

	while (*i && line[*i] != ' ')
		(*i)--;

	return !strncmp(line + (line[*i] == ' ' ? *i + 1 : *i),
							token, token_len);
}

bool command_line_find_token(const char *token, uint8_t num_to_inspect)
{
	int i = rl_point - 1;
	int len = strlen(token);

	if (!len)
		return false;

	while (i && num_to_inspect) {
		if (find_next_token(&i, token, len))
			return true;

		num_to_inspect--;
	}

	return false;
}

/*
 * Work around readline limitations of not being able to pass a context pointer
 * to match functions. Set the command match function/entity to these globals
 * and call a generic match function which can call the _real_ match function
 * and include the entity.
 */
static command_completion_func_t cmd_current_completion_func = NULL;
static const char *cmd_current_entity = NULL;

static char *cmd_completion_generic(const char *text, int state)
{
	return cmd_current_completion_func(text, state, cmd_current_entity);
}

static char **cmd_completion_match_entity_cmd(const char *cmd, const char *text,
						const struct command *cmd_list)
{
	char **matches = NULL;
	size_t i;
	char *family = NULL;
	char *entity = NULL;
	char *prompt = NULL;

	for (i = 0; cmd_list[i].cmd; i++) {
		char *tmp;

		if (strcmp(cmd_list[i].cmd, cmd))
			continue;

		if (!cmd_list[i].completion)
			break;

		if (cmd_list[i].entity) {
			prompt = rl_copy_text(0, rl_end);

			family = strtok_r(prompt, " ", &tmp);
			if (!family)
				goto done;

			entity = strtok_r(NULL, " ", &tmp);
		}

done:
		cmd_current_completion_func = cmd_list[i].completion;
		cmd_current_entity = entity;

		matches = rl_completion_matches(text, cmd_completion_generic);

		l_free(prompt);
		cmd_current_completion_func = NULL;
		cmd_current_entity = NULL;

		break;
	}

	return matches;
}

static char **cmd_completion_match_family_cmd(const char *cmd_family,
						char *args, const char *text,
						bool ends_with_space)
{
	const struct l_queue_entry *entry;
	const char *arg1;
	const char *arg2;
	const char *arg3;
	char **matches = NULL;

	for (entry = l_queue_get_entries(command_families); entry;
							entry = entry->next) {
		const struct command_family *family = entry->data;

		if (strcmp(family->name, cmd_family))
			continue;

		arg1 = strtok_r(NULL, " ", &args);
		if (!arg1) {
			if (!family->family_arg_completion)
				break;

			matches = rl_completion_matches(text,
						family->family_arg_completion);

			break;
		}

		arg2 = strtok_r(NULL, " ", &args);
		if (!arg2 && !ends_with_space) {
			if (!family->family_arg_completion)
				break;

			matches = rl_completion_matches(text,
						family->family_arg_completion);
			break;
		} else if (!arg2 && ends_with_space) {
			if (!cmd_completion_cmd_has_arg(arg1, family))
				break;

			if (!family->entity_arg_completion)
				break;

			matches = rl_completion_matches(text,
						family->entity_arg_completion);
			break;
		}

		arg3 = strtok_r(NULL, " ", &args);
		if (!arg3 && !ends_with_space) {
			if (!family->entity_arg_completion)
				break;

			matches = rl_completion_matches(text,
						family->entity_arg_completion);
			break;
		}

		matches = cmd_completion_match_entity_cmd(arg2, text,
							family->command_list);

		break;
	}

	return matches;
}

char **command_completion(const char *text, int start, int end)
{
	char **matches = NULL;
	const char *family;
	char *args = NULL;
	char *prompt = NULL;
	bool ends_with_space = false;

	if (display_agent_is_active()) {
		rl_attempted_completion_over = 1;
		return NULL;
	}

	if (!start) {
		matches = rl_completion_matches(text, cmd_generator);

		goto done;
	}

	prompt = rl_copy_text(0, rl_end);

	family = strtok_r(prompt, " ", &args);
	if (!family)
		goto done;

	if (args) {
		int len = strlen(args);

		if (len > 0 && args[len - 1] == ' ')
			ends_with_space = true;
	}

	matches = cmd_completion_match_family_cmd(family, args, text,
							ends_with_space);

done:
	l_free(prompt);

	if (!matches)
		rl_attempted_completion_over = 1;

	return matches;
}

char *command_entity_arg_completion(const char *text, int state,
					const struct command *command_list)
{
	static size_t index;
	static size_t len;
	const char *cmd;

	if (!state) {
		index = 0;
		len = strlen(text);
	}

	while ((cmd = command_list[index].cmd)) {
		if (!command_list[index++].entity)
			continue;

		if (strncmp(cmd, text, len))
			continue;

		return l_strdup(cmd);
	}

	return NULL;
}

static void execute_cmd(const char *family, const char *entity,
					const struct command *cmd,
					char **argv, int argc)
{
	enum cmd_status status;

	display_refresh_set_cmd(family, entity, cmd, argv, argc);

	status = cmd->function(entity, argv, argc);

	if (status != CMD_STATUS_TRIGGERED && status != CMD_STATUS_DONE)
		goto error;

	if (status == CMD_STATUS_DONE && !interactive_mode) {
		l_main_quit();

		return;
	}

	if (!interactive_mode)
		return;

	if (cmd->refreshable)
		display_refresh_timeout_set();

	return;

error:
	switch (status) {
	case CMD_STATUS_INVALID_ARGS:
		display("Invalid command. Use the following pattern:\n");
		display_command_line(family, cmd);
		break;

	case CMD_STATUS_INVALID_VALUE:
		break;

	case CMD_STATUS_UNSUPPORTED:
		display_refresh_reset();

		display("Unsupported command\n");
		break;

	case CMD_STATUS_FAILED:
		goto failure;

	case CMD_STATUS_TRIGGERED:
	case CMD_STATUS_DONE:
		l_error("Unknown command status.");
		break;
	}

	if (interactive_mode)
		return;

failure:
	exit_status = EXIT_FAILURE;

	l_main_quit();
}

static bool match_cmd(const char *family, const char *param,
				char **argv, int argc,
				const struct command *command_list)
{
	size_t i;

	for (i = 0; command_list[i].cmd; i++) {
		const char *entity;
		const char *cmd;
		int offset;

		if  (command_list[i].entity) {
			if (argc < 1)
				continue;

			entity = param;
			cmd = argv[0];
			offset = 1;
		} else {
			entity = NULL;
			cmd = param;
			offset = 0;
		}

		if (strcmp(command_list[i].cmd, cmd))
			continue;

		if (!command_list[i].function)
			return false;

		execute_cmd(family, entity, &command_list[i],
				argv + offset, argc - offset);

		return true;
	}

	return false;
}

static bool match_cmd_family(char **argv, int argc)
{
	const struct l_queue_entry *entry;

	if (argc < 2)
		return false;

	for (entry = l_queue_get_entries(command_families); entry;
							entry = entry->next) {
		const struct command_family *family = entry->data;

		if (strcmp(family->name, argv[0]))
			continue;

		return match_cmd(family->name, argv[1], argv + 2, argc - 2,
					family->command_list);
	}

	return false;
}

static void list_commands(const char *command_family,
						const struct command *cmd_list)
{
	size_t i;

	for (i = 0; cmd_list[i].cmd; i++) {
		if (!cmd_list[i].desc)
			continue;

		display_command_line(command_family, &cmd_list[i]);
	}
}

static void list_cmd_options(void)
{
	display(MARGIN "--%-*s  %s\n", 48, COMMAND_OPTION_USERNAME,
					"Provide username");
	display(MARGIN "--%-*s  %s\n", 48, COMMAND_OPTION_PASSWORD,
					"Provide password");
	display(MARGIN "--%-*s  %s\n", 48, COMMAND_OPTION_PASSPHRASE,
					"Provide passphrase");
	display(MARGIN "--%-*s  %s\n", 48, COMMAND_OPTION_DONTASK,
					"Don't ask for missing\n"
					"\t\t\t\t\t\t      credentials");
	display(MARGIN "--%-*s  %s\n", 48, "help", "Display help");
}

static void list_cmd_families(void)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(command_families); entry;
							entry = entry->next) {
		const struct command_family *family = entry->data;

		display("\n%s:\n", family->caption);
		list_commands(family->name, family->command_list);
	}
}

static void command_display_help(void)
{
	display("\n");
	display_table_header("iwctl version " VERSION, MARGIN "%-*s",
								5, "Usage");
	display(MARGIN "iwctl [--options] [commands]\n");
	display_table_footer();

	display_table_header("Available options", MARGIN "%-*s  %-*s",
					50, "Options", 28, "Description");
	list_cmd_options();
	display_table_footer();

	display_table_header("Available commands", MARGIN "%-*s  %-*s",
					50, "Commands", 28, "Description");
	list_cmd_families();
	display_table_footer();

	if (!interactive_mode)
		return;

	display("\nMiscellaneous:\n");

	list_commands(NULL, misc_commands);
}

static bool command_match_misc_commands(char **argv, int argc)
{
	if (match_cmd(NULL, argv[0], argv + 1, argc - 1, misc_commands))
		return true;

	if (strcmp(argv[0], "help"))
		return false;

	command_display_help();

	return true;
}

void command_process_prompt(char **argv, int argc)
{
	if (argc == 0)
		return;

	if (match_cmd_family(argv, argc))
		return;

	if (!interactive_mode) {
		if (command_match_misc_commands(argv, argc)) {
			exit_status = EXIT_SUCCESS;
			goto quit;
		}

		display_error("Invalid command\n");
		exit_status = EXIT_FAILURE;
quit:
		l_main_quit();
		return;
	}

	display_refresh_reset();

	if (command_match_misc_commands(argv, argc))
		return;

	display_error("Invalid command\n");
}

void command_noninteractive_trigger(void)
{
	if (!command_noninteractive.argc)
		return;

	command_process_prompt(command_noninteractive.argv,
						command_noninteractive.argc);
}

bool command_is_interactive_mode(void)
{
	return interactive_mode;
}

void command_set_exit_status(int status)
{
	exit_status = status;
}

int command_get_exit_status(void)
{
	return exit_status;
}

void command_family_register(const struct command_family *family)
{
	l_queue_push_tail(command_families, (void *) family);
}

void command_family_unregister(const struct command_family *family)
{
	l_queue_remove(command_families, (void *) family);
}

static const struct option command_opts[] = {
	{ COMMAND_OPTION_USERNAME,	required_argument, NULL, 'u' },
	{ COMMAND_OPTION_PASSWORD,	required_argument, NULL, 'p' },
	{ COMMAND_OPTION_PASSPHRASE,	required_argument, NULL, 'P' },
	{ COMMAND_OPTION_DONTASK,	no_argument,	   NULL, 'd' },
	{ "help",			no_argument,	   NULL, 'h' },
	{ }
};

extern struct command_family_desc __start___command[];
extern struct command_family_desc __stop___command[];

bool command_init(char **argv, int argc)
{
	struct command_family_desc *desc;
	int opt;

	command_families = l_queue_new();
	command_options = l_queue_new();

	for (desc = __start___command; desc < __stop___command; desc++) {
		if (!desc->init)
			continue;

		desc->init();
	}

	for (;;) {
		struct command_option *option;

		opt = getopt_long(argc, argv, "u:p:P:dh", command_opts, NULL);

		switch (opt) {
		case 'u':
			option = l_new(struct command_option, 1);
			option->name = COMMAND_OPTION_USERNAME;
			option->value = l_strdup(optarg);

			l_queue_push_tail(command_options, option);

			break;
		case 'p':
			option = l_new(struct command_option, 1);
			option->name = COMMAND_OPTION_PASSWORD;
			option->value = l_strdup(optarg);

			l_queue_push_tail(command_options, option);

			break;
		case 'P':
			option = l_new(struct command_option, 1);
			option->name = COMMAND_OPTION_PASSPHRASE;
			option->value = l_strdup(optarg);

			l_queue_push_tail(command_options, option);

			break;
		case 'd':
			option = l_new(struct command_option, 1);
			option->name = COMMAND_OPTION_DONTASK;

			l_queue_push_tail(command_options, option);

			break;
		case 'h':
			command_display_help();

			l_main_quit();

			return true;
		case -1:
			goto options_parsed;
		case '?':
			exit_status = EXIT_FAILURE;

			return true;
		}
	}

options_parsed:
	argv += optind;
	argc -= optind;

	if (argc < 2) {
		interactive_mode = true;
		return false;
	}

	command_noninteractive.argv = argv;
	command_noninteractive.argc = argc;

	return false;
}

void command_exit(void)
{
	struct command_family_desc *desc;

	for (desc = __start___command; desc < __stop___command; desc++) {
		if (!desc->exit)
			continue;

		desc->exit();
	}

	l_queue_destroy(command_families, NULL);
	command_families = NULL;

	l_queue_destroy(command_options, command_options_destroy);
	command_options = NULL;
}
