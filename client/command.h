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

#define COMMAND_OPTION_USERNAME		"username"
#define COMMAND_OPTION_PASSWORD		"password"
#define COMMAND_OPTION_PASSPHRASE	"passphrase"
#define COMMAND_OPTION_DONTASK		"dont-ask"

typedef char *(*command_completion_func_t)(const char *text, int state,
						const char *entity);
typedef char *(*command_rl_completion_func_t)(const char *text, int state);


enum cmd_status {
	CMD_STATUS_TRIGGERED,
	CMD_STATUS_DONE,
	CMD_STATUS_INVALID_ARGS,
	CMD_STATUS_INVALID_VALUE,
	CMD_STATUS_UNSUPPORTED,
	CMD_STATUS_FAILED,
};

struct command {
	const char *entity;
	const char *cmd;
	const char *arg;
	enum cmd_status (*function)(const char *entity,
						char **argv, int argc);
	const char *desc;
	const bool refreshable;
	command_completion_func_t completion;
};

struct command_family {
	const char *caption;
	const char *name;
	const struct command *command_list;
	command_rl_completion_func_t family_arg_completion;
	command_rl_completion_func_t entity_arg_completion;
};

bool command_option_get(const char *name, const char **value_out);
bool command_needs_no_agent(void);

bool command_line_find_token(const char *token, uint8_t num_to_inspect);
char **command_completion(const char *text, int start, int end);
char *command_entity_arg_completion(const char *text, int state,
					const struct command *command_list);

void command_process_prompt(char **argv, int argc);

void command_noninteractive_trigger(void);
bool command_is_interactive_mode(void);
int command_get_exit_status(void);
void command_set_exit_status(int status);

void command_family_register(const struct command_family *family);
void command_family_unregister(const struct command_family *family);

struct command_family_desc {
	const char *name;
	int (*init)(void);
	void (*exit)(void);
} __attribute__((aligned(8)));

#define COMMAND_FAMILY(name, init, exit)				\
	_Pragma("GCC diagnostic push")					\
	_Pragma("GCC diagnostic ignored \"-Wattributes\"")		\
	static struct command_family_desc __command_family_ ## name	\
		__attribute__((used, retain,				\
				section("__command"), aligned(8))) = {	\
			#name, init, exit				\
		};							\
	_Pragma("GCC diagnostic pop")

bool command_init(char **argv, int argc);
void command_exit(void);
