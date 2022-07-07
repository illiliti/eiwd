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

struct command;
struct command_family;

#define COLOR_BOLDGRAY	"\x1B[1;90m"
#define COLOR_GRAY	"\x1b[90m"
#define COLOR_GREEN	"\x1b[32m"
#define COLOR_RED	"\x1B[0;91m"
#define COLOR_BLUE	"\x1B[94m"
#define COLOR_YELLOW	"\x1b[33m"
#define COLOR_OFF	"\x1B[0m"
#define CLEAR_SCREEN	"\x1b[2J"
#define MARGIN		"  "

void display(const char *format, ...)
		__attribute__((format(printf, 1, 2)));
void display_table_header(const char *caption, const char *fmt, ...)
		__attribute__((format(printf, 2, 3)));
void display_table_row(const char *margin, unsigned int ncolumns, ...);
void display_table_footer(void);
void display_error(const char *error);
void display_command_line(const char *command_family,
						const struct command *cmd);

void display_refresh_timeout_set(void);
void display_refresh_reset(void);
void display_refresh_set_cmd(const char *family, const char *entity,
					const struct command *cmd,
					char **argv, int argc);

void display_enable_cmd_prompt(void);
void display_disable_cmd_prompt(void);

void display_agent_prompt(const char *label, bool mask_input);
void display_agent_prompt_release(const char *label);
bool display_agent_is_active(void);

void display_quit(void);

void display_init(void);
void display_exit(void);
