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
#include <signal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <wchar.h>

#include <readline/history.h>
#include <readline/readline.h>
#include <ell/ell.h>

#include "client/agent.h"
#include "client/command.h"
#include "client/display.h"

#define IWD_PROMPT \
	"\001" COLOR_GREEN("\002" "[iwd]" "\001") "\002" "# "
#define LINE_LEN 81

static struct l_signal *window_change_signal;
static struct l_io *io;
static char dashed_line[LINE_LEN] = { [0 ... LINE_LEN - 2] = '-' };
static char empty_line[LINE_LEN] = { [0 ... LINE_LEN - 2] = ' ' };
static struct l_timeout *refresh_timeout;
static struct saved_input *agent_saved_input;

static struct display_refresh {
	bool enabled;
	char *family;
	char *entity;
	const struct command *cmd;
	char **argv;
	int argc;
	size_t undo_lines;
	struct l_queue *redo_entries;
	bool recording;
} display_refresh = { .enabled = true };

struct saved_input {
	char *line;
	int point;
};

static struct saved_input *save_input(void)
{
	struct saved_input *input;

	if (RL_ISSTATE(RL_STATE_DONE))
		return NULL;

	input = l_new(struct saved_input, 1);

	input->point = rl_point;
	input->line = rl_copy_text(0, rl_end);
	rl_save_prompt();
	rl_replace_line("", 0);
	rl_redisplay();

	return input;
}

static void restore_input(struct saved_input *input)
{
	if (!input)
		return;

	rl_restore_prompt();
	rl_replace_line(input->line, 0);
	rl_point = input->point;
	rl_forced_update_display();

	l_free(input->line);
	l_free(input);
}

static void display_refresh_undo_lines(void)
{
	size_t num_lines = display_refresh.undo_lines;

	printf("\033[%dA", (int) num_lines);

	do {
		printf("%s\n", empty_line);
	} while (--display_refresh.undo_lines);

	printf("\033[%dA", (int) num_lines);
}

static void display_refresh_redo_lines(void)
{
	const struct l_queue_entry *entry;
	struct saved_input *input;

	input = save_input();

	for (entry = l_queue_get_entries(display_refresh.redo_entries); entry;
							entry = entry->next) {
		char *line = entry->data;

		printf("%s", line);

		display_refresh.undo_lines++;
	}

	restore_input(input);
	display_refresh.recording = true;

	l_timeout_modify(refresh_timeout, 1);
}

void display_refresh_reset(void)
{
	l_free(display_refresh.family);
	display_refresh.family = NULL;

	l_free(display_refresh.entity);
	display_refresh.entity = NULL;

	display_refresh.cmd = NULL;

	l_strfreev(display_refresh.argv);
	display_refresh.argv = NULL;
	display_refresh.argc = 0;

	display_refresh.undo_lines = 0;
	display_refresh.recording = false;

	l_queue_clear(display_refresh.redo_entries, l_free);
}

void display_refresh_set_cmd(const char *family, const char *entity,
				const struct command *cmd,
				char **argv, int argc)
{
	int i;

	if (cmd->refreshable) {
		l_free(display_refresh.family);
		display_refresh.family = l_strdup(family);

		l_free(display_refresh.entity);
		display_refresh.entity = l_strdup(entity);

		display_refresh.cmd = cmd;

		l_strfreev(display_refresh.argv);
		display_refresh.argc = argc;

		display_refresh.argv = l_new(char *, argc + 1);

		for (i = 0; i < argc; i++)
			display_refresh.argv[i] = l_strdup(argv[i]);

		l_queue_clear(display_refresh.redo_entries, l_free);

		display_refresh.recording = false;
		display_refresh.undo_lines = 0;

		return;
	}

	if (display_refresh.family && family &&
				!strcmp(display_refresh.family, family)) {
		struct l_string *buf = l_string_new(128);
		L_AUTO_FREE_VAR(char *, args);
		char *prompt;

		for (i = 0; i < argc; i++) {
			bool needs_quotes = false;
			char *p;

			for (p = argv[i]; *p != '\0'; p++) {
				if (*p != ' ')
					continue;

				needs_quotes = true;
				break;
			}

			if (needs_quotes)
				l_string_append_printf(buf, "\"%s\" ", argv[i]);
			else
				l_string_append_printf(buf, "%s ", argv[i]);
		}

		args = l_string_unwrap(buf);

		prompt = l_strdup_printf(IWD_PROMPT"%s%s%s %s %s\n", family,
						entity ? " " : "",
						entity ? : "",
						cmd->cmd ? : "", args ? : "");

		l_queue_push_tail(display_refresh.redo_entries, prompt);
		display_refresh.undo_lines++;

		display_refresh.recording = true;
	} else {
		display_refresh_reset();
	}
}

static void display_refresh_check_feasibility(void)
{
	const struct winsize ws;

	ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);

	if (ws.ws_col < LINE_LEN - 1) {
		if (display_refresh.enabled) {
			display_refresh.recording = false;
			display(COLOR_YELLOW("Auto-refresh is disabled. "
				"Enlarge window width to at least %u to enable."
				"\n"), LINE_LEN - 1);
			display_refresh.recording = true;
		}

		display_refresh.enabled = false;
	} else {
		display_refresh.enabled = true;
	}
}

static void display_refresh_check_applicability(void)
{
	if (display_refresh.enabled && display_refresh.cmd)
		display_refresh_redo_lines();
	else if (display_refresh.cmd)
		display_refresh_timeout_set();
}

static void timeout_callback(struct l_timeout *timeout, void *user_data)
{
	struct saved_input *input;

	if (!display_refresh.enabled || !display_refresh.cmd) {
		if (display_refresh.cmd)
			display_refresh_timeout_set();

		return;
	}

	input = save_input();
	display_refresh_undo_lines();
	restore_input(input);

	display_refresh.recording = false;
	display_refresh.cmd->function(display_refresh.entity,
						display_refresh.argv,
						display_refresh.argc);
}

void display_refresh_timeout_set(void)
{
	if (refresh_timeout)
		l_timeout_modify(refresh_timeout, 1);
	else
		refresh_timeout = l_timeout_create(1, timeout_callback,
							NULL, NULL);
}

static void display_text(const char *text)
{
	struct saved_input *input = save_input();

	printf("%s", text);

	restore_input(input);

	if (!display_refresh.cmd)
		return;

	display_refresh.undo_lines++;

	if (display_refresh.recording)
		l_queue_push_tail(display_refresh.redo_entries, l_strdup(text));
}

void display(const char *fmt, ...)
{
	va_list args;
	char *text;

	va_start(args, fmt);
	text = l_strdup_vprintf(fmt, args);
	va_end(args);

	display_text(text);

	l_free(text);
}

void display_error(const char *error)
{
	char *text = l_strdup_printf(COLOR_RED("%s\n"), error);

	display_text(text);

	l_free(text);
}

static char get_flasher(void)
{
	static char c;

	if (c == ' ')
		c = '*';
	else
		c = ' ';

	return c;
}

void display_table_header(const char *caption, const char *fmt, ...)
{
	va_list args;
	char *text;
	char *body;
	int caption_pos =
		(int) ((sizeof(dashed_line) - 1) / 2 + strlen(caption) / 2);

	text = l_strdup_printf("%*s" COLOR_BOLDGRAY("%*c") "\n",
				caption_pos, caption,
				LINE_LEN - 2 - caption_pos,
				display_refresh.cmd ? get_flasher() : ' ');
	display_text(text);
	l_free(text);

	text = l_strdup_printf(COLOR_GRAY("%s\n"), dashed_line);
	display_text(text);
	l_free(text);

	va_start(args, fmt);
	text = l_strdup_vprintf(fmt, args);
	va_end(args);

	body = l_strdup_printf(COLOR_BOLDGRAY("%s\n"), text);
	display_text(body);
	l_free(body);
	l_free(text);

	text = l_strdup_printf(COLOR_GRAY("%s\n"), dashed_line);
	display_text(text);
	l_free(text);
}

void display_table_footer(void)
{
	display_text("\n");

	display_refresh_check_applicability();
}

static unsigned int color_end(char *s)
{
	char *start = s;

	while (*s != 'm' && *s != '\0')
		s++;

	return s - start + 1;
}

/*
 * Finds last space in 's' before 'width' characters, terminates at that index,
 * and returns a new string to be printed on the next line.
 *
 * 'new_width' will be updated to include extra bytes for color escapes or
 * wide characters if found.
 *
 * Any colored escapes found are set to 'color_out' so they can be re-enabled
 * on the next line.
 */
static char* next_line(char *s, unsigned int width, unsigned int *new_width,
			char **color_out)
{
	unsigned int i = 0;
	int last_space = -1;
	int last_color = -1;
	unsigned int s_len = strlen(s);
	unsigned int color_adjust = 0;
	char *ret;

	*new_width = width;
	*color_out = NULL;

	/* Find the last space before 'max', as well as any color */
	while (i <= *new_width && i < s_len) {
		int sequence_len;
		int sequence_columns;
		wchar_t w;

		if (s[i] == 0x1b) {
			sequence_len = color_end(s + i);
			/* color escape won't count for column width */
			sequence_columns = 0;
			last_color = i;

			/*
			 * Color after a space. If the line gets broken this
			 * will need to be removed off new_width since it will
			 * appear on the next line.
			 */
			if (last_space != -1)
				color_adjust += sequence_len;

		} else {
			if (s[i] == ' ') {
				last_space = i;
				/* Any past colors will appear on this line */
				color_adjust = 0;
			}

			sequence_len = l_utf8_get_codepoint(&s[i], s_len - i,
									&w);
			sequence_columns = wcwidth(w);
		}

		/* Compensate max bytes */
		*new_width += sequence_len - sequence_columns;
		i += sequence_len;
	}

	/* Reached the end of the string within the column bounds */
	if (i <= *new_width)
		return NULL;

	/* Not anywhere nice to split the line */
	if (last_space == -1)
		last_space = *new_width;

	/*
	 * Only set the color if it occurred prior to the last space. If after,
	 * it will get picked up on the next line.
	 */
	if (last_color != -1 && last_space >= last_color)
		*color_out = l_strndup(s + last_color,
					color_end(s + last_color));
	else if (last_color != -1 && last_space < last_color)
		*new_width -= color_adjust;

	ret = l_strdup(s + last_space + 1);

	s[last_space + 1] = '\0';

	return ret;
}

struct table_entry {
	unsigned int width;
	char *next;
	char *color;
};

/*
 * Appends the next line from 'e' to 'line_buf'. 'done' is only set false when
 * there are more lines needed for the current entry.
 */
static int entry_append(struct table_entry *e, char *line_buf)
{
	char *value = e->next;
	unsigned int ret = 0;
	unsigned int new_width;

	/* Empty line */
	if (!value)
		return sprintf(line_buf, "%-*s  ", e->width, "");

	/* Color from previous line */
	if (e->color) {
		ret = sprintf(line_buf, "%s", e->color);
		l_free(e->color);
		e->color = NULL;
	}

	/* Advance entry to next line, and terminate current */
	e->next = next_line(value, e->width, &new_width, &e->color);

	/* Append current line */
	ret += sprintf(line_buf + ret, "%-*s  ", new_width, value);

	l_free(value);

	/* Un-color output for next column */
	if (e->color)
		ret += sprintf(line_buf + ret, "%s", COLOR_OFF);

	return ret;
}

static bool entries_done(unsigned int num, struct table_entry *e)
{
	unsigned int i;

	for (i = 0; i < num; i++)
		if (e[i].next)
			return false;

	return true;
}

/*
 * Expects an initial margin, number of columns in table, then row data:
 *
 * <row width>, <row data>, ...
 *
 * The data string can be of any length, and will be split into new lines of
 * length <row width>.
 */
void display_table_row(const char *margin, unsigned int ncolumns, ...)
{
	char buf[512];
	char *str = buf;
	unsigned int i;
	struct table_entry entries[ncolumns];
	va_list va;

	memset(&entries[0], 0, sizeof(entries));

	va_start(va, ncolumns);

	str += sprintf(str, "%s", margin);

	for (i = 0; i < ncolumns; i++) {
		struct table_entry *e = &entries[i];
		char *v;

		e->width = va_arg(va, unsigned int);
		v = va_arg(va, char *);

		if (!l_utf8_validate(v, strlen(v), NULL)) {
			display_error("Invalid utf-8 string!");
			goto done;
		}

		e->next = l_strdup(v);

		str += entry_append(e, str);
	}

	va_end(va);

	display("%s\n", buf);
	str = buf;

	/*
	 * The first column should now be indented, which effects the entry
	 * width. Subtract this indentation only from the first column.
	 */
	entries[0].width -= strlen(margin) * 2;

	while (!entries_done(ncolumns, &entries[0])) {
		for (i = 0; i < ncolumns; i++) {
			struct table_entry *e = &entries[i];

			if (i == 0)
				str += sprintf(str, "%s%s%s", margin,
						margin, margin);

			str += entry_append(e, str);
		}

		display("%s\n", buf);
		str = buf;
	}

done:
	for (i = 0; i < ncolumns; i++) {
		if (entries[i].color)
			l_free(entries[i].color);

		if (entries[i].next)
			l_free(entries[i].next);
	}
}

void display_command_line(const char *command_family, const struct command *cmd)
{
	char *cmd_line = l_strdup_printf("%s%s%s%s%s%s%s",
				command_family ? : "",
				command_family ? " " : "",
				cmd->entity ? : "",
				cmd->entity  ? " " : "",
				cmd->cmd,
				cmd->arg ? " " : "",
				cmd->arg ? : "");

	display_table_row(MARGIN, 2, 50, cmd_line, 30, cmd->desc);

	l_free(cmd_line);
}

static void display_completion_matches(char **matches, int num_matches,
								int max_length)
{
	char *prompt;
	char *entry;
	char line[LINE_LEN];
	size_t index;
	size_t line_used;
	char *input = rl_copy_text(0, rl_end);

	prompt = l_strdup_printf("%s%s\n", IWD_PROMPT, input);
	l_free(input);

	display_text(prompt);
	l_free(prompt);

	for (index = 1, line_used = 0; matches[index]; index++) {
		if ((line_used + max_length + 1) >= (LINE_LEN - 1)) {
			strcpy(&line[line_used], "\n");

			display_text(line);

			line_used = 0;
		}

		entry = l_strdup_printf("%-*s ", max_length, matches[index]);
		l_strlcpy(&line[line_used], entry, sizeof(line) - line_used);
		l_free(entry);

		line_used += max_length + 1;
	}

	strcpy(&line[line_used], "\n");

	display_text(line);
}

#define MAX_PASSPHRASE_LEN 63

static struct masked_input {
	bool use_mask;
	char passphrase[MAX_PASSPHRASE_LEN + 1];
	uint8_t point;
	uint8_t end;
} masked_input;

static void mask_input(void)
{
	if (!masked_input.use_mask)
		return;

	if (rl_end > MAX_PASSPHRASE_LEN) {
		rl_end = MAX_PASSPHRASE_LEN;
		rl_point = masked_input.point;

		goto set_mask;
	}

	if (masked_input.end == rl_end) {
		/* Moving cursor. */
		goto done;
	} else if (masked_input.end < rl_end) {
		/* Insertion. */
		memcpy(masked_input.passphrase + rl_point,
				masked_input.passphrase + masked_input.point,
				masked_input.end - masked_input.point);
		memcpy(masked_input.passphrase + masked_input.point,
				rl_line_buffer + masked_input.point,
				rl_point - masked_input.point);
	} else {
		/* Deletion. */
		if (masked_input.point > rl_point)
			/* Backspace key. */
			memcpy(masked_input.passphrase + rl_point,
				masked_input.passphrase + masked_input.point,
				masked_input.end - masked_input.point);
		else
			/* Delete key. */
			memcpy(masked_input.passphrase + rl_point,
				masked_input.passphrase + masked_input.point
									+ 1,
				rl_end - rl_point);
		memset(masked_input.passphrase + rl_end, 0,
				masked_input.end - rl_end);
	}

set_mask:
	memset(rl_line_buffer, '*', rl_end);
	rl_line_buffer[rl_end] = '\0';

	rl_redisplay();

	masked_input.end = rl_end;
done:
	masked_input.point = rl_point;
}

static void reset_masked_input(void)
{
	memset(masked_input.passphrase, 0, MAX_PASSPHRASE_LEN + 1);
	masked_input.point = 0;
	masked_input.end = 0;
}

static void readline_callback(char *prompt)
{
	char **argv;
	int argc;

	HIST_ENTRY *previous_prompt;

	if (agent_prompt(masked_input.use_mask ?
					masked_input.passphrase : prompt))
		goto done;

	if (!prompt) {
		display_quit();

		l_main_quit();

		return;
	}

	if (!strlen(prompt))
		goto done;

	previous_prompt = history_get(history_base + history_length - 1);
	if (!previous_prompt || strcmp(previous_prompt->line, prompt)) {
		add_history(prompt);
	}

	argv = l_parse_args(prompt, &argc);
	if (!argv) {
		display("Invalid command\n");
		goto done;
	}

	command_process_prompt(argv, argc);

	l_strfreev(argv);
done:
	l_free(prompt);
}

bool display_agent_is_active(void)
{
	if (agent_saved_input)
		return true;

	return false;
}

static bool read_handler(struct l_io *io, void *user_data)
{
	rl_callback_read_char();

	if (display_agent_is_active() || !command_is_interactive_mode())
		mask_input();

	return true;
}

static void disconnect_callback(struct l_io *io, void *user_data)
{
	l_main_quit();
}

void display_enable_cmd_prompt(void)
{
	if (!io)
		io = l_io_new(fileno(stdin));

	l_io_set_read_handler(io, read_handler, NULL, NULL);
	l_io_set_disconnect_handler(io, disconnect_callback, NULL, NULL);

	rl_set_prompt(IWD_PROMPT);

	/*
	 * The following sequence of rl_* commands forces readline to properly
	 * update its internal state and re-display the new prompt.
	 */
	rl_save_prompt();
	rl_redisplay();
	rl_restore_prompt();
	rl_forced_update_display();
}

void display_disable_cmd_prompt(void)
{
	display_refresh_reset();

	rl_set_prompt("Waiting for IWD to start...");
	printf("\r");
	rl_on_new_line();
	rl_redisplay();
}

void display_agent_prompt(const char *label, bool mask_input)
{
	char *prompt;

	masked_input.use_mask = mask_input;

	if (mask_input)
		reset_masked_input();

	prompt = l_strdup_printf(COLOR_BLUE("%s "), label);

	if (command_is_interactive_mode()) {
		if (agent_saved_input) {
			l_free(prompt);
			return;
		}

		agent_saved_input = l_new(struct saved_input, 1);

		agent_saved_input->point = rl_point;
		agent_saved_input->line = rl_copy_text(0, rl_end);
		rl_set_prompt("");
		rl_replace_line("", 0);
		rl_redisplay();

		rl_erase_empty_line = 0;
		rl_set_prompt(prompt);
	} else {
		rl_callback_handler_install(prompt, readline_callback);

		if (!io)
			io = l_io_new(fileno(stdin));

		l_io_set_read_handler(io, read_handler, NULL, NULL);
	}

	l_free(prompt);

	rl_redisplay();
}

void display_agent_prompt_release(const char *label)
{
	if (!command_is_interactive_mode()) {
		rl_callback_handler_remove();
		l_io_destroy(io);

		return;
	}

	if (!agent_saved_input)
		return;

	if (display_refresh.cmd) {
		char *text = rl_copy_text(0, rl_end);
		char *prompt = l_strdup_printf(COLOR_BLUE("%s ")
						"%s\n", label, text);
		l_free(text);

		l_queue_push_tail(display_refresh.redo_entries, prompt);
		display_refresh.undo_lines++;
	}

	rl_erase_empty_line = 1;

	rl_replace_line(agent_saved_input->line, 0);
	rl_point = agent_saved_input->point;

	l_free(agent_saved_input->line);
	l_free(agent_saved_input);
	agent_saved_input = NULL;

	rl_set_prompt(IWD_PROMPT);
}

void display_quit(void)
{
	if (command_is_interactive_mode())
		rl_crlf();
}

static void window_change_signal_handler(void *user_data)
{
	display_refresh_check_feasibility();
}

static char *history_path;

void display_init(void)
{
	const char *data_home;
	char *data_path;

	display_refresh.redo_entries = l_queue_new();

	stifle_history(24);

	data_home = getenv("XDG_DATA_HOME");
	if (!data_home || *data_home != '/') {
		const char *home_path;

		home_path = getenv("HOME");
		if (home_path)
			data_path = l_strdup_printf("%s/%s/iwctl",
						home_path, ".local/share");
		else
			data_path = NULL;
	} else {
		data_path = l_strdup_printf("%s/iwctl", data_home);
	}

	if (data_path) {
		/*
		 * If mkdir succeeds that means its a new directory, no need
		 * to read the history since it doesn't exist
		 */
		if (mkdir(data_path, 0700) != 0) {
			history_path = l_strdup_printf("%s/history", data_path);
			read_history(history_path);
		}

		l_free(data_path);
	} else {
		history_path = NULL;
	}

	setlinebuf(stdout);

	window_change_signal =
		l_signal_create(SIGWINCH, window_change_signal_handler, NULL,
									NULL);

	rl_attempted_completion_function = command_completion;
	rl_completion_display_matches_hook = display_completion_matches;

	rl_completer_quote_characters = "\"";
	rl_erase_empty_line = 1;
	rl_callback_handler_install("Waiting for IWD to start...",
							readline_callback);

	rl_redisplay();

	display_refresh_check_feasibility();
}

void display_exit(void)
{
	if (agent_saved_input) {
		l_free(agent_saved_input->line);
		l_free(agent_saved_input);
		agent_saved_input = NULL;
	}

	l_timeout_remove(refresh_timeout);
	refresh_timeout = NULL;

	l_queue_destroy(display_refresh.redo_entries, l_free);

	rl_callback_handler_remove();

	l_io_destroy(io);

	l_signal_remove(window_change_signal);

	if (history_path)
		write_history(history_path);

	l_free(history_path);

	display_quit();
}
