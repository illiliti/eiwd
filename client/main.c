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

#include <errno.h>
#include <locale.h>
#include <signal.h>
#include <ell/ell.h>

#include "client/command.h"
#include "client/display.h"
#include "client/dbus-proxy.h"

static int exit_status = EXIT_SUCCESS;

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		display("Terminate\n");
		exit_status = EXIT_FAILURE;
		l_main_quit();
		break;
	}
}

int main(int argc, char *argv[])
{
	bool all_done;

	setlocale(LC_CTYPE, "");

	if (!l_main_init())
		return EXIT_FAILURE;

	l_log_set_stderr();

	all_done = command_init(argv, argc);
	if (all_done)
		goto done;

	if (command_is_interactive_mode())
		display_init();

	dbus_proxy_init();

	l_main_run_with_signal(signal_handler, NULL);

	dbus_proxy_exit();

	if (command_is_interactive_mode())
		display_exit();

done:
	if (!exit_status)
		exit_status = command_get_exit_status();

	command_exit();

	l_main_exit();

	return exit_status;
}
