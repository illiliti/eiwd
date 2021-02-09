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

#define _GNU_SOURCE
#include <features.h>

#ifdef HAVE_BACKTRACE
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <linux/limits.h>

#include <ell/ell.h>

#include "src/backtrace.h"

static const char *program_exec;
static const char *program_path;

void __iwd_backtrace_print(unsigned int offset)
{
	void *frames[99];
	size_t n_ptrs;
	unsigned int i;
	int outfd[2], infd[2];
	int pathlen;
	pid_t pid;

	if (program_exec == NULL)
		return;

	pathlen = strlen(program_path);

	n_ptrs = backtrace(frames, L_ARRAY_SIZE(frames));
	if (n_ptrs < offset)
		return;

	if (pipe(outfd) < 0)
		return;

	if (pipe(infd) < 0) {
		close(outfd[0]);
		close(outfd[1]);
		return;
	}

	pid = fork();
	if (pid < 0) {
		close(outfd[0]);
		close(outfd[1]);
		close(infd[0]);
		close(infd[1]);
		return;
	}

	if (pid == 0) {
		close(outfd[1]);
		close(infd[0]);

		dup2(outfd[0], STDIN_FILENO);
		dup2(infd[1], STDOUT_FILENO);

		execlp("addr2line", "-C", "-f", "-e", program_exec, NULL);

		exit(EXIT_FAILURE);
	}

	close(outfd[0]);
	close(infd[1]);

	l_error("++++++++ backtrace ++++++++");

	for (i = offset; i < n_ptrs - 1; i++) {
		Dl_info info;
		char addr[20], buf[PATH_MAX * 2];
		int len, written;
		char *ptr, *pos;

		dladdr(frames[i], &info);

		len = snprintf(addr, sizeof(addr), "%p\n", frames[i]);
		if (len < 0)
			break;

		written = write(outfd[1], addr, len);
		if (written < 0)
			break;

		len = read(infd[0], buf, sizeof(buf) - 1);
		if (len < 0)
			break;

		buf[len] = '\0';

		pos = strchr(buf, '\n');
		if (!pos)
			continue;

		*pos++ = '\0';

		if (strcmp(buf, "??") == 0) {
			l_error("#%-2u %p in %s", i - offset,
						frames[i], info.dli_fname);
			continue;
		}

		ptr = strchr(pos, '\n');
		if (!ptr)
			continue;

		*ptr++ = '\0';

		if (strncmp(pos, program_path, pathlen) == 0)
			pos += pathlen + 1;

		l_error("#%-2u %p in %s() at %s", i - offset,
						frames[i], buf, pos);
	}

	l_error("+++++++++++++++++++++++++++");

	kill(pid, SIGTERM);

	close(outfd[1]);
	close(infd[0]);
}

static void signal_handler(int signo)
{
	l_error("Aborting (signal %d) [%s]", signo, program_exec);

	__iwd_backtrace_print(2);

	exit(EXIT_FAILURE);
}

void __iwd_backtrace_init()
{
	static char path[PATH_MAX];
	static char cwd[PATH_MAX];
	struct sigaction sa;
	sigset_t mask;
	ssize_t len;

	/* Attempt to get the full path to our executable */
	len = readlink("/proc/self/exe", path, sizeof(path) - 1);
	if (len > 0) {
		int i;
		path[len] = '\0';

		for (i = len - 1; i >= 0; i--) {
			if (path[i] != '/')
				continue;

			program_exec = path;
			break;
		}
	}

	if (program_exec == NULL)
		return;

	program_path = getcwd(cwd, sizeof(cwd));

	sigemptyset(&mask);
	sa.sa_handler = signal_handler;
	sa.sa_mask = mask;
	sa.sa_flags = 0;
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
}
#endif
