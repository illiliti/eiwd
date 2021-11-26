/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
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

#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <ell/ell.h>

#include "src/sysfs.h"

static int write_string(const char *file, const char *value)
{
	size_t l = strlen(value);
	int fd;
	int r;

	fd = L_TFR(open(file, O_WRONLY));
	if (fd < 0)
		return -errno;

	r = L_TFR(write(fd, value, l));
	L_TFR(close(fd));

	return r;
}

static bool sysfs_supports_ip_setting(const char *ipv, const char *ifname,
					const char *setting)
{
	struct stat st;
	int err;
	L_AUTO_FREE_VAR(char *, file) =
		l_strdup_printf("/proc/sys/net/%s/conf/%s/%s", ipv,
							ifname, setting);

	err = stat(file, &st);

	if (!err && S_ISREG(st.st_mode) != 0)
		return true;

	return false;
}

bool sysfs_supports_ipv6_setting(const char *ifname, const char *setting)
{
	return sysfs_supports_ip_setting("ipv6", ifname, setting);
}

int sysfs_write_ipv6_setting(const char *ifname, const char *setting,
					const char *value)
{
	int r;

	L_AUTO_FREE_VAR(char *, file) =
		l_strdup_printf("/proc/sys/net/ipv6/conf/%s/%s",
							ifname, setting);

	r = write_string(file, value);
	if (r < 0)
		l_error("Unable to write %s to %s", setting, file);

	return r;
}

bool sysfs_supports_ipv4_setting(const char *ifname, const char *setting)
{
	return sysfs_supports_ip_setting("ipv4", ifname, setting);
}

int sysfs_write_ipv4_setting(const char *ifname, const char *setting,
					const char *value)
{
	int r;

	L_AUTO_FREE_VAR(char *, file) =
		l_strdup_printf("/proc/sys/net/ipv4/conf/%s/%s",
							ifname, setting);

	r = write_string(file, value);
	if (r < 0)
		l_error("Unable to write %s to %s", setting, file);

	return r;
}
