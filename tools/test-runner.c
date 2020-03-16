/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2019  Intel Corporation. All rights reserved.
 *
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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <poll.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/reboot.h>
#include <sys/time.h>
#include <glob.h>
#include <time.h>
#include <ell/ell.h>

#include "linux/nl80211.h"

#ifndef WAIT_ANY
#define WAIT_ANY (-1)
#endif

#define CMDLINE_MAX			2048

#define BIN_IW				"iw"
#define BIN_HWSIM			"hwsim"
#define BIN_OFONO			"ofonod"
#define BIN_PHONESIM			"phonesim"
#define BIN_HOSTAPD			"hostapd"
#define BIN_IWD				"iwd"

#define HWSIM_RADIOS_MAX		100
#define TEST_MAX_EXEC_TIME_SEC		20

static enum action {
	ACTION_AUTO_TEST,
	ACTION_UNIT_TEST,
} test_action;

static const char *own_binary;
static char **test_argv;
static int test_argc;
static char **verbose_apps;
static char *verbose_opt;
static bool valgrind;
static char *gdb_opt;
static bool enable_debug;
const char *debug_filter;
static struct l_settings *hw_config;
static bool native_hw;
static bool shell;
static bool log;
static char log_dir[PATH_MAX];
static uid_t log_uid;
static gid_t log_gid;
static const char *qemu_binary;
static const char *kernel_image;
static const char *exec_home;
static const char *test_action_params;
static char top_level_path[PATH_MAX];
static struct l_queue *wiphy_list;

#if defined(__i386__)
/*
 * If iwd is being compiled for i386, prefer the i386 qemu but try the
 * X86-64 version as a fallback.
 */
static const char * const qemu_table[] = {
	"qemu-system-i386",
	"/usr/bin/qemu-system-i386",
	"qemu-system-x86_64",
	"/usr/bin/qemu-system-x86_64",
	NULL
};
#elif defined(__x86_64__)
/*
 * If iwd is being built for X86-64 bits there's no point booting a 32-bit
 * only system.
 */
static const char * const qemu_table[] = {
	"qemu-system-x86_64",
	"/usr/bin/qemu-system-x86_64",
	NULL
};
#elif defined(__arm__)
/*
 * If iwd is being built for ARM look for 32-bit version.
 */
static const char * const qemu_table[] = {
	"qemu-system-arm",
	"/usr/bin/qemu-system-arm",
	NULL
};
#elif defined(__aarch64__)
/*
 * If iwd is being built for AARCH64 look for 64-bit version.
 */
static const char * const qemu_table[] = {
	"qemu-system-aarch64",
	"/usr/bin/qemu-system-aarch64",
	NULL
};
#elif defined(__powerpc__)
/*
 * If iwd is being built for PowerPC look for 32-bit version.
 */
static const char * const qemu_table[] = {
	"qemu-system-ppc",
	"/usr/bin/qemu-system-ppc",
	NULL
};
#elif defined(__powerpc64__)
/*
 * If iwd is being built for PowerPC-64 look for 64-bit version.
 */
static const char * const qemu_table[] = {
	"qemu-system-ppc64",
	"/usr/bin/qemu-system-ppc64",
	NULL
};
#else
#warning Qemu binary name not defined for this architecture yet
static const char * const qemu_table[] = { NULL };
#endif

struct wiphy {
	char name[20];
	int id;
	unsigned int interface_index;
	bool interface_created : 1;
	bool used_by_hostapd : 1;
	char *interface_name;
	char *hostapd_ctrl_interface;
	char *hostapd_config;
	bool can_ap;
};

static bool check_verbosity(const char *app)
{
	char **apps = verbose_apps;

	/*
	 * All processes are verbose if logging is enabled. Kernel is a bit
	 * different as we just pipe dmesg into a log file at the end of
	 * execution.
	 */
	if (log && strcmp(app, "kernel") != 0)
		return true;

	/*
	 * Turn on output if this is a unit test run. Nothing should output
	 * anything except the tests themselves and the kernel.
	 */
	if (test_action == ACTION_UNIT_TEST && strcmp(app, "kernel") != 0)
		return true;

	if (!apps)
		return false;

	while (*apps) {
		if (!strcmp(app, *apps))
			return true;

		apps++;
	}

	return false;
}

static bool path_exist(const char *path_name)
{
	struct stat st;

	if (!stat(path_name, &st))
		return true;

	return false;
}

static const char *find_qemu(void)
{
	int i;

	for (i = 0; qemu_table[i]; i++)
		if (path_exist(qemu_table[i]))
			return qemu_table[i];

	return NULL;
}

static const char * const kernel_table[] = {
	"bzImage",
	"arch/x86/boot/bzImage",
	"vmlinux",
	"arch/x86/boot/vmlinux",
	NULL
};

static const char *find_kernel(void)
{
	int i;

	for (i = 0; kernel_table[i]; i++)
		if (path_exist(kernel_table[i]))
			return kernel_table[i];

	return NULL;
}

static const struct {
	const char *target;
	const char *linkpath;
} dev_table[] = {
	{ "/proc/self/fd",	"/dev/fd"	},
	{ "/proc/self/fd/0",	"/dev/stdin"	},
	{ "/proc/self/fd/1",	"/dev/stdout"	},
	{ "/proc/self/fd/2",	"/dev/stderr"	},
	{ }
};

static const struct {
	const char *fstype;
	const char *target;
	const char *options;
	unsigned long flags;
} mount_table[] = {
	{ "sysfs",    "/sys",     NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV },
	{ "proc",     "/proc",    NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV },
	{ "devpts",   "/dev/pts", "mode=0620", MS_NOSUID|MS_NOEXEC },
	{ "tmpfs",    "/dev/shm", "mode=1777",
					MS_NOSUID|MS_NODEV|MS_STRICTATIME },
	{ "tmpfs",    "/run",     "mode=0755",
					MS_NOSUID|MS_NODEV|MS_STRICTATIME },
	{ "tmpfs",    "/var/lib/iwd", "mode=0755", 0 },
	{ "tmpfs",    "/tmp",              NULL, 0 },
	{ "debugfs",  "/sys/kernel/debug", NULL, 0 },
	{ }
};

static const char * const config_table[] = {
	"/usr/share/dbus-1",
	NULL
};

static void prepare_sandbox(void)
{
	int i;

	for (i = 0; mount_table[i].fstype; i++) {
		struct stat st;

		if (lstat(mount_table[i].target, &st) < 0) {
			mkdir(mount_table[i].target, 0755);
		}

		if (mount(mount_table[i].fstype,
				mount_table[i].target,
				mount_table[i].fstype,
				mount_table[i].flags,
				mount_table[i].options) < 0) {
			l_error("Error: Failed to mount filesystem %s",
							mount_table[i].target);
		}
	}

	for (i = 0; dev_table[i].target; i++) {

		if (symlink(dev_table[i].target, dev_table[i].linkpath) < 0)
			l_error("Failed to create device symlink: %s",
							strerror(errno));
	}

	setsid();

	ioctl(STDIN_FILENO, TIOCSCTTY, 1);

	for (i = 0; config_table[i]; i++) {
		if (mount("tmpfs", config_table[i], "tmpfs",
				MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME,
				"mode=0755") < 0)
			l_error("Failed to create filesystem: %s",
							strerror(errno));
	}
}

static char *const qemu_argv[] = {
	"",
	"-machine", "type=q35,accel=kvm:tcg",
	"-nodefaults",
	"-no-user-config",
	"-monitor", "none",
	"-display", "none",
	"-m", "192M",
	"-nographic",
	"-vga", "none",
	"-net", "none",
	"-no-acpi",
	"-no-hpet",
	"-no-reboot",
	"-fsdev", "local,id=fsdev-root,path=/,readonly,security_model=none",
	"-device", "virtio-9p-pci,fsdev=fsdev-root,mount_tag=/dev/root",
	"-chardev", "stdio,id=chardev-serial0,signal=off",
	"-device", "pci-serial,chardev=chardev-serial0",
	"-device", "virtio-rng-pci",
	NULL
};

static char *const qemu_envp[] = {
	"HOME=/",
	NULL
};

static bool check_virtualization(void)
{
#if defined(__GNUC__) && (defined(__i386__) || defined(__amd64__))
	uint32_t ecx;

	__asm__ __volatile__("cpuid" : "=c" (ecx) :
				"a" (1) : "%ebx", "%edx");

	if (!!(ecx & (1 << 5))) {
		l_info("Found support for Virtual Machine eXtensions");
		return true;
	}

	__asm__ __volatile__("cpuid" : "=c" (ecx) :
				"a" (0x80000001) : "%ebx", "%edx");

	if (ecx & (1 << 2)) {
		l_info("Found support for Secure Virtual Machine extension");
		return true;
	}
#endif
	return false;
}

static bool start_qemu(void)
{
	char cwd[PATH_MAX], testargs[PATH_MAX];
	char *initcmd, *cmdline;
	char **argv;
	int i, pos;
	bool has_virt;
	int num_pci = 0, num_usb = 0;
	char **pci_keys = NULL;
	char **usb_keys = NULL;
	L_AUTO_FREE_VAR(char *, log_option) = NULL;

	has_virt = check_virtualization();

	if (!getcwd(cwd, sizeof(cwd)))
		strcat(cwd, "/");

	if (own_binary[0] == '/')
		initcmd = l_strdup_printf("%s", own_binary);
	else
		initcmd = l_strdup_printf("%s/%s", cwd, own_binary);

	pos = snprintf(testargs, sizeof(testargs), "%s", test_argv[0]);

	for (i = 1; i < test_argc; i++) {
		int len;

		len = sizeof(testargs) - pos;
		pos += snprintf(testargs + pos, len, " %s", test_argv[i]);
	}

	cmdline = l_strdup_printf(
			"console=ttyS0,115200n8 earlyprintk=serial "
			"rootfstype=9p "
			"root=/dev/root "
			"rootflags=trans=virtio,version=9p2000.u "
			"acpi=off pci=noacpi noapic %s ro "
			"mac80211_hwsim.radios=0 init=%s TESTHOME=%s "
			"TESTVERBOUT=\'%s\' DEBUG_FILTER=\'%s\'"
			"TEST_ACTION=%u TEST_ACTION_PARAMS=\'%s\' "
			"TESTARGS=\'%s\' PATH=\'%s\' VALGRIND=%u "
			"GDB=\'%s\' HW=\'%s\' SHELL=%u "
			"LOG_PATH=\'%s\' LOG_UID=\'%d\' LOG_GID=\'%d\'",
			check_verbosity("kernel") ? "ignore_loglevel" : "quiet",
			initcmd, cwd, verbose_opt ? verbose_opt : "none",
			enable_debug ? debug_filter : "",
			test_action,
			test_action_params ? test_action_params : "",
			testargs,
			getenv("PATH"),
			valgrind,
			gdb_opt ? gdb_opt : "none",
			hw_config ? "real" : "virtual",
			shell,
			log ? log_dir : "none",
			log_uid, log_gid);

	if (hw_config) {
		if (l_settings_has_group(hw_config, "PCIAdapters")) {
			pci_keys = l_settings_get_keys(hw_config, "PCIAdapters");

			for (num_pci = 0; pci_keys[num_pci]; num_pci++);
		}

		if (l_settings_has_group(hw_config, "USBAdapters")) {
			usb_keys = l_settings_get_keys(hw_config, "USBAdapters");

			for (num_usb = 0; usb_keys[num_usb]; num_usb++);
		}

		if (!pci_keys && !usb_keys) {
			l_error("hs config had no PCIAdapters or USBAdapters");
			l_free(initcmd);
			l_free(cmdline);
			return false;
		}
	}

	/*
	 * This got quite confusing. We need enough room for:
	 *
	 * qemu_argv (static list above with default parameters)
	 * -kernel,-append,-cpu,-host parameters (7)
	 * -enable-kvm and/or -usb (2)
	 * PCI and/or USB parameters (num_pci * 2) (num_usb * 2)
	 * Logging directory/device (2)
	 */
	argv = alloca(sizeof(qemu_argv) + sizeof(char *) *
				(7 + (2 + (num_pci * 2) + (num_usb * 2) + 2)));
	memcpy(argv, qemu_argv, sizeof(qemu_argv));

	pos = (sizeof(qemu_argv) / sizeof(char *)) - 1;

	argv[0] = (char *) qemu_binary;

	argv[pos++] = "-kernel";
	argv[pos++] = (char *) kernel_image;
	argv[pos++] = "-append";
	argv[pos++] = (char *) cmdline;
	argv[pos++] = "-cpu";
	argv[pos++] = has_virt ? "host" : "max";

	if (pci_keys) {
		argv[pos++] = "-enable-kvm";
		for (i = 0; pci_keys[i]; i++) {
			argv[pos++] = "-device";
			argv[pos] = alloca(22);
			sprintf(argv[pos], "vfio-pci,host=%s",
					l_settings_get_value(hw_config,
					"PCIAdapters", pci_keys[i]));
			pos++;
		}
	}

	if (usb_keys) {
		argv[pos++] = "-usb";
		for (i = 0; usb_keys[i]; i++) {
			const char *value = l_settings_get_value(hw_config,
						"USBAdapters", usb_keys[i]);
			char **info = l_strsplit(value, ',');

			if (l_strv_length(info) != 2) {
				l_error("hw config formatting error");
				l_strv_free(info);
				return false;
			}

			argv[pos++] = "-device";
			argv[pos] = alloca(32);
			sprintf(argv[pos], "usb-host,hostbus=%s,hostaddr=%s",
						info[0], info[1]);
			pos++;

			l_strv_free(info);
		}
	}

	if (log) {
		/*
		 * Create a virtfs device and tag it. This allows the guest to
		 * mount 'logdir' in the path specified with --log.
		 */
		log_option = l_strdup_printf("local,path=%s,mount_tag=logdir,"
					"security_model=passthrough,id=logdir",
					log_dir);
		argv[pos++] = "-virtfs";
		argv[pos++] = log_option;
	}

	argv[pos] = NULL;

	execve(argv[0], argv, qemu_envp);

	/* Don't expect to reach here */
	free(initcmd);
	free(cmdline);

	return true;
}

static pid_t execute_program(char *argv[], char *envp[], bool wait,
				const char *test_name)
{
	int status;
	pid_t pid, child_pid;
	char *str;
	bool verbose;
	char *log_name = argv[0];

	if (!argv[0])
		return -1;

	/*
	 * We have a few special cases here:
	 *
	 * Since execute_program automatically logs to <process>.log this would
	 * put all iwd output into valgrind.log rather than iwd.log. Since we
	 * are explicitly having valgrind output to a log file we can assume any
	 * output from this is only IWD, and not valgrind.
	 *
	 * python3 is special cased so that tests which start IWD manually can
	 * still show IWD output when using -v iwd.
	 */
	if (!strcmp(log_name, "valgrind") || !strcmp(log_name, "python3"))
		log_name = "iwd";

	str = l_strjoinv(argv, ' ');
	l_debug("Executing: %s", str);
	l_free(str);

	child_pid = fork();
	if (child_pid < 0) {
		l_error("Failed to fork new process");
		return -1;
	}

	if (child_pid == 0) {
		int fd = -1;
		L_AUTO_FREE_VAR(char *, log_file) = NULL;

		verbose = check_verbosity(log_name);

		/* No stdout and no logging */
		if (!verbose && !log)
			fd = open("/dev/null", O_WRONLY);
		else if (log && verbose) {
			/*
			 * Create the log file for this process. If no test name
			 * was specified this is a 'global' process (only run
			 * once, not per-test).
			 */
			if (test_name) {
				log_file = l_strdup_printf("%s/%s/%s.log",
						log_dir, test_name, log_name);
			} else
				log_file = l_strdup_printf("%s/%s.log",
						log_dir, log_name);

			fd = open(log_file, O_WRONLY | O_CREAT | O_APPEND,
					S_IRUSR | S_IWUSR);
			if (fchown(fd, log_uid, log_gid) < 0)
				l_error("failed to fchown %s", log_file);
		}

		if (fd > -1) {
			dup2(fd, 1);
			dup2(fd, 2);

			close(fd);
		}

		execvpe(argv[0], argv, envp);

		l_error("Failed to call execvpe for: %s. Error: %s", argv[0],
							strerror(errno));

		exit(EXIT_FAILURE);
	}

	if (!wait)
		goto exit;

	do {
		pid = waitpid(child_pid, &status, 0);
	} while (!WIFEXITED(status) && pid == child_pid);

	if (WEXITSTATUS(status) != EXIT_SUCCESS)
		return -1;

exit:
	return child_pid;
}

static void kill_process(pid_t pid)
{
	int status;

	l_debug("Terminate pid: %d", pid);

	kill(pid, SIGTERM);

	do {
		waitpid(pid, &status, 0);
	} while (!WIFEXITED(status) && !WIFSIGNALED(status));
}

static bool wait_for_socket(const char *socket, useconds_t wait_time)
{
	int i = 0;

	do {
		if (path_exist(socket))
			return true;

		usleep(wait_time);
	} while ((wait_time > 0) ? i++ < 20 : true);

	l_error("Error: cannot find socket: %s", socket);
	return false;
}

static void create_dbus_system_conf(void)
{
	FILE *fp;

	fp = fopen("/usr/share/dbus-1/system.conf", "we");
	if (!fp)
		return;

	fputs("<!DOCTYPE busconfig PUBLIC ", fp);
	fputs("\"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" ", fp);
	fputs("\"http://www.freedesktop.org/standards/dbus/1.0/", fp);
	fputs("busconfig.dtd\">\n", fp);
	fputs("<busconfig>\n", fp);
	fputs("<type>system</type>\n", fp);
	fputs("<listen>unix:path=/run/dbus/system_bus_socket</listen>\n", fp);
	fputs("<limit name=\"reply_timeout\">2147483647</limit>", fp);
	fputs("<policy context=\"default\">\n", fp);
	fputs("<allow user=\"*\"/>\n", fp);
	fputs("<allow own=\"*\"/>\n", fp);
	fputs("<allow send_type=\"method_call\"/>\n", fp);
	fputs("<allow send_type=\"signal\"/>\n", fp);
	fputs("<allow send_type=\"method_return\"/>\n", fp);
	fputs("<allow send_type=\"error\"/>\n", fp);
	fputs("<allow receive_type=\"method_call\"/>\n", fp);
	fputs("<allow receive_type=\"signal\"/>\n", fp);
	fputs("<allow receive_type=\"method_return\"/>\n", fp);
	fputs("<allow receive_type=\"error\"/>\n", fp);
	fputs("</policy>\n", fp);
	fputs("</busconfig>\n", fp);

	fclose(fp);

	mkdir("/run/dbus", 0755);
}

static bool start_dbus_daemon(void)
{
	char *argv[4];
	pid_t pid;

	argv[0] = "dbus-daemon";
	argv[1] = "--system";
	argv[2] = "--nosyslog";
	argv[3] = NULL;

	if (check_verbosity("dbus"))
		setenv("DBUS_VERBOSE", "1", true);

	pid = execute_program(argv, environ, false, NULL);
	if (pid < 0)
		return false;

	if (!wait_for_socket("/run/dbus/system_bus_socket", 25 * 10000))
		return false;

	if (check_verbosity("dbus-monitor")) {
		argv[0] = "dbus-monitor";
		argv[1] = "--system";
		argv[2] = NULL;
		execute_program(argv, environ, false, NULL);
	}

	l_debug("D-Bus is running");

	return true;
}

static bool start_haveged(void)
{
	char *argv[2];
	pid_t pid;

	argv[0] = "haveged";
	argv[1] = NULL;

	pid = execute_program(argv, environ, true, NULL);
	if (pid < 0)
		return false;

	return true;
}

static bool set_interface_state(const char *if_name, bool isUp)
{
	char *state, *argv[4];
	pid_t pid;

	if (isUp)
		state = "up";
	else
		state = "down";

	argv[0] = "ifconfig";
	argv[1] = (char *) if_name;
	argv[2] = state;
	argv[3] = NULL;

	pid = execute_program(argv, environ, true, NULL);
	if (pid < 0)
		return false;

	return true;
}

static bool create_interface(const char *if_name, const char *phy_name)
{
	char *argv[9];
	pid_t pid;

	argv[0] = BIN_IW;
	argv[1] = "phy";
	argv[2] = (char *) phy_name;
	argv[3] = "interface";
	argv[4] = "add";
	argv[5] = (char *) if_name;
	argv[6] = "type";
	argv[7] = "managed";
	argv[8] = NULL;

	pid = execute_program(argv, environ, true, NULL);
	if (pid < 0)
		return false;

	return true;
}

static bool delete_interface(const char *if_name)
{
	char *argv[5];
	pid_t pid;

	argv[0] = BIN_IW;
	argv[1] = "dev";
	argv[2] = (char *) if_name;
	argv[3] = "del";
	argv[4] = NULL;

	pid = execute_program(argv, environ, true, NULL);
	if (pid < 0)
		return false;

	return true;
}

static bool list_interfaces(void)
{
	char *argv[3];
	pid_t pid;

	argv[0] = "ifconfig";
	argv[1] = "-a";
	argv[2] = NULL;

	pid = execute_program(argv, environ, true, NULL);
	if (pid < 0)
		return false;

	return true;
}

static bool list_hwsim_radios(void)
{
	char *argv[3];
	pid_t pid;

	argv[0] = BIN_HWSIM;
	argv[1] = "--list";
	argv[2] = NULL;

	pid = execute_program(argv, environ, true, NULL);
	if (pid < 0)
		return false;

	return true;
}

static int read_radio_id(void)
{
	static int current_radio_id;

	return current_radio_id++;
}

struct hwsim_radio_params {
	unsigned int channels;
	bool p2p_device;
	bool use_chanctx;
	char *iftype_disable;
	char *cipher_disable;
};

static int create_hwsim_radio(const char *radio_name,
				struct hwsim_radio_params *params)
{
	char *argv[10];
	pid_t pid;
	int idx = 0;

	/*TODO add the rest of params*/
	argv[idx++] = BIN_HWSIM;
	argv[idx++] = "--create";
	argv[idx++] = "--name";
	argv[idx++] = (char *) radio_name;
	argv[idx++] = "--nointerface";

	if (params->iftype_disable) {
		argv[idx++] = "--iftype-disable";
		argv[idx++] = params->iftype_disable;
	}

	if (params->cipher_disable) {
		argv[idx++] = "--cipher-disable";
		argv[idx++] = params->cipher_disable;
	}

	argv[idx] = NULL;

	pid = execute_program(argv, environ, true, NULL);
	if (pid < 0)
		return -1;

	return read_radio_id();
}

static bool destroy_hwsim_radio(int radio_id)
{
	char *argv[4];
	char destroy_param[20];
	pid_t pid;

	sprintf(destroy_param, "--destroy=%d", radio_id);

	argv[0] = BIN_HWSIM;
	argv[1] = destroy_param;
	argv[2] = NULL;

	pid = execute_program(argv, environ, true, NULL);
	if (pid < 0)
		return false;

	return true;
}

static pid_t register_hwsim_as_trans_medium(void)
{
	char *argv[16];
	unsigned int idx = 0;

	if (strcmp(gdb_opt, "hwsim") == 0) {
		argv[idx++] = "gdb";
		argv[idx++] = "--args";
	}

	argv[idx++] = BIN_HWSIM;
	argv[idx++] = NULL;

	return execute_program(argv, environ, false, NULL);
}

static void terminate_medium(pid_t medium_pid)
{
	kill_process(medium_pid);
}

#define HOSTAPD_CTRL_INTERFACE_PREFIX "/var/run/hostapd"

static bool loopback_started;

static void start_loopback(void)
{
	char *argv[7];

	if (loopback_started)
		return;

	argv[0] = "ifconfig";
	argv[1] = "lo";
	argv[2] = "127.0.0.1";
	argv[3] = "up";
	argv[4] = NULL;
	execute_program(argv, environ, false, NULL);

	argv[0] = "route";
	argv[1] = "add";
	argv[2] = "127.0.0.1";
	argv[3] = NULL;
	execute_program(argv, environ, false, NULL);

	loopback_started = true;
}

static pid_t start_phonesim(const char *test_name)
{
	char *argv[5];

	argv[0] = BIN_PHONESIM;
	argv[1] = "-p";
	argv[2] = "12345";
	argv[3] = "/usr/share/phonesim/default.xml";
	argv[4] = NULL;

	start_loopback();

	setenv("OFONO_PHONESIM_CONFIG", "/tmp/phonesim.conf", true);

	return execute_program(argv, environ, false, test_name);
}

static void stop_phonesim(pid_t pid)
{
	kill_process(pid);
}

static pid_t start_ofono(const char *test_name)
{
	char *argv[5];
	bool verbose = check_verbosity(BIN_OFONO);

	argv[0] = BIN_OFONO;
	argv[1] = "-n";
	argv[2] = "--plugin=atmodem,phonesim";

	if (verbose)
		argv[3] = "-d";
	else
		argv[3] = NULL;

	argv[4] = NULL;

	start_loopback();

	return execute_program(argv, environ, false, test_name);
}

static void stop_ofono(pid_t pid)
{
	kill_process(pid);
}

static pid_t start_hostapd(char **config_files, struct wiphy **wiphys,
				const char *test_name)
{
	char **argv;
	pid_t pid;
	int idx = 0;
	uint32_t wait = 25 * 10000;
	bool verbose = check_verbosity(BIN_HOSTAPD);
	size_t ifnames_size;
	char *ifnames;
	int i;

	for (i = 0, ifnames_size = 0; wiphys[i]; i++)
		ifnames_size += 1 + strlen(wiphys[i]->interface_name);

	argv = alloca(sizeof(char *) * (9 + i));

	if (strcmp(gdb_opt, "hostapd") == 0) {
		argv[idx++] = "gdb";
		argv[idx++] = "--args";
		wait = 0;
	}

	argv[idx++] = BIN_HOSTAPD;

	ifnames = alloca(ifnames_size);
	argv[idx++] = "-i";
	argv[idx++] = ifnames;

	argv[idx++] = "-g";
	argv[idx++] = wiphys[0]->hostapd_ctrl_interface;

	for (i = 0, ifnames_size = 0; wiphys[i]; i++) {
		if (ifnames_size)
			ifnames[ifnames_size++] = ',';
		strcpy(ifnames + ifnames_size, wiphys[i]->interface_name);
		ifnames_size += strlen(wiphys[i]->interface_name);

		argv[idx++] = config_files[i];
	}

	if (verbose) {
		argv[idx++] = "-d";
		argv[idx++] = NULL;
	} else {
		argv[idx++] = NULL;
	}

	pid = execute_program(argv, environ, false, log ? test_name : NULL);
	if (pid < 0) {
		goto exit;
	}

	if (!wait_for_socket(wiphys[0]->hostapd_ctrl_interface, wait))
		pid = -1;
exit:
	return pid;
}

static void destroy_hostapd_instances(pid_t hostapd_pids[])
{
	int i = 0;

	while (hostapd_pids[i] != -1) {
		kill_process(hostapd_pids[i]);

		l_debug("hostapd instance with pid=%d is destroyed",
			hostapd_pids[i]);

		hostapd_pids[i] = -1;

		i++;
	}
}

#define TEST_TOP_DIR_DEFAULT_NAME	"autotests"
#define TEST_DIR_PREFIX			"test"

static bool is_test_file(const char *file)
{
	size_t i;
	static const char * const test_file_extension_table[] = {
		"test",
		"test.py",
		"Test",
		"Test.py",
		NULL
	};

	for (i = 0; test_file_extension_table[i]; i++) {
		if (l_str_has_suffix(file, test_file_extension_table[i]))
			return true;
	}

	return false;
}

static int is_test_dir(const char *dir)
{
	return strncmp(dir, TEST_DIR_PREFIX, strlen(TEST_DIR_PREFIX)) == 0;
}

static bool find_test_configuration(const char *path, int level,
						struct l_queue *config_queue);

struct test_entry {
	struct l_queue *test_queue;
	char *path;
};

static int insert_py_test(const void *a, const void *b, void *user_data)
{
	return strcmp((const char *)a, (const char *)b);
}

static int insert_test_entry(const void *a, const void *b, void *user_data)
{
	const struct test_entry *entry_a = a;
	const struct test_entry *entry_b = b;

	return strcmp(entry_a->path, entry_b->path);
}

static bool add_path(const char *path, int level, struct l_queue *config_queue)
{
	DIR *dir = NULL;
	struct l_queue *py_test_queue = NULL;
	struct dirent *entry;
	char *npath;

	dir = opendir(path);
	if (!dir) {
		l_error("Test directory does not exist: %s", path);
		return false;
	}

	while ((entry = readdir(dir))) {
		if (entry->d_type == DT_DIR) {
			if (!strcmp(entry->d_name, ".") ||
					!strcmp(entry->d_name, ".."))
				continue;

			if (level == 0 && is_test_dir(entry->d_name)) {
				npath = l_strdup_printf("%s/%s", path,
								entry->d_name);

				find_test_configuration(npath, 1, config_queue);

				l_free(npath);
			}
		} else if (level == 1 && is_test_file(entry->d_name)) {
			if (!py_test_queue)
				py_test_queue = l_queue_new();

			l_queue_insert(py_test_queue, l_strdup(entry->d_name),
						insert_py_test, NULL);
		}
	}

	if (py_test_queue && !l_queue_isempty(py_test_queue)) {
		struct test_entry *entry = l_new(struct test_entry, 1);

		entry->test_queue = py_test_queue;
		entry->path = l_strdup(path);

		l_queue_insert(config_queue, entry, insert_test_entry, NULL);
	}

	closedir(dir);
	return true;
}

static bool find_test_configuration(const char *path, int level,
						struct l_queue *config_queue)
{
	glob_t glist;
	int i = 0;
	int ret;

	if (!config_queue)
		return false;

	ret = glob(path, 0, NULL, &glist);
	if (ret != 0) {
		l_error("Could not match glob %s", path);
		return false;
	}

	while (glist.gl_pathv[i]) {
		if (!add_path(glist.gl_pathv[i], level, config_queue))
			return false;

		i++;
	}

	return true;
}

#define HW_CONFIG_FILE_NAME		"hw.conf"
#define HW_CONFIG_GROUP_HOSTAPD		"HOSTAPD"
#define HW_CONFIG_GROUP_SETUP		"SETUP"

#define HW_CONFIG_SETUP_NUM_RADIOS	"num_radios"
#define HW_CONFIG_SETUP_RADIO_CONFS	"radio_confs"
#define HW_CONFIG_SETUP_MAX_EXEC_SEC	"max_test_exec_interval_sec"
#define HW_CONFIG_SETUP_TMPFS_EXTRAS	"tmpfs_extra_stuff"
#define HW_CONFIG_SETUP_START_IWD	"start_iwd"
#define HW_CONFIG_SETUP_IWD_CONF_DIR	"iwd_config_dir"
#define HW_CONFIG_SETUP_REG_DOMAIN	"reg_domain"
#define HW_CONFIG_SETUP_NEEDS_HWSIM	"needs_hwsim"

static struct l_settings *read_hw_config(const char *test_dir_path)
{
	struct l_settings *hw_settings;
	char *hw_file;

	hw_file = l_strdup_printf("%s/%s", test_dir_path, HW_CONFIG_FILE_NAME);

	hw_settings = l_settings_new();

	if (!l_settings_load_from_file(hw_settings, hw_file)) {
		l_error("No %s file found", HW_CONFIG_FILE_NAME);
		goto error_exit;
	}

	if (!l_settings_has_group(hw_settings, HW_CONFIG_GROUP_SETUP)) {
		l_error("No %s setting group found in %s",
						HW_CONFIG_GROUP_SETUP, hw_file);
		goto error_exit;
	}

	l_free(hw_file);
	return hw_settings;

error_exit:
	l_free(hw_file);
	l_settings_free(hw_settings);
	return NULL;
}

#define HW_CONFIG_PHY_CHANNELS	"channels"
#define HW_CONFIG_PHY_CHANCTX	"use_chanctx"
#define HW_CONFIG_PHY_P2P	"p2p_device"
#define HW_CONFIG_PHY_IFTYPE_DISABLE "iftype_disable"
#define HW_CONFIG_PHY_CIPHER_DISABLE "cipher_disable"

#define HW_MIN_NUM_RADIOS	1

#define HW_INTERFACE_PREFIX	"wln"
#define HW_INTERFACE_STATE_UP   true
#define HW_INTERFACE_STATE_DOWN false

static bool configure_hw_radios(struct l_settings *hw_settings,
						struct l_queue *wiphy_list)
{
	char **radio_conf_list;
	int i, num_radios_requested;
	bool status = false;

	l_settings_get_int(hw_settings, HW_CONFIG_GROUP_SETUP,
						HW_CONFIG_SETUP_NUM_RADIOS,
							&num_radios_requested);

	if (num_radios_requested < HW_MIN_NUM_RADIOS) {
		l_error("%s must be greater or equal to %d",
			HW_CONFIG_SETUP_NUM_RADIOS, HW_MIN_NUM_RADIOS);
		return false;
	}

	radio_conf_list =
		l_settings_get_string_list(hw_settings, HW_CONFIG_GROUP_SETUP,
						HW_CONFIG_SETUP_RADIO_CONFS,
									':');
	for (i = 0; i < num_radios_requested; i++) {
		struct wiphy *wiphy;
		struct hwsim_radio_params params = { 0 };

		wiphy = l_new(struct wiphy, 1);

		sprintf(wiphy->name, "rad%d", i);

		/* radio not in radio_confs, use default parameters */
		if (!l_strv_contains(radio_conf_list, wiphy->name)) {
			params.channels = 1;
			params.p2p_device = true;
			params.use_chanctx = true;
			goto create;
		}

		if (!l_settings_get_uint(hw_settings, wiphy->name,
					HW_CONFIG_PHY_CHANNELS,
					&params.channels))
			params.channels = 1;

		if (!l_settings_get_bool(hw_settings, wiphy->name,
					HW_CONFIG_PHY_P2P, &params.p2p_device))
			params.p2p_device = true;

		if (!l_settings_get_bool(hw_settings, wiphy->name,
					HW_CONFIG_PHY_CHANCTX,
					&params.use_chanctx))
			params.use_chanctx = true;

		params.iftype_disable = l_settings_get_string(hw_settings,
					wiphy->name,
					HW_CONFIG_PHY_IFTYPE_DISABLE);
		params.cipher_disable = l_settings_get_string(hw_settings,
					wiphy->name,
					HW_CONFIG_PHY_CIPHER_DISABLE);

create:
		wiphy->id = create_hwsim_radio(wiphy->name, &params);
		wiphy->can_ap = true;

		if (wiphy->id < 0) {
			l_free(wiphy);
			goto exit;
		}

		l_queue_push_tail(wiphy_list, wiphy);
	}

	status = true;

exit:
	l_strfreev(radio_conf_list);
	return status;
}

static void wiphy_free(void *data)
{
	struct wiphy *wiphy = data;

	if (wiphy->interface_created) {
		set_interface_state(wiphy->interface_name,
					HW_INTERFACE_STATE_DOWN);

		if (delete_interface(wiphy->interface_name))
			l_debug("Removed interface %s", wiphy->interface_name);
		else
			l_error("Failed to remove interface %s",
				wiphy->interface_name);
	}

	/* Native interfaces cannot be destroyed */
	if (native_hw) {
		set_interface_state(wiphy->interface_name,
					HW_INTERFACE_STATE_DOWN);
	} else {
		destroy_hwsim_radio(wiphy->id);
		l_debug("Removed radio id %d", wiphy->id);
	}

	l_free(wiphy->hostapd_config);
	l_free(wiphy->hostapd_ctrl_interface);
	l_free(wiphy->interface_name);

	l_free(wiphy);
}

static bool configure_hostapd_instances(struct l_settings *hw_settings,
						char *config_dir_path,
						struct l_queue *wiphy_list,
						pid_t hostapd_pids_out[],
						int *phys_used)
{
	char **hostap_keys;
	int i;
	char **hostapd_config_file_paths;
	struct wiphy **wiphys;

	*phys_used = 0;

	if (!l_settings_has_group(hw_settings, HW_CONFIG_GROUP_HOSTAPD)) {
		l_info("No hostapd instances to create");
		return true;
	}

	hostap_keys =
		l_settings_get_keys(hw_settings, HW_CONFIG_GROUP_HOSTAPD);

	for (i = 0; hostap_keys[i]; i++);

	hostapd_config_file_paths = l_new(char *, i + 1);
	wiphys = alloca(sizeof(struct wiphy *) * (i + 1));
	wiphys[i] = NULL;

	hostapd_pids_out[0] = -1;

	for (i = 0; hostap_keys[i]; i++) {
		const struct l_queue_entry *wiphy_entry;
		const char *hostapd_config_file;
		unsigned wiphy_idx = 0;

		hostapd_config_file =
			l_settings_get_value(hw_settings,
						HW_CONFIG_GROUP_HOSTAPD,
						hostap_keys[i]);

		hostapd_config_file_paths[i] =
			l_strdup_printf("%s/%s", config_dir_path,
					hostapd_config_file);

		if (!path_exist(hostapd_config_file_paths[i])) {
			l_error("%s : hostapd configuration file [%s] "
				"does not exist.", HW_CONFIG_FILE_NAME,
						hostapd_config_file_paths[i]);
			goto done;
		}

		if (!strcmp(hostap_keys[i], "radius_server"))
			continue;

		for (wiphy_entry = l_queue_get_entries(wiphy_list);
					wiphy_entry;
					wiphy_entry = wiphy_entry->next,
					wiphy_idx++) {
			struct wiphy *wiphy = wiphy_entry->data;

			/*
			 * We can skip this check in native mode since we have
			 * no control over the phy name. Any test requiring a
			 * "special" radio should not be ran in native mode.
			 */
			if (!native_hw && strcmp(wiphy->name, hostap_keys[i]))
				continue;

			if (wiphy->used_by_hostapd) {
				/*
				 * Since we bypass the above check in native
				 * mode we could still get here. We can just
				 * continue searching for more adapters if this
				 * one is already in use.
				 */
				if (native_hw)
					continue;

				l_error("Wiphy %s already used by hostapd",
					wiphy->name);
				goto done;
			}

			if (!wiphy->can_ap)
				continue;

			wiphys[i] = wiphy;
			break;
		}

		if (!wiphy_entry) {
			l_error("Failed to find available wiphy.");
			goto done;
		}

		if (native_hw)
			goto hostapd_done;

		wiphys[i]->interface_name = l_strdup_printf("%s%d",
							HW_INTERFACE_PREFIX,
							wiphy_idx);
		if (!create_interface(wiphys[i]->interface_name,
					wiphys[i]->name)) {
			l_error("Failed to create hostapd interface %s on "
				"radio %s",
				wiphys[i]->interface_name, wiphys[i]->name);
			goto done;
		}

		wiphys[i]->interface_created = true;
		l_info("Created hostapd interface %s on %s radio",
			wiphys[i]->interface_name, wiphys[i]->name);

		if (!native_hw && !set_interface_state(wiphys[i]->interface_name,
						HW_INTERFACE_STATE_UP)) {
			l_error("Failed to set %s state UP",
				wiphys[i]->interface_name);
			goto done;
		}

hostapd_done:
		wiphys[i]->used_by_hostapd = true;
		wiphys[i]->hostapd_ctrl_interface =
			l_strdup_printf("%s/%s", HOSTAPD_CTRL_INTERFACE_PREFIX,
					wiphys[0]->interface_name);
		wiphys[i]->hostapd_config = l_strdup(hostapd_config_file);

		(*phys_used)++;
	}

	hostapd_pids_out[0] = start_hostapd(hostapd_config_file_paths, wiphys,
						basename(config_dir_path));
	hostapd_pids_out[1] = -1;

done:
	l_strfreev(hostapd_config_file_paths);

	if (hostapd_pids_out[0] < 1)
		return false;

	return true;
}

static pid_t start_iwd(const char *config_dir, struct l_queue *wiphy_list,
		const char *ext_options, int num_phys, const char *test_name)
{
	char *argv[13], **envp;
	char *iwd_phys = NULL;
	pid_t ret;
	int idx = 0;
	L_AUTO_FREE_VAR(char *, fd_option) = NULL;

	if (valgrind) {
		L_AUTO_FREE_VAR(char *, valgrind_log);
		int fd;

		argv[idx++] = "valgrind";
		argv[idx++] = "--leak-check=full";

		/*
		 * Valgrind needs --log-fd if we want both stderr and stdout
		 */
		if (log)
			valgrind_log = l_strdup_printf("%s/%s/valgrind.log",
							log_dir, test_name);
		else
			valgrind_log = l_strdup("/tmp/valgrind.log");

		fd = open(valgrind_log, O_WRONLY | O_CREAT | O_APPEND,
					S_IRUSR | S_IWUSR);

		if (log) {
			if (fchown(fd, log_uid, log_gid) < 0)
				l_error("chown failed");
		}

		fd_option = l_strdup_printf("--log-fd=%d", fd);
		argv[idx++] = fd_option;
	}

	if (strcmp(gdb_opt, "iwd") == 0) {
		argv[idx++] = "gdb";
		argv[idx++] = "--args";
	}

	argv[idx++] = BIN_IWD;

	if (check_verbosity(BIN_IWD) || shell)
		argv[idx++] = "-d";

	argv[idx] = NULL;

	if (wiphy_list) {
		const struct l_queue_entry *wiphy_entry;
		struct l_string *list = l_string_new(64);

		for (wiphy_entry = l_queue_get_entries(wiphy_list);
					wiphy_entry;
					wiphy_entry = wiphy_entry->next) {
			struct wiphy *wiphy = wiphy_entry->data;

			if (wiphy->used_by_hostapd)
				continue;

			/*
			 * Break out, only adding the required number of phys
			 * for this test.
			 */
			if (num_phys == 0)
				break;

			l_string_append_printf(list, "%s,", wiphy->name);

			num_phys--;
		}

		iwd_phys = l_string_unwrap(list);
		/* Take care of last comma */
		iwd_phys[strlen(iwd_phys) - 1] = '\0';

		argv[idx++] = "-p";
		argv[idx++] = iwd_phys;
		argv[idx] = NULL;
	}

	argv[idx++] = (char *)ext_options;
	argv[idx] = NULL;

	envp = l_strv_copy(environ);
	envp = l_strv_append_printf(envp, "CONFIGURATION_DIRECTORY=%s",
							config_dir);
	envp = l_strv_append_printf(envp, "STATE_DIRECTORY=%s",
							DAEMON_STORAGEDIR);

	ret = execute_program(argv, envp, false, test_name);

	l_strv_free(envp);

	l_free(iwd_phys);

	return ret;
}

static void terminate_iwd(pid_t iwd_pid)
{
	kill_process(iwd_pid);
}

static pid_t start_monitor(const char *test_name)
{
	char *argv[4];

	argv[0] = "iwmon";
	argv[1] = "--nortnl";
	argv[2] = "--nowiphy";
	argv[3] = NULL;

	return execute_program(argv, environ, false, test_name);
}

static bool create_tmpfs_extra_stuff(char **tmpfs_extra_stuff)
{
	size_t i = 0;

	if (!tmpfs_extra_stuff)
		return true;

	while (tmpfs_extra_stuff[i]) {
		char *link_dir;
		char *target_dir;

		target_dir = realpath(tmpfs_extra_stuff[i], NULL);

		if (!path_exist(target_dir)) {
			l_error("No such directory: %s", target_dir);
			l_free(target_dir);
			return false;
		}

		link_dir = l_strdup_printf("%s%s", "/tmp",
						rindex(target_dir, '/'));

		if (symlink(target_dir, link_dir) < 0) {
			l_error("Failed to create symlink %s for %s: %s",
					link_dir, target_dir, strerror(errno));

			l_free(target_dir);
			l_free(link_dir);
			return false;
		}

		l_free(tmpfs_extra_stuff[i]);
		l_free(target_dir);

		tmpfs_extra_stuff[i] = link_dir;
		i++;
	}

	return true;
}

static bool remove_absolute_path_dirs(char **tmpfs_extra_stuff)
{
	size_t i = 0;

	if (!tmpfs_extra_stuff)
		return true;

	while (tmpfs_extra_stuff[i]) {
		if (unlink(tmpfs_extra_stuff[i]) < 0) {
			l_error("Failed to remove symlink for %s: %s",
					tmpfs_extra_stuff[i], strerror(errno));

			return false;
		}

		i++;
	}

	return true;
}

#define CONSOLE_LN_DEFAULT	"\x1B[0m"
#define CONSOLE_LN_RED		"\x1B[31m"
#define CONSOLE_LN_GREEN	"\x1B[32m"
#define CONSOLE_LN_BLACK	"\x1B[30m"
#define CONSOLE_LN_YELLOW	"\x1B[33m"
#define CONSOLE_LN_RESET	"\033[0m"

#define CONSOLE_LN_BOLD		"\x1b[1m"

#define CONSOLE_BG_WHITE	"\e[47m"
#define CONSOLE_BG_DEFAULT	"\e[0m"

enum test_status {
	TEST_STATUS_STARTED,
	TEST_STATUS_PASSED,
	TEST_STATUS_FAILED,
	TEST_STATUS_TIMEDOUT,
};

static void print_test_status(char *test_name, enum test_status ts,
								double interval)
{
	const char *clear_line = "\r";
	int int_len;
	char *color_str;
	char *status_str;
	char *interval_str;
	char *line_end = "";

	switch (ts) {
	case TEST_STATUS_STARTED:
		color_str = CONSOLE_LN_RESET;
		status_str = "STARTED   ";

		if (strcmp(verbose_opt, "none"))
			line_end = "\n";

		break;
	case TEST_STATUS_PASSED:
		printf("%s", clear_line);
		color_str = CONSOLE_LN_GREEN;
		status_str = "PASSED    ";
		line_end = "\n";

		break;
	case TEST_STATUS_FAILED:
		printf("%s", clear_line);
		color_str = CONSOLE_LN_RED;
		status_str = "FAILED    ";
		line_end = "\n";

		break;
	case TEST_STATUS_TIMEDOUT:
		printf("%s", clear_line);
		color_str = CONSOLE_LN_YELLOW;
		status_str = "TIMED OUT ";
		line_end = "\n";

		break;
	}

	if (interval > 0)
		int_len = snprintf(NULL, 0, "%.3f", interval);
	else
		int_len = 3;

	int_len++;

	interval_str = l_malloc(int_len);
	memset(interval_str, ' ', int_len);
	interval_str[int_len - 1] = '\0';

	if (interval > 0)
		sprintf(interval_str, "%.3f sec", interval);
	else
		sprintf(interval_str, "%s", "...");

	printf("%s%s%s%-60s%7s%s", color_str, status_str, CONSOLE_LN_RESET,
		test_name, interval_str, line_end);

	fflush(stdout);

	l_free(interval_str);
}

static void test_timeout_timer_tick(struct l_timeout *timeout, void *user_data)
{
	pid_t *test_exec_pid = (pid_t *) user_data;

	kill_process(*test_exec_pid);

	l_main_quit();
}

static void test_timeout_signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_main_quit();
		break;
	}
}

static pid_t start_execution_timeout_timer(unsigned int max_exec_interval_sec,
							pid_t *test_exec_pid)
{
	struct l_timeout *test_exec_timeout;
	pid_t test_timer_pid;

	test_timer_pid = fork();
	if (test_timer_pid < 0) {
		l_error("Failed to fork new process");
		return -1;
	}

	if (test_timer_pid == 0) {
		if (!l_main_init())
			exit(EXIT_FAILURE);

		test_exec_timeout =
			l_timeout_create(max_exec_interval_sec,
						test_timeout_timer_tick,
						test_exec_pid,
						NULL);

		l_main_run_with_signal(test_timeout_signal_handler, NULL);

		l_timeout_remove(test_exec_timeout);

		l_main_exit();

		exit(EXIT_SUCCESS);
	}

	return test_timer_pid;
}

struct test_stats {
	char *config_cycle_name;
	unsigned int num_passed;
	unsigned int num_failed;
	unsigned int num_timedout;
	double py_run_time;
};

static void run_py_tests(struct l_settings *hw_settings,
					struct l_queue *test_queue,
					struct l_queue *test_stats_queue,
					const char *test_name)
{
	char *argv[3];
	pid_t test_exec_pid, test_timer_pid = -1;
	struct timeval time_before, time_after, time_elapsed;
	unsigned int max_exec_interval;
	char *py_test = NULL;
	struct test_stats *test_stats;

	if (!l_settings_get_uint(hw_settings, HW_CONFIG_GROUP_SETUP,
						HW_CONFIG_SETUP_MAX_EXEC_SEC,
							&max_exec_interval))
		max_exec_interval = TEST_MAX_EXEC_TIME_SEC;

	l_info(CONSOLE_LN_BOLD "%-10s%-60s%s" CONSOLE_LN_RESET, "Status",
							"Test", "Duration");

start_next_test:

	if (l_queue_isempty(test_queue))
		return;

	py_test = (char *) l_queue_pop_head(test_queue);
	if (!py_test)
		return;

	argv[0] = "python3";
	argv[1] = py_test;
	argv[2] = NULL;

	print_test_status(py_test, TEST_STATUS_STARTED, 0);
	test_exec_pid = execute_program(argv, environ, false, test_name);

	gettimeofday(&time_before, NULL);

	if (!strcmp(gdb_opt, "none"))
		test_timer_pid = start_execution_timeout_timer(
				max_exec_interval, &test_exec_pid);

	test_stats = (struct test_stats *) l_queue_peek_tail(test_stats_queue);

	while (true) {
		pid_t corpse;
		int status;
		double interval;

		corpse = waitpid(WAIT_ANY, &status, 0);

		if (corpse < 0 || corpse == 0)
			continue;

		if (test_exec_pid == corpse) {
			gettimeofday(&time_after, NULL);

			if (test_timer_pid != -1)
				kill_process(test_timer_pid);

			timersub(&time_after, &time_before, &time_elapsed);
			interval = time_elapsed.tv_sec +
					1e-6 * time_elapsed.tv_usec;

			if (WIFEXITED(status) &&
					WEXITSTATUS(status) == EXIT_SUCCESS) {
				print_test_status(py_test, TEST_STATUS_PASSED,
							interval);
				test_stats->num_passed++;
			} else if (WIFSIGNALED(status)) {
				print_test_status(py_test, TEST_STATUS_TIMEDOUT,
								interval);
				test_stats->num_timedout++;
			} else {
				print_test_status(py_test, TEST_STATUS_FAILED,
								interval);
				test_stats->num_failed++;
			}

			test_stats->py_run_time += interval;

			break;
		} else if (WIFSTOPPED(status))
			l_info("Process %d stopped with signal %d", corpse,
			       WSTOPSIG(status));
		else if (WIFCONTINUED(status))
			l_info("Process %d continued", corpse);
	}

	l_free(py_test);
	py_test = NULL;

	goto start_next_test;
}

static void set_config_cycle_info(const char *config_dir_path,
					struct l_queue *test_stats_queue)
{
	char sep_line[80];
	char *config_name_ptr;
	struct test_stats *test_stats;

	memset(sep_line, '_', sizeof(sep_line) - 1);
	sep_line[sizeof(sep_line) - 1] = '\0';

	config_name_ptr = strrchr(config_dir_path, '/');
	config_name_ptr++;

	l_info("%s", sep_line);
	l_info(CONSOLE_LN_BOLD "Starting configuration cycle No: %d [%s]"
		CONSOLE_LN_RESET, l_queue_length(test_stats_queue) + 1,
							config_name_ptr);

	test_stats = l_new(struct test_stats, 1);
	test_stats->config_cycle_name = strdup(config_name_ptr);

	l_queue_push_tail(test_stats_queue, test_stats);
}

static void set_wiphy_list(struct l_queue *wiphy_list)
{
	const struct l_queue_entry *wiphy_entry;
	int size = 32;
	char *var;

	for (wiphy_entry = l_queue_get_entries(wiphy_list);
				wiphy_entry; wiphy_entry = wiphy_entry->next) {
		struct wiphy *wiphy = wiphy_entry->data;

		size += 32 + strlen(wiphy->name);
		if (wiphy->used_by_hostapd) {
			size += 32 + strlen(wiphy->interface_name) +
				strlen(wiphy->hostapd_ctrl_interface) +
				strlen(wiphy->hostapd_config);
		}
	}

	var = alloca(size);
	size = 0;

	for (wiphy_entry = l_queue_get_entries(wiphy_list);
				wiphy_entry; wiphy_entry = wiphy_entry->next) {
		struct wiphy *wiphy = wiphy_entry->data;

		if (size)
			var[size++] = '\n';

		size += sprintf(var + size, "%s=", wiphy->name);

		if (wiphy->used_by_hostapd)
			size += sprintf(var + size,
					"hostapd,name=%s,ctrl_interface=%s,"
					"config=%s",
					wiphy->interface_name,
					wiphy->hostapd_ctrl_interface,
					wiphy->hostapd_config);
		else
			size += sprintf(var + size, "iwd");
	}

	var[size++] = '\0';

	setenv("TEST_WIPHY_LIST", var, true);
}

static void set_reg_domain(const char *domain)
{
	char *argv[5];

	argv[0] = "iw";
	argv[1] = "reg";
	argv[2] = "set";
	argv[3] = (char *) domain;
	argv[4] = NULL;

	execute_program(argv, environ, false, NULL);
}

static void wiphy_up(void *data, void *user_data)
{
	struct wiphy *wiphy = data;

	set_interface_state(wiphy->interface_name, true);
}

static void wiphy_reset(void *data, void *user_data)
{
	struct wiphy *wiphy = data;

	wiphy->used_by_hostapd = false;

	l_free(wiphy->hostapd_config);
	wiphy->hostapd_config = NULL;
	l_free(wiphy->hostapd_ctrl_interface);
	wiphy->hostapd_ctrl_interface = NULL;
}

static void create_network_and_run_tests(void *data, void *user_data)
{
	pid_t hostapd_pids[HWSIM_RADIOS_MAX];
	pid_t iwd_pid = -1;
	pid_t medium_pid = -1;
	pid_t ofono_pid = -1;
	pid_t phonesim_pid = -1;
	pid_t monitor_pid = -1;
	char *config_dir_path;
	char *iwd_config_dir;
	char **tmpfs_extra_stuff = NULL;
	struct l_settings *hw_settings;
	struct l_queue *test_queue;
	struct l_queue *test_stats_queue;
	bool start_iwd_daemon = true;
	bool needs_hwsim = false;
	bool ofono_req = false;
	const char *sim_keys;
	const char *iwd_ext_options = NULL;
	const char *reg_domain;
	int phys_used;
	int num_radios;
	struct test_entry *entry = data;
	char *test_name = NULL;

	memset(hostapd_pids, -1, sizeof(hostapd_pids));

	config_dir_path = (char *) entry->path;
	test_queue = (struct l_queue *) entry->test_queue;
	test_stats_queue = (struct l_queue *) user_data;

	if (l_queue_isempty(test_queue)) {
		l_error("No Python IWD tests have been found in %s",
							config_dir_path);
		return;
	}

	set_config_cycle_info(config_dir_path, test_stats_queue);

	hw_settings = read_hw_config(config_dir_path);
	if (!hw_settings)
		return;

	l_info("Configuring network...");

	if (log) {
		char *log_path;

		test_name = basename(config_dir_path);
		log_path = l_strdup_printf("%s/%s", log_dir, test_name);

		mkdir(log_path, 0755);
		if (chown(log_path, log_uid, log_gid) < 0)
			l_error("chown failed");

		l_free(log_path);
	}

	if (chdir(config_dir_path) < 0) {
		l_error("Failed to change to test directory: %s",
							strerror(errno));
		goto free_hw_settings;
	}

	tmpfs_extra_stuff =
		l_settings_get_string_list(hw_settings, HW_CONFIG_GROUP_SETUP,
						HW_CONFIG_SETUP_TMPFS_EXTRAS,
									':');

	sim_keys = l_settings_get_value(hw_settings, HW_CONFIG_GROUP_SETUP,
								"sim_keys");

	if (sim_keys) {
		if (!strcmp(sim_keys, "ofono")) {
			bool ofono_found = false;
			bool phonesim_found = false;

			if (!system("which ofonod > /dev/null 2>&1"))
				ofono_found = true;

			if (!system("which phonesim > /dev/null 2>&1"))
				phonesim_found = true;

			if (!ofono_found || !phonesim_found) {
				l_info("ofono or phonesim not found, skipping");
				goto free_tmpfs_extra;
			}

			ofono_req = true;
			iwd_ext_options = "--plugin=ofono";
		} else {
			setenv("IWD_SIM_KEYS", sim_keys, true);
			iwd_ext_options = "--plugin=sim_hardcoded";
		}
	}

	/* turn on/off timeouts if GDB is being used */
	if (!strcmp(gdb_opt, "none"))
		setenv("IWD_TEST_TIMEOUTS", "on", true);
	else
		setenv("IWD_TEST_TIMEOUTS", "off", true);

	if (!create_tmpfs_extra_stuff(tmpfs_extra_stuff))
		goto remove_abs_paths;

	l_settings_get_int(hw_settings, HW_CONFIG_GROUP_SETUP,
					HW_CONFIG_SETUP_NUM_RADIOS,
					&num_radios);

	if (!native_hw) {
		reg_domain = l_settings_get_value(hw_settings,
						HW_CONFIG_GROUP_SETUP,
						HW_CONFIG_SETUP_REG_DOMAIN);
		if (reg_domain)
			set_reg_domain(reg_domain);

		wiphy_list = l_queue_new();

		if (!configure_hw_radios(hw_settings, wiphy_list))
			goto remove_abs_paths;

		medium_pid = register_hwsim_as_trans_medium();
		if (medium_pid < 0)
			goto remove_abs_paths;

		if (check_verbosity("hwsim")) {
			list_hwsim_radios();
			list_interfaces();
		}
	} else {
		int len;

		l_settings_get_bool(hw_settings, HW_CONFIG_GROUP_SETUP,
				HW_CONFIG_SETUP_NEEDS_HWSIM, &needs_hwsim);

		/* Skip test that require hwsim dbus APIs (hwsim not running) */
		if (needs_hwsim) {
			l_error("test requires hwsim, skipping");
			goto remove_abs_paths;
		}

		len = l_queue_length(wiphy_list);

		/* Skip tests that need more radios than we have */
		if (num_radios > len) {
			l_error("test requires %d radios, only %d found",
					num_radios, len);
			goto remove_abs_paths;
		}

		l_queue_foreach(wiphy_list, wiphy_up, NULL);
	}

	if (log)
		monitor_pid = start_monitor(test_name);

	if (check_verbosity("tls"))
		setenv("IWD_TLS_DEBUG", "on", true);

	if (!configure_hostapd_instances(hw_settings, config_dir_path,
						wiphy_list, hostapd_pids,
						&phys_used))
		goto exit_hostapd;

	l_settings_get_bool(hw_settings, HW_CONFIG_GROUP_SETUP,
				HW_CONFIG_SETUP_START_IWD, &start_iwd_daemon);

	if (start_iwd_daemon) {
		/*
		 * In native mode we may have more radios than a test actually
		 * needs. This would result in IWD managing all phys that
		 * hostapd wasn't using, which could throw off test results.
		 * By passing the number of phys the test expects IWD to have
		 * we can leave the remaining (unneeded) phys unmanaged.
		 */
		int iwd_phys = num_radios - phys_used;

		iwd_config_dir =
			l_settings_get_string(hw_settings,
						HW_CONFIG_GROUP_SETUP,
						HW_CONFIG_SETUP_IWD_CONF_DIR);
		if (!iwd_config_dir)
			iwd_config_dir = DAEMON_CONFIGDIR;

		iwd_pid = start_iwd(iwd_config_dir, wiphy_list,
				iwd_ext_options, iwd_phys, test_name);

		if (iwd_pid == -1)
			goto exit_hostapd;
	} else {
		/* tells pytest to start iwd with valgrind */
		if (valgrind)
			setenv("IWD_TEST_VALGRIND", "on", true);
	}

	if (ofono_req) {
		phonesim_pid = start_phonesim(test_name);
		ofono_pid = start_ofono(test_name);
	}

	set_wiphy_list(wiphy_list);

	if (!shell)
		run_py_tests(hw_settings, test_queue, test_stats_queue,
				test_name);
	else {
		if (system("/bin/sh"))
			l_info("executing /bin/sh failed");
	}

	l_info("Destructing network...");

	/* Script has responsibility to cleanup any iwd instances it started */
	if (iwd_pid > 0)
		terminate_iwd(iwd_pid);

	/* /tmp/valgrind.log will only exist without logging turned on */
	if (valgrind && !log) {
		if (system("cat /tmp/valgrind.log"))
			l_info("cat /tmp/valgrind.log failed");

		if (system("echo \"\" > /tmp/valgrind.log"))
			l_info("Failed to reset /tmp/valgrind.log");
	}

	if (log) {
		L_AUTO_FREE_VAR(char *, dmesg);
		L_AUTO_FREE_VAR(char *, kernel_log);

		kernel_log = l_strdup_printf("%s/kernel.log", log_dir);
		dmesg = l_strdup_printf("dmesg > %s", kernel_log);

		if (system(dmesg))
			l_error("dmesg failed");
		if (chown(kernel_log, log_uid, log_gid))
			l_error("chown failed");
	}

	if (ofono_req) {
		loopback_started = false;
		stop_ofono(ofono_pid);
		stop_phonesim(phonesim_pid);
	}

	if (monitor_pid > 0)
		kill_process(monitor_pid);

exit_hostapd:
	destroy_hostapd_instances(hostapd_pids);

	if (!native_hw)
		terminate_medium(medium_pid);

remove_abs_paths:
	remove_absolute_path_dirs(tmpfs_extra_stuff);

	/*
	 * If running in hwsim mode, we want to completely free/destroy the
	 * wiphy list since it will be re-populated on the next test. For the
	 * native case we want to reset the list as if it was freshly
	 * discovered. This ensures that all the hostapd flags get reset.
	 */
	if (!native_hw)
		l_queue_destroy(wiphy_list, wiphy_free);
	else
		l_queue_foreach(wiphy_list, wiphy_reset, NULL);

free_tmpfs_extra:
	l_strfreev(tmpfs_extra_stuff);
free_hw_settings:
	l_settings_free(hw_settings);
}

struct stat_totals {
	unsigned int total_passed;
	unsigned int total_failed;
	unsigned int total_timedout;
	double total_duration;
};

static void print_test_stat(void *data, void *user_data)
{
	struct test_stats *test_stats;
	struct stat_totals *stat_totals;
	char *str_runtime, *str_passed, *str_failed, *str_timedout;

	test_stats = (struct test_stats *) data;
	stat_totals = (struct stat_totals *) user_data;

	stat_totals->total_duration	+= test_stats->py_run_time;
	stat_totals->total_passed	+= test_stats->num_passed;
	stat_totals->total_failed	+= test_stats->num_failed;
	stat_totals->total_timedout	+= test_stats->num_timedout;

	if (test_stats->py_run_time)
		str_runtime = l_strdup_printf("| %9.3f sec",
						test_stats->py_run_time);
	else
		str_runtime = l_strdup_printf("| %9s", "Skipped");

	if (test_stats->num_passed)
		str_passed = l_strdup_printf(" %6d ", test_stats->num_passed);
	else
		str_passed = l_strdup_printf(" %6c ", '-');

	if (test_stats->num_failed)
		str_failed = l_strdup_printf(" %6d ", test_stats->num_failed);
	else
		str_failed = l_strdup_printf(" %6c ", '-');

	if (test_stats->num_timedout)
		str_timedout = l_strdup_printf(" %9d ",
						test_stats->num_timedout);
	else
		str_timedout = l_strdup_printf(" %9c ", '-');

	l_info(CONSOLE_LN_BOLD "%27s "
			CONSOLE_LN_DEFAULT "|" CONSOLE_LN_GREEN "%s"
			CONSOLE_LN_DEFAULT "|" CONSOLE_LN_RED "%s"
			CONSOLE_LN_DEFAULT "|" CONSOLE_LN_YELLOW "%s"
			CONSOLE_LN_RESET "%s", test_stats->config_cycle_name,
			str_passed, str_failed, str_timedout, str_runtime);

	l_free(str_passed);
	l_free(str_failed);
	l_free(str_timedout);
	l_free(str_runtime);
}

static void print_results(struct l_queue *test_stat_queue)
{
	struct stat_totals stat_totals = { 0, 0, 0, 0 };
	char sep_line[80];

	memset(sep_line, '_', sizeof(sep_line) - 1);
	sep_line[sizeof(sep_line) - 1] = '\0';

	l_info("%s\n" CONSOLE_LN_RESET, sep_line);
	l_info("%27s " CONSOLE_LN_DEFAULT "|" CONSOLE_LN_GREEN " %s "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_RED " %5s "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_YELLOW " %9s "
		CONSOLE_LN_RESET "| Duration",
		"Configuration cycle", "PASSED", "FAILED", "TIMED OUT");

	memset(sep_line, '-', sizeof(sep_line) - 1);
	sep_line[sizeof(sep_line) - 1] = '\0';
	l_info("%s" CONSOLE_LN_RESET, sep_line);

	l_queue_foreach(test_stat_queue, print_test_stat, &stat_totals);

	l_info("%s" CONSOLE_LN_RESET, sep_line);
	l_info("%27s "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_GREEN " %6d "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_RED " %6d "
		CONSOLE_LN_DEFAULT "|" CONSOLE_LN_YELLOW " %9d "
		CONSOLE_LN_RESET "| %9.3f sec",
		"Total", stat_totals.total_passed, stat_totals.total_failed,
			stat_totals.total_timedout, stat_totals.total_duration);

	memset(sep_line, '_', sizeof(sep_line) - 1);
	sep_line[sizeof(sep_line) - 1] = '\0';
	l_info("%s" CONSOLE_LN_RESET, sep_line);
}

static void test_stat_queue_entry_destroy(void *data)
{
	struct test_stats *ts;

	ts = (struct test_stats *) data;

	l_free(ts->config_cycle_name);
	l_free(ts);
}

static void free_test_entry(void *data)
{
	struct test_entry *entry = data;

	l_free(entry->path);
	l_free(entry);
}

static void run_auto_tests(void)
{
	L_AUTO_FREE_VAR(char*, test_home_path) = NULL;
	L_AUTO_FREE_VAR(char*, env_path) = NULL;
	int i;
	struct l_queue *test_config_queue;
	struct l_queue *test_stat_queue;
	char **test_config_dirs;

	if (log) {
		if (mount("logdir", log_dir, "9p", 0,
					"trans=virtio,version=9p2000.L") < 0) {
			l_error("Mounting %s failed", log_dir);
			return;
		}
	}

	env_path = l_strdup_printf("%s/src:%s/tools:%s", top_level_path,
					top_level_path, getenv("PATH"));

	setenv("PATH", env_path, true);

	test_home_path = l_strdup_printf("%s/%s", top_level_path,
						TEST_TOP_DIR_DEFAULT_NAME);

	if (!path_exist(test_home_path)) {
		l_error("Test directory %s does not exist", test_home_path);
		return;
	}

	test_config_queue = l_queue_new();
	if (!test_config_queue)
		return;

	test_config_dirs = l_strsplit(test_action_params, ',');

	if (test_config_dirs[0]) {
		i = 0;

		while (test_config_dirs[i]) {
			if (strchr(test_config_dirs[i], '/')) {
				if (!find_test_configuration(
							test_config_dirs[i], 1,
							test_config_queue))
					goto exit;
			} else {
				char *config_dir_path;

				config_dir_path =
					l_strdup_printf("%s/%s", test_home_path,
							test_config_dirs[i]);

				if (!find_test_configuration(config_dir_path, 1,
							test_config_queue)) {
					l_free(config_dir_path);

					goto exit;
				}

				l_free(config_dir_path);
			}

			i++;
		}
	} else {
		/*
		 * --shell without any specific tests implies 'shell' test
		 */
		if (shell) {
			char *config_dir_path;
			config_dir_path = l_strdup_printf("%s/shell",
								test_home_path);

			if (!find_test_configuration(config_dir_path, 1,
							test_config_queue)) {
				l_free(config_dir_path);
				goto exit;
			}

			l_free(config_dir_path);
		} else {
			l_info("Automatic test execution requested");
			l_info("Searching for the test configurations...");

			if (!find_test_configuration(test_home_path, 0,
							test_config_queue))
				goto exit;
		}
	}

	if (l_queue_isempty(test_config_queue)) {
		l_error("No test configuration discovered");
		goto exit;
	}

	create_dbus_system_conf();

	if (!start_dbus_daemon())
		goto exit;

	if (!start_haveged()) {
		l_error("Failed to start haveged");
		goto exit;
	}

	test_stat_queue = l_queue_new();

	l_queue_foreach(test_config_queue, create_network_and_run_tests,
							test_stat_queue);

	print_results(test_stat_queue);

	l_queue_destroy(test_stat_queue, test_stat_queue_entry_destroy);

exit:
	l_strfreev(verbose_apps);
	l_strfreev(test_config_dirs);
	l_queue_destroy(test_config_queue, free_test_entry);
}

static void run_unit_tests(void)
{
	DIR *d;
	struct dirent *dirent;
	char *argv[2];
	char *unit_test_abs_path = NULL;
	char **unit_tests = NULL;

	if (strcmp(test_action_params, "")) {
		unit_tests = l_strsplit(test_action_params, ',');

		if (!unit_tests || !unit_tests[0])
			goto exit;
	}

	if (chdir(top_level_path) < 0)
		goto exit;

	d = opendir("unit/");
	if (!d)
		goto exit;

	while ((dirent = readdir(d)) != NULL) {
		struct stat st;

		if (dirent->d_type != DT_REG)
			continue;

		unit_test_abs_path = l_strdup_printf("%s%s%s", top_level_path,
						"/unit/", dirent->d_name);

		if (stat(unit_test_abs_path, &st) < 0)
			goto next;

		if (!(st.st_mode & S_IEXEC))
			goto next;

		if (unit_tests) {
			if (!l_strv_contains(unit_tests, dirent->d_name))
				goto next;
		}

		argv[0] = unit_test_abs_path;
		argv[1] = NULL;

		l_info("\n---------- Unit %s ----------", dirent->d_name);
		execute_program(argv, environ, true, NULL);

next:
		l_free(unit_test_abs_path);
	}

	closedir(d);

exit:
	l_strfreev(unit_tests);
}

static bool wiphy_match(const void *a, const void *b)
{
	const struct wiphy *wiphy = a;
	int id = L_PTR_TO_INT(b);

	return (wiphy->id == id);
}

static struct wiphy *wiphy_find(int wiphy_id)
{
	return l_queue_find(wiphy_list, wiphy_match, L_INT_TO_PTR(wiphy_id));
}

static void parse_supported_iftypes(uint16_t *iftypes,
						struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		/*
		 * NL80211_IFTYPE_UNSPECIFIED can be ignored, so we start
		 * at the first bit
		 */
		if (type > sizeof(uint16_t) * 8) {
			l_warn("unsupported iftype: %u", type);
			continue;
		}

		*iftypes |= 1 << (type - 1);
	}
}

static void wiphy_dump_callback(struct l_genl_msg *msg, void *user_data)
{
	struct wiphy *wiphy;
	struct l_genl_attr attr;
	struct l_genl_attr nested;
	uint32_t id = UINT32_MAX;
	uint16_t type, len;
	const void *data;
	const char *name = NULL;
	uint32_t name_len = 0;
	uint16_t iftypes = 0;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WIPHY:
			if (len != sizeof(uint32_t))
				return;

			id = *((uint32_t *) data);

			if (wiphy_find(id))
				return;

			break;
		case NL80211_ATTR_WIPHY_NAME:
			if (len > sizeof(((struct wiphy *) 0)->name))
				return;

			name = data;
			name_len = len;

			break;
		case NL80211_ATTR_SUPPORTED_IFTYPES:
			if (l_genl_attr_recurse(&attr, &nested))
				parse_supported_iftypes(&iftypes, &nested);

			break;
		}
	}

	if (id == UINT32_MAX || !name)
		return;

	wiphy = l_new(struct wiphy, 1);
	strncpy(wiphy->name, name, name_len);
	wiphy->id = id;
	wiphy->can_ap = iftypes & (1 << NL80211_IFTYPE_AP);

	l_queue_push_tail(wiphy_list, wiphy);
}

static void iface_dump_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	const char *ifname = NULL;
	struct wiphy *wiphy = NULL;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {

		case NL80211_ATTR_IFNAME:
			if (len > 16) {
				l_warn("Invalid interface name attribute");
				return;
			}

			ifname = data;
			break;

		case NL80211_ATTR_WIPHY:
			if (len != sizeof(uint32_t)) {
				l_warn("Invalid wiphy attribute");
				return;
			}

			wiphy = wiphy_find(*((uint32_t *) data));
			break;
		}
	}

	if (!ifname || !wiphy)
		return;

	wiphy->interface_name = l_strdup(ifname);
	wiphy->interface_created = false;

	l_info("Discovered interface %s", wiphy->interface_name);
}

struct nl_data {
	struct l_genl *genl;
	struct l_genl_family *nl80211;
};

static void iface_dump_done(void *user_data)
{
	struct nl_data *data = user_data;

	l_debug("Interface discovery complete, running tests");

	list_interfaces();

	run_auto_tests();

	l_queue_destroy(wiphy_list, wiphy_free);

	l_genl_family_free(data->nl80211);
	l_genl_unref(data->genl);
	l_free(data);

	l_main_quit();
}

static void wiphy_dump_done(void *user_data)
{
	struct nl_data *data = user_data;
	struct l_genl_msg *msg;

	l_debug("Wiphy discovery complete, discovering interfaces");

	msg = l_genl_msg_new(NL80211_CMD_GET_INTERFACE);
	if (!l_genl_family_dump(data->nl80211, msg, iface_dump_callback,
						data, iface_dump_done))
		l_error("Getting all interface information failed");
}

static void nl80211_requested(const struct l_genl_family_info *info,
							void *user_data)
{
	struct nl_data *data = user_data;
	struct l_genl_msg *msg;

	if (info == NULL) {
		l_info("No nl80211 family found");
		goto done;
	}

	l_debug("Found nl80211 interface");

	data->nl80211 = l_genl_family_new(data->genl, NL80211_GENL_NAME);
	wiphy_list = l_queue_new();

	msg = l_genl_msg_new(NL80211_CMD_GET_WIPHY);
	if (!l_genl_family_dump(data->nl80211, msg, wiphy_dump_callback,
						data, wiphy_dump_done))
		l_error("Getting all wiphy devices failed");

	return;
done:
	l_main_quit();
}

static void start_hw_discovery(void)
{
	struct nl_data *data = l_new(struct nl_data, 1);

	data->genl = l_genl_new();
	l_genl_request_family(data->genl, NL80211_GENL_NAME,
				nl80211_requested, data, NULL);
	/*
	 * This is somewhat of a mystery, but it appears that
	 * calling lshw causes the OS to re-enumerate the USB
	 * bus. Without this no USB adapters are found when
	 * doing the wiphy/iface dump from nl80211.
	 *
	 * This also conveniently prints all the network
	 * adapters and their iface name, so its much easier
	 * to know which adapter are being used by iwd/hostapd
	 * after the test.
	 */
	if (system("lshw -C network"))
		l_info("lshw failed");

	l_main_run();
}

static void run_tests(void)
{
	char cmdline[CMDLINE_MAX], *ptr, *cmds;
	char *test_action_str;
	FILE *fp;
	int i;

	fp = fopen("/proc/cmdline", "re");

	if (!fp) {
		l_error("Failed to open kernel command line");
		return;
	}

	ptr = fgets(cmdline, sizeof(cmdline), fp);
	fclose(fp);

	if (!ptr) {
		l_error("Failed to read kernel command line");
		return;
	}

	ptr = strstr(cmdline, "LOG_GID=");
	if (ptr) {
		*ptr = '\0';
		test_action_str = ptr + 9;
		ptr = strchr(test_action_str, '\'');
		*ptr = '\0';
		log_gid = atoi(test_action_str);
	}

	ptr = strstr(cmdline, "LOG_UID=");
	if (ptr) {
		*ptr = '\0';
		test_action_str = ptr + 9;
		ptr = strchr(test_action_str, '\'');
		*ptr = '\0';
		log_uid = atoi(test_action_str);
	}

	ptr = strstr(cmdline, "LOG_PATH=");
	if (ptr) {
		*ptr = '\0';
		test_action_str = ptr + 10;

		ptr = strchr(test_action_str, '\'');
		*ptr = '\0';

		if (strcmp(test_action_str, "none")) {
			log = true;
			strcpy(log_dir, test_action_str);
		}
	}

	ptr = strstr(cmdline, "SHELL=");
	if (ptr) {
		*ptr = '\0';
		test_action_str = ptr + 6;

		shell = atoi(test_action_str);
	}

	ptr = strstr(cmdline, "HW=");
	if (ptr) {
		*ptr = '\0';
		test_action_str = ptr + 4;

		ptr = strchr(test_action_str, '\'');
		if (ptr)
			*ptr = '\0';

		if (!strcmp(test_action_str, "virtual"))
			native_hw = false;
		else
			native_hw = true;
	}

	ptr = strstr(cmdline, "GDB=");
	if (ptr) {
		*ptr = '\0';
		test_action_str = ptr + 5;

		ptr = strchr(test_action_str, '\'');
		*ptr = '\0';
		gdb_opt = l_strdup(test_action_str);
	}

	ptr = strstr(cmdline, "VALGRIND=");
	if (ptr) {
		char *end;
		unsigned long v;

		*ptr = '\0';
		test_action_str = ptr + 9;
		v = strtoul(test_action_str, &end, 10);
		if ((v != 0 && v != 1) || end != test_action_str + 1) {
			l_error("malformed valgrind option");
			return;
		}

		valgrind = (bool) v;
	}

	ptr = strstr(cmdline, "PATH=");
	if (!ptr) {
		l_error("No $PATH section found");
		return;
	}

	*ptr = '\0';
	test_action_str = ptr + 6;
	ptr = strchr(test_action_str, '\'');
	*ptr = '\0';
	l_info("%s", test_action_str);
	setenv("PATH", test_action_str, true);

	ptr = strstr(cmdline, "TESTARGS=");

	if (!ptr) {
		l_error("No test command section found");
		return;
	}

	cmds = ptr + 10;
	ptr = strchr(cmds, '\'');

	if (!ptr) {
		l_error("Malformed test command section");
		return;
	}

	*ptr = '\0';

	ptr = strstr(cmdline, "TEST_ACTION_PARAMS=");

	if (ptr) {
		test_action_params = ptr + 20;
		ptr = strchr(test_action_params, '\'');

		if (!ptr) {
			l_error("Malformed test action parameters section");
			return;
		}

		*ptr = '\0';
	}

	ptr = strstr(cmdline, "TEST_ACTION=");

	if (ptr) {
		test_action_str = ptr + 12;
		ptr = strchr(test_action_str, ' ');

		if (!ptr) {
			l_error("Malformed test action parameters section");
			return;
		}

		*ptr = '\0';

		test_action = (enum action) atoi(test_action_str);
	}

	ptr = strstr(cmdline, "DEBUG_FILTER=");

	if (ptr) {
		debug_filter = ptr + 14;

		ptr = strchr(debug_filter, '\'');

		if (!ptr) {
			l_error("Malformed debug filter section");
			return;
		}

		*ptr = '\0';

		if (debug_filter[0] != '\0') {
			enable_debug = true;
			l_debug_enable(debug_filter);
			setenv("HWSIM_DEBUG", "", true);
		}
	}

	ptr = strstr(cmdline, "TESTVERBOUT=");

	if (ptr) {
		verbose_opt = ptr + 13;

		ptr = strchr(verbose_opt, '\'');
		if (!ptr) {
			l_error("Malformed verbose parameter");
			return;
		}

		*ptr = '\0';

		l_info("Enable verbose output for %s", verbose_opt);

		verbose_apps = l_strsplit(verbose_opt, ',');
	}

	ptr = strstr(cmdline, "TESTHOME=");

	if (ptr) {
		exec_home = ptr + 4;
		ptr = strpbrk(exec_home + 9, " \r\n");

		if (ptr)
			*ptr = '\0';
	}

	ptr = strrchr(exec_home, '/');

	if (!ptr)
		exit(EXIT_FAILURE);

	i = ptr - exec_home;

	strncpy(top_level_path, exec_home + 5, i - 5);
	top_level_path[i - 5] = '\0';

	switch (test_action) {
	case ACTION_AUTO_TEST:
		if (native_hw)
			start_hw_discovery();
		else
			run_auto_tests();
		break;
	case ACTION_UNIT_TEST:
		run_unit_tests();
		break;
	}
}

static void usage(void)
{
	l_info("test-runner - Automated test execution utility\n"
		"Usage:\n");
	l_info("\ttest-runner [options] [--] <command> [args]\n");
	l_info("Options:\n"
		"\t-q, --qemu <path>	QEMU binary\n"
		"\t-k, --kernel <image>	Kernel image (bzImage)\n"
		"\t-v, --verbose <apps>	Comma separated list of "
						"applications to enable\n"
						"\t\t\t\tverbose output\n"
		"\t-h, --help		Show help options\n"
		"\t-V, --valgrind		Run valgrind on iwd. Note: \"-v"
						" iwd\" is required\n"
						"\t\t\t\tto see valgrind"
						" output\n"
		"\t-g, --gdb <iwd|hostapd>	Run gdb on the specified"
						" executable\n"
		"\t-w, --hw <config>	Run using a physical hardware "
					"configuration\n"
		"\t-s, --shell		Boot into shell. If -A is used the"
					" environment\n"
					"\t\t\t\twill be setup exactly as it is"
					" in the test,\n"
					"\t\t\t\tbut no test will be run. If no"
					" test is specified\n"
					"\t\t\t\tthe 'shell' test"
					" will be used\n"
		"\t-l, --log <dir>		Directory used for log output. "
					"This option sets \n"
					"\t\t\t\t--verbose on all apps");
	l_info("Commands:\n"
		"\t-A, --auto-tests <dirs>	Comma separated list of the "
						"test configuration\n\t\t\t\t"
						"directories to run\n"
		"\t-U, --unit-tests <tests>	Comma separated list of the "
						"unit tests to run\n");
}

static const struct option main_options[] = {
	{ "auto-tests",	required_argument, NULL, 'A' },
	{ "unit-tests",	optional_argument, NULL, 'U' },
	{ "qemu",	required_argument, NULL, 'q' },
	{ "kernel",	required_argument, NULL, 'k' },
	{ "verbose",	required_argument, NULL, 'v' },
	{ "debug",	optional_argument, NULL, 'd' },
	{ "gdb",	required_argument, NULL, 'g' },
	{ "valgrind",	no_argument,       NULL, 'V' },
	{ "hw",		required_argument, NULL, 'w' },
	{ "shell",	optional_argument, NULL, 's' },
	{ "log",	required_argument, NULL, 'l' },
	{ "help",	no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	uint8_t actions = 0;
	struct tm *timeinfo;
	time_t t;

	l_log_set_stderr();

	if (getpid() == 1 && getppid() == 0) {
		if (!l_main_init())
			return EXIT_FAILURE;

		prepare_sandbox();

		run_tests();

		sync();
		l_info("Done running tests. Rebooting...");

		reboot(RB_AUTOBOOT);
		return EXIT_SUCCESS;
	}

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "A:q:k:v:g:sl:UVdh", main_options,
									NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'A':
			test_action = ACTION_AUTO_TEST;
			test_action_params = optarg;
			actions++;
			break;
		case 'U':
			test_action = ACTION_UNIT_TEST;
			test_action_params = optarg;
			actions++;
			break;
		case 'q':
			qemu_binary = optarg;
			break;
		case 'k':
			kernel_image = optarg;
			break;
		case 'd':
			enable_debug = true;

			if (optarg)
				debug_filter = optarg;
			else
				debug_filter = "*";

			l_debug_enable(debug_filter);
			break;
		case 'v':
			verbose_opt = optarg;
			verbose_apps = l_strsplit(optarg, ',');
			break;
		case 'V':
			valgrind = true;
			break;
		case 'g':
			gdb_opt = optarg;
			if (!gdb_opt || (strcmp(gdb_opt, "iwd") &&
					strcmp(gdb_opt, "hostapd") &&
					strcmp(gdb_opt, "hwsim"))) {
				l_error("--gdb can only be used with iwd"
					", hwsim or hostapd");
				return EXIT_FAILURE;
			}
			break;
		case 'w':
			hw_config = l_settings_new();
			if (!l_settings_load_from_file(hw_config, optarg)) {
				l_error("could not read hw config from %s",
						optarg);
				l_settings_free(hw_config);
				return EXIT_FAILURE;
			}
			break;
		case 's':
			shell = true;
			break;
		case 'l':
			/*
			 * Setup the log directory. This is created under the
			 * passed in log dir (--log) in the format:
			 * <logdir>/run-<year>-<month>-<day>-<PID>
			 *
			 * The created log dir is then chown'ed to the user
			 * who started test-runner, as are all files created
			 * under this directory.
			 */
			log = true;

			if (!optarg)
				optarg = ".";

			time(&t);
			timeinfo = localtime(&t);

			log_gid = atoi(getenv("SUDO_GID"));
			log_uid = atoi(getenv("SUDO_UID"));

			snprintf(log_dir, sizeof(log_dir), "%s/run-%d-%d-%d-%d",
					optarg, timeinfo->tm_year + 1900,
					timeinfo->tm_mon + 1, timeinfo->tm_mday,
					getpid());
			mkdir(log_dir, 0755);

			if (chown(log_dir, log_uid, log_gid) < 0)
				l_error("failed to fchown %s", log_dir);

			break;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		l_error("Invalid command line parameters");
		return EXIT_FAILURE;
	}

	if (actions > 1) {
		l_error("Only one action can be specified");
		return EXIT_FAILURE;
	}

	if (!actions)
		test_action = ACTION_AUTO_TEST;

	own_binary = argv[0];
	test_argv = argv + optind;
	test_argc = argc - optind;

	if (!qemu_binary) {
		qemu_binary = find_qemu();
		if (!qemu_binary) {
			l_error("No default QEMU binary found");
			return EXIT_FAILURE;
		}
	}

	if (!kernel_image) {
		kernel_image = find_kernel();
		if (!kernel_image) {
			l_error("No default kernel image found");
			return EXIT_FAILURE;
		}
	}

	l_info("Using QEMU binary %s", qemu_binary);
	l_info("Using kernel image %s", kernel_image);

	if (!start_qemu())
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
