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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/rtnetlink.h>
#include <ell/ell.h>

#include <ell/useful.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/module.h"
#include "src/wiphy.h"
#include "src/dbus.h"
#include "src/eap.h"
#include "src/eapol.h"
#include "src/rfkill.h"
#include "src/storage.h"
#include "src/anqp.h"
#include "src/netconfig.h"
#include "src/crypto.h"

#include "src/backtrace.h"

static struct l_genl *genl;
static struct l_netlink *rtnl;
static struct l_settings *iwd_config;
static struct l_timeout *timeout;
static const char *interfaces;
static const char *nointerfaces;
static const char *phys;
static const char *nophys;
static const char *debugopt;
static const char *logger;
static bool developeropt;
static bool terminating;
static bool nl80211_complete;

static void main_loop_quit(struct l_timeout *timeout, void *user_data)
{
	l_main_quit();
}

static void iwd_shutdown(void)
{
	if (terminating)
		return;

	terminating = true;

	if (!nl80211_complete) {
		l_main_quit();
		return;
	}

	dbus_shutdown();
	netdev_shutdown();

	timeout = l_timeout_create(1, main_loop_quit, NULL, NULL);
}

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		iwd_shutdown();
		break;
	}
}

const struct l_settings *iwd_get_config(void)
{
	return iwd_config;
}

struct l_genl *iwd_get_genl(void)
{
	return genl;
}

struct l_netlink *iwd_get_rtnl(void)
{
	return rtnl;
}

const char *iwd_get_iface_whitelist(void)
{
	return interfaces;
}

const char *iwd_get_iface_blacklist(void)
{
	return nointerfaces;
}

const char *iwd_get_phy_whitelist(void)
{
	return phys;
}

const char *iwd_get_phy_blacklist(void)
{
	return nophys;
}

bool iwd_is_developer_mode(void)
{
	return developeropt;
}

static void usage(void)
{
	printf("iwd - Wireless daemon\n"
		"Usage:\n");
	printf("\tiwd [options]\n");
	printf("Options:\n"
		"\t-E, --developer        Enable developer mode\n"
		"\t-i, --interfaces       Interfaces to manage\n"
		"\t-I, --nointerfaces     Interfaces to ignore\n"
		"\t-p, --phys             Phys to manage\n"
		"\t-P, --nophys           Phys to ignore\n"
		"\t-d, --debug            Enable debug output\n"
		"\t-l, --logger           Override default stderr logging\n"
		"\t-v, --version          Show version\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "developer",    no_argument,       NULL, 'E' },
	{ "version",      no_argument,       NULL, 'v' },
	{ "interfaces",   required_argument, NULL, 'i' },
	{ "nointerfaces", required_argument, NULL, 'I' },
	{ "phys",         required_argument, NULL, 'p' },
	{ "nophys",       required_argument, NULL, 'P' },
	{ "logger",       required_argument, NULL, 'l' },
	{ "debug",        optional_argument, NULL, 'd' },
	{ "help",         no_argument,       NULL, 'h' },
	{ }
};

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void nl80211_appeared(const struct l_genl_family_info *info,
							void *user_data)
{
	l_debug("Found nl80211 interface");

	nl80211_complete = true;

	if (iwd_modules_init() < 0) {
		l_main_quit();
		return;
	}
}

static void request_name_callback(struct l_dbus *dbus, bool success,
					bool queued, void *user_data)
{
	if (!success) {
		l_error("Name request failed");
		goto fail_exit;
	}

	if (!l_dbus_object_manager_enable(dbus, "/"))
		l_warn("Unable to register the ObjectManager");

	if (!l_dbus_object_add_interface(dbus, IWD_BASE_PATH,
						IWD_DAEMON_INTERFACE,
						NULL) ||
			!l_dbus_object_add_interface(dbus, IWD_BASE_PATH,
						L_DBUS_INTERFACE_PROPERTIES,
						NULL))
		l_info("Unable to add %s and/or %s at %s",
			IWD_DAEMON_INTERFACE, L_DBUS_INTERFACE_PROPERTIES,
			IWD_BASE_PATH);

	/* TODO: Always request nl80211 for now, ignoring auto-loading */
	l_genl_request_family(genl, NL80211_GENL_NAME, nl80211_appeared,
				NULL, NULL);
	return;

fail_exit:
	l_main_quit();
}

static struct l_dbus_message *iwd_dbus_get_info(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct l_dbus_message *reply =
				l_dbus_message_new_method_return(message);
	_auto_(l_free) char *storage_dir = storage_get_path(NULL);

	l_dbus_message_set_arguments(reply, "a{sv}", 3,
					"NetworkConfigurationEnabled",
					"b", netconfig_enabled(),
					"StateDirectory", "s", storage_dir,
					"Version", "s", VERSION);

	return reply;
}

static void iwd_setup_deamon_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "GetInfo", 0, iwd_dbus_get_info,
				"a{sv}", "", "info");
}

static void dbus_ready(void *user_data)
{
	struct l_dbus *dbus = user_data;

	l_dbus_name_acquire(dbus, "net.connman.iwd", false, false, false,
				request_name_callback, NULL);

	l_dbus_register_interface(dbus, IWD_DAEMON_INTERFACE,
					iwd_setup_deamon_interface,
					NULL, false);
}

static void dbus_disconnected(void *user_data)
{
	l_info("D-Bus disconnected, quitting...");
	iwd_shutdown();
}

static void print_koption(const void *key, void *value, void *user_data)
{
	l_info("\t%s", (const char *) key);
}

#define ADD_MISSING(opt) \
	l_hashmap_replace(options, opt, &r, NULL)

#define ADD_OPTIONAL(opt) \
	l_hashmap_replace(optional, opt, &r, NULL)

static int check_crypto(void)
{
	int r = 0;
	struct l_hashmap *options = l_hashmap_string_new();
	struct l_hashmap *optional = l_hashmap_string_new();

	if (!l_checksum_is_supported(L_CHECKSUM_SHA1, true)) {
		r = -ENOTSUP;
		l_error("No HMAC(SHA1) support found");
		ADD_MISSING("CONFIG_CRYPTO_USER_API_HASH");
		ADD_MISSING("CONFIG_CRYPTO_SHA1");
		ADD_MISSING("CONFIG_CRYPTO_HMAC");
		ADD_OPTIONAL("CONFIG_CRYPTO_SHA1_SSSE3");
	}

	if (!l_checksum_is_supported(L_CHECKSUM_MD5, true)) {
		r = -ENOTSUP;
		l_error("No HMAC(MD5) support found");
		ADD_MISSING("CONFIG_CRYPTO_USER_API_HASH");
		ADD_MISSING("CONFIG_CRYPTO_MD5");
		ADD_MISSING("CONFIG_CRYPTO_HMAC");
	}

	if (!l_checksum_cmac_aes_supported()) {
		r = -ENOTSUP;
		l_error("No CMAC(AES) support found");
		ADD_MISSING("CONFIG_CRYPTO_USER_API_HASH");
		ADD_MISSING("CONFIG_CRYPTO_AES");
		ADD_MISSING("CONFIG_CRYPTO_CMAC");
		ADD_OPTIONAL("CONFIG_CRYPTO_AES_X86_64");
		ADD_OPTIONAL("CONFIG_CRYPTO_AES_NI_INTEL");
	}

	if (!l_checksum_is_supported(L_CHECKSUM_SHA256, true)) {
		r = -ENOTSUP;
		l_error("No HMAC(SHA256) support not found");
		ADD_MISSING("CONFIG_CRYPTO_USER_API_HASH");
		ADD_MISSING("CONFIG_CRYPTO_HMAC");
		ADD_MISSING("CONFIG_CRYPTO_SHA256");
		ADD_OPTIONAL("CONFIG_CRYPTO_SHA256_SSSE3");
	}

	if (!l_checksum_is_supported(L_CHECKSUM_SHA512, true)) {
		l_warn("No HMAC(SHA512) support found, "
				"certain TLS connections might fail");
		ADD_MISSING("CONFIG_CRYPTO_SHA512");
		ADD_OPTIONAL("CONFIG_CRYPTO_SHA512_SSSE3");
	}

	if (!l_cipher_is_supported(L_CIPHER_DES) ||
			!l_cipher_is_supported(L_CIPHER_DES3_EDE_CBC)) {
		r = -ENOTSUP;
		l_error("DES support not found");
		ADD_MISSING("CONFIG_CRYPTO_USER_API_SKCIPHER");
		ADD_MISSING("CONFIG_CRYPTO_DES");
		ADD_MISSING("CONFIG_CRYPTO_ECB");
		ADD_OPTIONAL("CONFIG_CRYPTO_DES3_EDE_X86_64");
	}

	if (!l_cipher_is_supported(L_CIPHER_AES)) {
		r = -ENOTSUP;
		l_error("AES support not found");
		ADD_MISSING("CONFIG_CRYPTO_USER_API_SKCIPHER");
		ADD_MISSING("CONFIG_CRYPTO_AES");
		ADD_MISSING("CONFIG_CRYPTO_ECB");
		ADD_OPTIONAL("CONFIG_CRYPTO_AES_X86_64");
		ADD_OPTIONAL("CONFIG_CRYPTO_AES_NI_INTEL");
	}

	if (!l_cipher_is_supported(L_CIPHER_DES3_EDE_CBC)) {
		l_warn("No CBC(DES3_EDE) support found, "
				"certain TLS connections might fail");
		ADD_MISSING("CONFIG_CRYPTO_DES");
		ADD_MISSING("CONFIG_CRYPTO_CBC");
		ADD_OPTIONAL("CONFIG_CRYPTO_DES3_EDE_X86_64");
	}

	if (!l_cipher_is_supported(L_CIPHER_AES_CBC)) {
		l_warn("No CBC(AES) support found, "
				"WPS will not be available");
		ADD_MISSING("CONFIG_CRYPTO_CBC");
	}

	if (!l_key_is_supported(L_KEY_FEATURE_DH)) {
		l_warn("No Diffie-Hellman support found, "
				"WPS will not be available");
		ADD_MISSING("CONFIG_KEY_DH_OPERATIONS");
	}

	if (!l_key_is_supported(L_KEY_FEATURE_RESTRICT)) {
		l_warn("No keyring restrictions support found.");
		ADD_MISSING("CONFIG_KEYS");
	}

	if (!l_key_is_supported(L_KEY_FEATURE_CRYPTO)) {
		l_warn("No asymmetric key support found.");
		l_warn("TLS based WPA-Enterprise authentication methods will"
				" not function.");
		l_warn("Kernel 4.20+ is required for this feature.");
		ADD_MISSING("CONFIG_ASYMMETRIC_KEY_TYPE");
		ADD_MISSING("CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE");
		ADD_MISSING("CONFIG_X509_CERTIFICATE_PARSER");
		ADD_MISSING("CONFIG_PKCS7_MESSAGE_PARSER");
		ADD_MISSING("CONFIG_PKCS8_PRIVATE_KEY_PARSER");
	}

	if (l_hashmap_isempty(options))
		goto done;

	l_info("The following options are missing in the kernel:");

	if (l_hashmap_remove(options, "CONFIG_CRYPTO_USER_API_HASH"))
		l_info("\tCONFIG_CRYPTO_USER_API_HASH");

	if (l_hashmap_remove(options, "CONFIG_CRYPTO_USER_API_SKCIPHER"))
		l_info("\tCONFIG_CRYPTO_USER_API_SKCIPHER");

	l_hashmap_foreach(options, print_koption, NULL);

	if (!l_hashmap_isempty(optional)) {
		l_info("The following optimized implementations might be "
			"available:");
		l_hashmap_foreach(optional, print_koption, NULL);
	}

done:
	l_hashmap_destroy(options, NULL);
	l_hashmap_destroy(optional, NULL);

	return r;
}

/*
 * Initialize a systemd encryption key for encrypting/decrypting credentials.
 */
static bool setup_system_key(void)
{
	int fd;
	struct stat st;
	const char *cred_dir;
	void *key = NULL;
	_auto_(l_free) char *path = NULL;
	_auto_(l_free) char *key_id = NULL;
	bool r = false;

	key_id = l_settings_get_string(iwd_config, "General",
							"SystemdEncrypt");
	if (!key_id)
		return true;

	cred_dir = getenv("CREDENTIALS_DIRECTORY");
	if (!cred_dir) {
		l_warn("SystemdEncrypt enabled but CREDENTIALS_DIRECTORY not "
			"set, check iwd.service file");
		return false;
	}

	path = l_strdup_printf("%s/%s", cred_dir, key_id);

	fd = open(path, O_RDONLY, 0);
	if (fd < 0) {
		l_warn("SystemdEncrypt: Cannot open secret: %s (%d)",
				strerror(errno), errno);
		return false;
	}

	if (fstat(fd, &st) < 0 || st.st_size == 0)
		goto close_fd;

	key = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (key == MAP_FAILED) {
		l_warn("SystemdEncrypt: can't mmap secret: %s (%d)",
				strerror(errno), errno);
		goto close_fd;
	}

	if (mlock(key, st.st_size) < 0) {
		l_warn("SystemdEncrypt: Failed to mlock secrets file");
		goto unmap;
	}

	r = storage_init(key, st.st_size);
	munlock(key, st.st_size);

unmap:
	munmap(key, st.st_size);
close_fd:
	close(fd);

	return r;
}

int main(int argc, char *argv[])
{
	int exit_status;
	struct l_dbus *dbus;
	const char *config_dir;
	char **config_dirs;
	int i;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "Ei:I:p:P:d::vhl:",
							main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'E':
			developeropt = true;
			break;
		case 'i':
			interfaces = optarg;
			break;
		case 'I':
			nointerfaces = optarg;
			break;
		case 'p':
			phys = optarg;
			break;
		case 'P':
			nophys = optarg;
			break;
		case 'd':
			if (optarg)
				debugopt = optarg;
			else if (argv[optind] && argv[optind][0] != '-')
				debugopt = argv[optind++];
			else
				debugopt = "*";
			break;
		case 'l':
			logger = optarg;
			break;
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	if (logger && !strcmp(logger, "syslog"))
		l_log_set_syslog();
	else if (logger && !strcmp(logger, "journal"))
		l_log_set_journal();
	else
		l_log_set_stderr();

	l_log_set_ident("iwd");

	if (check_crypto() < 0)
		return EXIT_FAILURE;

	if (!l_main_init())
		return EXIT_FAILURE;

	if (debugopt)
		l_debug_enable(debugopt);

#ifdef HAVE_BACKTRACE
	__iwd_backtrace_init();
#endif

	l_info("Wireless daemon version %s", VERSION);

	config_dir = getenv("CONFIGURATION_DIRECTORY");
	if (!config_dir)
		config_dir = DAEMON_CONFIGDIR;

	l_debug("Using configuration directory %s", config_dir);

	iwd_config = l_settings_new();

	config_dirs = l_strsplit(config_dir, ':');

	for (i = 0; config_dirs[i]; i++) {
		L_AUTO_FREE_VAR(char *, path) =
			l_strdup_printf("%s/%s", config_dirs[i], "main.conf");

		if (!l_settings_load_from_file(iwd_config, path))
			continue;

		l_info("Loaded configuration from %s", path);
		break;
	}

	l_strv_free(config_dirs);

	__eapol_set_config(iwd_config);
	__eap_set_config(iwd_config);

	exit_status = EXIT_FAILURE;

	if (!storage_create_dirs())
		goto failed_dirs;

	genl = l_genl_new();
	if (!genl) {
		l_error("Failed to open generic netlink socket");
		goto failed_genl;
	}

	if (getenv("IWD_GENL_DEBUG"))
		l_genl_set_debug(genl, do_debug, "[GENL] ", NULL);

	rtnl = l_netlink_new(NETLINK_ROUTE);
	if (!rtnl) {
		l_error("Failed to open route netlink socket");
		goto failed_rtnl;
	}

	if (getenv("IWD_RTNL_DEBUG"))
		l_netlink_set_debug(rtnl, do_debug, "[RTNL] ", NULL);

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	if (!dbus) {
		l_error("Failed to initialize D-Bus");
		goto failed_dbus;
	}

	l_dbus_set_ready_handler(dbus, dbus_ready, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, dbus_disconnected, NULL, NULL);
	dbus_init(dbus);

	if (!setup_system_key())
		goto failed_storage;

	exit_status = l_main_run_with_signal(signal_handler, NULL);

	iwd_modules_exit();
	storage_exit();

failed_storage:
	dbus_exit();
	l_dbus_destroy(dbus);

failed_dbus:
	l_netlink_destroy(rtnl);

failed_rtnl:
	l_genl_unref(genl);

failed_genl:
	storage_cleanup_dirs();

failed_dirs:
	l_settings_free(iwd_config);
	l_timeout_remove(timeout);
	l_main_exit();

	return exit_status;
}
