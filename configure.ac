AC_PREREQ([2.69])
AC_INIT([iwd],[2.12])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(build-aux)

AM_INIT_AUTOMAKE([foreign subdir-objects color-tests silent-rules
					tar-pax no-dist-gzip dist-xz])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

PKG_PROG_PKG_CONFIG

COMPILER_FLAGS

AC_LANG([C])

AC_PROG_CC
AC_PROG_CC_PIE
AC_PROG_CC_ASAN
AC_PROG_CC_LSAN
AC_PROG_CC_UBSAN
AC_PROG_CC_GCOV
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_LN_S

AC_SYS_LARGEFILE

LT_PREREQ(2.2)
LT_INIT([disable-static])

AC_ARG_ENABLE(optimization, AS_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
	if (test "${enableval}" = "no"); then
		CFLAGS="$CFLAGS -O0"
	fi
])

if (test "${enable_optimization}" != "no"); then
	CFLAGS="$CFLAGS -O2"
	CFLAGS="$CFLAGS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
fi

AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi
])

AC_ARG_ENABLE(gcov, AS_HELP_STRING([--enable-gcov],
			[enable compiling with code coverage information]), [
	if (test "${enableval}" = "yes" &&
			test "${ac_cv_prog_cc_profile_arcs}" = "yes" &&
			test "${ac_cv_prog_cc_test_coverage}" = "yes"); then
		CFLAGS="$CFLAGS -fprofile-arcs -ftest-coverage"
	fi
])

if (test "${enable_gcov}" = "yes"); then
	AC_CHECK_PROGS(LCOV, [lcov], "no")
	AC_CHECK_PROGS(GENHTML, [genhtml], "no")
	if (test "${LCOV}" == "no"); then
		AC_MSG_ERROR([lcov is required])
	fi
	if (test "${GENHTML}" == "no"); then
		AC_MSG_ERROR([genhtml is required])
	fi
fi

AM_CONDITIONAL(GCOV, test "${enable_gcov}" != "no")

AC_ARG_ENABLE(pie, AS_HELP_STRING([--enable-pie],
			[enable position independent executables flag]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi
])

save_LIBS=$LIBS
AC_CHECK_LIB(asan, _init)
LIBS=$save_LIBS

AC_ARG_ENABLE(asan, AS_HELP_STRING([--enable-asan],
			[enable linking with address sanitizer]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_asan__init}" = "yes" &&
				test "${ac_cv_prog_cc_asan}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=address";
		LDFLAGS="$LDFLAGS -fsanitize=address"
	fi
])

save_LIBS=$LIBS
AC_CHECK_LIB(lsan, _init)
LIBS=$save_LIBS

AC_ARG_ENABLE(lsan, AS_HELP_STRING([--enable-lsan],
			[enable linking with leak sanitizer]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_lsan__init}" = "yes" &&
				test "${ac_cv_prog_cc_lsan}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=leak";
		LDFLAGS="$LDFLAGS -fsanitize=leak"
	fi
])

save_LIBS=$LIBS
AC_CHECK_LIB(ubsan, _init)
LIBS=$save_LIBS

AC_ARG_ENABLE(ubsan, AS_HELP_STRING([--enable-ubsan],
			[enable linking with undefined behavior sanitizer]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_ubsan__init}" = "yes" &&
				test "${ac_cv_prog_cc_ubsan}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=undefined";
		LDFLAGS="$LDFLAGS -fsanitize=undefined"
	fi
])
if (test "${prefix}" = "NONE"); then
	dnl no prefix and no localstatedir, so default to /var
	if (test "$localstatedir" = '${prefix}/var'); then
		AC_SUBST([localstatedir], ['/var'])
	fi

	prefix="${ac_default_prefix}"
fi

if (test "$localstatedir" = '${prefix}/var'); then
	daemon_storagedir="${prefix}/var/lib/iwd"
	wired_storagedir="${prefix}/var/lib/ead"
else
	daemon_storagedir="${localstatedir}/lib/iwd"
	wired_storagedir="${localstatedir}/lib/ead"
fi

AC_SUBST([daemon_storagedir], [${daemon_storagedir}])
AC_SUBST([wired_storagedir], [${wired_storagedir}])

AC_DEFINE_UNQUOTED(DAEMON_STORAGEDIR, "${daemon_storagedir}",
			[Directory for Wireless daemon storage files])
AC_DEFINE_UNQUOTED(DAEMON_CONFIGDIR, "/etc/iwd",
			[Directory for Wireless daemon configuration])

AC_DEFINE_UNQUOTED(WIRED_STORAGEDIR, "${wired_storagedir}",
			[Directory for Ethernet daemon storage files])

AC_CHECK_FUNCS(explicit_bzero)
AC_CHECK_FUNCS(rawmemchr)
AC_CHECK_FUNCS(reallocarray)

AC_CHECK_HEADERS(linux/types.h linux/if_alg.h)

# In maintainer mode: try to build with application backtrace and disable PIE.
if (test "${USE_MAINTAINER_MODE}" = yes); then
	AC_SEARCH_LIBS([backtrace], [execinfo],
		[
			AC_DEFINE([HAVE_BACKTRACE], [1],
				[Define to 1 if you have backtrace(3).])
			CFLAGS="$CFLAGS -fno-PIE"
			LDFLAGS="$LDFLAGS -no-pie"
		])
fi

AC_ARG_ENABLE([daemon], AS_HELP_STRING([--disable-daemon],
				[don't install iwd system daemon]),
					[enable_daemon=${enableval}])
AM_CONDITIONAL(DAEMON, test "${enable_daemon}" != "no")

AC_ARG_ENABLE([client], AS_HELP_STRING([--disable-client],
				[don't install iwctl client utility]),
					[enable_client=${enableval}])
if (test "${enable_client}" != "no"); then
	if (test "${enable_libedit}" = "yes"); then
		PKG_CHECK_MODULES(LIBEDIT, libedit >= 3.1, dummy=yes,
				AC_MSG_ERROR(Editline library is required))
		AC_SUBST(LIBEDIT_CFLAGS)
		AC_SUBST(LIBEDIT_LIBS)
	else
		PKG_CHECK_MODULES(READLINE, readline, dummy=yes,
				AC_MSG_ERROR(Readline library is required))
		AC_SUBST(READLINE_CFLAGS)
		AC_SUBST(READLINE_LIBS)
	fi
fi
AM_CONDITIONAL(CLIENT, test "${enable_client}" != "no")

AC_ARG_ENABLE([monitor], AS_HELP_STRING([--disable-monitor],
				[don't install iwmon monitor utility]),
					[enable_monitor=${enableval}])
AM_CONDITIONAL(MONITOR, test "${enable_monitor}" != "no")

AC_ARG_ENABLE([dbus-policy], AS_HELP_STRING([--disable-dbus-policy],
				[don't install D-Bus system policy files]),
					[enable_dbus_policy=${enableval}])
AM_CONDITIONAL(DBUS_POLICY, test "${enable_dbus_policy}" != "no")

AC_ARG_WITH([dbus-datadir], AS_HELP_STRING([--with-dbus-datadir=DIR],
				[path to D-Bus data directory]),
					[path_dbus_datadir=${withval}])
if (test "${enable_dbus_policy}" != "no" && test -z "${path_dbus_datadir}"); then
	AC_MSG_CHECKING([D-Bus data directory])
	path_dbus_datadir="`$PKG_CONFIG --variable=datadir dbus-1`"
	if (test -z "${path_dbus_datadir}"); then
		path_dbus_datadir="`$PKG_CONFIG --variable=sysconfdir dbus-1`"
		if (test -z "${path_dbus_datadir}"); then
			AC_MSG_ERROR([D-Bus data directory is required])
		fi
	fi
	AC_MSG_RESULT([${path_dbus_datadir}])
fi
AC_SUBST(DBUS_DATADIR, [${path_dbus_datadir}])

AC_ARG_ENABLE([systemd-service], AS_HELP_STRING([--disable-systemd-service],
				[don't install systemd service files]),
					[enable_systemd_service=${enableval}])
AM_CONDITIONAL(SYSTEMD_SERVICE, test "${enable_systemd_service}" != "no")

AC_ARG_ENABLE([manual-pages], AS_HELP_STRING([--disable-manual-pages],
				[don't install manual pages]),
					[enable_manual_pages=${enableval}])
if (test "${enable_manual_pages}" != "no"); then
	AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], "no")
fi
AM_CONDITIONAL(MANUAL_PAGES, test "${enable_manual_pages}" != "no")
AM_CONDITIONAL(RUN_RST2MAN, test "${enable_manual_pages}" != "no" && test "${RST2MAN}" != "no")

AC_ARG_WITH([dbus-busdir], AS_HELP_STRING([--with-dbus-busdir=DIR],
				[path to D-Bus bus services directory]),
					[path_dbus_busdir=${withval}])
if (test "${enable_systemd_service}" != "no" && test -z "${path_dbus_busdir}"); then
	AC_MSG_CHECKING([D-Bus bus services directory])
	path_dbus_busdir="`$PKG_CONFIG --variable=system_bus_services_dir dbus-1`"
	if (test -z "${path_dbus_busdir}"); then
		AC_MSG_ERROR([D-Bus bus services directory is required])
	fi
	AC_MSG_RESULT([${path_dbus_busdir}])
fi
AC_SUBST(DBUS_BUSDIR, [${path_dbus_busdir}])

AC_ARG_WITH([systemd-unitdir], AS_HELP_STRING([--with-systemd-unitdir=DIR],
				[path to systemd unit directory]),
					[path_systemd_unitdir=${withval}])
if (test "${enable_systemd_service}" != "no" && test -z "${path_systemd_unitdir}"); then
	AC_MSG_CHECKING([systemd unit directory])
	path_systemd_unitdir="`$PKG_CONFIG --variable=systemdsystemunitdir systemd`"
	if (test -z "${path_systemd_unitdir}"); then
		AC_MSG_ERROR([systemd unit directory is required])
	fi
	AC_MSG_RESULT([${path_systemd_unitdir}])
fi
AC_SUBST(SYSTEMD_UNITDIR, [${path_systemd_unitdir}])

AC_ARG_WITH([systemd-networkdir], AS_HELP_STRING([--with-systemd-networkdir=DIR],
				[path to systemd network directory]),
					[path_systemd_networkdir=${withval}])
if (test "${enable_systemd_service}" != "no" && test -z "${path_systemd_networkdir}"); then
	AC_MSG_CHECKING([systemd network directory])
	path_systemd_networkdir="`$PKG_CONFIG --variable=systemdutildir systemd`"
	if (test -z "${path_systemd_networkdir}"); then
		AC_MSG_ERROR([systemd network directory is required])
	fi
	path_systemd_networkdir="${path_systemd_networkdir}/network"
	AC_MSG_RESULT([${path_systemd_networkdir}])
fi
AC_SUBST(SYSTEMD_NETWORKDIR, [${path_systemd_networkdir}])

AC_ARG_WITH([systemd-modloaddir], AS_HELP_STRING([--with-systemd-modloaddir=DIR],
				[path to systemd modules load directory]),
					[path_systemd_modloaddir=${withval}])
if (test "${enable_systemd_service}" != "no" && test -z "${path_systemd_modloaddir}"); then
	AC_MSG_CHECKING([systemd modules load directory])
	path_systemd_modloaddir="`$PKG_CONFIG --variable=modulesloaddir systemd`"
	if (test -z "${path_systemd_modloaddir}"); then
		AC_MSG_ERROR([systemd modules load directory is required])
	fi
	AC_MSG_RESULT([${path_systemd_modloaddir}])
fi
AC_SUBST(SYSTEMD_MODLOADDIR, [${path_systemd_modloaddir}])

AC_ARG_ENABLE([external_ell], AS_HELP_STRING([--enable-external-ell],
				[enable external Embedded Linux library]),
					[enable_external_ell=${enableval}])
if (test "${enable_external_ell}" = "yes"); then
	if (test "${enable_daemon}" != "no" ||
			test "${enable_client}" != "no" ||
			test "${enable_monitor}" != "no" ||
			test "${enable_wired}" = "yes" ||
			test "${enable_hwsim}" = "yes"); then
		ell_min_version="0.61"
	else
		ell_min_version="0.5"
	fi
	PKG_CHECK_MODULES(ELL, ell >= ${ell_min_version}, dummy=yes,
		AC_MSG_ERROR(Embedded Linux library >= ${ell_min_version} is required))
	AC_SUBST(ELL_CFLAGS)
	AC_SUBST(ELL_LIBS)
fi
AM_CONDITIONAL(EXTERNAL_ELL, test "${enable_external_ell}" = "yes")

AC_ARG_ENABLE([libedit], AS_HELP_STRING([--enable-libedit],
				[enable Editline library instead of Readline]),
					[enable_libedit=${enableval}])
AM_CONDITIONAL(LIBEDIT, test "${enable_libedit}" = "yes")

AC_ARG_ENABLE([wired], AS_HELP_STRING([--enable-wired],
				[enable Ethernet authentication support]),
					[enable_wired=${enableval}])
AM_CONDITIONAL(WIRED, test "${enable_wired}" = "yes")

AC_ARG_ENABLE([hwsim], AS_HELP_STRING([--enable-hwsim],
				[enable Wireless simulation utility]),
					[enable_hwsim=${enableval}])
AM_CONDITIONAL(HWSIM, test "${enable_hwsim}" = "yes")

AC_ARG_ENABLE([tools], AS_HELP_STRING([--enable-tools],
				[enable internal testing utilities]),
					[enable_tools=${enableval}])
AM_CONDITIONAL(TOOLS, test "${enable_tools}" = "yes")

AC_ARG_ENABLE([ofono], AS_HELP_STRING([--enable-ofono],
				[enable oFono SIM authentication support]),
					[enable_ofono=${enableval}])
AM_CONDITIONAL(OFONO, test "${enable_ofono}" = "yes")

AC_CONFIG_FILES(Makefile)

AC_OUTPUT

AC_MSG_RESULT([
	$PACKAGE_NAME $VERSION
])
