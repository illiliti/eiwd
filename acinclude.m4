AC_DEFUN([AC_PROG_CC_PIE], [
	AC_CACHE_CHECK([whether ${CC-cc} accepts -fPIE], ac_cv_prog_cc_pie, [
		echo 'void f(){}' > conftest.c
		if test -z "`${CC-cc} -fPIE -pie -c conftest.c 2>&1`"; then
			ac_cv_prog_cc_pie=yes
		else
			ac_cv_prog_cc_pie=no
		fi
		rm -rf conftest*
	])
])

AC_DEFUN([AC_PROG_CC_ASAN], [
	AC_CACHE_CHECK([whether ${CC-cc} accepts -fsanitize=address], ac_cv_prog_cc_asan, [
		echo 'void f(){}' > conftest.c
		if test -z "`${CC-cc} -fsanitize=address -c conftest.c 2>&1`"; then
			ac_cv_prog_cc_asan=yes
		else
			ac_cv_prog_cc_asan=no
		fi
		rm -rf conftest*
	])
])

AC_DEFUN([AC_PROG_CC_LSAN], [
	AC_CACHE_CHECK([whether ${CC-cc} accepts -fsanitize=leak], ac_cv_prog_cc_lsan, [
		echo 'void f(){}' > conftest.c
		if test -z "`${CC-cc} -fsanitize=leak -c conftest.c 2>&1`"; then
			ac_cv_prog_cc_lsan=yes
		else
			ac_cv_prog_cc_lsan=no
		fi
		rm -rf conftest*
	])
])

AC_DEFUN([AC_PROG_CC_UBSAN], [
	AC_CACHE_CHECK([whether ${CC-cc} accepts -fsanitize=undefined], ac_cv_prog_cc_ubsan, [
		echo 'void f(){}' > conftest.c
		if test -z "`${CC-cc} -fsanitize=undefined -c conftest.c 2>&1`"; then
			ac_cv_prog_cc_ubsan=yes
		else
			ac_cv_prog_cc_ubsan=no
		fi
		rm -rf conftest*
	])
])

AC_DEFUN([COMPILER_FLAGS], [
	if (test "${CFLAGS}" = ""); then
		CFLAGS="-Wall -O2 -fsigned-char -fno-exceptions"
		CFLAGS+=" -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
	fi
	if (test "$USE_MAINTAINER_MODE" = "yes"); then
		CFLAGS+=" -Werror -Wextra"
		CFLAGS+=" -Wno-unused-parameter"
		CFLAGS+=" -Wno-missing-field-initializers"
		CFLAGS+=" -Wdeclaration-after-statement"
		CFLAGS+=" -Wmissing-declarations"
		CFLAGS+=" -Wredundant-decls"
		CFALGS+=" -Wvariadic-macros"
		CFLAGS+=" -Wformat -Wformat-security"
		if ( $CC -v 2>/dev/null | grep "gcc version" ); then
			CFLAGS+=" -Wcast-align"
		fi
	fi

	if (test "$CC" = "clang"); then
		CFLAGS+=" -Wno-unknown-warning-option"
		CFLAGS+=" -Wno-unknown-pragmas"
	fi
])
