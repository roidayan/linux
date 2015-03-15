AC_PREREQ([2.57])
AC_INIT([compat_mlnx], 2.3, [http://support.mellanox.com/SupportWeb/service_center/SelfService], [compat_mlnx])

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([1.10 foreign tar-ustar silent-rules subdir-objects])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC

AM_PROG_AS

AC_CHECK_TOOLS(AR, ar)

SET_BUILD_ARCH
LB_PROG_CC

AC_ARG_WITH(njobs,
	AS_HELP_STRING([--with-njobs=N],[Allow N jobs at once; jobs as number of CPUs with no arg.]),
	[
		NJOBS="$withval"
		if [[ "x$NJOBS" == "x" ]] || [[[ $NJOBS =~ [A-Za-z]+ ]]]; then
			NJOBS=$(grep ^processor /proc/cpuinfo | wc -l)
		fi
	],
	NJOBS=1
)

MLNX_PROG_LINUX
LB_CONDITIONALS
