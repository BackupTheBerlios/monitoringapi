#   Autoconf script for MAPI module
#
#   Written by Konstantinos Xinidis <xinidis@csd.uoc.gr>	
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License
#   as published by the Free Software Foundation; either version
#   2 of the License, or (at your option) any later version.
#

AC_PREREQ(2.57)
AC_INIT(Monitoring API,0.1,xinidis@csd.uoc.gr)
AC_CONFIG_SRCDIR([src/af_mapi.c])

dnl set up for automake
AM_INIT_AUTOMAKE(mapi,0.0.1)
AM_CONFIG_HEADER([src/include/linux/mapi/config.h:config.in])

dnl needed for module build
MAPI_MODULE_DIR=`pwd`
AC_SUBST(MAPI_MODULE_DIR)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
ACX_MODUTILS

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE

AX_CFLAGS_OPTION(MODCFLAGS,[-finline-functions])
AX_CFLAGS_OPTION(MODCFLAGS,[-funroll-all-loops])
AX_CFLAGS_OPTION(MODCFLAGS,[-fomit-frame-pointer])

AC_SUBST(MODCFLAGS)

AX_FIND_KERNEL
AX_CONFIG_MODULE

AC_ARG_ENABLE(debug,
	      AC_HELP_STRING([--enable-debug], [Debug Linux kernel module (disabled by default)]),
	      MODCFLAGS="$MODCFLAGS -g -DDEBUG")

AC_OUTPUT(Makefile				\
	  src/Makefile				\
	  src/profiling/Makefile		\
	  src/functions/Makefile		\
	  src/functions/check/Makefile		\
	  src/functions/cooking/Makefile	\
	  src/functions/cooking/ipv4/Makefile	\
	  src/functions/cooking/udp/Makefile	\
	  src/functions/cooking/tcp/Makefile	\
	  src/functions/count/Makefile		\
	  src/functions/filter/Makefile		\
	  src/functions/flow/Makefile		\
	  src/functions/flow/report/Makefile	\
	  src/functions/flow/subflow/Makefile	\
	  src/functions/logging/Makefile	\
	  src/functions/meter/Makefile		\
	  src/functions/performance/Makefile	\
	  src/functions/print/Makefile		\
	  src/functions/save/Makefile		\
	  src/functions/search/Makefile		\
	  src/functions/tree/Makefile		\
	  src/functions/tree/decide/Makefile	\
	  src/misc/Makefile			\
	  src/include/Makefile			\
	  src/include/linux/Makefile		\
	  src/include/linux/mapi/Makefile	\
	  examples/Rules.make			\
	  )

cp -f doc/config.default .config

dnl ##################################################
dnl # Print summary
dnl ##################################################

dnl Commands for funkier shtool output:
BLD_ON=`./shtool echo -n -e %B`
BLD_OFF=`./shtool echo -n -e %b`

echo "  Setup finished. Now run:"
echo
echo "  # "${BLD_ON}"make qconfig or make gconfig or edit .config"${BLD_OFF}
echo "  # "${BLD_ON}"make"${BLD_OFF}
echo "  # "${BLD_ON}"make install"${BLD_OFF}
echo

dnl end configure.in
