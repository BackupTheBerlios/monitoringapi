#   Autoconf script for MAPI library
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
AC_CONFIG_SRCDIR([src/libmapi.c])

dnl set up for automake
AM_INIT_AUTOMAKE(libmapi,0.0.1)
AM_CONFIG_HEADER([src/include/config.h:config.in])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_LN_S

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE

AX_CFLAGS_OPTION(LIBMAPI_CFLAGS,[-Wall])
AX_CFLAGS_OPTION(LIBMAPI_CFLAGS,[-finline-functions])
AX_CFLAGS_OPTION(LIBMAPI_CFLAGS,[-funroll-all-loops])
AX_CFLAGS_OPTION(LIBMAPI_CFLAGS,[-O3])

AC_SUBST(LIBMAPI_CFLAGS)

#check for libs
AC_PATH_PCAP

AC_ARG_ENABLE(debug,
	      AC_HELP_STRING([--enable-debug], [Debug MAPI library (disabled by default)]),
	      LIBMAPI_CFLAGS="$LIBMAPI_CFLAGS -g -DDEBUG")

AC_OUTPUT(Makefile		\
	  src/Makefile		\
	  src/include/Makefile	\
	  )
