#
# This macro implements a check for libpcap and pcap.h.
# It also adds --with-pcap-headers and --with-pcap-lib
# options to the configure script so that the user can
# provide his own preferences.
AC_DEFUN([AC_PATH_PCAP],
[AC_ARG_WITH(pcap-headers,
            AC_HELP_STRING([--with-pcap-headers=PATH], [Add PATH to include paths searched for pcap.h]),
	    CPPFLAGS="$CPPFLAGS -I$withval")

AC_ARG_WITH(pcap-lib,
            AC_HELP_STRING([--with-pcap-lib=PATH], [Add PATH to paths searched for pcap library files]),
	    LIBS="-L$withval $LIBS")

ck_pcap_found="no"
AC_CHECK_HEADERS(pcap.h, ck_pcap_found="yes")
if test "$ck_pcap_found" = "no"; then
	AC_MSG_NOTICE([adjusting include paths])
	CPPFLAGS="$CPPFLAGS -I/usr/include/pcap -I/usr/local/include/pcap"
dnl This is so ugly it's no fun -- I don't want this crap
dnl to be cached! How can I prevent this!?
	unset ac_cv_header_pcap_h
	AC_CHECK_HEADERS(pcap.h, [ck_pcap_found="yes"])
fi

if test "$ck_pcap_found" = "no"; then cat <<EOF;
------------------------------------------------------
ERROR: Could not find pcap.h on this system.
------------------------------------------------------
EOF
exit 1
fi

ck_pcap_found="yes"
AC_CHECK_LIB(pcap, main, , ck_pcap_found="no")
if test "$ck_pcap_found" = "no"; then cat <<EOF;
------------------------------------------------------
ERROR: Could not find libpcap on this system.
------------------------------------------------------
EOF
fi
])# AC_PATH_PCAP
