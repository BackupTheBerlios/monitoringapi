dnl Handle the 2.4 module inside module/
AC_DEFUN(AX_CONFIG_MODULE,
[
if test ! -f $KINC/linux/autoconf.h; then
	AC_MSG_ERROR([no suitably configured kernel include tree found])
fi

dnl  --- Get Linux kernel version and compile parameters ---

AC_SUBST(KVERS)
AC_MSG_CHECKING([for kernel version])
dnl it's like this to handle mandrake's fubar version.h - bug #471448
eval KVERS=`gcc -I$KINC -E -dM $KINC/linux/version.h | grep -w UTS_RELEASE | awk '{print $[]3}'`
AC_MSG_RESULT([$KVERS])
case "$KVERS" in
2.4.*) KSERIES="2.4" ;;
2.6.*) KSERIES="2.6" ;;
*) AC_MSG_ERROR([Unsupported kernel version])
esac

AC_SUBST(KSERIES)

dnl Check for the minimal kernel version supported
dnl AC_MSG_CHECKING([kernel version])
dnl AX_KERNEL_VERSION(2, 4, 18, >= , AC_MSG_RESULT([ok]), AC_MSG_ERROR([unsupported]))

dnl for now we do not support PREEMPT patch
AC_MSG_CHECKING([for preempt patch])
AX_KERNEL_OPTION(CONFIG_PREEMPT,preempt=1,preempt=0)
AX_MSG_RESULT_YN([$preempt])
test "$preempt" = 0 || AC_MSG_ERROR([unsupported kernel configuration : CONFIG_PREEMPT])
]
AC_SUBST(KINC)
)
