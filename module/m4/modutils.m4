AC_DEFUN([ACX_MODUTILS],[
AC_PATH_PROG(MODPROBE,modprobe,,$PATH:/sbin)
if test -z "$MODPROBE"; then
  AC_ERROR([modprobe not found])
fi
AC_PATH_PROG(DEPMOD,depmod,,$PATH:/sbin)
if test -z "$DEPMOD"; then
  AC_ERROR([depmod not found])
fi
AC_PATH_PROG(INSMOD,insmod,,$PATH:/sbin)
if test -z "$INSMOD"; then
  AC_MSG_WARN([insmod not found])
fi
AC_PATH_PROG(RMMOD,rmmod,,$PATH:/sbin)
if test -z "$RMMOD"; then
  AC_MSG_WARN([rmmod not found])
fi
])
