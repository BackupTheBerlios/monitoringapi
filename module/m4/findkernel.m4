dnl Find the kernel and handle 2.5 settings
AC_DEFUN(AX_FIND_KERNEL,
[
	dnl  --- Find the Linux kernel, at least the headers ---
 
	AC_SUBST(KSRC)
	KSRC=/lib/modules/`uname -r`/build
	
	AC_ARG_WITH(linux,
		    AC_HELP_STRING([--with-linux[[=DIR]]], [Linux source code is in DIR]),
		    KSRC=$withval)
	KINC=$KSRC/include
	AC_SUBST(KINC)
]
)
