/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_COMPAT_H_
#define __MAPI_COMPAT_H_

#include <linux/version.h>

#define V_BEFORE(a,b,c) (LINUX_VERSION_CODE < KERNEL_VERSION(a,b,c))
#define V_AT_LEAST(a,b,c) (LINUX_VERSION_CODE >= KERNEL_VERSION(a,b,c))

#include <linux/mapi/compat/sock.h>

#ifdef __KERNEL__

#if V_BEFORE(2,6,0)

#include <linux/mapi/compat/list.h>
#include <linux/mapi/compat/sock_list.h>

#define mapi_sock_from_inode(__inode)	(&__inode->u.socket_i)
#define mapi_module_put(__module)	(__MOD_DEC_USE_COUNT(__module))

static inline int mapi_module_get(struct module *module)
{
	__MOD_INC_USE_COUNT(module);
		
	return 0;
}

#define mapi_files_read_lock(__f)	(read_lock(&(__f->file_lock)))
#define mapi_files_read_unlock(__f)	(read_unlock(&(__f->file_lock)))

#else

#define mapi_sock_from_inode(__inode)	(SOCKET_I(__inode))
#define mapi_module_get(__module)	(try_module_get(__module))
#define mapi_module_put(__module)	(module_put(__module))
#define mapi_files_read_lock(__f)	(spin_lock(&(__f->file_lock)))
#define mapi_files_read_unlock(__f)	(spin_unlock(&(__f->file_lock)))

#define EXPORT_NO_SYMBOLS		

#endif

#endif /* __KERNEL__ */

#endif /* __MAPI_COMPAT_H_ */
