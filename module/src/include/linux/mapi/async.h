/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_ASYNC_
#define __MAPI_ASYNC_

#include <linux/mapi/compat.h>


#if V_AT_LEAST(2,6,0)
#include <linux/file.h>
#else
#include <linux/sched.h>
#endif

#ifdef __KERNEL__

static inline int get_fd_from_file(struct task_struct *process,struct file *filp)
{
	int ret = -1;
	struct files_struct *files;
	int i = 0;
	
	files = process->files;
	
	//mapi_files_read_lock(files);
	
	for( i = 0 ; i < files->max_fdset ; i++)
	{
		if(files->fd[i] == filp)
		{
			ret = i;

			break;	
		}
	}
	
	//mapi_files_read_unlock(files);
	
	return ret;
}

static inline int add_async_notification(struct sock *sk,struct fasync_struct **notify_queue,pid_t pid)
{
	struct task_struct *process;
	struct file *filp;
	int ret = 0;
	int fd;
	
	filp = mapi_sk_socket(sk)->file;
	
	lock_kernel();
	
	if((process = find_task_by_pid(pid)) == NULL)
	{
		return -ESRCH;
	}
	
	filp->f_owner.pid = pid;
	filp->f_owner.uid = process->uid;
	filp->f_owner.euid = process->euid;
	filp->f_flags |= FASYNC;
	
	/*if(S_ISSOCK(filp->f_dentry->d_inode->i_mode))
	{
		ret = sock_fcntl(filp,F_SETOWN,pid);
	}*/
	
	unlock_kernel();
	
	if((fd = get_fd_from_file(process,filp)) == -1)
	{
		return -ENOENT;
	}
	
	if((ret = fasync_helper(fd,filp,filp->f_mode,notify_queue)) < 0)
	{
		return ret;
	}
	
	return 0;
}

static inline int remove_async_notification(struct sock *sk,struct fasync_struct **notify_queue)
{
	struct file *filp;
	int ret = 0;
	
	filp = mapi_sk_socket(sk)->file;
	
	lock_kernel();
	filp->f_flags &= ~FASYNC;
	unlock_kernel();

	if((ret = fasync_helper(-1,mapi_sk_socket(sk)->file,0,notify_queue)) < 0)
	{
		return ret;
	}
	
	return 0;
}

#endif /* __KERNEL__ */

#endif /* __MAPI_ASYNC_ */
