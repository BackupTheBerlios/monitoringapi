/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/fs.h>

#include <linux/mapi/common.h>

#include <fakepcap.h>
#include <file_ops.h>

PUBLIC int do_truncate(struct dentry *dentry, loff_t length)
{
	struct iattr newattrs;
	struct inode *inode = dentry->d_inode;
	int error;

	if (length < 0)
	{
		return -EINVAL;
	}

	down(&inode->i_sem);
	newattrs.ia_size = length;
	newattrs.ia_valid = ATTR_SIZE | ATTR_CTIME;
	error = notify_change(dentry, &newattrs);
	up(&inode->i_sem);
	
	return error;
}

PUBLIC struct file *create_file(char *filename,int *status)
{
	struct file *file;
	int flags;
	
	*status = 0;
	
	flags = /*O_NONBLOCK | */O_NOFOLLOW /*| O_TRUNC*/;
	
	lock_kernel();
	
	file = filp_open(filename, O_RDONLY | O_NOFOLLOW, 0600);
	
	if(IS_ERR(file))
	{
		flags |= O_CREAT;
	}
	else
	{
		filp_close(file,NULL);
	}
	
	file = filp_open(filename, O_WRONLY | flags, 0600);
	
	if(IS_ERR(file))
	{
		*status = -EIO;
		
		goto fail;
	}	
	if(!file->f_op)
	{
		*status = -ENOSYS;
		
		goto close_fail;
	}
	if(!file->f_op->write)
	{
		*status = -ENOSYS;		
		
		goto close_fail;
	}
	
	unlock_kernel();	
	
	return file;
	
close_fail:
	filp_close(file,NULL);
fail:	
	unlock_kernel();

	return NULL;
}

PUBLIC void close_file(struct file *filp)
{
	if(filp != NULL)
	{
		lock_kernel();
		
		filp_close(filp,NULL);

		unlock_kernel();
	}
}

PUBLIC int truncate_file(struct file *filp)
{
	int ret = 0;

	if(filp != 0)
	{	
		lock_kernel();
		
		if(do_truncate(filp->f_dentry,0) != 0)
		{
			ret = -EPERM;
		}
		
		unlock_kernel();
	}

	return ret;
}
