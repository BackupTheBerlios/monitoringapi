/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <asm/atomic.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

#ifdef CONFIG_PROC_FS

PRIVATE struct proc_dir_entry *debug_path;

#define INFO_LEN 100

PRIVATE int debug_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;
	
	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	char info[INFO_LEN];
	struct hlist_node *node;
	
	len += sprintf(buffer,"Socket    Type Info\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = mapi_sk(s)->pfunc_list;
				
		for( cur = pfunc ; cur != NULL ; cur = cur->next)
		{	
			len += sprintf(buffer + len,"%8p  %-4u %s\n",mapi_sk_socket(s),cur->type,get_info(cur,info,INFO_LEN,0));
				
			pos = begin + len;

			if(pos < offset)
			{
				len = 0;
				begin = pos;
			}
			
			if(pos > offset + length)
			{
				goto done;
			}
		}
	}

	*eof = 1;

done:
	unlock_active_socket_list();

	*start = buffer + (offset - begin);
	len -= (offset - begin);

	if(len > length)
	{
		len = length;
	}
	
	if(len < 0)
	{
		len = 0;
	}

	return len;
}

PRIVATE int registered_functions_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;
	struct predefined *pr;
	u16 i;

	len += sprintf(buffer,"Function_Type\n");

	for( i = 1 ; i < PREDEF_MAX ; i++)
	{
		if((pr = get_function(i)) == NULL)
		{
			continue;
		}

		len += sprintf(buffer + len,"%-13d\n",i);
			
		pos = begin + len;

		if(pos < offset)
		{
			len = 0;
			begin = pos;
		}
		
		if(pos > offset + length)
		{
			goto done;
		}
	}

	*eof = 1;

done:
	*start = buffer + (offset - begin);
	len -= (offset - begin);

	if(len > length)
	{
		len = length;
	}
	
	if(len < 0)
	{
		len = 0;
	}

	return len;
}
#endif

int __init debug_init(void)
{
#ifdef CONFIG_PROC_FS
	if((debug_path = proc_mkdir("debug",proc_path)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc directory debug : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}

	if(create_proc_read_entry("pfunc", 0, debug_path, debug_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file pfunc : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}

	if(create_proc_read_entry("registered", 0, debug_path, registered_functions_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file registered : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}

#endif

	return 0;
}

void __exit debug_exit(void)
{
#ifdef CONFIG_PROC_FS
	remove_proc_entry("pfunc",debug_path);
	remove_proc_entry("registered",debug_path);
	remove_proc_entry("debug",proc_path);
#endif
}

module_init(debug_init);
module_exit(debug_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

