/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <asm/atomic.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

#include <decide.h>

struct private_struct
{
	struct socket *parent_sock;
};

#define function_cb(ds) ((struct private_struct *)(((struct decide_struct *)ds)->cb))

PRIVATE __u8 decide_proxy_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	struct decide_struct *fds = (struct decide_struct *)fpf->data;
	struct decide_struct *sds = (struct decide_struct *)spf->data;
	
	if((fpf->type == spf->type) && (fds->uid == sds->uid))
	{
		return 1;
	}
	
	return 0;
}

PRIVATE inline void decide_proxy_init_pfunc(struct predef_func *pfunc,struct decide_struct *ds)
{
	init_pfunc(pfunc);
	
	pfunc->type = DECIDE_PROXY;
	pfunc->data = (unsigned long)ds;
	pfunc->func = NULL;
	pfunc->equals = decide_proxy_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct decide_struct *ds;
	struct predef_func *pfunc;

	if((ds = kmem_cache_alloc(decide_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(decide_cache,ds);

		return NULL;
	}

	decide_proxy_init_pfunc(pfunc,ds);

	return pfunc;
}

PRIVATE int info_decide_proxy(struct predef_func *pfunc,char *msg,size_t msg_size,u8 verbosity)
{
	struct decide_struct *ds;
	struct private_struct *cb;
	int len;
	
	if(pfunc->type != DECIDE_PROXY)
	{
		return snprintf(msg,msg_size,"BUG : expected %u , found %u",DECIDE_PROXY,pfunc->type);	
	}

	ds = (struct decide_struct *)pfunc->data;
	cb = function_cb(ds);

	len = snprintf(msg,msg_size,"Uid : %d , VSock : %p ( %s )",ds->uid,cb->parent_sock,ds->debug_info);

	return len;
}

PUBLIC int register_decide_proxy(struct sock *real_sk,struct socket *parent_sock,struct decide_struct *ds_to_copy)
{
	struct predef_func *pfunc;
	struct decide_struct *ds;
	struct private_struct *cb;

	if((pfunc = pfunc_alloc_r()) == NULL)
	{
		return -ENOMEM;
	}
	
	ds = (struct decide_struct *)pfunc->data;
	cb = function_cb(ds);

	memcpy(ds,ds_to_copy,sizeof(*ds));
	
	memset(cb,0,sizeof(*cb));
	
	cb->parent_sock = parent_sock;
	
	return sk_attach_predef(real_sk,pfunc);
}

PUBLIC int unregister_decide_proxy(struct sock *real_sk,u16 uid)
{
	struct predef_func *pfunc;	
	struct predef_func *found;
	struct decide_struct *ds;
	
	if((pfunc = pfunc_alloc_r()) == NULL)
	{
		return -ENOMEM;
	}
	
	ds = (struct decide_struct *)pfunc->data;

	ds->uid = uid;

	if((found = sk_detach_predef(real_sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	
	kmem_cache_free(decide_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);
	kmem_cache_free(decide_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return 0;
}

PRIVATE inline int fill_fields(struct decide_struct *ds,unsigned long arg)
{
	struct decide_struct *arg_ds = (struct decide_struct *)arg;
	
	if(copy_from_user(ds,arg_ds,sizeof(*ds) - sizeof(ds->cb)))
	{
		return -EFAULT;
	}

	return 0;
}

PRIVATE inline struct predef_func *get_pfunc(unsigned long arg,int *status)
{
	struct predef_func *pfunc;

	*status = 0;
	
	if((pfunc = pfunc_alloc_r()) == NULL)
	{
		*status = -ENOMEM;

		return NULL;
	}
	
	if((*status = fill_fields((struct decide_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(decide_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int decide_proxy_ioctl(struct socket *real_sock,unsigned int cmd,unsigned long arg)
{
	struct socket *virtual_sock;
	struct sock *real_sk = real_sock->sk;
	struct predef_func *pfunc;
	struct predef_func *found;
	struct decide_struct *ds;
	struct private_struct *cb;
	int ret = NRIOCTL;
	
	if(cmd != SIOCIODECIDE)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	if((found = sk_find_predef(real_sk,pfunc)) == NULL)
	{
		ret = -ENODATA;

		goto error;
	}
	
	ds = (struct decide_struct *)found->data;
	cb = function_cb(ds);
	
	virtual_sock = cb->parent_sock;
	
	printk("DECIDE_PROXY : Intercepting ioctl\n");

	ret = decide_intercept_ioctl(real_sock,virtual_sock,arg);
	
error:	
	kmem_cache_free(decide_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS

#define INFO_LEN 100

PRIVATE int decide_proxy_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct predef_func *cur_virtual_pfunc;
	struct predef_func *virtual_pfunc;
	struct decide_struct *ds;
	struct private_struct *cb;
	char info[INFO_LEN];
	u8 verbosity = *((u8 *)data);
	struct hlist_node *node;
	
	len += sprintf(buffer,"Sock      LPredef RPredef Info\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,DECIDE_PROXY);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			ds = (struct decide_struct *)cur->data;
			cb = function_cb(ds);
			
			virtual_pfunc = sk_find_type(cb->parent_sock->sk,DECIDE);

			for( cur_virtual_pfunc = virtual_pfunc ; cur_virtual_pfunc != NULL ; cur_virtual_pfunc = cur_virtual_pfunc->tnext)
			{	
				ds = (struct decide_struct *)cur_virtual_pfunc->data;

				len += sprintf(buffer + len,"%-8p  %-7u %-7u %s\n",s,
					       atomic_read(&(mapi_sk(get_left_socket(ds)->sk)->predef_func_nr)),
					       atomic_read(&(mapi_sk(get_right_socket(ds)->sk)->predef_func_nr)),
					       get_info(cur_virtual_pfunc,info,INFO_LEN,verbosity));

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
#endif

PRIVATE struct predefined fta =
{
	index:DECIDE_PROXY,
	owner:THIS_MODULE,
	ioctl:decide_proxy_ioctl,
	info:info_decide_proxy,
};

PRIVATE struct proc_dir_entry *dproxy_path;
PRIVATE u8 verbosity_A = 0;
PRIVATE u8 verbosity_B = 1;

int __init decide_proxy_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if((dproxy_path = proc_mkdir("dproxy",proc_path)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc directory dproxy : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}

	if(create_proc_read_entry("v0", 0, dproxy_path, decide_proxy_read_proc,&verbosity_A) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file v0 : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}

	if(create_proc_read_entry("v1", 0, dproxy_path, decide_proxy_read_proc,&verbosity_B) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file v1 : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif

	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit decide_proxy_exit(void)
{
#ifdef CONFIG_PROC_FS
	remove_proc_entry("v0",dproxy_path);
	remove_proc_entry("v1",dproxy_path);
	remove_proc_entry("dproxy",proc_path);	
#endif

	unregister_function(DECIDE_PROXY);
}
