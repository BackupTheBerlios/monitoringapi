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
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/smp_lock.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/async.h>
#include <linux/mapi/ioctl.h>

#include <subflow_hook.h>

EXPORT_NO_SYMBOLS;

PRIVATE u32 max_number_of_subflows = 10000;

struct private_struct
{
	struct subflow_struct *ss;

	wait_queue_head_t queue;
	struct fasync_struct *notify_queue;
	
	struct list_head *expired_sbf_list;
	rwlock_t expired_sbf_list_lock;

	u32 expired_sbf_nr;
};

#define function_cb(frs) ((struct private_struct *)(((struct flow_raw_struct *)frs)->cb))

/*PRIVATE void print_subflow(struct subflow *sbf)
{
	printk("%3u.%3u.%3u.%3u  ",HIPQUAD(sbf->src_ip));
	printk("%3u.%3u.%3u.%3u  ",HIPQUAD(sbf->dst_ip));
	printk("%.5u ",sbf->src_port);
	printk("%.5u ",sbf->dst_port);
	printk("%.7llu ",sbf->npackets);
	printk("%.10llu ",sbf->nbytes);
	printk("%.10lu ",sbf->start_time.tv_sec);
	printk("%.10lu\n",sbf->end_time.tv_sec);
}*/

int raw_subflow_handler(struct subflow *sbf,void *data)
{
	struct flow_raw_struct *frs = (struct flow_raw_struct *)data;
	struct private_struct *cb = function_cb(frs);
	struct subflow_private_struct *sbf_cb = subflow_cb(sbf);
	u8 wake_up_flag = 0;
	
	write_lock(&(cb->expired_sbf_list_lock));
	{
		if(cb->expired_sbf_nr < max_number_of_subflows)
		{
			list_add_tail(&(sbf_cb->list),cb->expired_sbf_list);
			cb->expired_sbf_nr++;

			wake_up_flag = 1;			
		}
		else
		{
			subflow_free(sbf);
		}
	}
	write_unlock(&(cb->expired_sbf_list_lock));
	
	if(wake_up_flag)
	{
		wake_up_interruptible_sync(&(cb->queue));

		if(cb->notify_queue != NULL)
		{
			kill_fasync(&(cb->notify_queue),SIGIO,POLL_IN);
		}
	}
	
	return 0;
}

PRIVATE int set_async(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct flow_raw_struct *frs;
	struct private_struct *cb;
	
	if((found = sk_find_predef(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}

	frs = (struct flow_raw_struct *)found->data;
	cb = function_cb(frs);
	
	return add_async_notification(sk,&(cb->notify_queue),current->pid);
}

PRIVATE int unset_async(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct flow_raw_struct *frs;
	struct private_struct *cb;

	if((found = sk_find_predef(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}

	frs = (struct flow_raw_struct *)found->data;
	cb = function_cb(frs);
	
	return remove_async_notification(sk,&(cb->notify_queue));
}

PRIVATE __u8 flow_raw_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE int add_flow_raw(struct sock *sk,struct predef_func *pfunc)
{
	struct flow_raw_struct *frs = (struct flow_raw_struct *)pfunc->data;
	struct private_struct *cb = function_cb(frs);
	struct predef_func *pfunc_subflow;
	struct subflow_hook *hook;
	int ret;
	
	if((pfunc_subflow = sk_find_type(sk,SUBFLOW)) == NULL)
	{
		return -EPERM;
	}

	cb->ss = (struct subflow_struct *)pfunc_subflow->data;
	
	if((hook = kmalloc(sizeof(struct subflow_hook),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	hook->data = frs;
	hook->expired_subflow = raw_subflow_handler;
	
	if((cb->expired_sbf_list = (struct list_head *)kmalloc(sizeof(struct list_head),GFP_KERNEL)) == NULL)
	{
		kfree(hook);
			
		return -ENOMEM;
	}
	
	INIT_LIST_HEAD(cb->expired_sbf_list);	
	rwlock_init(&(cb->expired_sbf_list_lock));
	cb->expired_sbf_nr = 0;
	
	cb->notify_queue = NULL;
	init_waitqueue_head(&(cb->queue));
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		mapi_module_get(THIS_MODULE);		
		
		if((ret = register_subflow_hook(cb->ss,hook)) != 0)
		{
			return ret;
		}
	}

	return ret;
}

PRIVATE int remove_flow_raw(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct flow_raw_struct *frs;
	struct subflow_hook *hook;
	struct private_struct *cb;
	struct list_head *list_cur;
	
	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	frs = (struct flow_raw_struct *)found->data;
	cb = function_cb(frs);
	
	if((hook = unregister_subflow_hook(cb->ss)) == NULL)
	{
		BUG();
	}

	list_for_each(list_cur,cb->expired_sbf_list)
	{
		struct subflow *sbf = subflow_list_entry(list_cur);
		
		subflow_free(sbf);
	}
	
	kfree(cb->expired_sbf_list);

	kfree(hook);
	kfree(frs);
	kmem_cache_free(predef_func_cache,found);
	
	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE struct predef_func *getresults_flow_raw(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void flow_raw_init_pfunc(struct predef_func *pfunc,struct flow_raw_struct *frs)
{
	init_pfunc(pfunc);
	
	pfunc->type = FLOW_RAW;
	pfunc->data = (unsigned long)frs;
	pfunc->func = NULL;
	pfunc->equals = flow_raw_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct flow_raw_struct *frs;
	struct predef_func *pfunc;

	if((frs = kmalloc(sizeof(struct flow_raw_struct),GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kfree(frs);

		return NULL;
	}

	flow_raw_init_pfunc(pfunc,frs);

	return pfunc;
}

PRIVATE inline struct subflow *find_expired_sbf(struct flow_raw_struct *frs)
{
	struct private_struct *cb = function_cb(frs);
	struct subflow_private_struct *sbf_cb;
	struct subflow *sbf = NULL;
	struct list_head *list_cur;
	struct list_head *help_cur;
	
	write_lock(&(cb->expired_sbf_list_lock));

	list_for_each_safe(list_cur,help_cur,cb->expired_sbf_list)
	{
		sbf = subflow_list_entry(list_cur);
		sbf_cb = subflow_cb(sbf);

		list_del(&(sbf_cb->list));
		
		cb->expired_sbf_nr--;			

		break;
	}
	
	write_unlock(&(cb->expired_sbf_list_lock));
	
	return sbf;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_flow_raw(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		struct flow_raw_struct *frs = (struct flow_raw_struct *)pfunc->data;
		struct flow_raw_struct *arg_frs = (struct flow_raw_struct *)arg;
		struct subflow *expired_sbf = find_expired_sbf(frs);
		struct private_struct *cb = function_cb(frs);
		
		if(expired_sbf == NULL)
		{
			interruptible_sleep_on(&(cb->queue));

			expired_sbf = find_expired_sbf(frs);
		}

		if(expired_sbf == NULL)
		{
			return -EINTR;
		}
		
		if(copy_to_user(&(arg_frs->sbf),expired_sbf,sizeof(*expired_sbf) - sizeof(expired_sbf->cb)))
		{
			return -EFAULT;
		}

		subflow_free(expired_sbf);
	}

	return 0;
}

PRIVATE inline int put_expired_nr_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_flow_raw(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		struct flow_raw_struct *frs = (struct flow_raw_struct *)pfunc->data;
		struct flow_raw_struct *arg_frs = (struct flow_raw_struct *)arg;
		struct private_struct *cb = function_cb(frs);
		int expired_nr = cb->expired_sbf_nr;
		
		if(copy_to_user(&(arg_frs->expired_nr),&expired_nr,sizeof(u32)))
		{
			return -EFAULT;
		}
	}

	return 0;
}

PRIVATE inline int fill_fields(struct flow_raw_struct *frs,unsigned long arg)
{
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
	
	if((*status = fill_fields((struct flow_raw_struct *)pfunc->data,arg)) != 0)
	{
		kfree((void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int flow_raw_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCGFLOW_RAW && cmd != SIOCSFLOW_RAW && 
	   cmd != SIOCRMFLOW_RAW && cmd != SIOCGNFLOW_RAW &&
	   cmd != SIOCSASYNCSUBFLOW && cmd != SIOCRMASYNCSUBFLOW)
	{
		return ret;
	}

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCGFLOW_RAW:
			ret = put_fields_to_userspace(sk,pfunc,arg);			
			break;
		
		case SIOCGNFLOW_RAW:
			ret = put_expired_nr_to_userspace(sk,pfunc,arg);			
			break;
			
		case SIOCSFLOW_RAW:
			if((ret = add_flow_raw(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;
			
		case SIOCRMFLOW_RAW:
			ret = remove_flow_raw(sk,pfunc,1);
			break;

		case SIOCSASYNCSUBFLOW:
			ret = set_async(sk,pfunc);
			break;
			
		case SIOCRMASYNCSUBFLOW:
			ret = unset_async(sk,pfunc);
			break;
	}

	kfree((void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

PRIVATE struct predefined fta =
{
	index:FLOW_RAW,
	owner:THIS_MODULE,
	add:add_flow_raw,
	remove:remove_flow_raw,
	ioctl:flow_raw_ioctl,
};

int __init flow_raw_init(void)
{
	int ret;
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit flow_raw_exit(void)
{
	unregister_function(FLOW_RAW);
}

module_init(flow_raw_init);
module_exit(flow_raw_exit);

#if V_BEFORE(2,5,0)
MODULE_PARM(max_number_of_subflows,"i");
#else
#include <linux/moduleparam.h>
module_param(max_number_of_subflows,uint,0);
#endif

MODULE_PARM_DESC(max_number_of_subflows,"How large the internal list which stores expired subflows not read by application can be (default = 10000)");

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

