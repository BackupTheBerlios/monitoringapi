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
#include <asm/semaphore.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>
#include <linux/mapi/prof.h>

PRIVATE int can_use;
struct semaphore can_use_sem;

struct msrs cpu_msrs;

EXPORT_SYMBOL(cpu_msrs);

PRIVATE kmem_cache_t *set_perf_counter_cache;

PRIVATE __u8 set_perf_counter_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long set_perf_counter(struct sk_buff **skb,struct sock *sk,struct predef_func *pfunc)
{
	struct set_perf_counter_struct *spcs = (struct set_perf_counter_struct *)pfunc->data;
	struct skb_mapi_anno *skb_anno = skb_mapianno(sk);
	struct perf_counter *ctr = spcs->ctr;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	prof(ctr,&cpu_msrs,skb_anno->ctr_count);
	
	return 0;
}

PRIVATE int add_set_perf_counter(struct sock *sk,struct predef_func *pfunc)
{
	struct set_perf_counter_struct *spcs = (struct set_perf_counter_struct *)pfunc->data;
	struct perf_counter *ctr = spcs->ctr;
	int ret;
	
	//only one such module per system must be active!
	if(down_interruptible(&can_use_sem))
	{
		return -ERESTARTSYS;
	}
	
	if(!can_use)
	{
		up(&can_use_sem);
		
		return -EPERM;
	}
	
	can_use = 0;

	up(&can_use_sem);
	
	if((ret = init_profiling(ctr,&cpu_msrs)) != 0)
	{
		return ret;
	}
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_set_perf_counter(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct set_perf_counter_struct *spcs;
	struct perf_counter *ctr;
		
	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	spcs = (struct set_perf_counter_struct *)found->data;
	ctr = spcs->ctr;
	
	kmem_cache_free(set_perf_counter_cache,spcs);
	kmem_cache_free(predef_func_cache,found);
	
	if(down_interruptible(&can_use_sem))
	{
		return -ERESTARTSYS;
	}

	can_use = 1;
	
	deinit_profiling(ctr,&cpu_msrs);

	up(&can_use_sem);
	
	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE void set_perf_counter_init_pfunc(struct predef_func *pfunc,struct set_perf_counter_struct *spcs)
{
	init_pfunc(pfunc);
	
	pfunc->type = SET_PERF_COUNTER;
	pfunc->data = (unsigned long)spcs;
	pfunc->func = set_perf_counter;
	pfunc->equals = set_perf_counter_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct set_perf_counter_struct *spcs;
	struct predef_func *pfunc;

	if((spcs = kmem_cache_alloc(set_perf_counter_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(set_perf_counter_cache,spcs);

		return NULL;
	}

	set_perf_counter_init_pfunc(pfunc,spcs);

	return pfunc;
}

#ifdef DEBUG
PRIVATE void print_ctr_table(struct perf_counter *ctr)
{
	int i;
	
	for( i = 0 ; i < prof_num_counters() ; i++)
	{
		printk("Counter %d:\n",i);
		printk("Enabled   = %d\n",ctr[i].enabled);
		printk("Event     = %x\n",ctr[i].event);
		printk("Unit mask = %x\n\n",ctr[i].unit_mask);
	}
}
#endif

PRIVATE inline int fill_fields(struct set_perf_counter_struct *spcs,unsigned long arg)
{
	struct set_perf_counter_struct *arg_spcs = (struct set_perf_counter_struct *)arg;
	struct perf_counter *arg_ctr = arg_spcs->ctr;
	struct perf_counter *ctr = spcs->ctr;
	int i;
	
	for( i = 0 ; i < prof_num_counters() ; i++)
	{
		if(get_user(ctr[i].enabled,(int *)(&((arg_ctr[i].enabled)))) ||
		   get_user(ctr[i].event,(int *)(&((arg_ctr[i].event)))) ||
		   get_user(ctr[i].unit_mask,(int *)(&((arg_ctr[i].unit_mask)))))
		{
			return -EFAULT;
		}
	}

#ifdef DEBUG	
	print_ctr_table(ctr);
#endif	
	
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
	
	if((*status = fill_fields((struct set_perf_counter_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(set_perf_counter_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int set_perf_counter_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSSET_PERF_COUNTER && cmd != SIOCRMSET_PERF_COUNTER)
	{
		return ret;
	}

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCSSET_PERF_COUNTER:
			if((ret = add_set_perf_counter(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCRMSET_PERF_COUNTER:
			ret = remove_set_perf_counter(sk,pfunc,1);
			break;
	}

	kmem_cache_free(set_perf_counter_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

PRIVATE struct predefined fta =
{
	index:SET_PERF_COUNTER,
	owner:THIS_MODULE,
	add:add_set_perf_counter,
	remove:remove_set_perf_counter,
	ioctl:set_perf_counter_ioctl,
};

int __init set_perf_counter_init(void)
{
	int ret;
	
	if((set_perf_counter_cache = kmem_cache_create("setprof",sizeof(struct set_perf_counter_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create set_perf_counter_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}

	sema_init(&can_use_sem,1);
	
	can_use = 1;
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit set_perf_counter_exit(void)
{
	unregister_function(SET_PERF_COUNTER);

	if(kmem_cache_destroy(set_perf_counter_cache))
	{
		printk(KERN_ALERT "Error : Could not remove set_perf_counter_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(set_perf_counter_init);
module_exit(set_perf_counter_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");
