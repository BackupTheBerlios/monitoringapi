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

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

EXPORT_NO_SYMBOLS;

PRIVATE __u8 set_cycle_counter_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long set_cycle_counter(struct sk_buff **skb,struct sock *sk,struct predef_func *pfunc)
{
	struct skb_mapi_anno *skb_anno = skb_mapianno(sk);
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	skb_anno->cycles = get_cycles();
	
	return 0;
}

PRIVATE int add_set_cycle_counter(struct sock *sk,struct predef_func *pfunc)
{
	int ret;
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_set_cycle_counter(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	kfree((void *)found->data);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE void set_cycle_counter_init_pfunc(struct predef_func *pfunc,struct set_cycle_counter_struct *sccs)
{
	init_pfunc(pfunc);
	
	pfunc->type = SET_CYCLE_COUNTER;
	pfunc->data = (unsigned long)sccs;
	pfunc->func = set_cycle_counter;
	pfunc->equals = set_cycle_counter_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct set_cycle_counter_struct *sccs;
	struct predef_func *pfunc;

	if((sccs = kmalloc(sizeof(struct set_cycle_counter_struct),GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kfree(sccs);

		return NULL;
	}

	set_cycle_counter_init_pfunc(pfunc,sccs);

	return pfunc;
}

PRIVATE int set_cycle_counter_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSSET_CYCLE_COUNTER && cmd != SIOCRMSET_CYCLE_COUNTER)
	{
		return ret;
	}

	if((pfunc = pfunc_alloc_r()) == NULL)
	{
		return -ENOMEM;
	}

	if(copy_from_user((void *)pfunc->data,(void *)arg,sizeof(struct set_cycle_counter_struct)))
	{
		kfree((void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);
		
		return -EFAULT;
	}

	switch(cmd)
	{
		case SIOCSSET_CYCLE_COUNTER:
			if((ret = add_set_cycle_counter(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCRMSET_CYCLE_COUNTER:
			ret = remove_set_cycle_counter(sk,pfunc,1);
			break;
	}

	kfree((void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

PRIVATE struct predefined fta =
{
	index:SET_CYCLE_COUNTER,
	owner:THIS_MODULE,
	add:add_set_cycle_counter,
	remove:remove_set_cycle_counter,
	ioctl:set_cycle_counter_ioctl,
};

int __init set_cycle_counter_init(void)
{
	int ret;
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit set_cycle_counter_exit(void)
{
	unregister_function(SET_CYCLE_COUNTER);
}

module_init(set_cycle_counter_init);
module_exit(set_cycle_counter_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

