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
#include <linux/string.h>
#include <linux/smp_lock.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

#include <ether_addr_to_name.h>

EXPORT_NO_SYMBOLS;

PRIVATE __u8 print_udp_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long print_udp(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct print_udp_struct *pus = (struct print_udp_struct *)pfunc->data;
	struct sk_buff *skb = *skbp;
	struct net_device *dev = skb->dev;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if(pus->print_newline)
	{
		printk("\n");
	}
	
	return 0;
}

PRIVATE int add_print_udp(struct sock *sk,struct predef_func *pfunc)
{
	int ret;

	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_print_udp(struct sock *sk,struct predef_func *pfunc,int lock)
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

PRIVATE void print_udp_init_pfunc(struct predef_func *pfunc,struct print_udp_struct *pus)
{
	init_pfunc(pfunc);
	
	pfunc->type = PRINT_UDP;
	pfunc->data = (unsigned long)pus;
	pfunc->func = print_udp;
	pfunc->equals = print_udp_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r()
{
	struct print_udp_struct *pus;
	struct predef_func *pfunc;

	if((pus = kmalloc(sizeof(struct print_udp_struct),GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kfree(pus);

		return NULL;
	}

	print_udp_init_pfunc(pfunc,pus);

	return pfunc;
}

PRIVATE inline int fill_fields(struct print_udp_struct *pus,unsigned long arg)
{
	if(copy_from_user(pus,(struct print_udp_struct *)arg,sizeof(struct print_udp_struct)))
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
	
	if((*status = fill_fields((struct print_udp_struct *)pfunc->data,arg)) != 0)
	{
		kfree((void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int print_udp_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSPRINT_UDP && cmd != SIOCRMPRINT_UDP)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}
	
	switch(cmd)
	{
		case SIOCSPRINT_UDP:
			if((ret = add_print_udp(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCRMPRINT_UDP:
			ret = remove_print_udp(sk,pfunc,1);
			break;
	}

	kfree((void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

PRIVATE struct predefined fta =
{
	index:PRINT_UDP,
	owner:THIS_MODULE,
	add:add_print_udp,
	remove:remove_print_udp,
	ioctl:print_udp_ioctl,
};

int __init print_udp_init()
{
	int ret;
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit print_udp_exit()
{
	unregister_function(PRINT_UDP);
}

module_init(print_udp_init);
module_exit(print_udp_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

