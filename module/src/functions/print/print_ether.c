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

PRIVATE __u8 print_ether_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long print_ether(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct print_ether_struct *pes = (struct print_ether_struct *)pfunc->data;
	struct sk_buff *skb = *skbp;
	struct net_device *dev = skb->dev;
	unsigned char *dst = skb->mac.ethernet->h_dest;
	unsigned char *src = skb->mac.ethernet->h_source;
	u8 *payload;
	register u32 p_len,i;
	char *proto_name = etherproto_to_string(skb->mac.ethernet->h_proto);
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if(dev->hard_header == NULL || skb->len < ETH_HLEN)
	{
		printk("[|ether]\n");
	}
	else
	{
		printk("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x ",dst[0],dst[1],dst[2],dst[3],dst[4],dst[5]);
		printk("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x ",src[0],src[1],src[2],src[3],src[4],src[5]);

		if(proto_name != NULL)
		{
			printk("%s ",proto_name);
		}
	}

	printk("%u ",skb->len);
	
	if(dev->hard_header == NULL)
	{
		payload = skb->data;
	}
	else
	{
		payload = skb->mac.raw + dev->hard_header_len;
	}
	
	p_len = skb->len - dev->hard_header_len;
	
	if(pes->nbytes > 0)
	{
		p_len = p_len < (u32)pes->nbytes ? p_len : (u32)pes->nbytes;
	}
	
	if(pes->print_payload)
	{
		for( i = 0 ; i < p_len ; i++)
		{
			printk("%.2x ",payload[i]);
		}
	}
	
	if(pes->print_newline == 1)
	{
		printk("\n");
	}
	
	return 0;
}

PRIVATE int add_print_ether(struct sock *sk,struct predef_func *pfunc)
{
	int ret;

	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);		
	}

	return ret;
}

PRIVATE int remove_print_ether(struct sock *sk,struct predef_func *pfunc,int lock)
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

PRIVATE void print_ether_init_pfunc(struct predef_func *pfunc,struct print_ether_struct *pes)
{
	init_pfunc(pfunc);
	
	pfunc->type = PRINT_ETHER;
	pfunc->data = (unsigned long)pes;
	pfunc->func = print_ether;
	pfunc->equals = print_ether_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct print_ether_struct *pes;
	struct predef_func *pfunc;

	if((pes = kmalloc(sizeof(struct print_ether_struct),GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kfree(pes);

		return NULL;
	}

	print_ether_init_pfunc(pfunc,pes);

	return pfunc;
}

PRIVATE inline int fill_fields(struct print_ether_struct *pes,unsigned long arg)
{
	if(copy_from_user(pes,(struct print_ether_struct *)arg,sizeof(struct print_ether_struct)))
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
	
	if((*status = fill_fields((struct print_ether_struct *)pfunc->data,arg)) != 0)
	{
		kfree((void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int print_ether_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSPRINT_ETHER && cmd != SIOCRMPRINT_ETHER)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}
	
	switch(cmd)
	{
		case SIOCSPRINT_ETHER:
			if((ret = add_print_ether(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCRMPRINT_ETHER:
			ret = remove_print_ether(sk,pfunc,1);
			break;
	}

	kfree((void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

PRIVATE struct predefined fta =
{
	index:PRINT_ETHER,
	owner:THIS_MODULE,
	add:add_print_ether,
	remove:remove_print_ether,
	ioctl:print_ether_ioctl,
};

int __init print_ether_init(void)
{
	int ret;
	
	if((ret = init_eprotoarray()) != 0)
	{
		return ret;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit print_ether_exit(void)
{
	unregister_function(PRINT_ETHER);
	
	deinit_eprotoarray();
}

module_init(print_ether_init);
module_exit(print_ether_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

