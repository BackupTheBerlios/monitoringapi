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
#include <linux/ip.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

#include <ip_addr_to_name.h>

EXPORT_NO_SYMBOLS;

PRIVATE __u8 print_ip_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long print_ip(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct print_ip_struct *pis = (struct print_ip_struct *)pfunc->data;
	struct sk_buff *skb = *skbp;
	struct net_device *dev = skb->dev;
	struct iphdr *iph;
	u32 len,iplen,hlen;
	char *proto_name;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if(skb->protocol != htons(ETH_P_IP))
	{
		return 0;
	}
	
	if(dev->hard_header == NULL)
	{
		iph = (struct iphdr *)(skb->data);
	}
	else
	{
		iph = (struct iphdr *)(skb->mac.raw + dev->hard_header_len);
	}
	
	len = skb->len - dev->hard_header_len;
		
	if(len < sizeof(struct iphdr))
	{
		printk("truncated-ip %d ",len);

		return 0;
	}
	
	hlen = iph->ihl * 4;
	
	if(hlen < sizeof(struct iphdr)) 
	{
		printk("bad-hlen %d ", hlen);
		
		return 0;
	}

	iplen = ntohs(iph->tot_len);
	
	if(len < iplen)
	{
		printk("truncated-ip - %d bytes missing! ",iplen - len);
	}
	
	printk("%u.%u.%u.%u ",NIPQUAD(iph->daddr));
	printk("%u.%u.%u.%u ",NIPQUAD(iph->saddr));
	
	if(pis->print_id)
	{
		printk("id %.1x ",iph->id);
	}
	
	if(pis->print_ttl)
	{
		printk("ttl %d ",iph->ttl);
	}
	
	if(pis->print_tos)
	{
		printk("tos %.1x ",iph->tos);
	}
	
	if(pis->print_ip_len)
	{
		printk("tot_len %d ",iplen);
	}
	
	proto_name = ipproto_to_string(iph->protocol);
	
	if(proto_name != NULL)
	{
		printk("%s ",proto_name);
	}

	if(pis->print_newline)
	{
		printk("\n");
	}
	
	return 0;
}

PRIVATE int add_print_ip(struct sock *sk,struct predef_func *pfunc)
{
	int ret;

	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_print_ip(struct sock *sk,struct predef_func *pfunc,int lock)
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

PRIVATE void print_ip_init_pfunc(struct predef_func *pfunc,struct print_ip_struct *pis)
{
	init_pfunc(pfunc);
	
	pfunc->type = PRINT_IP;
	pfunc->data = (unsigned long)pis;
	pfunc->func = print_ip;
	pfunc->equals = print_ip_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct print_ip_struct *pis;
	struct predef_func *pfunc;

	if((pis = kmalloc(sizeof(struct print_ip_struct),GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kfree(pis);

		return NULL;
	}

	print_ip_init_pfunc(pfunc,pis);

	return pfunc;
}

PRIVATE inline int fill_fields(struct print_ip_struct *pis,unsigned long arg)
{
	if(copy_from_user(pis,(struct print_ip_struct *)arg,sizeof(struct print_ip_struct)))
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
	
	if((*status = fill_fields((struct print_ip_struct *)pfunc->data,arg)) != 0)
	{
		kfree((void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int print_ip_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSPRINT_IP && cmd != SIOCRMPRINT_IP)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}
	
	switch(cmd)
	{
		case SIOCSPRINT_IP:
			if((ret = add_print_ip(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCRMPRINT_IP:
			ret = remove_print_ip(sk,pfunc,1);
			break;
	}

	kfree((void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

PRIVATE struct predefined fta =
{
	index:PRINT_IP,
	owner:THIS_MODULE,
	add:add_print_ip,
	remove:remove_print_ip,
	ioctl:print_ip_ioctl,
};

int __init print_ip_init(void)
{
	int ret;
	
	if((ret = init_ipprotoarray()) != 0)
	{
		return ret;
	}

	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit print_ip_exit(void)
{
	unregister_function(PRINT_IP);
	
	deinit_ipprotoarray();
}

module_init(print_ip_init);
module_exit(print_ip_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

