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
#include <linux/mapi/proto.h>

#include <flow_key.h>

PRIVATE kmem_cache_t *flow_key_cache;

PUBLIC struct flow_key *flow_key_alloc(int gfp)
{
	struct flow_key *key;
	
	if((key = kmem_cache_alloc(flow_key_cache,gfp)) == NULL)
	{
		return NULL;
	}
	
	return key;
}

PUBLIC void flow_key_free(struct flow_key *key)
{
	kmem_cache_free(flow_key_cache,key);	
}

EXPORT_SYMBOL(flow_key_alloc);
EXPORT_SYMBOL(flow_key_free);

PUBLIC u32 flow_key_hash_func(struct flow_key *key,struct flow_key_struct *fks)
{
	u32 hash = 0;

	if(fks->in_dev)
	{
		hash ^= key->in_dev;
		hash = hash << 2;
	}

	if(fks->out_dev)
	{
		hash ^= key->out_dev;
		hash = hash << 2;
	}
	
	if(fks->src_ip)
	{
		hash ^= key->src_ip;
		hash = hash << 2;
	}
	
	if(fks->dst_ip)
	{
		hash ^= key->dst_ip;
		hash = hash << 2;
	}
	
	if(fks->ip_proto)
	{
		hash ^= key->ip_proto;
		hash = hash << 2;
	}
	
	if(fks->ip_version)
	{
		hash ^= key->ip_version;
		hash = hash << 2;
	}
	
	if(fks->src_port)
	{
		hash ^= key->src_port;
		hash = hash << 2;
	}
	
	if(fks->dst_port)
	{
		hash ^= key->dst_port;
		hash = hash << 2;
	}
	
	return hash;
}

PUBLIC u8 flow_key_equals_func(struct flow_key *keyA,struct flow_key *keyB,struct flow_key_struct *fks)
{
	if(fks->in_dev)
	{
		if(keyA->in_dev != keyB->in_dev)
		{
			return 0;
		}
	}

	if(fks->out_dev)
	{
		if(keyA->out_dev != keyB->out_dev)
		{
			return 0;
		}
	}
	
	if(fks->src_ip)
	{
		if(keyA->src_ip != keyB->src_ip)
		{
			return 0;
		}
	}
	
	if(fks->dst_ip)
	{
		if(keyA->dst_ip != keyB->dst_ip)
		{
			return 0;
		}
	}
	
	if(fks->ip_proto)
	{
		if(keyA->ip_proto != keyB->ip_proto)
		{
			return 0;
		}
	}
	
	if(fks->ip_version)
	{
		if(keyA->ip_version != keyB->ip_version)
		{
			return 0;
		}
	}
	
	if(fks->src_port)
	{
		if(keyA->src_port != keyB->src_port)
		{
			return 0;
		}
	}
	
	if(fks->dst_port)
	{
		if(keyA->dst_port != keyB->dst_port)
		{
			return 0;
		}
	}
	
	return 1;
}

PUBLIC void fill_flow_key(struct flow_key *fkey,struct subflow *sbf,struct flow_key_struct *fks)
{
	if(fks->in_dev) fkey->in_dev = sbf->in_dev;
	if(fks->out_dev) fkey->out_dev = sbf->out_dev;
	if(fks->src_ip) fkey->src_ip = sbf->src_ip;
	if(fks->dst_ip) fkey->dst_ip = sbf->dst_ip;
	if(fks->ip_proto) fkey->ip_proto = sbf->ip_proto;
	if(fks->ip_version) fkey->ip_version = sbf->ip_version;
	if(fks->src_port) fkey->src_port = sbf->src_port;
	if(fks->dst_port) fkey->dst_port = sbf->dst_port;
}

PUBLIC void get_flow_key_fields(struct sk_buff *skb,struct flow_key *fkey,struct flow_key_struct *fks)
{
	struct iphdr *iph;
	u16 src_port,dst_port;

	iph = proto_iphdr(skb);

	if(fks->src_ip) fkey->src_ip = ntohl(iph->saddr);
	if(fks->dst_ip) fkey->dst_ip = ntohl(iph->daddr);

	if(fks->src_port || fks->dst_port)
	{
		if(iph->protocol == IPPROTO_TCP)
		{
			struct tcphdr *th = proto_tcphdr(skb,iph);
			
			src_port = th->source;
			dst_port = th->dest;
		}
		else if(iph->protocol == IPPROTO_UDP)
		{
			struct udphdr *uh = proto_udphdr(skb,iph);
			
			src_port = uh->source;
			dst_port = uh->dest;
		}
		else
		{
			src_port = dst_port = 0;
		}

		src_port = ntohs(src_port);
		dst_port = ntohs(dst_port);
		
		fkey->src_port = src_port;
		fkey->dst_port = dst_port;
	}

	if(fks->in_dev) fkey->in_dev = skb->dev->ifindex;
	if(fks->out_dev) fkey->out_dev = skb->dev->ifindex;
	
	if(fks->ip_proto) fkey->ip_proto = iph->protocol;
	if(fks->ip_version) fkey->ip_version = iph->version;
}

EXPORT_SYMBOL(flow_key_hash_func);
EXPORT_SYMBOL(flow_key_equals_func);
EXPORT_SYMBOL(fill_flow_key);
EXPORT_SYMBOL(get_flow_key_fields);

PRIVATE void print_flow_key_struct(struct flow_key_struct *fks)
{
#ifdef DEBUG	
	printk("FLOW_KEY\n");
	printk("in_dev		: %.1d\n",fks->in_dev);
	printk("out_dev		: %.1d\n",fks->out_dev);
	printk("src_ip		: %.1d\n",fks->src_ip);
	printk("dst_ip		: %.1d\n",fks->dst_ip);
	printk("ip_proto	: %.1d\n",fks->ip_proto);
	printk("ip_version	: %.1d\n",fks->ip_version);
	printk("src_port	: %.1d\n",fks->src_port);
	printk("dst_port	: %.1d\n",fks->dst_port);
#endif	
}

PRIVATE __u8 flow_key_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE int add_flow_key(struct sock *sk,struct predef_func *pfunc)
{
	struct flow_key_struct *fks = (struct flow_key_struct *)pfunc->data;
	int ret;
	
	if(fks->in_dev == 0 && fks->out_dev == 0 && fks->src_ip == 0 && fks->dst_ip == 0 &&
	   fks->ip_proto == 0 && fks->ip_version == 0 && fks->src_port == 0 && fks->dst_port == 0)
	{
		return -EINVAL;
	}
	
	print_flow_key_struct(fks);
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_flow_key(struct sock *sk,struct predef_func *pfunc,int lock)
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

PRIVATE void flow_key_init_pfunc(struct predef_func *pfunc,struct flow_key_struct *fks)
{
	init_pfunc(pfunc);
	
	pfunc->type = FLOW_KEY;
	pfunc->data = (unsigned long)fks;
	pfunc->func = NULL;
	pfunc->equals = flow_key_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct flow_key_struct *fks;
	struct predef_func *pfunc;

	if((fks = kmalloc(sizeof(struct flow_key_struct),GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kfree(fks);

		return NULL;
	}

	flow_key_init_pfunc(pfunc,fks);

	return pfunc;
}

PRIVATE inline int fill_fields(struct flow_key_struct *fks,unsigned long arg)
{
	if(copy_from_user(fks,(struct flow_key_struct *)arg,sizeof(struct flow_key_struct)))
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
	
	if((*status = fill_fields((struct flow_key_struct *)pfunc->data,arg)) != 0)
	{
		kfree((void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int flow_key_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSFLOW_KEY && cmd != SIOCRMFLOW_KEY)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}
	
	switch(cmd)
	{
		case SIOCSFLOW_KEY:
			if((ret = add_flow_key(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCRMFLOW_KEY:
			ret = remove_flow_key(sk,pfunc,1);
			break;
	}

	kfree((void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

PRIVATE struct predefined fta =
{
	index:FLOW_KEY,
	owner:THIS_MODULE,
	add:add_flow_key,
	remove:remove_flow_key,
	ioctl:flow_key_ioctl,
};

int __init flow_key_init(void)
{
	int ret;
	
	if((flow_key_cache = kmem_cache_create("flowkey",sizeof(struct flow_key),0,0,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create flow_key_cache : %s,%i\n",__FILE__,__LINE__);
		
		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit flow_key_exit(void)
{
	unregister_function(FLOW_KEY);

	if(kmem_cache_destroy(flow_key_cache))
	{
		printk(KERN_ALERT "Error : Could not remove flow_key_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(flow_key_init);
module_exit(flow_key_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

