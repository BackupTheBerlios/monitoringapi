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

EXPORT_NO_SYMBOLS;

PRIVATE __u8 pkt_type_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long pkt_type(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct pkt_type_struct *pts = (struct pkt_type_struct *)pfunc->data;
	struct sk_buff *skb = *skbp;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if(skb->pkt_type != pts->type)
	{
		skb_mapi->action = SKB_DROP;
	}
	
	return 0;
}

PRIVATE int add_pkt_type(struct sock *sk,struct predef_func *pfunc)
{
	struct pkt_type_struct *pts = (struct pkt_type_struct *)pfunc->data;
	u8 type = pts->type;
	int ret;
	
	if(	type != PACKET_HOST && 
		type != PACKET_BROADCAST && 
		type != PACKET_MULTICAST &&
		type != PACKET_OTHERHOST && 
		type != PACKET_OUTGOING)
	{
		return -EINVAL;
	}
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);		
	}

	return ret;
}

PRIVATE int remove_pkt_type(struct sock *sk,struct predef_func *pfunc,int lock)
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

PRIVATE void pkt_type_init_pfunc(struct predef_func *pfunc,struct pkt_type_struct *pts)
{
	init_pfunc(pfunc);
	
	pfunc->type = PKT_TYPE;
	pfunc->data = (unsigned long)pts;
	pfunc->func = pkt_type;
	pfunc->equals = pkt_type_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct pkt_type_struct *pts;
	struct predef_func *pfunc;

	if((pts = kmalloc(sizeof(struct pkt_type_struct),GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kfree(pts);

		return NULL;
	}

	pkt_type_init_pfunc(pfunc,pts);

	return pfunc;
}

PRIVATE inline int fill_fields(struct pkt_type_struct *pts,unsigned long arg)
{
	if(copy_from_user(pts,(struct pkt_type_struct *)arg,sizeof(struct pkt_type_struct)))
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
	
	if((*status = fill_fields((struct pkt_type_struct *)pfunc->data,arg)) != 0)
	{
		kfree((void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int pkt_type_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSPKT_TYPE && cmd != SIOCRMPKT_TYPE)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}
	
	switch(cmd)
	{
		case SIOCSPKT_TYPE:
			if((ret = add_pkt_type(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCRMPKT_TYPE:
			ret = remove_pkt_type(sk,pfunc,1);
			break;
	}

	kfree((void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int pkt_type_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct pkt_type_struct *pts = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Type\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,PKT_TYPE);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			pts = (struct pkt_type_struct *)cur->data;
			len += sprintf(buffer + len,"%8p  %.2d\n",s,pts->type);

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
#endif

PRIVATE struct predefined fta =
{
	index:PKT_TYPE,
	owner:THIS_MODULE,	      
	add:add_pkt_type,
	remove:remove_pkt_type,
	ioctl:pkt_type_ioctl,
};

int __init pkt_type_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("pkttype",0,proc_path,pkt_type_read_proc,NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file pkttype : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit pkt_type_exit(void)
{
	unregister_function(PKT_TYPE);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("pkttype",proc_path);
#endif
}

module_init(pkt_type_init);
module_exit(pkt_type_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

