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

PRIVATE __u8 packet_save_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long packet_save(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct packet_save_struct *pss = (struct packet_save_struct *)pfunc->data;
	struct sk_buff *skb = *skbp;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if(skb->len < pss->start_byte || skb->len < pss->end_byte)
	{
		return 0;
	}
	
	if((skb = mapi_skb_private(skbp,sk)) == NULL)
	{
		return -ENOMEM;
	}
	
	skb->data = &(skb->data[pss->start_byte]);
	skb->tail = &(skb->data[pss->end_byte]);
	skb->len = pss->end_byte - pss->start_byte + 1;
	
	if(pss->receive_packet)
	{
		receive(skbp,sk);
	}
	
	return 0;
}

PRIVATE int add_packet_save(struct sock *sk,struct predef_func *pfunc)
{
	struct packet_save_struct *pss = (struct packet_save_struct *)pfunc->data;
	int ret;
	
	if(pss->end_byte < pss->start_byte)
	{
		return -EINVAL;
	}
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);		
	}

	return ret;
}

PRIVATE int remove_packet_save(struct sock *sk,struct predef_func *pfunc,int lock)
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

PRIVATE void packet_save_init_pfunc(struct predef_func *pfunc,struct packet_save_struct *pss)
{
	init_pfunc(pfunc);
	
	pfunc->type = PACKET_SAVE;
	pfunc->data = (unsigned long)pss;
	pfunc->func = packet_save;
	pfunc->equals = packet_save_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct packet_save_struct *pss;
	struct predef_func *pfunc;

	if((pss = kmalloc(sizeof(struct packet_save_struct),GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kfree(pss);

		return NULL;
	}

	packet_save_init_pfunc(pfunc,pss);

	return pfunc;
}

PRIVATE inline int fill_fields(struct packet_save_struct *pss,unsigned long arg)
{
	if(copy_from_user(pss,(struct packet_save_struct *)arg,sizeof(struct packet_save_struct)))
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
	
	if((*status = fill_fields((struct packet_save_struct *)pfunc->data,arg)) != 0)
	{
		kfree((void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int packet_save_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSPACKET_SAVE && cmd != SIOCRMPACKET_SAVE)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}
	
	switch(cmd)
	{
		case SIOCSPACKET_SAVE:
			if((ret = add_packet_save(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCRMPACKET_SAVE:
			ret = remove_packet_save(sk,pfunc,1);
			break;
	}

	kfree((void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int packet_save_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct packet_save_struct *pss = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Start_Byte  End_byte\n");

	lock_active_socket_list();

	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,PACKET_SAVE);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			pss = (struct packet_save_struct *)cur->data;
			len += sprintf(buffer + len,"%8p  %.10d  %.8d\n",s,pss->start_byte,pss->end_byte);

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
	index:PACKET_SAVE,
	owner:THIS_MODULE,
	add:add_packet_save,
	remove:remove_packet_save,
	ioctl:packet_save_ioctl,
};

int __init packet_save_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("packetsave",0,proc_path,packet_save_read_proc,NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file packetsave : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit packet_save_exit(void)
{
	unregister_function(PACKET_SAVE);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("packetsave",proc_path);
#endif
}

module_init(packet_save_init);
module_exit(packet_save_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

