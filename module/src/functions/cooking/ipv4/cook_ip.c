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
#include <mapiipv4.h>
#include <cookip.h>

EXPORT_NO_SYMBOLS;

PUBLIC struct proc_dir_entry *cook_ip_proc_path;
PRIVATE kmem_cache_t *cook_ip_cache;

PRIVATE __u8 cook_ip_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long cook_ip(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct sk_buff *skb = *skbp;
	struct sk_buff *defrag_skb;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	int ret;
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if(skb->protocol != htons(ETH_P_IP))
	{
		return 0;
	}
	
	if((skb = mapi_skb_private(skbp,sk)) == NULL)
	{
		return -ENOMEM;
	}
	
	/* Possible cases : 
	 * 
	 * 1) mapi_ip_rcv returns NULL
	 *    a) virtualy "drop" private skb (*skbp must point to it)
	 *    b) skb appended to a list -> do not kfree skb
	 *    
	 * 2) mapi_ip_rcv returns an skb
	 *    a) make skbp points to this skb -> kfree private skb
	 *
	 */
	if((defrag_skb = mapi_ip_rcv(skb,pfunc)) == NULL)
	{
		skb_mapi->action = SKB_DROP;
		
		return 0;
	}
	
	kfree_skb(skb);
	
	if(skb_is_nonlinear(defrag_skb))
	{
		if((ret = skb_linearize(defrag_skb,GFP_ATOMIC)) != 0)
		{
			skb_mapi->action = SKB_DROP;
			
			return -ENOMEM;
		}
	}
	
	*skbp = defrag_skb;

	return 0;
}

PRIVATE int add_cook_ip(struct sock *sk,struct predef_func *pfunc)
{
	struct cook_ip_struct *cis = (struct cook_ip_struct *)pfunc->data;	
	int ret;

	memset(cis,0,sizeof(struct cook_ip_struct));
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);		
	}

	return ret;
}

PRIVATE int remove_cook_ip(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	kmem_cache_free(cook_ip_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);		

	return 0;
}

PRIVATE int reset_cook_ip(struct sock *sk,struct predef_func *pfunc)
{
	return -ENOSYS;
}

PRIVATE struct predef_func *getresults_cook_ip(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void cook_ip_init_pfunc(struct predef_func *pfunc,struct cook_ip_struct *cis)
{
	init_pfunc(pfunc);

	pfunc->type = COOK_IP;
	pfunc->func = cook_ip;
	pfunc->equals = cook_ip_equals;
	pfunc->data = (unsigned long)cis;
}

PRIVATE struct predef_func *pfunc_alloc_r(void)
{
	struct cook_ip_struct *cis;
	struct predef_func *pfunc;

	if((cis = kmem_cache_alloc(cook_ip_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(cook_ip_cache,cis);

		return NULL;
	}

	cook_ip_init_pfunc(pfunc,cis);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_cook_ip(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		if(copy_to_user((void *)arg,(void *)pfunc->data,sizeof(struct cook_ip_struct)))
		{
			return -EFAULT;
		}
	}

	return 0;
}

PRIVATE int cook_ip_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSCOOK_IP && cmd != SIOCGCOOK_IP && cmd != SIOCRSCOOK_IP && cmd != SIOCRMCOOK_IP)
	{
		return ret;
	}

	if((pfunc = pfunc_alloc_r()) == NULL)
	{
		return -ENOMEM;
	}

	if(copy_from_user((void *)pfunc->data,(void *)arg,sizeof(struct cook_ip_struct)))
	{
		kmem_cache_free(cook_ip_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);
		
		return -EFAULT;
	}

	switch(cmd)
	{
		case SIOCSCOOK_IP:
			if((ret = add_cook_ip(sk,pfunc)) == -EALREADY)
			{
				break;
			}
			
			return ret;

		case SIOCGCOOK_IP:
			ret = put_fields_to_userspace(sk,pfunc,arg);
			break;
			
		case SIOCRSCOOK_IP:
			ret = reset_cook_ip(sk,pfunc);
			break;
			
		case SIOCRMCOOK_IP:
			ret = remove_cook_ip(sk,pfunc,1);
			break;
	}

	kmem_cache_free(cook_ip_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int cook_ip_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct cook_ip_struct *cis = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Defrag_completed IP_hdr_errors IP_options_errors Defrag_errors\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,COOK_IP);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			cis = (struct cook_ip_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  %.16d %.13d %.17d %.13d\n",s,cis->defrag_completed,cis->ip_header_errors,cis->ip_options_errors,cis->defrag_errors);

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
	index:COOK_IP,
	owner:THIS_MODULE,
	add:add_cook_ip,
	remove:remove_cook_ip,
	ioctl:cook_ip_ioctl,
};

int __init cook_ip_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if((cook_ip_proc_path = proc_mkdir("ipv4",proc_path)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc directory ipv4 : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if(create_proc_read_entry("cookip",0,cook_ip_proc_path,cook_ip_read_proc,NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file cookip : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	
	if((cook_ip_cache = kmem_cache_create("cookip",sizeof(struct cook_ip_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create cook_ip_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = mapi_defragmentation_init()) != 0)
	{
		return ret;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit cook_ip_exit(void)
{
	unregister_function(COOK_IP);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("cookip",cook_ip_proc_path);
	remove_proc_entry("ipv4",proc_path);
#endif
	
	if(kmem_cache_destroy(cook_ip_cache))
	{
		printk(KERN_ALERT "Error : Could not remove cook_ip_cache : %s,%i\n",__FILE__,__LINE__);
	}

	mapi_defragmentation_exit();
}

module_init(cook_ip_init);
module_exit(cook_ip_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

