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
#include <asm/atomic.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *count_packets_cache;

PRIVATE atomic_t uid_nr = ATOMIC_INIT(0);

PRIVATE __u8 count_packets_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	struct count_packets_struct *fcps = (struct count_packets_struct *)fpf->data;
	struct count_packets_struct *scps = (struct count_packets_struct *)spf->data;
	
	if((fpf->type == spf->type) && (fcps->uid == scps->uid))
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long count_packets(struct sk_buff **skb,struct sock *sk,struct predef_func *pfunc)
{
	struct count_packets_struct *cps = (struct count_packets_struct *)pfunc->data;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	spin_lock(&(pfunc->data_lock));

	cps->counter++;
	
	spin_unlock(&(pfunc->data_lock));

	return 0;
}

PRIVATE int add_count_packets(struct sock *sk,struct predef_func *pfunc)
{
	struct count_packets_struct *cps = (struct count_packets_struct *)pfunc->data;
	int ret;
	
	cps->counter = 0;
	cps->uid = atomic_read(&uid_nr);
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		atomic_inc(&(uid_nr));
		
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_count_packets(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	kmem_cache_free(count_packets_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE int reset_count_packets(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct count_packets_struct *cps;

	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	cps = (struct count_packets_struct *)found->data;

	spin_lock(&(found->data_lock));
	{
		cps->counter = 0;
	}
	spin_unlock(&(found->data_lock));

	return 0;
}

PRIVATE struct predef_func *getresults_count_packets(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void count_packets_init_pfunc(struct predef_func *pfunc,struct count_packets_struct *cps)
{
	init_pfunc(pfunc);
	
	pfunc->type = COUNT_PACKETS;
	pfunc->data = (unsigned long)cps;
	pfunc->func = count_packets;
	pfunc->equals = count_packets_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct count_packets_struct *cps;
	struct predef_func *pfunc;

	if((cps = kmem_cache_alloc(count_packets_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(count_packets_cache,cps);

		return NULL;
	}

	count_packets_init_pfunc(pfunc,cps);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_count_packets(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		struct count_packets_struct *cps = (struct count_packets_struct *)pfunc->data;
		struct count_packets_struct *arg_cps = (struct count_packets_struct *)arg;

		if(copy_to_user(&(arg_cps->counter),&(cps->counter),sizeof(__u64)))
		{
			return -EFAULT;
		}
	}

	return 0;
}

PRIVATE inline int fill_fields(struct count_packets_struct *cps,unsigned long arg)
{
	if(copy_from_user(cps,(void *)arg,sizeof(struct count_packets_struct)))
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
	
	if((*status = fill_fields((struct count_packets_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(count_packets_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int count_packets_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSCOUNT_PACKETS && cmd != SIOCGCOUNT_PACKETS && cmd != SIOCRSCOUNT_PACKETS && 
	   cmd != SIOCRMCOUNT_PACKETS)
	{
		return ret;
	}

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}
	
	switch(cmd)
	{
		case SIOCSCOUNT_PACKETS:
			{
				struct count_packets_struct *cps;
				struct count_packets_struct *arg_cps;
				
				if((ret = add_count_packets(sk,pfunc)) != 0)
				{
					break;
				}
				
				cps = (struct count_packets_struct *)pfunc->data;
				arg_cps = (struct count_packets_struct *)arg;
					
				if(put_user(cps->uid,(u16 *)&(arg_cps->uid)))
				{
					return -EFAULT;
				}

				return ret;
			}
			
		case SIOCGCOUNT_PACKETS:
			ret = put_fields_to_userspace(sk,pfunc,arg);			
			break;
			
		case SIOCRSCOUNT_PACKETS:
			ret = reset_count_packets(sk,pfunc);
			break;

		case SIOCRMCOUNT_PACKETS:
			ret = remove_count_packets(sk,pfunc,1);
			break;
	}

	kmem_cache_free(count_packets_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int count_packets_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct count_packets_struct *cps = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Total_Packets\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,COUNT_PACKETS);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			cps = (struct count_packets_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  %.13lld\n", s, cps->counter);

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
	index:COUNT_PACKETS,
	owner:THIS_MODULE,
	add:add_count_packets,
	remove:remove_count_packets,
	ioctl:count_packets_ioctl,
};

int __init count_packets_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("countpackets", 0, proc_path, count_packets_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file countpackets : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((count_packets_cache = kmem_cache_create("countp",sizeof(struct count_packets_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create count_packets_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit count_packets_exit(void)
{
	unregister_function(COUNT_PACKETS);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("countpackets",proc_path);
#endif
	if(kmem_cache_destroy(count_packets_cache))
	{
		printk(KERN_ALERT "Error : Could not remove count_packets_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(count_packets_init);
module_exit(count_packets_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

