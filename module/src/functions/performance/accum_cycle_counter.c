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

PRIVATE kmem_cache_t *accum_cycle_counter_cache;

PRIVATE __u8 accum_cycle_counter_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long accum_cycle_counter(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct accum_cycle_counter_struct *accs = (struct accum_cycle_counter_struct *)pfunc->data;
	struct skb_mapi_anno *skb_anno = skb_mapianno(sk);
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	spin_lock(&(pfunc->data_lock));

	accs->total_cycles += (get_cycles() - skb_anno->cycles);
	
	spin_unlock(&(pfunc->data_lock));

	return 0;
}

PRIVATE int add_accum_cycle_counter(struct sock *sk,struct predef_func *pfunc)
{
	struct accum_cycle_counter_struct *accs = (struct accum_cycle_counter_struct *)pfunc->data;
	int ret;
	
	accs->total_cycles = 0;
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_accum_cycle_counter(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	kmem_cache_free(accum_cycle_counter_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE int reset_accum_cycle_counter(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct accum_cycle_counter_struct *accs;

	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	accs = (struct accum_cycle_counter_struct *)found->data;

	spin_lock(&(pfunc->data_lock));
	{
		accs->total_cycles = 0;
	}
	spin_unlock(&(pfunc->data_lock));

	return 0;
}

PRIVATE struct predef_func *getresults_accum_cycle_counter(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void accum_cycle_counter_init_pfunc(struct predef_func *pfunc,struct accum_cycle_counter_struct *accs)
{
	init_pfunc(pfunc);
	
	pfunc->type = ACCUM_CYCLE_COUNTER;
	pfunc->data = (unsigned long)accs;
	pfunc->func = accum_cycle_counter;
	pfunc->equals = accum_cycle_counter_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct accum_cycle_counter_struct *accs;
	struct predef_func *pfunc;

	if((accs = kmem_cache_alloc(accum_cycle_counter_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(accum_cycle_counter_cache,accs);

		return NULL;
	}

	accum_cycle_counter_init_pfunc(pfunc,accs);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_accum_cycle_counter(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		if(copy_to_user((void *)arg,(void *)pfunc->data,sizeof(struct accum_cycle_counter_struct)))
		{
			return -EFAULT;
		}
	}

	return 0;
}

PRIVATE int accum_cycle_counter_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSACCUM_CYCLE_COUNTER && cmd != SIOCGACCUM_CYCLE_COUNTER && cmd != SIOCRSACCUM_CYCLE_COUNTER && 
	   cmd != SIOCRMACCUM_CYCLE_COUNTER)
	{
		return ret;
	}

	if((pfunc = pfunc_alloc_r()) == NULL)
	{
		return -ENOMEM;
	}

	if(copy_from_user((void *)pfunc->data,(void *)arg,sizeof(struct accum_cycle_counter_struct)))
	{
		kmem_cache_free(accum_cycle_counter_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);
		
		return -EFAULT;
	}

	switch(cmd)
	{
		case SIOCSACCUM_CYCLE_COUNTER:
			
			if((ret = add_accum_cycle_counter(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCGACCUM_CYCLE_COUNTER:
			ret = put_fields_to_userspace(sk,pfunc,arg);			
			break;
			
		case SIOCRSACCUM_CYCLE_COUNTER:
			ret = reset_accum_cycle_counter(sk,pfunc);
			break;

		case SIOCRMACCUM_CYCLE_COUNTER:
			ret = remove_accum_cycle_counter(sk,pfunc,1);
			break;
	}

	kmem_cache_free(accum_cycle_counter_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int accum_cycle_counter_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct accum_cycle_counter_struct *accs = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Total_Cycles\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,ACCUM_CYCLE_COUNTER);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			accs = (struct accum_cycle_counter_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  %.13lld\n", s, accs->total_cycles);

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
	index:ACCUM_CYCLE_COUNTER,
	owner:THIS_MODULE,
	add:add_accum_cycle_counter,
	remove:remove_accum_cycle_counter,
	ioctl:accum_cycle_counter_ioctl,
};

int __init accum_cycle_counter_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("accycle", 0, proc_path, accum_cycle_counter_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file accycle : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((accum_cycle_counter_cache = kmem_cache_create("accycle",sizeof(struct accum_cycle_counter_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create accum_cycle_counter_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit accum_cycle_counter_exit(void)
{
	unregister_function(ACCUM_CYCLE_COUNTER);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("accycle",proc_path);
#endif
	if(kmem_cache_destroy(accum_cycle_counter_cache))
	{
		printk(KERN_ALERT "Error : Could not remove accum_cycle_counter_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(accum_cycle_counter_init);
module_exit(accum_cycle_counter_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

