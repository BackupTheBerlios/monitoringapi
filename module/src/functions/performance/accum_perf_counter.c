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
#include <asm/semaphore.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>
#include <linux/mapi/prof.h>

EXPORT_NO_SYMBOLS;

PRIVATE int can_use;
struct semaphore can_use_sem;

extern struct msrs cpu_msrs;

PRIVATE kmem_cache_t *accum_perf_counter_cache;

PRIVATE __u8 accum_perf_counter_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long accum_perf_counter(struct sk_buff **skb,struct sock *sk,struct predef_func *pfunc)
{
	u32 ctr_count[PERF_MAX_COUNTERS];
	struct accum_perf_counter_struct *apcps = (struct accum_perf_counter_struct *)pfunc->data;
	struct skb_mapi_anno *skb_anno = skb_mapianno(sk);
	struct perf_counter *ctr = apcps->ctr;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	int i;
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	prof(ctr,&cpu_msrs,ctr_count);
	
	for( i = 0 ; i < prof_num_counters() ; ++i) 
	{
		spin_lock(&(pfunc->data_lock));
		{
			apcps->ctr[i].count += (ctr_count[i] - skb_anno->ctr_count[i]);
		}
		spin_unlock(&(pfunc->data_lock));
	}

	return 0;
}

PRIVATE int add_accum_perf_counter(struct sock *sk,struct predef_func *pfunc)
{
	struct accum_perf_counter_struct *apcps = (struct accum_perf_counter_struct *)pfunc->data;
	int i,ret;
	
	for( i = 0 ; i < prof_num_counters() ; i++)
	{
		apcps->ctr[i].count = 0;
	}
	
	//only one such module per system must be active!
	if(down_interruptible(&can_use_sem))
	{
		return -ERESTARTSYS;
	}
	
	if(!can_use)
	{
		up(&can_use_sem);
		
		return -EPERM;
	}
	
	can_use = 0;

	up(&can_use_sem);
	
	if((ret = check_params(apcps->ctr,prof_num_counters())) != 0)
	{
		return ret;
	}

	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_accum_perf_counter(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	kmem_cache_free(accum_perf_counter_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);
	
	if(down_interruptible(&can_use_sem))
	{
		return -ERESTARTSYS;
	}

	can_use = 1;
	
	up(&can_use_sem);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE int reset_accum_perf_counter(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct accum_perf_counter_struct *apcps;
	int i;
	
	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	apcps = (struct accum_perf_counter_struct *)found->data;

	spin_lock(&(found->data_lock));
	{
		for( i = 0 ; i < prof_num_counters() ; i++)
		{
			apcps->ctr[i].count = 0;
		}
	}
	spin_unlock(&(found->data_lock));

	return 0;
}

PRIVATE struct predef_func *getresults_accum_perf_counter(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void accum_perf_counter_init_pfunc(struct predef_func *pfunc,struct accum_perf_counter_struct *apcps)
{
	init_pfunc(pfunc);
	
	pfunc->type = ACCUM_PERF_COUNTER;
	pfunc->data = (unsigned long)apcps;
	pfunc->func = accum_perf_counter;
	pfunc->equals = accum_perf_counter_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct accum_perf_counter_struct *apcps;
	struct predef_func *pfunc;

	if((apcps = kmem_cache_alloc(accum_perf_counter_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(accum_perf_counter_cache,apcps);

		return NULL;
	}

	accum_perf_counter_init_pfunc(pfunc,apcps);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_accum_perf_counter(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		struct accum_perf_counter_struct *apcps = (struct accum_perf_counter_struct *)pfunc->data;
		struct accum_perf_counter_struct *arg_apcps = (struct accum_perf_counter_struct *)arg;
		u16 i;
	
		for( i = 0 ; i < prof_num_counters(); i++)
		{
			if(put_user(apcps->ctr[i].count,(int *)(&(arg_apcps->ctr[i].count))))
			{
				return -EFAULT;
			}
		}
	}

	return 0;
}

PRIVATE inline int fill_fields(struct accum_perf_counter_struct *apcps,unsigned long arg)
{
	struct accum_perf_counter_struct *arg_apcps = (struct accum_perf_counter_struct *)arg;
	struct perf_counter *arg_ctr = arg_apcps->ctr;
	struct perf_counter *ctr = apcps->ctr;
	int i;
	
	for( i = 0 ; i < prof_num_counters() ; i++)
	{
		if(get_user(ctr[i].enabled,(int *)(&((arg_ctr[i].enabled)))) ||
		   get_user(ctr[i].event,(int *)(&((arg_ctr[i].event)))) ||
		   get_user(ctr[i].unit_mask,(int *)(&((arg_ctr[i].unit_mask)))))
		{
			return -EFAULT;
		}
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
	
	if((*status = fill_fields((struct accum_perf_counter_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(accum_perf_counter_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int accum_perf_counter_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSACCUM_PERF_COUNTER && cmd != SIOCGACCUM_PERF_COUNTER && cmd != SIOCRSACCUM_PERF_COUNTER && 
	   cmd != SIOCRMACCUM_PERF_COUNTER)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCSACCUM_PERF_COUNTER:
			if((ret = add_accum_perf_counter(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCGACCUM_PERF_COUNTER:
			ret = put_fields_to_userspace(sk,pfunc,arg);			
			break;
			
		case SIOCRSACCUM_PERF_COUNTER:
			ret = reset_accum_perf_counter(sk,pfunc);
			break;

		case SIOCRMACCUM_PERF_COUNTER:
			ret = remove_accum_perf_counter(sk,pfunc,1);
			break;
	}

	kmem_cache_free(accum_perf_counter_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int accum_perf_counter_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct accum_perf_counter_struct *apcps = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Total_Events\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,ACCUM_PERF_COUNTER);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			apcps = (struct accum_perf_counter_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  %-12d\n", s, apcps->ctr[0].count);

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
	index:ACCUM_PERF_COUNTER,
	owner:THIS_MODULE,
	add:add_accum_perf_counter,
	remove:remove_accum_perf_counter,
	ioctl:accum_perf_counter_ioctl,
};

int __init accum_perf_counter_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("accump", 0, proc_path,accum_perf_counter_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file accump : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((accum_perf_counter_cache = kmem_cache_create("accump",sizeof(struct accum_perf_counter_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create accum_perf_counter_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	sema_init(&can_use_sem,1);
	
	can_use = 1;

	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit accum_perf_counter_exit(void)
{
	unregister_function(ACCUM_PERF_COUNTER);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("accump",proc_path);
#endif
	if(kmem_cache_destroy(accum_perf_counter_cache))
	{
		printk(KERN_ALERT "Error : Could not remove accum_perf_counter_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(accum_perf_counter_init);
module_exit(accum_perf_counter_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

