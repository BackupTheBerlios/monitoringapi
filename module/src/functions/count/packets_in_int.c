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

#include <linux/mapi/async.h>
#include <linux/mapi/timeval.h>
#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *packets_in_interval_cache;

struct private_struct
{
	struct fasync_struct *notify_queue;
	u8 signal_sent;
	u64 time_elapsed;
};

#define function_cb(pin) ((struct private_struct *)(((struct packets_in_interval_struct *)pin)->cb))

PRIVATE __u8 packets_in_interval_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long packets_in_interval(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct timeval tv;
	u64 elapsed_time;
	struct packets_in_interval_struct *pin = (struct packets_in_interval_struct *)pfunc->data;
	struct private_struct *cb = function_cb(pin);
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if((pin->start_time.tv_sec == 0) && (pin->start_time.tv_usec == 0))
	{
		tv_stamp(&(pin->start_time));
	}
	
	tv_stamp(&tv);
	
	elapsed_time = (tv.tv_sec - pin->start_time.tv_sec)*1000000 + (tv.tv_usec - pin->start_time.tv_usec);
	
	/* Used for debugging purposes
	 */
	cb->time_elapsed = elapsed_time;
	
	if(elapsed_time <= pin->time_interval)
	{
		spin_lock(&(pfunc->data_lock));
		pin->counter++;
		spin_unlock(&(pfunc->data_lock));
	}
	else
	{
		spin_lock(&(pfunc->data_lock));
		
		if(!cb->signal_sent)
		{
			cb->signal_sent = 1;
			
			if(cb->notify_queue != NULL)
			{
				kill_fasync(&(cb->notify_queue),SIGIO,POLL_IN);
			}
		}
		
		spin_unlock(&(pfunc->data_lock));
	}

	return 0;
}

PRIVATE int add_packets_in_interval(struct sock *sk,struct predef_func *pfunc)
{
	struct packets_in_interval_struct *pin = (struct packets_in_interval_struct *)pfunc->data;
	struct private_struct *cb = function_cb(pin);	
	int ret;
	
	pin->counter = 0;
	memset(&(pin->start_time),0,sizeof(struct timeval));
	
	cb->notify_queue = NULL;
	cb->signal_sent = 0;
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_packets_in_interval(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct packets_in_interval_struct *pin;
	struct private_struct *cb;
	int ret;
	
	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	pin = (struct packets_in_interval_struct *)found->data;
	cb = function_cb(pin);

	kmem_cache_free(packets_in_interval_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);
	
	mapi_module_put(THIS_MODULE);

	if((ret = remove_async_notification(sk,&(cb->notify_queue))) < 0)
	{
		return ret;
	}
	
	return 0;
}

PRIVATE int reset_packets_in_interval(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct packets_in_interval_struct *pin;
	struct private_struct *cb;

	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	pin = (struct packets_in_interval_struct *)found->data;
	cb = function_cb(pin);
	
	spin_lock(&(found->data_lock));
	{
		pin->counter = 0;
		memset(&(pin->start_time),0,sizeof(struct timeval));
		cb->signal_sent = 0;
	}
	spin_unlock(&(found->data_lock));
	
	return 0;
}

PRIVATE void packets_in_interval_init_pfunc(struct predef_func *pfunc,struct packets_in_interval_struct *pin)
{
	init_pfunc(pfunc);
	
	pfunc->type = PACKETS_IN_INTERVAL;
	pfunc->data = (unsigned long)pin;
	pfunc->func = packets_in_interval;
	pfunc->equals = packets_in_interval_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct packets_in_interval_struct *pin;
	struct predef_func *pfunc;

	if((pin = kmem_cache_alloc(packets_in_interval_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(packets_in_interval_cache,pin);

		return NULL;
	}

	packets_in_interval_init_pfunc(pfunc,pin);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = sk_find_predef(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		struct packets_in_interval_struct *pin = (struct packets_in_interval_struct *)pfunc->data;
		struct packets_in_interval_struct *upin = (struct packets_in_interval_struct *)arg;
		
		if(copy_to_user(&(upin->start_time),&(pin->start_time),sizeof(struct timeval)) ||
		   copy_to_user(&(upin->counter),&(pin->counter),sizeof(u64)))
		{
			return -EFAULT;
		}
	}

	return 0;
}

PRIVATE inline int fill_fields(struct packets_in_interval_struct *pin,unsigned long arg)
{
	if(copy_from_user(&(pin->time_interval),&(((struct packets_in_interval_struct *)arg)->time_interval),sizeof(u64)) ||
	   copy_from_user(&(pin->pid),&(((struct packets_in_interval_struct *)arg)->pid),sizeof(pid_t)))
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
	
	if((*status = fill_fields((struct packets_in_interval_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(packets_in_interval_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int packets_in_interval_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSPACKETS_IN_INTERVAL && cmd != SIOCGPACKETS_IN_INTERVAL && cmd != SIOCRSPACKETS_IN_INTERVAL && 
	   cmd != SIOCRMPACKETS_IN_INTERVAL && cmd != SIOCSASYNCPACKETS_IN_INTERVAL && cmd != SIOCRMASYNCPACKETS_IN_INTERVAL)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}
	
	switch(cmd)
	{
		case SIOCSPACKETS_IN_INTERVAL:
			if((ret = add_packets_in_interval(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCGPACKETS_IN_INTERVAL:
			ret = put_fields_to_userspace(sk,pfunc,arg);			
			break;
			
		case SIOCRSPACKETS_IN_INTERVAL:
			ret = reset_packets_in_interval(sk,pfunc);
			break;

		case SIOCRMPACKETS_IN_INTERVAL:
			ret = remove_packets_in_interval(sk,pfunc,1);
			break;

		case SIOCSASYNCPACKETS_IN_INTERVAL:
			{
				struct predef_func *found;
				struct packets_in_interval_struct *pin;
				struct private_struct *cb;

				if((found = sk_find_predef(sk,pfunc)) == NULL)
				{
					ret = -ENODATA;

					break;
				}
				
				pin = (struct packets_in_interval_struct *)found->data;
				cb = function_cb(pin);

				ret = add_async_notification(sk,&(cb->notify_queue),pin->pid);
			}
			break;
			
		case SIOCRMASYNCPACKETS_IN_INTERVAL:
			{
				struct predef_func *found;
				struct packets_in_interval_struct *pin;
				struct private_struct *cb;
				
				if((found = sk_find_predef(sk,pfunc)) == NULL)
				{
					ret = -ENODATA;

					break;
				}
			
				pin = (struct packets_in_interval_struct *)found->data;
				cb = function_cb(pin);
				
				ret = remove_async_notification(sk,&(cb->notify_queue));
			}	
			break;
	}

	kmem_cache_free(packets_in_interval_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int packets_in_interval_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct packets_in_interval_struct *pin = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Time_Interval Total_Packets Time_Elapsed\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,PACKETS_IN_INTERVAL);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			struct private_struct *cb;
			
			pin = (struct packets_in_interval_struct *)cur->data;
			cb = function_cb(pin);
			
			len += sprintf(buffer + len,"%8p  %.13lld %.13lld %.12lld\n",s,pin->time_interval,pin->counter,cb->time_elapsed);

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
	index:PACKETS_IN_INTERVAL,
	owner:THIS_MODULE,
	add:add_packets_in_interval,
	remove:remove_packets_in_interval,
	ioctl:packets_in_interval_ioctl,
};

int __init packets_in_interval_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("packetsint", 0, proc_path, packets_in_interval_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file packetsint : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	
	if((packets_in_interval_cache = kmem_cache_create("packetsint",sizeof(struct packets_in_interval_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create packets_in_interval_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit packets_in_interval_exit(void)
{
	unregister_function(PACKETS_IN_INTERVAL);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("packetsint",proc_path);
#endif
	
	if(kmem_cache_destroy(packets_in_interval_cache))
	{
		printk(KERN_ALERT "Error : Could not remove packets_in_interval_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(packets_in_interval_init);
module_exit(packets_in_interval_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

