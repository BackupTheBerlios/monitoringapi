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

#include <linux/mapi/packet.h>
#include <linux/mapi/timeval.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

#define DEFAULT_INTERVAL 3

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *meter_cache;

struct private_struct
{
	__u64 total_packets;
	struct timeval stamp;
	struct timer_list timeout_timer;
	__u8 stop_timer;
};

#define function_cb(ms) ((struct private_struct *)(((struct meter_struct *)ms)->cb))

PRIVATE double compute_elapsed_time_millis(struct timeval *end_tv,struct timeval *start_tv)
{
	double elapsed_time = (1000*(end_tv->tv_sec - start_tv->tv_sec));
	
	if(end_tv->tv_usec < start_tv->tv_usec)
	{
		elapsed_time += ((1000000 + (start_tv->tv_usec - end_tv->tv_usec)) / ((float)1000));
	}
	else
	{
		elapsed_time += ((end_tv->tv_usec - start_tv->tv_usec) / ((float)1000));
	}

	return elapsed_time;
}

PRIVATE void check_timeout(unsigned long data)
{
	double elapsed_time;
	struct meter_struct *ms = (struct meter_struct *)data;
	struct private_struct *cb = function_cb(ms);
	struct timeval stamp;
	
	if(cb->total_packets == 0)
	{
		ms->pkts_per_sec = 0;

		goto timer;
	}
	
	tv_stamp(&stamp);
	
	elapsed_time = compute_elapsed_time_millis(&stamp,&(cb->stamp));
	ms->pkts_per_sec = (cb->total_packets/elapsed_time)*1000;

	memset(&(cb->stamp),0,sizeof(struct timeval));
	cb->total_packets = 0;

timer:
	if(cb->stop_timer == 0)
	{
		init_timer(&(cb->timeout_timer));
		
		cb->timeout_timer.function = check_timeout;
		cb->timeout_timer.data = (unsigned long)ms;
		cb->timeout_timer.expires = jiffies + HZ*ms->interval;

		add_timer(&(cb->timeout_timer));
	}
}

PRIVATE __u8 meter_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long meter(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct meter_struct *ms = (struct meter_struct *)pfunc->data;
	struct private_struct *cb = function_cb(ms);
	struct sk_buff *skb = *skbp;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	spin_lock(&(pfunc->data_lock));
	cb->total_packets++;
	spin_unlock(&(pfunc->data_lock));
	
	if(cb->stamp.tv_sec == 0)
	{
		cb->stamp = skb->stamp;

		return 0;
	}

	return 0;
}

PRIVATE int add_meter(struct sock *sk,struct predef_func *pfunc)
{
	struct meter_struct *ms = (struct meter_struct *)pfunc->data;
	struct private_struct *cb = function_cb(ms);
	int ret;
	
	ms->pkts_per_sec = 0;
	
	if(ms->interval == 0)
	{
		ms->interval = DEFAULT_INTERVAL;
	}
	
	cb->total_packets = 0;
	cb->stop_timer = 0;
	memset(&(cb->stamp),0,sizeof(struct timeval));

	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		mapi_module_get(THIS_MODULE);

		check_timeout((unsigned long)ms);		
	}

	return ret;
}

PRIVATE int remove_meter(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct meter_struct *ms;
	struct private_struct *cb;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	ms = (struct meter_struct *)found->data;
	cb = function_cb(ms);
		
	cb->stop_timer = 1;
	del_timer_sync(&(cb->timeout_timer));
	
	kmem_cache_free(meter_cache,ms);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE int reset_meter(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct meter_struct *ms;
	struct private_struct *cb;

	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	ms = (struct meter_struct *)found->data;
	cb = function_cb(ms);

	spin_lock(&(found->data_lock));
	{
		ms->pkts_per_sec = 0;
		
		cb->total_packets = 0;
		memset(&(cb->stamp),0,sizeof(struct timeval));
	}
	spin_unlock(&(found->data_lock));

	return 0;
}

PRIVATE struct predef_func *getresults_meter(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void meter_init_pfunc(struct predef_func *pfunc,struct meter_struct *ms)
{
	init_pfunc(pfunc);
	
	pfunc->type = METER;
	pfunc->data = (unsigned long)ms;
	pfunc->func = meter;
	pfunc->equals = meter_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct meter_struct *ms;
	struct predef_func *pfunc;

	if((ms = kmem_cache_alloc(meter_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(meter_cache,ms);

		return NULL;
	}

	meter_init_pfunc(pfunc,ms);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_meter(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		struct meter_struct *ms = (struct meter_struct *)pfunc->data;
		struct meter_struct *arg_ms = (struct meter_struct *)arg;
		
		if(put_user(ms->pkts_per_sec,(float *)(&(arg_ms->pkts_per_sec))))
		{
			return -EFAULT;
		}
	}

	return 0;
}

PRIVATE inline int fill_fields(struct meter_struct *ms,unsigned long arg)
{
	struct meter_struct *arg_ms = (struct meter_struct *)arg;
	
	if(get_user(ms->interval,(u16 *)(&(arg_ms->interval))))
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
	
	if((*status = fill_fields((struct meter_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(meter_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int meter_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSMETER && cmd != SIOCGMETER && cmd != SIOCRSMETER && cmd != SIOCRMMETER)
	{
		return ret;
	}

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCGMETER:
			ret = put_fields_to_userspace(sk,pfunc,arg);			
			break;
			
		case SIOCSMETER:
			if((ret = add_meter(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;
			
		case SIOCRSMETER:
			ret = reset_meter(sk,pfunc);
			break;

		case SIOCRMMETER:
			ret = remove_meter(sk,pfunc,1);
			break;
	}

	kmem_cache_free(meter_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int meter_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct meter_struct *ms = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Bytes/sec\n");

	lock_active_socket_list();

	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,METER);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			ms = (struct meter_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  %-13d\n",s,(int)ms->pkts_per_sec);

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
	index:METER,
	owner:THIS_MODULE,
	add:add_meter,
	remove:remove_meter,
	ioctl:meter_ioctl,
};

int __init meter_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("meter", 0, proc_path, meter_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file meter : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((meter_cache = kmem_cache_create("meter",sizeof(struct meter_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create meter_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit meter_exit(void)
{
	unregister_function(METER);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("meter",proc_path);
#endif
	if(kmem_cache_destroy(meter_cache))
	{
		printk(KERN_ALERT "Error : Could not remove meter_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(meter_init);
module_exit(meter_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

