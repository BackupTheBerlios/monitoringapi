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

PRIVATE kmem_cache_t *band_meter_cache;

struct private_struct
{
	__u64 total_bytes;
	struct timeval stamp;
	struct timer_list timeout_timer;
	__u8 stop_timer;
};

#define function_cb(bms) ((struct private_struct *)(((struct band_meter_struct *)bms)->cb))

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
	struct band_meter_struct *bms = (struct band_meter_struct *)data;
	struct private_struct *cb = function_cb(bms);
	struct timeval stamp;
	
	if(cb->total_bytes == 0)
	{
		bms->bytes_per_sec = 0;

		goto timer;
	}
	
	tv_stamp(&stamp);
	
	elapsed_time = compute_elapsed_time_millis(&stamp,&(cb->stamp));
	bms->bytes_per_sec = (cb->total_bytes/elapsed_time)*1000;

	memset(&(cb->stamp),0,sizeof(struct timeval));
	cb->total_bytes = 0;

timer:
	if(cb->stop_timer == 0)
	{
		init_timer(&(cb->timeout_timer));
		
		cb->timeout_timer.function = check_timeout;
		cb->timeout_timer.data = (unsigned long)bms;
		cb->timeout_timer.expires = jiffies + HZ*bms->interval;

		add_timer(&(cb->timeout_timer));
	}
}

PRIVATE __u8 band_meter_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long band_meter(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct band_meter_struct *bms = (struct band_meter_struct *)pfunc->data;
	struct private_struct *cb = function_cb(bms);
	struct sk_buff *skb = *skbp;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	spin_lock(&(pfunc->data_lock));
	cb->total_bytes += skb->len;
	spin_unlock(&(pfunc->data_lock));
	
	if(cb->stamp.tv_sec == 0)
	{
		cb->stamp = skb->stamp;

		return 0;
	}

	return 0;
}

PRIVATE int add_band_meter(struct sock *sk,struct predef_func *pfunc)
{
	struct band_meter_struct *bms = (struct band_meter_struct *)pfunc->data;
	struct private_struct *cb = function_cb(bms);
	int ret;
	
	bms->bytes_per_sec = 0;
	
	if(bms->interval == 0)
	{
		bms->interval = DEFAULT_INTERVAL;
	}
	
	cb->total_bytes = 0;
	cb->stop_timer = 0;
	memset(&(cb->stamp),0,sizeof(struct timeval));

	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		mapi_module_get(THIS_MODULE);

		check_timeout((unsigned long)bms);		
	}

	return ret;
}

PRIVATE int remove_band_meter(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct band_meter_struct *bms;
	struct private_struct *cb;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	bms = (struct band_meter_struct *)found->data;
	cb = function_cb(bms);
		
	cb->stop_timer = 1;
	del_timer_sync(&(cb->timeout_timer));
	
	kmem_cache_free(band_meter_cache,bms);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE int reset_band_meter(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct band_meter_struct *bms;
	struct private_struct *cb;

	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	bms = (struct band_meter_struct *)found->data;
	cb = function_cb(bms);

	spin_lock(&(found->data_lock));
	{
		bms->bytes_per_sec = 0;
		
		cb->total_bytes = 0;
		memset(&(cb->stamp),0,sizeof(struct timeval));
	}
	spin_unlock(&(found->data_lock));

	return 0;
}

PRIVATE struct predef_func *getresults_band_meter(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void band_meter_init_pfunc(struct predef_func *pfunc,struct band_meter_struct *bms)
{
	init_pfunc(pfunc);
	
	pfunc->type = BAND_METER;
	pfunc->data = (unsigned long)bms;
	pfunc->func = band_meter;
	pfunc->equals = band_meter_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct band_meter_struct *bms;
	struct predef_func *pfunc;

	if((bms = kmem_cache_alloc(band_meter_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(band_meter_cache,bms);

		return NULL;
	}

	band_meter_init_pfunc(pfunc,bms);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_band_meter(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		struct band_meter_struct *bms = (struct band_meter_struct *)pfunc->data;
		struct band_meter_struct *arg_bms = (struct band_meter_struct *)arg;
		
		if(put_user(bms->bytes_per_sec,(float *)(&(arg_bms->bytes_per_sec))))
		{
			return -EFAULT;
		}
	}

	return 0;
}

PRIVATE inline int fill_fields(struct band_meter_struct *bms,unsigned long arg)
{
	struct band_meter_struct *arg_bms = (struct band_meter_struct *)arg;
	
	if(get_user(bms->interval,(u16 *)(&(arg_bms->interval))))
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
	
	if((*status = fill_fields((struct band_meter_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(band_meter_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int band_meter_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSBAND_METER && cmd != SIOCGBAND_METER && cmd != SIOCRSBAND_METER && cmd != SIOCRMBAND_METER)
	{
		return ret;
	}

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCGBAND_METER:
			ret = put_fields_to_userspace(sk,pfunc,arg);			
			break;
			
		case SIOCSBAND_METER:
			if((ret = add_band_meter(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;
			
		case SIOCRSBAND_METER:
			ret = reset_band_meter(sk,pfunc);
			break;

		case SIOCRMBAND_METER:
			ret = remove_band_meter(sk,pfunc,1);
			break;
	}

	kmem_cache_free(band_meter_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int band_meter_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct band_meter_struct *bms = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Bytes/sec\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,BAND_METER);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			bms = (struct band_meter_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  %-13d\n",s,(int)bms->bytes_per_sec);

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
	index:BAND_METER,
	owner:THIS_MODULE,
	add:add_band_meter,
	remove:remove_band_meter,
	ioctl:band_meter_ioctl,
};

int __init band_meter_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("bandmeter", 0, proc_path, band_meter_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file bandmeter : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((band_meter_cache = kmem_cache_create("bandmeter",sizeof(struct band_meter_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create band_meter_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit band_meter_exit(void)
{
	unregister_function(BAND_METER);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("bandmeter",proc_path);
#endif
	if(kmem_cache_destroy(band_meter_cache))
	{
		printk(KERN_ALERT "Error : Could not remove band_meter_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(band_meter_init);
module_exit(band_meter_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

