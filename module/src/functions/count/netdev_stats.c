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

PRIVATE kmem_cache_t *netdev_stats_cache;

PRIVATE __u8 netdev_stats_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long netdev_stats(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct netdev_stats_struct *nss = (struct netdev_stats_struct *)pfunc->data;
	struct net_device_stats *limits = &(nss->limits);
	struct net_device *dev = (*skbp)->dev;
	struct net_device_stats *stats = dev->get_stats(dev);
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if(stats->rx_packets > limits->rx_packets && limits->rx_packets != 0)
	{
		printk("rx_packets : %lu\n",stats->rx_packets);
	}
	else if(stats->rx_bytes > limits->rx_bytes && limits->rx_bytes != 0)
	{
		printk("rx_bytes : %lu\n",stats->rx_bytes);
	}
	else if(stats->rx_errors > limits->rx_errors && limits->rx_errors != 0)
	{
		printk("rx_erros : %lu\n",stats->rx_errors);
	}
	else if(stats->rx_dropped > limits->rx_dropped && limits->rx_dropped != 0)
	{
		printk("rx_dropped : %lu\n",stats->rx_dropped);
	}
	else if(stats->multicast > limits->multicast && limits->multicast != 0)
	{
		printk("multicast : %lu\n",stats->multicast);
	}
	else if(stats->rx_length_errors > limits->rx_length_errors && limits->rx_length_errors != 0)
	{
		printk("rx_length_errors : %lu\n",stats->rx_length_errors);
	}
	else if(stats->rx_over_errors > limits->rx_over_errors && limits->rx_over_errors != 0)
	{
		printk("rx_over_errors : %lu\n",stats->rx_over_errors);
	}
	else if(stats->rx_crc_errors > limits->rx_crc_errors && limits->rx_crc_errors != 0)
	{
		printk("rx_crc_errors : %lu\n",stats->rx_crc_errors);
	}
	else if(stats->rx_frame_errors > limits->rx_frame_errors && limits->rx_frame_errors != 0)
	{
		printk("rx_frame_errors : %lu\n",stats->rx_frame_errors);
	}
	else if(stats->rx_fifo_errors > limits->rx_fifo_errors && limits->rx_fifo_errors != 0)
	{
		printk("rx_fifo_errors : %lu\n",stats->rx_fifo_errors);
	}
	else if(stats->rx_missed_errors > limits->rx_missed_errors && limits->rx_missed_errors != 0)
	{
		printk("rx_missed_errors : %lu\n",stats->rx_missed_errors);
	}
	else if(stats->rx_compressed > limits->rx_compressed && limits->rx_compressed != 0)
	{
		printk("rx_compressed : %lu\n",stats->rx_compressed);
	}
	
	return 0;
}

PRIVATE int add_netdev_stats(struct sock *sk,struct predef_func *pfunc)
{
	int ret;
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);		
	}

	return ret;
}

PRIVATE int remove_netdev_stats(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	kmem_cache_free(netdev_stats_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);		

	return 0;
}

PRIVATE int reset_netdev_stats(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct netdev_stats_struct *nss;

	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	nss = (struct netdev_stats_struct *)found->data;

	memset(nss,0,sizeof(struct netdev_stats_struct));
	
	return 0;
}

PRIVATE struct predef_func *getresults_netdev_stats(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void netdev_stats_init_pfunc(struct predef_func *pfunc,struct netdev_stats_struct *nss)
{
	init_pfunc(pfunc);
	
	pfunc->type = NETDEV_STATS;
	pfunc->data = (unsigned long)nss;
	pfunc->func = netdev_stats;
	pfunc->equals = netdev_stats_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r()
{
	struct netdev_stats_struct *nss;
	struct predef_func *pfunc;

	if((nss = kmem_cache_alloc(netdev_stats_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(netdev_stats_cache,nss);

		return NULL;
	}

	netdev_stats_init_pfunc(pfunc,nss);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_netdev_stats(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		if(copy_to_user((void *)arg,(void *)pfunc->data,sizeof(struct netdev_stats_struct)))
		{
			return -EFAULT;
		}
	}

	return 0;
}

PRIVATE int netdev_stats_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSNETDEV_STATS && cmd != SIOCGNETDEV_STATS && cmd != SIOCRSNETDEV_STATS && 
	   cmd != SIOCRMNETDEV_STATS)
	{
		return ret;
	}

	if((pfunc = pfunc_alloc_r()) == NULL)
	{
		return -ENOMEM;
	}

	if(copy_from_user((void *)pfunc->data,(void *)arg,sizeof(struct netdev_stats_struct)))
	{
		kmem_cache_free(netdev_stats_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);
		
		return -EFAULT;
	}

	switch(cmd)
	{
		case SIOCSNETDEV_STATS:
			if((ret = add_netdev_stats(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCGNETDEV_STATS:
			ret = put_fields_to_userspace(sk,pfunc,arg);			
			break;
			
		case SIOCRSNETDEV_STATS:
			ret = reset_netdev_stats(sk,pfunc);
			break;

		case SIOCRMNETDEV_STATS:
			ret = remove_netdev_stats(sk,pfunc,1);
			break;
	}

	kmem_cache_free(netdev_stats_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS

static int sprintf_limits(char *buffer,struct netdev_stats_struct *nss)
{
	struct net_device_stats *limits = &(nss->limits);
	int size;
	
	size = sprintf(buffer,"%8lu %7lu %4lu %4lu %4lu %5lu %10lu %9lu\n",
		   limits->rx_bytes,
		   limits->rx_packets,
		   limits->rx_errors,
		   limits->rx_dropped + limits->rx_missed_errors,
		   limits->rx_fifo_errors,
		   limits->rx_length_errors + limits->rx_over_errors + limits->rx_crc_errors + limits->rx_frame_errors,
		   limits->rx_compressed,
		   limits->multicast
		   );

	return size;
}

PRIVATE int netdev_stats_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct netdev_stats_struct *nss = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      ");
	len += sprintf(buffer + len,"Bytes    Packets Errs Drop Fifo Frame Compressed Multicast\n");
	
	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,NETDEV_STATS);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			nss = (struct netdev_stats_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  ",s);
			len += sprintf_limits(buffer + len,nss);

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
	index:NETDEV_STATS,
	owner:THIS_MODULE,
	add:add_netdev_stats,
	remove:remove_netdev_stats,
	ioctl:netdev_stats_ioctl,
};

int __init netdev_stats_init()
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("netdevstats", 0, proc_path, netdev_stats_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file netdevstats : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((netdev_stats_cache = kmem_cache_create("netdevstats",sizeof(struct netdev_stats_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create netdev_stats_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit netdev_stats_exit()
{
	unregister_function(NETDEV_STATS);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("netdevstats",proc_path);
#endif
	
	if(kmem_cache_destroy(netdev_stats_cache))
	{
		printk(KERN_ALERT "Error : Could not remove netdev_stats_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(netdev_stats_init);
module_exit(netdev_stats_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

