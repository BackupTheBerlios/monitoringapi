/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include <asm/semaphore.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/cache.h>
#include <linux/threads.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>

PUBLIC struct proc_dir_entry *proc_path;
PUBLIC kmem_cache_t *predef_func_cache;
PUBLIC kmem_cache_t *hw_cache_lines_cache;

EXPORT_SYMBOL(proc_path);
EXPORT_SYMBOL(predef_func_cache);
EXPORT_SYMBOL(hw_cache_lines_cache);

void reset_net_dev_stats()
{
	struct net_device *dev;
	struct net_device_stats *stats;
	
	write_lock(&dev_base_lock);
	
	for (dev = dev_base; dev != NULL; dev = dev->next) 
	{
		stats = dev->get_stats(dev);
		
		memset(stats,0,sizeof(struct net_device_stats));

		printk("Reseting statistics for device %s\n",dev->name);
	}
	
	write_unlock(&dev_base_lock);
}

EXPORT_SYMBOL(reset_net_dev_stats);

int __init init_mapi()
{
#ifdef CONFIG_PROC_FS
	if((proc_path = proc_mkdir("mapi_func",proc_net)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc directory mapi : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((predef_func_cache = kmem_cache_create("predeffunc",sizeof(struct predef_func),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create predef_func_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
#if defined(CONFIG_FILTER) && defined(CONFIG_CACHED_BPF)
	if((hw_cache_lines_cache = kmem_cache_create("hwcline",L1_CACHE_BYTES,0,SLAB_HWCACHE_ALIGN | SLAB_NO_REAP,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create hw_cache_lines_cache : %s,%i\n",__FILE__,__LINE__);
		
		return -EPERM;
	}
#endif

	reset_net_dev_stats();
	
	return 0;
}

int __exit exit_mapi()
{
#ifdef CONFIG_PROC_FS
	remove_proc_entry("mapi_func",proc_net);
#endif
        if(kmem_cache_destroy(predef_func_cache))
        {
                printk(KERN_ALERT "Error : Could not remove predef_func_cache : %s,%i\n",__FILE__,__LINE__);
                
                return -EPERM;
        }
	
        if(kmem_cache_destroy(hw_cache_lines_cache))
        {
                printk(KERN_ALERT "Error : Could not remove hw_cache_lines_cache : %s,%i\n",__FILE__,__LINE__);
                
                return -EPERM;
        }
	
	return 0;
}

int init_when_create_sock(struct sock *sk)
{
	struct packet_opt *po = mapi_sk(sk);
	
	rwlock_init(&(po->pfunc_list_lock));
	atomic_set(&(po->predef_func_nr),0);

	if((po->per_cpu = kmalloc(NR_CPUS*sizeof(struct mapi_per_cpu),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	return 0;
}

int do_when_destruct_sock(struct sock *sk)
{
	struct packet_opt *po = mapi_sk(sk);
	
	remove_all_func(sk);
	kfree(po->per_cpu);
	
	return 0;
}

EXPORT_SYMBOL(init_when_create_sock);
EXPORT_SYMBOL(do_when_destruct_sock);

// vim:ts=8:expandtab

