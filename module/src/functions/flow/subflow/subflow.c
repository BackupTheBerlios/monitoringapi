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
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <asm/atomic.h>
#include <asm/errno.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <asm/string.h>
#include <linux/random.h>
#include <linux/byteorder/generic.h>
#include <linux/stat.h>
#include <linux/smp_lock.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/prefetch.h>
#include <linux/vmalloc.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>
#include <linux/mapi/async.h>
#include <linux/mapi/proto.h>

#include <hashtable.h>
#include <subflow.h>
#include <flow_key.h>
#include <subflow_hook.h>

#define COLLECT_STATISTICS

PRIVATE u32 hashtable_capacity = 1000;
PRIVATE struct proc_dir_entry *subflow_proc_path;

PRIVATE inline u8 check_ipstack(struct sk_buff *skb)
{
	struct iphdr *iph;

	if(skb->protocol != htons(ETH_P_IP))
	{
		return 0;
	}
	
	iph = proto_iphdr(skb);
	
	if((iph->protocol != IPPROTO_TCP) && 
	   (iph->protocol != IPPROTO_UDP) &&
	   (iph->protocol != IPPROTO_ICMP))
	{
		return 0;
	}
	
	return 1;
}

PRIVATE inline struct subflow *get_subflow(struct sk_buff *skb,struct subflow_struct *ss)
{
	struct subflow *sbf;
	struct flow_key *fkey;
	
	if((fkey = flow_key_alloc(GFP_ATOMIC)) == NULL)
	{
		return NULL;
	}
	
	get_flow_key_fields(skb,fkey,ss->fks);
		
	write_lock(&(ss->subflow_hash_table_lock));
	sbf = (struct subflow *)hash_get(ss->subflow_hash_table,fkey);
	write_unlock(&(ss->subflow_hash_table_lock));
	
	flow_key_free(fkey);
	
	return sbf;
}

PRIVATE void get_subflow_fields(struct sk_buff *skb,struct subflow *sbf)
{
	struct iphdr *iph;
	u16 src_port,dst_port;
	
	iph = proto_iphdr(skb);

	sbf->src_ip = ntohl(iph->saddr);
	sbf->dst_ip = ntohl(iph->daddr);

	if(iph->protocol == IPPROTO_TCP)
	{
		struct tcphdr *th = proto_tcphdr(skb,iph);

		src_port = th->source;
		dst_port = th->dest;

		sbf->tcp_flags = tcp_flag_word(th) & 0x00FF0000;
	}
	else if(iph->protocol == IPPROTO_UDP)
	{
		struct udphdr *uh = proto_udphdr(skb,iph);

		src_port = uh->source;
		dst_port = uh->dest;
	}
	else
	{
		struct icmphdr *icmp = proto_icmphdr(skb,iph);
		
		sbf->icmp_type = icmp->type;
		sbf->icmp_code = icmp->code;
		
		src_port = dst_port = 0;
	}

	src_port = ntohs(src_port);
	dst_port = ntohs(dst_port);

	sbf->src_port = src_port;
	sbf->dst_port = dst_port;

	sbf->in_dev = skb->dev->ifindex;
	sbf->out_dev = skb->dev->ifindex;
	
	sbf->ip_proto = iph->protocol;
	sbf->ip_version = iph->version;

	sbf->tos = iph->tos;
	sbf->probe_uid = 0;
}

#ifdef COLLECT_STATISTICS
PRIVATE inline void update_subflow_statistics(struct sk_buff *skb,struct subflow *sbf)
{
	double elapsed_time = 0;
	
	if(sbf->end_time.tv_sec < skb->stamp.tv_sec)
	{
		elapsed_time = (1000000*(skb->stamp.tv_sec - sbf->end_time.tv_sec));
	}
	
	if(skb->stamp.tv_usec < sbf->end_time.tv_usec)
	{
		elapsed_time += (1000000 + (skb->stamp.tv_usec - sbf->end_time.tv_usec));
	}
	else
	{
		elapsed_time += (skb->stamp.tv_usec - sbf->end_time.tv_usec);
	}
	
	if(sbf->avg_tbpa != 0)
	{
		double new_avg_tbpa;
		double new_avg_ps;
		
		/* Knuth's The Art Of Computer Programming */
		new_avg_tbpa = sbf->avg_tbpa + (elapsed_time - sbf->avg_tbpa)/(sbf->npackets + 1);
		sbf->std_dev_tbpa += (elapsed_time - sbf->avg_tbpa)*(elapsed_time - new_avg_tbpa);
		sbf->avg_tbpa = new_avg_tbpa;
		
		new_avg_ps = sbf->avg_ps + (skb->len - sbf->avg_ps)/(sbf->npackets + 1);
		sbf->std_dev_ps += (skb->len - sbf->avg_ps)*(skb->len - new_avg_ps);
		sbf->avg_ps = new_avg_ps;
	}
	else
	{
		sbf->avg_tbpa = elapsed_time;
		sbf->avg_ps = skb->len;
	}
	
	sbf->end_time = skb->stamp;
	sbf->npackets++;
	sbf->nbytes += (skb->len);
	
	sbf->avg_tbpa = (sbf->avg_tbpa < 0) ? 0 : sbf->avg_tbpa;
	sbf->std_dev_tbpa = (sbf->std_dev_tbpa < 0) ? 0 : sbf->std_dev_tbpa;
	sbf->avg_ps = (sbf->avg_ps < 0) ? 0 : sbf->avg_ps;
	sbf->std_dev_ps = (sbf->std_dev_ps < 0) ? 0 : sbf->std_dev_ps;
}
#endif

PRIVATE inline void update_subflow(struct sk_buff *skb,struct predef_func *pfunc,struct subflow *sbf)
{
	struct subflow_struct *ss = (struct subflow_struct *)pfunc->data;
	struct subflow_private_struct *cb = subflow_cb(sbf);
	
	if(cb->expired == 1)
	{
		return;
	}
	
#ifdef COLLECT_STATISTICS
	spin_lock(&(pfunc->data_lock));
	update_subflow_statistics(skb,sbf);
	spin_unlock(&(pfunc->data_lock));
#endif	
	
	write_lock(&(ss->subflow_list_lock));
	list_del(&(cb->list));
	list_add_tail(&(cb->list),ss->subflow_list);
	write_unlock(&(ss->subflow_list_lock));
}

PRIVATE inline void first_update_subflow(struct sk_buff *skb,struct subflow *sbf)
{
	sbf->start_time = skb->stamp;
	sbf->end_time = skb->stamp;
	
	sbf->npackets = 1;
	sbf->nbytes = skb->len;
}

PRIVATE inline int new_subflow(struct sk_buff *skb,struct subflow_struct *ss)
{
	struct subflow *sbf;
	struct flow_key *fkey;
	struct subflow_private_struct *cb;
	
	if((fkey = flow_key_alloc(GFP_ATOMIC)) == NULL)
	{
		return -ENOMEM;
	}
	
	if((sbf = kmem_cache_alloc(sub_subflow_cache,GFP_ATOMIC)) == NULL)
	{
		flow_key_free(fkey);
		
		return -ENOMEM;
	}
	
	memset(sbf,0,sizeof(struct subflow));
	
	get_subflow_fields(skb,sbf);
	
	fill_flow_key(fkey,sbf,ss->fks);
	
	first_update_subflow(skb,sbf);
	
	write_lock(&(ss->subflow_hash_table_lock));
	hash_insert(ss->subflow_hash_table,fkey,sbf);
	write_unlock(&(ss->subflow_hash_table_lock));
	
	cb = subflow_cb(sbf);
	
	write_lock(&(ss->subflow_list_lock));
	list_add_tail(&(cb->list),ss->subflow_list);
	write_unlock(&(ss->subflow_list_lock));
	
	atomic_inc(&(ss->subflows_nr));
	
	MAPI_DEBUG(if(net_ratelimit())
		   printk("Total subflows = %d\n",atomic_read(&(ss->subflows_nr))));
	
	/*MAPI_DEBUG(if(net_ratelimit())
	 * printk(KERN_DEBUG "Hashtable items = %d\n",ss->subflow_hash_table->items));
	 */

	return 0;
}

PUBLIC struct subflow *find_expired_subflow(struct subflow_struct *ss)
{
	struct subflow *sbf = NULL;
	struct subflow_private_struct *cb;
	struct list_head *list_cur;
	struct list_head *help_cur;
	
	write_lock(&(ss->subflow_list_lock));

	list_for_each_safe(list_cur,help_cur,ss->subflow_list)
	{
		sbf = subflow_list_entry(list_cur);
		cb = subflow_cb(sbf);

		if(cb->expired == 1)
		{
			struct flow_key *fkey;

			if((fkey = flow_key_alloc(GFP_ATOMIC)) == NULL)
			{
				break;
			}
			
			list_del(&(cb->list));
			
			fill_flow_key(fkey,sbf,ss->fks);

			write_lock(&(ss->subflow_hash_table_lock));
			hash_remove(ss->subflow_hash_table,fkey);
			write_unlock(&(ss->subflow_hash_table_lock));
			
			atomic_dec(&(ss->subflows_nr));
			
			flow_key_free(fkey);
		}
		else
		{
			sbf = NULL;
		}

		break;
	}
	
	write_unlock(&(ss->subflow_list_lock));
	
	return sbf;
}

PRIVATE inline int expire_all(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct subflow_struct *ss;
	struct list_head *list_cur;
		
	if((found = sk_find_predef(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	
	ss = (struct subflow_struct *)found->data;
	
	read_lock(&(ss->subflow_list_lock));

	list_for_each(list_cur,ss->subflow_list)
	{
		struct subflow *sbf = subflow_list_entry(list_cur);
		struct subflow_private_struct *cb = subflow_cb(sbf);

		cb->expired = 1;
	}
	
	read_unlock(&(ss->subflow_list_lock));

	return 0;
}

PRIVATE u8 subflow_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long subflow(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct subflow_struct *ss = (struct subflow_struct *)pfunc->data;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	struct sk_buff *skb = *skbp;
	struct subflow *sbf;
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if(check_ipstack(skb) == 0)
	{
		return 0;
	}
	
	if((sbf = get_subflow(skb,ss)) == NULL)
	{
		int ret;
		
		if((ret = new_subflow(skb,ss)) != 0)
		{
			return ret;
		}
	}
	else
	{
		update_subflow(skb,pfunc,sbf);
	}
	
	return 0;
}

PRIVATE int setup_subflow_struct(struct sock *sk,struct subflow_struct *ss)
{
	struct predef_func *pfunc_flow;

	if((pfunc_flow = sk_find_type(sk,FLOW_KEY)) == NULL)
	{
		return -EPERM;
	}
	
	ss->fks = (struct flow_key_struct *)pfunc_flow->data;
	
	atomic_set(&(ss->subflows_nr),0);
	rwlock_init(&(ss->subflow_list_lock));
	rwlock_init(&(ss->subflow_hash_table_lock));
	
	if((ss->subflow_list = (struct list_head *)kmalloc(sizeof(struct list_head),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	if((ss->subflow_hash_table = create_hash_table(&subflow_callbacks,hashtable_capacity,ss->fks)) == NULL)
	{
		kfree(ss->subflow_list);

		return -ENOMEM;
	}
	
	INIT_LIST_HEAD(ss->subflow_list);
	
	return 0;
}

PRIVATE int undo_setup_subflow_struct(struct subflow_struct *ss)
{
	kfree(ss->subflow_list);
	free_hash_table(ss->subflow_hash_table);
	
	return 0;
}

PRIVATE void create_hash_proc_file(struct subflow_struct *ss)
{
#if defined(CONFIG_PROC_FS) && defined(DEBUG)
		{
			char proc_file_name[MAX_PROC_FILENAME_SIZE];
			
			if(snprintf(proc_file_name,MAX_PROC_FILENAME_SIZE,"hashtable%d",current->pid) > MAX_PROC_FILENAME_SIZE)
			{
				printk(KERN_DEBUG "Filename %s was truncated\n",proc_file_name);
			}

			create_proc_read_entry(proc_file_name,0,subflow_proc_path,hash_table_read_proc,ss);
		}
#endif
}

PRIVATE int add_subflow(struct sock *sk,struct predef_func *pfunc)
{
	struct subflow_struct *ss = (struct subflow_struct *)pfunc->data;
	int ret;
	
	if((ret = setup_subflow_struct(sk,ss)) != 0)
	{
		return ret;
	}
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);
		
		check_timeouts((unsigned long)ss);
		check_durations((unsigned long)ss);
		run_expired_subflow_hook((unsigned long)ss);
		
		create_hash_proc_file(ss);
	}
	else
	{
		undo_setup_subflow_struct(ss);
	}

	return ret;
}

PRIVATE void destroy_subflow_struct(struct subflow_struct *ss)
{
	struct list_head *list_cur;

	ss->stop_timers = 1;
	del_timer_sync(&(ss->timeout_timer));
	del_timer_sync(&(ss->duration_timer));
	del_timer_sync(&(ss->subflow_hook_timer));
	
	free_hash_table(ss->subflow_hash_table);
	
	list_for_each(list_cur,ss->subflow_list)
	{
		struct subflow *sbf = subflow_list_entry(list_cur);
		
		kmem_cache_free(sub_subflow_cache,sbf);
	}
	
	kfree(ss->subflow_list);
}

PRIVATE void remove_hash_proc_file(void)
{
#if defined(CONFIG_PROC_FS) && defined(DEBUG)
	{
		char proc_file_name[MAX_PROC_FILENAME_SIZE];
		
		if(snprintf(proc_file_name,MAX_PROC_FILENAME_SIZE,"hashtable%d",current->pid) > MAX_PROC_FILENAME_SIZE)
		{
			printk(KERN_DEBUG "Filename %s was truncated\n",proc_file_name);
		}
		
		remove_proc_entry(proc_file_name,subflow_proc_path);
	}
#endif
}

PRIVATE int remove_subflow(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct subflow_struct *ss;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	ss = (struct subflow_struct *)found->data;
	
	destroy_subflow_struct(ss);
	
	kmem_cache_free(subflow_cache,ss);
	kmem_cache_free(predef_func_cache,found);
	
	remove_hash_proc_file();
	
	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE void subflow_init_pfunc(struct predef_func *pfunc,struct subflow_struct *ss)
{
	init_pfunc(pfunc);

	pfunc->type = SUBFLOW;
	pfunc->func = subflow;
	pfunc->equals = subflow_equals;
	pfunc->data = (unsigned long)ss;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct subflow_struct *ss;
	struct predef_func *pfunc;

	if((ss = kmem_cache_alloc(subflow_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(subflow_cache,ss);

		return NULL;
	}
	
	subflow_init_pfunc(pfunc,ss);

	return pfunc;
}

PRIVATE inline struct subflow_ioctl_struct *get_arg(unsigned long arg,int *status)
{
	struct subflow_ioctl_struct *sis;

	*status = 0;

	if((sis = kmalloc(sizeof(struct subflow_ioctl_struct),GFP_KERNEL)) == NULL)
	{
		*status = -ENOMEM;
	}
	
	if(copy_from_user(&(sis->timeout),(u64 *)(&(((struct subflow_ioctl_struct *)arg)->timeout)),sizeof(u64)) ||
	   copy_from_user(&(sis->max_duration),(u64 *)(&(((struct subflow_ioctl_struct *)arg)->max_duration)),sizeof(u64)))
	   {
		*status = -EFAULT;
		
		kfree(sis);
	   }
	
	return sis;
}

PRIVATE inline struct predef_func *get_pfunc(unsigned long arg,int *status)
{
	struct predef_func *pfunc;
	struct subflow_struct *ss;
	struct subflow_ioctl_struct *sis;

	*status = 0;
	
	if((pfunc = pfunc_alloc_r()) == NULL)
	{
		*status = -ENOMEM;

		return NULL;
	}
	
	sis = get_arg(arg,status);
	
	if(*status != 0)
	{
		kmem_cache_free(subflow_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}
	
	ss = (struct subflow_struct *)pfunc->data;
	memset(ss,0,sizeof(struct subflow_struct));
	
	ss->timeout = sis->timeout;
	ss->max_duration = sis->max_duration;
	
	kfree(sis);

	return pfunc;
}

PRIVATE int subflow_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;
	
	if(cmd != SIOCSSUBFLOW && cmd != SIOCGSUBFLOW &&
	   cmd != SIOCRSSUBFLOW && cmd != SIOCRMSUBFLOW &&
	   cmd != SIOCEXPIREALL)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}
	
	switch(cmd)
	{
		case SIOCSSUBFLOW:
			if((ret = add_subflow(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCGSUBFLOW:
			ret = -ENOSYS; 
			break;

		case SIOCRSSUBFLOW:
			ret = -ENOSYS;
			break;

		case SIOCRMSUBFLOW:
			ret = remove_subflow(sk,pfunc,1);
			break;
		
		case SIOCEXPIREALL:
			ret = expire_all(sk,pfunc);
			break;
	}

	kmem_cache_free(subflow_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

PRIVATE struct predefined fta =
{
	index:SUBFLOW,
	owner:THIS_MODULE,
	add:add_subflow,
	remove:remove_subflow,
	ioctl:subflow_ioctl,
};

int __init subflow_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if((subflow_proc_path = proc_mkdir("subflow",proc_path)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc directory subflow : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
		
	if(create_proc_read_entry("subflows",0,subflow_proc_path,subflow_read_proc,NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file subflows : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif

	if((ret = create_caches()) != 0)
	{
		return ret;
	}
	
	if((ret = init_hash_table()) != 0)
	{
		return ret;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit subflow_exit(void)
{
	unregister_function(SUBFLOW);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("subflows",subflow_proc_path);
	remove_proc_entry("subflow",proc_path);
#endif
	destroy_caches();
	
	exit_hash_table();
}

module_init(subflow_init);
module_exit(subflow_exit);

#if V_BEFORE(2,5,0)
MODULE_PARM(hashtable_capacity,"i");
#else
#include <linux/moduleparam.h>
module_param(hashtable_capacity,uint,0);
#endif

MODULE_PARM_DESC(hashtable_capacity,"The capacity of the internal hashtable (default = 1000)");

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");
