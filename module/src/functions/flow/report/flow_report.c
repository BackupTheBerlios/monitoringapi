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
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>
#include <linux/mapi/timeval.h>

#include <subflow_hook.h>
#include <netflow.h>

EXPORT_NO_SYMBOLS;

//#define DEBUG_NETFLOW

PRIVATE u32 timeout_check_period = 5;

struct private_struct
{
	struct subflow_struct *ss;
	struct netflow *nf;
	struct sock *sk;
	
	struct list_head *expired_sbf_list;
	rwlock_t expired_sbf_list_lock;

	u32 expired_sbf_nr;
	u32 expired_sbf_seq;

	u8 stop_timer;
	struct timer_list timeout_timer;
};

#define function_cb(frs) ((struct private_struct *)(((struct flow_report_struct *)frs)->cb))

PRIVATE u8 *format_sbf(struct flow_report_struct *frs,int fields,u16 *format,struct subflow *sbf,u8 *packet)
{
	struct private_struct *cb = function_cb(frs);
	struct timeval tv;
	int i;
	
	tv_stamp(&tv);
	
	for( i = 0 ; i < fields ; i++) 
	{
		switch(format[i])
		{
			case NETFLOW_IPV4_SRC_ADDR:
				*((u32 *) packet) = htonl(sbf->src_ip);
				packet += NETFLOW_IPV4_SRC_ADDR_SIZE;
				break;

			case NETFLOW_IPV4_DST_ADDR:
				*((u32 *) packet) = htonl(sbf->dst_ip);
				packet += NETFLOW_IPV4_DST_ADDR_SIZE;
				break;

			case NETFLOW_PKTS_32:
				*((u32 *) packet) = htonl((u32)sbf->npackets);
				packet += NETFLOW_PKTS_32_SIZE;
				break;

			case NETFLOW_BYTES_32:
				*((u32 *) packet) = htonl((u32)sbf->nbytes);
				packet += NETFLOW_BYTES_32_SIZE;
				break;

			case NETFLOW_FIRST_SWITCHED:
				*((u32 *) packet) = htonl(sbf->start_time.tv_sec);
				packet += NETFLOW_FIRST_SWITCHED_SIZE;
				break;

			case NETFLOW_LAST_SWITCHED:
				*((u32 *) packet) = htonl(sbf->end_time.tv_sec);
				packet += NETFLOW_LAST_SWITCHED_SIZE;
				break;

			case NETFLOW_L4_SRC_PORT:
				*((u16 *) packet) = htons(sbf->src_port);
				packet += NETFLOW_L4_SRC_PORT_SIZE;
				break;

			case NETFLOW_L4_DST_PORT:
				*((u16 *) packet) = htons(sbf->dst_port);
				packet += NETFLOW_L4_DST_PORT_SIZE;
				break;

			case NETFLOW_PROT:
				*((u8 *) packet) = sbf->ip_proto;
				packet += NETFLOW_PROT_SIZE;
				break;

			case NETFLOW_TOS:
				*((u8 *) packet) = sbf->tos;
				packet += NETFLOW_TOS_SIZE;
				break;

			case NETFLOW_VERSION:
				*((u16 *) packet) = htons(cb->nf->version);
				packet += NETFLOW_VERSION_SIZE;
				break;

			case NETFLOW_COUNT:
				*((u16 *) packet) = htons(cb->expired_sbf_nr);
				packet += NETFLOW_COUNT_SIZE;
				break;

			case NETFLOW_UNIX_SECS:
				*((u32 *) packet) = htonl(tv.tv_sec);
				packet += NETFLOW_UNIX_SECS_SIZE;
				break;

			case NETFLOW_UNIX_NSECS:
				*((u32 *) packet) = htonl(tv.tv_usec * 1000);
				packet += NETFLOW_UNIX_NSECS_SIZE;
				break;

			case NETFLOW_FLOW_SEQUENCE:
				*((u32 *) packet) = htonl(cb->expired_sbf_seq);
				packet += NETFLOW_FLOW_SEQUENCE_SIZE;
				break;

			case NETFLOW_PAD8:
			/* Unsupported (u8) */
			case NETFLOW_TCP_FLAGS:
			case NETFLOW_ENGINE_TYPE:
			case NETFLOW_ENGINE_ID:
			case NETFLOW_FLAGS7_1:
			case NETFLOW_SRC_MASK:
			case NETFLOW_DST_MASK:
				*((u8 *) packet) = 0;
				packet += NETFLOW_PAD8_SIZE;
				break;

			case NETFLOW_PAD16:
			/* Unsupported (u16) */
			case NETFLOW_INPUT_SNMP:
			case NETFLOW_OUTPUT_SNMP:
			case NETFLOW_SRC_AS:
			case NETFLOW_DST_AS:
			case NETFLOW_FLAGS7_2:
				*((u16 *) packet) = 0;
				packet += NETFLOW_PAD16_SIZE;
				break;

			case NETFLOW_PAD32:
			/* Unsupported (u32) */
			case NETFLOW_UPTIME:
			case NETFLOW_IPV4_NEXT_HOP:
				*((u32 *) packet) = 0;
				packet += NETFLOW_PAD32_SIZE;
				break;

			default:
				printk("Unknown format at [%d]: %u\n",i,format[i]);
		}
	}

	return packet;
}

PRIVATE void raw_receive(struct sk_buff *skb,struct sock *sk)
{
	if(((atomic_read(&mapi_sk_rmem_alloc(sk)) + skb->truesize) < (unsigned)mapi_sk_rcvbuf(sk)))
	{	
		skb_set_owner_r(skb,sk);
		skb->dev = NULL;
		
		skb_queue_tail(&mapi_sk_receive_queue(sk),skb);
		mapi_sk_data_ready(sk)(sk,skb->len);
	}
	else
	{
		kfree_skb(skb);
	}
}

#ifdef DEBUG_NETFLOW
PRIVATE void print_subflow(struct subflow *sbf)
{
	printk("%3u.%3u.%3u.%3u  ",HIPQUAD(sbf->src_ip));
	printk("%3u.%3u.%3u.%3u  ",HIPQUAD(sbf->dst_ip));
	printk("%.5u ",sbf->src_port);
	printk("%.5u ",sbf->dst_port);
	printk("%.7llu ",sbf->npackets);
	printk("%.10llu ",sbf->nbytes);
	printk("%.10lu ",sbf->start_time.tv_sec);
	printk("%.10lu\n",sbf->end_time.tv_sec);
}

PRIVATE void print_debug_info(struct netflow *nf,u8 *packet)
{
	char src_ip[sizeof("255.255.255.255")];
	char dst_ip[sizeof("255.255.255.255")];
	u16 cnt;
	
	printk("E: Hdr ver:%d cnt:%d uptime:%d secs:%d nsecs:%d",
		ntohs(*(u16 *)(packet + 0)),
		ntohs(*(u16 *)(packet + 2)),
		ntohl(*(u32 *)(packet + 4)),
		ntohl(*(u32 *)(packet + 8)),
		ntohl(*(u32 *)(packet + 12))
		);
	
	cnt = ntohs(*(u16 *)(packet + 2));
	packet += nf->header_size;

	for( ; cnt-- ; ) 
	{
		sprintf(src_ip,"%3u.%3u.%3u.%3u",NIPQUAD(*(u32 *)(packet + 0)));
		sprintf(dst_ip,"%3u.%3u.%3u.%3u",NIPQUAD((*(u32 *)(packet + 4))));
		
		printk("E: #%d-%d %d/%d %s>%s P:%x TCP:%x %d>%d",
			ntohl(*(u32 *)(packet + 24)),
			ntohl(*(u32 *)(packet + 28)),
			ntohl(*(u32 *)(packet + 20)),
			ntohl(*(u32 *)(packet + 16)),
			src_ip,
			dst_ip,
			*(u8 *)(packet + 38),
			*(u8 *)(packet + 37),
			ntohs(*(u16 *)(packet + 32)),
			ntohs(*(u16 *)(packet + 34))
			);

		packet += nf->flow_size;
	}
}
#endif

PRIVATE int receive_netflow_packet(struct flow_report_struct *frs)
{
	struct private_struct *cb = function_cb(frs);
	struct subflow_private_struct *sbf_cb;
	struct list_head *list_cur;
	struct list_head *help_cur;
	struct netflow *nf = cb->nf;
	struct subflow *sbf = NULL;
	struct sk_buff *skb;
	u32 packet_size;
	u8 *header_data;
	u8 *flow_data;
	u32 emit_count = cb->expired_sbf_nr;
	
	if(list_empty(cb->expired_sbf_list))
	{
		return 0;
	}
	
	if((skb = alloc_skb(NETFLOW_MAX_PACKET,GFP_ATOMIC)) == NULL)
	{
		return -ENOMEM;
	}
	
	header_data = skb->data;
	flow_data = header_data + nf->header_size;

	format_sbf(frs,nf->header_fields,nf->header_format,NULL,header_data);

	list_for_each_safe(list_cur,help_cur,cb->expired_sbf_list)
	{
		sbf = subflow_list_entry(list_cur);
		sbf_cb = subflow_cb(sbf);

		list_del(&(sbf_cb->list));
		
		flow_data = format_sbf(frs,nf->flow_fields,nf->flow_format,sbf,flow_data);

		cb->expired_sbf_nr--;			
		
		subflow_free(sbf);
	}
	
	packet_size = nf->header_size + (emit_count * nf->flow_size);
	
	skb_put(skb,packet_size);

	cb->expired_sbf_seq += emit_count;

#ifdef DEBUG_NETFLOW	
	print_debug_info(cb->nf,skb->data);
#endif
	raw_receive(skb,cb->sk);
	
	return 0;
}

PRIVATE void run_timeout(unsigned long data)
{
	struct flow_report_struct *frs = (struct flow_report_struct *)data;
	struct private_struct *cb = function_cb(frs);
	
	write_lock(&(cb->expired_sbf_list_lock));
	{
		receive_netflow_packet(frs);
	}
	write_unlock(&(cb->expired_sbf_list_lock));
	
	if(cb->stop_timer == 0)
	{
		init_timer(&(cb->timeout_timer));
		
		cb->timeout_timer.function = run_timeout;
		cb->timeout_timer.data = (unsigned long)frs;
		cb->timeout_timer.expires = jiffies + timeout_check_period;

		add_timer(&(cb->timeout_timer));
	}
}

PRIVATE int netflow_handler(struct subflow *sbf,void *data)
{
	struct flow_report_struct *frs = (struct flow_report_struct *)data;
	struct private_struct *cb = function_cb(frs);
	struct subflow_private_struct *sbf_cb = subflow_cb(sbf);
	int ret = 0;
	
	write_lock(&(cb->expired_sbf_list_lock));
	{
		if(cb->expired_sbf_nr < cb->nf->max_flows)
		{
			list_add_tail(&(sbf_cb->list),cb->expired_sbf_list);
			cb->expired_sbf_nr++;
		}
		else
		{
			ret = receive_netflow_packet(frs);
		}
	}
	write_unlock(&(cb->expired_sbf_list_lock));
	
	return ret;
}

PRIVATE __u8 flow_report_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE int add_flow_report(struct sock *sk,struct predef_func *pfunc)
{
	struct flow_report_struct *frs = (struct flow_report_struct *)pfunc->data;
	struct private_struct *cb = function_cb(frs);
	struct predef_func *pfunc_subflow;
	struct subflow_hook *hook;
	int ret;
	
	if((pfunc_subflow = sk_find_type(sk,SUBFLOW)) == NULL)
	{
		return -EPERM;
	}

	memset(cb,0,sizeof(frs->cb));
	
	cb->ss = (struct subflow_struct *)pfunc_subflow->data;
	cb->sk = sk;
	
	if((hook = kmalloc(sizeof(struct subflow_hook),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	hook->data = frs;
	hook->expired_subflow = netflow_handler;
	
	if(frs->format == NETFLOW_V1)
	{
		cb->nf = &netflow1;
	}
	else if(frs->format == NETFLOW_V5)
	{
		cb->nf = &netflow5;
	}
	else if(frs->format == NETFLOW_V7)
	{
		cb->nf = &netflow7;
	}
	else
	{
		return -EINVAL;
	}
	
	if((cb->expired_sbf_list = (struct list_head *)kmalloc(sizeof(struct list_head),GFP_KERNEL)) == NULL)
	{
		kfree(hook);

		return -ENOMEM;
	}
	
	INIT_LIST_HEAD(cb->expired_sbf_list);	
	rwlock_init(&(cb->expired_sbf_list_lock));

	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		mapi_module_get(THIS_MODULE);

		if((ret = register_subflow_hook(cb->ss,hook)) != 0)
		{
			return ret;
		}

		run_timeout((unsigned long)frs);		
	}

	return ret;
}

PRIVATE int remove_flow_report(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct flow_report_struct *frs;
	struct subflow_hook *hook;
	struct private_struct *cb;
	struct list_head *list_cur;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	frs = (struct flow_report_struct *)found->data;
	cb = function_cb(frs);
	
	if((hook = unregister_subflow_hook(cb->ss)) == NULL)
	{
		BUG();
	}
	
	cb->stop_timer = 1;
	del_timer_sync(&(cb->timeout_timer));

	list_for_each(list_cur,cb->expired_sbf_list)
	{
		struct subflow *sbf = subflow_list_entry(list_cur);
		
		subflow_free(sbf);
	}
	
	kfree(hook);
	kfree(cb->expired_sbf_list);
	kfree(frs);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE void flow_report_init_pfunc(struct predef_func *pfunc,struct flow_report_struct *frs)
{
	init_pfunc(pfunc);
	
	pfunc->type = FLOW_REPORT;
	pfunc->data = (unsigned long)frs;
	pfunc->func = NULL;
	pfunc->equals = flow_report_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct flow_report_struct *frs;
	struct predef_func *pfunc;

	if((frs = kmalloc(sizeof(struct flow_report_struct),GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kfree(frs);

		return NULL;
	}

	flow_report_init_pfunc(pfunc,frs);

	return pfunc;
}

PRIVATE inline int fill_fields(struct flow_report_struct *frs,unsigned long arg)
{
	struct flow_report_struct *arg_frs = (struct flow_report_struct *)arg;
	
	if(get_user(frs->format,(u8 *)(&(arg_frs->format))))
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
	
	if((*status = fill_fields((struct flow_report_struct *)pfunc->data,arg)) != 0)
	{
		kfree((void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int flow_report_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSFLOW_REPORT && cmd != SIOCRMFLOW_REPORT)
	{
		return ret;
	}

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCSFLOW_REPORT:
			if((ret = add_flow_report(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;
			
		case SIOCRMFLOW_REPORT:
			ret = remove_flow_report(sk,pfunc,1);
			break;
	}

	kfree((void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

PRIVATE struct predefined fta =
{
	index:FLOW_REPORT,
	owner:THIS_MODULE,
	add:add_flow_report,
	remove:remove_flow_report,
	ioctl:flow_report_ioctl,
};

int __init flow_report_init(void)
{
	int ret;
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit flow_report_exit(void)
{
	unregister_function(FLOW_REPORT);
}

module_init(flow_report_init);
module_exit(flow_report_exit);

#if V_BEFORE(2,5,0)
MODULE_PARM(timeout_check_period,"i");
#else
#include <linux/moduleparam.h>
module_param(timeout_check_period,uint,0);
#endif

MODULE_PARM_DESC(timeout_check_period,"The time MAPI will wait for expired subflows before reported to application (default = 5 jiffies)");

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

