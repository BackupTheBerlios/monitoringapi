/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *		
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_PACKET_H
#define __MAPI_PACKET_H

#include <linux/config.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/if_packet.h>
#include <asm/atomic.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/smp.h>

#include <linux/mapi/sockopt.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>
#include <linux/mapi/compat.h>

#ifdef __KERNEL__

#define CONFIG_PACKET_MULTICAST	1

#ifdef CONFIG_PACKET_MULTICAST
struct packet_mclist
{
	struct packet_mclist	*next;
	int			ifindex;
	int			count;
	unsigned short		type;
	unsigned short		alen;
	unsigned char		addr[8];
};
#endif

typedef enum
{
	SKB_PROCESS,
	SKB_DROP,
	SKB_STOP_PROCESS,
	
} skb_action_t;

struct skb_mapi_priv
{
	skb_action_t action;
	
	int status;
};

struct skb_mapi_anno
{
	cycles_t cycles;
	
	u32 ctr_count[PERF_MAX_COUNTERS];
};

struct mapi_per_cpu
{
	struct skb_mapi_priv skb_priv;
	struct skb_mapi_anno skb_anno;
};

#define skb_mapiinfo(SK)	((struct skb_mapi_priv *)(&(mapi_sk(SK)->per_cpu[smp_processor_id()].skb_priv)))
#define skb_mapianno(SK)	((struct skb_mapi_anno *)(&(mapi_sk(SK)->per_cpu[smp_processor_id()].skb_anno)))

struct packet_opt
{
	struct packet_type	prot_hook;
	spinlock_t		bind_lock;
	char			running;	/* prot_hook is attached*/
	int			ifindex;	/* bound device		*/
	struct tpacket_stats	stats;
	
#ifdef CONFIG_PACKET_MULTICAST
	struct packet_mclist	*mclist;
#endif

#ifdef CONFIG_MAPI_MMAP
	atomic_t		mapped;
	unsigned long		*pg_vec;
	unsigned int		pg_vec_order;
	unsigned int		pg_vec_pages;
	unsigned int		pg_vec_len;

	struct tpacket_hdr	**iovec;
	unsigned int		frame_size;
	unsigned int		iovmax;
	unsigned int		head;
	int			copy_thresh;
#endif
	struct predef_func      *pfunc_list;
	rwlock_t		pfunc_list_lock;
	atomic_t		predef_func_nr;

	struct mapi_stats	mapistats;
	struct mapi_per_cpu	*per_cpu;

#if V_AT_LEAST(2,6,0)
	unsigned short          num;
#endif
};

int mapi_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg);
void remove_all_func(struct sock *sk);

int init_mapi(void);
int exit_mapi(void);

int init_when_create_sock(struct sock *sk);
int do_when_destruct_sock(struct sock *sk);

void run_mapi_nommap(struct sk_buff *skb,struct net_device *dev,struct sock *sk);

#ifdef CONFIG_MAPI_MMAP
void run_mapi_mmap(struct sk_buff *skb,struct net_device *dev,struct sock *sk);
#endif

#endif /* __KERNEL__ */

#endif /* __MAPI_PACKET_H */
