/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/module.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

PRIVATE inline void drop_n_acct(struct sk_buff *skb,struct sock *sk)
{
	struct packet_opt *po = mapi_sk(sk);

	spin_lock(&mapi_sk_receive_queue(sk).lock);
	po->stats.tp_drops++;
	po->mapistats.pkttype[skb->pkt_type].p_dropped++;
	spin_unlock(&mapi_sk_receive_queue(sk).lock);

	kfree_skb(skb);
}

EXPORT_SYMBOL(receive_nommap);

PUBLIC void receive_nommap(struct sk_buff **skbp,struct sock *sk)
{
	struct sk_buff *skb = *skbp;
	struct packet_opt *po = mapi_sk(sk);
	struct net_device *dev = skb->dev;
	struct sockaddr_ll *sll;

	if(skb_shared(skb))
	{
		struct sk_buff *nskb = skb_clone(skb,GFP_ATOMIC);

		if(nskb == NULL)
		{
			drop_n_acct(skb,sk);

			return;
		}

		kfree_skb(skb);
		skb = nskb;

		*skbp = skb;
	}
	
	sll = (struct sockaddr_ll *)skb->cb;
	sll->sll_family = AF_MAPI;
	sll->sll_hatype = dev->type;
	sll->sll_protocol = skb->protocol;
	sll->sll_pkttype = skb->pkt_type;
	sll->sll_ifindex = dev->ifindex;
	sll->sll_halen = 0;
	
	if(dev->hard_header_parse)
	{
		sll->sll_halen = dev->hard_header_parse(skb,sll->sll_addr);
	}

	if(((atomic_read(&mapi_sk_rmem_alloc(sk)) + skb->truesize) < (unsigned)mapi_sk_rcvbuf(sk)) && skb->sk == NULL)
	{	
		skb = skb_get(skb);
		skb_set_owner_r(skb,sk);
		skb->dev = NULL;
		
		skb_queue_tail(&mapi_sk_receive_queue(sk),skb);
		mapi_sk_data_ready(sk)(sk,skb->len);

		spin_lock(&mapi_sk_receive_queue(sk).lock);
		po->mapistats.pkttype[skb->pkt_type].p_queued++;
		spin_unlock(&mapi_sk_receive_queue(sk).lock);
	}
}

PUBLIC inline void run_mapi_nommap(struct sk_buff *skb,struct net_device *dev,struct sock *sk)
{
	struct packet_opt *po = mapi_sk(sk);
	struct sk_buff **skbp = &skb;
	
	sk_run_predef(skbp,sk);
	
	if(*skbp != NULL)
	{
		kfree_skb(*skbp);
	}
	
        spin_lock(&mapi_sk_receive_queue(sk).lock);
	po->stats.tp_packets++;
	po->mapistats.pkttype[skb->pkt_type].p_processed++;
        spin_unlock(&mapi_sk_receive_queue(sk).lock);
}

// vim:ts=8:expandtab
