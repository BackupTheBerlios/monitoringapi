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
#include <linux/rtnetlink.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>

#ifdef CONFIG_MAPI_MMAP

PRIVATE inline void ring_is_full(struct sk_buff *skb,struct sk_buff *copy_skb,struct sock *sk)
{
	struct packet_opt *po = mapi_sk(sk);

	po->stats.tp_drops++;
	po->mapistats.pkttype[skb->pkt_type].p_dropped++;
	spin_unlock(&mapi_sk_receive_queue(sk).lock);

	mapi_sk_data_ready(sk)(sk,0);
	
	if(copy_skb)
	{
		kfree_skb(copy_skb);
	}

	kfree_skb(skb);
}

EXPORT_SYMBOL(receive_mmap);

PUBLIC void receive_mmap(struct sk_buff **skbp,struct sock *sk)
{
	struct sk_buff *skb = *skbp;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	struct packet_opt *po = mapi_sk(sk);
	struct sk_buff *copy_skb = NULL;
	struct tpacket_hdr *h;
	struct sockaddr_ll *sll;
	unsigned short macoff;
	unsigned short netoff;
	int snaplen = skb->len;
	struct net_device *dev;
	
	if(skb->sk != NULL)
	{
		return;
	}
	
	if(mapi_sk_type(sk) == SOCK_DGRAM)
	{
		macoff = netoff = TPACKET_ALIGN(TPACKET_HDRLEN) + 16;
	}
	else
	{
		unsigned maclen = skb->nh.raw - skb->data;
		
		netoff = TPACKET_ALIGN(TPACKET_HDRLEN + (maclen < 16 ? 16 : maclen));
		macoff = netoff - maclen;
	}
	
	if(macoff + snaplen > po->frame_size) 
	{
		if(po->copy_thresh && (atomic_read(&mapi_sk_rmem_alloc(sk)) + skb->truesize < (unsigned)mapi_sk_rcvbuf(sk))) 
		{
			if(skb_shared(skb)) 
			{
				copy_skb = skb_clone(skb,GFP_ATOMIC);
			}
			else
			{
				copy_skb = skb_get(skb);
			}
			
			copy_skb = skb_get(copy_skb);
			
			if(copy_skb)
			{
				skb_set_owner_r(copy_skb,sk);
			}
		}
		
		snaplen = po->frame_size - macoff;
		
		if((int)snaplen < 0)
		{
			snaplen = 0;
		}
	}
	
	if(snaplen > (skb->len - skb->data_len))
	{
		snaplen = skb->len - skb->data_len;
	}

	spin_lock(&mapi_sk_receive_queue(sk).lock);
	h = po->iovec[po->head];
	
	if(h->tp_status)
	{
		ring_is_full(skb,copy_skb,sk);
		
		return;
	}

	po->head = po->head != po->iovmax ? po->head + 1 : 0;
	po->stats.tp_packets++;
	po->mapistats.pkttype[skb->pkt_type].p_queued++;
	
	if(copy_skb) 
	{
		skb_mapi->status |= TP_STATUS_COPY;
		__skb_queue_tail(&mapi_sk_receive_queue(sk),copy_skb);
	}

	*skbp = copy_skb;
	
	if(!po->stats.tp_drops)
	{
		skb_mapi->status &= ~TP_STATUS_LOSING;
	}
	
	spin_unlock(&mapi_sk_receive_queue(sk).lock);

	memcpy((u8*)h + macoff,skb->data,snaplen);

	h->tp_len = skb->len;
	h->tp_snaplen = snaplen;
	h->tp_mac = macoff;
	h->tp_net = netoff;
	h->tp_sec = skb->stamp.tv_sec;
	h->tp_usec = skb->stamp.tv_usec;

	sll = (struct sockaddr_ll*)((u8*)h + TPACKET_ALIGN(sizeof(*h)));
	sll->sll_halen = 0;

	dev = skb->dev;
	
	if(dev->hard_header_parse)
	{
		sll->sll_halen = dev->hard_header_parse(skb,sll->sll_addr);
	}
	
	sll->sll_family = AF_PACKET;
	sll->sll_hatype = skb->dev->type;
	sll->sll_protocol = skb->protocol;
	sll->sll_pkttype = skb->pkt_type;
	sll->sll_ifindex = skb->dev->ifindex;

	h->tp_status = skb_mapi->status;
	mb();

	{
		struct page *p_start, *p_end;
		u8 *h_end = (u8 *)h + macoff + snaplen - 1;

		p_start = virt_to_page(h);
		p_end = virt_to_page(h_end);
		
		while(p_start <= p_end) 
		{
			flush_dcache_page(p_start);
			p_start++;
		}
	}

	mapi_sk_data_ready(sk)(sk,0);
}

PUBLIC inline void run_mapi_mmap(struct sk_buff *skb,struct net_device *dev,struct sock *sk)
{
	struct packet_opt *po = mapi_sk(sk);
	struct sk_buff **skbp = &skb;

	skb->dev = dev;
	
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

#endif

// vim:ts=8:expandtab

