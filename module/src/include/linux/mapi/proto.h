/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_PROTO_H
#define __MAPI_PROTO_H

#ifdef __KERNEL__

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

static inline u8 *proto_llhdr(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	u8 *llh;
	
	if(dev->hard_header == NULL)
	{
		llh = NULL;
	}
	else
	{
		llh = (u8 *)(skb->mac.raw);
	}

	return llh;
}

static inline struct iphdr *proto_iphdr(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct iphdr *iph;
	
	if(dev->hard_header == NULL)
	{
		iph = (struct iphdr *)(skb->data);
	}
	else
	{
		iph = (struct iphdr *)(skb->mac.raw + dev->hard_header_len);
	}

	return iph;
}

static inline struct udphdr *proto_udphdr(struct sk_buff *skb,struct iphdr *iph)
{
	struct udphdr *uh;

	if(iph == NULL)
	{
		iph = proto_iphdr(skb);
	}
	
	uh = (struct udphdr *)(((u8 *)iph) + iph->ihl*4);
	
	return uh;
}

static inline struct tcphdr *proto_tcphdr(struct sk_buff *skb,struct iphdr *iph)
{
	struct tcphdr *th;

	if(iph == NULL)
	{
		iph = proto_iphdr(skb);
	}
	
	th = (struct tcphdr *)(((u8 *)iph) + iph->ihl*4);
	
	return th;
}

static inline struct icmphdr *proto_icmphdr(struct sk_buff *skb,struct iphdr *iph)
{
	struct icmphdr *th;

	if(iph == NULL)
	{
		iph = proto_iphdr(skb);
	}
	
	th = (struct icmphdr *)(((u8 *)iph) + iph->ihl*4);
	
	return th;
}

#endif /* __KERNEL__ */

#endif /* __MAPI_PROTO_H */
