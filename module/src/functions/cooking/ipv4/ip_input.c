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
#include <net/ip.h>
#include <net/checksum.h>
#include <linux/netdevice.h>
#include <linux/byteorder/generic.h>
#include <net/sock.h>

#include <linux/mapi/ioctl.h>
#include <linux/mapi/common.h>
#include <linux/mapi/proto.h>
#include <mapiipv4.h>

static inline struct sk_buff *mapi_ip_local_deliver_finish(struct sk_buff *skb)
{
	int ihl = skb->nh.iph->ihl * 4;
	
	if(!pskb_may_pull(skb,ihl))
	{
		goto out;
	}
	
	__skb_pull(skb,ihl);

	/*
	 * Point into the IP datagram, just past the header. 
	 */
	skb->h.raw = skb->data;
	
	return skb;

    out:
	
	kfree_skb(skb);

	return NULL;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
static inline struct sk_buff *mapi_ip_local_deliver(struct sk_buff *skb,struct predef_func *pf)
{
	struct cook_ip_struct *cis = (struct cook_ip_struct *)pf->data;
	/*
	 *    Reassemble IP fragments.
	 */
	if(skb->nh.iph->frag_off & htons(IP_MF | IP_OFFSET))
	{
		struct sk_buff *nskb;
		
		nskb = mapi_ip_defrag(skb,pf);

		if(nskb == NULL)
		{
			return NULL;
		}

		spin_lock(&pf->data_lock);
		cis->defrag_completed++;
		spin_unlock(&pf->data_lock);
		
		skb = nskb;
	}

	return mapi_ip_local_deliver_finish(skb);
}

static inline struct sk_buff *mapi_ip_rcv_finish(struct sk_buff *skb,struct predef_func *pf)
{
	struct iphdr *iph = skb->nh.iph;
	struct cook_ip_struct *cis = (struct cook_ip_struct *)pf->data;

	if(iph->ihl > 5)
	{
		/*
		 * It looks as overkill, because not all
		 * IP options require packet mangling.
		 * But it is the easiest for now, especially taking
		 * into account that combination of IP options
		 * and running sniffer is extremely rare condition.
		 * --ANK (980813)
		 */

		if(skb_cow(skb,skb_headroom(skb)))
		{
			goto drop;
		}

		iph = skb->nh.iph;

		skb->ip_summed = 0;

		if(ip_options_compile(NULL,skb))
		{
			goto inhdr_error;
		}
	}

	return mapi_ip_local_deliver(skb,pf);

inhdr_error:
	spin_lock(&pf->data_lock);
	cis->ip_options_errors++;
	spin_unlock(&pf->data_lock);
	
	MAPI_DEBUG(if(net_ratelimit()) 
		   printk("COOK_IP : IP options error : %u.%u.%u.%u <- %u.%u.%u.%u\n",
			   NIPQUAD(skb->nh.iph->daddr),
			   NIPQUAD(skb->nh.iph->saddr)));

drop:
	
	kfree_skb(skb);

	return NULL;
}

struct sk_buff *mapi_ip_rcv(struct sk_buff *skb,struct predef_func *pf)
{
	struct cook_ip_struct *cis = (struct cook_ip_struct *)pf->data;
	struct iphdr *iph;
	
	if((skb = skb_clone(skb,GFP_ATOMIC)) == NULL)
	{
		MAPI_DEBUG(if(net_ratelimit()) printk("COOK_IP : Could not allocate memory\n"));
		
		return NULL;
	}
	
	skb->nh.iph = proto_iphdr(skb);
	
	skb->data = (u8 *)(skb->nh.iph);
	skb->len = skb->tail - skb->data;
	
	if(!pskb_may_pull(skb,sizeof(struct iphdr)))
	{
		goto inhdr_error;
	}

	iph = skb->nh.iph;

	/*
	 *    RFC1122: 3.1.2.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *    Is the datagram acceptable?
	 *
	 *    1.    Length at least the size of an ip header
	 *    2.    Version of 4
	 *    3.    Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *    4.    Doesn't have a bogus length
	 */

	if(iph->ihl < 5 || iph->version != 4)
	{
		goto inhdr_error;
	}

	if(!pskb_may_pull(skb, iph->ihl * 4))
	{
		goto inhdr_error;
	}

	iph = skb->nh.iph;
	
	if(ip_fast_csum((u8 *) iph, iph->ihl) != 0)
	{
		goto inhdr_error;
	}

	{
		__u32 len = ntohs(iph->tot_len);

		if(skb->len < len || len < (iph->ihl << 2))
		{
			goto inhdr_error;
		}

		/*
		 * Our transport medium may have padded the buffer out. Now we know it
		 * is IP we can trim to the true length of the frame.
		 * Note this now means skb->len holds ntohs(iph->tot_len).
		 */
		if(skb->len > len)
		{
			__pskb_trim(skb, len);

			if(skb->ip_summed == CHECKSUM_HW)
			{
				skb->ip_summed = CHECKSUM_NONE;
			}
		}
	}
	
	return mapi_ip_rcv_finish(skb,pf);
	
    inhdr_error:
	
	spin_lock(&pf->data_lock);
	cis->ip_header_errors++;
	spin_unlock(&pf->data_lock);
	
	MAPI_DEBUG(if(net_ratelimit()) 
		   printk("COOK_IP : Header error : %u.%u.%u.%u <- %u.%u.%u.%u\n",
			   NIPQUAD(skb->nh.iph->daddr),
			   NIPQUAD(skb->nh.iph->saddr)));
	
	kfree_skb(skb);
	
	return NULL;
}
