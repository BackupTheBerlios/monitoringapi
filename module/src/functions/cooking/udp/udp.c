#include <net/checksum.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <linux/mapi/ioctl.h>
#include <linux/mapi/common.h>
#include <linux/mapi/proto.h>
#include <linux/mapi/csum.h>
#include <linux/mapi/skbuff.h>
#include <cookudp.h>

__u8 mapi_udp(struct sk_buff *skb,struct predef_func *pf)
{
	struct cook_udp_struct *cus = (struct cook_udp_struct *)pf->data;
	struct iphdr *iph = skb->nh.iph;
	struct udphdr *uh;
	unsigned short ulen = 0;
	
	//MAPI_DEBUG(if(net_ratelimit()) printk("COOK_UDP : Cooking UDP packet\n"));

	uh = proto_udphdr(skb,iph);
	
	if(!mapi_pskb_may_pull(skb,sizeof(struct udphdr)))
	{
		goto no_header;
	}
	
	ulen = ntohs(uh->len);

	if(ulen > skb->len || ulen < sizeof(*uh))
	{
		goto short_packet;
	}
	
	if(uh->check != 0)
	{
		unsigned csum = ~in_cksum((unsigned char *)uh,ulen) & 0xFFFF;
		
		if(csum_tcpudp_magic(iph->saddr,iph->daddr,ulen,IPPROTO_UDP,csum) != 0)
		{
			goto csum_error;
		}
	}
	
	skb->data = ((u8 *)uh) + sizeof(struct udphdr);
	skb->len = skb->tail - skb->data;
	
	return 0;

    short_packet:
	
	spin_lock(&pf->data_lock);
	cus->short_packets++;
	spin_unlock(&pf->data_lock);
	
	MAPI_DEBUG(if(net_ratelimit())
		   printk("COOK_UDP: Short packet: %u.%u.%u.%u:%u <- %u.%u.%u.%u:%u\n",
			   NIPQUAD(skb->nh.iph->daddr),
			   ntohs(skb->h.uh->dest),
			   NIPQUAD(skb->nh.iph->saddr),
			   ntohs(skb->h.uh->source)));
	return 1;
	
    no_header:
	
	spin_lock(&pf->data_lock);
	cus->no_header_errors++;
	spin_unlock(&pf->data_lock);
	
	MAPI_DEBUG(if(net_ratelimit())
		   printk("COOK_UDP: No header: %u.%u.%u.%u:%u <- %u.%u.%u.%u:%u\n",
			   NIPQUAD(skb->nh.iph->daddr),
			   ntohs(skb->h.uh->dest),
			   NIPQUAD(skb->nh.iph->saddr),
			   ntohs(skb->h.uh->source)));

	return 1;

    csum_error:
	
	spin_lock(&pf->data_lock);
	cus->csum_errors++;
	spin_unlock(&pf->data_lock);
	
	MAPI_DEBUG(if(net_ratelimit())
		   printk("COOK_UDP: Csum error: %u.%u.%u.%u:%u <- %u.%u.%u.%u:%u\n",
			   NIPQUAD(skb->nh.iph->daddr),
			   ntohs(skb->h.uh->dest),
			   NIPQUAD(skb->nh.iph->saddr),
			   ntohs(skb->h.uh->source)));
	
	return 1;
}
