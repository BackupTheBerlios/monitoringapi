#ifndef __PCAPTEST_H
#define __PCAPTEST_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/byteorder/generic.h>
#include <linux/if_ether.h>

#define HIPQUAD(addr) \
((unsigned char *)&addr)[3], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[0]

static inline void print_quad(__u32 src_ip,__u32 dst_ip,__u16 src_port,__u16 dst_port)
{
	printf("%u.%u.%u.%u  ",HIPQUAD(src_ip));
	printf("%u.%u.%u.%u  ",HIPQUAD(dst_ip));
	printf(" %d ",src_port);
	printf(" %d ",dst_port);
	printf("\n");
}

static inline void print_packet(const __u8 *packet,int length)
{
	int i;

	for( i = 0 ; i < length ; i++)
	{
		printf("%.2x ",packet[i]);
	}
	
	printf("\n");
}

static inline void get_ips_ports(const __u8 *packet,__u32 *src_ip,__u32 *dst_ip,__u16 *src_port,__u16 *dst_port)
{
	struct iphdr *iph;
	struct tcphdr *th;
	struct udphdr *uh;
	
	iph = (struct iphdr *)packet;
	th = (struct tcphdr *)(((__u8 *)iph) + iph->ihl*4);
	uh = (struct udphdr *)(((__u8 *)iph) + iph->ihl*4);

	*src_ip = ntohl(iph->saddr);
	*dst_ip = ntohl(iph->daddr);

	if(iph->protocol == IPPROTO_TCP)
	{
		*src_port = th->source;
		*dst_port = th->dest;
	}
	else
	{
		*src_port = uh->source;
		*dst_port = uh->dest;
	}

	*src_port = ntohs(*src_port);
	*dst_port = ntohs(*dst_port);
}

#endif
