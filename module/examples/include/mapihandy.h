#ifndef __MAPIHANDY_H
#define __MAPIHANDY_H

#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <alloca.h>

#include <linux/mapi/sockopt.h>
#include <pcap.h>

static inline int if_promisc_on(int sk,char *ifname)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);

	if(ioctl(sk,SIOCGIFFLAGS,&ifr) == -1)
	{
		return -1;
	}

	if(!(ifr.ifr_flags & IFF_PROMISC))
	{
		ifr.ifr_flags |= IFF_PROMISC;
		
		if(ioctl(sk,SIOCSIFFLAGS,&ifr) == -1)
		{
			return -1;
		}
	}

	return 0;
}

static inline int if_promisc_off(int sk,char *ifname)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
	
	if(ioctl(sk,SIOCGIFFLAGS,&ifr) == -1)
	{
		return -1;
	}

	if(ifr.ifr_flags & IFF_PROMISC)
	{
		ifr.ifr_flags ^= IFF_PROMISC;
		
		if(ioctl(sk,SIOCSIFFLAGS,&ifr) == -1)
		{
			return -1;
		}
	}

	return 0;
}

static inline int set_all_promisc_on(int sk)
{
	struct ifreq *ifaces;
	struct ifconf ifc;
	int noifaces;
	int i;

	noifaces = ifc.ifc_len = sizeof(struct ifreq);
	
	do
	{
		noifaces *= 2;

		ifc.ifc_len = noifaces;
		ifc.ifc_req = alloca(ifc.ifc_len);
		
		if(ioctl(sk,SIOCGIFCONF,&ifc))
		{
			return -1;
		}
	}
	while(ifc.ifc_len >= noifaces);
	
	ifaces = ifc.ifc_ifcu.ifcu_req;
	
	for(i = 0 ; i < ifc.ifc_len/sizeof(struct ifreq) ; i++)
	{
		//printf("Trying interface %s\n");
		
		if(ioctl(sk,SIOCGIFFLAGS,ifaces + i))
		{
			return -1;
		}
		
		ifaces[i].ifr_flags |= IFF_PROMISC;
		
		if(ioctl(sk,SIOCSIFFLAGS,ifaces + i))
		{
			return -1;
		}
	}

	return 0;
}

static inline int set_all_promisc_off(int sk)
{
	struct ifreq *ifaces;
	struct ifconf ifc;
	int noifaces;
	int i;

	noifaces = ifc.ifc_len = sizeof(struct ifreq);
	
	do
	{
		noifaces *= 2;

		ifc.ifc_len = noifaces;
		ifc.ifc_req = alloca(ifc.ifc_len);
		
		if(ioctl(sk,SIOCGIFCONF,&ifc))
		{
			return -1;
		}
	}
	while(ifc.ifc_len >= noifaces);
	
	ifaces = ifc.ifc_ifcu.ifcu_req;

	for(i = 0 ; i < ifc.ifc_len/sizeof(struct ifreq) ; i++)
	{
		if(ioctl(sk,SIOCGIFFLAGS,ifaces + i))
		{
			return -1;
		}
		
		ifaces[i].ifr_flags ^= IFF_PROMISC;
		
		if(ioctl(sk,SIOCSIFFLAGS,ifaces + i))
		{
			return -1;
		}
	}

	return 0;
}

static inline int get_if_mtu(int sk,char *ifname)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);

	if(ioctl(sk,SIOCGIFMTU,&ifr) == -1)
	{
		return -1;
	}

	return ifr.ifr_mtu;
}

static inline int get_if_index(int fd,const char *device)
{
	struct ifreq ifr;

	memset(&ifr,0,sizeof(ifr));
	strncpy(ifr.ifr_name,device,sizeof(ifr.ifr_name));

	if(ioctl(fd,SIOCGIFINDEX,&ifr) == -1) 
	{
		return -1;
	}

	return ifr.ifr_ifindex;
}

static inline int bind_if_index(int fd,int ifindex)
{
	struct sockaddr_ll sll;

	memset(&sll,0,sizeof(sll));
	sll.sll_family = AF_MAPI;
	sll.sll_ifindex	= ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);

	if(bind(fd,(struct sockaddr *)&sll,sizeof(sll)) == -1) 
	{
		return 1;
	}

	return 0;
}

static inline int bind_if_name(int fd,const char *device)
{
	int ifindex;

	if((ifindex = get_if_index(fd,device)) == -1)
	{
		return 1;
	}

	if(bind_if_index(fd,ifindex))
	{
		return 1;
	}

	return 0;
}

char *pkttype_names[] = { "PACKET_HOST",
			  "PACKET_BROADCAST",
			  "PACKET_MULTICAST",
			  "PACKET_OTHERHOST",
			  "PACKET_OUTGOING",
			  "PACKET_LOOPBACK",
			  "PACKET_FASTROUTE",
			  "ALL_PACKET_TYPES"
                     };

static inline int print_mapi_statistics(int sock)
{
	struct mapi_stats stats;
	int n = sizeof(stats);
	int i;
	
	if(getsockopt(sock,SOL_PACKET,MAPI_STATISTICS,&stats,&n))
	{
		return 1;
	}

	for( i = 0 ; i < MAX_MAPI_STATISTICS ; i++)
	{
		if(stats.pkttype[i].p_recv == 0 && stats.pkttype[i].p_processed == 0 && stats.pkttype[i].p_queued == 0 &&
		   stats.pkttype[i].p_dropped == 0 && stats.pkttype[i].p_dropped_by_filter == 0)
		{
			continue;
		}
		
		printf("\nPacket type : %s\n",pkttype_names[i]);
		printf("MAPI statistics : Packets received = %d\n",stats.pkttype[i].p_recv);
		printf("MAPI statistics : Packets processed = %d\n",stats.pkttype[i].p_processed);
		printf("MAPI statistics : Packets queued = %d\n",stats.pkttype[i].p_queued);
		printf("MAPI statistics : Packets dropped = %d\n",stats.pkttype[i].p_dropped);
		printf("MAPI statistics : Packets dropped by filter = %d\n",stats.pkttype[i].p_dropped_by_filter);
	}
	
	printf("\n");

	return 0;
}

static inline int print_packet_statistics(int sock)
{
	struct tpacket_stats nst;
	int n = sizeof(nst);
	
	/*
	 * In "linux/net/packet/af_packet.c", at least in the
	 * 2.4.20 kernel, "tp_packets" is incremented for every
	 * packet that passes the packet filter *and* is
	 * successfully queued on the socket; "tp_drops" is
	 * incremented for every packet dropped because there's
	 * not enough free space in the socket buffer.
	 *
	 * When the statistics are returned for a PACKET_STATISTICS
	 * "getsockopt()" call, "tp_drops" is added to "tp_packets",
	 * so that "tp_packets" counts all packets handed to
	 * the PF_PACKET socket, including packets dropped because
	 * there wasn't room on the socket buffer - but not
	 * including packets that didn't pass the filter.
	 */

	if(getsockopt(sock,SOL_PACKET,PACKET_STATISTICS,&nst,&n) == -1)
	{
		return 1;
	}

	printf("Packet statistics : Packets queued = %d\n",nst.tp_packets - nst.tp_drops);
	printf("Packet statistics : Packets dropped (socket queue full) = %d\n",nst.tp_drops);

	return 0;
}

static inline int print_pcap_statistics(pcap_t *p)
{
	struct pcap_stat ps;
	
	if(pcap_stats(p,&ps) == -1)
	{
		return 1;
	}
	
	printf("Pcap statistics : Packets queued = %d\n",ps.ps_recv - ps.ps_drop);
	printf("Pcap statistics : Packets dropped (socket queue full) = %d\n",ps.ps_drop);

	return 0;
}

static inline __u32 set_rcvbuf_size(int sock,__u32 rcvbuf_size)
{
	int size;
	
	if(setsockopt(sock,SOL_SOCKET,SO_RCVBUF,(char *)&rcvbuf_size,sizeof(rcvbuf_size)))
	{
		return -1;
	}
	
	if(getsockopt(sock,SOL_SOCKET,SO_RCVBUF,(char *)&rcvbuf_size,&size))
	{
		return -1;
	}

	return rcvbuf_size;
}

#endif /* __MAPIHANDY_H */
