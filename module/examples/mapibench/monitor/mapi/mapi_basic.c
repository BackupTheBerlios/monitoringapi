#include <stdio.h>
#include <linux/types.h>
#include <sys/types.h>
#include <net/bpf.h>
#include <pcap.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>

#include <linux/mapi/ioctl.h>
#include <mapibench.h>
#include <mapihandy.h>
#include <tconfig.h>

void open_sockets(struct monitor_struct *mons)
{
	int i;

	for( i = 0 ; i < mons->ports_nr ; i++)
	{
		if((mons->socks[i] = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
		{
			perror("socket");
			exit(1);
		}
	}
	
	for( i = 0 ; i < mons->ports_nr ; i++)
	{
		if(bind_if_name(mons->socks[i],DEVICE))
		{
			printf("Cannot bind to interface %s\n",DEVICE);
			exit(1);
		}
	}
}

void apply_bpf_filters(struct monitor_struct *mons)
{
	struct bpf_program bpf_filter;
	char str[50];
	pcap_t *p;
	int i;
	
	if((p = pcap_open_dead(DLT_EN10MB,SNAPLEN)) == NULL)
	{
		fprintf(stderr,"pcap_open_dead failed\n");
		
		exit(1);
	}
	
	for( i = 0 ; i < mons->ports_nr ; i++)
	{
		sprintf(str,"port %u",mons->monitored_ports[i]);
		
		printf("Constructing filter : %s\n",str);
		
		if(pcap_compile(p,&bpf_filter,str,1,0xFFFFFF00))
		{
			pcap_perror(p,"pcap_compile");
			
			exit(1);
		}

		{
			struct bpf_filter_struct bpf;
			
			memcpy(&(bpf.fprog),&bpf_filter,sizeof(bpf_filter));
	
			if(ioctl(mons->socks[i],SIOCSBPF_FILTER,&bpf))
			{
				perror("ioctl");
				exit(1);
			}

		}
		
		pcap_freecode(&bpf_filter);
	}

	pcap_close(p);
}

void count_mmap(struct monitor_struct *mons,int index,int length,const u_char *data)
{
	__u32 src_ip,dst_ip;
	__u16 src_port,dst_port;

	get_ips_ports(data,&src_ip,&dst_ip,&src_port,&dst_port);
	
	mons->packets_per_port[index]++;
	mons->bytes_per_port[index] += length;
	
#ifdef BENCH_DEBUG
	print_quad(src_ip,dst_ip,src_port,dst_port);
#endif	
}

void count(struct monitor_struct *mons,int index,int length,const u_char *data)
{
	__u32 src_ip,dst_ip;
	__u16 src_port,dst_port;

	get_ips_ports(data + MAPI_IPHDR_OFFSET,&src_ip,&dst_ip,&src_port,&dst_port);
	
	mons->packets_per_port[index]++;
	mons->bytes_per_port[index] += length;
	
#ifdef BENCH_DEBUG
	print_quad(src_ip,dst_ip,src_port,dst_port);
#endif	
}

void print_ports_stats(struct monitor_struct *mons)
{
	struct tpacket_stats nst;
	int n = sizeof(nst);
	__u64 kernel_recv = 0;
	__u64 kernel_drop = 0;
	int i;

	printf("Port   Packets     Bytes\n");
	
	for(i = 0 ; i < mons->ports_nr ; i++)
	{
		printf("%.5u  %.10lld  %.10lld\n",mons->monitored_ports[i],mons->packets_per_port[i],mons->bytes_per_port[i]);
	}
	
	for(i = 0 ; i < mons->ports_nr ; i++)
	{
		if(getsockopt(mons->socks[i],SOL_PACKET,PACKET_STATISTICS,&nst,&n) == -1 )
		{
			perror("getsockopt");
			
			continue;
		}

		kernel_recv += (nst.tp_packets - nst.tp_drops);
		kernel_drop += nst.tp_drops;
	}
	
	printf("Kernel stats : Packets received  = %lld\n",kernel_recv);
	printf("Kernel stats : Packets dropped   = %lld\n",kernel_drop);
	
	for(i = 0 ; i < mons->ports_nr ; i++)
	{
		printf("Monitored port : %d\n",monitored_ports[i]);
		
		if(print_mapi_statistics(mons->socks[i]) || print_packet_statistics(mons->socks[i]))
		{
			perror("print_mapi_statistics || print_packet_statistics");
			exit(1);
		}
	}
	
	printf("\n");
}

