#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <signal.h>
#include <asm/fcntl.h>
#include <net/bpf.h>
#include <pcap.h>
#include <stdlib.h>
#include <linux/byteorder/generic.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

#include <linux/mapi/ioctl.h>
#include <mapihandy.h>
#include <pcapbench.h>
#include <tconfig.h>
#include <pcap-int.h>

static __u32 packets_per_port[PORTS_NR];
static __u32 bytes_per_port[PORTS_NR];

static pcap_t *p;

static void terminate()
{
	pcap_close(p);	
}

static void print_ports_stats()
{
	int i;

	printf("Port   Packets     MBytes\n");
	
	for(i = 0 ; i < PORTS_NR ; i++)
	{
		printf("%.5u  %.10u  %.10f\n",monitored_ports[i],packets_per_port[i],((float)bytes_per_port[i])/(1024*1024));
	}
	
	printf("\n");
}

static void sigint_handler()
{
	__u64 total_packets = 0;
	__u64 total_bytes = 0;
	int i;
	
	for(i = 0 ; i < PORTS_NR ; i++)
	{
		total_packets += packets_per_port[i];
		total_bytes += bytes_per_port[i];
	}
	
	print_ports_stats();
	
	if(print_mapi_statistics(p->fd))
	{
		perror("print_mapi_statistics");
	}
	
	if(print_packet_statistics(p->fd) || print_pcap_statistics(p))
	{
		perror("print_packet_statistics || print_pcap_statistics");
		exit(1);
	}

	exit(0);
}

static inline int find_index(__u16 port)
{
	int i;
		
	for( i = 0 ; i < PORTS_NR ; i++)
	{
		if(monitored_ports[i] == port)
		{
			return i;
		}
	}

	return -1;
}

static void apply_bpf_filters()
{
	struct bpf_program bpf_filter;
	char *str = "ip and tcp or udp";
	
	printf("Constructing filter : %s\n",str);
	
	if(pcap_compile(p,&bpf_filter,str,1,0xFFFFFF00))
	{
		pcap_perror(p,"pcap_compile");
		
		exit(1);
	}

	if(pcap_setfilter(p,&bpf_filter))
	{
		pcap_perror(p,"pcap_setfilter");
		
		exit(1);
	}
	
	pcap_freecode(&bpf_filter);
}

static void count(u_char *user,const struct pcap_pkthdr *packet_header,const u_char *packet)
{
	__u32 src_ip,dst_ip;
	__u16 src_port,dst_port;
	int index;
	
	get_ips_ports(packet+IPHDR_OFFSET,&src_ip,&dst_ip,&src_port,&dst_port);
	
	if((index = find_index(src_port)) == -1)
	{
		return;
	}

	packets_per_port[index]++;
	bytes_per_port[index] += packet_header->len;

#ifdef BENCH_DEBUG
	//print_packet(packet,packet_header->len);
	print_quad(src_ip,dst_ip,src_port,dst_port);
#endif	
}

int main(int argc,char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	__u32 so_rcvbuf_size;
	
	if((p = pcap_open_live(DEVICE,SNAPLEN,0,0,errbuf)) == NULL)
	{
		fprintf(stderr,"pcap_open_live : %s\n",errbuf);
		
		return 1;
	}
	
	atexit(terminate);
	
	if((so_rcvbuf_size = set_rcvbuf_size(p->fd,SO_RCVBUF_SIZE)) == -1)
	{
		perror("set_rcvbuf_size");
		exit(1);
	}
	
	printf("Socket recv buffer size = %d\n",so_rcvbuf_size);
	
	signal(SIGINT,sigint_handler);
	
#ifdef SLEEP
	signal(SIGALRM,sigint_handler);
	alarm(SLEEP_TIME);
#endif	
	apply_bpf_filters();
	
	if(pcap_loop(p,-1,count,NULL))
	{
		pcap_perror(p,"pcap_loop");
		
		exit(1);
	}
	
	return 0;
}
