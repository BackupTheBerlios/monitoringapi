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
#include <tconfig.h>
#include <pcap-int.h>
#include <mapirusage.h>

static pcap_t *p;

static void terminate()
{
	pcap_close(p);	
}

static void sigint_handler()
{
	if(end_time_and_usage())
	{
		perror("end_time_and_usage");
		exit(1);
	}

	print_mapi_statistics(p->fd);
	
	if(print_packet_statistics(p->fd) || print_pcap_statistics(p))
	{
		perror("print_packet_statistics || print_pcap_statistics");
		exit(1);
	}

	print_rusage();	
	
	exit(0);
}

static void touch(u_char *user,const struct pcap_pkthdr *packet_header,const u_char *packet)
{
	/*int i;
	
	for( i = 0 ; i < packet_header->len ; i += PERIOD)
	{
		packet[i];
	}*/
}

void apply_bpf_filter(pcap_t *p,char *condition)
{
	struct bpf_program bpf_filter;
	
	printf("Constructing filter : %s\n",condition);
	
	if(pcap_compile(p,&bpf_filter,condition,0,0xFFFFFF00))
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

int main(int argc,char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	__u32 so_rcvbuf_size;

	if(start_time_and_usage())
	{
		perror("start_time_and_usage");
		exit(1);
	}
	
	if((p = pcap_open_live(IFNAME,SNAPLEN,1,0,errbuf)) == NULL)
	{
		fprintf(stderr,"pcap_open_live : %s\n",errbuf);
		
		return 1;
	}
	
	apply_bpf_filter(p,"ether src 00:07:E9:0F:9E:F9");

#ifdef SO_RCVBUF_SIZE
	if((so_rcvbuf_size = set_rcvbuf_size(p->fd,SO_RCVBUF_SIZE)) == -1)
	{
		perror("set_rcvbuf_size");
		exit(1);
	}
	
	printf("Socket recv buffer size = %d\n",so_rcvbuf_size);
#endif	
	
	atexit(terminate);
	
	signal(SIGINT,sigint_handler);
	
#ifdef SLEEP
	signal(SIGALRM,sigint_handler);
	alarm(SLEEP_TIME);
#endif	

	if(pcap_loop(p,-1,touch,NULL))
	{
		pcap_perror(p,"pcap_loop");
		
		exit(1);
	}
	
	return 0;
}
