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

#include <linux/mapi/ioctl.h>
#include <mapihandy.h>
#include <mapirusage.h>
#include <tconfig.h>

pcap_t *p;
__u32 nofilters;

__u64 total_packets;

static void terminate()
{
	pcap_close(p);
}

void sigint_handler()
{
	if(end_time_and_usage())
	{
		perror("end_time_and_usage");
		exit(1);
	}

	if(print_pcap_statistics(p))
	{
		perror("print_packet_statistics");
	}

	printf("Total packets = %lld\n",total_packets);
	
	print_rusage();	
	
	exit(0);
}

void open_lives()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if((p = pcap_open_live(IFNAME,SNAPLEN,0,0,errbuf)) == NULL)
	{
		fprintf(stderr,"pcap_open_live : %s\n",errbuf);
		
		exit(1);
	}
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

void count(u_char *user,const struct pcap_pkthdr *packet_header,const u_char *packet)
{
	total_packets++;
}

void monitor_all()
{
	char condition[MAX_FILTER_LEN];	
	int len = 0;
	int i;
	
	for( i = 0 ; i < nofilters ; i++)
	{
		len += sprintf(condition + len,"ether host %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			       i%0xFF,(i+1)%0xFF,(i+2)%0xFF,(i+3)%0xFF,(i+4)%0xFF,(i+5)%0xFF);
		
		if(i < (nofilters - 1))
		{
			len += sprintf(condition + len," or ");
		}
	}

	apply_bpf_filter(p,condition);
	
	if(pcap_loop(p,-1,count,NULL))
	{
		pcap_perror(p,"pcap_loop");
		
		return;
	}
}

int main(int argc,char **argv)
{
	if(argc != 2)
	{
		fprintf(stderr,"Usage : %s num_of_flows_to_open\n",argv[0]);
		exit(1);
	}
	
	if(start_time_and_usage())
	{
		perror("start_time_and_usage");
		exit(1);
	}
	
	nofilters = atoi(argv[1]);

	open_lives();
	
	atexit(terminate);
	
	signal(SIGINT,sigint_handler);

	monitor_all();
	
	return 0;
}
