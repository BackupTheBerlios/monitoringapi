#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <linux/if_ether.h>
#include <net/bpf.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <sys/time.h>

#include <linux/mapi/ioctl.h>
#include <mapirusage.h>
#include <mapihandy.h>
#include <tconfig.h>

#ifdef HAVE_PAPI_H
#include <papi.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

int events[] = 
{ 
	PAPI_TOT_CYC,	/* Total cycles */
	PAPI_TOT_INS,	/* Instructions completed */
	PAPI_L1_TCM, 	/* Level 1 cache misses */
};

#define MAX_PERF_EVENTS ARRAY_SIZE(events)

int num_hwcntrs;
long_long hwcnt_values[MAX_PERF_EVENTS];

#endif

#include <performance.h>

int sock[MAX_FLOWS];
__u32 nosocks;

struct count_packets_struct cps;

void terminate()
{
	int i;
	
	performance_exit();
	
	for( i = 0 ; i < nosocks ; i++)
	{
		close(sock[i]);
	}
}

void handler()
{
	int i;
	
	for( i = 0 ; i < nosocks ; i++)
	{
		printf("Flow number %d :\n",i);
		
		if(ioctl(sock[i],SIOCGCOUNT_PACKETS,&cps))
		{
			perror("ioctl");
			exit(1);
		}
		
		if(print_packet_statistics(sock[i]))
		{
			perror("print_packet_statistics");
		}
		
		printf("Total packets = %lld\n",cps.counter);
	}
	
	performance_read();
	performance_print();

	exit(0);
}

void apply_bpf_filter(int sock,char *condition)
{
	struct bpf_program bpf_filter;
	pcap_t *p;
	
	if((p = pcap_open_dead(DLT_EN10MB,SNAPLEN)) == NULL)
	{
		fprintf(stderr,"pcap_open_dead failed\n");
		
		exit(1);
	}
	
	printf("Constructing filter : %s\n",condition);
	
	if(pcap_compile(p,&bpf_filter,condition,0,0xFFFFFF00))
	{
		pcap_perror(p,"pcap_compile");
		
		exit(1);
	}

	{
			struct bpf_filter_struct bpf;
			
			memcpy(&(bpf.fprog),&bpf_filter,sizeof(bpf_filter));
	
			if(ioctl(sock,SIOCSBPF_FILTER,&bpf))
			{
				perror("ioctl");
				exit(1);
			}
	}

	pcap_freecode(&bpf_filter);

	pcap_close(p);
}

int main(int argc, char **argv)
{
	int i;
	char condition[MAX_FILTER_LEN];
	
	if(argc != 2)
	{
		fprintf(stderr,"Usage : %s num_of_flows_to_open\n",argv[0]);
		exit(1);
	}
	
	nosocks = atoi(argv[1]);

	for( i = 0 ; i < nosocks ; i++)
	{
		if((sock[i] = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
		{
			perror("socket");
			exit(1);
		}
	}
	
	atexit(terminate);
	
	for( i = 0 ; i < nosocks ; i++)
	{
		sprintf(condition,"ether host %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			       i%0xFF,(i+1)%0xFF,(i+2)%0xFF,(i+3)%0xFF,(i+4)%0xFF,(i+5)%0xFF);
		
		apply_bpf_filter(sock[i],condition);
		
		if(bind_if_name(sock[i],IFNAME))
		{
			perror("bind_if_name");
			exit(1);
		}

		if(ioctl(sock[i],SIOCSCOUNT_PACKETS,&cps))
		{
			perror("ioctl");
			exit(1);
		}
	}
	
	performance_init();
	
	signal(SIGINT,handler);
	
	pause();

	return 0;
}
