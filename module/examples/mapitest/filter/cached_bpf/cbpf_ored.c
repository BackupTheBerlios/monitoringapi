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

#include <linux/mapi/ioctl.h>
#include <mapihandy.h>
#include <tconfig.h>

int sock;

struct count_packets_struct cps;
struct bpf_filter_struct bpf;

void terminate()
{
	close(sock);
}

void handler()
{
	if(ioctl(sock,SIOCGCOUNT_PACKETS,&cps))
	{
		perror("ioctl");
		exit(1);
	}
	
	if(print_packet_statistics(sock))
	{
		perror("print_packet_statistics");
	}
	
	printf("Total packets = %lld\n",cps.counter);

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

	memcpy(&(bpf.fprog),&bpf_filter,sizeof(bpf_filter));
	
	if(ioctl(sock,SIOCSCACHED_BPF_FILTER,&bpf))
	{
		perror("ioctl");
		exit(1);
	}
	
	pcap_freecode(&bpf_filter);

	pcap_close(p);
}

int main(int argc, char **argv)
{
	char condition[MAX_FILTER_LEN];
	int nofilters;
	int len = 0;
	int i;
	
	if(argc != 2)
	{
		fprintf(stderr,"Usage : %s num_of_filters\n",argv[0]);
		exit(1);
	}

	nofilters = atoi(argv[1]);
	
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	for( i = 0 ; i < nofilters ; i++)
	{
		len += sprintf(condition + len,"ether host %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			       i%0xFF,(i+1)%0xFF,(i+2)%0xFF,(i+3)%0xFF,(i+4)%0xFF,(i+5)%0xFF);
		
		if(i < (nofilters - 1))
		{
			len += sprintf(condition + len," or ");
		}
	}
	
	apply_bpf_filter(sock,condition);
	
	if(bind_if_name(sock,IFNAME))
	{
		perror("bind_if_name");
		exit(1);
	}

	if(ioctl(sock,SIOCSCOUNT_PACKETS,&cps))
	{
		perror("ioctl");
		exit(1);
	}
	
	signal(SIGINT,handler);
	
	pause();

	return 0;
}
