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

#define MAX_FILTERS 100

int sock;

struct bpf_filter_struct bpf[MAX_FILTERS];

void terminate()
{
	close(sock);
}

void handler()
{
	int i;

	for( i = 0 ; i < MAX_FILTERS ; i++)	
	{
		if(ioctl(sock,SIOCGBPF_FILTER,&bpf[i]))
		{
			perror("ioctl");
			exit(1);
		}
	}
	
	if(print_packet_statistics(sock))
	{
		perror("print_packet_statistics");
	}
	
	exit(0);
}

void apply_bpf_filters(int sock)
{
	char condition[MAX_FILTER_LEN];
	struct bpf_program bpf_filter;
	pcap_t *p;
	int i;
	
	if((p = pcap_open_dead(DLT_EN10MB,SNAPLEN)) == NULL)
	{
		fprintf(stderr,"pcap_open_dead failed\n");
		
		exit(1);
	}
	
	for( i = 0 ; i < MAX_FILTERS ; i++)	
	{
		sprintf(condition,"ether host %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			       i%0xFF,(i+1)%0xFF,(i+2)%0xFF,(i+3)%0xFF,(i+4)%0xFF,(i+5)%0xFF);

		printf("Constructing filter : %s\n",condition);
	
		if(pcap_compile(p,&bpf_filter,condition,0,0xFFFFFF00))
		{
			pcap_perror(p,"pcap_compile");
			
			exit(1);
		}
		
		memcpy(&(bpf[i].fprog),&bpf_filter,sizeof(bpf_filter));
		
		if(ioctl(sock,SIOCSBPF_FILTER,&bpf[i]))
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
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
		
	apply_bpf_filters(sock);
	
	signal(SIGINT,handler);
	
	pause();

	return 0;
}
