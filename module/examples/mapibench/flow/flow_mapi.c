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

//#define BYTES_COUNT

int sock[MAX_FLOWS];
__u32 nosocks;

#ifdef BYTES_COUNT
struct count_bytes_struct cbs;
#else
struct count_packets_struct cps;
#endif

void terminate()
{
	int i;
	
	for( i = 0 ; i < nosocks ; i++)
	{
		if(if_promisc_off(sock[i],IFNAME))
		{
			perror("if_promisc_off");
		}

		close(sock[i]);
	}
}

void handler()
{
	int i;
	
	for( i = 0 ; i < nosocks ; i++)
	{
		printf("Flow number %d :\n",i);
		
		if(
#ifdef BYTES_COUNT
		   ioctl(sock[i],SIOCGCOUNT_BYTES,&cbs) 
#else		      
		   ioctl(sock[i],SIOCGCOUNT_PACKETS,&cps)
#endif		   
		   )
		{
			perror("ioctl");
			exit(1);
		}
		
		/*if(print_packet_statistics(sock[i]))
		{
			perror("print_packet_statistics");
		}*/
		
		if(print_mapi_statistics(sock[i]))
		{
			perror("print_mapi_statistics");
		}
		
#ifdef BYTES_COUNT
		printf("Total bytes   = %lld\n",cbs.counter);
#else		
		printf("Total packets = %lld\n",cps.counter);
#endif		
	}

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
	
	if(pcap_compile(p,&bpf_filter,condition,1,0xFFFFFF00))
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
	__u8 use_bpf;
	char expression[100];
	
	if(argc != 3)
	{
		fprintf(stderr,"Usage : %s use_bpf num_of_flows_to_open\n",argv[0]);
		exit(1);
	}
	
	use_bpf = atoi(argv[1]);
	nosocks = atoi(argv[2]);

	for( i = 0 ; i < nosocks ; i++)
	{
		if((sock[i] = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
		{
			perror("socket");
			exit(1);
		}

		if(use_bpf)
		{
			sprintf(expression,"port %d",i);
			apply_bpf_filter(sock[i],expression);
		}
		
		if(if_promisc_on(sock[i],IFNAME) || bind_if_name(sock[i],IFNAME))
		{
			perror("if_promisc_on || bind_if_name");

			exit(1);
		}

		if(
#ifdef BYTES_COUNT
		    ioctl(sock[i],SIOCSCOUNT_BYTES,&cbs)
#else		    
		    ioctl(sock[i],SIOCSCOUNT_PACKETS,&cps)
#endif		   
		   )
		{
			perror("ioctl");
			exit(1);
		}
	}
	
	atexit(terminate);
	
	signal(SIGINT,handler);
	
	pause();

	return 0;
}
