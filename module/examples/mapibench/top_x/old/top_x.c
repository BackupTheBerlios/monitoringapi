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
#include <mapihandy.h>
#include <tconfig.h>
#include <subflow.h>
#include <top_x.h>

int sock[MAX_FLOWS];
__u32 top_x;
struct subflow *top_x_table;

struct count_packets_struct cps[MAX_FLOWS];
struct substring_search_struct ss[MAX_FLOWS];

void terminate()
{
	int i;
	
	for( i = 0 ; i < top_x ; i++)
	{
		close(sock[i]);
	}
}

void handler()
{
	int i;
	
	for( i = 0 ; i < top_x ; i++)
	{
		printf("Src port %u :\n",top_x_table[i].src_port);
		
		if(print_mapi_statistics(sock[i]))
		{
			perror("print_mapi_statistics");
		}
	}
	
	for( i = 0 ; i < top_x ; i++)
	{
		do_ioctl(sock[i],SIOCGCOUNT_PACKETS,&cps[i],"SIOCGCOUNT_PACKETS");
		do_ioctl(sock[i],SIOCGSUBSTRING_SEARCH,&ss[i],"SIOCGSUBSTRING_SEARCH");
		
		printf("Port : %-6u , Total packets  : %-10llu\n",top_x_table[i].src_port,cps[i].counter);
		printf("Port : %-6u , Strings found  : %-10llu\n",top_x_table[i].src_port,ss[i].counter);
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
	
	printf("BPF : %s\n",condition);
	
	if(pcap_compile(p,&bpf_filter,condition,0,0xFFFFFF00))
	{
		pcap_perror(p,"pcap_compile");
		
		exit(1);
	}

	{
			struct bpf_filter_struct bpf;
			
			memcpy(&(bpf.fprog),&bpf_filter,sizeof(bpf_filter));
	
			do_ioctl(sock,SIOCSBPF_FILTER,&bpf,"SIOCSBPF_FILTER");
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
		fprintf(stderr,"Usage : %s howmany\n",argv[0]);
		exit(1);
	}
	
	top_x = atoi(argv[1]);

	printf("Press enter to start");
	getchar();
	
	top_x_table = get_top_x(top_x);
	
	for( i = 0 ; i < top_x ; i++)
	{
		if((sock[i] = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
		{
			perror("socket");
			exit(1);
		}
	}
	
	atexit(terminate);
	
	for( i = 0 ; i < top_x ; i++)
	{
		struct subflow *sbf = &top_x_table[i];
		
		do_ioctl(sock[i],SIOCSCOUNT_PACKETS,&cps[i],"SIOCSCOUNT_PACKETS");
		
		sprintf(condition,"src host %u.%u.%u.%u and dst host %u.%u.%u.%u and src port %u and dst port %u",
				  HIPQUAD(sbf->src_ip),HIPQUAD(sbf->dst_ip),sbf->src_port,sbf->dst_port);
		
		apply_bpf_filter(sock[i],condition);
		
		if(bind_if_name(sock[i],IFNAME))
		{
			perror("bind_if_name");
			exit(1);
		}
		
		if((ss[i].string = malloc((strlen(STRING_TO_SEARCH)+1)*sizeof(char))) == NULL)
		{
			fprintf(stderr,"Could not allocate memory\n");
			exit(1);
		}
	
		sprintf(ss[i].string,STRING_TO_SEARCH);
		ss[i].length = strlen(ss[i].string);

		do_ioctl(sock[i],SIOCSSUBSTRING_SEARCH,&ss[i],"SIOCSSUBSTRING_SEARCH");
	}
	
	signal(SIGINT,handler);
	
	pause();

	return 0;
}
