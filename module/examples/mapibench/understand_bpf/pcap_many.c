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

pcap_t *p[MAX_FLOWS];
__u32 nops;

pthread_t threads[MAX_FLOWS];

__u64 total_packets[MAX_FLOWS];

static void terminate()
{
	int i;
	
	for( i = 0 ; i < nops ; i++)
	{
		pthread_kill(threads[i],SIGQUIT);
	}
	
	for( i = 0 ; i < nops ; i++)
	{
		pcap_close(p[i]);
	}
}

void sigint_handler()
{
	int i;
	
	if(end_time_and_usage())
	{
		perror("end_time_and_usage");
		exit(1);
	}
	
	for( i = 0 ; i < nops ; i++)
	{
		printf("Flow number %d :\n",i);
		
		if(print_pcap_statistics(p[i]))
		{
			perror("print_packet_statistics");
		}

		printf("Total packets = %lld\n",total_packets[i]);
	}
	
	print_rusage();	
	
	exit(0);
}

void open_lives()
{
	int i;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	for( i = 0 ; i < nops ; i++)
	{
		if((p[i] = pcap_open_live(IFNAME,SNAPLEN,0,0,errbuf)) == NULL)
		{
			fprintf(stderr,"pcap_open_live[%d] : %s\n",i,errbuf);
			
			exit(1);
		}
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
	int index = (int)(*user);
	
	total_packets[index]++;
}

void run(void *arg)
{
	int index = (int)(*((int *)arg));
	
	if(pcap_loop(p[index],-1,count,(u_char *)&index))
	{
		pcap_perror(p[index],"pcap_loop");
		
		return;
	}
}

void monitor_all()
{
	char condition[MAX_FILTER_LEN];	
	int i;
	
	for( i = 0 ; i < nops ; i++)
	{
		int *index;
		
		if((index = malloc(sizeof(int))) == NULL)
		{
			fprintf(stderr,"Cound not allocate memory\n");
			
			exit(1);
		}
		
		sprintf(condition,"ether host %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			       i%0xFF,(i+1)%0xFF,(i+2)%0xFF,(i+3)%0xFF,(i+4)%0xFF,(i+5)%0xFF);
		
		apply_bpf_filter(p[i],condition);
		
		*index = i;
		
		if(pthread_create(&threads[*index],NULL,(void *)&run,(void *)index))
		{
			fprintf(stderr,"Cound not create thread for thread %d\n",*index);

			exit(1);
		}
	}

	pthread_join(threads[0],NULL);
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
	
	nops = atoi(argv[1]);

	open_lives();
	
	atexit(terminate);
	
	signal(SIGINT,sigint_handler);

	monitor_all();
	
	return 0;
}
