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
__u8 cached_bpf;

struct count_packets_struct cps;
struct bpf_filter_struct bpf;
struct set_perf_counter_struct spcs;
struct accum_perf_counter_struct apcs;

void setup_ctrs(struct set_perf_counter_struct *spcs,struct accum_perf_counter_struct *apcs)
{
	spcs->ctr[0].enabled = 1;
	spcs->ctr[0].event = 0x0c;	/* BSQ_CACHE_REFERENCE */
	spcs->ctr[0].unit_mask = 0x07ff;
	
	spcs->ctr[3].enabled = 1;
	spcs->ctr[3].event = 0x23;	/* INSTR_RETIRED */
	spcs->ctr[3].unit_mask = 0x01;
	
	spcs->ctr[4].enabled = 1;
	spcs->ctr[4].event = 0x1d;	/* GLOBAL_POWER_EVENTS */
	spcs->ctr[4].unit_mask = 0x01;

	memcpy(&(apcs->ctr[0]),&(spcs->ctr[0]),sizeof(spcs->ctr[0]));
	memcpy(&(apcs->ctr[3]),&(spcs->ctr[3]),sizeof(spcs->ctr[3]));
	memcpy(&(apcs->ctr[4]),&(spcs->ctr[4]),sizeof(spcs->ctr[4]));
}

void print_ctrs(struct accum_perf_counter_struct *apcs)
{
	int i;

	for( i = 0 ; i < PERF_MAX_COUNTERS ; i++)
	{
		if(!apcs->ctr[i].enabled)
		{
			continue;
		}

		printf("Event %d : %u\n",i,apcs->ctr[i].count);
	}
}

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
	
	if(ioctl(sock,SIOCGACCUM_PERF_COUNTER,&apcs))
	{
		perror("ioctl : SIOCGACCUM_PERF_COUNTER");
		exit(1);
	}
		
	print_ctrs(&apcs);

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

	if(cached_bpf)
	{
		if(ioctl(sock,SIOCSCACHED_BPF_FILTER,&bpf))
		{
			perror("ioctl");
			exit(1);
		}
	}
	else
	{
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
	char condition[MAX_FILTER_LEN];
	int nofilters;
	int len = 0;
	int i;
	
	if(argc != 3)
	{
		fprintf(stderr,"Usage : %s num_of_filters cached_bpf\n",argv[0]);
		exit(1);
	}

	nofilters = atoi(argv[1]);
	cached_bpf = atoi(argv[2]);
	
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	setup_ctrs(&spcs,&apcs);
	
	for( i = 0 ; i < nofilters ; i++)
	{
		len += sprintf(condition + len,"ether host %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			       i%0xFF,(i+1)%0xFF,(i+2)%0xFF,(i+3)%0xFF,(i+4)%0xFF,(i+5)%0xFF);
		
		if(i < (nofilters - 1))
		{
			len += sprintf(condition + len," or ");
		}
	}
	
	if(ioctl(sock,SIOCSSET_PERF_COUNTER,&spcs))
	{
		perror("ioctl : SIOCSSET_PERF_COUNTER");
		exit(1);
	}

	apply_bpf_filter(sock,condition);
	
	if(ioctl(sock,SIOCSACCUM_PERF_COUNTER,&apcs))
	{
		perror("ioctl : SIOCSACCUM_PERF_COUNTER");
		exit(1);
	}

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
