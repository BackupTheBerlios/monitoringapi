#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <signal.h>
#include <asm/fcntl.h>
#include <net/bpf.h>
#include <pcap.h>
#include <stdlib.h>
#include <linux/byteorder/generic.h>
#include <pthread.h>

#include <pcapbench.h>
#include <tconfig.h>

static __u32 packets_per_port[PORTS_NR];
static __u32 bytes_per_port[PORTS_NR];

static pcap_t *p[PORTS_NR];
static pthread_t threads[PORTS_NR];

static void terminate()
{
	int i;
	
	for( i = 0 ; i < PORTS_NR ; i++)
	{
		pthread_kill(threads[i],SIGQUIT);
	}
	
	for( i = 0 ; i < PORTS_NR ; i++)
	{
		pcap_close(p[i]);
	}
}

static void print_ports_stats()
{
	struct pcap_stat ps;
	__u64 pcap_recv = 0;
	__u64 pcap_drop = 0;
	int i;

	printf("Port   Packets     Bytes\n");
	
	for(i = 0 ; i < PORTS_NR ; i++)
	{
		printf("%.5u  %.10u  %.10u\n",monitored_ports[i],packets_per_port[i],bytes_per_port[i]);
	}
	
	for(i = 0 ; i < PORTS_NR ; i++)
	{
		if(pcap_stats(p[i],&ps) == -1)
		{
			pcap_perror(p[i],"pcap_stats");

			continue;
		}

		pcap_recv += (ps.ps_recv - ps.ps_drop);
		pcap_drop += ps.ps_drop;
	}

	printf("Pcap stats : Packets received  = %lld\n",pcap_recv);
	printf("Pcap stats : Packets dropped   = %lld\n",pcap_drop);
	
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
	
	printf("Process stats : Total packets = %lld\n",total_packets);
	printf("Process stats : Total bytes   = %lld\n",total_bytes);

	exit(0);
}

static void open_lives()
{
	int i;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	for( i = 0 ; i < PORTS_NR ; i++)
	{
		if((p[i] = pcap_open_live(DEVICE,SNAPLEN,0,0,errbuf)) == NULL)
		{
			fprintf(stderr,"pcap_open_live[%d] : %s\n",i,errbuf);
			
			exit(1);
		}
	}
}

static void apply_bpf_filters()
{
	struct bpf_program bpf_filters[PORTS_NR];
	char str[50];
	int i;
	
	for( i = 0 ; i < PORTS_NR ; i++)
	{
		sprintf(str,"port %u",monitored_ports[i]);
		
		printf("Constructing filter : %s\n",str);
		
		if(pcap_compile(p[i],&bpf_filters[i],str,1,0xFFFFFF00))
		{
			pcap_perror(p[i],"pcap_compile");
			
			exit(1);
		}
	}

	for( i = 0 ; i < PORTS_NR ; i++)
	{
		if(pcap_setfilter(p[i],&bpf_filters[i]))
		{
			pcap_perror(p[i],"pcap_setfilter");
			
			exit(1);
		}
	}
	
	for( i = 0 ; i < PORTS_NR ; i++)
	{
		pcap_freecode(&bpf_filters[i]);
	}
}

static void count(u_char *user,const struct pcap_pkthdr *packet_header,const u_char *packet)
{
	int index = (int)(*user);
	__u32 src_ip,dst_ip;
	__u16 src_port,dst_port;
	
	get_ips_ports(packet+IPHDR_OFFSET,&src_ip,&dst_ip,&src_port,&dst_port);
	
	packets_per_port[index]++;
	bytes_per_port[index] += packet_header->len;
	
#ifdef BENCH_DEBUG
	//print_packet(packet,packet_header->len);
	print_quad(src_ip,dst_ip,src_port,dst_port);
#endif	
}

static void run(void *arg)
{
	int index = (int)(*((int *)arg));
	
	printf("Monitoring port %d\n",monitored_ports[index]);
		
	if(pcap_loop(p[index],-1,count,(u_char *)&index))
	{
		pcap_perror(p[index],"pcap_loop");
		
		return;
	}
}

static void monitor_all()
{
	int i;
	
	for( i = 0 ; i < PORTS_NR ; i++)
	{
		int *index;
		
		if((index = malloc(sizeof(int))) == NULL)
		{
			fprintf(stderr,"Cound not allocate memory\n");
			
			exit(1);
		}
		
		*index = i;
		
		if(pthread_create(&threads[*index],NULL,(void *)&run,(void *)index))
		{
			fprintf(stderr,"Cound not create thread for port %d\n",monitored_ports[*index]);

			exit(1);
		}
	}

	pthread_join(threads[0],NULL);
}

int main(int argc,char **argv)
{
	open_lives();
	apply_bpf_filters();
	
	atexit(terminate);
	
	signal(SIGINT,sigint_handler);

#ifdef SLEEP
	signal(SIGALRM,sigint_handler);
	alarm(SLEEP_TIME);
#endif	

	monitor_all();
	
	return 0;
}
