#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <asm/fcntl.h>
#include <net/bpf.h>
#include <pcap.h>
#include <stdlib.h>
#include <linux/byteorder/generic.h>
#include <sys/time.h>
#include <linux/filter.h>
#include <asm/string.h>
#include <linux/if_packet.h>
#include <unistd.h>

#include <linux/mapi/ioctl.h>
#include <mapibench.h>
#include <tconfig.h>

static struct monitor_struct *mons;

static struct count_packets_struct cps[PORTS_NR];
static struct count_bytes_struct cbs[PORTS_NR];

static void terminate()
{
	int i;
	
	for( i = 0 ; i < mons->ports_nr ; i++)
	{
		close(mons->socks[i]);
	}
}

static void sigint_handler()
{
	__u64 total_packets = 0;
	__u64 total_bytes = 0;
	int i;
	
	for(i = 0 ; i < mons->ports_nr ; i++)
	{
		if(ioctl(mons->socks[i],SIOCGCOUNT_PACKETS,&cps[i]) == -1)
		{
			perror("ioctl");
			
			exit(1);
		}
		
		if(ioctl(mons->socks[i],SIOCGCOUNT_BYTES,&cbs[i]) == -1)
		{
			perror("ioctl");
			
			exit(1);
		}
		
		mons->packets_per_port[i] = cps[i].counter;
		mons->bytes_per_port[i] = cbs[i].counter;

		total_packets += mons->packets_per_port[i];
		total_bytes += mons->bytes_per_port[i];
	}
	
	print_ports_stats(mons);
	
	printf("Process stats : Total packets = %lld\n",total_packets);
	printf("Process stats : Total bytes   = %lld\n",total_bytes);

	exit(0);
}

static void monitor_all()
{
	int i;
	
	for( i = 0 ; i < mons->ports_nr ; i++)
	{
		printf("Monitoring port %d\n",mons->monitored_ports[i]);
		
		if(ioctl(mons->socks[i],SIOCSCOUNT_PACKETS,&cps[i]) == -1)
		{
			perror("ioctl");
			
			exit(1);
		}

		if(ioctl(mons->socks[i],SIOCSCOUNT_BYTES,&cbs[i]) == -1)
		{
			perror("ioctl");
			
			exit(1);
		}
	}
}

int main(int argc,char **argv)
{
	mons = monitor_struct_alloc(PORTS_NR);
	init_monitor_struct(mons,monitored_ports);
	
	open_sockets(mons);
	apply_bpf_filters(mons);
	
	atexit(terminate);
        
	signal(SIGINT,sigint_handler);

#ifdef SLEEP
        signal(SIGALRM,sigint_handler);
        alarm(SLEEP_TIME);
#endif  

	monitor_all();
	
	pause();
	
	return 0;
}
