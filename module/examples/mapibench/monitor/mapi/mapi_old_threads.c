#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <signal.h>
#include <asm/fcntl.h>
#include <stdlib.h>
#include <linux/byteorder/generic.h>
#include <sys/time.h>
#include <pthread.h>
#include <linux/filter.h>
#include <asm/string.h>
#include <linux/if_packet.h>
#include <unistd.h>

#include <mapibench.h>
#include <tconfig.h>

static struct monitor_struct *mons;
static pthread_t threads[PORTS_NR];

static void terminate()
{
	int i;
	
	for( i = 0 ; i < mons->ports_nr ; i++)
	{
		pthread_kill(threads[i],SIGQUIT);
	}
	
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
		total_packets += mons->packets_per_port[i];
		total_bytes += mons->bytes_per_port[i];
	}
	
	print_ports_stats(mons);
	
	printf("Process stats : Total packets = %lld\n",total_packets);
	printf("Process stats : Total bytes   = %lld\n",total_bytes);

	exit(0);
}

static void run(void *arg)
{
	char packet[SNAPLEN];
	int index = (int)(*((int *)arg));

	printf("Monitoring port %d\n",mons->monitored_ports[index]);
		
	while(1)
	{
		int len;
		
		if((len = recvfrom(mons->socks[index],packet,SNAPLEN,MSG_TRUNC,NULL,NULL)) == -1)
		{
			perror("recvfrom");
			
			return;
		}

		count(mons,index,len,packet);
	}
}

static inline void monitor_all()
{
	int i;
	
	for( i = 0 ; i < mons->ports_nr ; i++)
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
	mons = monitor_struct_alloc(PORTS_NR);
	init_monitor_struct(mons,monitored_ports);
	
	open_sockets(mons);
	atexit(terminate);
	
	apply_bpf_filters(mons);

        signal(SIGINT,sigint_handler);
	
#ifdef SLEEP
        signal(SIGALRM,sigint_handler);
        alarm(SLEEP_TIME);
#endif  

	monitor_all();
	
	return 0;
}
