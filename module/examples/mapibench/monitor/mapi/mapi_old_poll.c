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
#include <asm/string.h>
#include <linux/if_packet.h>
#include <sys/types.h>
#include <unistd.h>

#include <mapibench.h>
#include <tconfig.h>

static struct monitor_struct *mons;

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
	fd_set rfds;
	char packet[SNAPLEN];
	int max_fd;
	int i;
	
	FD_ZERO(&rfds);

	for( i = 0,max_fd = 0 ; i < mons->ports_nr ; i++)
	{
		printf("Monitoring port %d\n",mons->monitored_ports[i]);

		FD_SET(mons->socks[i],&rfds);

		max_fd = max(mons->socks[i],max_fd);
	}

	while(1)
	{	
		if(select(max_fd + 1,&rfds,NULL,NULL,NULL) == -1)
		{
			perror("select");
			
			exit(1);
		}
		
		for( i = 0,max_fd = 0 ; i < mons->ports_nr ; i++)
		{
			max_fd = max(mons->socks[i],max_fd);

			if(FD_ISSET(mons->socks[i],&rfds))
			{
				int len;
		
				if((len = recvfrom(mons->socks[i],packet,SNAPLEN,MSG_TRUNC,NULL,NULL)) == -1)
				{
					perror("recvfrom");
					
					exit(1);
				}

				count(mons,i,len,packet);
			}
			else
			{
				FD_SET(mons->socks[i],&rfds);
			}
		}
	}
}

int main(int argc,char **argv)
{
	mons = monitor_struct_alloc(PORTS_NR);
	init_monitor_struct(mons,monitored_ports);

	open_sockets(mons);
	atexit(terminate);
	
	apply_bpf_filters(mons);
	signal(SIGINT,sigint_handler);

	monitor_all();
	
	return 0;
}
