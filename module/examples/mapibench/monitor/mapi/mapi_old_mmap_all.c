#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <signal.h>
#include <asm/fcntl.h>
#include <stdlib.h>
#include <asm/string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <asm/system.h>
#include <linux/if_packet.h>

#include <mapibench.h>
#include <tconfig.h>

static struct monitor_struct *mons;

static struct tpacket_req req;
static struct iovec *rings[PORTS_NR];
static void *mapped_regions[PORTS_NR];

static void terminate()
{
	int i;
	
	for( i = 0 ; i < mons->ports_nr ; i++)
	{
		if(mapped_regions[i]) 
		{
			munmap(mapped_regions[i],req.tp_block_size*req.tp_block_nr);
		}
		
		if(rings[i])
		{
			free(rings[i]);
		}
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

static void setup_mmap(int index)
{
	int i;

	if((setsockopt(mons->socks[index],SOL_PACKET,PACKET_RX_RING,(char *)&req,sizeof(req))) != 0 )
	{
		perror("setsockopt");
		exit(1);
	}

	if((mapped_regions[index] = mmap(NULL,req.tp_block_size*req.tp_block_nr,
	    PROT_READ|PROT_WRITE|PROT_EXEC,MAP_SHARED,mons->socks[index],0)) == MAP_FAILED)
	{
		perror("mmap");
		exit(1);
	}

	if((rings[index] = malloc(req.tp_frame_nr*sizeof(struct iovec))) == NULL)
	{
		fprintf(stderr,"Could not allocate memory\n");
		exit(1);
	}
	
	for(i = 0 ; i < req.tp_frame_nr ; i++) 
	{
		rings[index][i].iov_base = (void *)((long)mapped_regions[index]) + (i*req.tp_frame_size);
		rings[index][i].iov_len = req.tp_frame_size;
	}
}

static void setup_all_mmaps()
{
	int i;
	
	req.tp_block_size = getpagesize();
	req.tp_block_nr = BLOCK_NR;
	req.tp_frame_size = getpagesize()/4;
	req.tp_frame_nr = 4*BLOCK_NR;

	for( i = 0 ; i < mons->ports_nr ; i++)
	{
		setup_mmap(i);
	}
}

static int last_indexes[PORTS_NR];

static void receive_packets(int index)
{
	int i = last_indexes[index];
	
	while(*(unsigned long*)rings[index][i].iov_base)
	{
		struct tpacket_hdr *h = rings[index][i].iov_base;
		//struct sockaddr_ll *sll = (void *)h + TPACKET_ALIGN(sizeof(*h));
		//unsigned char *bp = (unsigned char *)h + h->tp_mac;
		
		count_mmap(mons,index,h->tp_len,rings[index][i].iov_base + h->tp_net);
		
		h->tp_status = 0;
		
		mb();
		
		i = (i == req.tp_frame_nr - 1) ? 0 : i+1;

		last_indexes[index] = i;
	}
}

static void monitor_all()
{
	fd_set rfds;
	int max_fd;
	int i;
	
	FD_ZERO(&rfds);

	for( i = 0,max_fd = 0 ; i < mons->ports_nr ; i++)
	{
		printf("Monitoring port %d\n",monitored_ports[i]);

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
				receive_packets(i);
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
	
#ifdef SLEEP
        signal(SIGALRM,sigint_handler);
        alarm(SLEEP_TIME);
#endif  
	
	setup_all_mmaps();
	
	monitor_all();
	
	return 0;
}
