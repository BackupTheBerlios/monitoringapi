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
#include <sys/mman.h>
#include <poll.h>
#include <asm/system.h>
#include <linux/types.h>

#include <mapibench.h>
#include <tconfig.h>

static struct monitor_struct *mons;

static struct tpacket_req req;
static struct iovec *ring;
static void *mapped_region;

static void terminate()
{	
	if(mapped_region) 
	{
		munmap(mapped_region,req.tp_block_size*req.tp_block_nr);
	}
	
	if(ring)
	{
		free(ring);
	}

	close(mons->socks[0]);
}

static void sigint_handler()
{
	printf("Process stats : Total packets = %lld\n",mons->packets_per_port[0]);
	printf("Process stats : Total bytes   = %lld\n",mons->bytes_per_port[0]);

	exit(0);
}

static void setup_mmap()
{
	int i;

	req.tp_block_size = 2*getpagesize();
	req.tp_block_nr = 64;
	req.tp_frame_size = getpagesize()/2;
	req.tp_frame_nr = 4*64;
	
	if((setsockopt(mons->socks[0],SOL_PACKET,PACKET_RX_RING,(char *)&req,sizeof(req))) != 0 )
	{
		perror("setsockopt");
		exit(1);
	}

	if((mapped_region = mmap(NULL,req.tp_block_size*req.tp_block_nr,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_SHARED,mons->socks[0],0)) == MAP_FAILED)
	{
		perror("mmap");
		exit(1);
	}

	if((ring = malloc(req.tp_frame_nr*sizeof(struct iovec))) == NULL)
	{
		fprintf(stderr,"Could not allocate memory\n");
		exit(1);
	}
	
	for(i = 0 ; i < req.tp_frame_nr ; i++) 
	{
		ring[i].iov_base = (void *)((long)mapped_region) + (i*req.tp_frame_size);
		ring[i].iov_len = req.tp_frame_size;
	}
}

static void monitor_all()
{
	struct pollfd pfd;
	int i;

	setup_mmap();
	
	for( i = 0 ; ; )
	{
		while(*(unsigned long*)ring[i].iov_base)
		{
			struct tpacket_hdr *h = ring[i].iov_base;
			//struct sockaddr_ll *sll = (void *)h + TPACKET_ALIGN(sizeof(*h));
			//unsigned char *bp = (unsigned char *)h + h->tp_mac;
			
			count_mmap(mons,0,h->tp_len,ring[i].iov_base + h->tp_net);
			
			h->tp_status = 0;
			
			mb();
			
			i = (i == req.tp_frame_nr - 1) ? 0 : i+1;
		}

		pfd.fd = mons->socks[0];
		pfd.events = POLLIN | POLLERR;
		pfd.revents = 0;
		
		if(poll(&pfd,1,-1) == -1)
		{
			perror("poll");
			exit(1);
		}
	}
}

int main(int argc,char **argv)
{
	mons = monitor_struct_alloc(PORTS_NR);
	mons->monitored_ports[0] = monitored_ports[0];
	mons->ports_nr = 1;
	
	open_sockets(mons);

	atexit(terminate);

        signal(SIGINT,sigint_handler);

#ifdef SLEEP
        signal(SIGALRM,sigint_handler);
        alarm(SLEEP_TIME);
#endif  
	apply_bpf_filters(mons);

	monitor_all();
	
	return 0;
}
