#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <signal.h>
#include <asm/fcntl.h>
#include <stdlib.h>
#include <linux/byteorder/generic.h>
#include <asm/string.h>
#include <linux/if_packet.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <asm/system.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <sys/poll.h>

#include <linux/mapi/ioctl.h>
#include <compcommon.h>
#include <tconfig.h>
#include <mapihandy.h>
#include <mapirusage.h>

int sock;
struct tpacket_req req;
struct iovec *ring;
void *mapped_region;

void terminate()
{	
	if(mapped_region) 
	{
		munmap(mapped_region,req.tp_block_size*req.tp_block_nr);
	}
	
	if(ring)
	{
		free(ring);
	}

	close(sock);
}

void sigint_handler()
{
	if(end_time_and_usage())
	{
		perror("end_time_and_usage");
		exit(1);
	}

	print_mapi_statistics(sock);
	
	if(print_packet_statistics(sock))
	{
		perror("print_packet_statistics");
	}

	print_rusage();

	exit(0);
}

void setup_mmap()
{
	int i;

	req.tp_block_size = 2*getpagesize();
	req.tp_block_nr = 64;
	req.tp_frame_size = getpagesize()/2;
	req.tp_frame_nr = 4*64;
	
	if((setsockopt(sock,SOL_PACKET,PACKET_RX_RING,(char *)&req,sizeof(req))) != 0 )
	{
		perror("setsockopt");
		exit(1);
	}

	if((mapped_region = mmap(NULL,req.tp_block_size*req.tp_block_nr,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_SHARED,sock,0)) == MAP_FAILED)
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

void touch_mmap(int sock,int index,int length,const u_char *data)
{
	/*int i;
	
	for( i = 0 ; i < length ; i += PERIOD)
	{
		data[i];
	}

	printf("%d bytes read\n",length);*/
}

void monitor_all()
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
			
			touch_mmap(sock,0,h->tp_len,ring[i].iov_base + h->tp_net);
			
			h->tp_status = 0;
			
			mb();
			
			i = (i == req.tp_frame_nr - 1) ? 0 : i+1;
		}

		pfd.fd = sock;
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
	if(start_time_and_usage())
	{
		perror("start_time_and_usage");
		exit(1);
	}
		
	if((sock = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}

	atexit(terminate);
	
	if(bind_if_name(sock,IFNAME))
	{
		printf("Cannot bind to interface %s\n",IFNAME);
		exit(1);
	}

        signal(SIGINT,sigint_handler);

#ifdef SLEEP
        signal(SIGALRM,sigint_handler);
        alarm(SLEEP_TIME);
#endif  
	monitor_all();
	
	return 0;
}
