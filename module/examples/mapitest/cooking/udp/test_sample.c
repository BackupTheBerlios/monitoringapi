#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <stdlib.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <linux/mapi/ioctl.h>

#include <mapihandy.h>
#include <tconfig.h>

int sock;
struct cook_ip_struct cis;
struct cook_udp_struct cus;
struct sample_packets_struct sps;

void terminate()
{
	close(sock);
}

void handler()
{
	if(ioctl(sock,SIOCGCOOK_IP,&cis) || ioctl(sock,SIOCGCOOK_UDP,&cus))
	{
		perror("ioctl");
		exit(1);
	}
	
	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_mapi_statistics || print_packet_statistics");
	}

	exit(0);
}

void init_cook_packets()
{
	if(ioctl(sock,SIOCSCOOK_IP,&cis) || ioctl(sock,SIOCSCOOK_UDP,&cus))
	{
		perror("ioctl");
		exit(1);
	}
}	

void init_sample_packets()
{
	sps.mode = SAMPLE_MODE_ALL;
	sps.period = 0;

	if(ioctl(sock,SIOCSSAMPLE_PACKETS,&sps) == -1)
	{
		perror("ioctl");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	char *buffer;
	__u32 rbuf_size;
	
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	if(bind_if_name(sock,IFNAME) || (rbuf_size = get_if_mtu(sock,IFNAME)) == -1)
	{
		perror("bind_if_name || get_if_mtu");
		exit(1);
	}
	
	printf("Socket bound to interface %s\n",IFNAME);
	printf("MTU of %s = %d bytes\n",IFNAME,rbuf_size);

	rbuf_size -= (sizeof(struct iphdr) + sizeof(struct udphdr));
	
	init_cook_packets();
	init_sample_packets();

	signal(SIGINT,handler);
		
	buffer = alloca(rbuf_size);

	while(1)
	{
		int n;
		
		if((n = recvfrom(sock,buffer,rbuf_size,0,NULL,NULL)) == -1)
		{
			perror("recvfrom");
			exit(1);
		}
		
		printf("%d bytes read\n",n);
	}
}

