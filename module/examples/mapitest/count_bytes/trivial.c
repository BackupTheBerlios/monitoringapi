#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <linux/mapi/ioctl.h>
#include <mapihandy.h>
#include <tconfig.h>

int sock;
__u32 rbuf_size;
__u64 incoming_bytes;
__u64 outgoing_bytes;

void terminate()
{
	if(if_promisc_off(sock,IFNAME))
	{
		perror("if_promisc_off");
	}
	else
	{
		printf("Interface %s set to non-promiscuous mode\n",IFNAME);
	}
	
	close(sock);
}

void handler()
{
	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_mapi_statistics || print_packet_statistics");
	}

	printf("Incoming : Total Mbytes = %f , Gbytes = %f\n",((float)incoming_bytes)/(1024*1024),((float)incoming_bytes)/(1024*1024*1024));
	printf("Outgoing : Total Mbytes = %f , Gbytes = %f\n",((float)outgoing_bytes)/(1024*1024),((float)outgoing_bytes)/(1024*1024*1024));
	
	exit(0);
}

void init_socket(int sock)
{
	__u32 so_rcvbuf_size;

	if((so_rcvbuf_size = set_rcvbuf_size(sock,SO_RCVBUF_SIZE)) == -1 || 
	   bind_if_name(sock,IFNAME) ||
	   (rbuf_size = get_if_mtu(sock,IFNAME)) == -1 ||
	   if_promisc_on(sock,IFNAME))
	{
		perror("set_rcvbuf_size || bind_if_name || get_if_mtu || if_promisc_on");
		exit(1);
	}
	
	printf("Socket recv buffer size = %d\n",so_rcvbuf_size);
	printf("Socket bound to interface %s\n",IFNAME);
	printf("MTU of %s = %d bytes\n",IFNAME,rbuf_size);
	printf("Interface %s set to promiscuous mode\n",IFNAME);
}

int main(int argc, char **argv)
{
	char *buffer;
	struct sockaddr_ll pinfo;
	socklen_t pinfo_len;
	
	if((sock = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);

	init_socket(sock);
	
	signal(SIGINT,handler);

#ifdef SLEEP
	signal(SIGALRM,handler);
	alarm(SLEEP_TIME);
#endif	
	buffer = alloca(rbuf_size);
	
	while(1)
	{
		int n;
		
		pinfo_len = sizeof(pinfo);
		
		if((n = recvfrom(sock,buffer,rbuf_size,MSG_TRUNC,(struct sockaddr *)&pinfo,&pinfo_len)) < 0)
		{
			perror("recvfrom");

			exit(1);
		}
		
		if(pinfo.sll_pkttype == PACKET_OUTGOING)
		{
			outgoing_bytes += n;

			continue;
		}
		
		incoming_bytes += n;
	}
}
