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

#include <linux/mapi/ioctl.h>
#include <mapihandy.h>
#include <tconfig.h>

int sock;
struct packet_save_struct pss;

static void terminate()
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
	
	exit(0);
}

int main(int argc, char **argv)
{
	char buffer[RBUF_SIZE];
	struct sockaddr_ll pinfo;
	socklen_t pinfo_len;

	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	if(if_promisc_on(sock,IFNAME) || bind_if_name(sock,IFNAME))
	{
		perror("if_promisc_on || bind_if_name");
	}

	pss.start_byte = START_BYTE;
	pss.end_byte = END_BYTE;
	pss.receive_packet = RECEIVE_PACKET;
		
	if(ioctl(sock,SIOCSPACKET_SAVE,&pss))
	{
		perror("ioctl");
		exit(1);
	}
	
	signal(SIGINT,handler);
	
	while(1)
	{
		int n;

		if((n = recvfrom(sock,buffer,RBUF_SIZE,MSG_TRUNC,(struct sockaddr *)&pinfo,&pinfo_len)) < 0)
		{
			perror("recvfrom");

			exit(1);
		}

		printf("%d bytes read\n",n);
	}
}

