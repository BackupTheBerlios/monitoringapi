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

void terminate()
{
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
	char *buffer;
	int rbuf_size;
	int counter = 0;

	if((sock = socket(PF_PACKET,RTYPE,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);	

	signal(SIGINT,handler);

	if((rbuf_size = get_if_mtu(sock,IFNAME)) == -1)
	{
		perror("get_if_mtu");
		exit(1);
	}
	
	buffer = alloca(rbuf_size);
	
	while(1)
	{
		int n;

		if((n = recvfrom(sock,buffer,rbuf_size,0,NULL,NULL)) == -1)
		{
			perror("recvfrom");

			exit(1);
		}

		if(PERIOD != 0 && counter%PERIOD == 0)
		{
			printf("%d bytes read\n",n);
		}

		counter++;
	}

	return 0;
}
