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
struct sample_packets_struct sps;

void terminate()
{
	close(sock);
}

void handler()
{
	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_mapi_statistics");
	}
	
	exit(0);
}

int main(int argc, char **argv)
{
	char *buffer;
	int rbuf_size;

	if((sock = socket(PF_MAPI,RTYPE,htons(ETH_P_IP))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);

	sps.mode = MODE;
	sps.period = PERIOD;

	if(ioctl(sock,SIOCSSAMPLE_PACKETS,&sps) == -1)
	{
		perror("ioctl");
		exit(1);
	}
	
	signal(SIGINT,handler);

	/*if((rbuf_size = get_if_mtu(sock,IFNAME)) == -1 || 
	    bind_if_name(sock,IFNAME))
	{
		perror("get_if_mtu || bind_if_name");
		exit(1);
	}*/
	
	rbuf_size = 1514;
	
	printf("MTU of %s : %d\n",IFNAME,rbuf_size);
	printf("Interface %s set to promiscuous mode\n",IFNAME);
	
	buffer = alloca(rbuf_size);
	
	while(1)
	{
		int n;

		if((n = recvfrom(sock,buffer,rbuf_size,MSG_TRUNC,NULL,NULL)) < 0)
		{
			perror("recvfrom");

			exit(1);
		}

		printf("%d bytes read\n",n);
	}

	return 0;
}
