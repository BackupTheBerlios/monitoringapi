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
#include <tconfig.h>
#include <mapihandy.h>

int sock;
struct print_ether_struct pes;

static void terminate()
{
	if(set_all_promisc_off(sock) == -1)
	{
		perror("set_all_promisc_off");
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
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	if(set_all_promisc_on(sock) == -1)
	{
		perror("set_all_promisc_on");
	}
	else
	{
		printf("Interface %s set to promiscuous mode\n",IFNAME);		
	}
	
	atexit(terminate);
	
	pes.print_newline = 1;
	pes.print_payload = 0;
	
	if(ioctl(sock,SIOCSPRINT_ETHER,&pes))
	{
		perror("ioctl");
		exit(1);
	}
	
	signal(SIGINT,handler);

	pause();

	return 0;
}

