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

#define MAX_COUNTERS 10

int sock;
struct count_bytes_struct cbs[MAX_COUNTERS];

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
	int i;
	
	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_mapi_statistics || print_packet_statistics");
	}
	
	for( i = 0 ; i < MAX_COUNTERS ; i++)
	{
		if(ioctl(sock,SIOCGCOUNT_BYTES,&cbs[i]))
		{
			perror("ioctl");
			exit(1);
		}
		
		printf("[%-3d] Total bytes = %lld\n",i,cbs[i].counter);
	}

	exit(0);
}

int main(int argc, char **argv)
{
	int i;
		
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
	
	for( i = 0 ; i < MAX_COUNTERS ; i++)
	{
		if(ioctl(sock,SIOCSCOUNT_BYTES,&cbs[i]))
		{
			perror("ioctl : SIOCSCOUNT_BYTES");
			exit(1);
		}
	}
	
	signal(SIGINT,handler);

#ifdef SLEEP
	signal(SIGALRM,handler);
	alarm(SLEEP_TIME);
#endif	
	pause();

	return 0;
}

