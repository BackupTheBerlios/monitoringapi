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
struct count_bytes_struct cps;

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
	if(ioctl(sock,SIOCGCOUNT_BYTES,&cps) == -1)
	{
		perror("ioctl");
		exit(1);
	}
	
	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_mapi_statistics || print_packet_statistics");
	}
	
	printf("Total bytes = %lld\n",cps.counter);
	
	exit(0);
}

int main(int argc, char **argv)
{
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

	if(ioctl(sock,SIOCSCOUNT_BYTES,&cps))
	{
		perror("ioctl");
		exit(1);
	}
	
	signal(SIGINT,handler);
#ifdef SLEEP
	signal(SIGALRM,handler);
	alarm(SLEEP_TIME);
#endif	
	pause();

	return 0;
}

