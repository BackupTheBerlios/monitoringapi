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
struct cook_ip_struct cis;
struct cook_udp_struct cus;

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

int main(int argc, char **argv)
{
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	if(ioctl(sock,SIOCSCOOK_IP,&cis) || ioctl(sock,SIOCSCOOK_UDP,&cus))
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

