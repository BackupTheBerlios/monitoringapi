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
struct band_meter_struct bms;

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
	
	bms.interval = 2;	//secs
	
	if(ioctl(sock,SIOCSBAND_METER,&bms))
	{
		perror("ioctl");
		exit(1);
	}
	
	signal(SIGINT,handler);

	while(1)
	{
		if(ioctl(sock,SIOCGBAND_METER,&bms) == -1)
		{
			perror("ioctl");
			exit(1);
		}
		
		printf("Kbps = %.2f or ",((float)8*bms.bytes_per_sec)/1000);
		printf("Mbps = %.2f\n",((float)8*bms.bytes_per_sec)/1000000);
	
		sleep(2);
	}
	
	return 0;
}

