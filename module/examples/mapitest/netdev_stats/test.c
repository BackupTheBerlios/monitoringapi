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

int sock;
struct netdev_stats_struct nss;

static void terminate()
{
	close(sock);
}

void handler()
{
	if(ioctl(sock,SIOCGNETDEV_STATS,&nss) == -1)
	{
		perror("ioctl");
		exit(1);
	}
	
	exit(0);
}

int main(int argc, char **argv)
{
	struct net_device_stats *limits = &(nss.limits);
	
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	/*struct net_device_stats
	{
		unsigned long   rx_packets;
		unsigned long   tx_packets;
		unsigned long   rx_bytes;
		unsigned long   tx_bytes;
		unsigned long   rx_errors;
		unsigned long   tx_errors;
		unsigned long   rx_dropped;
		unsigned long   tx_dropped;
		unsigned long   multicast;
		unsigned long   collisions;

		unsigned long   rx_length_errors;
		unsigned long   rx_over_errors;
		unsigned long   rx_crc_errors;
		unsigned long   rx_frame_errors;
		unsigned long   rx_fifo_errors;
		unsigned long   rx_missed_errors;

		unsigned long   tx_aborted_errors;
		unsigned long   tx_carrier_errors;
		unsigned long   tx_fifo_errors;
		unsigned long   tx_heartbeat_errors;
		unsigned long   tx_window_errors;

		unsigned long   rx_compressed;
		unsigned long   tx_compressed;
	};*/
	
	limits->rx_dropped = 10L;
	
	if(ioctl(sock,SIOCSNETDEV_STATS,&nss))
	{
		perror("ioctl");
		exit(1);
	}
	
	signal(SIGINT,handler);

	pause();

	return 0;
}

