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
struct count_packets_struct cps;
struct set_cycle_counter_struct sccs;
struct accum_cycle_counter_struct accs;

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
	if(ioctl(sock,SIOCGCOUNT_PACKETS,&cps) ||
	   ioctl(sock,SIOCGACCUM_CYCLE_COUNTER,&accs))
	{
		perror("ioctl");
		exit(1);
	}
	
	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_mapi_statistics || print_packet_statistics");
	}

	printf("Total packets = %llu\n",cps.counter);
	printf("Total cycles  = %llu\n",accs.total_cycles);
	printf("Cycles/Packet = %f\n",((float)accs.total_cycles)/cps.counter);
	
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
	
	if(ioctl(sock,SIOCSSET_CYCLE_COUNTER,&sccs) ||
	   ioctl(sock,SIOCSCOUNT_PACKETS,&cps) ||
	   ioctl(sock,SIOCSACCUM_CYCLE_COUNTER,&accs))
	{
		perror("ioctl");
		exit(1);
	}
	
	signal(SIGINT,handler);

	pause();

	return 0;
}

