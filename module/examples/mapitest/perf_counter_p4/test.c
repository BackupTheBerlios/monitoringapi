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
struct set_perf_counter_struct spcs;
struct accum_perf_counter_struct apcs;

void setup_ctrs(struct set_perf_counter_struct *spcs,struct accum_perf_counter_struct *apcs)
{
	spcs->ctr[0].enabled = 1;
	spcs->ctr[0].event = 0x0c;	/* BSQ_CACHE_REFERENCE */
	spcs->ctr[0].unit_mask = 0x07ff;
	
	spcs->ctr[3].enabled = 1;
	spcs->ctr[3].event = 0x23;	/* INSTR_RETIRED */
	spcs->ctr[3].unit_mask = 0x01;
	
	spcs->ctr[4].enabled = 1;
	spcs->ctr[4].event = 0x1d;	/* GLOBAL_POWER_EVENTS */
	spcs->ctr[4].unit_mask = 0x01;

	memcpy(&(apcs->ctr[0]),&(spcs->ctr[0]),sizeof(spcs->ctr[0]));
	memcpy(&(apcs->ctr[3]),&(spcs->ctr[3]),sizeof(spcs->ctr[3]));
	memcpy(&(apcs->ctr[4]),&(spcs->ctr[4]),sizeof(spcs->ctr[4]));
}

void print_ctrs(struct accum_perf_counter_struct *apcs)
{
	int i;

	for( i = 0 ; i < PERF_MAX_COUNTERS ; i++)
	{
		if(!apcs->ctr[i].enabled)
		{
			continue;
		}

		printf("Event %d : %u\n",i,apcs->ctr[i].count);
	}
}

static void terminate()
{
	if(if_promisc_off(sock,IFNAME) == -1)
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
	if(ioctl(sock,SIOCGACCUM_PERF_COUNTER,&apcs) ||
	   ioctl(sock,SIOCGCOUNT_PACKETS,&cps) == -1)
	{
		perror("ioctl");
		exit(1);
	}
	
	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_mapi_statistics || print_packet_statistics");
	}

	printf("Total packets = %llu\n",cps.counter);
	
	print_ctrs(&apcs);
	
	exit(0);
}

int main(int argc, char **argv)
{
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	if(bind_if_name(sock,IFNAME))
	{
		perror("bind_if_name");
		exit(1);
	}
	
	if(if_promisc_on(sock,IFNAME) == -1)
	{
		perror("if_promisc_on");
	}
	else
	{
		printf("Interface %s set to promiscuous mode\n",IFNAME);		
	}

	atexit(terminate);
	
	setup_ctrs(&spcs,&apcs);
	
	if(ioctl(sock,SIOCSSET_PERF_COUNTER,&spcs) ||
	   ioctl(sock,SIOCSCOUNT_PACKETS,&cps) ||
	   ioctl(sock,SIOCSACCUM_PERF_COUNTER,&apcs))
	{
		perror("ioctl");
		exit(1);
	}
	
	signal(SIGINT,handler);

	pause();

	return 0;
}

