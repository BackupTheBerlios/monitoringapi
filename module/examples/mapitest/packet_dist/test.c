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
#include <time.h>
#include <linux/ip.h>
#include <stdlib.h>

#include <linux/mapi/ioctl.h>
#include <tconfig.h>
#include <mapihandy.h>

int sock;
struct packet_distribution_struct pds;

void terminate()
{
	if(set_all_promisc_off(sock) == -1)
	{
		perror("set_all_promisc_off");
	}
	
	close(sock);
}

void write_data()
{
	FILE *fp;
	int i;
	
	if((fp = fopen(FILENAME,"w")) == NULL)
	{
		fprintf(stderr,"Could not open file %s for writing\n",FILENAME);

		exit(1);
	}

	fprintf(fp,"#src_port #packets\n");
	
	for( i = 0 ; i < MAX_DIST_ARRAY_SIZE ; i++)
	{
		fprintf(fp,"%d %lld\n",i,pds.dist[i]);
	}

	fclose(fp);
}

void handler()
{
	if(ioctl(sock,SIOCGPACKET_DISTRIBUTION,&pds))
	{
		perror("ioctl");
		exit(1);
	}
	
	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_*_statistics");
		exit(1);
	}

	write_data();
	
	exit(0);
}

void init_packet_distribution_struct()
{
	//src port distribution
	pds.offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(__u16);
	pds.mask = 16;
	
	if((pds.dist = malloc(MAX_DIST_ARRAY_SIZE*sizeof(__u64))) == NULL)
	{
		fprintf(stderr,"Could not allocate memory\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_IP))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	if(set_all_promisc_on(sock) == -1)
	{
		perror("set_all_promisc_on");
	}
	
	init_packet_distribution_struct();
	
	if(ioctl(sock,SIOCSPACKET_DISTRIBUTION,&pds))
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

