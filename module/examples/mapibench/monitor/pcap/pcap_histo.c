#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <signal.h>
#include <asm/fcntl.h>
#include <net/bpf.h>
#include <pcap.h>
#include <stdlib.h>
#include <linux/byteorder/generic.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

#include <linux/mapi/ioctl.h>
#include <mapihandy.h>
#include <pcapbench.h>
#include <tconfig.h>

#include <pcap-int.h>

static pcap_t *p;
__u32 histogram[256];

static void terminate()
{
	pcap_close(p);	
}

static void write_data()
{
	FILE *fp;
	int i;
	
	if((fp = fopen(FILENAME,"w")) == NULL)
	{
		fprintf(stderr,"Could not open file %s for writing\n",FILENAME);

		exit(1);
	}

	fprintf(fp,"#character #times_appeared\n");
	
	for( i = 0 ; i < 256 ; i++)
	{
		fprintf(fp,"%d %d\n",i,histogram[i]);
	}

	fclose(fp);
}

static void sigint_handler()
{
	if(print_mapi_statistics(p->fd))
	{
		perror("print_mapi_statistics");
	}

	if(print_packet_statistics(p->fd) || print_pcap_statistics(p))
	{
		perror("print_packet_statistics || print_pcap_statistics");
		exit(1);
	}
	
	write_data();
	
	exit(0);
}

static void touch(u_char *user,const struct pcap_pkthdr *packet_header,const u_char *packet)
{
	int i;

	for( i = 0 ; i < packet_header->len ; i += PERIOD)
	{
		histogram[packet[i]]++;
	}
}

int main(int argc,char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	__u32 so_rcvbuf_size;

	if((p = pcap_open_live(DEVICE,SNAPLEN,0,0,errbuf)) == NULL)
	{
		fprintf(stderr,"pcap_open_live : %s\n",errbuf);
		
		return 1;
	}
	
	if((so_rcvbuf_size = set_rcvbuf_size(p->fd,SO_RCVBUF_SIZE)) == -1)
	{
		perror("set_rcvbuf_size");
		exit(1);
	}
	
	printf("Socket recv buffer size = %d\n",so_rcvbuf_size);
	
	atexit(terminate);

	signal(SIGINT,sigint_handler);

#ifdef SLEEP
	signal(SIGALRM,sigint_handler);
	alarm(SLEEP_TIME);
#endif	

	if(pcap_loop(p,-1,touch,NULL))
	{
		pcap_perror(p,"pcap_loop");
		exit(1);
	}
	
	return 0;
}
