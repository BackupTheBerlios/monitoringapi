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
#include <sys/ioctl.h>
#include <linux/if_packet.h>

#include <linux/mapi/ioctl.h>
#include <pcaptest.h>
#include <tconfig.h>
#include <mapihandy.h>

pcap_t *p;

void terminate()
{
	pcap_close(p);	
}

void sigint_handler()
{
	if(print_pcap_statistics(p))
	{
		perror("print_pcap_statistics");
	}

	exit(0);
}

 void apply_bpf_filters()
{
	struct bpf_program bpf_filter;
	char *str = "(src host 139.91.70.42 or src host 1.1.1.2) " 
		    "and (dst host 139.91.70.43 or dst host 1.1.1.3) "
		    "and (dst port 22 or dst port 23)";
	
	printf("Constructing filter : %s\n",str);
	
	if(pcap_compile(p,&bpf_filter,str,1,0xFFFFFF00))
	{
		pcap_perror(p,"pcap_compile");
		
		exit(1);
	}

	if(pcap_setfilter(p,&bpf_filter))
	{
		pcap_perror(p,"pcap_setfilter");
		
		exit(1);
	}
	
	pcap_freecode(&bpf_filter);
}

 void count(u_char *user,const struct pcap_pkthdr *packet_header,const u_char *packet)
{
	__u32 src_ip,dst_ip;
	__u16 src_port,dst_port;
	
	get_ips_ports(packet+IPHDR_OFFSET,&src_ip,&dst_ip,&src_port,&dst_port);
	
#ifdef DEBUG
	//print_packet(packet,packet_header->len);
	print_quad(src_ip,dst_ip,src_port,dst_port);
#endif	
}

int main(int argc,char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if((p = pcap_open_live(DEVICE,SNAPLEN,0,0,errbuf)) == NULL)
	{
		fprintf(stderr,"pcap_open_live : %s\n",errbuf);
		
		return 1;
	}
	
	atexit(terminate);
	signal(SIGINT,sigint_handler);

	apply_bpf_filters();
	
	if(pcap_loop(p,-1,count,NULL))
	{
		pcap_perror(p,"pcap_loop");
		
		exit(1);
	}
	
	return 0;
}
