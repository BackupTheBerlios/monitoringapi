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
#include <stdlib.h>
#include <signal.h>

#include <linux/mapi/ioctl.h>
#include <tconfig.h>
#include <mapihandy.h>

int sock;

struct logging_struct ls;
struct print_ether_struct pes;
struct print_ip_struct pis;
struct pkt_type_struct pts;

void terminate()
{
	close(sock);
}

void handler()
{
	if(ioctl(sock,SIOCGLOGGING,&ls) == -1)
	{
		perror("ioctl");
		exit(1);
	}
	
	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_mapi_statistics || print_packet_statistics");
	}

	printf("Filename = %s\n",ls.filename);
	printf("Size = %d\n",ls.file_size);
	printf("Packets Logged = %d\n",ls.packets_logged);
	
	exit(0);
}

void setup_pkt_type()
{
	pts.type = PACKET_HOST;
	
	if(ioctl(sock,SIOCSPKT_TYPE,&pts))
	{
		perror("ioctl");
		exit(1);
	}
}

void setup_print()
{
	pes.print_newline = 0;
	pes.print_payload = 0;
	
	if(ioctl(sock,SIOCSPRINT_ETHER,&pes))
	{
		perror("ioctl");
		exit(1);
	}
	
	pis.print_newline = 1;
	pis.print_id = 1;
	pis.print_tos = 1;
	pis.print_ttl = 1;
	pis.print_ip_len = 1;
	
	if(ioctl(sock,SIOCSPRINT_IP,&pis))
	{
		perror("ioctl");
		exit(1);
	}
}

void setup_logging()
{
	ls.filename = (char *)malloc((strlen(FILENAME)+1)*sizeof(char));
	sprintf(ls.filename,"%s",FILENAME);
	ls.length = strlen(ls.filename) + 1;

	ls.snaplen = 1514;
	ls.encap_type = FAKE_DLT_EN10MB;
	
	if(ioctl(sock,SIOCSLOGGING,&ls) == -1)
	{
		perror("ioctl");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	setup_pkt_type();
	setup_print();
	setup_logging();
	
	signal(SIGINT,handler);

	pause();

	return 0;
}

