#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

#include <linux/mapi/ioctl.h>
#include <tconfig.h>
#include <mapihandy.h>

int sock;
struct flow_key_struct fks;
struct subflow_ioctl_struct sis;
struct flow_report_struct frs;

void terminate()
{
	close(sock);
}

void sigint_handler()
{
	if(print_packet_statistics(sock))
	{
		perror("print_packet_statistics");
	}
	
	if(print_mapi_statistics(sock))
	{
		perror("print_mapi_statistics");
	}
	
	exit(0);
}

void init_flow_key_struct()
{
	memset(&fks,0,sizeof(fks));

	fks.src_ip = 1;
	fks.dst_ip = 1;
	fks.src_port = 1;
	fks.dst_port = 1;
	fks.ip_proto = 1;
}

void init_ioctl_struct()
{
	sis.timeout = TIMEOUT;
	sis.max_duration = MAX_DURATION;
}

void init_flow_report_struct()
{
	frs.format = FORMAT;
}

int main(int argc,char **argv)
{
	__u8 buffer[BUFFER_SIZE];	
	
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	init_flow_key_struct();
	init_flow_report_struct();
	init_ioctl_struct();
	
	if(ioctl(sock,SIOCSFLOW_KEY,&fks))
	{
		perror("ioctl : SIOCSFLOW_KEY");
		exit(1);
	}

	if(ioctl(sock,SIOCSSUBFLOW,&sis))
	{
		perror("ioctl : SIOCSSUBFLOW");
		exit(1);
	}

	if(ioctl(sock,SIOCSFLOW_REPORT,&frs))
	{
		perror("ioctl : SIOCSFLOW_REPORT");
		exit(1);
	}

	signal(SIGINT,sigint_handler);
	
	while(1)
	{
		int n;

		if((n = recvfrom(sock,buffer,BUFFER_SIZE,0,NULL,NULL)) == -1)
		{
			perror("recvfrom");

			exit(1);
		}

		printf("Bytes read : %u\n",n);
	}

	return 0;
}
