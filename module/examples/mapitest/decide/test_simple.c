#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>

#include <linux/mapi/ioctl.h>
#include <tconfig.h>
#include <mapihandy.h>

int udp_sock,mapi_sock;
struct decide_struct ds;
struct flow_key_struct fks;
struct subflow_ioctl_struct sis;
struct flow_report_struct frs;

void terminate()
{
	close(udp_sock);
	close(mapi_sock);
}

void sigint_handler()
{
	if(print_mapi_statistics(mapi_sock))
	{
		perror("print_mapi_statistics");
	}
	
	exit(0);
}

void pdu_xmit(__u8 *buffer,int buffer_size,int udp_sock)
{

again:
	if(send(udp_sock,(char *)buffer,buffer_size,0) < 0)
	{
		/*
		 * always complete a send, drop flows in the kernel on receive if
		 * overloaded 
		 */
		if(errno == ENOBUFS)
		{
			usleep(1);

			goto again;
		}

		if(errno != ECONNREFUSED)
		{
			perror("send");
		}
	}

	if(TX_DELAY)
	{
		usleep((unsigned)TX_DELAY);
	}
}

void init_udp()
{
	struct sockaddr_in loc_addr;
	struct sockaddr_in rem_addr;

	bzero(&loc_addr,sizeof(struct sockaddr_in));
	bzero(&rem_addr,sizeof(struct sockaddr_in));

	if(inet_aton(REMOTE_IP,&(rem_addr.sin_addr)) == 0)
	{
		perror("inet_aton");
		exit(1);
	}
	
	rem_addr.sin_family = AF_INET;
	rem_addr.sin_port = htons(REMOTE_PORT);

	loc_addr.sin_addr.s_addr = INADDR_ANY;
	loc_addr.sin_family = AF_INET;

	if((udp_sock = socket(AF_INET,SOCK_DGRAM,0)) < 0)
	{
		perror("socket : AF_INET");
		exit(1);
	}

	if(bind(udp_sock,(struct sockaddr *)&loc_addr,sizeof(loc_addr)) < 0)
	{
		perror("bind");
		exit(1);
	}

	if(connect(udp_sock,(struct sockaddr *)&rem_addr,sizeof(rem_addr)) < 0)
	{
		perror("connect");
		exit(1);
	}
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

void init_mapi()
{
	init_flow_key_struct();
	init_flow_report_struct();
	init_ioctl_struct();

	if((mapi_sock = socket(AF_MAPI,SOCK_RAW,htons(ETH_P_IP))) < 0)
	{
		perror("socket : AF_MAPI");
		exit(1);
	}
	
	if(ioctl(mapi_sock,SIOCSDECIDE,&ds))
	{
		perror("ioctl : SIOCSDECIDE");
		exit(1);
	}
	
	ds.ioctl.cmd = SIOCSFLOW_KEY;
	ds.ioctl.arg = &fks;
	
	if(ioctl(mapi_sock,SIOCIODECIDE,&ds))
	{
		perror("ioctl : SIOCIODECIDE ( = SIOCSFLOW_KEY )");
		exit(1);
	}
	
	ds.ioctl.cmd = SIOCSSUBFLOW;
	ds.ioctl.arg = &sis;

	if(ioctl(mapi_sock,SIOCIODECIDE,&ds))
	{
		perror("ioctl : SIOCIODECIDE ( = SIOCSSUBFLOW )");
		exit(1);
	}

	ds.ioctl.cmd = SIOCSFLOW_REPORT;
	ds.ioctl.arg = &frs;
	
	if(ioctl(mapi_sock,SIOCIODECIDE,&ds))
	{
		perror("ioctl : SIOCIODECIDE ( = SIOCSFLOW_REPORT )");
		exit(1);
	}
}

int main(int argc,char **argv)
{
	__u8 buffer[BUFFER_SIZE];	

	init_udp();	
	init_mapi();
	
	atexit(terminate);
	signal(SIGINT,sigint_handler);
	
	while(1)
	{
		int n;

		if((n = recvfrom(mapi_sock,buffer,BUFFER_SIZE,0,NULL,NULL)) == -1)
		{
			perror("recvfrom");

			exit(1);
		}

		printf("Bytes read : %u\n",n);

		pdu_xmit(buffer,n,udp_sock);
	}

	return 0;
}
