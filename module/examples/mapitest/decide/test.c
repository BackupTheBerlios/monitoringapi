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

#define HIPQUAD(addr) \
((unsigned char *)&addr)[3], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[0]

int sock;
struct decide_struct ds;
struct flow_key_struct fks;
struct subflow_ioctl_struct sis;
struct flow_raw_struct frs;

void terminate()
{
	close(sock);
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

int main(int argc, char **argv)
{
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	init_flow_key_struct();
	init_ioctl_struct();
	
	if(ioctl(sock,SIOCSDECIDE,&ds))
	{
		perror("ioctl : SIOCSDECIDE");
		exit(1);
	}
	
	ds.ioctl.cmd = SIOCSFLOW_KEY;
	ds.ioctl.arg = &fks;
	
	if(ioctl(sock,SIOCIODECIDE,&ds))
	{
		perror("ioctl : SIOCIODECIDE ( = SIOCSFLOW_KEY )");
		exit(1);
	}
	
	ds.ioctl.cmd = SIOCSSUBFLOW;
	ds.ioctl.arg = &sis;

	if(ioctl(sock,SIOCIODECIDE,&ds))
	{
		perror("ioctl : SIOCIODECIDE ( = SIOCSSUBFLOW )");
		exit(1);
	}

	ds.ioctl.cmd = SIOCSFLOW_RAW;
	ds.ioctl.arg = &frs;
	
	if(ioctl(sock,SIOCIODECIDE,&ds))
	{
		perror("ioctl : SIOCIODECIDE ( = SIOCSFLOW_RAW )");
		exit(1);
	}

	while(1)
	{
		struct subflow *sbf;
		
		ds.ioctl.cmd = SIOCGFLOW_RAW;
		ds.ioctl.arg = &frs;

		if(ioctl(sock,SIOCIODECIDE,&ds))
		{
			perror("ioctl : SIOCIODECIDE : ( = SIOCGFLOW_RAW )");
			exit(1);
		}
		
		sbf = &(frs.sbf);
		
		printf("%u.%u.%u.%u  ",HIPQUAD(sbf->src_ip));
		printf("%u.%u.%u.%u  ",HIPQUAD(sbf->dst_ip));
		printf(" %d ",sbf->src_port);
		printf(" %d ",sbf->dst_port);
		printf(" %lld ",sbf->npackets);
		printf(" %lld ",sbf->nbytes);
		printf("\n");
	}

	return 0;
}
