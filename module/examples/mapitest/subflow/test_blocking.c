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

#include <linux/mapi/ioctl.h>
#include <tconfig.h>
#include <subflow.h>

int sock;
struct flow_key_struct fks;
struct subflow_ioctl_struct sis;
struct flow_raw_struct frs;

extern __u64 total_subflows;
extern __u64 total_packets;
extern __u64 total_bytes;

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
	
	if(ioctl(sock,SIOCSFLOW_KEY,&fks))
	{
		error("ioctl : SIOCSFLOW_KEY",sock);
	}

	if(ioctl(sock,SIOCSSUBFLOW,&sis))
	{
		error("ioctl : SIOCSSUBFLOW",sock);
	}

	if(ioctl(sock,SIOCSFLOW_RAW,&frs))
	{
		error("ioctl : SIOCSFLOW_RAW",sock);
	}

	signal(SIGINT,sigint_handler);
	
	while(1)
	{
		struct subflow *sbf;

		if(ioctl(sock,SIOCGFLOW_RAW,&frs))
		{
			error("ioctl : SIOCGFLOW_RAW",sock);
		}
		
		sbf = &(frs.sbf);
		
		printf("%u.%u.%u.%u  ",HIPQUAD(sbf->src_ip));
		printf("%u.%u.%u.%u  ",HIPQUAD(sbf->dst_ip));
		printf(" %d ",sbf->src_port);
		printf(" %d ",sbf->dst_port);
		printf(" %lld ",sbf->npackets);
		printf(" %lld ",sbf->nbytes);
		printf("\n");

		total_subflows++;
		total_packets += sbf->npackets;
		total_bytes += sbf->nbytes;
	}

	return 0;
}
