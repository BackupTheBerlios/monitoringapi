#include <stdio.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include <string.h>

#include <linux/mapi/ioctl.h>
#include <tconfig.h>
#include <subflow.h>
#include <mapihandy.h>

void error(char *msg,int sock)
{
	perror(msg);
	exit(1);
}

extern int sock;
extern struct subflow_ioctl_struct sis;
extern struct flow_raw_struct frs;

__u64 total_subflows = 0;
__u64 total_packets = 0;
__u64 total_bytes = 0;

int expire_all = 0;

void sigint_handler()
{
	if(expire_all == 0)
	{
		if(ioctl(sock,SIOCEXPIREALL,&sis))
		{
			error("ioctl",sock);
		}
		
		expire_all = 1;
		
		printf("All subflows expired successfully\n");
		printf("Press CTRL-C to exit\n");
		
		return;
	}
	
	if(print_packet_statistics(sock))
	{
		perror("print_packet_statistics");
	}
	
	if(print_mapi_statistics(sock))
	{
		perror("print_mapi_statistics");
	}
	
	printf("Stats : Total subflows   = %llu\n",total_subflows);
	printf("Stats : Total packets    = %llu\n",total_packets);
	printf("Stats : Total bytes      = %llu\n",total_bytes);

	exit(0);
}

