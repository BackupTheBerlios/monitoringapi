#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>

#include <linux/mapi/ioctl.h>
#include <mstring.h>
#include <mapihandy.h>
#include <tconfig.h>

int sock;
__u64 counter = 0;
__u32 rbuf_size;

static void terminate()
{
	close(sock);
}

void handler()
{
	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_mapi_statistics || print_packet_statistics");
	}
	
	printf("Total times string found = %lld\n",counter);

	exit(0);
}

void init()
{
	__u32 so_rcvbuf_size;

	if((so_rcvbuf_size = set_rcvbuf_size(sock,SO_RCVBUF_SIZE)) == -1 || 
	   (rbuf_size = get_if_mtu(sock,IFNAME)) ||
	   bind_if_name(sock,IFNAME))
	{
		perror("set_rcvbuf_size || get_if_mtu || bind_if_name");
		exit(1);
	}
	
	printf("Socket recv buffer size = %d\n",so_rcvbuf_size);
	printf("MTU of %s = %d bytes\n",IFNAME,rbuf_size);
}

int main(int argc, char **argv)
{
	char *buffer;
	char *string = STRING_TO_SEARCH;	
	int length = strlen(string);
	__u32 *skip_table;
	__u32 *shift_table;
	
	if((sock = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	skip_table = make_skip(string,length);
	shift_table = make_shift(string,length);
	
	printf("Search string = %s\n",string);
	
	init();
	
	signal(SIGINT,handler);

#ifdef SLEEP
	signal(SIGALRM,handler);
	alarm(SLEEP_TIME);
#endif	
	buffer = alloca(rbuf_size);

	while(1)
	{
		int n;
		
		if((n = recvfrom(sock,buffer,rbuf_size,MSG_TRUNC,NULL,NULL)) < 0)
		{
			perror("recvfrom");

			exit(1);
		}

		if(search_substring(buffer,n,string,length,skip_table,shift_table))
		{
			counter++;
		}
	}

	return 0;
}
