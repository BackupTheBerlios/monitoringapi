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
#include <stdlib.h>

#include <linux/mapi/ioctl.h>
#include <tconfig.h>
#include <mapihandy.h>

int sock;
struct substring_search_struct ss;

void terminate()
{
	close(sock);
}

void handler()
{
	if(ioctl(sock,SIOCGSUBSTRING_SEARCH,&ss) == -1)
	{
		perror("ioctl");
		exit(1);
	}
	
	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_mapi_statistics || print_packet_statistics");
	}
	
	printf("Total times string found = %lld\n",ss.counter);

	exit(0);
}

int main(int argc, char **argv)
{
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	ss.string = (char *)malloc((strlen(STRING_TO_SEARCH)+1)*sizeof(char));
	sprintf(ss.string,STRING_TO_SEARCH);
	ss.length = strlen(ss.string);
	
	printf("String length = %d\n",ss.length);
	
	if(ioctl(sock,SIOCSSUBSTRING_SEARCH,&ss) == -1)
	{
		perror("ioctl");
		exit(1);
	}
	
	printf("Search string = %s\n",ss.string);
	
	signal(SIGINT,handler);

#ifdef SLEEP
	signal(SIGALRM,handler);
	alarm(SLEEP_TIME);
#endif	

	pause();

	return 0;
}
