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

#include <linux/mapi/ioctl.h>
#include <tconfig.h>

int sock;

void terminate()
{
	close(sock);
}

int main(int argc, char **argv)
{
	struct substring_search_struct ss;
	struct substring_search_struct ss2;

	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	ss.string = (char *)malloc(100*sizeof(char));
	sprintf(ss.string,"ls");
	ss.length = strlen(ss.string);

	if(ioctl(sock,SIOCSSUBSTRING_SEARCH,&ss) == -1)
	{
		perror("ioctl");
		exit(1);
	}

	ss2.string = (char *)malloc(100*sizeof(char));
	sprintf(ss2.string,"clear");
	ss2.length = strlen(ss2.string);
	
	if(ioctl(sock,SIOCSSUBSTRING_SEARCH,&ss2) == -1)
	{
		perror("ioctl");
		exit(1);
	}
	
	sleep(60);

	return 0;
}

