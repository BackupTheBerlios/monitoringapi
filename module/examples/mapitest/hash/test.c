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
	char buffer[RBUF_SIZE];
	struct hash_struct hs;

	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	
	hs.mode = HASH_ADDITIVE;
	hs.prime = 10;
	hs.low = 1;
	hs.high = 3;

	if(ioctl(sock,SIOCSHASH,&hs) == -1)
	{
		perror("ioctl");
		exit(1);
	}

	while(1)
	{
		int n;
		
		if((n = recvfrom(sock,buffer,RBUF_SIZE,MSG_TRUNC,NULL,NULL)) < 0)
		{
			perror("recvfrom");

			exit(1);
		}

		printf("%d bytes read\n",n);
	}

	return 0;
}

