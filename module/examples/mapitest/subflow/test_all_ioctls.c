#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <linux/mapi/ioctl.h>
#include <tconfig.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

//#define ALL_IOCTLS

#ifdef ALL_IOCTLS

char *ioctl_names[] = {	"SIOCSSUBFLOW",
			"SIOCGSUBFLOW",
			"SIOCRSSUBFLOW",
			"SIOCRMSUBFLOW",
		     };

int ioctl_calls[] = {	SIOCSSUBFLOW,
			SIOCGSUBFLOW,
			SIOCRSSUBFLOW,
			SIOCRMSUBFLOW,
		     };
#else

char *ioctl_names[] = {	"SIOCSSUBFLOW",
			"SIOCRMSUBFLOW",
		     };

int ioctl_calls[] = {	SIOCSSUBFLOW,
			SIOCRMSUBFLOW,
		     };
#endif /* ALL_IOCTLS */

#define IOCTLS_NR ARRAY_SIZE(ioctl_calls)

__u64 *stats;

typedef struct subflow_ioctl_struct function_struct;

function_struct fs;

void function_init()
{
	fs.timeout = TIMEOUT;
	fs.max_duration = MAX_DURATION;
}

int sock;

void sigint_handler()
{
	int i;

	for( i = 0 ; i < IOCTLS_NR ; i++)
	{
		printf("Total times %s called = %lld\n",ioctl_names[i],stats[i]);
	}
	
	close(sock);
	exit(0);
}

int main(int argc, char **argv)
{
	if((stats = (__u64 *)calloc(IOCTLS_NR,sizeof(__u64))) == NULL)
	{
		fprintf(stderr,"No more memory\n");
		exit(1);
	}
	
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	function_init();
	
	signal(SIGINT,sigint_handler);

	while(1)
	{
		long int rand = random();
		
		rand = rand >> 5;
		rand %= IOCTLS_NR;
		
		stats[rand]++;

		if(ioctl(sock,ioctl_calls[rand],&fs) == -1)
		{
			perror("ioctl");
			
			continue;
		}

		printf("%s succeeded\n",ioctl_names[rand]);
	}
	
	close(sock);
}
