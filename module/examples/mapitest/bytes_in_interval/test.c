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
#include <time.h>
#include <stdlib.h>

#include <linux/mapi/ioctl.h>

#include <tconfig.h>
#include <mapihandy.h>

int sock;
struct bytes_in_interval_struct pin;

static void terminate()
{
	if(set_all_promisc_off(sock) == -1)
	{
		perror("set_all_promisc_off");
	}

	close(sock);
}

void handler()
{
	char *start_time;
	
	if(ioctl(sock,SIOCGBYTES_IN_INTERVAL,&pin) == -1)
	{
		perror("ioctl");
		exit(1);
	}
	
	start_time = ctime((time_t *)&pin.start_time.tv_sec);
	start_time[strlen(start_time) - 1] = '\0';
	
	printf("Total bytes = %lld\n",pin.counter);
	printf("Start time = %s and %lld usecs\n",start_time,(__u64)pin.start_time.tv_usec);
	
	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_mapi_statistics || print_packet_statistics");
	}
	
	exit(0);
}

int main(int argc, char **argv)
{
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	if(set_all_promisc_on(sock) == -1)
	{
		perror("set_all_promisc_on");
	}
	
	atexit(terminate);
	
	pin.time_interval = TIME_INTERVAL;
	pin.pid = getpid();

	if(ioctl(sock,SIOCSBYTES_IN_INTERVAL,&pin))
	{
		perror("ioctl");
		exit(1);
	}
	
	signal(SIGINT,handler);

#ifdef SLEEP
	signal(SIGALRM,handler);
	alarm(SLEEP_TIME);
#endif	
	pause();

	return 0;
}

