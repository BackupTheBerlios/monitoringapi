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
#include <signal.h>
#include <linux/if_packet.h>
#include <stdlib.h>

#include <linux/mapi/ioctl.h>
#include <tconfig.h>
#include <mapihandy.h>

int sock;
struct count_packets_struct cps;
struct count_bytes_struct cbs;
struct sample_packets_struct sps;
struct hash_struct hs;
struct substring_search_struct ss;
struct logging_struct ls;

void terminate()
{
	close(sock);
}

void handler()
{
	if(ioctl(sock,SIOCGCOUNT_PACKETS,&cps) == -1)
	{
		perror("ioctl");	
	}

	if(ioctl(sock,SIOCGCOUNT_BYTES,&cbs) == -1)
	{
		perror("ioctl");	
	}
	
	if(ioctl(sock,SIOCGSUBSTRING_SEARCH,&ss) == -1)
	{
		perror("ioctl");	
	}
	
	if(ioctl(sock,SIOCGLOGGING,&ls) == -1)
	{
		perror("ioctl");	
	}

	if(print_mapi_statistics(sock) || print_packet_statistics(sock))
	{
		perror("print_mapi_statistics || print_packet_statistics");
	}
	
	printf("Total packets = %lld\n",cps.counter);
	printf("Total bytes = %lld\n",cbs.counter);
	printf("Total Mbytes = %f\n",cbs.counter/(float)1000000);
	printf("Total times string found = %lld\n",ss.counter);
	printf("Packets logged = %d\n",ls.packets_logged);

	exit(0);
}

void init_count_packets()
{
	if(ioctl(sock,SIOCSCOUNT_PACKETS,&cps) == -1)
	{
		perror("ioctl");	
	}
}

void init_count_bytes()
{
	if(ioctl(sock,SIOCSCOUNT_BYTES,&cbs) == -1)
	{
		perror("ioctl");	
	}
}

void init_sample_packets()
{
	sps.mode = MODE;
	sps.period = PERIOD;

	if(ioctl(sock,SIOCSSAMPLE_PACKETS,&sps) == -1)
	{
		perror("ioctl");	
	}
}

void init_hash()
{
	hs.mode = HASH_ADDITIVE;
	hs.prime = 10;
	hs.low = 1;
	hs.high = 3;

	if(ioctl(sock,SIOCSHASH,&hs) == -1)
	{
		perror("ioctl");	
	}
}

void init_substring_search()
{
	ss.string = (char *)malloc((strlen(STRING_TO_SEARCH)+1)*sizeof(char));
	sprintf(ss.string,STRING_TO_SEARCH);
	ss.length = strlen(ss.string);

	if(ioctl(sock,SIOCSSUBSTRING_SEARCH,&ss) == -1)
	{
		perror("ioctl");	
	}
	
	printf("Search string = %s\n",ss.string);
}

void init_logging()
{
	ls.filename = (char *)malloc((strlen(FILENAME)+1)*sizeof(char));
	sprintf(ls.filename,FILENAME);
	ls.length = strlen(ls.filename);

	if(ioctl(sock,SIOCSLOGGING,&ls) == -1)
	{
		perror("ioctl");	
	}
	
	printf("Filename = %s\n",ls.filename);
}

int main(int argc, char **argv)
{
	char *buffer;
	__u32 so_rcvbuf_size;
	__u32 rbuf_size;
	
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_IP))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);	
	
	if((so_rcvbuf_size = set_rcvbuf_size(sock,SO_RCVBUF_SIZE)) == -1 || 
	   bind_if_name(sock,IFNAME) ||
	   (rbuf_size = get_if_mtu(sock,IFNAME)) == -1)
	{
		perror("set_rcvbuf_size || bind_if_name || get_if_mtu");
		exit(1);
	}
	
	printf("Socket recv buffer size = %d\n",so_rcvbuf_size);
	printf("Socket bound to interface %s\n",IFNAME);
	printf("MTU of %s = %d bytes\n",IFNAME,rbuf_size);

	init_sample_packets();
	init_count_packets();
	init_count_bytes();
	init_hash();	
	init_substring_search();
	init_logging();

	signal(SIGINT,handler);

	buffer = alloca(rbuf_size);

	while(1)
	{
		int n;
		if((n = recvfrom(sock,buffer,rbuf_size,MSG_TRUNC,NULL,NULL)) < 0)
		{
			perror("recvfrom");

			exit(1);
		}

		printf("%d bytes read\n",n);
	}
}
