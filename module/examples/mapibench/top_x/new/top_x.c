#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <linux/if_ether.h>
#include <net/bpf.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <sys/time.h>
#include <math.h>
#include <string.h>

#include <linux/mapi/ioctl.h>
#include <mapihandy.h>
#include <tconfig.h>
#include <subflow.h>
#include <top_x.h>

struct subflow *top_x_table;
__u32 top_x;

struct decide_struct top_ds;
struct decide_struct *leaf_ds;
__u32 leaf_ds_nr;
struct substring_search_struct *ss;
struct count_packets_struct *cps;

__u32 nlevels;
int sock;

static void terminate()
{
	close(sock);
}

static struct substring_search_struct *get_substring_search(struct decide_struct *parent_ds,__u16 node,__u8 direction)
{
	struct substring_search_struct *this_ss = &ss[node];
	
	parent_ds->ioctl.cmd = SIOCGSUBSTRING_SEARCH;
	parent_ds->ioctl.arg = this_ss;
	parent_ds->ioctl.direction = direction;
	
	do_ioctl(sock,SIOCIODECIDE,parent_ds,"SIOCIODECIDE : SIOCGSUBSTRING_SEARCH");

	return this_ss;
}

static struct count_packets_struct *get_count_packets(struct decide_struct *parent_ds,__u16 node,__u8 direction)
{
	struct count_packets_struct *this_cps = &cps[node];
	
	parent_ds->ioctl.cmd = SIOCGCOUNT_PACKETS;
	parent_ds->ioctl.arg = this_cps;
	parent_ds->ioctl.direction = direction;
	
	do_ioctl(sock,SIOCIODECIDE,parent_ds,"SIOCIODECIDE : SIOCGCOUNT_PACKETS");

	return this_cps;
}

static void handler()
{
	int i;
	
	if(print_mapi_statistics(sock))
	{
		perror("print_mapi_statistics");
	}

	for( i = 0 ; i < leaf_ds_nr ; i++)
	{
		__u32 node = 2*i;
		struct substring_search_struct *left_ss = get_substring_search(&leaf_ds[i],node,DIRECTION_LEFT);
		struct substring_search_struct *right_ss = get_substring_search(&leaf_ds[i],node + 1,DIRECTION_RIGHT);
		struct count_packets_struct *left_cps = get_count_packets(&leaf_ds[i],node,DIRECTION_LEFT);
		struct count_packets_struct *right_cps = get_count_packets(&leaf_ds[i],node + 1,DIRECTION_RIGHT);

		printf("Port : %-6u , Total packets  : %-10llu\n",top_x_table[node].src_port,left_cps->counter);
		printf("Port : %-6u , Strings found  : %-10llu\n",top_x_table[node].src_port,left_ss->counter);
		printf("Port : %-6u , Total packets  : %-10llu\n",top_x_table[node + 1].src_port,right_cps->counter);
		printf("Port : %-6u , Strings found  : %-10llu\n",top_x_table[node + 1].src_port,right_ss->counter);
	}
	
	exit(0);
}

static void add_count_packets(struct decide_struct *parent_ds,__u16 node,__u8 direction)
{
	struct count_packets_struct *this_cps = &cps[node];
	
	parent_ds->ioctl.cmd = SIOCSCOUNT_PACKETS;
	parent_ds->ioctl.arg = this_cps;
	parent_ds->ioctl.direction = direction;
	
	do_ioctl(sock,SIOCIODECIDE,parent_ds,"SIOCIODECIDE : SIOCSCOUNT_PACKETS");
}

static void add_substring_search(struct decide_struct *parent_ds,__u16 node,__u8 direction)
{
	struct substring_search_struct *this_ss = &ss[node];
	
	if((this_ss->string = malloc((strlen(STRING_TO_SEARCH)+1)*sizeof(char))) == NULL)
	{
		fprintf(stderr,"Could not allocate memory\n");
		exit(1);
	}
	
	sprintf(this_ss->string,STRING_TO_SEARCH);
	this_ss->length = strlen(this_ss->string);
	
	parent_ds->ioctl.cmd = SIOCSSUBSTRING_SEARCH;
	parent_ds->ioctl.arg = this_ss;
	parent_ds->ioctl.direction = direction;
	
	do_ioctl(sock,SIOCIODECIDE,parent_ds,"SIOCIODECIDE : SIOCSSUBSTRING_SEARCH");
}

static void leaf_ds_config(struct decide_struct *parent_ds,__u16 node)
{
	char condition[MAX_FILTER_LEN];
	struct subflow *sbf = &top_x_table[node];
	
	memcpy(&leaf_ds[node/2],parent_ds,sizeof(struct decide_struct));
	
	sbf = &top_x_table[node];
	sprintf(condition,"src host %u.%u.%u.%u and dst host %u.%u.%u.%u and src port %u and dst port %u",
		HIPQUAD(sbf->src_ip),HIPQUAD(sbf->dst_ip),sbf->src_port,sbf->dst_port);

	add_count_packets(parent_ds,node,DIRECTION_LEFT);
	apply_bpf_filter(sock,parent_ds,condition,DIRECTION_LEFT);
	add_substring_search(parent_ds,node,DIRECTION_LEFT);
	
	sbf = &top_x_table[node + 1];
	sprintf(condition,"src host %u.%u.%u.%u and dst host %u.%u.%u.%u and src port %u and dst port %u",
		HIPQUAD(sbf->src_ip),HIPQUAD(sbf->dst_ip),sbf->src_port,sbf->dst_port);

	add_count_packets(parent_ds,node + 1,DIRECTION_RIGHT);
	apply_bpf_filter(sock,parent_ds,condition,DIRECTION_RIGHT);
	add_substring_search(parent_ds,node + 1,DIRECTION_RIGHT);
}

static void sio_decide_left(struct decide_struct *parent_ds,struct decide_struct *left_ds,__u16 level,__u16 node)
{
	char condition[MAX_FILTER_LEN];
	struct subflow *sbf = &top_x_table[node];
	
	sprintf(left_ds->debug_info,"L : %u, N : %u ( src port %u )",level,node,sbf->src_port);
	parent_ds->ioctl.cmd = SIOCSDECIDE;
	parent_ds->ioctl.arg = left_ds;
	parent_ds->ioctl.direction = DIRECTION_LEFT;
	
	do_ioctl(sock,SIOCIODECIDE,parent_ds,"SIOCIODECIDE : SIOCSDECIDE");
	sprintf(condition,"tcp[0:2] <= %u or udp[0:2] <= %u",sbf->src_port,sbf->src_port);
	apply_bpf_hook(sock,parent_ds,condition,DIRECTION_LEFT);
}

static void sio_decide_right(struct decide_struct *parent_ds,struct decide_struct *right_ds,__u16 level,__u16 node)
{
	char condition[MAX_FILTER_LEN];
	struct subflow *sbf = &top_x_table[node];

	sprintf(right_ds->debug_info,"L : %u, N : %u ( src port %u )",level,node,sbf->src_port);
	parent_ds->ioctl.cmd = SIOCSDECIDE;
	parent_ds->ioctl.arg = right_ds;
	parent_ds->ioctl.direction = DIRECTION_RIGHT;
	
	do_ioctl(sock,SIOCIODECIDE,parent_ds,"SIOCIODECIDE : SIOCSDECIDE");
	sprintf(condition,"tcp[0:2] <= %u or udp[0:2] <= %u",sbf->src_port,sbf->src_port);
	apply_bpf_hook(sock,parent_ds,condition,DIRECTION_RIGHT);
}

static void construct_8()
{
	char condition[MAX_FILTER_LEN];
	struct decide_struct parent_ds;
	struct decide_struct left_ds;
	struct decide_struct right_ds;
	struct decide_struct tmp_ds;

/*
 * Level 0
 */
	sprintf(parent_ds.debug_info,"L : %u, N : %u",0,3);
	do_ioctl(sock,SIOCSDECIDE,&parent_ds,"SIOCSDECIDE");
	sprintf(condition,"tcp[0:2] <= %u or udp[0:2] <= %u",top_x_table[3].src_port,top_x_table[3].src_port);
	apply_bpf_hook(sock,NULL,condition,0);
	
	top_ds = parent_ds;
	
/*
 * Level 1
 */
	sio_decide_left(&parent_ds,&left_ds,1,1);
	sio_decide_right(&parent_ds,&right_ds,1,5);
	
/*
 * Level 2
 */
	memcpy(&parent_ds,&left_ds,sizeof(parent_ds));
	memcpy(&tmp_ds,&right_ds,sizeof(tmp_ds));
	
	sio_decide_left(&parent_ds,&left_ds,2,0);
	leaf_ds_config(&left_ds,0);
	sio_decide_right(&parent_ds,&right_ds,2,2);
	leaf_ds_config(&right_ds,2);

	memcpy(&parent_ds,&tmp_ds,sizeof(parent_ds));
	
	sio_decide_left(&parent_ds,&left_ds,2,4);
	leaf_ds_config(&left_ds,4);
	sio_decide_right(&parent_ds,&right_ds,2,6);
	leaf_ds_config(&right_ds,6);
}

static void construct_bin_tree()
{
	__u32 ds_nr = 0;
	int i;
	
	nlevels = (__u32)(log(top_x)/log(2) + 0.000000000001);
	
	for(i = 0 ; i < nlevels ; i++)
	{
		ds_nr += (__u32)pow(2,i);
	}
	
	printf("Height : %u\n",nlevels);
	printf("Decisions : %u\n",ds_nr);
	
	if((ss = malloc(top_x*sizeof(struct substring_search_struct))) == NULL)
	{
		fprintf(stderr,"Could not allocate memory\n");
		exit(1);
	}
	
	if((cps = malloc(top_x*sizeof(struct count_packets_struct))) == NULL)
	{
		fprintf(stderr,"Could not allocate memory\n");
		exit(1);
	}
	
	leaf_ds_nr = (__u32)pow(2,nlevels - 1);
	
	if((leaf_ds = malloc(leaf_ds_nr*sizeof(struct decide_struct))) == NULL)
	{
		fprintf(stderr,"Could not allocate memory\n");
		exit(1);
	}
	
	construct_8();
	
	do_ioctl(sock,SIOCDBDECIDE,&top_ds,"SIOCDBDECIDE");
}

int main(int argc, char **argv)
{
	if(argc != 2)
	{
		fprintf(stderr,"Usage : %s power_of_2\n",argv[0]);
		exit(1);
	}
	
	top_x = atoi(argv[1]);
	top_x -= top_x%2;

	printf("Top_x : %u\n",top_x);

	printf("Press enter to start");
	getchar();
	
	top_x_table = get_top_x(top_x);
	top_x_table = sort_subflows(top_x_table,top_x);
	
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	atexit(terminate);
	signal(SIGINT,handler);
	
	if(bind_if_name(sock,IFNAME))
	{
		perror("bind_if_name");
		exit(1);
	}
	
	construct_bin_tree();
	
	pause();

	return 0;
}
