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
#include <stdlib.h>

#include <linux/mapi/ioctl.h>
#include <tconfig.h>
#include <subflow.h>

static void init_flow_key_struct(struct flow_key_struct *fks)
{
	memset(fks,0,sizeof(*fks));

	fks->src_ip = 1;
	fks->dst_ip = 1;
	fks->src_port = 1;
	fks->dst_port = 1;
	fks->ip_proto = 1;
}

static void init_ioctl_struct(struct subflow_ioctl_struct *sis)
{
	sis->timeout = TIMEOUT;
	sis->max_duration = MAX_DURATION;
}

static void do_set_ioctls(int sock,struct flow_key_struct *fks,struct subflow_ioctl_struct *sis,struct flow_raw_struct *frs)
{
	if(ioctl(sock,SIOCSFLOW_KEY,fks))
	{
		perror("ioctl : SIOCSFLOW_KEY");
		exit(1);
	}
	
	if(ioctl(sock,SIOCSSUBFLOW,sis))
	{
		perror("ioctl : SIOCSSUBFLOW");
		exit(1);
	}

	if(ioctl(sock,SIOCSFLOW_RAW,frs))
	{
		perror("ioctl : SIOCSFLOW_RAW");
		exit(1);
	}
}

static int init_mapi_socket(struct flow_key_struct *fks,struct subflow_ioctl_struct *sis,struct flow_raw_struct *frs)
{
	int sock;
		
	if((sock = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		return sock;
	}
	
	init_flow_key_struct(fks);
	init_ioctl_struct(sis);
	do_set_ioctls(sock,fks,sis,frs);
	
	return sock;
}

static __u32 get_expired_number(int sock,struct subflow_ioctl_struct *sis,struct flow_raw_struct *frs)
{
	if(ioctl(sock,SIOCEXPIREALL,sis))
	{
		perror("ioctl : SIOCEXPIREALL");
		exit(1);
	}	

	sleep(1);

	if(ioctl(sock,SIOCGNFLOW_RAW,frs))
	{
		perror("ioctl : SIOCGNFLOW_RAW");
		exit(1);
	}
	
	printf("Expired subflows found : %u\n",frs->expired_nr);

	return frs->expired_nr;
}

static struct subflow *read_all_expired_subflows(int sock,struct flow_raw_struct *frs,int expired_nr)
{
	struct subflow *sbf_table;
	int i;
	
	if((sbf_table = malloc(expired_nr*sizeof(struct subflow))) == NULL)
	{
		fprintf(stderr,"Could not allocate memory\n");

		exit(1);
	}
	
	for( i = 0 ; i < expired_nr ; i++)
	{
		if(ioctl(sock,SIOCGFLOW_RAW,frs))
		{
			perror("ioctl : SIOCGFLOW_RAW");
			exit(1);
		}
		
		memcpy(&sbf_table[i],&(frs->sbf),sizeof(frs->sbf));
	}
	
	//print_subflow_table(sbf_table,expired_nr);

	return sbf_table;
}

static struct subflow *find_max_subflow(struct subflow *sbf_table,__u32 sbf_table_size)
{
	__u32 max_bytes = 0;
	__u32 index = 0; 
	int i;

	for( i = 0 ; i < sbf_table_size ; i++)
	{
		struct subflow *sbf = &sbf_table[i];
		
		if(sbf->nbytes > max_bytes)
		{
			max_bytes = sbf->nbytes;

			index = i;
		}
	}
	
	return &sbf_table[index];
}

static int sbf_table_contains(struct subflow *sbf_table,__u32 sbf_table_size,__u16 src_port)
{
	struct subflow *sbf;
	int i;
	
	for( i = 0 ; i < sbf_table_size ; i++)
	{
		sbf = &sbf_table[i];

		if(sbf->src_port == src_port)
		{
			return i;
		}
	}

	return -1;
}

static struct subflow *find_top_x(struct subflow *sbf_table,__u32 sbf_table_size,__u32 top_x)
{
	struct subflow *top_x_table;
	struct subflow *max_subflow;
	int i;
	
	if((top_x_table = malloc(top_x*sizeof(struct subflow))) == NULL)
	{
		fprintf(stderr,"Could not allocate memory\n");

		exit(1);
	}
	
	for( i = 0 ; i < top_x ; i++)
	{
		max_subflow = find_max_subflow(sbf_table,sbf_table_size);

		if(sbf_table_contains(top_x_table,top_x,max_subflow->src_port) >= 0)
		{
			max_subflow->nbytes = 0;
			i--;

			continue;
		}
		
		top_x_table[i] = *max_subflow;
		
		max_subflow->nbytes = 0;
	}
	
	return top_x_table;
}

static void psleep(int sec)
{
	int i;
	
	for(i = 0 ; i < sec ; i++)
	{
		printf("\rSleeping %d secs",i);
		fflush(stdout);

		sleep(1);
	}
	
	printf("\n");
}

struct subflow *get_top_x(int top_size)
{
	struct flow_key_struct fks;
	struct subflow_ioctl_struct sis;
	struct flow_raw_struct frs;
	struct subflow *sbf_table;
	struct subflow *top_table;
	__u32 expired_nr;
	int sock;
	
	if((sock = init_mapi_socket(&fks,&sis,&frs)) < 0)
	{
		perror("socket");
		exit(1);
	}
	
	psleep(SLEEP_TIME);

	expired_nr = get_expired_number(sock,&sis,&frs);
	
	if(expired_nr < top_size)
	{
		fprintf(stderr,"Not enough expired subflows found!\n");

		exit(1);
	}
	
	sbf_table = read_all_expired_subflows(sock,&frs,expired_nr);
	
	top_table = find_top_x(sbf_table,expired_nr,top_size);

	free(sbf_table);
	close(sock);

	return top_table;
}

