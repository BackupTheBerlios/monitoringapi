#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <sys/ioctl.h>
#include <string.h>

#include <linux/mapi/ioctl.h>
#include <tconfig.h>
#include <subflow.h>
#include <top_x.h>

static struct subflow *find_min_subflow_port(struct subflow *sbf_table,__u32 sbf_table_size)
{
	__u16 min_port = 65535;
	__u32 index = 0; 
	int i;

	for( i = 0 ; i < sbf_table_size ; i++)
	{
		struct subflow *sbf = &sbf_table[i];
		
		if(sbf->src_port < min_port)
		{
			min_port = sbf->src_port;
			
			index = i;
		}
	}
	
	return &sbf_table[index];
}

struct subflow *sort_subflows(struct subflow *top_x_table,__u32 top_x_size)
{
	struct subflow *sorted_top_x_table;
	struct subflow *sbf;
	int i;
	
	if((sorted_top_x_table = malloc(top_x_size*sizeof(struct subflow))) == NULL)
	{
		fprintf(stderr,"Could not allocate memory\n");

		exit(1);
	}
	
	for( i = 0 ; i < top_x_size ; i++)
	{
		sbf = find_min_subflow_port(top_x_table,top_x_size);

		sorted_top_x_table[i] = *sbf;
		
		sbf->src_port = 65535;
	}
	
	print_subflow_table(sorted_top_x_table,top_x_size);

	free(top_x_table);
	
	return sorted_top_x_table;
}
