#ifndef __SUBFLOW_H_
#define __SUBFLOW_H_

#define HIPQUAD(addr) \
((unsigned char *)&addr)[3], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[0]

struct subflow *get_top_x(int top_size);

static inline void print_subflow_table(struct subflow *sbf_table,__u32 sbf_table_size)
{
	int i;

	for( i = 0 ; i < sbf_table_size ; i++)
	{
		struct subflow *sbf = &sbf_table[i];
	
		printf("%-4d : ",i);
		printf("%-3u.%-3u.%-3u.%-3u  ",HIPQUAD(sbf->src_ip));
		printf("%-3u.%-3u.%-3u.%-3u  ",HIPQUAD(sbf->dst_ip));
		printf(" %-5d ",sbf->src_port);
		printf(" %-5d ",sbf->dst_port);
		printf(" %-10lld ",sbf->npackets);
		printf(" %-10lld ",sbf->nbytes);
		printf("\n");
	}
}

#endif /* __SUBFLOW_H_ */
