#ifndef __TOP_X_H_
#define __TOP_X_H_

#include <errno.h>

void apply_bpf_hook(int sock,struct decide_struct *ds,char *condition,__u8 direction);
void apply_bpf_filter(int sock,struct decide_struct *ds,char *condition,__u8 direction);
struct subflow *sort_subflows(struct subflow *top_x_table,__u32 top_x_size);

static inline void do_ioctl(int sock,int cmd,void *arg,char *msg)
{
	int ret;
	
	if((ret = ioctl(sock,cmd,arg)) != 0)
	{
		fprintf(stderr,"ioctl : %s : %s\n",msg,strerror(errno));
		//exit(1);
	}
}

#endif
