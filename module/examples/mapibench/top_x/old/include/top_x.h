#ifndef __TOP_X_H_
#define __TOP_X_H_

#include <errno.h>

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
