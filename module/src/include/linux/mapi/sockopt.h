/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_SOCKOPT_H
#define __MAPI_SOCKOPT_H

#include <linux/config.h>

#define MAX_MAPI_STATISTICS 8

struct mapi_stats
{
	struct ll_pkttype
	{
		__u32 p_recv;
		__u32 p_processed;
		__u32 p_queued;
		__u32 p_dropped;
		__u32 p_dropped_by_filter;

	} pkttype[MAX_MAPI_STATISTICS];
};

#define MAPI_STATISTICS	9

#ifdef __KERNEL__

int mapi_getsockopt(struct socket *sock,int level,int optname,char *optval,int *optlen);

#endif /* __KERNEL__ */

#endif /* __MAPI_SOCKOPT_H */
