/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPIFILTER_H
#define __MAPIFILTER_H

#include <sys/types.h>
#include <net/bpf.h>

struct mapi_filter
{
	char *expression;
	u_int exp_len;
	
	struct
	{
		u_int bf_len;
		
		struct bpf_insn *bf_insns;

	} bpf_filter;
};

struct mapi_filter *mapi_create_filter(char *expression,int arptype,u_int32_t netmask);
void mapi_free_filter(struct mapi_filter *filter);
int mapi_apply_filter(int fd,struct mapi_filter *filter);

#endif /* __MAPIFILTER_H */
