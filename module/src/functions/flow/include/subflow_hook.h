/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __SUBFLOW_HOOK_H_
#define __SUBFLOW_HOOK_H_

#include <subflow.h>

struct subflow_hook
{
	void *data;
	
	int (*expired_subflow)(struct subflow *sbf,void *data);
};

static inline int register_subflow_hook(struct subflow_struct *ss,struct subflow_hook *hook)
{
	if(ss->expired_sbf_hook == NULL)
	{
		ss->expired_sbf_hook = hook;
	}
	else
	{
		return -EALREADY;
	}

	return 0;
}

static inline struct subflow_hook *unregister_subflow_hook(struct subflow_struct *ss)
{
	struct subflow_hook *hook;
	
	hook = ss->expired_sbf_hook;
	
	ss->expired_sbf_hook = NULL;

	return hook;
}

#endif /* __SUBFLOW_HOOK_H_ */
