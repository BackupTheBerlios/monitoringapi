/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __DECIDE_HOOK_H_
#define __DECIDE_HOOK_H_

#define DECIDE_LEFT	0
#define DECIDE_RIGHT	1
#define DECIDE_BOTH	2

struct decide_hook
{
	void *data;
	
	int (*skb_hook)(struct sk_buff *skb,void *data);
};

struct decide_hook **get_decide_hook(struct decide_struct *ds);

static inline int register_decide_hook(struct decide_struct *ds,struct decide_hook *hook)
{
	struct decide_hook **old_hook = get_decide_hook(ds);
	
	if(*old_hook == NULL)
	{
		*old_hook = hook;
	}
	else
	{
		return -EALREADY;
	}

	return 0;
}

static inline struct decide_hook *unregister_decide_hook(struct decide_struct *ds)
{
	struct decide_hook **hook = get_decide_hook(ds);
	struct decide_hook *old_hook = *hook;

	*hook = NULL;

	return old_hook;
}

#endif /* __DECIDE_HOOK_H_ */
