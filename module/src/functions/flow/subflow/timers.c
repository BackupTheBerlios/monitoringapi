/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/list.h>
#include <linux/time.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include <linux/mapi/ioctl.h>
#include <linux/mapi/timeval.h>

#include <flow_key.h>
#include <subflow_hook.h>
#include <subflow.h>

PRIVATE u32 timeout_check_period = 1;
PRIVATE u32 duration_check_period = 1;

PUBLIC void check_timeouts(unsigned long data)
{
	struct subflow_struct *ss;
	struct list_head *list_cur;
	struct timeval tv;
	
	ss = (struct subflow_struct *)data;
	
	tv_stamp(&tv);
	
	read_lock(&(ss->subflow_list_lock));
	
	list_for_each(list_cur,ss->subflow_list)
	{
		struct subflow *sbf = subflow_list_entry(list_cur);
		struct subflow_private_struct *cb = subflow_cb(sbf);
		
		if(cb->expired == 0 && ((tv.tv_sec - sbf->end_time.tv_sec) >= ss->timeout))
		{
			/* spinlock not necessary because if expired == 1 cannot
			 * become 0.
			 * */
			cb->expired = 1;
		}
		else if(cb->expired == 0 && ((tv.tv_sec - sbf->end_time.tv_sec) < ss->timeout))
		{
			break;
		}
		else if(cb->expired == 1)
		{
		}
	}
	
	read_unlock(&(ss->subflow_list_lock));

	if(ss->stop_timers == 0)
	{
		init_timer(&(ss->timeout_timer));
		
		ss->timeout_timer.function = check_timeouts;
		ss->timeout_timer.data = (unsigned long)ss;
		ss->timeout_timer.expires = jiffies + timeout_check_period;

		add_timer(&(ss->timeout_timer));
	}
}

PUBLIC void check_durations(unsigned long data)
{
	struct subflow_struct *ss;
	struct list_head *list_cur;
	struct timeval tv;
	
	ss = (struct subflow_struct *)data;
	
	tv_stamp(&tv);
	
	read_lock(&(ss->subflow_list_lock));
	
	list_for_each(list_cur,ss->subflow_list)
	{
		struct subflow *sbf = subflow_list_entry(list_cur);
		struct subflow_private_struct *cb = subflow_cb(sbf);
		
		if(cb->expired == 0 && ((tv.tv_sec - sbf->start_time.tv_sec) >= ss->max_duration))
		{
			cb->expired = 1;
		}
		else if(cb->expired == 1)
		{
		}
	}
	
	read_unlock(&(ss->subflow_list_lock));

	if(ss->stop_timers == 0)
	{
		init_timer(&(ss->duration_timer));
		
		ss->duration_timer.function = check_durations;
		ss->duration_timer.data = (unsigned long)ss;
		ss->duration_timer.expires = jiffies + duration_check_period;
		
		add_timer(&(ss->duration_timer));
	}
}

PUBLIC void run_expired_subflow_hook(unsigned long data)
{
	struct subflow_struct *ss = (struct subflow_struct *)data;
	
	if(likely(ss->expired_sbf_hook != NULL))
	{
		struct subflow *expired_sbf;

		while((expired_sbf = find_expired_subflow(ss)) != NULL)
		{
			(*(ss->expired_sbf_hook->expired_subflow))(expired_sbf,ss->expired_sbf_hook->data);
		}
	}
	
	if(ss->stop_timers == 0)
	{
		init_timer(&(ss->subflow_hook_timer));
		
		ss->subflow_hook_timer.function = run_expired_subflow_hook;
		ss->subflow_hook_timer.data = (unsigned long)ss;
		ss->subflow_hook_timer.expires = jiffies + 1;

		add_timer(&(ss->subflow_hook_timer));
	}
}

#if V_BEFORE(2,5,0)
MODULE_PARM(timeout_check_period,"i");
MODULE_PARM(duration_check_period,"i");
#else
#include <linux/moduleparam.h>
module_param(timeout_check_period,uint,0);
module_param(duration_check_period,uint,0);
#endif

MODULE_PARM_DESC(timeout_check_period,"The period (jiffies) to check for expired subflows (default = 1 jiffy)");
MODULE_PARM_DESC(duration_check_period,"The period (jiffies) to check for subflows which exist for too long (default = 1 jiffy)");
