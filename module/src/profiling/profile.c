/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#include <asm/semaphore.h>
#include <asm/processor.h>
#include <linux/errno.h>
#include <linux/init.h>

#include <linux/mapi/prof.h>
#include <linux/mapi/common.h>

struct x86_model_spec const *prof_spec;

void prof_start(struct perf_counter *ctr,struct msrs const * const mrs)
{
	(*(prof_spec->prof_start))(ctr,mrs);
}

void prof_stop(struct perf_counter *ctr,struct msrs const * const mrs)
{
	(*(prof_spec->prof_stop))(ctr,mrs);
}

int prof_setup_ctrs(struct perf_counter *ctr,struct msrs const * const mrs)
{
	return (*(prof_spec->prof_setup_ctrs))(ctr,mrs);
}

int prof_fill_in_addresses(struct msrs * const mrs)
{
	return (*(prof_spec->prof_fill_in_addresses))(mrs);
}

void prof_free_addresses(struct msrs * const mrs)
{
	(*(prof_spec->prof_free_addresses))(mrs);
}

void prof(struct perf_counter *ctr,struct msrs * const mrs,u32 *ctr_count)
{
	(*(prof_spec->prof))(ctr,mrs,ctr_count);
}

int prof_num_counters(void)
{
	return prof_spec->num_counters;
}

int prof_num_controls(void)
{
	return prof_spec->num_controls;
}

EXPORT_SYMBOL(prof_start);
EXPORT_SYMBOL(prof_stop);
EXPORT_SYMBOL(prof_setup_ctrs);
EXPORT_SYMBOL(prof_fill_in_addresses);
EXPORT_SYMBOL(prof_free_addresses);
EXPORT_SYMBOL(prof);
EXPORT_SYMBOL(prof_num_counters);
EXPORT_SYMBOL(prof_num_controls);

PRIVATE int __init prof_init(void)
{
	int cpu;
	
	if((cpu = get_cpu_type()) == CPU_P4)
	{
		prof_spec = &p4_spec;
	}
	else if((cpu = get_cpu_type()) == CPU_ATHLON)
	{
		prof_spec = &athlon_spec;
	}
	else
	{
		printk(KERN_ALERT "Warning : Unsupported CPU type : %s,%i\n",__FILE__,__LINE__);
		
		prof_spec = &dummy_spec;
	}
	
	return 0;
}

PRIVATE void __exit prof_exit(void)
{
}

module_init(prof_init);
module_exit(prof_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");
