/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		stolen from oprofile
 * 
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>

#ifdef CONFIG_X86

#include <linux/kernel.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#include <asm/semaphore.h>
#include <asm/processor.h>

#include <linux/mapi/prof.h>

#include <perfmsr.h>
#include <perfathlon.h>

void athlon_start(struct perf_counter *ctr,struct msrs const * const mrs)
{
	uint low, high;
	int i;
	
	for(i = 0 ; i < NUM_COUNTERS ; ++i) 
	{
		if(ctr[i].count) 
		{
			CTRL_READ(low, high, mrs, i);
			CTRL_SET_ACTIVE(low);
			CTRL_WRITE(low, high, mrs, i);
		}
	}
}

void athlon_stop(struct perf_counter *ctr,struct msrs const * const mrs)
{
	uint low,high;
	int i;

	for(i = 0 ; i < NUM_COUNTERS ; ++i) 
	{
		if(ctr[i].count)
		{
			CTRL_READ(low, high, mrs, i);
			CTRL_SET_INACTIVE(low);
			CTRL_WRITE(low, high, mrs, i);
		}
	}
}

int athlon_setup_ctrs(struct perf_counter *ctr,struct msrs const * const mrs)
{
	uint low, high;
	int i;

	/* clear all counters */
	for(i = 0 ; i < NUM_CONTROLS ; ++i) 
	{
		CTRL_READ(low, high, mrs, i);
		CTRL_CLEAR(low);
		CTRL_WRITE(low, high, mrs, i);
	}
	
	/* avoid a false detection of ctr overflows in NMI handler */
	for(i = 0 ; i < NUM_COUNTERS ; ++i) 
	{
		CTR_WRITE(1, mrs, i);
	}

	/* enable active counters */
	for(i = 0 ; i < NUM_COUNTERS ; ++i) 
	{
		if(ctr[i].event) 
		{

			CTR_WRITE(ctr[i].count, mrs, i);

			CTRL_READ(low, high, mrs, i);
			CTRL_CLEAR(low);
			CTRL_SET_ENABLE(low);
			CTRL_SET_KERN(low,1);
			CTRL_SET_UM(low, ctr[i].unit_mask);
			CTRL_SET_EVENT(low, ctr[i].event);
			CTRL_WRITE(low, high, mrs, i);
		}
	}

	return 0;
}

int athlon_fill_in_addresses(struct msrs * const mrs)
{
	if((mrs->counters.addrs = kmalloc(NUM_COUNTERS * sizeof(uint),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	if((mrs->controls.addrs = kmalloc(NUM_COUNTERS * sizeof(uint),GFP_KERNEL)) == NULL)
	{
		kfree(mrs->counters.addrs);

		return -ENOMEM;
	}
	
	mrs->counters.addrs[0] = MSR_K7_PERFCTR0;
	mrs->counters.addrs[1] = MSR_K7_PERFCTR1;
	mrs->counters.addrs[2] = MSR_K7_PERFCTR2;
	mrs->counters.addrs[3] = MSR_K7_PERFCTR3;

	mrs->controls.addrs[0] = MSR_K7_EVNTSEL0;
	mrs->controls.addrs[1] = MSR_K7_EVNTSEL1;
	mrs->controls.addrs[2] = MSR_K7_EVNTSEL2;
	mrs->controls.addrs[3] = MSR_K7_EVNTSEL3;

	return 0;
}

void athlon_free_addresses(struct msrs * const mrs)
{
	kfree(mrs->counters.addrs);
	kfree(mrs->controls.addrs);
}

void athlon(struct perf_counter *ctr,struct msrs * const mrs,u32 *ctr_count)
{
	uint low, high;
	int i;

	for(i = 0 ; i < NUM_COUNTERS; ++i)
	{
		if (ctr[i].event) 
		{
			CTR_READ(low, high, mrs, i);
			
			if(CTR_OVERFLOWED(low)) 
			{
				CTR_WRITE(0, mrs, i);
			}

			ctr_count[i] = low;

			//printk("athlon : Counter %d : %d\n",i,low);
		}
	}
}

struct x86_model_spec const athlon_spec = 
{
	.num_counters = NUM_COUNTERS,
	.num_controls = NUM_CONTROLS,

	.prof_start = &athlon_start,
	.prof_stop = &athlon_stop,
	.prof_setup_ctrs = &athlon_setup_ctrs,
	.prof_fill_in_addresses = &athlon_fill_in_addresses,
	.prof_free_addresses = &athlon_free_addresses,
	.prof = &athlon
};

#endif
