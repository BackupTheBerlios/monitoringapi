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
#include <perfp4.h>

void p4_start(struct perf_counter *ctr,struct msrs const * const mrs)
{
	uint low, high;
	int i;
	
	for(i = 0 ; i < NUM_COUNTERS ; ++i) 
	{
		if(!ctr[i].enabled)
		{
			continue;
		}

		CCCR_READ(low, high, i);
		CCCR_SET_ENABLE(low);
		CCCR_WRITE(low, high, i);
	}
}

void p4_stop(struct perf_counter *ctr,struct msrs const * const mrs)
{
	uint low,high;
	int i;

	for(i = 0 ; i < NUM_COUNTERS ; ++i) 
	{
		if (!ctr[i].enabled)
		{
			continue;
		}

		CCCR_READ(low, high, i);
		CCCR_SET_DISABLE(low);
		CCCR_WRITE(low, high, i);
	}
}

static int setup_one_p4_counter(struct perf_counter *ctr,unsigned int ct)
{
	struct p4_event_binding *ev = 0;
	unsigned int counter_bit;
	int const maxbind = 2;
	unsigned int cccr = 0;
	unsigned int escr = 0;
	unsigned int high = 0;
	int i;
	
	/* convert from counter *number* to counter *bit* */
	counter_bit = 1 << ct;
	
	/* find our event binding structure. */
	if(ctr[ct].event <= 0 || ctr[ct].event > NUM_EVENTS) 
	{
		printk(KERN_DEBUG "P4 event code 0x%x out of range\n", ctr[ct].event);
		
		return -EINVAL;
	}
	
	ev = &(p4_events[ctr[ct].event - 1]);
	
	for(i = 0 ; i < maxbind ; i++) 
	{
		if(ev->bindings[i].virt_counter & counter_bit) 
		{
			/* modify ESCR */
			ESCR_READ(escr, high, ev, i);
			ESCR_CLEAR(escr);
			ESCR_SET_OS_0(escr, 1);
			ESCR_SET_EVENT_SELECT(escr, ev->event_select);
			ESCR_SET_EVENT_MASK(escr, ctr[ct].unit_mask);			
			ESCR_WRITE(escr, high, ev, i);
		       
			/* modify CCCR */
			CCCR_READ(cccr, high, ct);
			CCCR_CLEAR(cccr);
			CCCR_SET_REQUIRED_BITS(cccr);
			CCCR_SET_ESCR_SELECT(cccr, ev->escr_select);
			CCCR_WRITE(cccr, high, ct);

			return 0;
		}
	}

	printk(KERN_DEBUG "P4 event code 0x%x no binding, ctr %d\n",ctr[ct].event,ct);

	return -EINVAL;
}

int p4_setup_ctrs(struct perf_counter *ctr,struct msrs const * const mrs)
{
	unsigned int low, high;
	unsigned int addr;
	unsigned int i;

	rdmsr(MSR_IA32_MISC_ENABLE, low, high);
	
	if(!MISC_PMC_ENABLED_P(low)) 
	{
		printk(KERN_DEBUG "P4 PMC not available\n");
		
		return -ENOTSUPP;
	}

	/* clear all cccrs (including those outside our concern) */
	for(addr = MSR_P4_BPU_CCCR0 ; addr <= MSR_P4_IQ_CCCR5 ; ++addr) 
	{
		rdmsr(addr, low, high);
		CCCR_CLEAR(low);
		CCCR_SET_REQUIRED_BITS(low);
		wrmsr(addr, low, high);
	}

	/* clear all escrs (including those outside out concern) */
	for(addr = MSR_P4_BSU_ESCR0 ; addr <= MSR_P4_SSU_ESCR0; ++addr)
	{ 
		wrmsr(addr, 0, 0);
	}
	
	for(addr = MSR_P4_MS_ESCR0 ; addr <= MSR_P4_TC_ESCR1; ++addr)
	{ 
		wrmsr(addr, 0, 0);
	}
	
	for (addr = MSR_P4_IX_ESCR0 ; addr <= MSR_P4_CRU_ESCR3; ++addr)
	{ 
		wrmsr(addr, 0, 0);
	}
	
	/* setup all counters */
	for(i = 0 ; i < NUM_COUNTERS ; ++i) 
	{
		if(ctr[i].event) 
		{
			int ret;
			
			if((ret = setup_one_p4_counter(ctr,i)) != 0)
			{
				return ret;
			}
			
			//printk("Configuring counter %d\n",i);
		}
	}

	return 0;
}

int p4_fill_in_addresses(struct msrs * const mrs)
{
	unsigned int addr;
	int i; 
	
	if((mrs->counters.addrs = kmalloc(NUM_COUNTERS * sizeof(uint),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	if((mrs->controls.addrs = kmalloc(NUM_COUNTERS * sizeof(uint),GFP_KERNEL)) == NULL)
	{
		kfree(mrs->counters.addrs);

		return -ENOMEM;
	}
	
	/* the counter registers we pay attention to */
	for(i = 0 ; i < NUM_COUNTERS ; ++i)
	{
		mrs->counters.addrs[i] = p4_counters[i].counter_address;
	}

	/* 18 CCCR registers */
	for(i = 0, addr = MSR_P4_BPU_CCCR0 ; addr <= MSR_P4_IQ_CCCR5; ++addr, ++i)
	{
		mrs->controls.addrs[i] = addr;
	}
	
	/* 43 ESCR registers in three discontiguous group */
	for(addr = MSR_P4_BSU_ESCR0 ; addr <= MSR_P4_SSU_ESCR0; ++addr, ++i)
	{ 
		mrs->controls.addrs[i] = addr;
	}
	
	for(addr = MSR_P4_MS_ESCR0 ; addr <= MSR_P4_TC_ESCR1; ++addr, ++i)
	{ 
		mrs->controls.addrs[i] = addr;
	}
	
	for(addr = MSR_P4_IX_ESCR0 ; addr <= MSR_P4_CRU_ESCR3; ++addr, ++i)
	{
		mrs->controls.addrs[i] = addr;
	}
	
	/* there are 2 remaining non-contiguously located ESCRs */
	mrs->controls.addrs[i++] = MSR_P4_CRU_ESCR4;
	mrs->controls.addrs[i++] = MSR_P4_CRU_ESCR5;

	return 0;
}

void p4_free_addresses(struct msrs * const mrs)
{
	kfree(mrs->counters.addrs);
	kfree(mrs->controls.addrs);
}

void p4(struct perf_counter *ctr,struct msrs * const mrs,u32 *ctr_count)
{
	unsigned int ct,low,high;
	int i;
	
	for( i = 0 ; i < NUM_COUNTERS ; ++i) 
	{
		if (!ctr[i].event)
		{
			continue;
		}

		CCCR_READ(low, high, i);
 		CTR_READ(ct, high, i);
		
		if(CCCR_OVF_P(low) || CTR_OVERFLOW_P(ct)) 
		{
			CCCR_CLEAR_OVF(low);
			CCCR_WRITE(low, high, i);
			CTR_WRITE(0, i);
		}

		ctr_count[i] = ct;

		//printk("p4 : Counter %d : %d\n",i,ct);
	}
}

struct x86_model_spec const p4_spec = 
{
	.num_counters = NUM_COUNTERS,
	.num_controls = NUM_CONTROLS,

	.prof_start = &p4_start,
	.prof_stop = &p4_stop,
	.prof_setup_ctrs = &p4_setup_ctrs,
	.prof_fill_in_addresses = &p4_fill_in_addresses,
	.prof_free_addresses = &p4_free_addresses,
	.prof = &p4
};

#endif /* CONFIG_X86 */
