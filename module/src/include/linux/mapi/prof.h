/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_PROF_H
#define __MAPI_PROF_H

#include <linux/smp.h>

#define PERF_MAX_COUNTERS 8

struct perf_counter 
{
	int count;
	int enabled;
	int event;
	int unit_mask;
};

#ifdef __KERNEL__

typedef enum 
{
	CPU_UNSUPPORTED = -1,	/* unsupported CPU type */
	CPU_PPRO, 		/* Pentium Pro */
	CPU_PII, 		/* Pentium II series */
	CPU_PIII, 		/* Pentium III series */
	CPU_ATHLON,		/* AMD P6 series */
	CPU_P4,			/* Pentium 4 / Xeon series */
	MAX_CPU_TYPE
		
} cpu_type_t ;

struct msr_group 
{
	uint *addrs;
};

struct msrs
{
	struct msr_group counters;
	struct msr_group controls;
};

struct x86_model_spec 
{
	uint const num_counters;
	uint const num_controls;
	
	void (*prof_start)(struct perf_counter *ctr,struct msrs const * const mrs);
	void (*prof_stop)(struct perf_counter *ctr,struct msrs const * const mrs);
	int (*prof_setup_ctrs)(struct perf_counter *ctr,struct msrs const * const mrs);
	int (*prof_fill_in_addresses)(struct msrs * const mrs);
	void (*prof_free_addresses)(struct msrs * const mrs);
	void (*prof)(struct perf_counter *ctr,struct msrs * const mrs,u32 *ctr_count);
};

void prof_start(struct perf_counter *ctr,struct msrs const * const mrs);
void prof_stop(struct perf_counter *ctr,struct msrs const * const mrs);
int prof_setup_ctrs(struct perf_counter *ctr,struct msrs const * const mrs);
int prof_fill_in_addresses(struct msrs * const mrs);
void prof_free_addresses(struct msrs * const mrs);
void prof(struct perf_counter *ctr,struct msrs * const mrs,u32 *ctr_count);
int prof_num_counters(void);
int prof_num_controls(void);

extern struct x86_model_spec const athlon_spec;
extern struct x86_model_spec const p4_spec;
extern struct x86_model_spec const dummy_spec;

static inline cpu_type_t get_cpu_type(void)
{
#ifdef CONFIG_X86	
	__u8 vendor = current_cpu_data.x86_vendor;
	__u8 family = current_cpu_data.x86;
	__u8 model = current_cpu_data.x86_model;
	__u16 val;

	switch(vendor)
	{
		case X86_VENDOR_AMD:

			if(family == 6) 
			{
				/* certain models of K7 does not have apic.
				 * Check if apic is really present before enabling it.
				 * IA32 V3, 7.4.1 
				 */
				val = cpuid_edx(1);
				
				if (!(val & (1 << 9)))
				{
					return CPU_UNSUPPORTED;
				}

				return CPU_ATHLON;
			}
			
			return CPU_UNSUPPORTED;

		case X86_VENDOR_INTEL:
			
			switch (family) 
			{
				default:
					return CPU_UNSUPPORTED;
				
				case 6:
					/* A P6-class processor */
					if (model > 5)
					{
						return CPU_PIII;
					}
					else if (model > 2)
					{
						return CPU_PII;
					}

					return CPU_PPRO;

				case 0xf:
					if(model <= 3) 
					{
						return CPU_P4;
					} 
					else
					{
						return CPU_UNSUPPORTED;
					}
			}

	default:
		return CPU_UNSUPPORTED;
	}
#else
	return CPU_UNSUPPORTED;
#endif
}

static inline int check_params(struct perf_counter *ctr,int num_counters)
{
	int enabled = 0;
	int i;

	for(i = 0 ; i < num_counters ; i++) 
	{
		if(!ctr[i].enabled)
		{
			continue;
		}

		enabled = 1;
	}

	if(!enabled)
	{
		return -EINVAL;
	}

	return 0;
}

static inline void setup_perf_counter(struct perf_counter *ctr,int event,int unit_mask)
{
	ctr->enabled = 1;
	ctr->event = event;
	ctr->unit_mask = unit_mask;
}

static inline int init_profiling(struct perf_counter *ctr,struct msrs *cpu_msrs)
{
	int ret;
	
	if((ret = check_params(ctr,prof_num_counters())) != 0)
	{
		return ret;
	}

	if((ret = prof_fill_in_addresses(cpu_msrs)) != 0)
	{
		return ret;
	}
	
	if((ret = prof_setup_ctrs(ctr,cpu_msrs)) != 0)
	{
		return ret;
	}
	
	prof_start(ctr,cpu_msrs);
	
	return 0;
}

static inline void deinit_profiling(struct perf_counter *ctr,struct msrs *cpu_msrs)
{
	prof_stop(ctr,cpu_msrs);
	prof_free_addresses(cpu_msrs);
}

#endif /* __KERNEL__ */

#endif /* __MAPI_PROF_H */
