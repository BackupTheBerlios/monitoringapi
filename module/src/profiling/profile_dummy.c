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
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#include <asm/semaphore.h>
#include <asm/processor.h>

#include <linux/mapi/prof.h>

#define NUM_COUNTERS 1
#define NUM_CONTROLS 1

void dummy_start(struct perf_counter *ctr,struct msrs const * const mrs)
{
}

void dummy_stop(struct perf_counter *ctr,struct msrs const * const mrs)
{
}

int dummy_setup_ctrs(struct perf_counter *ctr,struct msrs const * const mrs)
{
	return 0;
}

int dummy_fill_in_addresses(struct msrs * const mrs)
{
	return 0;
}

void dummy_free_addresses(struct msrs * const mrs)
{
}

void dummy(struct perf_counter *ctr,struct msrs * const mrs,u32 *ctr_count)
{
}

struct x86_model_spec const dummy_spec = 
{
	.num_counters = NUM_COUNTERS,
	.num_controls = NUM_CONTROLS,

	.prof_start = &dummy_start,
	.prof_stop = &dummy_stop,
	.prof_setup_ctrs = &dummy_setup_ctrs,
	.prof_fill_in_addresses = &dummy_fill_in_addresses,
	.prof_free_addresses = &dummy_free_addresses,
	.prof = &dummy
};
