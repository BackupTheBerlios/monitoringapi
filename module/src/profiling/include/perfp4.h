/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 * 		stolen from oprofile
 * 
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __PERFP4_H_
#define __PERFP4_H_

#include <perfmsr.h>

#define NUM_EVENTS	39
#define NUM_COUNTERS	8
#define NUM_ESCRS	45
#define NUM_CCCRS	18
#define NUM_CONTROLS	(NUM_ESCRS + NUM_CCCRS)

/* tables to simulate simplified hardware view of p4 registers */
struct p4_counter_binding 
{
	int virt_counter;
	int counter_address;
	int cccr_address;
};

struct p4_event_binding 
{
	int escr_select;  /* value to put in CCCR */
	int event_select; /* value to put in ESCR */
	
	struct 
	{
		int virt_counter; /* for this counter... */
		int escr_address; /* use this ESCR       */

	} bindings[2];
};

/* nb: these CTR_* defines are a duplicate of defines in
   event/i386.p4*events. */

#define CTR_BPU_0      (1 << 0)
#define CTR_MS_0       (1 << 1)
#define CTR_FLAME_0    (1 << 2)
#define CTR_IQ_4       (1 << 3)
#define CTR_BPU_2      (1 << 4)
#define CTR_MS_2       (1 << 5)
#define CTR_FLAME_2    (1 << 6)
#define CTR_IQ_5       (1 << 7)

static struct p4_counter_binding p4_counters [NUM_COUNTERS] = 
{
	{ CTR_BPU_0,   MSR_P4_BPU_PERFCTR0,   MSR_P4_BPU_CCCR0 },
	{ CTR_MS_0,    MSR_P4_MS_PERFCTR0,    MSR_P4_MS_CCCR0 },
	{ CTR_FLAME_0, MSR_P4_FLAME_PERFCTR0, MSR_P4_FLAME_CCCR0 },
	{ CTR_IQ_4,    MSR_P4_IQ_PERFCTR4,    MSR_P4_IQ_CCCR4 },
	{ CTR_BPU_2,   MSR_P4_BPU_PERFCTR2,   MSR_P4_BPU_CCCR2 },
	{ CTR_MS_2,    MSR_P4_MS_PERFCTR2,    MSR_P4_MS_CCCR2 },
	{ CTR_FLAME_2, MSR_P4_FLAME_PERFCTR2, MSR_P4_FLAME_CCCR2 },
	{ CTR_IQ_5,    MSR_P4_IQ_PERFCTR5,    MSR_P4_IQ_CCCR5 }
};

/* p4 event codes in libop/op_event.h are indices into this table. */

static struct p4_event_binding p4_events[NUM_EVENTS] = 
{
	{ /* BRANCH_RETIRED */
		0x05, 0x06, 
		{ {CTR_IQ_4, MSR_P4_CRU_ESCR2},
		  {CTR_IQ_5, MSR_P4_CRU_ESCR3} }
	},
	
	{ /* MISPRED_BRANCH_RETIRED */
		0x04, 0x03, 
		{ { CTR_IQ_4, MSR_P4_CRU_ESCR0},
		  { CTR_IQ_5, MSR_P4_CRU_ESCR1} }
	},
	
	{ /* TC_DELIVER_MODE */
		0x01, 0x01,
		{ { CTR_MS_0, MSR_P4_TC_ESCR0},  
		  { CTR_MS_2, MSR_P4_TC_ESCR1} }
	},
	
	{ /* BPU_FETCH_REQUEST */
		0x00, 0x03, 
		{ { CTR_BPU_0, MSR_P4_BPU_ESCR0},
		  { CTR_BPU_2, MSR_P4_BPU_ESCR1} }
	},

	{ /* ITLB_REFERENCE */
		0x03, 0x18,
		{ { CTR_BPU_0, MSR_P4_ITLB_ESCR0},
		  { CTR_BPU_2, MSR_P4_ITLB_ESCR1} }
	},

	{ /* MEMORY_CANCEL */
		0x05, 0x02,
		{ { CTR_FLAME_0, MSR_P4_DAC_ESCR0},
		  { CTR_FLAME_2, MSR_P4_DAC_ESCR1} }
	},

	{ /* MEMORY_COMPLETE */
		0x02, 0x08,
		{ { CTR_FLAME_0, MSR_P4_SAAT_ESCR0},
		  { CTR_FLAME_2, MSR_P4_SAAT_ESCR1} }
	},

	{ /* LOAD_PORT_REPLAY */
		0x02, 0x04, 
		{ { CTR_FLAME_0, MSR_P4_SAAT_ESCR0},
		  { CTR_FLAME_2, MSR_P4_SAAT_ESCR1} }
	},

	{ /* STORE_PORT_REPLAY */
		0x02, 0x05,
		{ { CTR_FLAME_0, MSR_P4_SAAT_ESCR0},
		  { CTR_FLAME_2, MSR_P4_SAAT_ESCR1} }
	},

	{ /* MOB_LOAD_REPLAY */
		0x02, 0x03,
		{ { CTR_BPU_0, MSR_P4_MOB_ESCR0},
		  { CTR_BPU_2, MSR_P4_MOB_ESCR1} }
	},

	{ /* PAGE_WALK_TYPE */
		0x04, 0x01,
		{ { CTR_BPU_0, MSR_P4_PMH_ESCR0},
		  { CTR_BPU_2, MSR_P4_PMH_ESCR1} }
	},

	{ /* BSQ_CACHE_REFERENCE */
		0x07, 0x0c, 
		{ { CTR_BPU_0, MSR_P4_BSU_ESCR0},
		  { CTR_BPU_2, MSR_P4_BSU_ESCR1} }
	},

	/* intel doc vol 3 table A-1: P4 and xeon with cpuid signature < 0xf27
	 * doen't allow MSR_FSB_ESCR1 so only counter 0 is available */
	{ /* IOQ_ALLOCATION */
		0x06, 0x03, 
		{ { CTR_BPU_0, MSR_P4_FSB_ESCR0},
		  { 0, 0 } }
	},

	{ /* IOQ_ACTIVE_ENTRIES */
		0x06, 0x1a, 
		{ { CTR_BPU_2, MSR_P4_FSB_ESCR1},
		  { 0, 0 } }
	},

	{ /* FSB_DATA_ACTIVITY */
		0x06, 0x17, 
		{ { CTR_BPU_0, MSR_P4_FSB_ESCR0},
		  { CTR_BPU_2, MSR_P4_FSB_ESCR1} }
	},

	{ /* BSQ_ALLOCATION */
		0x07, 0x05, 
		{ { CTR_BPU_0, MSR_P4_BSU_ESCR0},
		  { 0, 0 } }
	},

	{ /* BSQ_ACTIVE_ENTRIES */
		0x07, 0x06,
		/* FIXME intel doc don't say which ESCR1 to use, using
		   BSU_ESCR1 is a sensible guess but will need validation */
		{ { CTR_BPU_2, MSR_P4_BSU_ESCR1 },  
		  { 0, 0 } }
	},

	{ /* X87_ASSIST */
		0x05, 0x03, 
		{ { CTR_IQ_4, MSR_P4_CRU_ESCR2},
		  { CTR_IQ_5, MSR_P4_CRU_ESCR3} }
	},

	{ /* SSE_INPUT_ASSIST */
		0x01, 0x34,
		{ { CTR_FLAME_0, MSR_P4_FIRM_ESCR0},
		  { CTR_FLAME_2, MSR_P4_FIRM_ESCR1} }
	},
  
	{ /* PACKED_SP_UOP */
		0x01, 0x08, 
		{ { CTR_FLAME_0, MSR_P4_FIRM_ESCR0},
		  { CTR_FLAME_2, MSR_P4_FIRM_ESCR1} }
	},
  
	{ /* PACKED_DP_UOP */
		0x01, 0x0c, 
		{ { CTR_FLAME_0, MSR_P4_FIRM_ESCR0},
		  { CTR_FLAME_2, MSR_P4_FIRM_ESCR1} }
	},

	{ /* SCALAR_SP_UOP */
		0x01, 0x0a, 
		{ { CTR_FLAME_0, MSR_P4_FIRM_ESCR0},
		  { CTR_FLAME_2, MSR_P4_FIRM_ESCR1} }
	},

	{ /* SCALAR_DP_UOP */
		0x01, 0x0e,
		{ { CTR_FLAME_0, MSR_P4_FIRM_ESCR0},
		  { CTR_FLAME_2, MSR_P4_FIRM_ESCR1} }
	},

	{ /* 64BIT_MMX_UOP */
		0x01, 0x02, 
		{ { CTR_FLAME_0, MSR_P4_FIRM_ESCR0},
		  { CTR_FLAME_2, MSR_P4_FIRM_ESCR1} }
	},
  
	{ /* 128BIT_MMX_UOP */
		0x01, 0x1a, 
		{ { CTR_FLAME_0, MSR_P4_FIRM_ESCR0},
		  { CTR_FLAME_2, MSR_P4_FIRM_ESCR1} }
	},

	{ /* X87_FP_UOP */
		0x01, 0x04, 
		{ { CTR_FLAME_0, MSR_P4_FIRM_ESCR0},
		  { CTR_FLAME_2, MSR_P4_FIRM_ESCR1} }
	},
  
	{ /* X87_SIMD_MOVES_UOP */
		0x01, 0x2e, 
		{ { CTR_FLAME_0, MSR_P4_FIRM_ESCR0},
		  { CTR_FLAME_2, MSR_P4_FIRM_ESCR1} }
	},
  
	{ /* MACHINE_CLEAR */
		0x05, 0x02, 
		{ { CTR_IQ_4, MSR_P4_CRU_ESCR2},
		  { CTR_IQ_5, MSR_P4_CRU_ESCR3} }
	},

	{ /* GLOBAL_POWER_EVENTS */
		0x06, 0x13 /* manual says 0x05 */, 
		{ { CTR_BPU_0, MSR_P4_FSB_ESCR0},
		  { CTR_BPU_2, MSR_P4_FSB_ESCR1} }
	},
  
	{ /* TC_MS_XFER */
		0x00, 0x05, 
		{ { CTR_MS_0, MSR_P4_MS_ESCR0},
		  { CTR_MS_2, MSR_P4_MS_ESCR1} }
	},

	{ /* UOP_QUEUE_WRITES */
		0x00, 0x09,
		{ { CTR_MS_0, MSR_P4_MS_ESCR0},
		  { CTR_MS_2, MSR_P4_MS_ESCR1} }
	},

	{ /* FRONT_END_EVENT */
		0x05, 0x08,
		{ { CTR_IQ_4, MSR_P4_CRU_ESCR2},
		  { CTR_IQ_5, MSR_P4_CRU_ESCR3} }
	},

	{ /* EXECUTION_EVENT */
		0x05, 0x0c,
		{ { CTR_IQ_4, MSR_P4_CRU_ESCR2},
		  { CTR_IQ_5, MSR_P4_CRU_ESCR3} }
	},

	{ /* REPLAY_EVENT */
		0x05, 0x09,
		{ { CTR_IQ_4, MSR_P4_CRU_ESCR2},
		  { CTR_IQ_5, MSR_P4_CRU_ESCR3} }
	},

	{ /* INSTR_RETIRED */
		0x04, 0x02, 
		{ { CTR_IQ_4, MSR_P4_CRU_ESCR0},
		  { CTR_IQ_5, MSR_P4_CRU_ESCR1} }
	},

	{ /* UOPS_RETIRED */
		0x04, 0x01,
		{ { CTR_IQ_4, MSR_P4_CRU_ESCR0},
		  { CTR_IQ_5, MSR_P4_CRU_ESCR1} }
	},

	{ /* UOP_TYPE */    
		0x02, 0x02, 
		{ { CTR_IQ_4, MSR_P4_RAT_ESCR0},
		  { CTR_IQ_5, MSR_P4_RAT_ESCR1} }
	},

	{ /* RETIRED_MISPRED_BRANCH_TYPE */
		0x02, 0x05, 
		{ { CTR_MS_0, MSR_P4_TBPU_ESCR0},
		  { CTR_MS_2, MSR_P4_TBPU_ESCR1} }
	},

	{ /* RETIRED_BRANCH_TYPE */
		0x02, 0x04,
		{ { CTR_MS_0, MSR_P4_TBPU_ESCR0},
		  { CTR_MS_2, MSR_P4_TBPU_ESCR1} }
	}
};


#define MISC_PMC_ENABLED_P(x) ((x) & 1 << 7)

#define ESCR_RESERVED_BITS 0x80000003
#define ESCR_CLEAR(escr) ((escr) &= ESCR_RESERVED_BITS)
#define ESCR_SET_USR_0(escr, usr) ((escr) |= (((usr) & 1) << 2))
#define ESCR_SET_OS_0(escr, os) ((escr) |= (((os) & 1) << 3))
#define ESCR_SET_EVENT_SELECT(escr, sel) ((escr) |= (((sel) & 0x3f) << 25))
#define ESCR_SET_EVENT_MASK(escr, mask) ((escr) |= (((mask) & 0xffff) << 9))
#define ESCR_READ(escr,high,ev,i) do {rdmsr(ev->bindings[(i)].escr_address, (escr), (high));} while (0);
#define ESCR_WRITE(escr,high,ev,i) do {wrmsr(ev->bindings[(i)].escr_address, (escr), (high));} while (0);

#define CCCR_RESERVED_BITS 0x38030FFF
#define CCCR_CLEAR(cccr) ((cccr) &= CCCR_RESERVED_BITS)
#define CCCR_SET_REQUIRED_BITS(cccr) ((cccr) |= 0x00030000)
#define CCCR_SET_ESCR_SELECT(cccr, sel) ((cccr) |= (((sel) & 0x07) << 13))
#define CCCR_SET_PMI_OVF(cccr) ((cccr) |= (1<<26))
#define CCCR_SET_ENABLE(cccr) ((cccr) |= (1<<12))
#define CCCR_SET_DISABLE(cccr) ((cccr) &= ~(1<<12))
#define CCCR_READ(low, high, i) do {rdmsr (p4_counters[(i)].cccr_address, (low), (high));} while (0);
#define CCCR_WRITE(low, high, i) do {wrmsr (p4_counters[(i)].cccr_address, (low), (high));} while (0);
#define CCCR_OVF_P(cccr) ((cccr) & (1U<<31))
#define CCCR_CLEAR_OVF(cccr) ((cccr) &= (~(1U<<31)))

#define CTR_READ(l,h,i) do {rdmsr(p4_counters[(i)].counter_address, (l), (h));} while (0);
#define CTR_WRITE(l,i) do {wrmsr(p4_counters[(i)].counter_address, -(u32)(l), -1);} while (0);
#define CTR_OVERFLOW_P(ctr) (!((ctr) & 0x80000000))

#endif /* __PERFP4_H_ */
