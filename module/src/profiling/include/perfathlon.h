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

#ifndef __PERFATHLON_H_
#define __PERFATHLON_H_

#include <perfmsr.h>

#define NUM_COUNTERS 4
#define NUM_CONTROLS 4

#define CTR_READ(l,h,msrs,c) do {rdmsr(msrs->counters.addrs[(c)], (l), (h));} while (0)
#define CTR_WRITE(l,msrs,c) do {wrmsr(msrs->counters.addrs[(c)], -(u32)(l), 0xffff);} while (0)
#define CTR_OVERFLOWED(n) (!((n) & (1U<<31)))

#define CTRL_READ(l,h,msrs,c) do {rdmsr(msrs->controls.addrs[(c)], (l), (h));} while (0)
#define CTRL_WRITE(l,h,msrs,c) do {wrmsr(msrs->controls.addrs[(c)], (l), (h));} while (0)
#define CTRL_SET_ACTIVE(n) (n |= (1<<22))
#define CTRL_SET_INACTIVE(n) (n &= ~(1<<22))
#define CTRL_CLEAR(x) (x &= (1<<21))
#define CTRL_SET_ENABLE(val) (val |= 1<<20)
#define CTRL_SET_USR(val,u) (val |= ((u & 1) << 16))
#define CTRL_SET_KERN(val,k) (val |= ((k & 1) << 17))
#define CTRL_SET_UM(val, m) (val |= (m << 8))
#define CTRL_SET_EVENT(val, e) (val |= e)

#endif /* __PERFATHLON_H_ */
