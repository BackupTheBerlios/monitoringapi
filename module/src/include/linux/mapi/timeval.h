/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_TIMEVAL_H
#define __MAPI_TIMEVAL_H

#include <linux/config.h>

#ifdef CONFIG_X86_TSC
#include <asm/msr.h>
#endif

#ifdef CONFIG_X86_TSC

static inline void tv_stamp(struct timeval *tv)
{
	rdtsc(tv->tv_usec,tv->tv_sec);
}

static inline void tv_add(struct timeval *sum,struct timeval *first_tv,struct timeval *sec_tv)
{
	__asm__ __volatile__ (  "addl %2,%0\n\t" 
				"adcl %3,%1\n\t" 
				: "=r" (sec_tv->tv_usec), "=r" (sec_tv->tv_sec)
				: "g" (first_tv->tv_usec), "g" (first_tv->tv_sec),
				"0" (sum->tv_usec), "1" (sum->tv_sec));
}

static inline void tv_sub(struct timeval *diff,struct timeval *first_tv,struct timeval *sec_tv)
{
	__asm__ __volatile__ (  "subl %2,%0\n\t" 
				"sbbl %3,%1\n\t" 
				: "=r" (sec_tv->tv_usec), "=r" (sec_tv->tv_sec)
				: "g" (first_tv->tv_usec), "g" (first_tv->tv_sec),
				"0" (diff->tv_usec), "1" (diff->tv_sec));
}

#else

static inline void tv_stamp(struct timeval *tv)
{
#ifdef __KERNEL__	
	do_gettimeofday(tv);
#else
	gettimeofday(tv,NULL);
#endif
}

static inline void tv_add(struct timeval *sum,struct timeval *first_tv,struct timeval *sec_tv)
{
	sum->tv_sec = first_tv->tv_sec + sec_tv->tv_sec;
	sum->tv_usec = first_tv->tv_usec + sec_tv->tv_usec;
	
	if(sum->tv_usec > 1000000)
	{
		sum->tv_sec++;
		sum->tv_usec -= 1000000;
	}
}

static inline void tv_sub(struct timeval *diff,struct timeval *first_tv,struct timeval *sec_tv)
{
	diff->tv_sec = first_tv->tv_sec - sec_tv->tv_sec;
	diff->tv_usec = first_tv->tv_usec - sec_tv->tv_usec;

	if(diff->tv_usec < 0)
	{
		diff->tv_sec--;
		diff->tv_usec += 1000000;
	}
}

#endif

#endif /* __MAPI_TIMEVAL_H */
