#ifndef __MAPIRUSAGE_H
#define __MAPIRUSAGE_H

#include <sys/resource.h>
#include <unistd.h>

#include <linux/mapi/timeval.h>

struct rusage start_usage;
struct rusage end_usage;
struct timeval start_time;
struct timeval end_time;

static inline int start_time_and_usage()
{
	if(getrusage(RUSAGE_SELF,&start_usage) || gettimeofday(&start_time,NULL))
	{
		return 1;
	}

	return 0;
}

static inline int end_time_and_usage()
{
	if(getrusage(RUSAGE_SELF,&end_usage) || gettimeofday(&end_time,NULL))
	{
		return 1;
	}

	return 0;
}

static inline void print_rusage()
{
	struct timeval diff;
	time_t t;
	int ms;
	
	t = (end_usage.ru_utime.tv_sec - start_usage.ru_utime.tv_sec)*100+
	    (end_usage.ru_utime.tv_usec - start_usage.ru_utime.tv_usec)/10000+
	    (end_usage.ru_stime.tv_sec - start_usage.ru_stime.tv_sec)*100+
	    (end_usage.ru_stime.tv_usec - start_usage.ru_stime.tv_usec)/10000;

	ms = (end_time.tv_sec - start_time.tv_sec)*100 + (end_time.tv_usec - start_time.tv_usec)/10000;

	printf("Rusage statistics : ");
	
	/*ru_utime : Time spent executing user instructions*/
	tv_sub(&diff,&end_usage.ru_utime,&start_usage.ru_utime);
	printf("%ld.%01lduser ",diff.tv_sec,diff.tv_usec/100000);
	
	/*ru_stime : Time spent in operating system code on behalf of processes*/
	tv_sub(&diff,&end_usage.ru_stime,&start_usage.ru_stime);
	printf("%ld.%01ldsys ", diff.tv_sec, diff.tv_usec/100000);
	
	tv_sub(&diff,&end_time,&start_time);
	printf("%ld.%01ldreal ",diff.tv_sec,diff.tv_usec/100000);
	
	printf("%d%% ",(int)(t*100/((ms ? ms : 1))));
	
	/*ru_nswap : The number of times processes was swapped entirely out of main memory*/
	printf("%ldsw ",end_usage.ru_nswap - start_usage.ru_nswap);
	
	/*ru_minflt : The number of page faults which were serviced without requiring any I/O
	  ru_majflt : The number of page faults which were serviced by doing I/O*/
	printf("%ld+%ldpf ",end_usage.ru_minflt - start_usage.ru_minflt,end_usage.ru_majflt - start_usage.ru_majflt);
	
	/*ru_nvcsw : The number of times processes voluntarily invoked a context switch (usually to wait for some service).
	  ru_nivcsw : The number of times an involuntary context switch took place (because a time slice expired, or another process of higher priority was scheduled)*/
	printf("%ld+%ldcsw\n",end_usage.ru_nvcsw - start_usage.ru_nvcsw,end_usage.ru_nivcsw - start_usage.ru_nivcsw);
}

#endif /* __MAPIRUSAGE_H */
