#ifdef HAVE_PAPI_H
extern int events[];
extern int num_hwcntrs;
extern long_long hwcnt_values[];
#endif

static inline void performance_init()
{
#ifdef HAVE_PAPI_H
	int ret;
	
	if((num_hwcntrs = PAPI_num_counters()) < 0)
	{
		fprintf(stderr,"PAPI error : counters < 0\n");
		exit(1);
	}
	
	if(num_hwcntrs > MAX_PERF_EVENTS) 
	{
		num_hwcntrs = MAX_PERF_EVENTS;
	}

	if((ret = PAPI_start_counters(events,num_hwcntrs)) != PAPI_OK)
	{
		PAPI_perror(ret,NULL,0);
		exit(1);
	}
#endif	
}

static inline void performance_read()
{
#ifdef HAVE_PAPI_H
	int ret;

	if((ret = PAPI_read_counters(hwcnt_values,num_hwcntrs)) != PAPI_OK)
	{
		PAPI_perror(ret,NULL,0);
		exit(1);
	}
#endif
}

static inline void performance_print()
{
#ifdef HAVE_PAPI_H
	char event_name[PAPI_MAX_STR_LEN];
	int ret;
	int i;
	
	for( i = 0 ; i < num_hwcntrs ; i++)
	{
		if((ret = PAPI_event_code_to_name(events[i],event_name)) != PAPI_OK)
		{
			PAPI_perror(ret,NULL,0);
		}

		printf("%s : %lld\n",event_name,hwcnt_values[i]);
	}
#endif
}

static inline void performance_exit()
{
#ifdef HAVE_PAPI_H
	int ret;

	if((ret = PAPI_stop_counters(hwcnt_values,num_hwcntrs)) != PAPI_OK)
	{
		PAPI_perror(ret,NULL,0);
		exit(1);
	}
#endif
}
