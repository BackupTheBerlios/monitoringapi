/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *		
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __CACHED_BPF_H
#define __CACHED_BPF_H

#define MAX_HEADER_LEN 128

#define MAX_FILTER_CACHE_BITS	8	/* 8 is the maximum allowed value*/
#define MAX_FILTER_CACHE_MASK	0xFF
#define MAX_FILTER_CACHE_SLOTS	(1 << MAX_FILTER_CACHE_BITS)
#define FILTER_CACHE_SLOTS_ALIGN 4

struct private_struct
{
	struct sk_filter *filter;

	struct filter_mem_accesses *fmem_accesses;
	struct filter_cache *fcache;
};

typedef struct filter_cache_slot
{
	u32 result;

	/* Remember to check also function setup_filter_cache(...)
	 */
	u8 fields[0];

} filt_data;

typedef struct filter_cache
{
	struct filter_cache_slot *cache[MAX_FILTER_CACHE_SLOTS];
	u8 *hw_cache_lines[MAX_FILTER_CACHE_SLOTS];
	
	u16 slot_size;
	
	u64 hits;
	u64 misses;

	int (*run_mapi_filter)(const struct private_struct *cb,const struct sk_buff *skb,const struct sock_filter *filter,int flen);
	
} filt_cache;

typedef struct filter_mem_accesses
{
	u16	*locations;
	u16	nolocations;
	
} filt_accesses;

#endif /* __CACHED_BPF_H */
