/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __SUBFLOW_H_
#define __SUBFLOW_H_

#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/timer.h>
#include <linux/slab.h>

#include <linux/mapi/common.h>

#include <hashtable.h>

#define MAX_PROC_FILENAME_SIZE 30

#ifdef __KERNEL__

extern kmem_cache_t *subflow_cache;
extern kmem_cache_t *sub_subflow_cache;

struct subflow_private_struct
{
	/* member list must be first. Do not change! */
	struct list_head list;

	__u8 expired;
};

static inline struct subflow *subflow_list_entry(struct list_head *list)
{
	return ((struct subflow *)((char *)(list)-(unsigned long)(&((struct subflow *)0)->cb)));
}

#define subflow_cb(sbf) ((struct subflow_private_struct *)(((struct subflow *)sbf)->cb))

struct subflow_struct
{
	atomic_t subflows_nr;
	
	struct list_head *subflow_list;
	rwlock_t subflow_list_lock;

	struct hash_table *subflow_hash_table;
	rwlock_t subflow_hash_table_lock;
	
	u64 timeout;
	u64 max_duration;

	u8 stop_timers;
	struct timer_list timeout_timer;
	struct timer_list duration_timer;
	struct timer_list subflow_hook_timer;

	struct subflow_hook *expired_sbf_hook;

	struct flow_key_struct *fks;
};

void check_timeouts(unsigned long data);
void check_durations(unsigned long data);
void run_expired_subflow_hook(unsigned long data);

int create_caches(void);
int destroy_caches(void);

int subflow_read_proc(char *buffer,char **start,off_t offset,int length,int *eof,void *data);
int hash_table_read_proc(char *buffer,char **start,off_t offset,int length,int *eof,void *data);

extern struct callbacks subflow_callbacks;

struct subflow *subflow_alloc(int gfp);
void subflow_free(struct subflow *sbf);

struct subflow *find_expired_subflow(struct subflow_struct *ss);

#endif /* __KERNEL__ */

#endif /* __SUBFLOW_H_ */
