/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __HASHTABLE_H_
#define __HASHTABLE_H_

#include <linux/types.h>
#include <linux/list.h>

#define PRIVATE static
#define PUBLIC

#ifdef __KERNEL__

struct hash_item
{
	void *key;
	void *data;

	struct list_head list;
};
	
struct hash_table
{
	u32 capacity;
	u32 items;
	
	struct callbacks *calls;
	struct list_head **table;
	int table_pages_order;
	
	void *priv;
	
#ifdef DEBUG
	u32 *usage;
	int usage_pages_order;
#endif
};

struct callbacks
{
	u32 (*hash)(void *key,struct hash_table *ht,void *priv);
	u8 (*equals)(void *keyA,void *keyB,void *priv);
	void (*free_key)(void *key,void *priv);
	void (*free_data)(void *data,void *priv);
};

struct hash_table *create_hash_table(struct callbacks *calls,int capacity,void *priv);
void free_hash_table(struct hash_table *ht);
void *hash_get(struct hash_table *ht,void *key);
void hash_insert(struct hash_table *ht,void *key,void *data);
void hash_remove(struct hash_table *ht,void *key);

int init_hash_table(void);
int exit_hash_table(void);

#endif /* __KERNEL__ */

#endif
