/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/skbuff.h>

#include <linux/mapi/ioctl.h>

#include <hashtable.h>
#include <flow_key.h>

PRIVATE u32 subflow_hash_func(void *key,struct hash_table *ht,void *priv)
{
	struct flow_key *fkey = (struct flow_key *)key;
	struct flow_key_struct *fks = (struct flow_key_struct *)priv;
	
	return flow_key_hash_func(fkey,fks)%(ht->capacity);
}

PRIVATE u8 subflow_equals_func(void *keyA,void *keyB,void *priv)
{
	struct flow_key *fkeyA = (struct flow_key *)keyA;
	struct flow_key *fkeyB = (struct flow_key *)keyB;
	struct flow_key_struct *fks = (struct flow_key_struct *)priv;

	return flow_key_equals_func(fkeyA,fkeyB,fks);
}

PRIVATE void subflow_free_key(void *key,void *priv)
{
	struct flow_key *fkey = (struct flow_key *)key;
	
	flow_key_free(fkey);
}

PRIVATE void subflow_free_data(void *data,void *priv)
{
}

PUBLIC struct callbacks subflow_callbacks =
{
	hash:subflow_hash_func,
	equals:subflow_equals_func,
	free_key:subflow_free_key,
	free_data:subflow_free_data
};
