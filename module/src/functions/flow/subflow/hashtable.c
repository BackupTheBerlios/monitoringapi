/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/page.h>

#include <hashtable.h>

PRIVATE kmem_cache_t *hash_item_cache;
PRIVATE kmem_cache_t *list_head_cache;

PRIVATE inline struct hash_table *hash_table_alloc(int capacity)
{
	struct hash_table *ht;
	u8 error = 0;
	int i;
	
	if((ht = (struct hash_table *)kmalloc(sizeof(struct hash_table),GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	ht->table_pages_order = get_order(capacity*sizeof(struct list_head *));
	
	if((ht->table = (struct list_head **)__get_free_pages(GFP_KERNEL,ht->table_pages_order)) == NULL)
	{
		kfree(ht);

		return NULL;
	}

#ifdef DEBUG
	ht->usage_pages_order = get_order(capacity*sizeof(u32));
	
	if((ht->usage = (u32 *)__get_free_pages(GFP_KERNEL,ht->usage_pages_order)) == NULL)
	{
		free_pages((unsigned long)ht->table,ht->table_pages_order);

		kfree(ht);

		return NULL;
	}
#endif
	for( i = 0 ; i < capacity ; i++)
	{
		if((ht->table[i] = kmem_cache_alloc(list_head_cache,GFP_KERNEL)) == NULL)
		{
			error = 1;
			
			break;
		}
	}
	
	if(error)
	{
		int j;

		for(j = 0 ; j < i ; j++)
		{
			kmem_cache_free(list_head_cache,ht->table[j]);
		}
		
		free_pages((unsigned long)ht->table,ht->table_pages_order);
		kfree(ht);
		
		return NULL;
	}

	return ht;
}

PUBLIC struct hash_table *create_hash_table(struct callbacks *calls,int capacity,void *priv)
{
	struct hash_table *ht;
	int i;

	if((ht = hash_table_alloc(capacity)) == NULL)
	{
		return NULL;
	}
	
#ifdef DEBUG
	memset(ht->usage,0,capacity*sizeof(u32));
#endif
	for( i = 0 ; i < capacity ; i++)
	{
		INIT_LIST_HEAD(ht->table[i]);
	}
	
	ht->capacity = capacity;
	ht->items = 0;
	ht->calls = calls;
	ht->priv = priv;

	return ht;
}

PUBLIC void free_hash_table(struct hash_table *ht)
{
	struct list_head *list_cur;
	int i;

	for( i = 0 ; i < ht->capacity ; i++)
	{
		list_for_each(list_cur,ht->table[i])
		{
			struct hash_item *item = list_entry(list_cur,struct hash_item,list);
			
			if(ht->calls->free_key != NULL)
			{
				(*(ht->calls->free_key))(item->key,ht->priv);
			}
			
			if(ht->calls->free_data != NULL)
			{
				(*(ht->calls->free_data))(item->data,ht->priv);
			}
			
			kmem_cache_free(hash_item_cache,item);
		}
		
		kmem_cache_free(list_head_cache,ht->table[i]);
	}

#ifdef DEBUG
	free_pages((unsigned long)ht->usage,ht->usage_pages_order);
#endif	
	free_pages((unsigned long)ht->table,ht->table_pages_order);
	kfree(ht);
}

PUBLIC void *hash_get(struct hash_table *ht,void *key)
{
	struct list_head *list_cur;
	struct hash_item *found = NULL;
	int index = (*(ht->calls->hash))(key,ht,ht->priv);

	list_for_each(list_cur,ht->table[index])
	{
		struct hash_item *item = list_entry(list_cur,struct hash_item,list);
		
		if((*(ht->calls->equals))(item->key,key,ht->priv))
		{
			found = item;
			
			break;
		}
	}
	
	if(found == NULL)
	{
		return NULL;
	}
	
	list_del(&(found->list));
	list_add(&(found->list),ht->table[index]);
	
	return found->data;
}

PUBLIC void hash_insert(struct hash_table *ht,void *key,void *data)
{
	struct hash_item *item;
	int index;

	if((item = kmem_cache_alloc(hash_item_cache,GFP_ATOMIC)) == NULL)
	{
		printk(KERN_ALERT "Could not allocate memory for struct hash_item\n");
		
		return;
	}
	
	index = (*(ht->calls->hash))(key,ht,ht->priv);

	item->key = key;
	item->data = data;
	
	list_add_tail(&(item->list),ht->table[index]);

	ht->items++;

#ifdef DEBUG
	ht->usage[index]++;
#endif	
}

PUBLIC void hash_remove(struct hash_table *ht,void *key)
{
	struct list_head *list_cur;
	struct hash_item *found = NULL;
	int index;

	index = (*(ht->calls->hash))(key,ht,ht->priv);

	list_for_each(list_cur,ht->table[index])
	{
		struct hash_item *item = list_entry(list_cur,struct hash_item,list);
		
		if((*(ht->calls->equals))(item->key,key,ht->priv))
		{
			found = item;

			break;
		}
	}
	
	if(found == NULL)
	{
		printk(KERN_DEBUG "Item not found in hash_remove : %s,%i\n",__FILE__,__LINE__);
		
		return;
	}
	
	list_del(&(found->list));
	
	(*(ht->calls->free_key))(found->key,ht->priv);
	(*(ht->calls->free_data))(found->data,ht->priv);
	kfree(found);
	
	ht->items--;

#ifdef DEBUG
	ht->usage[index]--;
#endif	
}

PUBLIC int init_hash_table(void)
{
	if((hash_item_cache = kmem_cache_create("hashitem",sizeof(struct hash_item),0,0,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create hash_item_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((list_head_cache = kmem_cache_create("listhead",sizeof(struct list_head),0,0,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create list_head_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}

	return 0;
}

PUBLIC int exit_hash_table(void)
{
	if(kmem_cache_destroy(hash_item_cache))
	{
		printk(KERN_ALERT "Error : Could not remove hash_item_cache : %s,%i\n",__FILE__,__LINE__);
		
		return -EPERM;
	}
	
	if(kmem_cache_destroy(list_head_cache))
	{
		printk(KERN_ALERT "Error : Could not remove list_head_cache : %s,%i\n",__FILE__,__LINE__);
		
		return -EPERM;
	}

	return 0;
}
