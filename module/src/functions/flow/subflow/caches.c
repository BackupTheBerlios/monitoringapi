/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/netdevice.h>

#include <linux/mapi/ioctl.h>
#include <subflow.h>

PUBLIC kmem_cache_t *subflow_cache;
PUBLIC kmem_cache_t *sub_subflow_cache;

PUBLIC int create_caches()
{
	if((subflow_cache = kmem_cache_create("subflow",sizeof(struct subflow_struct),0,0,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create subflow_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((sub_subflow_cache = kmem_cache_create("subsubflow",sizeof(struct subflow),0,0,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create sub_subflow_cache : %s,%i\n",__FILE__,__LINE__);
		
		return -EPERM;
	}
	
	return 0;
}

PUBLIC int destroy_caches()
{
	if(kmem_cache_destroy(subflow_cache))
	{
		printk(KERN_ALERT "Error : Could not remove subflow_cache : %s,%i\n",__FILE__,__LINE__);
		
		return -EPERM;
	}

	if(kmem_cache_destroy(sub_subflow_cache))
	{
		printk(KERN_ALERT "Error : Could not remove sub_subflow_cache : %s,%i\n",__FILE__,__LINE__);
		
		return -EPERM;
	}
	
	return 0;
}

PUBLIC struct subflow *subflow_alloc(int gfp)
{
	return kmem_cache_alloc(sub_subflow_cache,gfp);
}

PUBLIC void subflow_free(struct subflow *sbf)
{
	kmem_cache_free(sub_subflow_cache,sbf);	
}

EXPORT_SYMBOL(subflow_alloc);
EXPORT_SYMBOL(subflow_free);

