/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/smp_lock.h>
#include <asm/page.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *packet_distribution_cache;

struct private_struct
{
	u64 *distribution[DIST_X_DIM_SIZE];
	u32 dist_pages_order;
	u32 bytesno;
	u32 bitsno;
};

#define function_cb(pds) ((struct private_struct *)(((struct packet_distribution_struct *)pds)->cb))

PRIVATE __u8 packet_distribution_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		struct packet_distribution_struct *fpds = (struct packet_distribution_struct *)fpf->data;
		struct packet_distribution_struct *spds = (struct packet_distribution_struct *)spf->data;

		if((fpds->offset == spds->offset) && (fpds->mask == spds->mask))
		{
			return 1;
		}
	}

	return 0;
}

/* We use a two-dimension distribution array because we can not allocate too much memory for
 * a one dimension array!
 * 
 * 	       mapping
 *  ----			 ---- ----        ---- -----    * = N/M + 1
 * | 1	|		     1	|  1 |  2 | . . .|    | N/M |   ** = (M - 1)*(N/M) + 1
 *  ----			 ---- ----        ---- ----- 
 * | 2  |		     2	|  * |    |      |    |     |
 *  ----    			 ---- ----        ---- -----
 * | 3  |			.               .
 *  ----			.		.
 *    .		===>		.               .
 *    .				 ---- ----        ---- -----
 *    .			     M	| ** |    | . . .|    |  N  |
 *  ----  			 ---- ----        ---- -----
 * | N  |
 *  ----
 *
 *  N = MAX_DIST_ARRAY_SIZE      M = DIST_X_DIM_SIZE
 */

PRIVATE unsigned long packet_distribution(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct packet_distribution_struct *pds = (struct packet_distribution_struct *)pfunc->data;
	struct private_struct *cb = function_cb(pds);	
	struct sk_buff *skb = *skbp;
	u16 distindex = 0;
	u8 *data;
	int i;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if((pds->offset + cb->bytesno) < skb->len)
	{
		data = (skb->data + pds->offset);
	}
	else
	{
		return 0;
	}
	
	for( i = 0 ; i < cb->bytesno ; i++)
	{
		distindex += data[i];
	}
	
	distindex += (data[i] & (0xFF << (8 - cb->bitsno)));
	
	if(distindex >= MAX_DIST_ARRAY_SIZE)
	{
		return 0;
	}
	
	spin_lock(&(pfunc->data_lock));
	{
		cb->distribution[distindex%DIST_X_DIM_SIZE][distindex/DIST_X_DIM_SIZE]++;
	}
	spin_unlock(&(pfunc->data_lock));
	
	return 0;
}

PRIVATE int alloc_distribution_array(struct packet_distribution_struct *pds)
{
	struct private_struct *cb = function_cb(pds);	
	u8 error = 0;
	int i;
	
	cb->dist_pages_order = get_order((MAX_DIST_ARRAY_SIZE*sizeof(u64))/DIST_X_DIM_SIZE);
	
	for( i = 0 ; i < DIST_X_DIM_SIZE ; i++)
	{
		if((cb->distribution[i] = (u64 *)__get_free_pages(GFP_KERNEL,cb->dist_pages_order)) == NULL)
		{
			error = 1;
			
			break;
		}
	}

	if(error)
	{
		while(--i >= 0)
		{
			free_pages((unsigned long)cb->distribution[i],cb->dist_pages_order);
		}

		return -ENOMEM;
	}	
	
	for( i = 0 ; i < DIST_X_DIM_SIZE ; i++)
	{
		memset(cb->distribution[i],0,PAGE_SIZE << cb->dist_pages_order);
	}
	
	return 0;
}

PRIVATE void free_distribution_array(struct packet_distribution_struct *pds)
{
	struct private_struct *cb = function_cb(pds);	
	int i;

	for( i = 0 ; i < DIST_X_DIM_SIZE ; i++)
	{
		free_pages((unsigned long)cb->distribution[i],cb->dist_pages_order);
	}
}

PRIVATE int add_packet_distribution(struct sock *sk,struct predef_func *pfunc)
{
	struct packet_distribution_struct *pds = (struct packet_distribution_struct *)pfunc->data;
	struct private_struct *cb = function_cb(pds);	
	int ret;
	
	if((ret = alloc_distribution_array(pds)) != 0)
	{
		return ret;
	}
	
	cb->bytesno = pds->mask/8;
	cb->bitsno = pds->mask%8;
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_packet_distribution(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct packet_distribution_struct *pds;
	
	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	pds = (struct packet_distribution_struct *)found->data;
	
	free_distribution_array(pds);
	kmem_cache_free(packet_distribution_cache,pds);
	kmem_cache_free(predef_func_cache,found);
	
	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE int reset_packet_distribution(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct packet_distribution_struct *pds;
	struct private_struct *cb;
	int i;
	
	if((found = sk_find_predef(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	
	pds = (struct packet_distribution_struct *)found->data;
	cb = function_cb(pds);
	
	spin_lock(&(found->data_lock));
	{
		for( i = 0 ; i < DIST_X_DIM_SIZE ; i++)
		{
			memset(cb->distribution[i],0,PAGE_SIZE << cb->dist_pages_order);
		}
	}
	spin_unlock(&(found->data_lock));
	
	return 0;
}

PRIVATE void packet_distribution_init_pfunc(struct predef_func *pfunc,struct packet_distribution_struct *pds)
{
	init_pfunc(pfunc);
	
	pfunc->type = PACKET_DISTRIBUTION;
	pfunc->data = (unsigned long)pds;
	pfunc->func = packet_distribution;
	pfunc->equals = packet_distribution_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct packet_distribution_struct *pds;
	struct predef_func *pfunc;
	struct private_struct *cb;
	
	if((pds = kmem_cache_alloc(packet_distribution_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(packet_distribution_cache,pds);

		return NULL;
	}

	packet_distribution_init_pfunc(pfunc,pds);
	
	cb = function_cb(pds);

	memset(cb->distribution,0,DIST_X_DIM_SIZE*sizeof(u64 *));
	pds->dist = NULL;
		
	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	struct packet_distribution_struct upds;
	struct packet_distribution_struct *pds;
	struct private_struct *cb;
	int block_size_in_bytes = (MAX_DIST_ARRAY_SIZE*sizeof(u64))/DIST_X_DIM_SIZE;
	int block_size = MAX_DIST_ARRAY_SIZE/DIST_X_DIM_SIZE;
	int i;
	
	if((pfunc = sk_find_predef(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}	
	
	if(copy_from_user(&upds,(struct packet_distribution_struct *)arg,sizeof(struct packet_distribution_struct)))
	{
		return -EFAULT;
	}
	
	pds = (struct packet_distribution_struct *)pfunc->data;
	cb = function_cb(pds);

	for( i = 0 ; i < DIST_X_DIM_SIZE ; i++)
	{
		if(copy_to_user(upds.dist,cb->distribution[i],block_size_in_bytes))
		{
			return -EFAULT;
		}
		
		upds.dist = upds.dist + block_size;
	}

	return 0;
}

PRIVATE inline int fill_fields(struct packet_distribution_struct *pds,unsigned long arg)
{
	if(get_user(pds->offset,(u32 *)&(((struct packet_distribution_struct *)arg)->offset)) ||
	   get_user(pds->mask,(u8 *)&(((struct packet_distribution_struct *)arg)->mask)))
	{
		return -EFAULT;
	}
	
	if(pds->mask > MAX_MASK)
	{
		return -EINVAL;
	}
	
	return 0;
}

PRIVATE inline struct predef_func *get_pfunc(unsigned long arg,int *status)
{
	struct predef_func *pfunc;

	*status = 0;
	
	if((pfunc = pfunc_alloc_r()) == NULL)
	{
		*status = -ENOMEM;

		return NULL;
	}
	
	if((*status = fill_fields((struct packet_distribution_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(packet_distribution_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int packet_distribution_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSPACKET_DISTRIBUTION && cmd != SIOCGPACKET_DISTRIBUTION && cmd != SIOCRSPACKET_DISTRIBUTION && 
	   cmd != SIOCRMPACKET_DISTRIBUTION)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}
	
	switch(cmd)
	{
		case SIOCSPACKET_DISTRIBUTION:
			if((ret = add_packet_distribution(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCGPACKET_DISTRIBUTION:
			ret = put_fields_to_userspace(sk,pfunc,arg);			
			break;
			
		case SIOCRSPACKET_DISTRIBUTION:
			ret = reset_packet_distribution(sk,pfunc);
			break;

		case SIOCRMPACKET_DISTRIBUTION:
			ret = remove_packet_distribution(sk,pfunc,1);
			break;
	}

	kmem_cache_free(packet_distribution_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int packet_distribution_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct packet_distribution_struct *pds = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Offset   Mask\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,PACKET_DISTRIBUTION);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			pds = (struct packet_distribution_struct *)cur->data;
			
			len += sprintf(buffer + len,"%8p  %.8d %.4d\n",s,pds->offset,pds->mask);

			pos = begin + len;

			if(pos < offset)
			{
				len = 0;
				begin = pos;
			}
			
			if(pos > offset + length)
			{
				goto done;
			}
		}
	}

	*eof = 1;

done:
	unlock_active_socket_list();

	*start = buffer + (offset - begin);
	len -= (offset - begin);

	if(len > length)
	{
		len = length;
	}
	
	if(len < 0)
	{
		len = 0;
	}

	return len;
}
#endif

PRIVATE struct predefined fta =
{
	index:PACKET_DISTRIBUTION,
	owner:THIS_MODULE,
	add:add_packet_distribution,
	remove:remove_packet_distribution,
	ioctl:packet_distribution_ioctl,
};

int __init packet_distribution_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("packetdist", 0, proc_path, packet_distribution_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file packetdist : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((packet_distribution_cache = kmem_cache_create("packetdist",sizeof(struct packet_distribution_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create packet_distribution_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit packet_distribution_exit(void)
{
	unregister_function(PACKET_DISTRIBUTION);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("packetdist",proc_path);
#endif

	if(kmem_cache_destroy(packet_distribution_cache))
	{
		printk(KERN_ALERT "Error : Could not remove packet_distribution_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(packet_distribution_init);
module_exit(packet_distribution_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

