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
#include <linux/proc_fs.h>
#include <linux/types.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *hash_cache;

struct private_struct
{
	u64 counter;
};

#define function_cb(hs) ((struct private_struct *)(((struct hash_struct *)hs)->cb))

PRIVATE __u8 hash_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long hash(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct hash_struct *hs = (struct hash_struct *)pfunc->data;
	struct private_struct *cb = function_cb(hs);
	struct sk_buff *skb = *skbp;	
	__u32 len = skb->len;
	int val;
	int hash;
	int i;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	switch(hs->mode)
	{
		case HASH_ADDITIVE:
		{
			i = 0;
			
			for( hash = len ; i < len ; i++)
			{
				hash += skb->data[i];
			}
			
			val = hash%hs->prime;
			
			if(val >= hs->low && val <= hs->high)
			{
				spin_lock(&(pfunc->data_lock));
				{
					cb->counter++;
				}
				spin_unlock(&(pfunc->data_lock));
				
				return 0;
			}
			
			break;
		}
		case HASH_ROTATING:
		{	
			i = 0;
			
			for( hash = len ; i < len ; i++)
			{
				hash = (hash << 5) ^ (hash >> 27) ^ skb->data[i]; 
			}
			
			val = hash%hs->prime;
			
			if(val >= hs->low && val <= hs->high)
			{
				spin_lock(&(pfunc->data_lock));
				{
					cb->counter++;
				}
				spin_unlock(&(pfunc->data_lock));
				
				return 0;
			}

			break;
		}

		default:
			break;
	}

	skb_mapi->action = SKB_DROP;
	
	return 0;
}

PRIVATE int add_hash(struct sock *sk,struct predef_func *pfunc)
{
	struct hash_struct *hs = (struct hash_struct *)pfunc->data;
	struct private_struct *cb = function_cb(hs);	
	int ret;

	cb->counter = 0;

	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_hash(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	kmem_cache_free(hash_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE int reset_hash(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct hash_struct *hs;
	struct private_struct *cb;

	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	hs = (struct hash_struct *)found->data;
	cb = function_cb(hs);
	
	spin_lock(&(found->data_lock));
	{
		cb->counter = 0;
	}
	spin_unlock(&(found->data_lock));

	return 0;
}

PRIVATE void hash_init_pfunc(struct predef_func *pfunc,struct hash_struct *hs)
{
	init_pfunc(pfunc);

	pfunc->type = HASH;
	pfunc->func = hash;
	pfunc->equals = hash_equals;
	pfunc->data = (unsigned long)hs;
}

PRIVATE struct predef_func *pfunc_alloc_r(void)
{
	struct hash_struct *hs;
	struct predef_func *pfunc;

	if((hs = kmem_cache_alloc(hash_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}

	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(hash_cache,hs);

		return NULL;
	}
	
	hash_init_pfunc(pfunc,hs);

	return pfunc;
}

PRIVATE inline int fill_fields(struct hash_struct *hs,unsigned long arg)
{
	struct hash_struct *arg_hs = (struct hash_struct *)arg;
	
	if(get_user(hs->mode,(u8 *)(&(arg_hs->mode))) ||
	   get_user(hs->prime,(s32 *)(&(arg_hs->prime))) ||
	   get_user(hs->low,(s32 *)(&(arg_hs->low))) ||
	   get_user(hs->high,(s32 *)(&(arg_hs->high))))
	{
		return -EFAULT;
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
	
	if((*status = fill_fields((struct hash_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(hash_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int hash_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSHASH && cmd != SIOCGHASH && cmd != SIOCRSHASH && cmd != SIOCRMHASH)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCSHASH:
			if((ret = add_hash(sk,pfunc)) == -EALREADY)
			{
				break;
			}
			
			return ret;

		case SIOCGHASH:
			return -ENOSYS;
			
		case SIOCRSHASH:
			ret = reset_hash(sk,pfunc);
			break;
			
		case SIOCRMHASH:
			ret = remove_hash(sk,pfunc,1);
			break;
	}

	kmem_cache_free(hash_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int hash_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct hash_struct *hs = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Counter         Mode  Prime     Low       High\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,HASH);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			struct private_struct *cb;
			hs = (struct hash_struct *)cur->data;
			cb = function_cb(hs);

			len += sprintf(buffer + len,"%8p  %.14lld  %.4d  %.5d     %.5d     %.5d\n", s, cb->counter , hs->mode, hs->prime , hs->low, hs->high);

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

static struct predefined fta =
{
	index:HASH,
	owner:THIS_MODULE,
	add:add_hash,
	remove:remove_hash,
	ioctl:hash_ioctl,
};

int __init hash_init(void)
{
	int ret;

#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("hash", 0, proc_path, hash_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file hash : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}

#endif
	if((hash_cache = kmem_cache_create("hash",sizeof(struct hash_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create hash_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit hash_exit(void)
{
	unregister_function(HASH);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("hash",proc_path);
#endif
	if(kmem_cache_destroy(hash_cache))
	{
		printk(KERN_ALERT "Error : Could not remove hash_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(hash_init);
module_exit(hash_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

