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

#include <linux/mapi/packet.h>
#include <linux/mapi/timeval.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

#include <decide_hook.h>

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *decide_action_hook_cache;

PRIVATE atomic_t uid_nr = ATOMIC_INIT(0);

struct private_struct
{
	struct decide_struct *ds;
	struct sock *sk;
};

#define function_cb(dahs) ((struct private_struct *)(((struct decide_action_hook_struct *)dahs)->cb))

PRIVATE __u8 decide_action_hook_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	struct decide_action_hook_struct *fdahs = (struct decide_action_hook_struct *)fpf->data;
	struct decide_action_hook_struct *sdahs = (struct decide_action_hook_struct *)spf->data;
	
	if((fpf->type == spf->type) && (fdahs->uid == sdahs->uid))
	{
		return 1;
	}

	return 0;
}

PRIVATE int decide_action_hook_handler(struct sk_buff *skb,void *data)
{
	struct decide_action_hook_struct *dahs = (struct decide_action_hook_struct *)data;
	struct private_struct *cb = function_cb(dahs);
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(cb->sk);
	
	if(skb_mapi->action == SKB_DROP)
	{
		return DECIDE_RIGHT;
	}

	return DECIDE_LEFT;
}

PRIVATE int add_decide_action_hook(struct sock *sk,struct predef_func *pfunc)
{
	struct decide_action_hook_struct *dahs = (struct decide_action_hook_struct *)pfunc->data;
	struct private_struct *cb = function_cb(dahs);
	struct predef_func *pfunc_decide;	
	struct decide_hook *hook;	
	int ret;
	
	if((pfunc_decide = sk_find_last_predef(sk,DECIDE)) == NULL)
	{
		return -ENODATA;
	}

	cb->ds = (struct decide_struct *)pfunc_decide->data;
	cb->sk = sk;

	if((hook = kmalloc(sizeof(struct decide_hook),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	hook->data = dahs;
	hook->skb_hook = decide_action_hook_handler;

	dahs->uid = atomic_read(&uid_nr);

	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		atomic_inc(&(uid_nr));	

		mapi_module_get(THIS_MODULE);

		if((ret = register_decide_hook(cb->ds,hook)) != 0)
		{
			return ret;
		}
	}

	return ret;
}

PRIVATE int remove_decide_action_hook(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct decide_action_hook_struct *dahs;
	struct private_struct *cb;
	struct decide_hook *hook;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	dahs = (struct decide_action_hook_struct *)found->data;
	cb = function_cb(dahs);
	
	if((hook = unregister_decide_hook(cb->ds)) == NULL)
	{
		BUG();
	}

	kfree(hook);
	kmem_cache_free(decide_action_hook_cache,dahs);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE void decide_action_hook_init_pfunc(struct predef_func *pfunc,struct decide_action_hook_struct *dahs)
{
	init_pfunc(pfunc);
	
	pfunc->type = DECIDE_ACTION_HOOK;
	pfunc->data = (unsigned long)dahs;
	pfunc->func = NULL;
	pfunc->equals = decide_action_hook_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct decide_action_hook_struct *dahs;
	struct predef_func *pfunc;

	if((dahs = kmem_cache_alloc(decide_action_hook_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(decide_action_hook_cache,dahs);

		return NULL;
	}

	decide_action_hook_init_pfunc(pfunc,dahs);

	return pfunc;
}

PRIVATE inline int fill_fields(struct decide_action_hook_struct *dahs,unsigned long arg)
{
	struct decide_action_hook_struct *arg_dahs = (struct decide_action_hook_struct *)arg;
	
	if(get_user(dahs->uid,(u16 *)&(arg_dahs->uid)))
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
	
	if((*status = fill_fields((struct decide_action_hook_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(decide_action_hook_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int decide_action_hook_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSDECIDE_ACTION_HOOK && cmd != SIOCRMDECIDE_ACTION_HOOK)
	{
		return ret;
	}

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCSDECIDE_ACTION_HOOK:
			{
				struct decide_action_hook_struct *dahs;
				struct decide_action_hook_struct *arg_dahs;
				
				if((ret = add_decide_action_hook(sk,pfunc)) != 0)
				{
					break;
				}
				
				dahs = (struct decide_action_hook_struct *)pfunc->data;
				arg_dahs = (struct decide_action_hook_struct *)arg;
					
				if(put_user(dahs->uid,(u16 *)&(arg_dahs->uid)))
				{
					return -EFAULT;
				}

				return ret;
			}
		case SIOCRMDECIDE_ACTION_HOOK:
			ret = remove_decide_action_hook(sk,pfunc,1);
			break;
	}
	
	kmem_cache_free(decide_action_hook_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

PRIVATE struct predefined fta =
{
	index:DECIDE_ACTION_HOOK,
	owner:THIS_MODULE,
	add:add_decide_action_hook,
	remove:remove_decide_action_hook,
	ioctl:decide_action_hook_ioctl,
};

int __init decide_action_hook_init(void)
{
	int ret;
	
	if((decide_action_hook_cache = kmem_cache_create("ahook",sizeof(struct decide_action_hook_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create decide_action_hook_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit decide_action_hook_exit(void)
{
	unregister_function(DECIDE_ACTION_HOOK);

	if(kmem_cache_destroy(decide_action_hook_cache))
	{
		printk(KERN_ALERT "Error : Could not remove decide_action_hook_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(decide_action_hook_init);
module_exit(decide_action_hook_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");
