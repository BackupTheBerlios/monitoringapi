/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>

#ifdef CONFIG_FILTER

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

PRIVATE kmem_cache_t *decide_bpf_hook_cache;

PRIVATE atomic_t uid_nr = ATOMIC_INIT(0);

struct private_struct
{
	struct sk_filter *filter;
	struct decide_struct *ds;	
};

#define function_cb(dbhs) ((struct private_struct *)(((struct decide_bpf_hook_struct *)dbhs)->cb))

PRIVATE __u8 decide_bpf_hook_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	struct decide_bpf_hook_struct *fdbhs = (struct decide_bpf_hook_struct *)fpf->data;
	struct decide_bpf_hook_struct *sdbhs = (struct decide_bpf_hook_struct *)spf->data;
	
	if((fpf->type == spf->type) && (fdbhs->uid == sdbhs->uid))
	{
		return 1;
	}

	return 0;
}

PRIVATE int decide_bpf_hook_handler(struct sk_buff *skb,void *data)
{
	struct decide_bpf_hook_struct *dbhs = (struct decide_bpf_hook_struct *)data;
	struct private_struct *cb = function_cb(dbhs);
	struct sk_filter *filter = cb->filter;
	int res;
	
	res = sk_run_filter(skb,filter->insns,filter->len);

	return (res == 0) ? DECIDE_RIGHT : DECIDE_LEFT ;
}

PRIVATE int add_decide_bpf_hook(struct sock *sk,struct predef_func *pfunc)
{
	struct decide_bpf_hook_struct *dbhs = (struct decide_bpf_hook_struct *)pfunc->data;
	struct private_struct *cb = function_cb(dbhs);
	struct sk_filter *fp = cb->filter;
	struct predef_func *pfunc_decide;	
	struct decide_hook *hook;	
	int ret;
	
	if((pfunc_decide = sk_find_last_predef(sk,DECIDE)) == NULL)
	{
		return -ENODATA;
	}

	cb->ds = (struct decide_struct *)pfunc_decide->data;
	
	if((ret = sk_chk_filter(fp->insns,fp->len)) != 0)
	{
		return ret;
	}
	
	if((hook = kmalloc(sizeof(struct decide_hook),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	hook->data = dbhs;
	hook->skb_hook = decide_bpf_hook_handler;

	dbhs->uid = atomic_read(&uid_nr);

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

PRIVATE int remove_decide_bpf_hook(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct decide_bpf_hook_struct *dbhs;
	struct private_struct *cb;
	struct decide_hook *hook;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	dbhs = (struct decide_bpf_hook_struct *)found->data;
	cb = function_cb(dbhs);
	
	if((hook = unregister_decide_hook(cb->ds)) == NULL)
	{
		BUG();
	}

	kfree(hook);
	kfree(cb->filter);
	kmem_cache_free(decide_bpf_hook_cache,dbhs);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE void decide_bpf_hook_init_pfunc(struct predef_func *pfunc,struct decide_bpf_hook_struct *dbhs)
{
	init_pfunc(pfunc);
	
	pfunc->type = DECIDE_BPF_HOOK;
	pfunc->data = (unsigned long)dbhs;
	pfunc->func = NULL;
	pfunc->equals = decide_bpf_hook_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct decide_bpf_hook_struct *dbhs;
	struct predef_func *pfunc;

	if((dbhs = kmem_cache_alloc(decide_bpf_hook_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(decide_bpf_hook_cache,dbhs);

		return NULL;
	}

	decide_bpf_hook_init_pfunc(pfunc,dbhs);

	return pfunc;
}

PRIVATE inline int fill_fields(struct decide_bpf_hook_struct *dbhs,unsigned long arg)
{
	struct decide_bpf_hook_struct *arg_dbhs = (struct decide_bpf_hook_struct *)arg;
	struct private_struct *cb = function_cb(dbhs);
	struct sock_fprog *fprog = &(dbhs->fprog);
	struct sk_filter *fp; 
	unsigned int fsize;
	
	if(copy_from_user(fprog,&(arg_dbhs->fprog),sizeof(dbhs->fprog)))
	{
		return -EFAULT;
	}
	
	fsize = sizeof(struct sock_filter) * fprog->len;

        if(fprog->filter == NULL || fprog->len > BPF_MAXINSNS)
	{
                return -EINVAL;
	}

	if((fp = kmalloc(fsize + sizeof(*fp),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	if(copy_from_user(fp->insns,fprog->filter,fsize)) 
	{
		kfree(fp); 
		
		return -EFAULT;
	}

	atomic_set(&fp->refcnt,1);
	fp->len = fprog->len;

	cb->filter = fp;
	
	if(get_user(dbhs->uid,(u16 *)&(arg_dbhs->uid)))
	{
		kfree(fp); 
		
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
	
	if((*status = fill_fields((struct decide_bpf_hook_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(decide_bpf_hook_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int decide_bpf_hook_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSDECIDE_BPF_HOOK && cmd != SIOCRMDECIDE_BPF_HOOK)
	{
		return ret;
	}

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCSDECIDE_BPF_HOOK:
			{
				struct decide_bpf_hook_struct *dbhs;
				struct decide_bpf_hook_struct *arg_dbhs;
				
				if((ret = add_decide_bpf_hook(sk,pfunc)) != 0)
				{
					break;
				}
				
				dbhs = (struct decide_bpf_hook_struct *)pfunc->data;
				arg_dbhs = (struct decide_bpf_hook_struct *)arg;
					
				if(put_user(dbhs->uid,(u16 *)&(arg_dbhs->uid)))
				{
					return -EFAULT;
				}

				return ret;
			}

		case SIOCRMDECIDE_BPF_HOOK:
			ret = remove_decide_bpf_hook(sk,pfunc,1);
			break;
	}
	
	{
		struct private_struct *cb = function_cb(pfunc->data);
		kfree(cb->filter);
	}
	
	kmem_cache_free(decide_bpf_hook_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

PRIVATE struct predefined fta =
{
	index:DECIDE_BPF_HOOK,
	owner:THIS_MODULE,
	add:add_decide_bpf_hook,
	remove:remove_decide_bpf_hook,
	ioctl:decide_bpf_hook_ioctl,
};

int __init decide_bpf_hook_init(void)
{
	int ret;
	
	if((decide_bpf_hook_cache = kmem_cache_create("bpfhook",sizeof(struct decide_bpf_hook_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create decide_bpf_hook_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit decide_bpf_hook_exit(void)
{
	unregister_function(DECIDE_BPF_HOOK);

	if(kmem_cache_destroy(decide_bpf_hook_cache))
	{
		printk(KERN_ALERT "Error : Could not remove decide_bpf_hook_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(decide_bpf_hook_init);
module_exit(decide_bpf_hook_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

#endif
