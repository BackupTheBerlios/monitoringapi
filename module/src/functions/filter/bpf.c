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

#define DEBUG_BPF

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *bpf_filter_cache;

PRIVATE atomic_t uid_nr = ATOMIC_INIT(0);

struct private_struct
{
	struct sk_filter *filter;

	__u32 packets_checked;
	__u32 packets_passed;
};

#define function_cb(bpf) ((struct private_struct *)(((struct bpf_filter_struct *)bpf)->cb))

PRIVATE void do_skb_trim(struct sk_buff *skb,int len)
{
	if(skb->len > len)
	{
		skb->len = len;
		skb->tail = skb->data + len;
	}
}

PRIVATE __u8 bpf_filter_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	struct bpf_filter_struct *fbpf = (struct bpf_filter_struct *)fpf->data;
	struct bpf_filter_struct *sbpf = (struct bpf_filter_struct *)spf->data;
	
	if((fpf->type == spf->type) && (fbpf->uid == sbpf->uid))
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long bpf_filter(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct bpf_filter_struct *bpf = (struct bpf_filter_struct *)pfunc->data;
	struct private_struct *cb = function_cb(bpf);
	struct sk_filter *filter = cb->filter;
	struct sk_buff *skb = *skbp;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	int res;
	
#ifdef DEBUG_BPF	
	spin_lock(&(pfunc->data_lock));
	{
		cb->packets_checked++;
	}
	spin_unlock(&(pfunc->data_lock));
#endif	
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	res = sk_run_filter(skb,filter->insns,filter->len);
	
	if(res == 0)
	{
		skb_mapi->action = SKB_DROP;
	}
	else
	{
		do_skb_trim(skb,res);

#ifdef DEBUG_BPF	
		spin_lock(&(pfunc->data_lock));
		{
			cb->packets_passed++;
		}
		spin_unlock(&(pfunc->data_lock));
#endif	
	}
	
	return 0;
}

PRIVATE int add_bpf_filter(struct sock *sk,struct predef_func *pfunc)
{
	struct bpf_filter_struct *bpf = (struct bpf_filter_struct *)pfunc->data;
	struct private_struct *cb = function_cb(bpf);
	struct sk_filter *fp = cb->filter;
	int ret;
	
	if((ret = sk_chk_filter(fp->insns,fp->len)) != 0)
	{
		return ret;
	}

	bpf->uid = atomic_read(&uid_nr);

	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		atomic_inc(&(uid_nr));	
		
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_bpf_filter(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct bpf_filter_struct *bpf;
	struct private_struct *cb;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	bpf = (struct bpf_filter_struct *)found->data;
	cb = function_cb(bpf);
	
	kfree(cb->filter);
	kmem_cache_free(bpf_filter_cache,bpf);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE int reset_bpf_filter(struct sock *sk,struct predef_func *pfunc)
{
	return -ENOSYS;
}

PRIVATE struct predef_func *getresults_bpf_filter(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void bpf_filter_init_pfunc(struct predef_func *pfunc,struct bpf_filter_struct *bpf)
{
	init_pfunc(pfunc);
	
	pfunc->type = BPF_FILTER;
	pfunc->data = (unsigned long)bpf;
	pfunc->func = bpf_filter;
	pfunc->equals = bpf_filter_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct bpf_filter_struct *bpf;
	struct predef_func *pfunc;

	if((bpf = kmem_cache_alloc(bpf_filter_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(bpf_filter_cache,bpf);

		return NULL;
	}

	bpf_filter_init_pfunc(pfunc,bpf);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_bpf_filter(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		/* struct bpf_filter_struct *bpf = (struct bpf_filter_struct *)pfunc->data;
		 * struct bpf_filter_struct *arg_bpf = (struct bpf_filter_struct *)arg;
		 */
	}

	return 0;
}

PRIVATE inline int fill_fields(struct bpf_filter_struct *bpf,unsigned long arg)
{
	struct bpf_filter_struct *arg_bpf = (struct bpf_filter_struct *)arg;
	struct private_struct *cb = function_cb(bpf);
	struct sock_fprog *fprog = &(bpf->fprog);
	struct sk_filter *fp; 
	unsigned int fsize;
	
	if(copy_from_user(fprog,&(arg_bpf->fprog),sizeof(bpf->fprog)))
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
	
	if(get_user(bpf->uid,(u16 *)&(arg_bpf->uid)))
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
	
	if((*status = fill_fields((struct bpf_filter_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(bpf_filter_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int bpf_filter_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSBPF_FILTER && cmd != SIOCGBPF_FILTER && 
	   cmd != SIOCRSBPF_FILTER && cmd != SIOCRMBPF_FILTER)
	{
		return ret;
	}

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCGBPF_FILTER:
			ret = put_fields_to_userspace(sk,pfunc,arg);			
			break;
			
		case SIOCSBPF_FILTER:
			{
				struct bpf_filter_struct *bpf;
				struct bpf_filter_struct *arg_bpf;
				
				if((ret = add_bpf_filter(sk,pfunc)) != 0)
				{
					break;
				}
				
				bpf = (struct bpf_filter_struct *)pfunc->data;
				arg_bpf = (struct bpf_filter_struct *)arg;
					
				if(put_user(bpf->uid,(u16 *)&(arg_bpf->uid)))
				{
					return -EFAULT;
				}

				return ret;
			}
		case SIOCRSBPF_FILTER:
			ret = reset_bpf_filter(sk,pfunc);
			break;

		case SIOCRMBPF_FILTER:
			ret = remove_bpf_filter(sk,pfunc,1);
			break;
	}
	
	{
		struct private_struct *cb = function_cb(pfunc->data);
		kfree(cb->filter);
	}
	
	kmem_cache_free(bpf_filter_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int bpf_filter_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct bpf_filter_struct *bpf = NULL;
	struct private_struct *cb;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Checked    Passed\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())	
	{
		pfunc = sk_find_type(s,BPF_FILTER);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			bpf = (struct bpf_filter_struct *)cur->data;
			cb = function_cb(bpf);

			len += sprintf(buffer + len,"%-8p  %-10u %-10u\n",s,cb->packets_checked,cb->packets_passed);

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
	index:BPF_FILTER,
	owner:THIS_MODULE,
	add:add_bpf_filter,
	remove:remove_bpf_filter,
	ioctl:bpf_filter_ioctl,
};

int __init bpf_filter_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("bpf", 0, proc_path, bpf_filter_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file bpf : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((bpf_filter_cache = kmem_cache_create("bpf",sizeof(struct bpf_filter_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create bpf_filter_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit bpf_filter_exit(void)
{
	unregister_function(BPF_FILTER);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("bpf",proc_path);
#endif

	if(kmem_cache_destroy(bpf_filter_cache))
	{
		printk(KERN_ALERT "Error : Could not remove bpf_filter_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(bpf_filter_init);
module_exit(bpf_filter_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

#endif
