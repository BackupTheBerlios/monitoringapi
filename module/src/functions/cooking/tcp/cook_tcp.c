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
#include <linux/ip.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>
#include <cooktcp.h>

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *cook_tcp_cache;

PRIVATE __u8 cook_tcp_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long cook_tcp(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct sk_buff *skb = *skbp;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if(skb->nh.iph->protocol != IPPROTO_TCP)
	{
		return 0;
	}
	
	if((skb = mapi_skb_private(skbp,sk)) == NULL)
	{
		return -ENOMEM;
	}
	
	if(mapi_tcp(skb,sk))
	{
		skb_mapi->action = SKB_DROP;

		return 0;
	}

	return 0;
}

PRIVATE int add_cook_tcp(struct sock *sk,struct predef_func *pfunc)
{
	struct cook_tcp_struct *cts = (struct cook_tcp_struct *)pfunc->data;	
	int ret;

	memset(cts,0,sizeof(struct cook_tcp_struct));	
	
	if((ret = mapi_tcp_init(cts)) != 0)
	{
		return ret;
	}

	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);		
	}

	return ret;
}

PRIVATE int remove_cook_tcp(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct cook_tcp_struct *cts;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	cts = (struct cook_tcp_struct *)found->data;

	mapi_tcp_deinit(cts);
	
	kmem_cache_free(cook_tcp_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);		

	return 0;
}

PRIVATE int reset_cook_tcp(struct sock *sk,struct predef_func *pfunc)
{
	return -ENOSYS;
}

PRIVATE struct predef_func *getresults_cook_tcp(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void cook_tcp_init_pfunc(struct predef_func *pfunc,struct cook_tcp_struct *cts)
{
	init_pfunc(pfunc);

	pfunc->type = COOK_TCP;
	pfunc->func = cook_tcp;
	pfunc->equals = cook_tcp_equals;
	pfunc->data = (unsigned long)cts;
}

PRIVATE struct predef_func *pfunc_alloc_r()
{
	struct cook_tcp_struct *cts;
	struct predef_func *pfunc;

	if((cts = kmem_cache_alloc(cook_tcp_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(cook_tcp_cache,cts);

		return NULL;
	}

	cook_tcp_init_pfunc(pfunc,cts);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_cook_tcp(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		if(copy_to_user((void *)arg,(void *)pfunc->data,sizeof(struct cook_tcp_struct)))
		{
			return -EFAULT;
		}
	}

	return 0;
}

PRIVATE inline int fill_fields(struct cook_tcp_struct *cts,unsigned long arg)
{
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
	
	if((*status = fill_fields((struct cook_tcp_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(cook_tcp_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int cook_tcp_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSCOOK_TCP && cmd != SIOCGCOOK_TCP && 
	   cmd != SIOCRSCOOK_TCP && cmd != SIOCRMCOOK_TCP)
	{
		return ret;
	}

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCSCOOK_TCP:
			if((ret = add_cook_tcp(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCGCOOK_TCP:
			ret = put_fields_to_userspace(sk,pfunc,arg);
			break;
			
		case SIOCRSCOOK_TCP:
			ret = reset_cook_tcp(sk,pfunc);
			break;
			
		case SIOCRMCOOK_TCP:
			ret = remove_cook_tcp(sk,pfunc,1);
			break;
	}

	kmem_cache_free(cook_tcp_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int cook_tcp_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct cook_tcp_struct *cts = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Mode\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,COOK_TCP);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			cts = (struct cook_tcp_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  Mode\n", s);

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
	index:COOK_TCP,
	owner:THIS_MODULE,
	add:add_cook_tcp,
	remove:remove_cook_tcp,
	ioctl:cook_tcp_ioctl,
};

int __init cook_tcp_init()
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("cooktcp",0,proc_path,cook_tcp_read_proc,NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file cooktcp : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif

	if((cook_tcp_cache = kmem_cache_create("cooktcp",sizeof(struct cook_tcp_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create cook_tcp_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit cook_tcp_exit()
{
	unregister_function(COOK_TCP);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("cooktcp",proc_path);
#endif

	if(kmem_cache_destroy(cook_tcp_cache))
	{
		printk(KERN_ALERT "Error : Could not remove cook_tcp_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(cook_tcp_init);
module_exit(cook_tcp_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

