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
#include <cookudp.h>

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *cook_udp_cache;

PRIVATE __u8 cook_udp_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long cook_udp(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct sk_buff *skb = *skbp;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if(skb->nh.iph->protocol != IPPROTO_UDP)
	{
		return 0;
	}
	
	if((skb = mapi_skb_private(skbp,sk)) == NULL)
	{
		return -ENOMEM;
	}
	
	if(mapi_udp(skb,pfunc))
	{
		skb_mapi->action = SKB_DROP;

		return 0;
	}

	return 0;
}

PRIVATE int add_cook_udp(struct sock *sk,struct predef_func *pfunc)
{
	struct cook_udp_struct *cus = (struct cook_udp_struct *)pfunc->data;	
	int ret;

	memset(cus,0,sizeof(struct cook_udp_struct));
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);		
	}

	return ret;
}

PRIVATE int remove_cook_udp(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	kmem_cache_free(cook_udp_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);		

	return 0;
}

PRIVATE int reset_cook_udp(struct sock *sk,struct predef_func *pfunc)
{
	return -ENOSYS;
}

PRIVATE struct predef_func *getresults_cook_udp(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void cook_udp_init_pfunc(struct predef_func *pfunc,struct cook_udp_struct *cus)
{
	init_pfunc(pfunc);

	pfunc->type = COOK_UDP;
	pfunc->func = cook_udp;
	pfunc->equals = cook_udp_equals;
	pfunc->data = (unsigned long)cus;
}

PRIVATE struct predef_func *pfunc_alloc_r(void)
{
	struct cook_udp_struct *cus;
	struct predef_func *pfunc;

	if((cus = kmem_cache_alloc(cook_udp_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(cook_udp_cache,cus);

		return NULL;
	}

	cook_udp_init_pfunc(pfunc,cus);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_cook_udp(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		if(copy_to_user((void *)arg,(void *)pfunc->data,sizeof(struct cook_udp_struct)))
		{
			return -EFAULT;
		}
	}

	return 0;
}

PRIVATE int cook_udp_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSCOOK_UDP && cmd != SIOCGCOOK_UDP && cmd != SIOCRSCOOK_UDP && cmd != SIOCRMCOOK_UDP)
	{
		return ret;
	}

	if((pfunc = pfunc_alloc_r()) == NULL)
	{
		return -ENOMEM;
	}

	if(copy_from_user((void *)pfunc->data,(void *)arg,sizeof(struct cook_udp_struct)))
	{
		kmem_cache_free(cook_udp_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);
		
		return -EFAULT;
	}

	switch(cmd)
	{
		case SIOCSCOOK_UDP:
			if((ret = add_cook_udp(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCGCOOK_UDP:
			ret = put_fields_to_userspace(sk,pfunc,arg);
			break;
			
		case SIOCRSCOOK_UDP:
			ret = reset_cook_udp(sk,pfunc);
			break;
			
		case SIOCRMCOOK_UDP:
			ret = remove_cook_udp(sk,pfunc,1);
			break;
	}

	kmem_cache_free(cook_udp_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int cook_udp_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct cook_udp_struct *cus = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Short_packets Checksum_errors No_header_errors\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,COOK_UDP);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			cus = (struct cook_udp_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  %.13d %.15d %.16d\n",s,cus->short_packets,cus->csum_errors,cus->no_header_errors);

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
	index:COOK_UDP,
	owner:THIS_MODULE,
	add:add_cook_udp,
	remove:remove_cook_udp,
	ioctl:cook_udp_ioctl,
};

int __init cook_udp_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("cookudp",0,proc_path,cook_udp_read_proc,NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file cookudp : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	
	if((cook_udp_cache = kmem_cache_create("cookudp",sizeof(struct cook_udp_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create cook_udp_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)))
	{
		return ret;
	}

	return 0;
}

void __exit cook_udp_exit(void)
{
	unregister_function(COOK_UDP);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("cookudp",proc_path);
#endif
	
	if(kmem_cache_destroy(cook_udp_cache))
	{
		printk(KERN_ALERT "Error : Could not remove cook_udp_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(cook_udp_init);
module_exit(cook_udp_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

