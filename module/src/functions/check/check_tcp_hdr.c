/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *	
 *		stolen partially from net/ipv4/tcp_ipv4.c
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
#include <asm/checksum.h>
#include <linux/ip.h>
#include <net/tcp.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>
#include <linux/mapi/proto.h>
#include <linux/mapi/csum.h>
#include <linux/mapi/skbuff.h>

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *check_tcp_hdr_cache;

PRIVATE __u8 check_tcp_hdr_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long check_tcp_hdr(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct check_tcp_hdr_struct *cths = (struct check_tcp_hdr_struct *)pfunc->data;
	struct sk_buff *skb = *skbp;
	struct iphdr *iph = proto_iphdr(skb);	
	struct tcphdr *th;
	unsigned csum;
	unsigned short tlen = 0;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if(iph->protocol != IPPROTO_TCP)
	{
		return 0;
	}
	
	MAPI_DEBUG(if(net_ratelimit()) printk("CHECK_TCP_HDR : Checking TCP packet\n"));
	
	th = proto_tcphdr(skb,iph);
	
	if(!mapi_pskb_may_pull(skb,sizeof(struct tcphdr)))
	{
		goto no_header;
	}

	if(th->doff < sizeof(struct tcphdr)/4)
	{
		goto bad_packet;
	}
	
	if(!mapi_pskb_may_pull(skb,th->doff*4))
	{
		goto short_packet;
	}
	
	tlen = ntohs(iph->tot_len) - (iph->ihl << 2);

	csum = ~in_cksum((unsigned char *)th,tlen) & 0xFFFF;
	
	if(csum_tcpudp_magic(iph->saddr,iph->daddr,tlen,IPPROTO_TCP,csum) != 0)
	{
		goto csum_error;
	}

	return 0;

no_header:
	MAPI_DEBUG(if(net_ratelimit()) printk("CHECK_TCP_HDR : No header\n"));	
short_packet:
	MAPI_DEBUG(if(net_ratelimit()) printk("CHECK_TCP_HDR : Short packet (skb->len = %u , tlen = %u)\n",skb->len,tlen));	
bad_packet:
	MAPI_DEBUG(if(net_ratelimit()) printk("CHECK_TCP_HDR : Bad packet\n"));
csum_error:
	MAPI_DEBUG(if(net_ratelimit()) printk("CHECK_TCP_HDR : Csum error\n"));

	spin_lock(&(pfunc->data_lock));
	cths->errors++;
	spin_unlock(&(pfunc->data_lock));

	{
		skb_mapi->action = SKB_DROP;
	}
	
	return 0;
}

PRIVATE int add_check_tcp_hdr(struct sock *sk,struct predef_func *pfunc)
{
	struct check_tcp_hdr_struct *cths = (struct check_tcp_hdr_struct *)pfunc->data;
	int ret;
	
	cths->errors = 0;
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_check_tcp_hdr(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	kmem_cache_free(check_tcp_hdr_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE int reset_check_tcp_hdr(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct check_tcp_hdr_struct *cths;

	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	cths = (struct check_tcp_hdr_struct *)found->data;

	spin_lock(&(found->data_lock));
	{
		cths->errors = 0;
	}
	spin_unlock(&(found->data_lock));

	return 0;
}

PRIVATE struct predef_func *getresults_check_tcp_hdr(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void check_tcp_hdr_init_pfunc(struct predef_func *pfunc,struct check_tcp_hdr_struct *cths)
{
	init_pfunc(pfunc);
	
	pfunc->type = CHECK_TCP_HDR;
	pfunc->data = (unsigned long)cths;
	pfunc->func = check_tcp_hdr;
	pfunc->equals = check_tcp_hdr_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct check_tcp_hdr_struct *cths;
	struct predef_func *pfunc;

	if((cths = kmem_cache_alloc(check_tcp_hdr_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(check_tcp_hdr_cache,cths);

		return NULL;
	}

	check_tcp_hdr_init_pfunc(pfunc,cths);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_check_tcp_hdr(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		if(copy_to_user((void *)arg,(void *)pfunc->data,sizeof(struct check_tcp_hdr_struct)))
		{
			return -EFAULT;
		}
	}

	return 0;
}

PRIVATE int check_tcp_hdr_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSCHECK_TCP_HDR && cmd != SIOCGCHECK_TCP_HDR && cmd != SIOCRSCHECK_TCP_HDR && 
	   cmd != SIOCRMCHECK_TCP_HDR)
	{
		return ret;
	}

	if((pfunc = pfunc_alloc_r()) == NULL)
	{
		return -ENOMEM;
	}

	if(copy_from_user((void *)pfunc->data,(void *)arg,sizeof(struct check_tcp_hdr_struct)))
	{
		kmem_cache_free(check_tcp_hdr_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);
		
		return -EFAULT;
	}

	switch(cmd)
	{
		case SIOCSCHECK_TCP_HDR:
			if((ret = add_check_tcp_hdr(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCGCHECK_TCP_HDR:
			ret = put_fields_to_userspace(sk,pfunc,arg);			
			break;
			
		case SIOCRSCHECK_TCP_HDR:
			ret = reset_check_tcp_hdr(sk,pfunc);
			break;

		case SIOCRMCHECK_TCP_HDR:
			ret = remove_check_tcp_hdr(sk,pfunc,1);
			break;
	}

	kmem_cache_free(check_tcp_hdr_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int check_tcp_hdr_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct check_tcp_hdr_struct *cths = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Wrong_Packets\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,CHECK_TCP_HDR);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			cths = (struct check_tcp_hdr_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  %.13lld\n", s,cths->errors);

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
	index:CHECK_TCP_HDR,
	owner:THIS_MODULE,
	add:add_check_tcp_hdr,
	remove:remove_check_tcp_hdr,
	ioctl:check_tcp_hdr_ioctl,
};

int __init check_tcp_hdr_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("checktcp",0,proc_path,check_tcp_hdr_read_proc,NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file checktcp : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((check_tcp_hdr_cache = kmem_cache_create("checktcp",sizeof(struct check_tcp_hdr_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create check_tcp_hdr_cache : %s,%i\n",__FILE__,__LINE__);
		
		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit check_tcp_hdr_exit(void)
{
	unregister_function(CHECK_TCP_HDR);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("checktcp",proc_path);
#endif
	if(kmem_cache_destroy(check_tcp_hdr_cache))
	{
		printk(KERN_ALERT "Error : Could not remove check_tcp_hdr_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(check_tcp_hdr_init);
module_exit(check_tcp_hdr_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

