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
#include <linux/mm.h>
#include <linux/types.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *substring_search_cache;

struct private_struct
{
	__u32 *skip_table;
	__u32 *shift_table;
};

#define function_cb(ss) ((struct private_struct *)(((struct substring_search_struct *)ss)->cb))

/****************************************************************
 *
 *  Function: make_skip(__s8 *,__u32)
 *
 *  Purpose: Create a Boyer-Moore skip table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the skip table
 *
 ****************************************************************/
PRIVATE inline __s32 *make_skip(__s8 *ptrn,__u32 plen)
{
	__s32 *skip = (__s32 *)kmalloc(256 * sizeof(int), GFP_KERNEL);
	__s32 *sptr = &skip[256];

	if(skip == NULL)
	{
		return NULL;
	}

	while(sptr-- != skip)
	{
		*sptr = plen + 1;
	}

	while(plen != 0)
	{
		skip[(__u8)*ptrn++] = plen--;
	}

	return skip;
}

/****************************************************************
 *
 *  Function: make_shift(char *, __s32)
 *
 *  Purpose: Create a Boyer-Moore shift table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the shift table
 *
 ****************************************************************/
PRIVATE inline __s32 *make_shift(__s8 *ptrn,__u32 plen)
{
	__s32 *shift = (__s32 *)kmalloc(plen * sizeof(__s32), GFP_KERNEL);
	__s32 *sptr = shift + plen - 1;
	__s8 *pptr = ptrn + plen - 1;
	__s8 c;

	if(shift == NULL)
	{
		return NULL;
	}

	c = ptrn[plen - 1];

	*sptr = 1;

	while(sptr-- != shift)
	{
		__s8 *p1 = ptrn + plen - 2, *p2, *p3;

		do
		{
			while(p1 >= ptrn && *p1-- != c) ;

			p2 = ptrn + plen - 2;
			p3 = p1;

			while(p3 >= ptrn && *p3-- == *p2-- && p2 >= pptr) ;
		}
		while(p3 >= ptrn && p2 >= pptr);

		*sptr = shift + plen - sptr + p2 - p3;

		pptr--;
	}

	return shift;
}

/****************************************************************
 *
 *  Function: search_substring(__s8 *,__u32,__s8 *,__u32,__s32 *,__s32 *)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
PRIVATE inline __u8 search_substring(__s8 *buf, __u32 blen,__s8 *ptrn,__u32 plen,__s32 *skip,__s32 *shift)
{
	__s32 b_idx = plen;

	if(plen == 0)
	{
		return 1;
	}

	while(b_idx <= blen)
	{
		__s32 p_idx = plen, skip_stride, shift_stride;

		while(buf[--b_idx] == ptrn[--p_idx])
		{
			if(b_idx < 0)
			{
				return 0;
			}

			if(p_idx == 0)
			{
				return 1;
			}
		}

		skip_stride = skip[(__u8)buf[b_idx]];
		shift_stride = shift[p_idx];

		b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
	}

	return 0;
}

PRIVATE __u8 substring_search_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{	
		struct substring_search_struct *fss = (struct substring_search_struct *)fpf->data;
		struct substring_search_struct *sss = (struct substring_search_struct *)spf->data;
		
		if(strncmp(fss->string,sss->string,fss->length) == 0)
		{
			return 1;
		}
	}

	return 0;
}

PRIVATE unsigned long substring_search(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct substring_search_struct *sss = (struct substring_search_struct *)pfunc->data;
	struct private_struct *cb = function_cb(sss);
	struct sk_buff *skb = *skbp;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if(search_substring(skb->data,skb->len,sss->string,sss->length,cb->skip_table,cb->shift_table))
	{
		spin_lock(&(pfunc->data_lock));
		sss->counter++;
		spin_unlock(&(pfunc->data_lock));
	}
	else
	{
		skb_mapi->action = SKB_DROP;
	}

	return 0;
}

PRIVATE int add_substring_search(struct sock *sk,struct predef_func *pfunc)
{
	struct substring_search_struct *sss = (struct substring_search_struct *)pfunc->data;
	struct private_struct *cb = function_cb(sss);
	int ret;
	
	sss->counter = 0;
	
	if((cb->skip_table = make_skip(sss->string,sss->length)) == NULL)
	{
		return -ENOMEM;
	}
	
	if((cb->shift_table = make_shift(sss->string,sss->length)) == NULL)
	{
		kfree(cb->skip_table);
		
		return -ENOMEM;
	}
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_substring_search(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct substring_search_struct *sss;
	struct private_struct *cb;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);
	
	if(found == NULL)
	{
		return -ENODATA;
	}
	
	sss = (struct substring_search_struct *)found->data;
	cb = function_cb(sss);

	kfree(cb->skip_table);
	kfree(cb->shift_table);
	kfree(sss->string);

	kmem_cache_free(substring_search_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);
	
	mapi_module_put(THIS_MODULE);
	
	return 0;
}

PRIVATE int reset_substring_search(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct substring_search_struct *sss;

	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	sss = (struct substring_search_struct *)found->data;
	
	spin_lock(&(found->data_lock));
	{
		sss->counter = 0;
	}
	spin_unlock(&(found->data_lock));

	return 0;
}

PRIVATE inline void substring_search_init_pfunc(struct predef_func *pfunc,struct substring_search_struct *sss)
{
	init_pfunc(pfunc);

	pfunc->type = SUBSTRING_SEARCH;
	pfunc->func = substring_search;
	pfunc->equals = substring_search_equals;
	pfunc->data = (unsigned long)sss;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct substring_search_struct *sss;
	struct predef_func *pfunc;

	if((sss = kmem_cache_alloc(substring_search_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(substring_search_cache,sss);

		return NULL;
	}
	
	substring_search_init_pfunc(pfunc,sss);

	return pfunc;
}

PRIVATE inline int fill_fields(struct substring_search_struct *sss,unsigned long arg)
{
	if(get_user(sss->length,(__u32 *)(&(((struct substring_search_struct *)arg)->length))))
	{
		return -EFAULT;
	}
	
	if((sss->string = kmalloc(sss->length,GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	if(copy_from_user(sss->string,((struct substring_search_struct *)arg)->string,sss->length))
	{
		kfree(sss->string);
		
		return -EFAULT;
	}

	return 0;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = sk_find_predef(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		struct substring_search_struct *sss = (struct substring_search_struct *)pfunc->data;
		
		if(copy_to_user((u64 *)(&(((struct substring_search_struct *)arg)->counter)),&sss->counter,sizeof(u64)))
		{
			return -EFAULT;
		}
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
	
	if((*status = fill_fields((struct substring_search_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(substring_search_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int substring_search_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSSUBSTRING_SEARCH && cmd != SIOCGSUBSTRING_SEARCH 
	   && cmd != SIOCRSSUBSTRING_SEARCH && cmd != SIOCRMSUBSTRING_SEARCH)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCSSUBSTRING_SEARCH:
			if((ret = add_substring_search(sk,pfunc)) != 0)
			{
				break;
			}

			return ret;

		case SIOCGSUBSTRING_SEARCH:
			ret = put_fields_to_userspace(sk,pfunc,arg);
			break;

		case SIOCRSSUBSTRING_SEARCH:
			ret = reset_substring_search(sk,pfunc);
			break;

		case SIOCRMSUBSTRING_SEARCH:
			ret = remove_substring_search(sk,pfunc,1);
			break;
	}

	kfree(((struct substring_search_struct *)pfunc->data)->string);
	kmem_cache_free(substring_search_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int substring_search_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;
	int i;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct substring_search_struct *sss = NULL;
	struct hlist_node *node;

	len += sprintf(buffer + len,"Sock      Packets      Length     String\n");
	
	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,SUBSTRING_SEARCH);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			sss = (struct substring_search_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  %.12lld %.4d       ", s, sss->counter, sss->length);
			
			//XXX
			for( i = 0 ; i < sss->length; i++)
			{
				buffer[i+len] = sss->string[i];
			}
			
			len += i;

			buffer[len++] = '\n';

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
	index:SUBSTRING_SEARCH,
	owner:THIS_MODULE,
	add:add_substring_search,
	remove:remove_substring_search,
	ioctl:substring_search_ioctl,
};

int __init substring_search_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("sstring", 0, proc_path, substring_search_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file sstring : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif

	if((substring_search_cache = kmem_cache_create("sstring",sizeof(struct substring_search_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create substring_search_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit substring_search_exit(void)
{
	unregister_function(SUBSTRING_SEARCH);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("sstring",proc_path);
#endif
	if(kmem_cache_destroy(substring_search_cache))
	{
		printk(KERN_ALERT "Error : Could not remove substring_search_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(substring_search_init);
module_exit(substring_search_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

