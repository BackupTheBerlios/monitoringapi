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
#include <asm/atomic.h>
#include <asm/timex.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

#define MAXSIZE 16384		/*dimensions for occurence bitmap (currently 2^14*/
#define HSIZE (14-8)

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *exb_cache;
PRIVATE atomic_t pkt_nr;

struct private_struct
{
	__s8 *bits;
	__s32 *skip_table;
	__s32 *shift_table;
};

#define function_cb(es) ((struct private_struct *)(((struct exb_struct *)es)->cb))

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
PRIVATE __s32 *make_skip(__s8 *ptrn,__u32 plen)
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
PRIVATE __s32 *make_shift(__s8 *ptrn,__u32 plen)
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

PRIVATE inline void exb_init_table(__s8 *bits,__u8 *bbuf,const int len)
{
	register __s16 temp;
	register __u8 c1, c2;
	register __u8 *mmax = bbuf + len - 1;
	__s8 pktno = atomic_read(&pkt_nr) && 0xFF;
	
	c2 = *bbuf;

	while(bbuf++ < mmax) 
	{
		c1 = c2;
		c2 = *bbuf;
		temp = ((c1 << HSIZE) ^ c2);
		*(bits + temp) = pktno;
	}
}

PRIVATE inline int exb_search(__s8 *bits,__s8 *ptrn,const __u8 plen)
{
	__s16 temp;
	__s8 *c = ptrn;
	__s8 *done = ptrn + plen - 1;
	__s8 pktno = atomic_read(&pkt_nr) && 0xFF;

	while(c < done)
	{
		temp = ((__u8) (*c) << HSIZE) ^ ((__u8) *(++c));
		
		if (*(bits + temp) != pktno)
		{
			return 0;
		}
	}

	return 1;
}

PRIVATE __u8 exb_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	int cmp;
	
	if(fpf->type == spf->type)
	{	
		struct exb_struct *fes = (struct exb_struct *)fpf->data;
		struct exb_struct *ses = (struct exb_struct *)spf->data;
		
		cmp = strncmp(fes->string,ses->string,fes->length);
		
		if(cmp == 0)
		{
			return 1;
		}
	}

	return 0;
}

PRIVATE unsigned long exb(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct exb_struct *es = (struct exb_struct *)pfunc->data;
	struct private_struct *cb = function_cb(es);
	struct sk_buff *skb = *skbp;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	atomic_inc(&pkt_nr);
	
	exb_init_table(cb->bits,skb->data,skb->len);
	
	if(exb_search(cb->bits,es->string,es->length))
	{
		if(search_substring(skb->data,skb->len,es->string,es->length,cb->skip_table,cb->shift_table))
		{
			spin_lock(&(pfunc->data_lock));
			es->counter++;
			spin_unlock(&(pfunc->data_lock));
		}
		else
		{
			skb_mapi->action = SKB_DROP;
		}
	}

	return 0;
}

PRIVATE int add_exb(struct sock *sk,struct predef_func *pfunc)
{
	struct exb_struct *es = (struct exb_struct *)pfunc->data;
	struct private_struct *cb = function_cb(es);	
	int ret;
	
	es->counter = 0;
	
	if((cb->bits = (__s8 *)kmalloc(MAXSIZE*sizeof(__s8),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
		
	if((cb->skip_table = make_skip(es->string,es->length)) == NULL)
	{
		kfree(cb->bits);
		
		return -ENOMEM;
	}
	
	if((cb->shift_table = make_shift(es->string,es->length)) == NULL)
	{
		kfree(cb->bits);
		kfree(cb->skip_table);
		
		return -ENOMEM;
	}
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_exb(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct exb_struct *es;
	struct private_struct *cb;
	
	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	es = (struct exb_struct *)found->data;
	cb = function_cb(es);

	kfree(es->string);
	kfree(cb->bits);
	kfree(cb->skip_table);
	kfree(cb->shift_table);

	kmem_cache_free(exb_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);
	
	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE int reset_exb(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct exb_struct *es;

	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	es = (struct exb_struct *)found->data;
	
	spin_lock(&(found->data_lock));
	{
		es->counter = 0;
	}
	spin_unlock(&(found->data_lock));
	
	return 0;
}

PRIVATE void exb_init_pfunc(struct predef_func *pfunc,struct exb_struct *es)
{
	init_pfunc(pfunc);
	
	pfunc->type = EXB;
	pfunc->func = exb;
	pfunc->equals = exb_equals;
	pfunc->data = (unsigned long)es;
}

PRIVATE struct predef_func *pfunc_alloc_r(void)
{
	struct exb_struct *ts;
	struct predef_func *pfunc;

	if((ts = kmem_cache_alloc(exb_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(exb_cache,ts);

		return NULL;
	}

	exb_init_pfunc(pfunc,ts);

	return pfunc;
}

PRIVATE inline int fill_fields(struct exb_struct *es,unsigned long arg)
{
	if(get_user(es->length,(__u32 *)(&(((struct exb_struct *)arg)->length))))
	{
		return -EFAULT;
	}
	
	if((es->string = kmalloc(es->length,GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	if(copy_from_user(es->string,((struct exb_struct *)arg)->string,es->length))
	{
		kfree(es->string);
		
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
		struct exb_struct *es = (struct exb_struct *)pfunc->data;
		
		if(copy_to_user((__u64 *)(&(((struct exb_struct *)arg)->counter)),&es->counter,sizeof(__u64)))
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
	
	if((*status = fill_fields((struct exb_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(exb_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int exb_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSEXB && cmd != SIOCGEXB && cmd != SIOCRSEXB && cmd != SIOCRMEXB)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCSEXB:
			if((ret = add_exb(sk,pfunc)) != 0)
			{
				break;
			}

			return ret;

		case SIOCGEXB:
			ret = put_fields_to_userspace(sk,pfunc,arg);
			break;

		case SIOCRSEXB:
			ret = reset_exb(sk,pfunc);
			break;
			
		case SIOCRMEXB:
			ret = remove_exb(sk,pfunc,1);
			break;
	}

	kfree(((struct exb_struct *)pfunc->data)->string);
	kmem_cache_free(exb_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int exb_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct exb_struct *es = NULL;
	struct hlist_node *node;

	len += sprintf(buffer + len,"Sock      Total_Packets\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,EXB);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			es = (struct exb_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  %.12lld %.4d       \n",s, es->counter, es->length);			

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
	index:EXB,
	owner:THIS_MODULE,
	add:add_exb,
	remove:remove_exb,
	ioctl:exb_ioctl,
};

int __init exb_init(void)
{
	int ret;
	
	atomic_set(&pkt_nr,0);
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("exb", 0, proc_path, exb_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file exb : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}

#endif
	if((exb_cache = kmem_cache_create("exb",sizeof(struct exb_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create exb_cache : %s,%i\n",__FILE__,__LINE__);
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit exb_exit(void)
{
	unregister_function(EXB);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("exb",proc_path);
#endif
	if(kmem_cache_destroy(exb_cache))
	{
		printk(KERN_ALERT "Error : Could not remove exb_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(exb_init);
module_exit(exb_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

