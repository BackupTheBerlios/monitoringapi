/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/types.h>
#include <linux/prefetch.h>
#include <linux/module.h>
#include <linux/compiler.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>

PUBLIC void __sk_run_predef(struct sk_buff **skbp,struct sock *sk)
{
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	struct predef_func *pfunc;
	int ret;
	
        skb_mapi->action = SKB_PROCESS;

	for( pfunc = mapi_sk(sk)->pfunc_list,prefetch(pfunc->next) ; 
	     (pfunc != NULL) && (*skbp != NULL) ; pfunc = pfunc->next,prefetch(pfunc->next))
	{
		if(unlikely(pfunc->func == NULL))
		{
			continue;
		}
		
		if(unlikely((ret = (*(pfunc->func))(skbp,sk,pfunc)) != 0))
		{
			printk(KERN_EMERG "Error while running functions , <code = %d>\n",ret);
			printk(KERN_EMERG "Removing all functions\n");
			
			remove_all_func(sk);
		}
	}
}

PUBLIC void sk_run_predef(struct sk_buff **skbp,struct sock *sk)
{
	read_lock(&(mapi_sk(sk)->pfunc_list_lock));
	__sk_run_predef(skbp,sk);
	read_unlock(&(mapi_sk(sk)->pfunc_list_lock));
}

PUBLIC int __sk_attach_predef(struct sock *sk,const struct predef_func *pfunc)
{
	struct predef_func *cur;
	struct predef_func *tail;
	struct packet_opt *popt;

	popt = mapi_sk(sk);

	if(popt->pfunc_list == NULL)
	{
		popt->pfunc_list = (struct predef_func *)pfunc;
	}
	else
	{
		for( cur = popt->pfunc_list ; cur != NULL ; cur = cur->next)
		{
			if((*(cur->equals))(cur,pfunc))
			{
				return -EALREADY;
			}

			tail = cur;
		}

		tail->next = (struct predef_func *)pfunc;
	}

	atomic_inc(&(popt->predef_func_nr));

	return 0;
}

PUBLIC int sk_attach_predef(struct sock *sk,const struct predef_func *pfunc)
{
	int ret;

	write_lock(&(mapi_sk(sk)->pfunc_list_lock));
	ret = __sk_attach_predef(sk,pfunc);
	write_unlock(&(mapi_sk(sk)->pfunc_list_lock));

	return ret;
}

PUBLIC int __sk_attach_predef_head(struct sock *sk,const struct predef_func *pfunc)
{
	struct predef_func *cur;
	struct packet_opt *popt;

	popt = mapi_sk(sk);

	if(popt->pfunc_list == NULL)
	{
		popt->pfunc_list = (struct predef_func *)pfunc;
	}
	else
	{
		cur = popt->pfunc_list;

		if((*(cur->equals))(cur,pfunc))
		{
			return -EALREADY;
		}
		
		popt->pfunc_list = (struct predef_func *)pfunc;
		popt->pfunc_list->next = cur;
	}

	atomic_inc(&(popt->predef_func_nr));

	return 0;
}

PUBLIC int sk_attach_predef_head(struct sock *sk,const struct predef_func *pfunc)
{
	int ret;

	write_lock(&(mapi_sk(sk)->pfunc_list_lock));
	ret = __sk_attach_predef_head(sk,pfunc);
	write_unlock(&(mapi_sk(sk)->pfunc_list_lock));

	return ret;
}

PUBLIC struct predef_func *__sk_detach_predef(struct sock *sk,const struct predef_func *pfunc)
{
	struct predef_func *cur;
	struct predef_func *last = NULL;
	struct packet_opt *popt;
	u32 i;

	popt = mapi_sk(sk);

	i = 0;

	for( cur = popt->pfunc_list,prefetch(cur->next) ; cur != NULL ; cur = cur->next,prefetch(cur->next),i++)
	{
		if((*(cur->equals))(cur,pfunc))
		{
			if(i == 0)
			{
				popt->pfunc_list = cur->next;
			}
			else
			{
				last->next = cur->next;
			}

			atomic_dec(&(popt->predef_func_nr));
			
			return cur;
		}

		last = cur;
	}
	
	return NULL;
}

PUBLIC struct predef_func *sk_detach_predef(struct sock *sk,const struct predef_func *pfunc)
{
	struct predef_func *ret;

	write_lock(&(mapi_sk(sk)->pfunc_list_lock));
	ret = __sk_detach_predef(sk,pfunc);
	write_unlock(&(mapi_sk(sk)->pfunc_list_lock));

	return ret;
}

PUBLIC struct predef_func *__sk_find_predef(const struct sock *sk,const struct predef_func *pfunc)
{
	struct predef_func *cur;
	u8 found = 0;

	for( cur = mapi_sk(sk)->pfunc_list,prefetch(cur->next); cur != NULL ; 
             cur = cur->next,prefetch(cur->next))
	{
		if((*(cur->equals))(cur,pfunc))
		{
			found = 1;

			break;
		}
	}

	return (found == 1) ? cur : NULL;
}

PUBLIC struct predef_func *sk_find_predef(const struct sock *sk,const struct predef_func *pfunc)
{
	struct predef_func *ret;

	read_lock(&(mapi_sk(sk)->pfunc_list_lock));
	ret = __sk_find_predef(sk,pfunc);
	read_unlock(&(mapi_sk(sk)->pfunc_list_lock));

	return ret;
}

PUBLIC struct predef_func *__sk_find_last_predef(const struct sock *sk,u16 type)
{
        struct predef_func *cur;
        struct predef_func *prev = NULL;
        
	for( cur = mapi_sk(sk)->pfunc_list,prefetch(cur->next); cur != NULL ; 
             cur = cur->next,prefetch(cur->next))
	{
                if(cur->type == type)
                {
                        prev = cur;
                }
	}

	return prev;
}

PUBLIC struct predef_func *sk_find_last_predef(const struct sock *sk,u16 type)
{
	struct predef_func *ret;

	read_lock(&(mapi_sk(sk)->pfunc_list_lock));
	ret = __sk_find_last_predef(sk,type);
	read_unlock(&(mapi_sk(sk)->pfunc_list_lock));

	return ret;
}

PUBLIC struct predef_func *__sk_find_type(struct sock *sk,u16 type)
{
	struct predef_func *head = NULL;
	struct predef_func *subcur = NULL;
	struct predef_func *cur;
	u32 found = 0;

	for( cur = mapi_sk(sk)->pfunc_list ; cur != NULL ; cur = cur->next )
	{
                if(cur->type == type)
                {
		        cur->tnext = NULL;
                }
	}

	for( cur = mapi_sk(sk)->pfunc_list,prefetch(cur->next) ; cur != NULL ; cur = cur->next,prefetch(cur->next))
	{
		if(cur->type == type)
		{
			found++;

			if(found == 1)
			{
				head = cur;
				subcur = head;
			}
			else
			{
				subcur->tnext = cur;
				subcur = cur;
			}
		}
	}

	return (found >= 1) ? head : NULL;
}

PUBLIC struct predef_func *sk_find_type(struct sock *sk,u16 type)
{
	struct predef_func *ret;

	read_lock(&(mapi_sk(sk)->pfunc_list_lock));
	ret = __sk_find_type(sk,type);
	read_unlock(&(mapi_sk(sk)->pfunc_list_lock));

	return ret;
}

EXPORT_SYMBOL(__sk_run_predef);
EXPORT_SYMBOL(__sk_attach_predef);
EXPORT_SYMBOL(__sk_attach_predef_head);
EXPORT_SYMBOL(__sk_detach_predef);
EXPORT_SYMBOL(__sk_find_predef);
EXPORT_SYMBOL(__sk_find_type);
EXPORT_SYMBOL(__sk_find_last_predef);

EXPORT_SYMBOL(sk_run_predef);
EXPORT_SYMBOL(sk_attach_predef);
EXPORT_SYMBOL(sk_attach_predef_head);
EXPORT_SYMBOL(sk_detach_predef);
EXPORT_SYMBOL(sk_find_predef);
EXPORT_SYMBOL(sk_find_type);
EXPORT_SYMBOL(sk_find_last_predef);

// vim:ts=8:expandtab
