/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_COMPAT_SOCK_LIST_H_
#define __MAPI_COMPAT_SOCK_LIST_H_

#ifdef __KERNEL__

#if V_BEFORE(2,6,0)

/*
 * Hashed lists helper routines
 */
static inline struct sock *__sk_head(struct hlist_head *head)
{
	return hlist_entry(head->first,struct sock,daddr);
}

static inline struct sock *sk_head(struct hlist_head *head)
{
	return hlist_empty(head) ? NULL : __sk_head(head);
}

static inline struct sock *sk_next(struct sock *sk)
{
	return mapi_sk_node(sk).next ?
		hlist_entry(mapi_sk_node(sk).next,struct sock,daddr) : NULL;
}

static inline int sk_unhashed(struct sock *sk)
{
	return hlist_unhashed(&mapi_sk_node(sk));
}

static inline int sk_hashed(struct sock *sk)
{
	return mapi_sk_node(sk).pprev != NULL;
}

static inline void sk_node_init(struct hlist_node *node)
{
	node->pprev = NULL;
}

static inline void __sk_del_node(struct sock *sk)
{
	__hlist_del(&mapi_sk_node(sk));
}

static inline int __sk_del_node_init(struct sock *sk)
{
	if(sk_hashed(sk)) 
	{
		__sk_del_node(sk);
		sk_node_init(&mapi_sk_node(sk));
		
		return 1;
	}
	return 0;
}

static inline int sk_del_node_init(struct sock *sk)
{
	int rc = __sk_del_node_init(sk);

	if (rc) 
	{
		__sock_put(sk);
	}
	return rc;
}

static inline void __sk_add_node(struct sock *sk, struct hlist_head *list)
{
	hlist_add_head(&mapi_sk_node(sk),list);
}

static inline void sk_add_node(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	__sk_add_node(sk,list);
}

#define sk_for_each(__sk,node,list) hlist_for_each_entry(__sk,node,list,daddr)

#endif

#endif /* __KERNEL__ */

#endif /* __MAPI_COMPAT_SOCK_LIST_H_ */
