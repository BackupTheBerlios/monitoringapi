#ifndef __MAPI_COMPAT_LIST_H_
#define __MAPI_COMPAT_LIST_H_

#ifdef __KERNEL__

#include <linux/stddef.h>
#include <linux/prefetch.h>
#include <asm/system.h>

/*
 * These are non-NULL pointers that will result in page faults
 * under normal circumstances, used to verify that nobody uses
 * non-initialized list entries.
 */
#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

/* 
 * Double linked lists with a single pointer list head. 
 * Mostly useful for hash tables where the two pointer list head is 
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */ 

struct hlist_head 
{ 
	struct hlist_node *first; 
}; 

struct hlist_node 
{ 
	struct hlist_node *next, **pprev; 
}; 

#define HLIST_HEAD_INIT { .first = NULL } 
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL) 
#define INIT_HLIST_NODE(ptr) ((ptr)->next = NULL, (ptr)->pprev = NULL)

static inline int hlist_unhashed(struct hlist_node *h) 
{ 
	return !h->pprev;
} 

static inline int hlist_empty(struct hlist_head *h) 
{ 
	return !h->first;
} 

static inline void __hlist_del(struct hlist_node *n) 
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;  
	if (next) 
		next->pprev = pprev;
}  

static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}

/**
 * hlist_del_rcu - deletes entry from hash list without re-initialization
 * @entry: the element to delete from the hash list.
 *
 * Note: list_unhashed() on entry does not return true after this, 
 * the entry is in an undefined state. It is useful for RCU based
 * lockfree traversal.
 *
 * In particular, it means that we can not poison the forward
 * pointers that may still be used for walking the hash list.
 */
static inline void hlist_del_rcu(struct hlist_node *n)
{
	__hlist_del(n);
	n->pprev = LIST_POISON2;
}

static inline void hlist_del_init(struct hlist_node *n) 
{
	if (n->pprev)  {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}  

#define hlist_del_rcu_init hlist_del_init

static inline void hlist_add_head(struct hlist_node *n,struct hlist_head *h) 
{ 
	struct hlist_node *first = h->first;

	n->next = first; 
	
	if(first) 
	{
		first->pprev = &n->next;
	}
	
	h->first = n; 
	n->pprev = &h->first; 
} 

static inline void hlist_add_head_rcu(struct hlist_node *n,struct hlist_head *h) 
{ 
	struct hlist_node *first = h->first;
	n->next = first;
	n->pprev = &h->first; 
	smp_wmb();

	if(first) 
	{
		first->pprev = &n->next;
	}

	h->first = n; 
} 

/* next must be != NULL */
static inline void hlist_add_before(struct hlist_node *n,struct hlist_node *next)
{
	n->pprev = next->pprev;
	n->next = next; 
	next->pprev = &n->next; 
	*(n->pprev) = n;
}

static inline void hlist_add_after(struct hlist_node *n,struct hlist_node *next)
{
	next->next	= n->next;
	*(next->pprev)	= n;
	n->next		= next;
}

//#define hlist_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_entry(ptr, type, member) ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/* Cannot easily do prefetch unfortunately */
#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos && ({ prefetch(pos->next); 1; }); \
	     pos = pos->next) 

#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; n = pos ? pos->next : 0, pos; \
	     pos = n)

/**
 * hlist_for_each_entry	- iterate over list of given type
 * @tpos:	the type * to use as a loop counter.
 * @pos:	the &struct hlist_node to use as a loop counter.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(tpos, pos, head, member)			 \
	for (pos = (head)->first;					 \
	     pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

/**
 * hlist_for_each_entry_continue - iterate over a hlist continuing after existing point
 * @tpos:	the type * to use as a loop counter.
 * @pos:	the &struct hlist_node to use as a loop counter.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue(tpos, pos, member)		 \
	for (pos = (pos)->next;						 \
	     pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

/**
 * hlist_for_each_entry_from - iterate over a hlist continuing from existing point
 * @tpos:	the type * to use as a loop counter.
 * @pos:	the &struct hlist_node to use as a loop counter.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_from(tpos, pos, member)			 \
	for (; pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

/**
 * hlist_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @tpos:	the type * to use as a loop counter.
 * @pos:	the &struct hlist_node to use as a loop counter.
 * @n:		another &struct hlist_node to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_safe(tpos, pos, n, head, member) 		 \
	for (pos = (head)->first;					 \
	     pos && ({ n = pos->next; 1; }) && 				 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)
#endif /* __KERNEL__ */

#endif /* __MAPI_COMPAT_LIST_H_ */
