/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_COMMON_H
#define __MAPI_COMMON_H

#include <linux/config.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/proc_fs.h>
#include <linux/if_ether.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/spinlock.h>

#include <linux/mapi/compat.h>

#define PRIVATE static
#define PUBLIC

#ifdef __KERNEL__

#define NRIOCTL 1234

extern struct proc_dir_entry *proc_path;
extern kmem_cache_t *predef_func_cache;

struct predef_func
{
	u16			type;
	struct predef_func	*next;
	struct predef_func	*tnext;
	
	unsigned long		data;
	spinlock_t		data_lock;

	unsigned long (*func)(struct sk_buff **,struct sock *,struct predef_func *pfunc);
	u8 (*equals)(const struct predef_func *fpf,const struct predef_func *spf);
};

struct predefined
{
	u32 index;
	struct module *owner;
	
	int (*add)(struct sock *sk,struct predef_func *pfunc);
	int (*remove)(struct sock *sk,struct predef_func *pfunc,int lock);
	int (*ioctl)(struct socket *sock,unsigned int cmd,unsigned long arg);
	int (*info)(struct predef_func *pfunc,char *msg,size_t msg_size,u8 verbosity);
};

s8 register_function(struct predefined *fta);
s8 unregister_function(u16 index);
struct predefined *get_function(__u16 index);
u8 load_module_if_necessary(char *module_name,u16 index);

void __sk_run_predef(struct sk_buff **skb,struct sock *sk);
int __sk_attach_predef(struct sock *sk,const struct predef_func *pfunc);
int __sk_attach_predef_head(struct sock *sk,const struct predef_func *pfunc);
struct predef_func *__sk_detach_predef(struct sock *sk,const struct predef_func *pfunc);
struct predef_func *__sk_find_predef(const struct sock *sk,const struct predef_func *pfunc);
struct predef_func *__sk_find_type(struct sock *sk,u16 type);
struct predef_func *__sk_find_last_predef(const struct sock *sk,u16 type);

void sk_run_predef(struct sk_buff **skb,struct sock *sk);
int sk_attach_predef(struct sock *sk,const struct predef_func *pfunc);
int sk_attach_predef_head(struct sock *sk,const struct predef_func *pfunc);
struct predef_func *sk_detach_predef(struct sock *sk,const struct predef_func *pfunc);
struct predef_func *sk_find_predef(const struct sock *sk,const struct predef_func *pfunc);
struct predef_func *sk_find_type(struct sock *sk,u16 type);
struct predef_func *sk_find_last_predef(const struct sock *sk,u16 type);

#ifdef CONFIG_MAPI_MMAP
void receive_mmap(struct sk_buff **skbp,struct sock *sk);
#endif
void receive_nommap(struct sk_buff **skbp,struct sock *sk);
void receive(struct sk_buff **skbp,struct sock *sk);

struct sk_buff *mapi_skb_private(struct sk_buff **skbp,struct sock *sk);

void reset_net_dev_stats(void);

static inline void init_pfunc(struct predef_func *pfunc)
{
	memset(pfunc,0,sizeof(struct predef_func));

	spin_lock_init(&pfunc->data_lock);
}

struct hlist_head *get_active_socket_list(void);
void lock_active_socket_list(void);
void unlock_active_socket_list(void);

/* 
 *      Enable debug/info messages 
 */
#ifdef DEBUG
#define MAPI_DEBUG(x)     do { } while (0)
#else
#define MAPI_DEBUG(x)     do { x; } while (0)
#endif

static inline char *get_info(struct predef_func *pfunc,char *info,size_t info_size,u8 verbosity)
{
	struct predefined *pr;

	if((pr = get_function(pfunc->type)) != NULL)
	{
		if(pr->info != NULL)
		{
			(*(pr->info))(pfunc,info,info_size,verbosity);
		}
		else
		{
			snprintf(info,info_size,"Unavailable");
		}
	}
	else
	{
		snprintf(info,info_size,"Unavailable (No such function)");
	}

	return info;
}

#endif /* __KERNEL__ */

#endif /* __MAPI_COMMON_H */

