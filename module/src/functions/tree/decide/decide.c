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
#include <linux/timer.h>
#include <asm/atomic.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/timeval.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

#include <decide.h>
#include <decide_hook.h>

#define DEBUG_DECIDE

PRIVATE inline struct predef_func *get_pfunc(unsigned long arg,int *status);

PUBLIC kmem_cache_t *decide_cache;

EXPORT_SYMBOL(get_decide_hook);

PRIVATE atomic_t uid_nr = ATOMIC_INIT(0);

struct private_struct
{
	struct socket *left_sock;
	struct socket *right_sock;

	struct decide_hook *dhook;

	__u32 left_decisions;
	__u32 right_decisions;
	__u32 both_decisions;
};

#define function_cb(ds) ((struct private_struct *)(((struct decide_struct *)ds)->cb))

PUBLIC struct decide_hook **get_decide_hook(struct decide_struct *ds)
{
	return &(function_cb(ds)->dhook);
}

PUBLIC struct socket *get_left_socket(struct decide_struct *ds)
{
	struct private_struct *cb = function_cb(ds);

	return cb->left_sock;
}

PUBLIC struct socket *get_right_socket(struct decide_struct *ds)
{
	struct private_struct *cb = function_cb(ds);

	return cb->right_sock;
}

PRIVATE inline void run_predef(struct sk_buff **skbp,struct predef_func *pfunc,struct sock *sk)
{
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	skb_mapi->action = SKB_PROCESS;
	
	for( prefetch(pfunc->next) ; (pfunc != NULL) && (*skbp != NULL) ; 
	     pfunc = pfunc->next,prefetch(pfunc->next))
	{
		if(unlikely(pfunc->func == NULL))
		{
			continue;
		}
		
		if(unlikely((*(pfunc->func))(skbp,sk,pfunc) != 0))
		{
			printk(KERN_EMERG "Error while running functions\n");
			printk(KERN_EMERG "Removing all functions\n");
			
			remove_all_func(sk);
		}
	}
}

#define NULL_GAP	"            "
#define MAX_HEIGHT	5

PRIVATE void print_decide_node(struct decide_struct *ds,__u32 level,__u8 direction)
{
	int i;

	for( i = 0 ; i < level ; i++)
	{
		printk(NULL_GAP);
	}
	
	printk("%s",ds->debug_info);
	
	for( i = 0 ; i < MAX_HEIGHT - level ; i++)
	{
		printk("\n");
	}
}

PRIVATE void print_decide_tree(struct predef_func *ds_pfunc,__u32 level,__u8 direction)
{
	struct predef_func *left_pfunc_list;
	struct predef_func *right_pfunc_list;
	struct decide_struct *ds;
	struct private_struct *cb;

	if(ds_pfunc == NULL)
	{
		return;
	}
	
	ds = (struct decide_struct *)ds_pfunc->data;
	cb = function_cb(ds);

	left_pfunc_list = sk_find_type(cb->left_sock->sk,DECIDE);
	right_pfunc_list = sk_find_type(cb->right_sock->sk,DECIDE);
	
	print_decide_tree(right_pfunc_list,level + 1,DIRECTION_RIGHT);
	print_decide_node(ds,level,direction);
	print_decide_tree(left_pfunc_list,level + 1,DIRECTION_LEFT);
}

PRIVATE int print_decide(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	printk("\n");
	print_decide_tree(found,0,DIRECTION_RIGHT);
	
	return 0;
}

PRIVATE inline void update_stats(struct predef_func *pfunc,int decision)
{
#ifdef DEBUG_DECIDE
	struct private_struct *cb = function_cb(((struct decide_struct *)pfunc->data));

	if(decision == DECIDE_LEFT)
	{
		spin_lock(&(pfunc->data_lock));
		{
			cb->left_decisions++;
		}
		spin_unlock(&(pfunc->data_lock));
	}
	else if(decision == DECIDE_RIGHT)
	{
		spin_lock(&(pfunc->data_lock));
		{
			cb->right_decisions++;
		}
		spin_unlock(&(pfunc->data_lock));
	}
	else if(decision == DECIDE_BOTH)
	{
		spin_lock(&(pfunc->data_lock));
		{
			cb->both_decisions++;
		}
		spin_unlock(&(pfunc->data_lock));
	}
#endif	
}

PRIVATE __u8 decide_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	struct decide_struct *fds = (struct decide_struct *)fpf->data;
	struct decide_struct *sds = (struct decide_struct *)spf->data;
	
	if((fpf->type == spf->type) && (fds->uid == sds->uid))
	{
		return 1;
	}
	
	return 0;
}

PRIVATE unsigned long decide(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct private_struct *cb = function_cb(((struct decide_struct *)pfunc->data));

	if(unlikely(cb->dhook == NULL))
	{
		MAPI_DEBUG(if(net_ratelimit()) printk("DECIDE : No decide hook found\n"));

		return 0;
	}

	switch((*(cb->dhook->skb_hook))(*skbp,cb->dhook->data))
	{
		case DECIDE_LEFT:
		{
			run_predef(skbp,mapi_sk(cb->left_sock->sk)->pfunc_list,sk);
			update_stats(pfunc,DECIDE_LEFT);
			
			break;
		}
		case DECIDE_RIGHT:
		{
			run_predef(skbp,mapi_sk(cb->right_sock->sk)->pfunc_list,sk);
			update_stats(pfunc,DECIDE_RIGHT);

			break;
		}
		case DECIDE_BOTH:
		{
			run_predef(skbp,mapi_sk(cb->left_sock->sk)->pfunc_list,sk);
			run_predef(skbp,mapi_sk(cb->right_sock->sk)->pfunc_list,sk);
			update_stats(pfunc,DECIDE_BOTH);

			break;
		}
		default:
		{
			MAPI_DEBUG(if(net_ratelimit()) printk("DECIDE : No such action\n"));
		}
	}

	return 0;
}

PRIVATE struct socket *init_socket_struct(void)
{
	struct socket *sock;
	struct sock *sk;
	int ret;
	
	if((sock = kmalloc(sizeof(struct socket),GFP_KERNEL)) == NULL)
	{
		return NULL;
	}

	if((sk = mapi_sk_alloc()) == NULL)
	{
		kfree(sock);
		
		return NULL;
	}

	mapi_sk(sk) = kmalloc(sizeof(struct packet_opt),GFP_KERNEL);
	
        if(mapi_sk(sk) == NULL)
        {
	        sk_free(sk);
		kfree(sock);
	
		return NULL;
        }
        
	memset(mapi_sk(sk),0,sizeof(struct packet_opt));

	sock->sk = sk;
	mapi_sk_socket(sk) = sock;
	mapi_sk_user_data(sk) = NULL;
	
	if((ret = init_when_create_sock(sk)) != 0)
	{
		kfree(mapi_sk(sk));
		sk_free(sk);
		kfree(sock);
		
		return NULL;
	}

	return sock;
}

PRIVATE void deinit_socket_struct(struct socket *sock)
{
	struct sock *sk = sock->sk;
	
	do_when_destruct_sock(sk);
	
	kfree(mapi_sk(sk));
	sk_free(sk);
	kfree(sock);
}

PRIVATE int add_decide(struct sock *sk,struct predef_func *pfunc)
{
	struct decide_struct *ds = (struct decide_struct *)pfunc->data;
	struct private_struct *cb = function_cb(ds);
	int ret;
	
	ds->uid = atomic_read(&uid_nr);
	
	memset(cb,0,sizeof(*cb));
	
	if((cb->left_sock = init_socket_struct()) == NULL)
	{
		return -ENOMEM;
	}
	
	if((cb->right_sock = init_socket_struct()) == NULL)
	{
		deinit_socket_struct(cb->left_sock);
		
		return -ENOMEM;
	}
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		struct sock *real_sk;
		
		atomic_inc(&(uid_nr));
		
		mapi_module_get(THIS_MODULE);
		
		real_sk = ((struct sock *)mapi_sk_user_data(sk) == NULL) ? sk : (struct sock *)mapi_sk_user_data(sk);
	
		if((ret = register_decide_proxy(real_sk,mapi_sk_socket(sk),ds)) != 0)
		{
			return ret;
		}
	}
	else
	{
		deinit_socket_struct(cb->left_sock);
		deinit_socket_struct(cb->right_sock);
	}

	return ret;
}

PRIVATE int remove_decide(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct decide_struct *ds;
	struct private_struct *cb;
	struct sock *real_sk;
	int ret;
	
	real_sk = ((struct sock *)mapi_sk_user_data(sk) == NULL) ? sk : (struct sock *)mapi_sk_user_data(sk);

	ds = (struct decide_struct *)pfunc->data;
	
	if((ret = unregister_decide_proxy(real_sk,ds->uid)) != 0)
	{
		//do nothing
	}

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	ds = (struct decide_struct *)found->data;
	cb = function_cb(ds);
	
	remove_all_func(cb->left_sock->sk);
	remove_all_func(cb->right_sock->sk);
	
	deinit_socket_struct(cb->left_sock);
	deinit_socket_struct(cb->right_sock);

	kmem_cache_free(decide_cache,ds);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return ret;
}

PRIVATE int info_decide(struct predef_func *pfunc,char *msg,size_t msg_size,u8 verbosity)
{
	struct decide_struct *ds;
	struct private_struct *cb;
	int len;
	
	if(pfunc->type != DECIDE)
	{
		return snprintf(msg,msg_size,"BUG : expected %u , found %u",DECIDE,pfunc->type);	
	}
	
	ds = (struct decide_struct *)pfunc->data;
	cb = function_cb(ds);

	if(verbosity == 0)
	{
		len = snprintf(msg,msg_size,"Uid : %d , LPr : %d , RPr : %d , LSock : %p , RSock :%p",
			       ds->uid,
			       atomic_read(&(mapi_sk(cb->left_sock->sk)->predef_func_nr)),
			       atomic_read(&(mapi_sk(cb->right_sock->sk)->predef_func_nr)),
			       cb->left_sock,
			       cb->right_sock
			       );
	}
	else
	{
		len = snprintf(msg,msg_size,"LDec : %u , RDec : %u , BDec %u",
			       cb->left_decisions,
			       cb->right_decisions,
			       cb->both_decisions
			       );
	}

	return len;
}

PRIVATE int io_decide(struct sock *real_sk,struct sock *virtual_sk,unsigned long arg)
{
	struct decide_struct *arg_ds;
	struct predef_func *pfunc;
	struct predef_func *found;
	struct decide_struct *ds;
	struct private_struct *cb;
	int ret;

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}
	
	arg_ds = (struct decide_struct *)pfunc->data;
	
	if((found = sk_find_predef(virtual_sk,pfunc)) == NULL)
	{
		ret = -ENODATA;

		goto error;
	}
	
	ds = (struct decide_struct *)found->data;
	cb = function_cb(ds);
	
	if(arg_ds->ioctl.cmd == SIOCIODECIDE)
	{
		ret = -ENOTSUPP;
		
		goto error;
	}
	
	if(arg_ds->ioctl.direction == DIRECTION_LEFT)
	{
		mapi_sk_user_data(cb->left_sock->sk) = real_sk;
		
		if((ret = mapi_ioctl(cb->left_sock,arg_ds->ioctl.cmd,(unsigned long)(arg_ds->ioctl.arg))) != 0)
		{
			goto error;
		}
	}
	else
	{
		mapi_sk_user_data(cb->right_sock->sk) = real_sk;
		
		if((ret = mapi_ioctl(cb->right_sock,arg_ds->ioctl.cmd,(unsigned long)(arg_ds->ioctl.arg))) != 0)
		{
			goto error;
		}
	}
	
error:	
	kmem_cache_free(decide_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);
	
	return ret;
}

PRIVATE inline void decide_init_pfunc(struct predef_func *pfunc,struct decide_struct *ds)
{
	init_pfunc(pfunc);
	
	pfunc->type = DECIDE;
	pfunc->data = (unsigned long)ds;
	pfunc->func = decide;
	pfunc->equals = decide_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct decide_struct *ds;
	struct predef_func *pfunc;

	if((ds = kmem_cache_alloc(decide_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(decide_cache,ds);

		return NULL;
	}

	decide_init_pfunc(pfunc,ds);

	return pfunc;
}

PRIVATE inline int fill_fields(struct decide_struct *ds,unsigned long arg)
{
	struct decide_struct *arg_ds = (struct decide_struct *)arg;
	
	if(copy_from_user(ds,arg_ds,sizeof(*ds) - sizeof(ds->cb)))
	{
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
	
	if((*status = fill_fields((struct decide_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(decide_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int decide_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSDECIDE && cmd != SIOCRMDECIDE && cmd != SIOCDBDECIDE)
	{
		return ret;
	}

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCSDECIDE:
			{
				struct decide_struct *ds;
				struct decide_struct *arg_ds;
				
				if((ret = add_decide(sk,pfunc)) != 0)
				{
					break;
				}
				
				ds = (struct decide_struct *)pfunc->data;
				arg_ds = (struct decide_struct *)arg;
					
				if(put_user(ds->uid,(u16 *)&(arg_ds->uid)))
				{
					return -EFAULT;
				}

				return ret;
			}

		case SIOCRMDECIDE:
			ret = remove_decide(sk,pfunc,1);
			break;
		
		case SIOCDBDECIDE:
			ret = print_decide(sk,pfunc);
			break;
	}

	kmem_cache_free(decide_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

PUBLIC int decide_intercept_ioctl(struct socket *real_sock,struct socket *virtual_sock,unsigned long arg)
{
	return io_decide(real_sock->sk,virtual_sock->sk,arg);
}

#ifdef CONFIG_PROC_FS
PRIVATE int decide_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct decide_struct *ds = NULL;
	struct private_struct *cb;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      LPredef RPredef LDecisions RDecisions BDecisions\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,DECIDE);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			ds = (struct decide_struct *)cur->data;
			cb = function_cb(ds);

			len += sprintf(buffer + len,"%8p  %-7u %-7u %-10u %-10u %-10u\n",s,
				       atomic_read(&(mapi_sk(cb->left_sock->sk)->predef_func_nr)),
				       atomic_read(&(mapi_sk(cb->right_sock->sk)->predef_func_nr)),
				       cb->left_decisions,
				       cb->right_decisions,
				       cb->both_decisions
				       );

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
	index:DECIDE,
	owner:THIS_MODULE,
	add:add_decide,
	remove:remove_decide,
	ioctl:decide_ioctl,
	info:info_decide,
};

int __init decide_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("decide", 0, proc_path, decide_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file decide : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((decide_cache = kmem_cache_create("decide",sizeof(struct decide_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create decide_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return decide_proxy_init();
}

void __exit decide_exit(void)
{
	unregister_function(DECIDE);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("decide",proc_path);
#endif

	if(kmem_cache_destroy(decide_cache))
	{
		printk(KERN_ALERT "Error : Could not remove decide_cache : %s,%i\n",__FILE__,__LINE__);
	}

	decide_proxy_exit();
}

module_init(decide_init);
module_exit(decide_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

