/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/cache.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/sockopt.h>
#include <linux/mapi/ioctl.h>

struct predefined RegFuncs[PREDEF_MAX] __cacheline_aligned;

rwlock_t reg_funcs_lock = RW_LOCK_UNLOCKED;

PUBLIC __s8 register_function(struct predefined *fta)
{
	u8 registered = 0;
	
        if(fta->index == 0 || fta->owner == NULL)
        {
                return -EINVAL;
        }
        
	read_lock(&reg_funcs_lock);
	
	if(RegFuncs[fta->index].index != 0)
	{
		registered = 1;

		printk("Function %d already registered\n",fta->index);
	}
	
	read_unlock(&reg_funcs_lock);
	
	if(!registered)
	{
		write_lock(&reg_funcs_lock);
		RegFuncs[fta->index] = *fta;
		write_unlock(&reg_funcs_lock);
		
		return 0;
	}

	return -EALREADY;
}

PUBLIC __s8 unregister_function(__u16 index)
{	
	u8 registered = 1;
	
	read_lock(&reg_funcs_lock);
	
	if(RegFuncs[index].index == 0)
	{
		registered = 0;

		printk("Function %d not registered\n",index);
	}
	
	read_unlock(&reg_funcs_lock);
	
	if(registered)
	{
		write_lock(&reg_funcs_lock);
                memset(&RegFuncs[index],0,sizeof(RegFuncs[index]));
		write_unlock(&reg_funcs_lock);
		
		return 0;
	}

	return -EALREADY;
}

PUBLIC struct predefined *get_function(__u16 index)
{
	struct predefined *pr;
	
	read_lock(&reg_funcs_lock);
	pr = &RegFuncs[index];
	read_unlock(&reg_funcs_lock);

	return pr;
}

EXPORT_SYMBOL(register_function);
EXPORT_SYMBOL(unregister_function);
EXPORT_SYMBOL(get_function);

PUBLIC int mapi_getsockopt(struct socket *sock,int level,int optname,char *optval,int *optlen)
{
	int len;
	struct sock *sk = sock->sk;

	if(level != SOL_PACKET)
	{
		return -ENOPROTOOPT;
	}

  	if(get_user(len,optlen))
	{
  		return -EFAULT;
	}

	if(len < 0)
	{
		return -EINVAL;
	}
		
	switch(optname)	
	{
		case MAPI_STATISTICS:
		{
			struct mapi_stats stats;
			int i;
			
			if(len > sizeof(struct mapi_stats))
			{
				len = sizeof(struct mapi_stats);
			}
			
			spin_lock_bh(&mapi_sk_receive_queue(sk).lock);
			stats = mapi_sk(sk)->mapistats;
			memset(&mapi_sk(sk)->mapistats,0,sizeof(stats));
			spin_unlock_bh(&mapi_sk_receive_queue(sk).lock);
			
			for( i = 0 ; i < (MAX_MAPI_STATISTICS - 1) ; i++)
			{
				stats.pkttype[MAX_MAPI_STATISTICS - 1].p_recv += stats.pkttype[i].p_recv;
				stats.pkttype[MAX_MAPI_STATISTICS - 1].p_processed += stats.pkttype[i].p_processed;
				stats.pkttype[MAX_MAPI_STATISTICS - 1].p_queued += stats.pkttype[i].p_queued;
				stats.pkttype[MAX_MAPI_STATISTICS - 1].p_dropped += stats.pkttype[i].p_dropped;
				stats.pkttype[MAX_MAPI_STATISTICS - 1].p_dropped_by_filter += stats.pkttype[i].p_dropped_by_filter;
			}
			
			if(copy_to_user(optval,&stats,len))
			{
				return -EFAULT;
			}

			break;
		}
		default:
			return -ENOPROTOOPT;
	}

  	if(put_user(len,optlen))
	{
  		return -EFAULT;
	}

  	return 0;
}

EXPORT_SYMBOL(mapi_ioctl);

PUBLIC int mapi_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct predefined *pr;
	int ret;
	int i;

	for( i = 1 ; i < PREDEF_MAX ; i++)
	{
		if(likely((pr = get_function(i)) != NULL))
		{
			if(likely(pr->ioctl != NULL))
			{
                                if((ret = mapi_module_get(pr->owner)) != 0)
                                {
                                        return ret;
                                }

				if((ret = (*(pr->ioctl))(sock,cmd,arg)) != NRIOCTL)
				{
                                        mapi_module_put(pr->owner);
					
                                        return ret;
				}
                                
                                mapi_module_put(pr->owner);
			}
		}
	}
        
	return -EOPNOTSUPP;
}

EXPORT_SYMBOL(remove_all_func);

PUBLIC void remove_all_func(struct sock *sk)
{
	struct predef_func *cur;
	struct packet_opt *popt;
	struct predefined *pr;

	popt = mapi_sk(sk);

	write_lock(&(popt->pfunc_list_lock));
	
	for( cur = popt->pfunc_list ; cur != NULL ; cur = cur->next)
	{
		if((pr = get_function(cur->type)) != NULL)
		{
			if(pr->remove != NULL)
			{
				if((*(pr->remove))(sk,cur,0) != 0)
                                {
                                        printk(KERN_EMERG "Could not remove function (type = %u)\n",cur->type);
                                }
			}
		}
	}
	
	write_unlock(&(popt->pfunc_list_lock));
}

EXPORT_SYMBOL(load_module_if_necessary);

PUBLIC __u8 load_module_if_necessary(char *module_name,__u16 index)
{
	if(get_function(index) == NULL)
	{
		if(request_module(module_name))
		{
			printk(KERN_EMERG "Failed to load module %s\n",module_name);
		}
		
		return 1;
	}

	return 0;
}

// vim:ts=8:expandtab

