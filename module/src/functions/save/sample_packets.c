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
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/types.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *sample_packets_cache;

struct private_struct
{
	__u32 counter;
};

#define function_cb(sp) ((struct private_struct *)(((struct sample_packets_struct *)sp)->cb))

PRIVATE __u8 sample_packets_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long sample_packets(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct sample_packets_struct *sp = (struct sample_packets_struct *)pfunc->data;
	struct private_struct *cb = function_cb(sp);	
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	switch(sp->mode)
	{
		case SAMPLE_MODE_NONE:
		{
			goto drop_packet;
		}
		case SAMPLE_MODE_ALL:
		{
			goto receive_packet;
		}
		case SAMPLE_MODE_DET:
		case SAMPLE_MODE_PROB:
		{
			__u32 period = sp->period;

			if(period < 0)
			{
				goto drop_packet;
			}
			else if(period == 0)
			{
				goto receive_packet;
			}
			else
			{
				if(sp->mode == SAMPLE_MODE_DET)
				{
					if(cb->counter%period == 0)
					{
						goto receive_packet;
					}
					else 
					{
						goto drop_packet;
					}
				}
				else if(sp->mode == SAMPLE_MODE_PROB)
				{
					int rand;

					get_random_bytes(&rand,sizeof(int));
					
					if(rand%period == 0)
					{
						goto receive_packet;
					}
					else
					{
						goto drop_packet;
					}
				}
			}
		}
	
		default:
			break;
	}
	
receive_packet:
	receive(skbp,sk);
	
	return 0;
	
drop_packet:
	
	{
		struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);;

		skb_mapi->action = SKB_DROP;
	}
	
	spin_lock(&(pfunc->data_lock));
	cb->counter++;
	spin_unlock(&(pfunc->data_lock));
	
	return 0;
}

PRIVATE int add_sample_packets(struct sock *sk,struct predef_func *pfunc)
{
	struct sample_packets_struct *sp = (struct sample_packets_struct *)pfunc->data;
	struct private_struct *cb = function_cb(sp);	
	int ret;
	
	cb->counter = 0;
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		mapi_module_get(THIS_MODULE);		
	}

	return ret;
}

PRIVATE int remove_sample_packets(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	kmem_cache_free(sample_packets_cache,(void *)found->data);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);		

	return 0;
}

PRIVATE void sample_packets_init_pfunc(struct predef_func *pfunc,struct sample_packets_struct *sp)
{
	init_pfunc(pfunc);

	pfunc->type = SAMPLE_PACKETS;
	pfunc->func = sample_packets;
	pfunc->equals = sample_packets_equals;
	pfunc->data = (unsigned long)sp;
}

PRIVATE struct predef_func *pfunc_alloc_r(void)
{
	struct sample_packets_struct *sp;
	struct predef_func *pfunc;

	if((sp = kmem_cache_alloc(sample_packets_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}

	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(sample_packets_cache,sp);

		return NULL;
	}
	
	sample_packets_init_pfunc(pfunc,sp);

	return pfunc;
}

PRIVATE inline int fill_fields(struct sample_packets_struct *sp,unsigned long arg)
{
	struct sample_packets_struct *arg_sp = (struct sample_packets_struct *)arg;
	
	if(get_user(sp->period,(u32 *)(&(arg_sp->period))) ||
	   get_user(sp->mode,(u8 *)(&(arg_sp->mode))))
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
	
	if((*status = fill_fields((struct sample_packets_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(sample_packets_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int sample_packets_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSSAMPLE_PACKETS && cmd != SIOCRMSAMPLE_PACKETS)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCSSAMPLE_PACKETS:
			if((ret = add_sample_packets(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;
			
		case SIOCRMSAMPLE_PACKETS:
			ret = remove_sample_packets(sk,pfunc,1);
			break;
	}

	kmem_cache_free(sample_packets_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int sample_packets_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct sample_packets_struct *sp = NULL;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Mode  Period        \n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,SAMPLE_PACKETS);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			sp = (struct sample_packets_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  %.4d  %.12d", s, sp->mode, sp->period);

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
	index:SAMPLE_PACKETS,
	owner:THIS_MODULE,
	add:add_sample_packets,
	remove:remove_sample_packets,
	ioctl:sample_packets_ioctl,
};

int __init sample_packets_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("samplepackets", 0, proc_path, sample_packets_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file samplepackets : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((sample_packets_cache = kmem_cache_create("samplep",sizeof(struct sample_packets_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create sample_packets_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit sample_packets_exit(void)
{
	unregister_function(SAMPLE_PACKETS);
	
#ifdef CONFIG_PROC_FS
	remove_proc_entry("samplepackets",proc_path);
#endif
	if(sample_packets_cache != NULL)
	{
		if(kmem_cache_destroy(sample_packets_cache))
		{
			printk(KERN_ALERT "Error : Could not remove sample_packets_cache : %s,%i\n",__FILE__,__LINE__);
		}
	}
}

module_init(sample_packets_init);
module_exit(sample_packets_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

