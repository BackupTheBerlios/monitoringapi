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
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <linux/smp_lock.h>
#include <linux/tqueue.h>
#include <net/sock.h>
#include <linux/ctype.h>
#include <linux/tqueue.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

#include <fakepcap.h>
#include <file_ops.h>

#define DEFAULT_SNAPLEN 64

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *logging_cache;
PRIVATE kmem_cache_t *write_cache;
PRIVATE kmem_cache_t *tq_struct_cache;

struct private_struct
{
	unsigned long filp;
};

#define function_cb(ls) ((struct private_struct *)(((struct logging_struct *)ls)->cb))

PRIVATE __u8 logging_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	if(fpf->type == spf->type)
	{	
		return 1;
	}

	return 0;
}

struct wp_data
{
	struct sk_buff *skb;
	struct logging_struct *ls;
	struct tq_struct *task;
	struct wp_data *this;
};

PRIVATE void write_packet(void *data)
{
	struct wp_data 		*wpd	= (struct wp_data *)data;
	struct logging_struct	*ls	= wpd->ls;
	struct private_struct	*cb	= function_cb(ls);	
	struct file		*filp	= (struct file *)cb->filp;
	struct tq_struct	*write_task	= wpd->task;
	struct sk_buff 		*skb	= wpd->skb;
	mm_segment_t		oldfs;
	
	if(filp == NULL)
	{
		return;
	}
	
	lock_kernel();
	
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	
	if((filp->f_op != NULL) && (filp->f_op->write != NULL))
	{
		fake_pcap_write_packet(filp,skb,ls->snaplen);
	}
	
	set_fs(oldfs);

	unlock_kernel();
	
	ls->packets_logged++;
	ls->file_size += (skb->len);

	kfree_skb(skb);
	
	kmem_cache_free(write_cache,wpd->this);
	kmem_cache_free(tq_struct_cache,write_task);
}

PRIVATE unsigned long logging(struct sk_buff **skb,struct sock *sk,struct predef_func *pfunc)
{
	struct logging_struct *ls = (struct logging_struct *)pfunc->data;
	struct tq_struct *write_task;
	struct wp_data *wpd;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	if((write_task = kmem_cache_alloc(tq_struct_cache,GFP_ATOMIC)) == NULL)
	{
		return -ENOMEM;
	}
	
	if((wpd = kmem_cache_alloc(write_cache,GFP_ATOMIC)) == NULL)
	{
		return -ENOMEM;
	}

	wpd->skb = *skb;
	wpd->ls = ls;
	wpd->task = write_task;
	wpd->this = wpd;
	
	write_task->sync = 0;
	write_task->data = wpd;
	write_task->routine = write_packet;
	
	skb_get(*skb);
	
	schedule_task(write_task);
	
	return 0;
}

PRIVATE int add_logging(struct sock *sk,struct predef_func *pfunc)
{
	struct logging_struct *ls = (struct logging_struct *)pfunc->data;
	struct private_struct *cb = function_cb(ls);	
	struct file *file;
	int ret = 0;
	
	if(ls->snaplen <= 0)
	{
		ls->snaplen = DEFAULT_SNAPLEN;
	}
	
	ls->file_size = 0;
	ls->packets_logged = 0;
	
	cb->filp = 0;
	
	if((file = create_file(ls->filename,&ret)) == NULL)
	{
		return ret;
	}
	
	if((ret = fake_pcap_write_file_header(file,ls->encap_type,ls->snaplen)) != 0)
	{
		return ret;
	}
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{
		cb->filp = (unsigned long)file;
		
		mapi_module_get(THIS_MODULE);
	}

	return ret;
}

PRIVATE int remove_logging(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct logging_struct *ls;
	struct private_struct *cb;
	
	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);
	
	if(found == NULL)
	{
		return -ENODATA;
	}
	
	ls = (struct logging_struct *)found->data;
	cb = function_cb(ls);

	close_file((struct file *)cb->filp);
	
	kfree(ls->filename);
	kmem_cache_free(logging_cache,ls);
	kmem_cache_free(predef_func_cache,found);
	
	mapi_module_put(THIS_MODULE);
	
	return 0;
}

PRIVATE int reset_logging(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct logging_struct *ls;
	struct private_struct *cb;	
	int ret = 0;
	
	found = sk_find_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}

	ls = (struct logging_struct *)found->data;
	cb = function_cb(ls);
	
	if((ret = truncate_file((struct file *)cb->filp)) != 0)
	{
		return ret;
	}

	return ret;
}

PRIVATE struct logging_struct *getresults_logging(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;
	struct logging_struct *ls;
	
	found = sk_find_predef(sk,pfunc);
	
	if(found == NULL)
	{
		return NULL;
	}
	
	ls = (struct logging_struct *)found->data;	
	
 	return ls;
}

PRIVATE void logging_init_pfunc(struct predef_func *pfunc,struct logging_struct *ls)
{
	init_pfunc(pfunc);

	pfunc->type = LOGGING;
	pfunc->func = logging;
	pfunc->equals = logging_equals;
	pfunc->data = (unsigned long)ls;
}

PRIVATE struct predef_func *pfunc_alloc_r()
{
	struct logging_struct *ls;
	struct predef_func *pfunc;

	if((ls = kmem_cache_alloc(logging_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(logging_cache,ls);

		return NULL;
	}
	
	logging_init_pfunc(pfunc,ls);

	return pfunc;
}

PRIVATE inline int fill_fields(struct logging_struct *ls,unsigned long arg)
{
	if(get_user(ls->length,(__u32 *)(&(((struct logging_struct *)arg)->length))))
	{
		return -EFAULT;
	}
	
	if((ls->filename = kmalloc(ls->length,GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	if(copy_from_user(ls->filename,((struct logging_struct *)arg)->filename,ls->length))
	{
		kfree(ls->filename);
		
		return -EFAULT;
	}
	
	if(get_user(ls->snaplen,(__u16 *)(&(((struct logging_struct *)arg)->snaplen))) ||
	   get_user(ls->encap_type,(int *)(&(((struct logging_struct *)arg)->encap_type))))
	{
		return -EFAULT;
	}

	return 0;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	struct logging_struct *ls;
				
	if((ls = getresults_logging(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{	
		if(put_user(ls->file_size,(__u32 *)(&(((struct logging_struct *)arg)->file_size))) ||
		   put_user(ls->packets_logged,(__u32 *)(&(((struct logging_struct *)arg)->packets_logged))))
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
	
	if((*status = fill_fields((struct logging_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(logging_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int logging_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSLOGGING && cmd != SIOCGLOGGING && cmd != SIOCRSLOGGING && cmd != SIOCRMLOGGING)
	{
		return ret;
	}
	
	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCSLOGGING:
			if((ret = add_logging(sk,pfunc)) != 0)
			{
				break;
			}
			
			return ret;

		case SIOCGLOGGING:
			ret = put_fields_to_userspace(sk,pfunc,arg);
			break;

		case SIOCRSLOGGING:
			ret = reset_logging(sk,pfunc);
			break;

		case SIOCRMLOGGING:
			ret = remove_logging(sk,pfunc,1);
			break;
	}

	kfree(((struct logging_struct *)pfunc->data)->filename);
	kmem_cache_free(logging_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int logging_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;
	int i;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct logging_struct *ls = NULL;
	struct hlist_node *node;
	
	len += sprintf(buffer,"Sock      Size        Packets     Filename\n");
	
	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,LOGGING);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			ls = (struct logging_struct *)cur->data;

			len += sprintf(buffer + len,"%8p  %.10d  %.10d  ", s, ls->file_size, ls->packets_logged);
			
			for( i = 0 ; i < ls->length; i++)
			{
				buffer[i+len] = ls->filename[i];
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
	index:LOGGING,
	owner:THIS_MODULE,
	add:add_logging,
	remove:remove_logging,
	ioctl:logging_ioctl,
};

int __init logging_init()
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("logging", 0, proc_path, logging_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file logging : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}

#endif
	if((logging_cache  = kmem_cache_create("logging",sizeof(struct logging_struct),0,0,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create logging_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}

	if((write_cache = kmem_cache_create("wrtask",sizeof(struct wp_data),0,0,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create write_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((tq_struct_cache = kmem_cache_create("tq_struct",sizeof(struct tq_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create tq_struct_cache : %s,%i\n",__FILE__,__LINE__);
		
		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}
	
	return 0;
}

void __exit logging_exit()
{
	unregister_function(LOGGING);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("logging",proc_path);
#endif
	if(kmem_cache_destroy(logging_cache))
	{
		printk(KERN_ALERT "Error : Could not remove logging_cache : %s,%i\n",__FILE__,__LINE__);
	}

	if(kmem_cache_destroy(write_cache))
	{
		printk(KERN_ALERT "Error : Could not remove write_cache : %s,%i\n",__FILE__,__LINE__);
	}

	if(kmem_cache_destroy(tq_struct_cache))
        {
                printk(KERN_ALERT "Error : Could not remove tq_struct_cache : %s,%i\n",__FILE__,__LINE__);
        }
}

module_init(logging_init);
module_exit(logging_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

