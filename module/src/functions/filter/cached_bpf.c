/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>

#if defined(CONFIG_FILTER) && defined(CONFIG_CACHED_BPF)

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
#include <linux/compiler.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/timeval.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

#include <cached_bpf.h>

#define CACHE_DEBUG
#define CACHE_STATISTICS

EXPORT_NO_SYMBOLS;

PRIVATE kmem_cache_t *cached_bpf_filter_cache;
PRIVATE atomic_t uid_nr = ATOMIC_INIT(0);

PRIVATE unsigned short nbo_eth_ip;
PRIVATE const u16 ip_offset = ETH_HLEN + 12 + 3;	//last byte of src ip address

#define function_cb(bpf) ((struct private_struct *)(((struct cached_bpf_filter_struct *)bpf)->cb))

PRIVATE void do_skb_trim(struct sk_buff *skb,int len)
{
	if(skb->len > len)
	{
		skb->len = len;
		skb->tail = skb->data + len;
	}
}

PRIVATE inline void print_cache_hit_info(const struct private_struct *cb,const struct sk_buff *skb,struct filter_cache_slot *cache_slot)
{
	struct filter_mem_accesses *fmem_accesses = cb->fmem_accesses;
	struct filter_cache *fcache = cb->fcache;
	u16 *locations = fmem_accesses->locations;
	u8 *cached_fields = cache_slot->fields;
	u8 *data = skb->data;
	u16 nolocations = fmem_accesses->nolocations;
	u16 min,i;
	
	min = (skb->len > locations[nolocations - 1]) ? locations[nolocations - 1] : skb->len;

	printk("Packet searched : \n");
	
	for( i = 0 ; i < min ; i++ )
	{
		printk("(%.2d)%.2x ",i,data[i]);
	}
	
	printk("\nPacket found (hit no %lld): \n",fcache->hits);
	
	for( i = 0 ; i < nolocations ; i++ )
	{
		printk("(%.2d)%.2x ",locations[i],cached_fields[i]);
	}
	 
	printk("\n");
}

PRIVATE inline void print_cache_miss_info(const struct private_struct *cb,const struct sk_buff *skb)
{
	struct filter_mem_accesses *fmem_accesses = cb->fmem_accesses;
	struct filter_cache *fcache = cb->fcache;
	u16 *locations = fmem_accesses->locations;
	u8 *data = skb->data;
	u16 nolocations = fmem_accesses->nolocations;
	u16 min,i;
	
	min = (skb->len > locations[nolocations - 1]) ? locations[nolocations - 1] : skb->len;
	
	printk("\nPacket not found (miss no %lld): \n",fcache->misses);

	for( i = 0 ; i < min ; i++ )
	{
		printk("(%.2d)%.2x ",i,data[i]);
	}
	 
	printk("\n");
}

PRIVATE inline struct filter_cache_slot *is_in_cache(const struct sk_buff *skb,const struct private_struct *cb)
{
	const struct filter_mem_accesses *fmem_accesses = cb->fmem_accesses;
	const struct filter_cache *fcache = cb->fcache;
	const u8 *data = skb->data;
	const struct filter_cache_slot *cache_slot =  fcache->cache[(u8)data[ip_offset] & MAX_FILTER_CACHE_MASK];
	const u16 *locations = fmem_accesses->locations;
	const u8 *cached_fields = cache_slot->fields;
	register u16 nolocations = fmem_accesses->nolocations;
	register u16 i;
	
	for(i = 0 ; i < nolocations ; i++)
	{
		if(data[locations[i]] != cached_fields[i])
		{
			goto not_found;
		}
	}
	
	return (struct filter_cache_slot *)cache_slot;
	
not_found:
	
	return NULL;
}

PRIVATE inline void add_to_cache(const struct filter_cache *fcache,const struct filter_mem_accesses *fmem_accesses,const struct sk_buff *skb,int result)
{
	const u8 *data = skb->data;
	struct filter_cache_slot *cache_slot = fcache->cache[(u8)data[ip_offset] & MAX_FILTER_CACHE_MASK];
	const u16 *locations = fmem_accesses->locations;
	u8 *cached_fields = cache_slot->fields;
	u16 nolocations = fmem_accesses->nolocations;
	register u16 i;
	
	if(skb->len < locations[nolocations - 1])
	{
		return;
	}
	
	cache_slot->result = result;
	
	for( i = 0 ; i < nolocations ; i++)
	{
		cached_fields[i] = data[locations[i]];
	}
}

PRIVATE inline int run_mapi_filter_with_cache(const struct private_struct *cb,const struct sk_buff *skb,const struct sock_filter *filter,int flen)
{
	struct filter_cache *fcache = cb->fcache;
	struct filter_cache_slot *cached_slot;
	int result;
	
	if(skb->protocol != nbo_eth_ip)
	{
		return sk_run_filter((struct sk_buff *)skb,(struct sock_filter *)filter,flen);
	}
	
	if(likely((cached_slot = is_in_cache(skb,cb)) != NULL))
	{
#ifdef CACHE_STATISTICS
		fcache->hits++;
#endif
#ifdef CACHE_DEBUG		
		print_cache_hit_info(cb,skb,cached_slot);
#endif
		return cached_slot->result;
	}

#ifdef CACHE_STATISTICS
		fcache->misses++;
#endif
#ifdef CACHE_DEBUG
	print_cache_miss_info(cb,skb);
#endif
	result = sk_run_filter((struct sk_buff *)skb,(struct sock_filter *)filter,flen);

	add_to_cache(fcache,cb->fmem_accesses,skb,result);
	
	return result;
}

PRIVATE inline int run_mapi_filter_without_cache(const struct private_struct *cb,const struct sk_buff *skb,const struct sock_filter *filter,int flen)
{
	return sk_run_filter((struct sk_buff *)skb,(struct sock_filter *)filter,flen);
}

PRIVATE inline int run_mapi_filter(const struct private_struct *cb,const struct sk_buff *skb,const struct sock_filter *filter,int flen)
{
	struct filter_cache *fcache = cb->fcache;
	
	return (*(fcache->run_mapi_filter))(cb,skb,filter,flen);
}

PRIVATE inline void reset_filter_cache(struct filter_cache *fcache)
{
	register u16 i;
		
	for( i = 0 ; i < MAX_FILTER_CACHE_SLOTS ; i++)
	{
		fcache->cache[i] = NULL;
	}
	
	for( i = 0 ; i < MAX_FILTER_CACHE_SLOTS ; i++)
	{
		memset(fcache->hw_cache_lines[i],0,L1_CACHE_BYTES);
	}
	
	fcache->hits = 0;
	fcache->misses = 0;
	fcache->slot_size = 0;
	fcache->run_mapi_filter = NULL;
}

PRIVATE inline void setup_filter_cache(struct filter_cache *fcache,int nolocations)
{
	u16 slots_per_hw_cache_line;
	u16 slot_size;
	u16 i,j;
	
	slot_size = nolocations + sizeof(struct filter_cache_slot);
	
	for( i = 0 ; (slot_size%FILTER_CACHE_SLOTS_ALIGN) != 0 ; i++)
	{
		slot_size++;
	}
	
	fcache->slot_size = slot_size;
	
	slots_per_hw_cache_line = L1_CACHE_BYTES/fcache->slot_size;
	
#ifdef CACHE_STATISTICS	
	printk("Hw cache line size is %d bytes\n",L1_CACHE_BYTES);
	printk("Filter cache slot size is %d bytes\n",slot_size);
	printk("Filter cache slots/Hw cache line = %d\n",slots_per_hw_cache_line);
#endif	
	
	for( i = 0 ; i < MAX_FILTER_CACHE_SLOTS ; i++)
	{
		for( j = 0 ; j < slots_per_hw_cache_line && (i + j) < MAX_FILTER_CACHE_SLOTS ; j++)
		{
			fcache->cache[i+j] = (struct filter_cache_slot *)(fcache->hw_cache_lines[i] + j*fcache->slot_size);
		}
	}
}

PRIVATE int find_filter_mem_accesses(struct sock_filter *filter,int flen,struct filter_mem_accesses *fmem_accesses);

PRIVATE void attach_filter_cache(struct private_struct *cb,struct sock_fprog *fprog)
{
	reset_filter_cache(cb->fcache);
			
	if(find_filter_mem_accesses(fprog->filter,fprog->len,cb->fmem_accesses) == 0)
	{
		printk(KERN_INFO "Suitable BPF filter found, cached BPF filter enabled!\n");
		
		setup_filter_cache(cb->fcache,cb->fmem_accesses->nolocations);

		cb->fcache->run_mapi_filter = run_mapi_filter_with_cache;
	}
	else
	{
		printk(KERN_INFO "Unsuitable BPF filter found, cached BPF filter disabled!\n");
	}
}

extern kmem_cache_t *hw_cache_lines_cache;

PRIVATE int init_cached_filter(struct private_struct *cb)
{
	int i;
	
	nbo_eth_ip = htons(ETH_P_IP);
	
	if((cb->fmem_accesses = kmalloc(sizeof(struct filter_mem_accesses),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	memset(cb->fmem_accesses,0,sizeof(struct filter_mem_accesses));
	
	if((cb->fcache = kmalloc(sizeof(struct filter_cache),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}

	for( i = 0 ; i < MAX_FILTER_CACHE_SLOTS ; i++ )
	{
		if((cb->fcache->hw_cache_lines[i] = kmem_cache_alloc(hw_cache_lines_cache,GFP_KERNEL)) == NULL)
		{
			while(i-- >= 0)
			{
				kmem_cache_free(hw_cache_lines_cache,cb->fcache->hw_cache_lines[i]);
			}
			
			return -ENOMEM;
		}
	}
	
	cb->fcache->run_mapi_filter = run_mapi_filter_without_cache;

	return 0;
}

PRIVATE void deinit_cached_filter(struct private_struct *cb)
{
	int i;

	if(cb->fmem_accesses->locations != NULL)
	{
		kfree(cb->fmem_accesses->locations);
	}

	kfree(cb->fmem_accesses);
	
	for( i = 0 ; i < MAX_FILTER_CACHE_SLOTS ; i++ )
	{
		kmem_cache_free(hw_cache_lines_cache,cb->fcache->hw_cache_lines[i]);
	}
	
	kfree(cb->fcache);
}

PRIVATE int find_filter_mem_accesses(struct sock_filter *filter,int flen,struct filter_mem_accesses *fmem_accesses)
{
	struct sock_filter *ftest;
	u8 tmp_mem_accesses[MAX_HEADER_LEN];
	int mem_index;
        int pc;
	int i;

	memset(tmp_mem_accesses,0,MAX_HEADER_LEN);
	
	if(fmem_accesses->locations != NULL)
	{
		kfree(fmem_accesses->locations);
	}
	
	for(pc = 0 ; pc < flen ; pc++)
	{
                ftest = &filter[pc];
		
		if(BPF_CLASS(ftest->code) == BPF_LD)
		{
			if(BPF_SIZE(ftest->code) == BPF_W)
			{
				if(ftest->k < 0 || ftest->k >= (MAX_HEADER_LEN - 4))
				{
					return -EINVAL;
				}
				
				if(BPF_MODE(ftest->code) == BPF_ABS)
				{
					for( i = 0 ; i < 4 ; i++)
					{
						tmp_mem_accesses[ftest->k + i] = 1;
					}
				}
				else if(BPF_MODE(ftest->code) == BPF_IND)
				{
					return -EINVAL;
				}
				else if(BPF_MODE(ftest->code) == BPF_LEN)
				{
					return -EINVAL;
				}
			}
			else if(BPF_SIZE(ftest->code) == BPF_H)
			{
				if(ftest->k < 0 || ftest->k >= (MAX_HEADER_LEN - 2))
				{
					return -EINVAL;
				}
				
				if(BPF_MODE(ftest->code) == BPF_ABS)
				{
					for( i = 0 ; i < 2 ; i++)
					{
						tmp_mem_accesses[ftest->k + i] = 1;
					}
				}
				else if(BPF_MODE(ftest->code) == BPF_IND)
				{
					return -EINVAL;
				}
				else if(BPF_MODE(ftest->code) == BPF_LEN)
				{
					return -EINVAL;
				}
			}
			else if(BPF_SIZE(ftest->code) == BPF_B)
			{
				if(ftest->k < 0 || ftest->k >= MAX_HEADER_LEN)
				{
					return -EINVAL;
				}
				
				if(BPF_MODE(ftest->code) == BPF_ABS)
				{
					tmp_mem_accesses[ftest->k] = 1;
				}
				else if(BPF_MODE(ftest->code) == BPF_IND)
				{
					return -EINVAL;
				}
				else if(BPF_MODE(ftest->code) == BPF_LEN)
				{
					return -EINVAL;
				}
			}
                }
		else if(BPF_CLASS(ftest->code) == BPF_LDX)
		{
			if(BPF_MODE(ftest->code) == BPF_LEN)
			{
				return -EINVAL;
			}
                }
        }
	
	fmem_accesses->nolocations = 0;
	
	for( pc = 0 ; pc < MAX_HEADER_LEN ; pc++)
	{
		if(tmp_mem_accesses[pc] == 1)
		{
			fmem_accesses->nolocations++;
		}
	}

	if((fmem_accesses->locations = kmalloc(fmem_accesses->nolocations,GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	mem_index = 0;

	for( pc = 0 ; pc < MAX_HEADER_LEN ; pc++)
	{
		if(tmp_mem_accesses[pc] == 1)
		{
			fmem_accesses->locations[mem_index++] = pc;
		}
	}

#ifdef DEBUG	
	printk("BPF filter accesses %d packet header bytes\n",mem_index);

	printk("Bytes : ");
	
	for( mem_index = 0 ; mem_index < fmem_accesses->nolocations ; mem_index++)
	{
		printk("%d ",fmem_accesses->locations[mem_index]);
	}
	
	printk("\n");
#endif	

	return 0;
}

PRIVATE __u8 cached_bpf_filter_equals(const struct predef_func *fpf,const struct predef_func *spf)
{
	struct cached_bpf_filter_struct *fcbpf = (struct cached_bpf_filter_struct *)fpf->data;
	struct cached_bpf_filter_struct *scbpf = (struct cached_bpf_filter_struct *)spf->data;
	
	if((fpf->type == spf->type) && (fcbpf->uid == scbpf->uid))
	{
		return 1;
	}

	return 0;
}

PRIVATE unsigned long cached_bpf_filter(struct sk_buff **skbp,struct sock *sk,struct predef_func *pfunc)
{
	struct cached_bpf_filter_struct *cbpf = (struct cached_bpf_filter_struct *)pfunc->data;
	struct private_struct *cb = function_cb(cbpf);
	struct sk_filter *filter = cb->filter;
	struct sk_buff *skb = *skbp;
	struct skb_mapi_priv *skb_mapi = skb_mapiinfo(sk);
	int res;
	
	if(unlikely(skb_mapi->action == SKB_DROP))
	{
		return 0;
	}

	res = (*(cb->fcache->run_mapi_filter))(cb,skb,filter->insns,filter->len);
	
	if(res == 0)
	{
		skb_mapi->action = SKB_DROP;
	}
	else
	{
		do_skb_trim(skb,res);
	}
	
	return 0;
}

PRIVATE int add_cached_bpf_filter(struct sock *sk,struct predef_func *pfunc)
{
	struct cached_bpf_filter_struct *cbpf = (struct cached_bpf_filter_struct *)pfunc->data;
	struct private_struct *cb = function_cb(cbpf);
	struct sk_filter *fp = cb->filter;
	int ret;
	
	if((ret = sk_chk_filter(fp->insns,fp->len)) != 0)
	{
		return ret;
	}
	
	if((ret = init_cached_filter(cb)) != 0)
	{
		return ret;
	}

	attach_filter_cache(cb,&(cbpf->fprog));

	cbpf->uid = atomic_read(&uid_nr);
	
	if((ret = sk_attach_predef(sk,pfunc)) == 0)
	{	
		atomic_inc(&(uid_nr));	

		mapi_module_get(THIS_MODULE);
	}
	else
	{
		deinit_cached_filter(cb);
	}

	return ret;
}

PRIVATE int remove_cached_bpf_filter(struct sock *sk,struct predef_func *pfunc,int lock)
{
	struct predef_func *found;
	struct cached_bpf_filter_struct *cbpf;
	struct private_struct *cb;

	found = (lock == 1) ? sk_detach_predef(sk,pfunc) : __sk_detach_predef(sk,pfunc);

	if(found == NULL)
	{
		return -ENODATA;
	}
	
	cbpf = (struct cached_bpf_filter_struct *)found->data;
	cb = function_cb(cbpf);
	
	kfree(cb->filter);
	deinit_cached_filter(cb);

	kmem_cache_free(cached_bpf_filter_cache,cbpf);
	kmem_cache_free(predef_func_cache,found);

	mapi_module_put(THIS_MODULE);

	return 0;
}

PRIVATE int reset_cached_bpf_filter(struct sock *sk,struct predef_func *pfunc)
{
	return -ENOSYS;
}

PRIVATE struct predef_func *getresults_cached_bpf_filter(struct sock *sk,struct predef_func *pfunc)
{
	struct predef_func *found;

	found = sk_find_predef(sk,pfunc);

 	return found;
}

PRIVATE void cached_bpf_filter_init_pfunc(struct predef_func *pfunc,struct cached_bpf_filter_struct *cbpf)
{
	init_pfunc(pfunc);
	
	pfunc->type = CACHED_BPF_FILTER;
	pfunc->data = (unsigned long)cbpf;
	pfunc->func = cached_bpf_filter;
	pfunc->equals = cached_bpf_filter_equals;
}

PRIVATE inline struct predef_func *pfunc_alloc_r(void)
{
	struct cached_bpf_filter_struct *cbpf;
	struct predef_func *pfunc;

	if((cbpf = kmem_cache_alloc(cached_bpf_filter_cache,GFP_KERNEL)) == NULL)
	{
		return NULL;
	}
	
	if((pfunc = kmem_cache_alloc(predef_func_cache,GFP_KERNEL)) == NULL)
	{
		kmem_cache_free(cached_bpf_filter_cache,cbpf);

		return NULL;
	}

	cached_bpf_filter_init_pfunc(pfunc,cbpf);

	return pfunc;
}

PRIVATE inline int put_fields_to_userspace(struct sock *sk,struct predef_func *pfunc,unsigned long arg)
{
	if((pfunc = getresults_cached_bpf_filter(sk,pfunc)) == NULL)
	{
		return -ENODATA;
	}
	else
	{
		/* struct cached_bpf_filter_struct *cbpf = (struct cached_bpf_filter_struct *)pfunc->data;
		 * struct cached_bpf_filter_struct *arg_cbpf = (struct cached_bpf_filter_struct *)arg;
		 */
	}

	return 0;
}

PRIVATE inline int fill_fields(struct cached_bpf_filter_struct *cbpf,unsigned long arg)
{
	struct cached_bpf_filter_struct *arg_cbpf = (struct cached_bpf_filter_struct *)arg;
	struct private_struct *cb = function_cb(cbpf);
	struct sock_fprog *fprog = &(cbpf->fprog);
	struct sk_filter *fp;
	unsigned int fsize;
	
	if(copy_from_user(fprog,&(arg_cbpf->fprog),sizeof(cbpf->fprog)))
	{
		return -EFAULT;
	}
	
	fsize = sizeof(struct sock_filter) * fprog->len;

        if(fprog->filter == NULL || fprog->len > BPF_MAXINSNS)
	{
                return -EINVAL;
	}

	if((fp = kmalloc(fsize + sizeof(*fp),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;
	}
	
	if(copy_from_user(fp->insns,fprog->filter,fsize)) 
	{
		kfree(fp); 
		
		return -EFAULT;
	}

	atomic_set(&fp->refcnt,1);
	fp->len = fprog->len;

	cb->filter = fp;
	
	if(get_user(cbpf->uid,(u16 *)&(arg_cbpf->uid)))
	{
		kfree(fp); 
		
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
	
	if((*status = fill_fields((struct cached_bpf_filter_struct *)pfunc->data,arg)) != 0)
	{
		kmem_cache_free(cached_bpf_filter_cache,(void *)pfunc->data);
		kmem_cache_free(predef_func_cache,pfunc);

		return NULL;
	}

	return pfunc;
}

PRIVATE int cached_bpf_filter_ioctl(struct socket *sock,unsigned int cmd,unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct predef_func *pfunc;
	int ret = NRIOCTL;

	if(cmd != SIOCSCACHED_BPF_FILTER && cmd != SIOCGCACHED_BPF_FILTER && 
	   cmd != SIOCRSCACHED_BPF_FILTER && cmd != SIOCRMCACHED_BPF_FILTER)
	{
		return ret;
	}

	if((pfunc = get_pfunc(arg,&ret)) == NULL)
	{
		return ret;
	}

	switch(cmd)
	{
		case SIOCGCACHED_BPF_FILTER:
			ret = put_fields_to_userspace(sk,pfunc,arg);			
			break;
			
		case SIOCSCACHED_BPF_FILTER:
			{
				struct cached_bpf_filter_struct *cbpf;
				struct cached_bpf_filter_struct *arg_cbpf;
				
				if((ret = add_cached_bpf_filter(sk,pfunc)) != 0)
				{
					break;
				}
				
				cbpf = (struct cached_bpf_filter_struct *)pfunc->data;
				arg_cbpf = (struct cached_bpf_filter_struct *)arg;
					
				if(put_user(cbpf->uid,(u16 *)&(arg_cbpf->uid)))
				{
					return -EFAULT;
				}

				return ret;
			}
		case SIOCRSCACHED_BPF_FILTER:
			ret = reset_cached_bpf_filter(sk,pfunc);
			break;

		case SIOCRMCACHED_BPF_FILTER:
			ret = remove_cached_bpf_filter(sk,pfunc,1);
			break;
	}
	
	{
		struct private_struct *cb = function_cb((struct bpf_struct *)pfunc->data);
		kfree(cb->filter);
	}
	
	kmem_cache_free(cached_bpf_filter_cache,(void *)pfunc->data);
	kmem_cache_free(predef_func_cache,pfunc);

	return ret;
}

#ifdef CONFIG_PROC_FS
PRIVATE int cached_bpf_filter_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;

	struct sock *s;
	struct predef_func *pfunc;
	struct predef_func *cur;
	struct cached_bpf_filter_struct *cbpf = NULL;
	struct private_struct *cb;
	struct hlist_node *node;

	len += sprintf(buffer,"Sock      Hits       Misses\n");

	lock_active_socket_list();
	
	sk_for_each(s,node,get_active_socket_list())
	{
		pfunc = sk_find_type(s,CACHED_BPF_FILTER);
				
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			cbpf = (struct cached_bpf_filter_struct *)cur->data;
			cb = function_cb(cbpf);

#ifdef CACHE_STATISTICS
			u64 hits = cb->fcache->hits;
			u64 misses = cb->fcache->misses;
#else
			u64 hits = 0;
			u64 misses = 0;
#endif

			len += sprintf(buffer + len,"%-8p  %-10lld %-10lld\n",s,hits,misses);

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
	index:CACHED_BPF_FILTER,
	owner:THIS_MODULE,
	add:add_cached_bpf_filter,
	remove:remove_cached_bpf_filter,
	ioctl:cached_bpf_filter_ioctl,
};

int __init cached_bpf_filter_init(void)
{
	int ret;
	
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("cached_bpf", 0, proc_path, cached_bpf_filter_read_proc, NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file cached_bpf : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
#endif
	if((cached_bpf_filter_cache = kmem_cache_create("cbpf",sizeof(struct cached_bpf_filter_struct),0,SLAB_HWCACHE_ALIGN,NULL,NULL)) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create cached_bpf_filter_cache : %s,%i\n",__FILE__,__LINE__);

		return -EPERM;
	}
	
	if((ret = register_function(&fta)) != 0)
	{
		return ret;
	}

	return 0;
}

void __exit cached_bpf_filter_exit(void)
{
	unregister_function(CACHED_BPF_FILTER);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("cached_bpf",proc_path);
#endif
	if(kmem_cache_destroy(cached_bpf_filter_cache))
	{
		printk(KERN_ALERT "Error : Could not remove cached_bpf_filter_cache : %s,%i\n",__FILE__,__LINE__);
	}
}

module_init(cached_bpf_filter_init);
module_exit(cached_bpf_filter_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

#endif
