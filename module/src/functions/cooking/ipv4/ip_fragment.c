/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP fragmentation functionality.
 *		
 * Version:	$Id: ip_fragment.c,v 1.1 2003/10/06 16:04:15 xinidis Exp $
 *
 * Authors:	Fred N. van Kempen <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox <Alan.Cox@linux.org>
 *
 * Fixes:
 *		Alan Cox	:	Split from ip.c , see ip_input.c for history.
 *		David S. Miller :	Begin massive cleanup...
 *		Andi Kleen	:	Add sysctls.
 *		xxxx		:	Overlapfrag bug.
 *		Ultima          :       mapi_ip_expire() kernel panic.
 *		Bill Hawes	:	Frag accounting and evictor fixes.
 *		John McDonald	:	0 length frag bug.
 *		Alexey Kuznetsov:	SMP races, threading, cleanup.
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/checksum.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <cookip.h>

/* NOTE. Logic of IP defragmentation is parallel to corresponding IPv6
 * code now. If you change something here, _PLEASE_ update ipv6/reassembly.c
 * as well. Or notify me, at least. --ANK
 */

/* Fragment cache limits. We will commit 256K at one time. Should we
 * cross that limit we will prune down to 192K. This should cope with
 * even the most extreme cases without allowing an attacker to measurably
 * harm machine performance.
 */
PRIVATE int mapi_ipfrag_high_thresh = 256 * 1024;
PRIVATE int mapi_ipfrag_low_thresh = 192 * 1024;

/* Important NOTE! Fragment queue must be destroyed before MSL expires.
 * RFC791 is wrong proposing to prolongate timer each fragment arrival by TTL.
 */
PRIVATE int mapi_ipfrag_time = IP_FRAG_TIME;

struct ipfrag_skb_cb
{
	struct inet_skb_parm h;
	int offset;
};

#define FRAG_CB(skb)	((struct ipfrag_skb_cb*)((skb)->cb))

/* Describe an entry in the "incomplete datagrams" queue. */
struct ipq
{
	struct ipq *next;				 /* linked list pointers             */
	u32 saddr;
	u32 daddr;
	u16 id;
	u8 protocol;
	u8 last_in;

#define COMPLETE		4
#define FIRST_IN		2
#define LAST_IN			1

	struct sk_buff *fragments;			 /* linked list of received fragments      */
	int len;					 /* total length of original datagram      */
	int meat;
	spinlock_t lock;
	atomic_t refcnt;
	struct timer_list timer;			 /* when will this queue expire?           */
	struct ipq **pprev;
	int iif;
	struct timeval stamp;
};

/* Hash table. */

#define IPQ_HASHSZ	64

/* Per-bucket lock is easy to add now. */
PRIVATE struct ipq *mapi_ipq_hash[IPQ_HASHSZ];
PRIVATE rwlock_t mapi_ipfrag_lock = RW_LOCK_UNLOCKED;
PRIVATE int mapi_ip_frag_nqueues = 0;

static __inline__ void __mapi_mapi_ipq_unlink(struct ipq *qp)
{
	if(qp->next)
		qp->next->pprev = qp->pprev;
	*qp->pprev = qp->next;
	mapi_ip_frag_nqueues--;
}

static __inline__ void mapi_ipq_unlink(struct ipq *ipq)
{
	write_lock(&mapi_ipfrag_lock);
	__mapi_mapi_ipq_unlink(ipq);
	write_unlock(&mapi_ipfrag_lock);
}

/*
 * Was:	((((id) >> 1) ^ (saddr) ^ (daddr) ^ (prot)) & (IPQ_HASHSZ - 1))
 *
 * I see, I see evil hand of bigendian mafia. On Intel all the packets hit
 * one hash bucket with this hash function. 8)
 */
static __inline__ unsigned int mapi_ipqhashfn(u16 id, u32 saddr, u32 daddr, u8 prot)
{
	unsigned int h = saddr ^ daddr;

	h ^= (h >> 16) ^ id;
	h ^= (h >> 8) ^ prot;
	return h & (IPQ_HASHSZ - 1);
}


PRIVATE atomic_t mapi_ip_frag_mem = ATOMIC_INIT(0);		 /* Memory used for fragments */

/* Memory Tracking Functions. */
static __inline__ void mapi_frag_kfree_skb(struct sk_buff *skb)
{
	atomic_sub(skb->truesize, &mapi_ip_frag_mem);
	kfree_skb(skb);
}

static __inline__ void mapi_frag_free_queue(struct ipq *qp)
{
	atomic_sub(sizeof(struct ipq), &mapi_ip_frag_mem);
	kfree(qp);
}

static __inline__ struct ipq *mapi_frag_alloc_queue(void)
{
	struct ipq *qp = kmalloc(sizeof(struct ipq), GFP_ATOMIC);

	if(!qp)
	{
		return NULL;
	}
	
	atomic_add(sizeof(struct ipq), &mapi_ip_frag_mem);
	
	return qp;
}


/* Destruction primitives. */

/* Complete destruction of ipq. */
PRIVATE void mapi_ip_frag_destroy(struct ipq *qp)
{
	struct sk_buff *fp;

	BUG_TRAP(qp->last_in & COMPLETE);
	BUG_TRAP(del_timer(&qp->timer) == 0);

	/*
	 * Release all fragment data. 
	 */
	fp = qp->fragments;
	
	while(fp)
	{
		struct sk_buff *xp = fp->next;

		mapi_frag_kfree_skb(fp);
		fp = xp;
	}

	/*
	 * Finally, release the queue descriptor itself. 
	 */
	mapi_frag_free_queue(qp);
}

static __inline__ void mapi_ipq_put(struct ipq *ipq)
{
	if(atomic_dec_and_test(&ipq->refcnt))
	{
		mapi_ip_frag_destroy(ipq);
	}
}

/* Kill ipq entry. It is not destroyed immediately,
 * because caller (and someone more) holds reference count.
 */
static __inline__ void mapi_ipq_kill(struct ipq *ipq)
{
	if(del_timer(&ipq->timer))
	{
		atomic_dec(&ipq->refcnt);
	}

	if(!(ipq->last_in & COMPLETE))
	{
		mapi_ipq_unlink(ipq);
		atomic_dec(&ipq->refcnt);
		ipq->last_in |= COMPLETE;
	}
}

/* Memory limiting on fragments.  Evictor trashes the oldest 
 * fragment queue until we are back under the low threshold.
 */
PRIVATE void mapi_ip_evictor(void)
{
	int i, progress;

	do
	{
		if(atomic_read(&mapi_ip_frag_mem) <= mapi_ipfrag_low_thresh)
		{
			return;
		}
		
		progress = 0;
		/*
		 * FIXME: Make LRU queue of frag heads. -DaveM 
		 */
		for(i = 0; i < IPQ_HASHSZ; i++)
		{
			struct ipq *qp;
			
			if(mapi_ipq_hash[i] == NULL)
			{
				continue;
			}

			read_lock(&mapi_ipfrag_lock);
			
			if((qp = mapi_ipq_hash[i]) != NULL)
			{
				/*
				 * find the oldest queue for this hash bucket 
				 */
				while(qp->next)
				{
					qp = qp->next;
				}
				
				atomic_inc(&qp->refcnt);
				read_unlock(&mapi_ipfrag_lock);

				spin_lock(&qp->lock);
				
				if(!(qp->last_in & COMPLETE))
				{
					mapi_ipq_kill(qp);
				}
				
				spin_unlock(&qp->lock);

				mapi_ipq_put(qp);
				progress = 1;
				
				continue;
			}
			
			read_unlock(&mapi_ipfrag_lock);
		}
	}
	while(progress);
}

/*
 * Oops, a fragment queue timed out.  Kill it and send an ICMP reply.
 */
PRIVATE void mapi_ip_expire(unsigned long arg)
{
	struct ipq *qp = (struct ipq *)arg;

	spin_lock(&qp->lock);

	if(qp->last_in & COMPLETE)
	{
		goto out;
	}

	mapi_ipq_kill(qp);

out:
	spin_unlock(&qp->lock);
	mapi_ipq_put(qp);
}

/* Creation primitives. */

PRIVATE struct ipq *mapi_ip_frag_intern(unsigned int hash, struct ipq *qp_in)
{
	struct ipq *qp;

	write_lock(&mapi_ipfrag_lock);
#ifdef CONFIG_SMP
	/*
	 * With SMP race we have to recheck hash table, because
	 * such entry could be created on other cpu, while we
	 * promoted read lock to write lock.
	 */
	for(qp = mapi_ipq_hash[hash]; qp; qp = qp->next)
	{
		if(qp->id == qp_in->id && qp->saddr == qp_in->saddr && qp->daddr == qp_in->daddr && qp->protocol == qp_in->protocol)
		{
			atomic_inc(&qp->refcnt);
			write_unlock(&mapi_ipfrag_lock);
			qp_in->last_in |= COMPLETE;
			mapi_ipq_put(qp_in);
			
			return qp;
		}
	}
#endif
	qp = qp_in;

	if(!mod_timer(&qp->timer, jiffies + mapi_ipfrag_time))
	{
		atomic_inc(&qp->refcnt);
	}

	atomic_inc(&qp->refcnt);
	
	if((qp->next = mapi_ipq_hash[hash]) != NULL)
	{
		qp->next->pprev = &qp->next;
	}

	mapi_ipq_hash[hash] = qp;
	qp->pprev = &mapi_ipq_hash[hash];
	mapi_ip_frag_nqueues++;
	write_unlock(&mapi_ipfrag_lock);
	
	return qp;
}

/* Add an entry to the 'ipq' queue for a newly received IP datagram. */
PRIVATE struct ipq *mapi_ip_frag_create(unsigned hash, struct iphdr *iph)
{
	struct ipq *qp;

	if((qp = mapi_frag_alloc_queue()) == NULL)
	{
		goto out_nomem;
	}

	qp->protocol = iph->protocol;
	qp->last_in = 0;
	qp->id = iph->id;
	qp->saddr = iph->saddr;
	qp->daddr = iph->daddr;
	qp->len = 0;
	qp->meat = 0;
	qp->fragments = NULL;
	qp->iif = 0;

	/*
	 * Initialize a timer for this entry. 
	 */
	init_timer(&qp->timer);
	qp->timer.data = (unsigned long)qp;	 /* pointer to queue     */
	qp->timer.function = mapi_ip_expire;	 /* expire function      */
	qp->lock = SPIN_LOCK_UNLOCKED;
	atomic_set(&qp->refcnt, 1);

	return mapi_ip_frag_intern(hash,qp);

out_nomem:
	
	MAPI_DEBUG(if(net_ratelimit()) 
		   printk(KERN_ERR "COOK_IP : No memory left!\n")) ;
	
	return NULL;
}

/* Find the correct entry in the "incomplete datagrams" queue for
 * this IP datagram, and create new one, if nothing is found.
 */
static inline struct ipq *mapi_ip_find(struct iphdr *iph)
{
	__u16 id = iph->id;
	__u32 saddr = iph->saddr;
	__u32 daddr = iph->daddr;
	__u8 protocol = iph->protocol;
	unsigned int hash = mapi_ipqhashfn(id, saddr, daddr, protocol);
	struct ipq *qp;

	read_lock(&mapi_ipfrag_lock);
	
	for(qp = mapi_ipq_hash[hash]; qp; qp = qp->next)
	{
		if(qp->id == id && qp->saddr == saddr && qp->daddr == daddr && qp->protocol == protocol)
		{
			atomic_inc(&qp->refcnt);
			read_unlock(&mapi_ipfrag_lock);
			
			return qp;
		}
	}
	
	read_unlock(&mapi_ipfrag_lock);

	return mapi_ip_frag_create(hash, iph);
}

/* Add new segment to existing queue. */
PRIVATE void mapi_ip_frag_queue(struct ipq *qp, struct sk_buff *skb)
{
	struct sk_buff *prev, *next;
	int flags, offset;
	int ihl, end;

	if(qp->last_in & COMPLETE)
	{
		goto err;
	}

	offset = ntohs(skb->nh.iph->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;					 /* offset is in 8-byte chunks */
	ihl = skb->nh.iph->ihl * 4;

	/*
	 * Determine the position of this fragment. 
	 */
	end = offset + skb->len - ihl;

	/*
	 * Is this the final fragment? 
	 */
	if((flags & IP_MF) == 0)
	{
		/*
		 * If we already have some bits beyond end
		 * * or have different end, the segment is corrrupted.
		 */
		if(end < qp->len || ((qp->last_in & LAST_IN) && end != qp->len))
		{
			goto err;
		}
		
		qp->last_in |= LAST_IN;
		qp->len = end;
	}
	else
	{
		if(end & 7)
		{
			end &= ~7;
			if(skb->ip_summed != CHECKSUM_UNNECESSARY)
			{
				skb->ip_summed = CHECKSUM_NONE;
			}
		}
		if(end > qp->len)
		{
			/*
			 * Some bits beyond end -> corruption. 
			 */
			if(qp->last_in & LAST_IN)
			{
				goto err;
			}
			
			qp->len = end;
		}
	}
	if(end == offset)
	{
		goto err;
	}

	if(pskb_pull(skb, ihl) == NULL)
	{
		goto err;
	}
	if(pskb_trim(skb, end - offset))
	{
		goto err;
	}

	/*
	 * Find out which fragments are in front and at the back of us
	 * * in the chain of fragments so far.  We must know where to put
	 * * this fragment, right?
	 */
	prev = NULL;
	
	for(next = qp->fragments; next != NULL; next = next->next)
	{
		if(FRAG_CB(next)->offset >= offset)
		{
			break;				 /* bingo! */
		}

		prev = next;
	}

	/*
	 * We found where to put this one.  Check for overlap with
	 * * preceding fragment, and, if needed, align things so that
	 * * any overlaps are eliminated.
	 */
	if(prev)
	{
		int i = (FRAG_CB(prev)->offset + prev->len) - offset;

		if(i > 0)
		{
			offset += i;
			
			if(end <= offset)
			{
				goto err;
			}
			if(!pskb_pull(skb, i))
			{
				goto err;
			}
			if(skb->ip_summed != CHECKSUM_UNNECESSARY)
			{
				skb->ip_summed = CHECKSUM_NONE;
			}
		}
	}

	while(next && FRAG_CB(next)->offset < end)
	{
		int i = end - FRAG_CB(next)->offset; /* overlap is 'i' bytes */

		if(i < next->len)
		{
			/*
			 * Eat head of the next overlapped fragment
			 * * and leave the loop. The next ones cannot overlap.
			 */
			if(!pskb_pull(next, i))
			{
				goto err;
			}
			
			FRAG_CB(next)->offset += i;
			qp->meat -= i;
			
			if(next->ip_summed != CHECKSUM_UNNECESSARY)
			{
				next->ip_summed = CHECKSUM_NONE;
			}

			break;
		}
		else
		{
			struct sk_buff *free_it = next;

			/*
			 * Old fragmnet is completely overridden with
			 * * new one drop it.
			 */
			next = next->next;

			if(prev)
			{
				prev->next = next;
			}
			else
			{
				qp->fragments = next;
			}

			qp->meat -= free_it->len;
			mapi_frag_kfree_skb(free_it);
		}
	}

	FRAG_CB(skb)->offset = offset;

	/*
	 * Insert this fragment in the chain of fragments. 
	 */
	skb->next = next;
	
	if(prev)
	{
		prev->next = skb;
	}
	else
	{
		qp->fragments = skb;
	}

	if(skb->dev)
	{
		qp->iif = skb->dev->ifindex;
	}
	
	skb->dev = NULL;
	qp->stamp = skb->stamp;
	qp->meat += skb->len;
	atomic_add(skb->truesize, &mapi_ip_frag_mem);
	
	if(offset == 0)
	{
		qp->last_in |= FIRST_IN;
	}

	return;

    err:
	kfree_skb(skb);
	return;
}


/* Build a new IP datagram from all its fragments. */

PRIVATE struct sk_buff *mapi_ip_frag_reasm(struct ipq *qp, struct net_device *dev)
{
	struct iphdr *iph;
	struct sk_buff *fp, *head = qp->fragments;
	int len;
	int ihlen;

	mapi_ipq_kill(qp);

	BUG_TRAP(head != NULL);
	BUG_TRAP(FRAG_CB(head)->offset == 0);

	/*
	 * Allocate a new buffer for the datagram. 
	 */
	ihlen = head->nh.iph->ihl * 4;
	len = ihlen + qp->len;

	if(len > 65535)
	{
		goto out_oversize;
	}

	/*
	 * Head of list must not be cloned. 
	 */
	if(skb_cloned(head) && pskb_expand_head(head, 0, 0, GFP_ATOMIC))
	{
		goto out_nomem;
	}

	/*
	 * If the first fragment is fragmented itself, we split
	 * it to two chunks: the first with data and paged part
	 * and the second, holding only fragments. 
	 */
	if(skb_shinfo(head)->frag_list)
	{
		struct sk_buff *clone;
		int i, plen = 0;

		if((clone = alloc_skb(0, GFP_ATOMIC)) == NULL)
		{
			goto out_nomem;
		}
		
		clone->next = head->next;
		head->next = clone;
		skb_shinfo(clone)->frag_list = skb_shinfo(head)->frag_list;
		skb_shinfo(head)->frag_list = NULL;
		
		for(i = 0; i < skb_shinfo(head)->nr_frags; i++)
		{
			plen += skb_shinfo(head)->frags[i].size;
		}

		clone->len = clone->data_len = head->data_len - plen;
		head->data_len -= clone->len;
		head->len -= clone->len;
		clone->csum = 0;
		clone->ip_summed = head->ip_summed;
		atomic_add(clone->truesize, &mapi_ip_frag_mem);
	}

	skb_shinfo(head)->frag_list = head->next;
	skb_push(head, head->data - head->nh.raw);
	atomic_sub(head->truesize, &mapi_ip_frag_mem);

	for(fp = head->next; fp; fp = fp->next)
	{
		head->data_len += fp->len;
		head->len += fp->len;
		
		if(head->ip_summed != fp->ip_summed)
		{
			head->ip_summed = CHECKSUM_NONE;
		}
		else if(head->ip_summed == CHECKSUM_HW)
		{
			head->csum = csum_add(head->csum, fp->csum);
		}

		head->truesize += fp->truesize;
		atomic_sub(fp->truesize, &mapi_ip_frag_mem);
	}

	head->next = NULL;
	head->dev = dev;
	head->stamp = qp->stamp;

	iph = head->nh.iph;
	iph->frag_off = 0;
	iph->tot_len = htons(len);
	qp->fragments = NULL;

	return head;

out_nomem:
	MAPI_DEBUG(if(net_ratelimit())
		   printk(KERN_ERR "COOKI_IP: No memory for gluing queue %p\n", qp));
	
	goto out_fail;
    
out_oversize:
	if(net_ratelimit())
	{
		printk("Oversized IP packet from %d.%d.%d.%d.\n", NIPQUAD(qp->saddr));
	}
out_fail:
	
	return NULL;
}

/* Process an incoming IP datagram fragment. */
struct sk_buff *mapi_ip_defrag(struct sk_buff *skb,struct predef_func *pf)
{
	struct cook_ip_struct *cis = (struct cook_ip_struct *)pf->data;
	struct iphdr *iph = skb->nh.iph;
	struct ipq *qp;
	struct net_device *dev;

	/*
	 * Start by cleaning up the memory. 
	 */
	if(atomic_read(&mapi_ip_frag_mem) > mapi_ipfrag_high_thresh)
	{
		mapi_ip_evictor();
	}

	dev = skb->dev;
	
	/*
	 * Lookup (or create) queue header 
	 */
	if((qp = mapi_ip_find(iph)) != NULL)
	{
		struct sk_buff *ret = NULL;

		spin_lock(&qp->lock);

		mapi_ip_frag_queue(qp, skb);

		if(qp->last_in == (FIRST_IN | LAST_IN) && qp->meat == qp->len)
		{
			ret = mapi_ip_frag_reasm(qp,dev);
		}

		spin_unlock(&qp->lock);
		mapi_ipq_put(qp);
		
		return ret;
	}

	MAPI_DEBUG(if(net_ratelimit()) 
		   printk("COOK_IP : IP reassembly failed : %u.%u.%u.%u <- %u.%u.%u.%u\n",
			   NIPQUAD(skb->nh.iph->daddr),
			   NIPQUAD(skb->nh.iph->saddr)));

	spin_lock(&pf->data_lock);
	cis->defrag_errors++;
	spin_unlock(&pf->data_lock);
			
	kfree_skb(skb);
	
	return NULL;
}

#ifdef CONFIG_PROC_FS
PRIVATE int ipdefrag_read_proc(char *buffer,char **start,off_t offset,int length,int *eof,void *data)
{
	struct ipq *qp;
	off_t pos;
	int len = 0;
	
	len += sprintf(buffer + len,"\nSrc_IP           Dst_IP           Last_in Length\n");
	
	read_lock(&mapi_ipfrag_lock);

	for( pos = offset ; pos < IPQ_HASHSZ ; pos++)
	{
		for(qp = mapi_ipq_hash[pos]; qp != NULL ; qp = qp->next)
		{
			len += sprintf(buffer + len,"%3u.%3u.%3u.%3u  ",NIPQUAD(qp->saddr));
			len += sprintf(buffer + len,"%3u.%3u.%3u.%3u  ",NIPQUAD(qp->daddr));
			len += sprintf(buffer + len,"%.7d ",qp->last_in);
			len += sprintf(buffer + len,"%.6d\n",qp->len);

			if(len >= length)
			{
				goto done;
			}
		}
	}
	
	*eof = 1;
done:	
	read_unlock(&mapi_ipfrag_lock);

	*start = (char *)(pos - offset);
	
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

u8 __init mapi_defragmentation_init(void)
{
#ifdef CONFIG_PROC_FS
	if(create_proc_read_entry("ipdefrag",0,cook_ip_proc_path,ipdefrag_read_proc,NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file ipdefrag : %s,%i\n",__FILE__,__LINE__);

		return 1;
	}
#endif
	return 0;
}

u8 __exit mapi_defragmentation_exit(void)
{
#ifdef CONFIG_PROC_FS
	remove_proc_entry("ipdefrag",cook_ip_proc_path);
#endif
	return 0;
}
