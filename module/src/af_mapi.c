
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *
 * Fixes:	
 *		Alan Cox	:	verify_area() now used correctly
 *		Alan Cox	:	new skbuff lists, look ma no backlogs!
 *		Alan Cox	:	tidied skbuff lists.
 *		Alan Cox	:	Now uses generic datagram routines I
 *					added. Also fixed the peek/read crash
 *					from all old Linux datagram code.
 *		Alan Cox	:	Uses the improved datagram code.
 *		Alan Cox	:	Added NULL's for socket options.
 *		Alan Cox	:	Re-commented the code.
 *		Alan Cox	:	Use new kernel side addressing
 *		Rob Janssen	:	Correct MTU usage.
 *		Dave Platt	:	Counter leaks caused by incorrect
 *					interrupt locking and some slightly
 *					dubious gcc output. Can you read
 *					compiler: it said _VOLATILE_
 *	Richard Kooijman	:	Timestamp fixes.
 *		Alan Cox	:	New buffers. Use sk->mac.raw.
 *		Alan Cox	:	sendmsg/recvmsg support.
 *		Alan Cox	:	Protocol setting support
 *	Alexey Kuznetsov	:	Untied from IPv4 stack.
 *	Cyrus Durgin		:	Fixed kerneld for kmod.
 *	Michal Ostrowski        :       Module initialization cleanup.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <linux/kmod.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/if_bridge.h>
#include <linux/byteorder/generic.h>
#include <linux/compiler.h>

#ifdef CONFIG_NET_DIVERT
#include <linux/divert.h>
#endif							 /* CONFIG_NET_DIVERT */

#ifdef CONFIG_INET
#include <net/inet_common.h>
#endif

#ifdef CONFIG_DLCI
extern int dlci_ioctl(unsigned int, void *);
#endif

/*
   Proposed replacement for SIOC{ADD,DEL}MULTI and
   IFF_PROMISC, IFF_ALLMULTI flags.

   It is more expensive, but I believe,
   it is really correct solution: reentereble, safe and fault tolerant.

   IFF_PROMISC/IFF_ALLMULTI/SIOC{ADD/DEL}MULTI are faked by keeping
   reference count and global flag, so that real status is
   (gflag|(count != 0)), so that we can use obsolete faulty interface
   not harming clever users.
 */

/*
   Assumptions:
   - if device has no dev->hard_header routine, it adds and removes ll header
     inside itself. In this case ll header is invisible outside of device,
     but higher levels still should reserve dev->hard_header_len.
     Some devices are enough clever to reallocate skb, when header
     will not fit to reserved space (tunnel), another ones are silly
     (PPP).
   - packet socket receives packets with pulled ll header,
     so that SOCK_RAW should push it back.

On receive:
-----------

Incoming, dev->hard_header!=NULL
   mac.raw -> ll header
   data    -> data

Outgoing, dev->hard_header!=NULL
   mac.raw -> ll header
   data    -> ll header

Incoming, dev->hard_header==NULL
   mac.raw -> UNKNOWN position. It is very likely, that it points to ll header.
              PPP makes it, that is wrong, because introduce assymetry
	      between rx and tx paths.
   data    -> data

Outgoing, dev->hard_header==NULL
   mac.raw -> data. ll header is still not built!
   data    -> data

Resume
  If dev->hard_header==NULL we are unlikely to restore sensible ll header.


On transmit:
------------

dev->hard_header != NULL
   mac.raw -> ll header
   data    -> ll header

dev->hard_header == NULL (ll header is added by device, we cannot control it)
   mac.raw -> data
   data -> data

   We should set nh.raw on output to correct posistion,
   packet classifier depends on it.
 */

#include <linux/mapi/packet.h>
#include <linux/mapi/ioctl.h>

/* List of all mapi sockets. */
HLIST_HEAD(mapi_sklist);

static rwlock_t mapi_sklist_lock = RW_LOCK_UNLOCKED;
static atomic_t mapi_socks_nr;

struct hlist_head *get_active_socket_list(void)
{
	return &mapi_sklist;
}

void lock_active_socket_list(void)
{
	read_lock(&mapi_sklist_lock);
}

void unlock_active_socket_list(void)
{
	read_unlock(&mapi_sklist_lock);
}

EXPORT_SYMBOL(get_active_socket_list);
EXPORT_SYMBOL(lock_active_socket_list);
EXPORT_SYMBOL(unlock_active_socket_list);

#ifdef CONFIG_MAPI_MMAP
static int mapi_set_ring(struct sock *sk, struct tpacket_req *req, int closing);
#endif

static void mapi_flush_mclist(struct sock *sk);

void mapi_sock_destruct(struct sock *sk)
{
	BUG_TRAP(atomic_read(&mapi_sk_rmem_alloc(sk)) == 0);
	BUG_TRAP(atomic_read(&mapi_sk_wmem_alloc(sk)) == 0);

	if(!mapi_sk_dead(sk))
	{
		printk("Attempt to release alive packet socket: %p\n", sk);

		return;
	}

	if(mapi_sk(sk))
        {
		kfree(mapi_sk(sk));
        }

	atomic_dec(&mapi_socks_nr);

#ifdef PACKET_REFCNT_DEBUG
	printk(KERN_DEBUG "PACKET socket %p is free, %d are alive\n", sk, atomic_read(&mapi_socks_nr));
#endif
	
        mapi_module_put(THIS_MODULE);
}

extern struct proto_ops mapi_ops;

/*
   This function makes lazy skb cloning in hope that most of packets
   are discarded by BPF.

   Note tricky part: we DO mangle shared skb! skb->data, skb->len
   and skb->cb are mangled. It works because (and until) packets
   falling here are owned by current CPU. Output packets are cloned
   by dev_queue_xmit_nit(), input packets are processed by net_bh
   sequencially, so that if we return skb to original state on exit,
   we will not harm anyone.
 */

static int mapi_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt)
{
	struct packet_opt *po;
	struct sock *sk;
	u8 *skb_head;
	u8 *skb_tail;
	int skb_len;

	if(unlikely(skb->pkt_type == PACKET_LOOPBACK))
	{
		goto drop;
	}

#ifdef DEBUG
	SKB_LINEAR_ASSERT(skb);
#endif
	
	skb_head = skb->data;
	skb_len = skb->len;
	skb_tail = skb->tail;

	sk = (struct sock *)pt->data;
	po = mapi_sk(sk);

	skb->dev = dev;

	if(dev->hard_header)
	{
		/*
		 * The device has an explicit notion of ll header,
		 * exported to higher levels.
		 * 
		 * Otherwise, the device hides datails of it frame
		 * structure, so that corresponding packet head
		 * never delivered to user.
		 */
		if(likely(mapi_sk_type(sk) == SOCK_RAW))
		{
			skb_push(skb, skb->data - skb->mac.raw);
		}
		else if(skb->pkt_type == PACKET_OUTGOING)
		{
			/*
			 * Special case: outgoing packets have ll header at head 
			 */
			skb_pull(skb,skb->nh.raw - skb->data);
		}
	}

	spin_lock(&mapi_sk_receive_queue(sk).lock);
	po->mapistats.pkttype[skb->pkt_type].p_recv++;
	spin_unlock(&mapi_sk_receive_queue(sk).lock);
	
	run_mapi_nommap(skb,dev,sk);
	
	if(skb_head != skb->data) 
	{
		skb->data = skb_head;
		skb->len = skb_len;
		skb->tail = skb_tail;
	}
	
	return 0;

drop:
	kfree_skb(skb);

	return 0;
}

#ifdef CONFIG_MAPI_MMAP
static int tmapi_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt)
{
	unsigned long status = TP_STATUS_LOSING | TP_STATUS_USER;
	struct skb_mapi_priv *skb_mapi;
	struct packet_opt *po;
	struct sock *sk;
	u8 *skb_head;
	u8 *skb_tail;
	int skb_len;

	if(unlikely(skb->pkt_type == PACKET_LOOPBACK))
	{
		goto drop;
	}
	
	skb_head = skb->data;
	skb_len = skb->len;
	skb_tail = skb->tail;

	sk = (struct sock *)pt->data;
	po = mapi_sk(sk);
	skb_mapi = skb_mapiinfo(sk);

	if(dev->hard_header)
	{
		if(likely(mapi_sk_type(sk) == SOCK_RAW))
		{
			skb_push(skb,skb->data - skb->mac.raw);
		}
		else if(skb->pkt_type == PACKET_OUTGOING)
		{
			/*
			 * Special case: outgoing packets have ll header at head 
			 */
			skb_pull(skb,skb->nh.raw - skb->data);
			
			if(skb->ip_summed == CHECKSUM_HW)
			{
				status |= TP_STATUS_CSUMNOTREADY;
			}
		}
	}

	spin_lock(&mapi_sk_receive_queue(sk).lock);
	po->mapistats.pkttype[skb->pkt_type].p_recv++;
	spin_unlock(&mapi_sk_receive_queue(sk).lock);

	skb_mapi->status = status;
		
	run_mapi_mmap(skb,dev,sk);

	if(skb_head != skb->data)
	{
		skb->data = skb_head;
		skb->len = skb_len;
		skb->tail = skb_tail;
	}

drop:
	kfree_skb(skb);

	return 0;
}

#endif


#if V_BEFORE(2,5,0)
static int mapi_sendmsg(struct socket *sock,struct msghdr *msg,int len,struct scm_cookie *scm)
#else
static int mapi_sendmsg(struct kiocb *iocb,struct socket *sock,struct msghdr *msg,int len)
#endif
{
	struct sock *sk = sock->sk;
	struct sockaddr_ll *saddr = (struct sockaddr_ll *)msg->msg_name;
	struct sk_buff *skb;
	struct net_device *dev;
	unsigned short proto;
	unsigned char *addr;
	int ifindex, err, reserve = 0;

	/*
	 *    Get and verify the address. 
	 */

        if(saddr == NULL) 
        {
		struct packet_opt *po = mapi_sk(sk);

		ifindex	= po->ifindex;
		proto	= mapi_sk_num(sk);
		addr	= NULL;
	} 
        else 
        {
		err = -EINVAL;
		
                if (msg->msg_namelen < sizeof(struct sockaddr_ll))
                {
			goto out;
                }
                
		ifindex	= saddr->sll_ifindex;
		proto	= saddr->sll_protocol;
		addr	= saddr->sll_addr;
	}

	dev = dev_get_by_index(ifindex);
	err = -ENXIO;
	if(dev == NULL)
		goto out_unlock;
	if(sock->type == SOCK_RAW)
		reserve = dev->hard_header_len;

	err = -EMSGSIZE;
	if(len > dev->mtu + reserve)
		goto out_unlock;

	skb = sock_alloc_send_skb(sk, len + dev->hard_header_len + 15, msg->msg_flags & MSG_DONTWAIT, &err);
	if(skb == NULL)
		goto out_unlock;

	skb_reserve(skb, (dev->hard_header_len + 15) & ~15);
	skb->nh.raw = skb->data;

	if(dev->hard_header)
	{
		int res;
		err = -EINVAL;
		res = dev->hard_header(skb, dev, ntohs(proto), addr, NULL, len);
		if(sock->type == SOCK_RAW)
		{
			skb->tail = skb->data;
			skb->len = 0;
		}
		else if(res < 0)
			goto out_free;
	}

	/*
	 * Returns -EFAULT on error 
	 */
	err = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
	if(err)
		goto out_free;

	skb->protocol = proto;
	skb->dev = dev;
	skb->priority = mapi_sk_priority(sk);

	err = -ENETDOWN;
	if(!(dev->flags & IFF_UP))
		goto out_free;

	/*
	 *    Now send it
	 */

	err = dev_queue_xmit(skb);
	if(err > 0 && (err = net_xmit_errno(err)) != 0)
		goto out_unlock;

	dev_put(dev);

	return (len);

    out_free:
	kfree_skb(skb);
    out_unlock:
	if(dev)
		dev_put(dev);
    out:
	return err;
}

/*
 *	Close a PACKET socket. This is fairly simple. We immediately go
 *	to 'closed' state and remove our protocol entry in the device list.
 */

static int mapi_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct packet_opt *po = mapi_sk(sk);

	if(!sk)
		return 0;

	write_lock_bh(&mapi_sklist_lock);
	sk_del_node_init(sk);	
        write_unlock_bh(&mapi_sklist_lock);

	/*
	 *    Unhook packet receive handler.
	 */

	if(po->running)
	{
		/*
		 *    Remove the protocol hook
		 */
		dev_remove_pack(&po->prot_hook);
		po->running = 0;
                mapi_sk_num(sk) = 0;
		__sock_put(sk);
	}

#ifdef CONFIG_PACKET_MULTICAST
	mapi_flush_mclist(sk);
#endif

#ifdef CONFIG_MAPI_MMAP
	if(po->pg_vec)
	{
		struct tpacket_req req;
		memset(&req, 0, sizeof(req));
		mapi_set_ring(sk, &req, 1);
	}
#endif

	/*
	 *    Now the socket is dead. No more input will appear.
	 */

	do_when_destruct_sock(sk);

	sock_orphan(sk);
	sock->sk = NULL;

	/*
	 * Purge queues 
	 */

	skb_queue_purge(&mapi_sk_receive_queue(sk));

	sock_put(sk);

	return 0;
}

/*
 *	Attach a packet hook.
 */

static int mapi_do_bind(struct sock *sk, struct net_device *dev, int protocol)
{
        struct packet_opt *po = mapi_sk(sk);

	/*
	 *    Detach an existing hook if present.
	 */

	lock_sock(sk);

	spin_lock(&po->bind_lock);

        if(po->running) 
        {
		__sock_put(sk);
		po->running = 0;
		mapi_sk_num(sk) = 0;
		spin_unlock(&po->bind_lock);
		dev_remove_pack(&po->prot_hook);
		spin_lock(&po->bind_lock);
	}

	mapi_sk_num(sk) = protocol;

	po->prot_hook.type = protocol;
	po->prot_hook.dev = dev;

	po->ifindex = dev ? dev->ifindex : 0;

	if(protocol == 0)
        {
		goto out_unlock;
        }

	if(dev)
	{
		if(dev->flags & IFF_UP)
		{
			dev_add_pack(&po->prot_hook);
			sock_hold(sk);
			po->running = 1;
		}
		else
		{
			mapi_sk_err(sk) = ENETDOWN;
			
                        if(!mapi_sk_dead(sk))
                        {
                                mapi_sk_error_report(sk)(sk);
                        }
		}
	}
	else
	{
		dev_add_pack(&po->prot_hook);
		sock_hold(sk);
		po->running = 1;
	}

    out_unlock:
        
	spin_unlock(&po->bind_lock);
	release_sock(sk);
	
        return 0;
}

static int mapi_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_ll *sll = (struct sockaddr_ll *)uaddr;
	struct sock *sk = sock->sk;
	struct net_device *dev = NULL;
	int err;


	/*
	 *    Check legality
	 */

	if(addr_len < sizeof(struct sockaddr_ll))
		return -EINVAL;
	if(sll->sll_family != AF_MAPI)
		return -EINVAL;

	if(sll->sll_ifindex)
	{
		err = -ENODEV;
		dev = dev_get_by_index(sll->sll_ifindex);
		if(dev == NULL)
			goto out;
	}
        
	err = mapi_do_bind(sk, dev, sll->sll_protocol ? : mapi_sk_num(sk));
	
        if(dev)
		dev_put(dev);

    out:
	return err;
}


/*
 *	Create a packet of type SOCK_PACKET. 
 */

static int mapi_create(struct socket *sock,int protocol)
{
	struct sock *sk;
	struct packet_opt *po;        
	int err;

	if(!capable(CAP_NET_RAW))
        {
		return -EPERM;
        }

	if(sock->type != SOCK_RAW)
        {
		return -ESOCKTNOSUPPORT;
        }

	sock->state = SS_UNCONNECTED;
	
        mapi_module_get(THIS_MODULE);

	err = -ENOBUFS;

	sk = mapi_sk_alloc();
	
        if(sk == NULL)
        {
		goto out;
        }

	sock->ops = &mapi_ops;
	sock_init_data(sock,sk);
        
        mapi_sk_set_owner(sk);

	po = mapi_sk(sk) = kmalloc(sizeof(struct packet_opt),GFP_KERNEL);
	
        if(po == NULL)
        {
		goto out_free;
        }
        
	memset(po,0,sizeof(struct packet_opt));
	mapi_sk_family(sk) = PF_MAPI;
	mapi_sk_num(sk) = protocol;

	mapi_sk_destruct(sk) = mapi_sock_destruct;
	atomic_inc(&mapi_socks_nr);

	/*
	 *    Attach a protocol block
	 */
	spin_lock_init(&po->bind_lock);
	po->prot_hook.func = mapi_rcv;
	po->prot_hook.data = (void *)sk;

	if(protocol)
	{
		po->prot_hook.type = protocol;
		dev_add_pack(&po->prot_hook);
		sock_hold(sk);
		po->running = 1;
	}

	write_lock_bh(&mapi_sklist_lock);
	sk_add_node(sk,&mapi_sklist);
	write_unlock_bh(&mapi_sklist_lock);

        mapi_sk_socket(sk) = sock;
        
	init_when_create_sock(sk);

	return 0;

out_free:
        sk_free(sk);
        
out:
        mapi_module_put(THIS_MODULE);
	
        return err;
}

/*
 *	Pull a packet from our receive queue and hand it to the user.
 *	If necessary we block.
 */

#if V_BEFORE(2,5,0)
static int mapi_recvmsg(struct socket *sock,struct msghdr *msg,int len,int flags,struct scm_cookie *scm)
#else
static int mapi_recvmsg(struct kiocb *iocb,struct socket *sock,struct msghdr *msg,int len,int flags)
#endif
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int copied, err;

	err = -EINVAL;
	if(flags & ~(MSG_PEEK | MSG_DONTWAIT | MSG_TRUNC))
		goto out;

#if 0
	/*
	 * What error should we return now? EUNATTACH? 
	 */
	if(mapi_sk(sk)->ifindex < 0)
		return -ENODEV;
#endif

	/*
	 *    If the address length field is there to be filled in, we fill
	 *    it in now.
	 */

	if(sock->type == SOCK_PACKET)
		msg->msg_namelen = sizeof(struct sockaddr_pkt);
	else
		msg->msg_namelen = sizeof(struct sockaddr_ll);

	/*
	 *    Call the generic datagram receiver. This handles all sorts
	 *    of horrible races and re-entrancy so we can forget about it
	 *    in the protocol layers.
	 *
	 *    Now it will return ENETDOWN, if device have just gone down,
	 *    but then it will block.
	 */

	skb = skb_recv_datagram(sk, flags, flags & MSG_DONTWAIT, &err);

	/*
	 *    An error occurred so return it. Because skb_recv_datagram() 
	 *    handles the blocking we don't see and worry about blocking
	 *    retries.
	 */

	if(skb == NULL)
		goto out;

	/*
	 *    You lose any data beyond the buffer you gave. If it worries a
	 *    user program they can ask the device for its MTU anyway.
	 */

	copied = skb->len;
	if(copied > len)
	{
		copied = len;
		msg->msg_flags |= MSG_TRUNC;
	}

	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	if(err)
		goto out_free;

	sock_recv_timestamp(msg, sk, skb);

	if(msg->msg_name)
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);

	/*
	 *    Free or return the buffer as appropriate. Again this
	 *    hides all the races and re-entrancy issues from us.
	 */
	err = (flags & MSG_TRUNC) ? skb->len : copied;

    out_free:
	skb_free_datagram(sk, skb);
    out:
	return err;
}

static int mapi_getname(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len, int peer)
{
	struct net_device *dev;
	struct sock *sk = sock->sk;
	struct sockaddr_ll *sll = (struct sockaddr_ll *)uaddr;

	if(peer)
		return -EOPNOTSUPP;

	sll->sll_family = AF_MAPI;
	sll->sll_ifindex = mapi_sk(sk)->ifindex;
	sll->sll_protocol = mapi_sk_num(sk);
	dev = dev_get_by_index(mapi_sk(sk)->ifindex);

	if(dev)
	{
		sll->sll_hatype = dev->type;
		sll->sll_halen = dev->addr_len;
		memcpy(sll->sll_addr, dev->dev_addr, dev->addr_len);
		dev_put(dev);
	}
	else
	{
		sll->sll_hatype = 0;			 /* Bad: we have no ARPHRD_UNSPEC */
		sll->sll_halen = 0;
	}
	*uaddr_len = sizeof(*sll);

	return 0;
}

#ifdef CONFIG_PACKET_MULTICAST
static void mapi_dev_mc(struct net_device *dev, struct packet_mclist *i, int what)
{
	switch (i->type)
	{
	case PACKET_MR_MULTICAST:
		if(what > 0)
			dev_mc_add(dev, i->addr, i->alen, 0);
		else
			dev_mc_delete(dev, i->addr, i->alen, 0);
		break;
	case PACKET_MR_PROMISC:
		dev_set_promiscuity(dev, what);
		break;
	case PACKET_MR_ALLMULTI:
		dev_set_allmulti(dev, what);
		break;
	default:;
	}
}

static void mapi_dev_mclist(struct net_device *dev, struct packet_mclist *i, int what)
{
	for(; i; i = i->next)
	{
		if(i->ifindex == dev->ifindex)
			mapi_dev_mc(dev, i, what);
	}
}

static int mapi_mc_add(struct sock *sk, struct packet_mreq *mreq)
{
	struct packet_mclist *ml, *i;
	struct net_device *dev;
	int err;

	rtnl_lock();

	err = -ENODEV;
	dev = __dev_get_by_index(mreq->mr_ifindex);
	if(!dev)
		goto done;

	err = -EINVAL;
	if(mreq->mr_alen > dev->addr_len)
		goto done;

	err = -ENOBUFS;
	i = (struct packet_mclist *)kmalloc(sizeof(*i), GFP_KERNEL);
	if(i == NULL)
		goto done;

	err = 0;
	for(ml = mapi_sk(sk)->mclist; ml; ml = ml->next)
	{
		if(ml->ifindex == mreq->mr_ifindex && ml->type == mreq->mr_type && ml->alen == mreq->mr_alen && memcmp(ml->addr, mreq->mr_address, ml->alen) == 0)
		{
			ml->count++;
			/*
			 * Free the new element ... 
			 */
			kfree(i);
			goto done;
		}
	}

	i->type = mreq->mr_type;
	i->ifindex = mreq->mr_ifindex;
	i->alen = mreq->mr_alen;
	memcpy(i->addr, mreq->mr_address, i->alen);
	i->count = 1;
	i->next = mapi_sk(sk)->mclist;
	mapi_sk(sk)->mclist = i;
	mapi_dev_mc(dev, i, +1);

    done:
	rtnl_unlock();
	return err;
}

static int mapi_mc_drop(struct sock *sk, struct packet_mreq *mreq)
{
	struct packet_mclist *ml, **mlp;

	rtnl_lock();

	for(mlp = &mapi_sk(sk)->mclist; (ml = *mlp) != NULL; mlp = &ml->next)
	{
		if(ml->ifindex == mreq->mr_ifindex && ml->type == mreq->mr_type && ml->alen == mreq->mr_alen && memcmp(ml->addr, mreq->mr_address, ml->alen) == 0)
		{
			if(--ml->count == 0)
			{
				struct net_device *dev;
				*mlp = ml->next;
				dev = dev_get_by_index(ml->ifindex);
				if(dev)
				{
					mapi_dev_mc(dev, ml, -1);
					dev_put(dev);
				}
				kfree(ml);
			}
			rtnl_unlock();
			return 0;
		}
	}
	rtnl_unlock();
	return -EADDRNOTAVAIL;
}

static void mapi_flush_mclist(struct sock *sk)
{
	struct packet_mclist *ml;

	if(mapi_sk(sk)->mclist == NULL)
		return;

	rtnl_lock();
	while((ml = mapi_sk(sk)->mclist) != NULL)
	{
		struct net_device *dev;
		mapi_sk(sk)->mclist = ml->next;
                
		if((dev = dev_get_by_index(ml->ifindex)) != NULL)
		{
			mapi_dev_mc(dev, ml, -1);
			dev_put(dev);
		}

		kfree(ml);
	}
	rtnl_unlock();
}
#endif

static int mapi_basic_setsockopt(struct socket *sock, int level, int optname, char *optval, int optlen)
{
	struct sock *sk = sock->sk;
	int ret;

	if(level != SOL_PACKET)
		return -ENOPROTOOPT;

	switch (optname)
	{
#ifdef CONFIG_PACKET_MULTICAST
	case PACKET_ADD_MEMBERSHIP:
	case PACKET_DROP_MEMBERSHIP:
		{
			struct packet_mreq mreq;
			if(optlen < sizeof(mreq))
				return -EINVAL;
			if(copy_from_user(&mreq, optval, sizeof(mreq)))
				return -EFAULT;
			if(optname == PACKET_ADD_MEMBERSHIP)
				ret = mapi_mc_add(sk, &mreq);
			else
				ret = mapi_mc_drop(sk, &mreq);
			return ret;
		}
#endif

#ifdef CONFIG_MAPI_MMAP
	case PACKET_RX_RING:
		{
			struct tpacket_req req;

			if(optlen < sizeof(req))
				return -EINVAL;
			if(copy_from_user(&req, optval, sizeof(req)))
				return -EFAULT;
			return mapi_set_ring(sk, &req, 0);
		}
	case PACKET_COPY_THRESH:
		{
			int val;

			if(optlen != sizeof(val))
				return -EINVAL;
			if(copy_from_user(&val, optval, sizeof(val)))
				return -EFAULT;

			mapi_sk(sk)->copy_thresh = val;
			return 0;
		}
#endif
	default:
		return -ENOPROTOOPT;
	}
}

int mapi_basic_getsockopt(struct socket *sock, int level, int optname, char *optval, int *optlen)
{
	int len;
	struct sock *sk = sock->sk;

	if(level != SOL_PACKET)
		return -ENOPROTOOPT;

	if(get_user(len, optlen))
		return -EFAULT;

	if(len < 0)
		return -EINVAL;

	switch (optname)
	{
                case PACKET_STATISTICS:
                        {
                                struct tpacket_stats st;

                                if(len > sizeof(struct tpacket_stats))
                                {
                                        len = sizeof(struct tpacket_stats);
                                }
                                
                                spin_lock_bh(&mapi_sk_receive_queue(sk).lock);
                                st = mapi_sk(sk)->stats;
                                memset(&mapi_sk(sk)->stats, 0, sizeof(st));
                                spin_unlock_bh(&mapi_sk_receive_queue(sk).lock);
                                st.tp_packets += st.tp_drops;

                                if(copy_to_user(optval, &st, len))
                                        return -EFAULT;
                                break;
                        }
                default:
                        return mapi_getsockopt(sock, level, optname, optval, optlen);
	}

	if(put_user(len, optlen))
		return -EFAULT;

	return 0;
}


static int mapi_notifier(struct notifier_block *this, unsigned long msg, void *data)
{
	struct sock *sk;
	struct hlist_node *node;
	struct net_device *dev = (struct net_device *)data;

	read_lock(&mapi_sklist_lock);

        sk_for_each(sk,node,&mapi_sklist) 
        {
                struct packet_opt *po = mapi_sk(sk);

		switch (msg)
		{
                        case NETDEV_DOWN:
                        case NETDEV_UNREGISTER:

                                if(dev->ifindex == po->ifindex)
                                {
                                        spin_lock(&po->bind_lock);
                                        if(po->running)
                                        {
                                                dev_remove_pack(&po->prot_hook);
                                                __sock_put(sk);
                                                po->running = 0;

                                                mapi_sk_err(sk) = ENETDOWN;
                                                
                                                if(!mapi_sk_dead(sk))
                                                {
                                                        mapi_sk_error_report(sk)(sk);
                                                }
                                        }
                                        if(msg == NETDEV_UNREGISTER)
                                        {
                                                po->ifindex = -1;
                                                po->prot_hook.dev = NULL;
                                        }
                                        spin_unlock(&po->bind_lock);
                                }
#ifdef CONFIG_PACKET_MULTICAST
                                if(po->mclist)
                                        mapi_dev_mclist(dev, po->mclist, -1);
#endif
                                break;

                        case NETDEV_UP:

                                spin_lock(&po->bind_lock);
                                if(dev->ifindex == po->ifindex && mapi_sk_num(sk) && po->running == 0)
                                {
                                        dev_add_pack(&po->prot_hook);
                                        sock_hold(sk);
                                        po->running = 1;
                                }
                                spin_unlock(&po->bind_lock);
#ifdef CONFIG_PACKET_MULTICAST
                                if(po->mclist)
                                        mapi_dev_mclist(dev, po->mclist, +1);
#endif
                                break;
		}
	}

	read_unlock(&mapi_sklist_lock);
	
        return NOTIFY_DONE;
}

static int mapi_basic_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;

	switch (cmd)
	{
                case SIOCOUTQ:
		{
			int amount = atomic_read(&mapi_sk_wmem_alloc(sk));
			
                        return put_user(amount, (int *)arg);
		}
                case SIOCINQ:
		{
			struct sk_buff *skb;
			int amount = 0;

			spin_lock_bh(&mapi_sk_receive_queue(sk).lock);
			skb = skb_peek(&mapi_sk_receive_queue(sk));
                        
			if(skb)
                        {
				amount = skb->len;
                        }
			
                        spin_unlock_bh(&mapi_sk_receive_queue(sk).lock);
			
                        return put_user(amount, (int *)arg);
		}
                case SIOCGSTAMP:
                        
                        if(mapi_sk_stamp(sk).tv_sec == 0)
                        {
                                return -ENOENT;
                        }

                        if(copy_to_user((void *)arg, &mapi_sk_stamp(sk), sizeof(struct timeval)))
                        {
                                return -EFAULT;
                        }
                        break;

#ifdef CONFIG_INET
		case SIOCADDRT:
		case SIOCDELRT:
		case SIOCDARP:
		case SIOCGARP:
		case SIOCSARP:
		case SIOCGIFADDR:
		case SIOCSIFADDR:
		case SIOCGIFBRDADDR:
		case SIOCSIFBRDADDR:
		case SIOCGIFNETMASK:
		case SIOCSIFNETMASK:
		case SIOCGIFDSTADDR:
		case SIOCSIFDSTADDR:
		case SIOCSIFFLAGS:
			return inet_dgram_ops.ioctl(sock,cmd,arg);
#endif

                default:
                        {
                                int ret;
                                
                                if((ret = mapi_ioctl(sock,cmd,arg)) != 0)
                                {
                                        if(ret == -EOPNOTSUPP)
                                        {
                                                return dev_ioctl(cmd,(void *)arg);
                                        }

                                        return ret;
                                }
                        }
	}

	return 0;
}

#ifndef CONFIG_MAPI_MMAP
#define mapi_mmap sock_no_mmap
#define mapi_poll datagram_poll
#else

unsigned int mapi_poll(struct file *file, struct socket *sock, poll_table * wait)
{
	struct sock *sk = sock->sk;
	struct packet_opt *po = mapi_sk(sk);
	unsigned int mask = datagram_poll(file, sock, wait);

	spin_lock_bh(&mapi_sk_receive_queue(sk).lock);
	
        if(po->iovec)
	{
		unsigned last = po->head ? po->head - 1 : po->iovmax;

		if(po->iovec[last]->tp_status)
			mask |= POLLIN | POLLRDNORM;
	}
        
	spin_unlock_bh(&mapi_sk_receive_queue(sk).lock);

	return mask;
}


/* Dirty? Well, I still did not learn better way to account
 * for user mmaps.
 */

static void mapi_mm_open(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct inode *inode = file->f_dentry->d_inode;
	struct socket *sock = mapi_sock_from_inode(inode);
	struct sock *sk = sock->sk;

	if(sk)
		atomic_inc(&mapi_sk(sk)->mapped);
}

static void mapi_mm_close(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct inode *inode = file->f_dentry->d_inode;
	struct socket *sock = mapi_sock_from_inode(inode);
	struct sock *sk = sock->sk;

	if(sk)
		atomic_dec(&mapi_sk(sk)->mapped);
}

static struct vm_operations_struct mapi_mmap_ops = {
    open:mapi_mm_open,
    close:mapi_mm_close,
};

static void free_pg_vec(unsigned long *pg_vec, unsigned order, unsigned len)
{
	int i;

	for(i = 0; i < len; i++)
	{
		if(pg_vec[i])
		{
			struct page *page, *pend;

			pend = virt_to_page(pg_vec[i] + (PAGE_SIZE << order) - 1);
			for(page = virt_to_page(pg_vec[i]); page <= pend; page++)
				ClearPageReserved(page);
			free_pages(pg_vec[i], order);
		}
	}
	kfree(pg_vec);
}

static int mapi_set_ring(struct sock *sk, struct tpacket_req *req, int closing)
{
	unsigned long *pg_vec = NULL;
	struct tpacket_hdr **io_vec = NULL;
	struct packet_opt *po = mapi_sk(sk);
	int order = 0;
	int err = 0;

	if(req->tp_block_nr)
	{
		int i, l;
		int frames_per_block;

		/*
		 * Sanity tests and some calculations 
		 */
		if((int)req->tp_block_size <= 0)
			return -EINVAL;
		if(req->tp_block_size & (PAGE_SIZE - 1))
			return -EINVAL;
		if(req->tp_frame_size < TPACKET_HDRLEN)
			return -EINVAL;
		if(req->tp_frame_size & (TPACKET_ALIGNMENT - 1))
			return -EINVAL;
		frames_per_block = req->tp_block_size / req->tp_frame_size;
		if(frames_per_block <= 0)
			return -EINVAL;
		if(frames_per_block * req->tp_block_nr != req->tp_frame_nr)
			return -EINVAL;
		/*
		 * OK! 
		 */

		/*
		 * Allocate page vector 
		 */
		while((PAGE_SIZE << order) < req->tp_block_size)
			order++;

		err = -ENOMEM;

		pg_vec = kmalloc(req->tp_block_nr * sizeof(unsigned long *), GFP_KERNEL);
		if(pg_vec == NULL)
			goto out;
		memset(pg_vec, 0, req->tp_block_nr * sizeof(unsigned long *));

		for(i = 0; i < req->tp_block_nr; i++)
		{
			struct page *page, *pend;
			pg_vec[i] = __get_free_pages(GFP_KERNEL, order);
			if(!pg_vec[i])
				goto out_free_pgvec;
			memset((void *)(pg_vec[i]), 0, PAGE_SIZE << order);
			pend = virt_to_page(pg_vec[i] + (PAGE_SIZE << order) - 1);
			for(page = virt_to_page(pg_vec[i]); page <= pend; page++)
				SetPageReserved(page);
		}
		/*
		 * Page vector is allocated 
		 */

		/*
		 * Draw frames 
		 */
		io_vec = kmalloc(req->tp_frame_nr * sizeof(struct tpacket_hdr *), GFP_KERNEL);
		if(io_vec == NULL)
			goto out_free_pgvec;
		memset(io_vec, 0, req->tp_frame_nr * sizeof(struct tpacket_hdr *));

		l = 0;
		for(i = 0; i < req->tp_block_nr; i++)
		{
			unsigned long ptr = pg_vec[i];
			int k;

			for(k = 0; k < frames_per_block; k++, l++)
			{
				io_vec[l] = (struct tpacket_hdr *)ptr;
				io_vec[l]->tp_status = TP_STATUS_KERNEL;
				ptr += req->tp_frame_size;
			}
		}
		/*
		 * Done 
		 */
	}
	else
	{
		if(req->tp_frame_nr)
			return -EINVAL;
	}

	lock_sock(sk);

	/*
	 * Detach socket from network 
	 */
	spin_lock(&po->bind_lock);
	if(po->running)
		dev_remove_pack(&po->prot_hook);
	spin_unlock(&po->bind_lock);

	err = -EBUSY;
	if(closing || atomic_read(&po->mapped) == 0)
	{
		err = 0;
#define XC(a, b) ({ __typeof__ ((a)) __t; __t = (a); (a) = (b); __t; })

		spin_lock_bh(&mapi_sk_receive_queue(sk).lock);
		pg_vec = XC(po->pg_vec, pg_vec);
		io_vec = XC(po->iovec, io_vec);
		po->iovmax = req->tp_frame_nr - 1;
		po->head = 0;
		po->frame_size = req->tp_frame_size;
		spin_unlock_bh(&mapi_sk_receive_queue(sk).lock);

		order = XC(po->pg_vec_order, order);
		req->tp_block_nr = XC(po->pg_vec_len, req->tp_block_nr);

		po->pg_vec_pages = req->tp_block_size / PAGE_SIZE;
		po->prot_hook.func = po->iovec ? tmapi_rcv : mapi_rcv;
		skb_queue_purge(&mapi_sk_receive_queue(sk));
#undef XC
		if(atomic_read(&po->mapped))
			printk(KERN_DEBUG "mapi_mmap: vma is busy: %d\n", atomic_read(&po->mapped));
	}

	spin_lock(&po->bind_lock);
	if(po->running)
		dev_add_pack(&po->prot_hook);
	spin_unlock(&po->bind_lock);

	release_sock(sk);

	if(io_vec)
		kfree(io_vec);

    out_free_pgvec:
	if(pg_vec)
		free_pg_vec(pg_vec, order, req->tp_block_nr);
    out:
	return err;
}

static int mapi_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma)
{
	struct sock *sk = sock->sk;
	struct packet_opt *po = mapi_sk(sk);
	unsigned long size;
	unsigned long start;
	int err = -EINVAL;
	int i;

	if(vma->vm_pgoff)
		return -EINVAL;

	size = vma->vm_end - vma->vm_start;

	lock_sock(sk);
	if(po->pg_vec == NULL)
		goto out;
	if(size != po->pg_vec_len * po->pg_vec_pages * PAGE_SIZE)
		goto out;

	atomic_inc(&po->mapped);
	start = vma->vm_start;
	err = -EAGAIN;
        
	for(i = 0; i < po->pg_vec_len; i++)
	{
#if V_BEFORE(2,5,0)
		if(remap_page_range(start,__pa(po->pg_vec[i]),po->pg_vec_pages * PAGE_SIZE,vma->vm_page_prot))
                {
			goto out;
                }
#else
                if(remap_page_range(vma,start,__pa(po->pg_vec[i]),po->pg_vec_pages * PAGE_SIZE,vma->vm_page_prot))
                {
			goto out;
                }
#endif

		start += po->pg_vec_pages * PAGE_SIZE;
	}
        
	vma->vm_ops = &mapi_mmap_ops;
	err = 0;

    out:
	release_sock(sk);

	return err;
}
#endif

struct proto_ops mapi_ops = {
    family:PF_MAPI,

    release:mapi_release,
    bind:mapi_bind,
    connect:sock_no_connect,
    socketpair:sock_no_socketpair,
    accept:sock_no_accept,
    getname:mapi_getname,
    poll:mapi_poll,
    ioctl:mapi_basic_ioctl,
    listen:sock_no_listen,
    shutdown:sock_no_shutdown,
    setsockopt:mapi_basic_setsockopt,
    getsockopt:mapi_basic_getsockopt,
    sendmsg:mapi_sendmsg,
    recvmsg:mapi_recvmsg,
    mmap:mapi_mmap,
    sendpage:sock_no_sendpage,
};

static struct net_proto_family mapi_family_ops = {
    family:PF_MAPI,
    create:mapi_create,
};

static struct notifier_block mapi_netdev_notifier = {
    notifier_call:mapi_notifier,
};

#ifdef CONFIG_PROC_FS
static int mapi_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;
	struct sock *s;
	struct hlist_node *node;

	len += sprintf(buffer, "sk       RefCnt Type Proto  Iface R Rmem   User   Inode Predef\n");

	lock_active_socket_list() ;
	
        sk_for_each(s,node,&mapi_sklist)
	{
                struct packet_opt *po = mapi_sk(s);
                
		len += sprintf(buffer + len, "%p %-6d %-4d %04x   %-5d %1d %-6u %-6u %-6lu %-6u", 
                               s, 
                               atomic_read(&mapi_sk_refcnt(s)), 
                               mapi_sk_type(s),
                               ntohs(mapi_sk_num(s)), 
                               po->ifindex,
                               po->running, 
                               atomic_read(&mapi_sk_rmem_alloc(s)),
                               sock_i_uid(s), 
                               sock_i_ino(s),
                               atomic_read(&po->predef_func_nr)
                               );

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

static void __exit mapi_exit(void)
{
	remove_proc_entry("net/mapi", 0);
	unregister_netdevice_notifier(&mapi_netdev_notifier);
	sock_unregister(PF_MAPI);

	exit_mapi();

	return;
}

static int __init mapi_init(void)
{
	int ret;
	
	sock_register(&mapi_family_ops);
	register_netdevice_notifier(&mapi_netdev_notifier);

#ifdef CONFIG_PROC_FS
	create_proc_read_entry("net/mapi", 0, 0, mapi_read_proc, NULL);
#endif

	if((ret = init_mapi()) != 0)
	{
		return ret;
	}

	return 0;
}

module_init(mapi_init);
module_exit(mapi_exit);
MODULE_LICENSE("GPL");

// vim:ts=8:expandtab
