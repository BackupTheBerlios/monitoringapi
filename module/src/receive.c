/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/module.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>

EXPORT_SYMBOL(receive);
EXPORT_SYMBOL(mapi_skb_private);

PUBLIC struct sk_buff *mapi_skb_private(struct sk_buff **skbp,struct sock *sk)
{
	struct sk_buff *skb = *skbp;
	
	if(skb_shared(skb))
	{
		struct sk_buff *nskb = skb_clone(skb,GFP_ATOMIC);

		kfree_skb(skb);

		skb = nskb;
		*skbp = skb;
	}

	return skb;
}

PUBLIC void receive(struct sk_buff **skbp,struct sock *sk)
{
#ifdef CONFIG_MAPI_MMAP	
	struct packet_opt *po = mapi_sk(sk);
	
	if(po->iovec == NULL)
	{
		receive_nommap(skbp,sk);
	}
	else
	{
		receive_mmap(skbp,sk);
	}
#else
	receive_nommap(skbp,sk);
#endif
}

// vim:ts=8:expandtab

