/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_SKBUFF_H_
#define __MAPI_SKBUFF_H_

static inline int mapi_pskb_may_pull(struct sk_buff *skb,unsigned int len)
{
	if(len <= skb->len)
	{
		return 1;
	}
	
	return 0;
}

#endif /* __MAPI_SKBUFF_H_ */
