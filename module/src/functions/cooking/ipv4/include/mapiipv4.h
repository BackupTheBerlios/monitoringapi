/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPIIPV4_H
#define __MAPIPV4_H

#include <linux/mapi/common.h>

#ifdef __KERNEL__

struct sk_buff *mapi_ip_rcv(struct sk_buff *skb,struct predef_func *pf);
struct sk_buff *mapi_ip_defrag(struct sk_buff *skb,struct predef_func *pf);

u8 mapi_defragmentation_init(void);
u8 mapi_defragmentation_exit(void);

#endif /* __KERNEL__ */

#endif /* __MAPIPV4_H */
