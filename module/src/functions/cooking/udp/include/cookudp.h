/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __COOKUDP_H
#define __COOKUDP_H

#include <linux/mapi/common.h>

__u8 mapi_udp(struct sk_buff *skb,struct predef_func *pf);

#endif /* __COOKUDP_H */
