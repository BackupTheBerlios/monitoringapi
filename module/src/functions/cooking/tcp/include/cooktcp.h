/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __COOKPACKETS_H
#define __COOKPACKETS_H

#ifdef __KERNEL__

struct proc_dir_entry *cook_packets_proc_path;

int mapi_tcp_init(struct cook_tcp_struct *cts);
void mapi_tcp_deinit(struct cook_tcp_struct *cts);

struct sk_buff *mapi_tcp(struct sk_buff *skb,struct sock *sk);

#endif /* __KERNEL__ */

#endif /* __COOKPACKETS_H */
