/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __DECIDE_H_
#define __DECIDE_H_

extern kmem_cache_t *decide_cache;

int decide_intercept_ioctl(struct socket *real_sock,struct socket *virtual_sock,unsigned long arg);

int register_decide_proxy(struct sock *real_sk,struct socket *parent_sock,struct decide_struct *ds_to_copy);
int unregister_decide_proxy(struct sock *real_sk,u16 uid);

int __init decide_proxy_init(void);
void __exit decide_proxy_exit(void);

struct socket *get_left_socket(struct decide_struct *ds);
struct socket *get_right_socket(struct decide_struct *ds);

#endif /* __DECIDE_H_ */
