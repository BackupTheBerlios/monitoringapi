/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_COMPAT_SOCK_H_
#define __MAPI_COMPAT_SOCK_H_

#ifdef __KERNEL__

#if V_BEFORE(2,6,0)

#define mapi_sk(__sk)			((struct packet_opt *)((__sk)->protinfo.af_packet))
#define mapi_sk_num(__sk)		(__sk->num)
#define mapi_sk_dead(__sk)		(__sk->dead)
#define mapi_sk_alloc()			(sk_alloc(PF_MAPI,GFP_KERNEL,1))
#define mapi_sk_set_owner(__sk)		do {} while(0);
#define mapi_sk_receive_queue(__sk)	(__sk->receive_queue)
#define mapi_sk_rmem_alloc(__sk)	(__sk->rmem_alloc)
#define mapi_sk_wmem_alloc(__sk)	(__sk->wmem_alloc)
#define mapi_sk_type(__sk)		(__sk->type)
#define mapi_sk_protocol(__sk)		(__sk->protocol)
#define mapi_sk_priority(__sk)		(__sk->priority)
#define mapi_sk_err(__sk)		(__sk->err)
#define mapi_sk_error_report(__sk)	(__sk->error_report)
#define mapi_sk_family(__sk)		(__sk->family)
#define mapi_sk_destruct(__sk)		(__sk->destruct)
#define mapi_sk_socket(__sk)		(__sk->socket)
#define mapi_sk_stamp(__sk)		(__sk->stamp)
#define mapi_sk_refcnt(__sk)		(__sk->refcnt)
#define mapi_sk_node(__sk)		((*(struct hlist_node *)(__sk + ((unsigned long)(&((struct sock *)0)->daddr)))))	/* Hack */
#define mapi_sk_rcvbuf(__sk)		(__sk->rcvbuf)
#define mapi_sk_data_ready(__sk)	(__sk->data_ready)
#define mapi_sk_user_data(__sk)		(__sk->user_data)

#else

#define mapi_sk(__sk)			((struct packet_opt *)(__sk)->sk_protinfo)
#define mapi_sk_num(__sk)		(mapi_sk(__sk)->num)
#define mapi_sk_dead(__sk)		(test_bit(SOCK_DEAD,&sk->sk_flags))
#define mapi_sk_alloc()			(sk_alloc(PF_MAPI,GFP_KERNEL,1,NULL))
#define mapi_sk_set_owner(__sk)		(sk_set_owner(__sk,THIS_MODULE))
#define mapi_sk_receive_queue(__sk)	(__sk->sk_receive_queue)
#define mapi_sk_rmem_alloc(__sk)	(__sk->sk_rmem_alloc)
#define mapi_sk_wmem_alloc(__sk)	(__sk->sk_wmem_alloc)
#define mapi_sk_type(__sk)		(__sk->sk_type)
#define mapi_sk_protocol(__sk)		(__sk->sk_protocol)
#define mapi_sk_priority(__sk)		(__sk->sk_priority)
#define mapi_sk_err(__sk)		(__sk->sk_err)
#define mapi_sk_error_report(__sk)	(__sk->sk_error_report)
#define mapi_sk_family(__sk)		(__sk->sk_family)
#define mapi_sk_destruct(__sk)		(__sk->sk_destruct)
#define mapi_sk_socket(__sk)		(__sk->sk_socket)
#define mapi_sk_stamp(__sk)		(__sk->sk_stamp)
#define mapi_sk_refcnt(__sk)		(__sk->sk_refcnt)
#define mapi_sk_node(__sk)		(__sk->sk_node)
#define mapi_sk_rcvbuf(__sk)		(__sk->sk_rcvbuf)
#define mapi_sk_data_ready(__sk)	(__sk->sk_data_ready)
#define mapi_sk_user_data(__sk)		(__sk->sk_user_data)

#endif

#endif /* __KERNEL__ */

#endif /* __MAPI_COMPAT_SOCK_H_ */
