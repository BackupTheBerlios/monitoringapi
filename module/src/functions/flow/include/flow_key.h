/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __FLOW_KEY_H_
#define __FLOW_KEY_H_

struct flow_key
{
	int in_dev;
	int out_dev;
	u32 src_ip;
	u32 dst_ip;
	u8 ip_proto;
	u8 ip_version;
	u16 src_port;
	u16 dst_port;
};

struct flow_key *flow_key_alloc(int gfp);
void flow_key_free(struct flow_key *key);

u32 flow_key_hash_func(struct flow_key *key,struct flow_key_struct *fks);
u8 flow_key_equals_func(struct flow_key *keyA,struct flow_key *keyB,struct flow_key_struct *fks);
void fill_flow_key(struct flow_key *key,struct subflow *sbf,struct flow_key_struct *fks);
void get_flow_key_fields(struct sk_buff *skb,struct flow_key *fkey,struct flow_key_struct *fks);

#endif /* __FLOW_KEY_H_ */
