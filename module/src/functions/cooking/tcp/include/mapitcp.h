/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPITCP_H
#define __MAPITCP_H

#include <asm/string.h>
#include <asm/byteorder.h>
#include <linux/slab.h>
#include <linux/in.h>

#ifdef __KERNEL__

#define CON_JUST_EST	1
#define CON_DATA	2
#define CON_CLOSE	3
#define CON_RESET	4
#define CON_TIMED_OUT	5
#define CON_EXITING	6

struct tuple4			// TCP connection parameters
{
	u32 saddr;		// client and server IP addresses
	u32 daddr;
	u16 source;		// client and server port numbers
	u16 dest;
};

struct packet_struct
{
	struct packet_struct *next;
	struct packet_struct *prev;

	void *data;
	u32 len;
	u32 truesize;
	
	u32 urg_ptr;

	u8 fin;
	u8 urg;
	u32 seq;
	u32 ack;
};

struct half_stream		// structure describing one side of a TCP connection
{
	char state;		// socket state (ie TCP_ESTABLISHED )
	char collect;		// if > 0, then data should be stored in
				// "data" buffer; else
				// data flowing in this direction will be ignored

	char collect_urg;	// analogically, determines if to collect urgent
				// data


	u8 *data;		// buffer for normal data
	u8 urgdata;		// one-byte buffer for urgent data
	
	int count;		// how many bytes has been appended to buffer "data"
				// since the creation of a connection
	
	int offset;		// offset (in data stream) of first byte stored in
				// the "data" buffer

	int count_new;		// how many bytes were appended to "data" buffer
				// last (this) time; if == 0, no new data arrived
	
	u8 count_new_urg;	// if != 0, new urgent data arrived

	int bufsize;
	int rmem_alloc;

	int urg_count;
	
	u32 acked;
	u32 seq;
	u32 ack_seq;
	u32 first_data_seq;
	u8 urg_seen;
	u32 urg_ptr;
	u16 window;

	struct packet_struct *list;
	struct packet_struct *listtail;
};

struct tcp_stream
{
	struct tuple4 addr;
	struct half_stream client;	// structures describing client and
					// server side of the connection
	struct half_stream server;
	struct tcp_stream *next_node;
	struct tcp_stream *prev_node;
	struct tcp_stream *next_time;
	struct tcp_stream *prev_time;
	struct tcp_stream *next_free;
	char con_state;			// logical state of the connection
	int hash_index;
	int read;
};

#define b_comp(x,y)	(!memcmp(&(x), &(y), sizeof(x)))

u16 mapi_tcp_check(struct tcphdr *th,int len,u32 saddr,u32 daddr);

#endif /* __KERNEL__ */

#endif /* __MAPITCP_H */
