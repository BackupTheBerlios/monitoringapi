/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 * 		partially stolen from click router
 * 		
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/fs.h>
#include <asm/errno.h>

#include <linux/mapi/timeval.h>
#include <linux/mapi/common.h>
#include <fakepcap.h>

PUBLIC u8 fake_pcap_write_file_header(struct file *filp,int encap_type,int snaplen)
{
	struct fake_pcap_file_header h;
	size_t wrote_header;

	h.magic = FAKE_PCAP_MAGIC;
	h.version_major = FAKE_PCAP_VERSION_MAJOR;
	h.version_minor = FAKE_PCAP_VERSION_MINOR;

	h.thiszone = 0;             // timestamps are in GMT
	h.sigfigs = 0;              // XXX accuracy of timestamps?
	h.snaplen = snaplen;
	h.linktype = encap_type;

	wrote_header = filp->f_op->write(filp,(const char *)&h,sizeof(h),&filp->f_pos);

	if(wrote_header != sizeof(h))
	{
		return 1;
	}

	return 0;
}

PUBLIC u8 fake_pcap_write_packet(struct file *filp,struct sk_buff *skb,int snaplen)
{
	struct fake_pcap_pkthdr ph;
	const struct timeval ts = skb->stamp;
	unsigned to_write;
	
	if(!ts.tv_sec && !ts.tv_usec) 
	{
		struct timeval now;
		tv_stamp(&now);

		ph.ts.tv_sec = now.tv_sec;
		ph.ts.tv_usec = now.tv_usec;
	} 
	else 
	{
		ph.ts.tv_sec = ts.tv_sec;
		ph.ts.tv_usec = ts.tv_usec;
	}

	to_write = skb->tail - skb->mac.raw;

	ph.len = to_write;

	if(to_write > snaplen)
	{
		to_write = snaplen;
	}
	
	ph.caplen = to_write;

	if(filp->f_op->write(filp,(const char *)&ph,sizeof(ph),&filp->f_pos) == 0 ||
	   filp->f_op->write(filp,(const char *)skb->mac.raw,to_write,&filp->f_pos) == 0)
	{
		return 1;
	}

	return 0;
}
