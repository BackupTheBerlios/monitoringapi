/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 * 		stolen from click
 * 		
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __FAKEPCAP_H_
#define __FAKEPCAP_H_

#define FAKE_PCAP_MAGIC			0xa1b2c3d4
#define	FAKE_MODIFIED_PCAP_MAGIC	0xa1b2cd34
#define FAKE_PCAP_VERSION_MAJOR		2
#define FAKE_PCAP_VERSION_MINOR		4

/*
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 * Many fields here are 32 bit ints so compilers won't insert unwanted
 * padding; these files need to be interchangeable across architectures.
 */
struct fake_pcap_file_header
{
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;					 /* gmt to local correction */
	uint32_t sigfigs;					 /* accuracy of timestamps */
	uint32_t snaplen;					 /* max length saved portion of each pkt */
	uint32_t linktype;					 /* data link type (DLT_*) */
};

struct fake_bpf_timeval
{
	int32_t tv_sec;
	int32_t tv_usec;
};

/*
 * Each packet in the dump file is prepended with this generic header.
 * This gets around the problem of different headers for different
 * packet interfaces.
 */
struct fake_pcap_pkthdr
{
	struct fake_bpf_timeval ts;			 /* time stamp */
	uint32_t caplen;				 /* length of portion present */
	uint32_t len;					 /* length this packet (off wire) */
};

/* Unfortunately, Linux tcpdump generates a different format. */
struct fake_modified_pcap_pkthdr
{
	struct fake_pcap_pkthdr hdr;			 /* the regular header */
	uint32_t ifindex;				 /* index, in *capturing* machine's list of
							  * interfaces, of the interface on which this
							  * packet came in. */
	uint16_t protocol;				 /* Ethernet packet type */
	uint8_t pkt_type;				 /* broadcast/multicast/etc. indication */
	uint8_t pad;					 /* pad to a 4-byte boundary */
};

u8 fake_pcap_write_file_header(struct file *filp,int encap_type,int snaplen);
u8 fake_pcap_write_packet(struct file *filp,struct sk_buff *skb,int snaplen);

#endif /* __FAKEPCAP_H_ */
