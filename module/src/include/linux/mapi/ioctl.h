/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_IOCTL_H
#define __MAPI_IOCTL_H

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/filter.h>

#ifndef _NET_IF_H
#include <linux/netdevice.h>
#endif

#include <linux/mapi/prof.h>
#include <linux/mapi/log.h>

#define AF_MAPI	27
#define PF_MAPI	AF_MAPI

#define FINVALID			0
#define COUNT_PACKETS			1
#define COUNT_BYTES			2
#define SAMPLE_PACKETS			3
#define SUBSTRING_SEARCH		4
#define HASH				5
#define SUBFLOW				6
#define LOGGING				7
#define EXB				8
#define PACKETS_IN_INTERVAL		9
#define BYTES_IN_INTERVAL		10
#define PACKET_DISTRIBUTION		11
#define PACKET_SAVE			12
#define COOK_IP				13
#define COOK_UDP			14
#define COOK_TCP			15
#define PKT_TYPE			16
#define METER				17
#define BAND_METER			18
#define CHECK_IP_HDR			19
#define CHECK_UDP_HDR			20
#define CHECK_TCP_HDR			21
#define PRINT_ETHER			22
#define PRINT_IP			23
#define PRINT_UDP			24
#define PRINT_TCP			25
#define NETDEV_STATS			26
#define SET_PERF_COUNTER		27
#define ACCUM_PERF_COUNTER		28
#define SET_CYCLE_COUNTER		30
#define ACCUM_CYCLE_COUNTER		31
#define BPF_FILTER			32
#define CACHED_BPF_FILTER		33
#define FLOW_REPORT			34
#define FLOW_KEY			35
#define FLOW_RAW			36
#define DECIDE				37
#define DECIDE_BPF_HOOK			38
#define DECIDE_ACTION_HOOK		39
#define DECIDE_TEE_HOOK			40
#define DECIDE_PROXY			41
#define PREDEF_MAX			42

#define MAPI_MAGIC 'x'

#define SIOCRESET		_IO(MAPI_MAGIC, 1)

#define SIOCSCOUNT_PACKETS	_IO(MAPI_MAGIC, 2)
#define SIOCGCOUNT_PACKETS	_IO(MAPI_MAGIC, 3)
#define SIOCRSCOUNT_PACKETS	_IO(MAPI_MAGIC, 4)
#define SIOCRMCOUNT_PACKETS	_IO(MAPI_MAGIC, 5)

#define SIOCSCOUNT_BYTES	_IO(MAPI_MAGIC, 6)
#define SIOCGCOUNT_BYTES	_IO(MAPI_MAGIC, 7)
#define SIOCRSCOUNT_BYTES	_IO(MAPI_MAGIC, 8)
#define SIOCRMCOUNT_BYTES	_IO(MAPI_MAGIC, 9)

#define SIOCSSAMPLE_PACKETS	_IO(MAPI_MAGIC, 10)
#define SIOCRMSAMPLE_PACKETS	_IO(MAPI_MAGIC, 11)

#define SAMPLE_MODE_ALL		0
#define SAMPLE_MODE_NONE	1
#define SAMPLE_MODE_DET		2
#define SAMPLE_MODE_PROB	3

#define SIOCSSUBSTRING_SEARCH	_IO(MAPI_MAGIC, 12)
#define SIOCGSUBSTRING_SEARCH	_IO(MAPI_MAGIC, 13)
#define SIOCRSSUBSTRING_SEARCH	_IO(MAPI_MAGIC, 14)
#define SIOCRMSUBSTRING_SEARCH	_IO(MAPI_MAGIC, 15)

#define SIOCSHASH		_IO(MAPI_MAGIC, 16)
#define SIOCGHASH		_IO(MAPI_MAGIC, 17)
#define SIOCRSHASH		_IO(MAPI_MAGIC, 18)
#define SIOCRMHASH		_IO(MAPI_MAGIC, 19)

#define HASH_ADDITIVE	0
#define HASH_ROTATING	1

#define SIOCSSUBFLOW	_IO(MAPI_MAGIC, 20)
#define SIOCGSUBFLOW	_IO(MAPI_MAGIC, 21)
#define SIOCRSSUBFLOW	_IO(MAPI_MAGIC, 22)
#define SIOCRMSUBFLOW	_IO(MAPI_MAGIC, 23)
#define SIOCSASYNCSUBFLOW	_IO(MAPI_MAGIC, 24)
#define SIOCRMASYNCSUBFLOW	_IO(MAPI_MAGIC, 25)
#define SIOCEXPIREALL	_IO(MAPI_MAGIC, 26)

#define SIOCSLOGGING	_IO(MAPI_MAGIC, 27)
#define SIOCGLOGGING	_IO(MAPI_MAGIC, 28)
#define SIOCRSLOGGING	_IO(MAPI_MAGIC, 29)
#define SIOCRMLOGGING	_IO(MAPI_MAGIC, 30)

#define SIOCSCOOK_IP	_IO(MAPI_MAGIC, 31)
#define SIOCGCOOK_IP	_IO(MAPI_MAGIC, 32)
#define SIOCRSCOOK_IP	_IO(MAPI_MAGIC, 33)
#define SIOCRMCOOK_IP	_IO(MAPI_MAGIC, 34)

#define SIOCSEXB	_IO(MAPI_MAGIC, 35)
#define SIOCGEXB	_IO(MAPI_MAGIC, 36)
#define SIOCRSEXB	_IO(MAPI_MAGIC, 37)
#define SIOCRMEXB	_IO(MAPI_MAGIC, 38)

#define SIOCSPACKETS_IN_INTERVAL	_IO(MAPI_MAGIC, 39)
#define SIOCGPACKETS_IN_INTERVAL	_IO(MAPI_MAGIC, 40)
#define SIOCRSPACKETS_IN_INTERVAL	_IO(MAPI_MAGIC, 41)
#define SIOCRMPACKETS_IN_INTERVAL	_IO(MAPI_MAGIC, 42)
#define SIOCSASYNCPACKETS_IN_INTERVAL	_IO(MAPI_MAGIC, 43)
#define SIOCRMASYNCPACKETS_IN_INTERVAL	_IO(MAPI_MAGIC, 44)

#define SIOCSBYTES_IN_INTERVAL		_IO(MAPI_MAGIC, 45)
#define SIOCGBYTES_IN_INTERVAL		_IO(MAPI_MAGIC, 46)
#define SIOCRSBYTES_IN_INTERVAL		_IO(MAPI_MAGIC, 47)
#define SIOCRMBYTES_IN_INTERVAL		_IO(MAPI_MAGIC, 48)
#define SIOCSASYNCBYTES_IN_INTERVAL	_IO(MAPI_MAGIC, 49)
#define SIOCRMASYNCBYTES_IN_INTERVAL	_IO(MAPI_MAGIC, 50)

#define SIOCSPACKET_DISTRIBUTION	_IO(MAPI_MAGIC, 51)
#define SIOCGPACKET_DISTRIBUTION	_IO(MAPI_MAGIC, 52)
#define SIOCRSPACKET_DISTRIBUTION	_IO(MAPI_MAGIC, 53)
#define SIOCRMPACKET_DISTRIBUTION	_IO(MAPI_MAGIC, 54)

#define SIOCSPACKET_SAVE		_IO(MAPI_MAGIC, 55)
#define SIOCRMPACKET_SAVE		_IO(MAPI_MAGIC, 56)

#define SIOCSCOOK_UDP	_IO(MAPI_MAGIC, 57)
#define SIOCGCOOK_UDP	_IO(MAPI_MAGIC, 58)
#define SIOCRSCOOK_UDP	_IO(MAPI_MAGIC, 59)
#define SIOCRMCOOK_UDP	_IO(MAPI_MAGIC, 60)

#define SIOCSCOOK_TCP	_IO(MAPI_MAGIC, 61)
#define SIOCGCOOK_TCP	_IO(MAPI_MAGIC, 62)
#define SIOCRSCOOK_TCP	_IO(MAPI_MAGIC, 63)
#define SIOCRMCOOK_TCP	_IO(MAPI_MAGIC, 64)

#define SIOCSPKT_TYPE	_IO(MAPI_MAGIC, 65)
#define SIOCRMPKT_TYPE	_IO(MAPI_MAGIC, 66)

#define SIOCSMETER	_IO(MAPI_MAGIC, 67)
#define SIOCGMETER	_IO(MAPI_MAGIC, 68)
#define SIOCRSMETER	_IO(MAPI_MAGIC, 69)
#define SIOCRMMETER	_IO(MAPI_MAGIC, 70)

#define SIOCSBAND_METER		_IO(MAPI_MAGIC, 71)
#define SIOCGBAND_METER		_IO(MAPI_MAGIC, 72)
#define SIOCRSBAND_METER	_IO(MAPI_MAGIC, 73)
#define SIOCRMBAND_METER	_IO(MAPI_MAGIC, 74)

#define SIOCSCHECK_IP_HDR	_IO(MAPI_MAGIC, 75)
#define SIOCGCHECK_IP_HDR	_IO(MAPI_MAGIC, 76)
#define SIOCRSCHECK_IP_HDR	_IO(MAPI_MAGIC, 77)
#define SIOCRMCHECK_IP_HDR	_IO(MAPI_MAGIC, 78)

#define SIOCSCHECK_UDP_HDR	_IO(MAPI_MAGIC, 79)
#define SIOCGCHECK_UDP_HDR	_IO(MAPI_MAGIC, 80)
#define SIOCRSCHECK_UDP_HDR	_IO(MAPI_MAGIC, 81)
#define SIOCRMCHECK_UDP_HDR	_IO(MAPI_MAGIC, 82)

#define SIOCSCHECK_TCP_HDR	_IO(MAPI_MAGIC, 83)
#define SIOCGCHECK_TCP_HDR	_IO(MAPI_MAGIC, 84)
#define SIOCRSCHECK_TCP_HDR	_IO(MAPI_MAGIC, 85)
#define SIOCRMCHECK_TCP_HDR	_IO(MAPI_MAGIC, 86)

#define SIOCSPRINT_ETHER	_IO(MAPI_MAGIC, 87)
#define SIOCRMPRINT_ETHER	_IO(MAPI_MAGIC, 88)

#define SIOCSPRINT_IP		_IO(MAPI_MAGIC, 89)
#define SIOCRMPRINT_IP		_IO(MAPI_MAGIC, 90)

#define SIOCSPRINT_UDP		_IO(MAPI_MAGIC, 91)
#define SIOCRMPRINT_UDP		_IO(MAPI_MAGIC, 92)

#define SIOCSPRINT_TCP		_IO(MAPI_MAGIC, 93)
#define SIOCRMPRINT_TCP		_IO(MAPI_MAGIC, 94)

#define SIOCSNETDEV_STATS	_IO(MAPI_MAGIC, 95)
#define SIOCGNETDEV_STATS	_IO(MAPI_MAGIC, 96)
#define SIOCRSNETDEV_STATS	_IO(MAPI_MAGIC, 97)
#define SIOCRMNETDEV_STATS	_IO(MAPI_MAGIC, 98)

#define SIOCSSET_PERF_COUNTER		_IO(MAPI_MAGIC, 99)
#define SIOCRMSET_PERF_COUNTER		_IO(MAPI_MAGIC, 100)

#define SIOCSACCUM_PERF_COUNTER		_IO(MAPI_MAGIC, 101)
#define SIOCGACCUM_PERF_COUNTER		_IO(MAPI_MAGIC, 102)
#define SIOCRSACCUM_PERF_COUNTER	_IO(MAPI_MAGIC, 103)
#define SIOCRMACCUM_PERF_COUNTER	_IO(MAPI_MAGIC, 104)

#define SIOCSSET_CYCLE_COUNTER		_IO(MAPI_MAGIC, 105)
#define SIOCRMSET_CYCLE_COUNTER		_IO(MAPI_MAGIC, 106)

#define SIOCSACCUM_CYCLE_COUNTER	_IO(MAPI_MAGIC, 107)
#define SIOCGACCUM_CYCLE_COUNTER	_IO(MAPI_MAGIC, 108)
#define SIOCRSACCUM_CYCLE_COUNTER	_IO(MAPI_MAGIC, 109)
#define SIOCRMACCUM_CYCLE_COUNTER	_IO(MAPI_MAGIC, 110)

#define SIOCSBPF_FILTER			_IO(MAPI_MAGIC, 111)
#define SIOCGBPF_FILTER			_IO(MAPI_MAGIC, 112)
#define SIOCRSBPF_FILTER		_IO(MAPI_MAGIC, 113)
#define SIOCRMBPF_FILTER		_IO(MAPI_MAGIC, 114)

#define SIOCSCACHED_BPF_FILTER		_IO(MAPI_MAGIC, 115)
#define SIOCGCACHED_BPF_FILTER		_IO(MAPI_MAGIC, 116)
#define SIOCRSCACHED_BPF_FILTER		_IO(MAPI_MAGIC, 117)
#define SIOCRMCACHED_BPF_FILTER		_IO(MAPI_MAGIC, 118)

#define SIOCSFLOW_REPORT	_IO(MAPI_MAGIC, 119)
#define SIOCRMFLOW_REPORT	_IO(MAPI_MAGIC, 120)

#define NETFLOW_V1	0
#define NETFLOW_V5	1
#define NETFLOW_V7	2

#define SIOCSFLOW_KEY	_IO(MAPI_MAGIC, 121)
#define SIOCRMFLOW_KEY	_IO(MAPI_MAGIC, 122)

#define SIOCSFLOW_RAW		_IO(MAPI_MAGIC, 123)
#define SIOCGFLOW_RAW		_IO(MAPI_MAGIC, 124)
#define SIOCRMFLOW_RAW		_IO(MAPI_MAGIC, 125)
#define SIOCGNFLOW_RAW		_IO(MAPI_MAGIC, 126)

#define SIOCSDECIDE		_IO(MAPI_MAGIC, 127)
#define SIOCRMDECIDE		_IO(MAPI_MAGIC, 128)
#define SIOCIODECIDE		_IO(MAPI_MAGIC, 129)
#define SIOCDBDECIDE		_IO(MAPI_MAGIC, 130)

#define SIOCSDECIDE_BPF_HOOK		_IO(MAPI_MAGIC, 131)
#define SIOCRMDECIDE_BPF_HOOK		_IO(MAPI_MAGIC, 132)

#define SIOCSDECIDE_ACTION_HOOK		_IO(MAPI_MAGIC, 133)
#define SIOCRMDECIDE_ACTION_HOOK	_IO(MAPI_MAGIC, 134)

#define SIOCSDECIDE_TEE_HOOK		_IO(MAPI_MAGIC, 135)
#define SIOCRMDECIDE_TEE_HOOK		_IO(MAPI_MAGIC, 136)

struct count_packets_struct
{
	__u64 counter;

	__u16 uid;
};

struct count_bytes_struct
{
	__u64 counter;
	
	__u16 uid;
};

struct sample_packets_struct
{
	__u32 period;
	__u8 mode;

#define CB_LENGTH (16 - sizeof(__u32) - sizeof(__u8))
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH	
};

struct substring_search_struct
{
	__s8 *string;
	__u32 length;
	__u64 counter;
	
#define CB_LENGTH (32 - sizeof(__s8) - sizeof(__u32) - sizeof(__u64))
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH	
};

struct hash_struct
{
	__u8 mode;

	__s32 prime;
	__s32 low;
	__s32 high;

#define CB_LENGTH (32 - sizeof(__u8) - 3*sizeof(__s32))
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH	
};

struct subflow
{
	int in_dev;
	int out_dev;
	
	__u32 src_ip;
	__u32 dst_ip;
	__u8 ip_proto;
	__u8 ip_version;
	__u16 src_port;
	__u16 dst_port;
	
	__u64 npackets;
	__u64 nbytes;
	
	__u8 tos;
	__u8 tcp_flags;
	
	struct timeval start_time;
	struct timeval end_time;
	
	__u32 probe_uid;
	
	__u8 icmp_type;
	__u8 icmp_code;
	
	double avg_tbpa;
	double std_dev_tbpa;

	double avg_ps;
	double std_dev_ps;

#define CB_LENGTH (32)
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH	
};

struct subflow_ioctl_struct
{
	__u64 timeout;
	__u64 max_duration;
};

struct logging_struct
{
	__s8 *filename;
	__u32 length;
	
	__u32 file_size;
	__u32 packets_logged;
	
	__u16 snaplen;
	int encap_type;
	
#define CB_LENGTH (32 - sizeof(__s8) - 3*sizeof(__u32))
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH	
};

struct cook_ip_struct
{
	__u32 defrag_completed;
	__u32 ip_header_errors;
	__u32 ip_options_errors;
	__u32 defrag_errors;
};

struct cook_udp_struct
{
	__u32 short_packets;
	__u32 csum_errors;
	__u32 no_header_errors;
};

struct cook_tcp_struct
{
	__u64 paparies;
};

struct exb_struct
{
	__s8 *string;
	__u32 length;
	__u64 counter;
	
#define CB_LENGTH (32 - sizeof(__s8) - 3*sizeof(__u32))
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH	
};

struct packets_in_interval_struct
{
	__u64 time_interval;
	__u64 counter;
	
	struct timeval start_time;
	pid_t pid;

#define CB_LENGTH (64 - 2*sizeof(__u64) - sizeof(struct timeval) - sizeof(pid_t))
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH	
};

struct bytes_in_interval_struct
{
	__u64 time_interval;
	__u64 counter;
	
	struct timeval start_time;
	pid_t pid;

#define CB_LENGTH (64 - 2*sizeof(__u64) - sizeof(struct timeval) - sizeof(pid_t))
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH	
};

#define MAX_MASK 16
#define MAX_DIST_ARRAY_SIZE 65536	/* this equals to 2^MAX_MASK */
#define DIST_X_DIM_SIZE 32		/* this must be power off 2  */

struct packet_distribution_struct
{
	__u32 offset;
	__u8 mask;
	__u64 *dist;

#define CB_LENGTH (192 - sizeof(__u32) - sizeof(__u8) - sizeof(__u64 *))
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH	
};

struct packet_save_struct
{
	__u16 start_byte;
	__u16 end_byte;
	__u8 receive_packet;
};

struct pkt_type_struct
{
	__u8 type;
};

struct meter_struct
{
	float pkts_per_sec;
	__u16 interval;

#define CB_LENGTH (64 - sizeof(float) - sizeof(__u16))
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH	
};

struct band_meter_struct
{
	float bytes_per_sec;
	__u16 interval;
	
#define CB_LENGTH (64 - sizeof(float) - sizeof(__u16))
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH	
};

struct check_ip_hdr_struct
{
	__u64 errors;
};

struct check_udp_hdr_struct
{
	__u64 errors;
};

struct check_tcp_hdr_struct
{
	__u64 errors;
};

struct print_ether_struct
{
	__u8 print_payload:1,
	     print_newline:1;
	
	__u16 nbytes;
};

struct print_ip_struct
{
	__u8 print_id:1,
	     print_tos:1,
     	     print_ttl:1,
	     print_ip_len:1,
	     print_newline:1;
};

struct print_udp_struct
{
	__u8 print_newline:1;
};

struct print_tcp_struct
{
	__u8 print_newline:1;
};

#ifdef _LINUX_NETDEVICE_H
struct netdev_stats_struct
{
	struct net_device_stats limits;
};
#endif

struct set_perf_counter_struct
{
	struct perf_counter ctr[PERF_MAX_COUNTERS];
};

struct accum_perf_counter_struct
{
	struct perf_counter ctr[PERF_MAX_COUNTERS];
};

struct set_cycle_counter_struct
{
	__u8 dummy;
};

struct accum_cycle_counter_struct
{
	__u64 total_cycles;
};

struct bpf_filter_struct
{
	struct sock_fprog fprog;
	
	__u16 uid;

#define CB_LENGTH (32)
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH
};

struct cached_bpf_filter_struct
{
	struct sock_fprog fprog;
	
	__u16 uid;
	
#define CB_LENGTH (32)
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH
};

struct flow_report_struct
{
	__u8 format;

#define CB_LENGTH (64)
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH
};

struct flow_key_struct
{
	__u8	in_dev:1,
		out_dev:1,
		src_ip:1,
		dst_ip:1,
		ip_proto:1,
		ip_version:1,
		src_port:1,
		dst_port:1;
};

struct flow_raw_struct
{
	struct subflow sbf;

	__u32 expired_nr;
	
#define CB_LENGTH (64)
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH
};

#define DIRECTION_LEFT		0
#define DIRECTION_RIGHT		1

struct decide_struct
{
	struct
	{
		unsigned int cmd;
		void *arg;

		__u8 direction;
		
	} ioctl;
	
	__u16 uid;

#define DEBUG_INFO_SIZE 100	
	char debug_info[DEBUG_INFO_SIZE];
#undef DEBUG_INFO_SIZE
	
#define CB_LENGTH (64)
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH
};

struct decide_bpf_hook_struct
{
	struct sock_fprog fprog;
	
	__u16 uid;
	
#define CB_LENGTH (32)
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH
};

struct decide_action_hook_struct
{
	__u16 uid;
	
#define CB_LENGTH (32)
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH
};

struct decide_tee_hook_struct
{
	__u16 uid;
	
#define CB_LENGTH (32)
	__u8 cb[CB_LENGTH];
#undef CB_LENGTH
};

#endif /* __MAPI_IOCTL_H */
