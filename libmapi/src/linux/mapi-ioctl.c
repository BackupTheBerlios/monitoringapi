/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <sys/time.h>
#include <sys/types.h>
#include <net/if.h>

#include <linux/mapi/ioctl.h>

int functions_ioctls[PREDEF_MAX][10] = 
{
	/* FINVALID */
	{ 
	}
	,
	
	/* COUNT_PACKETS */
	{ 
		SIOCSCOUNT_PACKETS	,
		SIOCRMCOUNT_PACKETS	,
		SIOCGCOUNT_PACKETS	,
		SIOCRSCOUNT_PACKETS
	}	
	,
	
	/* COUNT_BYTES */
	{ 
		SIOCSCOUNT_BYTES	,
		SIOCRMCOUNT_BYTES 	,
		SIOCGCOUNT_BYTES	,
		SIOCRSCOUNT_BYTES
	}
	,

	/* SAMPLE_PACKETS */
	{ 
		SIOCSSAMPLE_PACKETS	,
		SIOCRMSAMPLE_PACKETS 	,
	}
	,
	
	/* SUBSTRING_SEARCH */
	{ 
		SIOCSSUBSTRING_SEARCH		,
		SIOCRMSUBSTRING_SEARCH		,
		SIOCGSUBSTRING_SEARCH		,
		SIOCRSSUBSTRING_SEARCH	
	}
	,
	
	/* HASH */
	{ 
		SIOCSHASH 	,
		SIOCRMHASH	,
		SIOCGHASH	,
		SIOCRSHASH
	}
	,

	/* SUBFLOW */
	{
		SIOCSSUBFLOW		,
		SIOCRMSUBFLOW		,
		SIOCEXPIREALL
	}
	,
	
	/* LOGGING */
	{ 
		SIOCSLOGGING	,	
		SIOCRMLOGGING	,
		SIOCGLOGGING	,
		SIOCRSLOGGING
	}
	,

	/* EXB */
	{ 
		SIOCSEXB	,
		SIOCRMEXB	,
		SIOCGEXB	,
		SIOCRSEXB
	}
	,
	
	/* PACKETS_IN_INTERVAL */
	{
		SIOCSPACKETS_IN_INTERVAL	,	
		SIOCRMPACKETS_IN_INTERVAL	,
		SIOCGPACKETS_IN_INTERVAL 	,
		SIOCRSPACKETS_IN_INTERVAL	,
		SIOCSASYNCPACKETS_IN_INTERVAL	,
		SIOCRMASYNCPACKETS_IN_INTERVAL
	}
	,
	
	/* BYTES_IN_INTERVAL */
	{	
		SIOCSBYTES_IN_INTERVAL		,	
		SIOCRMBYTES_IN_INTERVAL		,	
		SIOCGBYTES_IN_INTERVAL		,
		SIOCRSBYTES_IN_INTERVAL		,
		SIOCSASYNCBYTES_IN_INTERVAL	,
		SIOCRMASYNCBYTES_IN_INTERVAL
	}
	,
	
	/* PACKET_DISTRIBUTION */
	{	
		SIOCSPACKET_DISTRIBUTION	,
		SIOCRMPACKET_DISTRIBUTION 	,
		SIOCGPACKET_DISTRIBUTION	,
		SIOCRSPACKET_DISTRIBUTION
	}
	,
	
	/* PACKET_SAVE */
	{	
		SIOCSPACKET_SAVE	,
		SIOCRMPACKET_SAVE
	}
	,
	
	/* COOK_IP */
	{
		SIOCSCOOK_IP	,
		SIOCRMCOOK_IP	,
		SIOCGCOOK_IP	,
		SIOCRSCOOK_IP
	}
	,
	
	/* COOK_UDP */
	{ 
		SIOCSCOOK_UDP	,
		SIOCRMCOOK_UDP	,
		SIOCGCOOK_UDP	,
		SIOCRSCOOK_UDP
	}	
	,
	
	/* COOK_TCP */
	{ 
		SIOCSCOOK_TCP	,
		SIOCRMCOOK_TCP	,
		SIOCGCOOK_TCP	,
		SIOCRSCOOK_TCP
	}
	,

	/* PKT_TYPE */
	{ 
		SIOCSPKT_TYPE	,
		SIOCRMPKT_TYPE	,
	}
	,

	/* METER */
	{ 
		SIOCSMETER	,
		SIOCRMMETER	,
		SIOCGMETER	,
		SIOCRSMETER
	}
	,
	
	/* BAND_METER */
	{ 
		SIOCSBAND_METER	,
		SIOCRMBAND_METER,
		SIOCGBAND_METER	,
		SIOCRSBAND_METER
	}
	,
	
	/* CHECK_IP_HDR */
	{ 
		SIOCSCHECK_IP_HDR	,
		SIOCRMCHECK_IP_HDR	,
		SIOCGCHECK_IP_HDR	,
		SIOCRSCHECK_IP_HDR
	}
	,	
	
	/* CHECK_UDP_HDR */
	{ 
		SIOCSCHECK_UDP_HDR	,
		SIOCRMCHECK_UDP_HDR	,
		SIOCGCHECK_UDP_HDR	,
		SIOCRSCHECK_UDP_HDR
	}
	,

	/* CHECK_TCP_HDR */
	{ 
		SIOCSCHECK_TCP_HDR	,
		SIOCRMCHECK_TCP_HDR	,
		SIOCGCHECK_TCP_HDR	,
		SIOCRSCHECK_TCP_HDR
	}
	,

	/* PRINT_ETHER */
	{ 
		SIOCSPRINT_ETHER	,
		SIOCRMPRINT_ETHER	,
	}
	,

	/* PRINT_IP */
	{ 
		SIOCSPRINT_IP	,
		SIOCRMPRINT_IP	,
	}
	,

	/* PRINT_UDP */
	{ 
		SIOCSPRINT_UDP	,
		SIOCRMPRINT_UDP	,
	}
	,

	/* PRINT_TCP */
	{ 
		SIOCSPRINT_TCP	,
		SIOCRMPRINT_TCP	,
	}
	,

	/* NETDEV_STATS */
	{ 
		SIOCSNETDEV_STATS	,
		SIOCRMNETDEV_STATS	,
		SIOCGNETDEV_STATS	,
		SIOCRSNETDEV_STATS
	}
	,

	/* SET_PERF_COUNTER */
	{ 
		SIOCSSET_PERF_COUNTER	,
		SIOCRMSET_PERF_COUNTER	,
	}
	,

	/* ACCUM_PERF_COUNTER */
	{ 
		SIOCSACCUM_PERF_COUNTER		,
		SIOCRMACCUM_PERF_COUNTER	,
		SIOCGACCUM_PERF_COUNTER		,
		SIOCRSACCUM_PERF_COUNTER
	}
	,

	/* BPF_FILTER */
	{ 
		SIOCSBPF_FILTER		,
		SIOCRMBPF_FILTER	,
		SIOCGBPF_FILTER		,
		SIOCRSBPF_FILTER
	}
	,

	/* CACHED_BPF_FILTER */
	{ 
		SIOCSCACHED_BPF_FILTER	,
		SIOCRMCACHED_BPF_FILTER	,
		SIOCGCACHED_BPF_FILTER	,
		SIOCRSCACHED_BPF_FILTER
	}
	,

	/* FLOW_REPORT */
	{ 
		SIOCSFLOW_REPORT	,
		SIOCRMFLOW_REPORT	,
	}
	,

	/* FLOW_KEY */
	{ 
		SIOCSFLOW_KEY	,
		SIOCRMFLOW_KEY	,
	}
	,

	/* FLOW_RAW */
	{ 
		SIOCSFLOW_RAW	,
		SIOCRMFLOW_RAW	,
		SIOCGFLOW_RAW	
	}
	,

	/* DECIDE */
	{ 
		SIOCSDECIDE	,
		SIOCRMDECIDE	,
		0,
		0,
		SIOCIODECIDE,
		SIOCDBDECIDE
	}
	,

	/* DECIDE_BPF_HOOK */
	{ 
		SIOCSDECIDE_BPF_HOOK	,
		SIOCRMDECIDE_BPF_HOOK	,
	}
	,

	/* DECIDE_ACTION_HOOK */
	{ 
		SIOCSDECIDE_ACTION_HOOK		,
		SIOCRMDECIDE_ACTION_HOOK	,
	}
	,

	/* DECIDE_TEE_HOOK */
	{ 
		SIOCSDECIDE_TEE_HOOK	,
		SIOCRMDECIDE_TEE_HOOK	,
	}
	,
};

int find_ioctl(int function,int action)
{
	return functions_ioctls[function][action];
}
