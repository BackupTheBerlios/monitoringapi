/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <unistd.h>
#include <fcntl.h>

#include <pcap.h>

#include "../mapi-filter.h"
#include "pcap-int.h"

#include <linux/filter.h>

typedef struct mapi_filter mapi_filter_t;

void map_arphrd_to_dlt(pcap_t *handle,int arptype,int cooked_ok);
void bpf_dump(struct bpf_program *prog,int option);

static mapi_filter_t *mapi_filter_alloc(int expression_len,int filter_len)
{
	mapi_filter_t *mfilter;	
	
	if((mfilter = malloc(sizeof(mapi_filter_t))) == NULL)
	{
		return NULL;
	}

	if((mfilter->expression = malloc(expression_len)) == NULL)
	{
		free(mfilter);
		
		return NULL;
	}

#ifdef DEBUG	
	memset(mfilter->expression,0,expression_len);
#endif

	mfilter->exp_len = expression_len;
	mfilter->bpf_filter.bf_len = filter_len;
		
	if((mfilter->bpf_filter.bf_insns = malloc(filter_len*sizeof(struct bpf_insn))) == NULL)
	{
		free(mfilter);
		
		return NULL;
	}

#ifdef DEBUG	
	memset(mfilter->bpf_filter.bf_insns,0,filter_len*sizeof(struct bpf_insn));
#endif
	
	return mfilter;
}

/*static void mapi_filter_cpy(mapi_filter_t *to,mapi_filter_t *from)
{
	to->exp_len = from->exp_len;
	memcpy(to->bpf_filter.bf_insns,from->bpf_filter.bf_insns,from->bpf_filter.bf_len*sizeof(struct bpf_insn));
	
	to->bpf_filter.bf_len = from->bpf_filter.bf_len;
	memcpy(to->expression,from->expression,from->exp_len);
}

static mapi_filter_t *mapi_filter_clone(mapi_filter_t *mfilter)
{
	mapi_filter_t *cp_filter;

	if((cp_filter = mapi_filter_alloc(mfilter->exp_len,mfilter->bpf_filter.bf_len)) == NULL)
	{
		return NULL;
	}
	
	mapi_filter_cpy(cp_filter,mfilter);
	
	return cp_filter;
}*/

mapi_filter_t *mapi_create_filter(char *expression,int arptype,u_int32_t netmask)
{
	pcap_t *dead_p;
	struct bpf_program bpf_filter;
	mapi_filter_t *mfilter;	
	
	if((dead_p = pcap_open_dead(-1,netmask)) == NULL)
	{
		errno = EINVAL;

		return NULL;
	}
	
	map_arphrd_to_dlt(dead_p,arptype,0);
	
	if(dead_p->linktype == -1) 
	{
		errno = EINVAL;
		
		return NULL;
	}

	if(pcap_compile(dead_p,&bpf_filter,expression,1,netmask))
	{
		errno = EINVAL;
		pcap_close(dead_p);
		
		return NULL;
	}
	
	pcap_close(dead_p);

	if((mfilter = mapi_filter_alloc(strlen(expression) + 1,bpf_filter.bf_len)) == NULL)
	{
		errno = ENOMEM;

		return NULL;
	}
	
	memcpy(mfilter->expression,expression,mfilter->exp_len);
	memcpy(mfilter->bpf_filter.bf_insns,bpf_filter.bf_insns,bpf_filter.bf_len*sizeof(struct bpf_insn));
	
	pcap_freecode(&bpf_filter);

	return mfilter;
}

void mapi_free_filter(mapi_filter_t *filter)
{
	free(filter->expression);
	
	pcap_freecode((struct bpf_program *)&(filter->bpf_filter));
}

/* Removes any previously installed filter
 */
static int reset_kernel_filter(int fd)
{
	int dummy;

	return setsockopt(fd,SOL_SOCKET,SO_DETACH_FILTER,&dummy,sizeof(dummy));
}

/* This filter drops all packets
 */
static struct sock_filter drop_all_bpf_insn = BPF_STMT(BPF_RET | BPF_K, 0);
static struct sock_fprog drop_all_bpf_filter = { 1, &drop_all_bpf_insn };

static int set_kernel_filter(int fd,mapi_filter_t *filter)
{
	int drop_all_on = 0;
	int saved_socket_flags;
	int saved_errno;
	int ret;

	if(setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&drop_all_bpf_filter,sizeof(drop_all_bpf_filter)) == 0) 
	{
		char drain[1];

		/*
		 * Note that we've put the total filter onto the socket.
		 */
		drop_all_on = 1;

		/*
		 * Save the socket's current mode, and put it in non-blocking mode; 
		 * we drain it by reading packets until we get an error (which is 
		 * normally a "nothing more to be read" error).
		 */
		saved_socket_flags = fcntl(fd,F_GETFL,0);
		
		if(saved_socket_flags != -1 && fcntl(fd,F_SETFL,saved_socket_flags | O_NONBLOCK) >= 0)
		{
			while(recv(fd,&drain,sizeof(drain),MSG_TRUNC) >= 0)
			{
			}
			
			saved_errno = errno;
			
			fcntl(fd,F_SETFL,saved_socket_flags);
			
			if(saved_errno != EAGAIN) 
			{
				/* Fatal error 
				 */
				reset_kernel_filter(fd);
				
				return -1;
			}
		}
	}

	/*
	 * Now attach the new filter.
	 */
	
	ret = setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&(filter->bpf_filter),sizeof(struct bpf_program));
	
	if(ret == -1 && drop_all_on) 
	{
		/*
		 * Well, we couldn't set that filter on the socket,
		 * but we could set the drop_all filter on the socket.
		 *
		 * This could, for example, mean that the filter was
		 * too big to put into the kernel.
		 */
		saved_errno = errno;

		/*
		 * If this fails, we're really screwed;
		 * we have the total filter on the socket,
		 * and it won't come off.What do we do then?
		 */
		reset_kernel_filter(fd);

		errno = saved_errno;
	}

	return ret;	 
}

int mapi_apply_filter(int fd,mapi_filter_t *filter)
{
	if(filter == NULL)
	{
		return 0;
	}

	//bpf_dump((struct bpf_program *)&(filter->bpf_filter),0);
	
	if(set_kernel_filter(fd,filter) == -1)
	{
		return 1;
	}

	return 0;
}

/*
 *  Linux uses the ARP hardware type to identify the type of an 
 *  interface. pcap uses the DLT_xxx constants for this. This 
 *  function takes a pointer to a "pcap_t", and an ARPHRD_xxx
 *  constant, as arguments, and sets "handle->linktype" to the
 *  appropriate DLT_XXX constant and sets "handle->offset" to
 *  the appropriate value (to make "handle->offset" plus link-layer
 *  header length be a multiple of 4, so that the link-layer payload
 *  will be aligned on a 4-byte boundary when capturing packets).
 *  (If the offset isn't set here, it'll be 0; add code as appropriate
 *  for cases where it shouldn't be 0.)
 *
 *  If "cooked_ok" is non-zero, we can use DLT_LINUX_SLL and capture
 *  in cooked mode; otherwise, we can't use cooked mode, so we have
 *  to pick some type that works in raw mode, or fail.
 *  
 *  Sets the link type to -1 if unable to map the type.
 */
void map_arphrd_to_dlt(pcap_t *handle, int arptype, int cooked_ok)
{
	switch (arptype) {

	case ARPHRD_ETHER:
	case ARPHRD_METRICOM:
	case ARPHRD_LOOPBACK:
		handle->linktype = DLT_EN10MB;
		handle->offset = 2;
		break;

	case ARPHRD_EETHER:
		handle->linktype = DLT_EN3MB;
		break;

	case ARPHRD_AX25:
		handle->linktype = DLT_AX25;
		break;

	case ARPHRD_PRONET:
		handle->linktype = DLT_PRONET;
		break;

	case ARPHRD_CHAOS:
		handle->linktype = DLT_CHAOS;
		break;

#ifndef ARPHRD_IEEE802_TR
#define ARPHRD_IEEE802_TR 800	/* From Linux 2.4 */
#endif
	case ARPHRD_IEEE802_TR:
	case ARPHRD_IEEE802:
		handle->linktype = DLT_IEEE802;
		handle->offset = 2;
		break;

	case ARPHRD_ARCNET:
		handle->linktype = DLT_ARCNET;
		break;

#ifndef ARPHRD_FDDI	/* From Linux 2.2.13 */
#define ARPHRD_FDDI	774
#endif
	case ARPHRD_FDDI:
		handle->linktype = DLT_FDDI;
		handle->offset = 3;
		break;

#ifndef ARPHRD_ATM  /* FIXME: How to #include this? */
#define ARPHRD_ATM 19
#endif
	case ARPHRD_ATM:
		/*
		 * The Classical IP implementation in ATM for Linux
		 * supports both what RFC 1483 calls "LLC Encapsulation",
		 * in which each packet has an LLC header, possibly
		 * with a SNAP header as well, prepended to it, and
		 * what RFC 1483 calls "VC Based Multiplexing", in which
		 * different virtual circuits carry different network
		 * layer protocols, and no header is prepended to packets.
		 *
		 * They both have an ARPHRD_ type of ARPHRD_ATM, so
		 * you can't use the ARPHRD_ type to find out whether
		 * captured packets will have an LLC header, and,
		 * while there's a socket ioctl to *set* the encapsulation
		 * type, there's no ioctl to *get* the encapsulation type.
		 *
		 * This means that
		 *
		 *	programs that dissect Linux Classical IP frames
		 *	would have to check for an LLC header and,
		 *	depending on whether they see one or not, dissect
		 *	the frame as LLC-encapsulated or as raw IP (I
		 *	don't know whether there's any traffic other than
		 *	IP that would show up on the socket, or whether
		 *	there's any support for IPv6 in the Linux
		 *	Classical IP code);
		 *
		 *	filter expressions would have to compile into
		 *	code that checks for an LLC header and does
		 *	the right thing.
		 *
		 * Both of those are a nuisance - and, at least on systems
		 * that support PF_PACKET sockets, we don't have to put
		 * up with those nuisances; instead, we can just capture
		 * in cooked mode.  That's what we'll do, if we can.
		 * Otherwise, we'll just fail.
		 */
		if (cooked_ok)
			handle->linktype = DLT_LINUX_SLL;
		else
			handle->linktype = -1;
		break;

#ifndef ARPHRD_IEEE80211  /* From Linux 2.4.6 */
#define ARPHRD_IEEE80211 801
#endif
	case ARPHRD_IEEE80211:
		handle->linktype = DLT_IEEE802_11;
		break;

#ifndef ARPHRD_IEEE80211_PRISM  /* From Linux 2.4.18 */
#define ARPHRD_IEEE80211_PRISM 802
#endif
	case ARPHRD_IEEE80211_PRISM:
		handle->linktype = DLT_PRISM_HEADER;
		break;

	case ARPHRD_PPP:
		/*
		 * Some PPP code in the kernel supplies no link-layer
		 * header whatsoever to PF_PACKET sockets; other PPP
		 * code supplies PPP link-layer headers ("syncppp.c");
		 * some PPP code might supply random link-layer
		 * headers (PPP over ISDN - there's code in Ethereal,
		 * for example, to cope with PPP-over-ISDN captures
		 * with which the Ethereal developers have had to cope,
		 * heuristically trying to determine which of the
		 * oddball link-layer headers particular packets have).
		 *
		 * As such, we just punt, and run all PPP interfaces
		 * in cooked mode, if we can; otherwise, we just treat
		 * it as DLT_RAW, for now - if somebody needs to capture,
		 * on a 2.0[.x] kernel, on PPP devices that supply a
		 * link-layer header, they'll have to add code here to
		 * map to the appropriate DLT_ type (possibly adding a
		 * new DLT_ type, if necessary).
		 */
		if (cooked_ok)
			handle->linktype = DLT_LINUX_SLL;
		else {
			/*
			 * XXX - handle ISDN types here?  We can't fall
			 * back on cooked sockets, so we'd have to
			 * figure out from the device name what type of
			 * link-layer encapsulation it's using, and map
			 * that to an appropriate DLT_ value, meaning
			 * we'd map "isdnN" devices to DLT_RAW (they
			 * supply raw IP packets with no link-layer
			 * header) and "isdY" devices to a new DLT_I4L_IP
			 * type that has only an Ethernet packet type as
			 * a link-layer header.
			 *
			 * But sometimes we seem to get random crap
			 * in the link-layer header when capturing on
			 * ISDN devices....
			 */
			handle->linktype = DLT_RAW;
		}
		break;

#ifndef ARPHRD_HDLC
#define ARPHRD_HDLC 513	/* From Linux 2.2.13 */
#endif
	case ARPHRD_HDLC:
		handle->linktype = DLT_C_HDLC;
		break;

	/* Not sure if this is correct for all tunnels, but it
	 * works for CIPE */
	case ARPHRD_TUNNEL:
#ifndef ARPHRD_SIT
#define ARPHRD_SIT 776	/* From Linux 2.2.13 */
#endif
	case ARPHRD_SIT:
	case ARPHRD_CSLIP:
	case ARPHRD_SLIP6:
	case ARPHRD_CSLIP6:
	case ARPHRD_ADAPT:
	case ARPHRD_SLIP:
#ifndef ARPHRD_RAWHDLC
#define ARPHRD_RAWHDLC 518
#endif
	case ARPHRD_RAWHDLC:
		/*
		 * XXX - should some of those be mapped to DLT_LINUX_SLL
		 * instead?  Should we just map all of them to DLT_LINUX_SLL?
		 */
		handle->linktype = DLT_RAW;
		break;

	case ARPHRD_LOCALTLK:
		handle->linktype = DLT_LTALK;
		break;

	default:
		handle->linktype = -1;
		break;
	}
}
