/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

/** \file 
 *
 * This file contains Linux specific code.
 *
 * \author Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/types.h>
#include <linux/types.h>
#include <net/if.h>

#include <mapi.h>
#include <linux/mapi/ioctl.h>

#include "mapi-util.h"
#include "mapi-filter.h"
#include "mapi-linux.h"

#ifdef DEBUG
#include <stdio.h>
#endif

int init_mode(mapi_flow_t *mp,flow_mode_t mode);
int find_ioctl(int function,int action);

/** 
 * @see mapi_create_flow
 */

inline mapi_flow_t *linux_mapi_create_flow(char *ifname,char *filter_condition,mode_t mode)
{
	mapi_flow_t *mp;
	
	if((mp = malloc(sizeof(mapi_flow_t))) == NULL)
	{
		errno = ENOMEM;

		return NULL;
	}
	
	memset(mp,0,sizeof(*mp));
	
	if(ifname == NULL)
	{
		if((mp->ifname = lookup_if()) == NULL)
		{
			free(mp);

			errno = EINVAL;

			return NULL;
		}
	}
	else
	{
		mp->ifname = strdup(ifname);
	}
	
	if(filter_condition != NULL)
	{
		mp->condition = strdup(filter_condition);
	}
	
	mp->mode = mode;
	
	set_default_options(&(mp->options));
	
	return mp;
}

static inline int install_filter(mapi_flow_t *mp)
{
	int fd = mp->fd;
	int arptype;
	u_int32_t netmask;
	mapi_filter_t *filter = NULL;
	
	if((arptype = get_if_arptype(fd,mp->ifname)) == -1 ||
	   (netmask = get_if_netmask(fd,mp->ifname)) == -1)
	{
		return 1;
	}
	
	if(mp->condition)
	{
		if((filter = mapi_create_filter(mp->condition,arptype,netmask)) == NULL)
		{
			return 1;
		}
	}
	
	mp->filter = filter;
	
	if(mapi_apply_filter(fd,filter))
	{
		return 1;
	}

	return 0;
}

static inline int install_sampling(mapi_flow_t *mp)
{
	struct sample_packets_struct sps;
	
	if(mp->options.no_copy)
	{
		return 0;
	}
	
	sps.mode = SAMPLE_MODE_ALL;
	sps.period = 0;

	if(ioctl(mp->fd,SIOCSSAMPLE_PACKETS,&sps))
	{
		return 1;
	}

	return 0;
}

/** 
 * @see mapi_connect
 */ 

inline int linux_mapi_connect(mapi_flow_t *mp)
{
	int fd;
	
	if((fd = socket(PF_MAPI,SOCK_RAW,htons(ETH_P_ALL))) < 0)
        {
		return 1;
        }

	mp->fd = fd;
	
	if(bind_if_name(fd,mp->ifname) || install_filter(mp) || if_promisc_on(fd,mp->ifname))
	{
		return 1;
	}
	
	if((mp->packet.data = malloc(mp->options.packet.len)) == NULL)
	{
		errno = ENOMEM;
		
		return 1;
	}
	
	mp->packet.data_len = mp->options.packet.len;
	
	if(init_mode(mp,mp->mode) || install_sampling(mp))
	{
		return 1;
	}
	
	mp->options.rcv_buf_size = set_rcvbuf_size(mp->fd,mp->options.rcv_buf_size);
	
	return 0;
}

/** 
 * @see mapi_set_flow_option
 */ 

inline int linux_mapi_set_flow_option(mapi_flow_t *mp,int option,void *arg)
{
	mapi_options_t *moptions = &(mp->options);
	
	if(mp->fd == 0)
	{
		return 1;
	}
	
	switch(option)
	{
		case PACKET_SIZE:
			moptions->packet.size = *((u_int *)arg);
			break;
		case PACKET_LENGTH:
			moptions->packet.len = *((u_int *)arg);
			break;
		case SUBFLOW_TIMEOUT:
			moptions->subflow.bytes = *((u_int *)arg);
			break;
		case SUBFLOW_MAX_DURATION:
			moptions->subflow.max_duration = *((u_int *)arg);
			break;
		case SUBFLOW_MAX_SUBFLOWS_TO_COPY:
			moptions->subflow.max_subflows_to_copy = *((u_int *)arg);
			break;
		case NO_COPY:
			moptions->no_copy = *((u_char *)arg);
			break;
		case RCVBUFSIZE:
			moptions->rcv_buf_size = *((u_char *)arg);
	}
	
	return 0;
}

/** 
 * @see mapi_get_flow_option
 */ 

inline void *linux_mapi_get_flow_option(mapi_flow_t *mp,int option)
{
	mapi_options_t *moptions = &(mp->options);
	void *val = NULL;
	
	switch(option)
	{
		case PACKET_SIZE:
			val = &(moptions->packet.size);
			break;
		case PACKET_LENGTH:
			val = &(moptions->packet.len);
			break;
		case SUBFLOW_TIMEOUT:
			val = &(moptions->subflow.timeout);
			break;
		case SUBFLOW_MAX_DURATION:
			val = &(moptions->subflow.max_duration);
			break;
		case SUBFLOW_MAX_SUBFLOWS_TO_COPY:
			val = &(moptions->subflow.max_subflows_to_copy);
			break;
		case NO_COPY:
			val = &(moptions->no_copy);
			break;
		case CONDITION:
			val = &(mp->condition);
			break;
		case RCVBUFSIZE:
			val = &(moptions->rcv_buf_size);
	}

	return val;
}

/**
 * @see mapi_apply_function
 */

inline mapi_func_t *linux_mapi_apply_function(mapi_flow_t *mp,int function_id,void *args)
{
	mapi_func_t *func;
	int ioctl_num;
	void *copied_args;
	
	if((func = malloc(sizeof(mapi_func_t))) == NULL)
	{
		errno = ENOMEM;
		
		return NULL;
	}
	
	if((ioctl_num = find_ioctl(function_id,ADD)) == 0)
	{
		return NULL;
	}
	
	if(ioctl(mp->fd,ioctl_num,args))
	{
		return NULL;
	}
	
	func->function_id = function_id;

	if((copied_args = malloc(sizeof(*args))) == NULL)
	{
		return NULL;
	}

	memcpy(copied_args,args,sizeof(*args));
	
	func->args = copied_args;
	
	return func;
}

/** 
 * @see mapi_remove_function
 */

inline int linux_mapi_remove_function(mapi_flow_t *mp,mapi_func_t *func)
{
	int ioctl_num;

	if((ioctl_num = find_ioctl(func->function_id,REMOVE)) == 0)
	{
		return 1;
	}
	
	if(ioctl(mp->fd,ioctl_num,func->args))
	{
		return 1;
	}
	
	free(func->args);
	
	return 0;
}

/**
 * @see mapi_reset_function
 */

inline int linux_mapi_reset_function(mapi_flow_t *mp,mapi_func_t *func)
{
	int ioctl_num;

	if((ioctl_num = find_ioctl(func->function_id,RESET)) == 0)
	{
		return 1;
	}
	
	if(ioctl(mp->fd,ioctl_num,func->args))
	{
		return 1;
	}
	
	return 0;
}

/**
 * @see mapi_read_results
 */

inline int linux_mapi_read_results(mapi_flow_t *mp,mapi_func_t *func,void *results)
{
	int ioctl_num;

	if((ioctl_num = find_ioctl(func->function_id,READ_RESULTS)) == 0)
	{
		return 1;
	}
	
	if(ioctl(mp->fd,ioctl_num,results))
	{
		return 1;
	}
	
	return 0;
}

/** 
 * @see mapi_get_next_packet
 */

inline mapi_packet_t *linux_mapi_get_next_packet(mapi_flow_t *mp)
{
	struct sockaddr_ll pinfo;
	socklen_t pinfo_len;
	mapi_packet_t *packet = &(mp->packet);
	
	do
	{
		pinfo_len = sizeof(pinfo);
		
		packet->real_len = recvfrom(mp->fd,packet->data,packet->data_len,MSG_TRUNC,(struct sockaddr *)&pinfo,&pinfo_len);
	}
	while(packet->real_len == -1 && errno == EINTR);

	if(packet->real_len == -1) 
	{
		return NULL;
	}
	
	return packet;
}

/** 
 * @see mapi_loop
 */ 

#ifdef BLOCKING_LOOP
inline int linux_mapi_loop(mapi_flow_t *mp,int cnt,mapi_handler handler,void *user_data)
{
	mapi_packet_t *packet;
	
	for(;;) 
	{
		do
		{
			packet = mapi_get_next_packet(mp);
		} 
		while(packet == NULL && errno == EAGAIN);
		
		if(packet == NULL && errno != EAGAIN)
		{
			return 1;
		}
		
		(*handler)(packet,user_data);
		
		if(cnt > 0) 
		{
			cnt--;
			
			if(cnt <= 0)
			{
				break;
			}
		}
	}
	
	return 0;
}
#else
inline int linux_mapi_loop(mapi_flow_t *mp,int cnt,mapi_handler handler,void *user_data)
{
	return 0;
}
#endif

/**
 * @see mapi_get_next_subflow
 */

inline mapi_subflow_t *linux_mapi_get_next_subflow(mapi_flow_t *mp)
{
	/*struct subflow *sbf;
	struct subflow_ioctl_struct *subflow_io = mp->mode_ptr.hierarchical.subflow_io;
	
	if(mp->mode_ptr.hierarchical.last_index >= mp->options.subflow.max_subflows_to_copy)
	{
		if(ioctl(mp->fd,SIOCGSUBFLOW,subflow_io))
		{
			return NULL;
		}

		mp->mode_ptr.hierarchical.last_index = 0;
	}
	
	sbf = mp->mode_ptr.hierarchical.subflow_io->sbf_table[mp->mode_ptr.hierarchical.last_index++];

	mp->subflow.sbf = sbf;

	return &(mp->subflow);*/

	return NULL;
}

/**
 * @see mapi_subflow_loop
 */

#ifdef BLOCKING_LOOP
inline int linux_mapi_subflow_loop(mapi_flow_t *mp,int cnt,mapi_subflow_handler handler,void *user_data)
{
	mapi_subflow_t *subflow;
	
	for(;;) 
	{
		do
		{
			subflow = mapi_get_next_subflow(mp);
		} 
		while(subflow == NULL && errno == EAGAIN);
		
		if(subflow == NULL && errno != EAGAIN)
		{
			return 1;
		}
		
		(*handler)(subflow,user_data);
		
		if(cnt > 0) 
		{
			cnt--;
			
			if(cnt <= 0)
			{
				break;
			}
		}
	}
	
	return 0;
}
#else
inline int linux_mapi_subflow_loop(mapi_flow_t *mp,int cnt,mapi_subflow_handler handler,void *user_data)
{
	return 0;
}
#endif

/*
 * @see mapi_save
 */

inline int linux_mapi_save(mapi_flow_t *mp,int filed)
{
	return 0;
}

/*
 * @see mapi_destroy_flow
 */

inline void linux_mapi_destroy_flow(mapi_flow_t *mp)
{
	if(mp->promisc_on)
	{
		if_promisc_off(mp->fd,mp->ifname);
	}
	
	if(mp->filter)
	{
		mapi_free_filter(mp->filter);
	}
	
	free(mp->ifname);

	if(mp->condition != NULL)
	{
		free(mp->condition);
	}

	if(mp->packet.data != NULL)
	{
		free(mp->packet.data);
	}

	if(mp->fd != 0)
	{
		close(mp->fd);
	}
	
	free(mp);
}
