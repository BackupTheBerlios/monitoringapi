/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <mapi.h>
#include <linux/mapi/ioctl.h>

/*int init_subflow_ioctl_struct(mapi_options_t *options,struct subflow_ioctl_struct *sis)
{
	int i;

	memset(sis,0,sizeof(struct subflow_ioctl_struct));
	
	sis->max_subflows_to_return = options->subflow.max_subflows_to_copy;
	
	if((sis->sbf_table = (struct subflow **)malloc(sis->max_subflows_to_return*sizeof(struct subflow *))) == NULL)
	{
		return ENOMEM;
	}
	
	for( i = 0 ; i < sis->max_subflows_to_return ; i++)
	{
		if((sis->sbf_table[i] = (struct subflow *)malloc(sizeof(struct subflow))) == NULL)
		{
			int j;

			for( j = 0 ; j < i ; j++)
			{
				free(sis->sbf_table[j]);
			}

			free(sis->sbf_table);
			
			return ENOMEM;
		}

		memset(sis->sbf_table[i],0,sizeof(struct subflow));
	}
	
	sis->timeout = options->subflow.timeout;
	sis->max_duration = options->subflow.max_duration;
	sis->pid = getpid();

	return 0;
}*/

int init_mode(mapi_flow_t *mp,flow_mode_t mode)
{
	int fd = mp->fd;
	
	if(mode == RAW)
	{
	}
	else if(mode == COOKED)
	{
		if((mp->mode_ptr.cooked.ip = malloc(sizeof(struct cook_ip_struct))) == NULL ||
		   (mp->mode_ptr.cooked.udp = malloc(sizeof(struct cook_udp_struct))) == NULL ||
		   (mp->mode_ptr.cooked.tcp = malloc(sizeof(struct cook_tcp_struct))) == NULL)
		{
			return ENOMEM;
		}

		if(ioctl(fd,SIOCSCOOK_IP,mp->mode_ptr.cooked.ip) || 
		   ioctl(fd,SIOCSCOOK_UDP,mp->mode_ptr.cooked.udp) ||
		   ioctl(fd,SIOCSCOOK_TCP,mp->mode_ptr.cooked.tcp))
		{
			return errno;
		}
	}
	else if(mode == HIERARCHICAL)
	{
		int err;
		
		if((mp->mode_ptr.hierarchical.subflow_io = malloc(sizeof(struct subflow_ioctl_struct))) == NULL)
		{
			return ENOMEM;
		}

		if((err = init_subflow_ioctl_struct(&(mp->options),mp->mode_ptr.hierarchical.subflow_io)) != 0)
		{
			return err;
		}

		if(ioctl(mp->fd,SIOCSSUBFLOW,mp->mode_ptr.hierarchical.subflow_io))
		{
			return errno;
		}
	}
	
	return 0;
}

