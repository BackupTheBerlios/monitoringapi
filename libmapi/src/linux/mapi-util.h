/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPIUTIL_H
#define __MAPIUTIL_H

static inline int if_promisc_on(int fd,char *ifname)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);

	if(ioctl(fd,SIOCGIFFLAGS,&ifr) == -1)
	{
		return -1;
	}

	if(!(ifr.ifr_flags & IFF_PROMISC))
	{
		ifr.ifr_flags |= IFF_PROMISC;
		
		if(ioctl(fd,SIOCSIFFLAGS,&ifr) == -1)
		{
			return -1;
		}
	}

	return 0;
}

static inline int if_promisc_off(int fd,char *ifname)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
	
	if(ioctl(fd,SIOCGIFFLAGS,&ifr) == -1)
	{
		return -1;
	}

	if(ifr.ifr_flags & IFF_PROMISC)
	{
		ifr.ifr_flags ^= IFF_PROMISC;
		
		if(ioctl(fd,SIOCSIFFLAGS,&ifr) == -1)
		{
			return -1;
		}
	}

	return 0;
}

static inline int set_all_promisc_on(int fd)
{
	struct ifreq *ifaces;
	struct ifconf ifc;
	int noifaces;
	int i;

	noifaces = ifc.ifc_len = sizeof(struct ifreq);
	
	do
	{
		noifaces *= 2;

		ifc.ifc_len = noifaces;
		ifc.ifc_req = alloca(ifc.ifc_len);
		
		if(ioctl(fd,SIOCGIFCONF,&ifc))
		{
			return -1;
		}
	}
	while(ifc.ifc_len >= noifaces);
	
	ifaces = ifc.ifc_ifcu.ifcu_req;
	
	for(i = 0 ; i < ifc.ifc_len/sizeof(struct ifreq) ; i++)
	{
		//printf("Trying interface %s\n");
		
		if(ioctl(fd,SIOCGIFFLAGS,ifaces + i))
		{
			return -1;
		}
		
		ifaces[i].ifr_flags |= IFF_PROMISC;
		
		if(ioctl(fd,SIOCSIFFLAGS,ifaces + i))
		{
			return -1;
		}
	}

	return 0;
}

static inline int set_all_promisc_off(int fd)
{
	struct ifreq *ifaces;
	struct ifconf ifc;
	int noifaces;
	int i;

	noifaces = ifc.ifc_len = sizeof(struct ifreq);
	
	do
	{
		noifaces *= 2;

		ifc.ifc_len = noifaces;
		ifc.ifc_req = alloca(ifc.ifc_len);
		
		if(ioctl(fd,SIOCGIFCONF,&ifc))
		{
			return -1;
		}
	}
	while(ifc.ifc_len >= noifaces);
	
	ifaces = ifc.ifc_ifcu.ifcu_req;

	for(i = 0 ; i < ifc.ifc_len/sizeof(struct ifreq) ; i++)
	{
		if(ioctl(fd,SIOCGIFFLAGS,ifaces + i))
		{
			return -1;
		}
		
		ifaces[i].ifr_flags ^= IFF_PROMISC;
		
		if(ioctl(fd,SIOCSIFFLAGS,ifaces + i))
		{
			return -1;
		}
	}

	return 0;
}

static inline int get_if_mtu(int fd,char *ifname)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);

	if(ioctl(fd,SIOCGIFMTU,&ifr) == -1)
	{
		return -1;
	}

	return ifr.ifr_mtu;
}

static inline int get_if_index(int fd,const char *device)
{
	/*struct ifreq ifr;

	memset(&ifr,0,sizeof(ifr));
	strncpy(ifr.ifr_name,device,sizeof(ifr.ifr_name));

	if(ioctl(fd,SIOCGIFINDEX,&ifr) == -1) 
	{
		return -1;
	}

	return ifr.ifr_ifindex;*/

	return if_nametoindex(device);
}

static inline int bind_if_index(int fd,int ifindex)
{
	struct sockaddr_ll sll;

	memset(&sll,0,sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex	= ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);

	if(bind(fd,(struct sockaddr *)&sll,sizeof(sll)) == -1) 
	{
		return 1;
	}

	return 0;
}

static inline int get_if_arptype(int fd,const char *device)
{
	struct ifreq ifr;

	memset(&ifr,0,sizeof(ifr));
	strncpy(ifr.ifr_name,device,sizeof(ifr.ifr_name));

	if(ioctl(fd,SIOCGIFHWADDR,&ifr) == -1)
	{
		return -1;
	}

	return ifr.ifr_hwaddr.sa_family;
}

static inline u_int32_t get_if_netmask(int fd,const char *device)
{
	struct ifreq ifr;

	memset(&ifr,0,sizeof(ifr));
	strncpy(ifr.ifr_name,device,sizeof(ifr.ifr_name));

	if(ioctl(fd,SIOCGIFNETMASK,&ifr) == -1)
	{
		return -1;
	}

	return (u_int32_t)(((struct sockaddr_in *)&(ifr.ifr_netmask))->sin_addr.s_addr);
}

static inline int bind_if_name(int fd,const char *device)
{
	int ifindex;

	if((ifindex = get_if_index(fd,device)) == -1)
	{
		return 1;
	}

	if(bind_if_index(fd,ifindex))
	{
		return 1;
	}

	return 0;
}

static inline __u32 set_rcvbuf_size(int fd,__u32 rcvbuf_size)
{
	int size;
	
	if(setsockopt(fd,SOL_SOCKET,SO_RCVBUF,(char *)&rcvbuf_size,sizeof(rcvbuf_size)))
	{
		return -1;
	}
	
	if(getsockopt(fd,SOL_SOCKET,SO_RCVBUF,(char *)&rcvbuf_size,&size))
	{
		return -1;
	}

	return rcvbuf_size;
}

static inline char *lookup_if(void)
{
	struct if_nameindex *iflist;
	char *ifname;
	u_int8_t found = 0;
	int i;
	
	if((ifname = calloc(IFNAMSIZ,sizeof(char))) == NULL)
	{
		errno = ENOMEM;

		return NULL;
	}
	
	if((iflist = if_nameindex()) == NULL)
	{
		errno = ENXIO;
		
		return NULL;
	}
	
	for( i = 0 ; (iflist[i].if_name != NULL) && (iflist[i].if_index != 0 ) ; i++)
	{
		/*printf("IFNAME : %s , IFINDEX : %d\n",iflist[i].if_name,iflist[i].if_index);
		 */

		if(strcmp(iflist[i].if_name,"lo") == 0)
		{
			continue;
		}

		strncpy(ifname,iflist[i].if_name,IFNAMSIZ);
		found = 1;
		
		break;
	}
	
	if_freenameindex(iflist);

	if(found == 0)
	{
		free(ifname);

		return NULL;
	}
	
	return ifname;
}

#endif /* __MAPIUTIL_H */
