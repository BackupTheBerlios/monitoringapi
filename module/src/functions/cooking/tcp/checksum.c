#include <linux/types.h>
#include <linux/byteorder/generic.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/linkage.h>
#include <asm/uaccess.h>
#include <asm/checksum.h>

inline u16 mapi_tcp_check(struct tcphdr *th,int len,u32 saddr,u32 daddr)
{
	return csum_tcpudp_magic(saddr,daddr,len,IPPROTO_TCP,csum_partial((char *)th,len,0));
}

