/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPI_CSUM_H_
#define __MAPI_CSUM_H_

u16 in_cksum(const unsigned char *addr,int len)
{
	int nleft = len;
	const u16 *w = (const u16 *)addr;
	u32 sum = 0;
	u16 answer = 0;

	/*
	* Our algorithm is simple, using a 32 bit accumulator (sum), we add
	* sequential 16 bit words to it, and at the end, fold back all the
	* carry bits from the top 16 bits into the lower 16 bits.
	*/
	while(nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if(nleft == 1)
	{
		*(unsigned char *)(&answer) = *(const unsigned char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum & 0xffff) + (sum >> 16);
	sum += (sum >> 16);
	
	/* guaranteed now that the lower 16 bits of sum are correct */

	answer = ~sum;              /* truncate to 16 bits */
	
	return answer;
}

#endif /* __MAPI_CSUM_H_ */
