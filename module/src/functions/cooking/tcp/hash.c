#include <linux/types.h>
#include <linux/random.h>

#include <linux/mapi/common.h>

PRIVATE u8 xor[12];
PRIVATE u8 perm[12];

PRIVATE void getrnd()
{
	u32 *ptr;
	int rand;

	get_random_bytes(&rand,sizeof(u32));
	
	ptr = (u32 *)xor;
	get_random_bytes(ptr,sizeof(u32));
	get_random_bytes(ptr+1,sizeof(u32));
	get_random_bytes(ptr+2,sizeof(u32));
	
	ptr = (u32 *)perm;
	get_random_bytes(ptr,sizeof(u32));
	get_random_bytes(ptr+1,sizeof(u32));
	get_random_bytes(ptr+2,sizeof(u32));
}

void init_hash()
{
	int i,n,j;
	int p[12];
	getrnd();
	
	for(i = 0 ; i < 12 ; i++)
	{
		p[i] = i;
	}
	
	for(i = 0 ; i < 12 ; i++)
	{
		n = perm[i] % (12 - i);
		perm[i] = p[n];
		
		for(j = 0 ; j < 11 - n ; j++)
		{
			p[n + j] = p[n + j + 1];
		}
	}
}

u32 mk_hash(u32 src,u16 sport,u32 dest,u16 dport)
{
	int i;
	u32 res = 0;
	u8 data[12];

	*(u32 *)(data) = src;
	*(u32 *)(data + 4) = dest;
	*(u16 *)(data + 8) = sport;
	*(u16 *)(data + 10) = dport;
	
	for(i = 0 ; i < 11 ; i++)
	{
		res = ((res << 8) + (data[perm[i]] ^ xor[i])) % 0xff100f;
	}
	
	return res;
}
