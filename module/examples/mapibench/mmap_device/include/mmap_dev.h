#ifndef __MMAP_DEV_H
#define __MMAP_DEV_H

#include <asm/page.h>

#define CAPLEN 1500
#define MEM_MAP_SIZE 256*PAGE_SIZE

typedef struct mem_slot_info 
{
  __u16 tot_num_slots;
  __u16 slot_len;
  __u16 cap_len;
  __u16 next_read_slot;
  __u16 next_write_slot;
  __u64 dropped;
  __u64 num_pkts;
  __u64 copy_time;

} mem_slot_info;

typedef struct mem_slot 
{
  __u16 slot_len;
  __u8 packet_data[];

} mem_slot;

#define MODNAME "mmap_dev"
#define MODNAME_PROC "mmap_dev_stats"

#define HIPQUAD(addr) \
((unsigned char *)&addr)[3], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[0]

#ifndef __KERNEL__

static inline void print_packet(const __u8 *packet,int length)
{
	int i;

	for( i = 0 ; i < length ; i++)
	{
		printf("%.2x ",packet[i]);
	}
	
	printf("\n");
}

#endif /* __KERNEL__ */

#endif
