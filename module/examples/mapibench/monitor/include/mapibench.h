#ifndef __MAPIBENCH_H
#define __MAPIBENCH_H

#include <benchcommon.h>

#undef max
#define max(x,y) ((x) > (y) ? (x) : (y))

struct monitor_struct
{
	int *socks;
	int ports_nr;
	
	__u16 *monitored_ports;
	__u64 *packets_per_port;
	__u64 *bytes_per_port;
};

static inline struct monitor_struct *monitor_struct_alloc(int ports_nr)
{
	struct monitor_struct *mons;

	if((mons = (struct monitor_struct *)malloc(sizeof(struct monitor_struct))) == NULL)
	{
		fprintf(stderr,"Could not allocate memory\n");

		exit(1);
	}
	
	mons->ports_nr = ports_nr;

	mons->socks = (int *)malloc(mons->ports_nr*sizeof(int));
	mons->monitored_ports = (__u16 *)malloc(mons->ports_nr*sizeof(__u16));
	mons->packets_per_port = (__u64 *)calloc(mons->ports_nr,sizeof(__u64));
	mons->bytes_per_port = (__u64 *)calloc(mons->ports_nr,sizeof(__u64));

	if(mons->socks == NULL || mons->monitored_ports == NULL || mons->packets_per_port == NULL || mons->bytes_per_port == NULL)
	{
		fprintf(stderr,"Could not allocate memory\n");

		exit(1);
	}

	return mons;
}

static inline void init_monitor_struct(struct monitor_struct *mons,__u16 *monitored_ports)
{
	int i;

	for( i = 0 ; i < mons->ports_nr ; i++)
	{
		mons->monitored_ports[i] = monitored_ports[i];
	}
}

void open_sockets(struct monitor_struct *mons);
void print_ports_stats(struct monitor_struct *mons);
void apply_bpf_filters(struct monitor_struct *mons);
void count(struct monitor_struct *mons,int index,int length,const u_char *data);
void count_mmap(struct monitor_struct *mons,int index,int length,const u_char *data);

#endif
