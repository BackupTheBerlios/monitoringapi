#ifndef __TCONFIG_H
#define __TCONFIG_H

#define SNAPLEN 1500
#define DEVICE "eth1"
#define IPHDR_OFFSET 16
#define MAPI_IPHDR_OFFSET 14
#define SLEEP_TIME 1*60
#define FILENAME "/tmp/histogram.txt"
#define PERIOD 1
#define SO_RCVBUF_SIZE 1024*1024

#define BLOCK_NR 1024

static __u16 monitored_ports[] = { 5001 , 20 , 21 , 22 , 23 , 25 , 80 , 2049 , 6000 , 6346 , 6347};

#define PORTS_NR ARRAY_SIZE(monitored_ports)

#endif
