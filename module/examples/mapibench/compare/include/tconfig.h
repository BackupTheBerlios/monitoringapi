#ifndef __TCONFIG_H
#define __TCONFIG_H

#include <net/ethernet.h>

#define SNAPLEN (ETHERMTU + ETHER_HDR_LEN)
#define IFNAME "eth1"
#define SLEEP_TIME 1*60
#define PERIOD 1
#define SO_RCVBUF_SIZE (1024*1024)

#endif
