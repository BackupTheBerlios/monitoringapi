#ifndef __SUBFLOW_H
#define __SUBFLOW_H

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#define HIPQUAD(addr) \
((unsigned char *)&addr)[3], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[0]

void error(char *msg,int sock);
void sigint_handler();

#endif
