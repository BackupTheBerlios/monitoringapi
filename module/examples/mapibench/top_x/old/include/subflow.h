#ifndef __SUBFLOW_H_
#define __SUBFLOW_H_

#define HIPQUAD(addr) \
((unsigned char *)&addr)[3], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[0]

struct subflow *get_top_x(int top_size);

#endif /* __SUBFLOW_H_ */
