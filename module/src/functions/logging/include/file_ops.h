/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __FILE_OPS_H_
#define __FILE_OPS_H_

struct file *create_file(char *filename,int *status);
void close_file(struct file *filp);
int truncate_file(struct file *filp);

#endif /* __FILE_OPS_H_ */
