/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef __MAPIHASH_H
#define __MAPIHASH_H

#ifdef __KERNEL__

void init_hash();
u_int mk_hash(u_int, u_short, u_int, u_short);

#endif /* __KERNEL__ */

#endif /* __MAPIHASH_H */
