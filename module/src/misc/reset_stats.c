/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>

#include <linux/mapi/common.h>

EXPORT_NO_SYMBOLS;

int __init reset_stats_init(void)
{
	reset_net_dev_stats();

	return 0;
}

void __exit reset_stats_exit(void)
{
}

module_init(reset_stats_init);
module_exit(reset_stats_exit);

MODULE_AUTHOR("Konstantinos Xinidis <xinidis@csd.uoc.gr>");
MODULE_LICENSE("GPL");

