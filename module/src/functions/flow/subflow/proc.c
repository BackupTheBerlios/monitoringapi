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
#include <linux/list.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include <linux/mapi/packet.h>
#include <linux/mapi/common.h>
#include <linux/mapi/ioctl.h>

#include <subflow.h>
#include <hashtable.h>

#ifdef CONFIG_PROC_FS

PRIVATE void subflow_to_string(struct subflow *sbf,char *buffer,int *len)
{
	struct subflow_private_struct *cb = subflow_cb(sbf);

	*len += sprintf(buffer + *len,"%3u.%3u.%3u.%3u  ",HIPQUAD(sbf->src_ip));
	*len += sprintf(buffer + *len,"%3u.%3u.%3u.%3u  ",HIPQUAD(sbf->dst_ip));
	*len += sprintf(buffer + *len,"%.5u ",sbf->src_port);
	*len += sprintf(buffer + *len,"%.5u ",sbf->dst_port);
	*len += sprintf(buffer + *len,"%.1u   ",cb->expired);
	*len += sprintf(buffer + *len,"%.7llu ",sbf->npackets);
	*len += sprintf(buffer + *len,"%.10llu ",sbf->nbytes);
	*len += sprintf(buffer + *len,"%.10lu ",sbf->start_time.tv_sec);
	*len += sprintf(buffer + *len,"%.10lu\n",sbf->end_time.tv_sec);
}

PUBLIC int subflow_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	struct sock *sk;
	off_t pos = 0;
	off_t begin = 0;
	u8 cont = 0;
	int len = 0;
	struct hlist_node *node;
	
	len += sprintf(buffer,"Sock      Total_Subflows  Timeout  Max_Duration\n");

	lock_active_socket_list();
	
	sk_for_each(sk,node,get_active_socket_list())
	{
		struct predef_func *pfunc = sk_find_type(sk,SUBFLOW);
		struct predef_func *cur;
		
		for( cur = pfunc ; cur != NULL ; cur = cur->tnext)
		{	
			struct subflow_struct *ss = (struct subflow_struct *)cur->data;
			struct list_head *list_cur;

			len += sprintf(buffer + len,"%8p  %.14d  %.7lld  %.12lld\n",sk,atomic_read(&(ss->subflows_nr)),ss->timeout,ss->max_duration);
			len += sprintf(buffer + len,"Src_IP           Dst_IP           sPort dPort Exp Packets Bytes      sTime      eTime\n");
			
			read_lock(&(ss->subflow_list_lock));			
			
			list_for_each(list_cur,ss->subflow_list)
			{
				struct subflow *sbf = subflow_list_entry(list_cur);
			
				subflow_to_string(sbf,buffer,&len);

				pos = begin + len;

				if(pos < offset)
				{
					len = 0;
					begin = pos;
				}
				else if(pos > offset + length)
				{
					cont = 1;
					read_unlock(&(ss->subflow_list_lock));
					
					break;
				}
			}
			
			read_unlock(&(ss->subflow_list_lock));			
		}
	}

	if(!cont)
	{
		*eof = 1;
	}

	unlock_active_socket_list();
	*start = buffer + (offset - begin);
	len -= (offset - begin);

	if(len > length)
	{
		len = length;
	}
	else if(len < 0)
	{
		len = 0;
	}

	return len;
}

#ifdef DEBUG
PUBLIC int hash_table_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	struct subflow_struct *ss = (struct subflow_struct *)data;
	struct hash_table *ht = ss->subflow_hash_table;
	off_t pos;
	int len = 0;
	
	len += sprintf(buffer + len,"index     usage\n");
	
	read_lock(&(ss->subflow_hash_table_lock));

	for( pos = offset ; pos < ht->capacity ; pos++)
	{
		len += sprintf(buffer + len,"%.8lld %lld\n",(u64)pos,(u64)ht->usage[pos]);
		
		if(len >= length)
		{
			goto done;
		}
	}
	
	*eof = 1;
done:	
	read_unlock(&(ss->subflow_hash_table_lock));
	*start = (char *)(pos - offset);
	
	if(len > length)
	{
		len = length;
	}

	if(len < 0)
	{
		len = 0;
	}

	return len;	
}
#endif /* DEBUG */

#endif /* CONFIG_PROC_FS */
