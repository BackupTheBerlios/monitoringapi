/*
 *	stolen from tcpdump
 */

#ifndef __IP_ADDR_TO_NAME_H_
#define __IP_ADDR_TO_NAME_H_

#define HASHNAMESIZE 256

#include <linux/in.h>

struct hnamemem 
{
	u32 addr;
	char *name;
	struct hnamemem *nxt;
};

static struct hnamemem ipprototable[HASHNAMESIZE];

static inline char *ipproto_to_string(u8 type)
{
	register struct hnamemem *tp;
	register u32 i = type;
	char buf[10];

	for(tp = &ipprototable[i & (HASHNAMESIZE-1)] ; tp->nxt ; tp = tp->nxt)
	{
		if(tp->addr == i)
		{
			return tp->name;
		}
	}

	tp->addr = i;
	
	if((tp->nxt = kmalloc(sizeof(struct hnamemem),GFP_ATOMIC)) == NULL)
	{
		return NULL;
	}

	memset(tp->nxt,0,sizeof(struct hnamemem));

	sprintf(buf,"%.1x",type);
	
	if((tp->name = kmalloc(sizeof(*buf),GFP_ATOMIC)) == NULL)
	{
		return NULL;
	}

	memcpy(tp->name,buf,sizeof(*buf));
	
	return tp->name;
}

struct ipproto 
{
	char *ascii;
	
	u32 id;
};

/* Static data base of ether protocol types. */

struct ipproto ipproto_db[] = 
{
	{"icmp"		,IPPROTO_ICMP	}	,
	{"tcp"		,IPPROTO_TCP	}	,
	{"udp"		,IPPROTO_UDP	}	,
	{"ipv6"		,IPPROTO_IPV6	}	,
	{"raw"		,IPPROTO_RAW 	}	,
	{"ipip"		,IPPROTO_IPIP 	}	,
	{NULL		,0 		}
};

static inline int init_ipprotoarray(void)
{
	register int i;
	register struct hnamemem *table;
	
	for(i = 0 ; ipproto_db[i].ascii ; i++)
	{
		int j = ipproto_db[i].id & (HASHNAMESIZE-1);
		
		table = &ipprototable[j];
		
		while(table->name)
		{
			table = table->nxt;
		}

		table->name = ipproto_db[i].ascii;
		table->addr = ipproto_db[i].id;
		
		if((table->nxt = kmalloc(sizeof(struct hnamemem),GFP_KERNEL)) == NULL)
		{
			return -ENOMEM;
		}

		memset(table->nxt,0,sizeof(struct hnamemem));
	}

	return 0;
}

static inline void free_proto_array_line(struct hnamemem *table,u32 level)
{
	if(table->nxt == NULL)
	{
		if(level > 0)
		{
			kfree(table);
		}

		return;
	}

	free_proto_array_line(table->nxt,level + 1);
	
	if(level > 0)
	{
		kfree(table);
	}
}

static inline void deinit_ipprotoarray(void)
{
	register int i;
	register struct hnamemem *table;

	for(i = 0 ; i < HASHNAMESIZE ; i++)
	{
		table = &ipprototable[i];
		
		free_proto_array_line(table,0);
	}
}

#endif /* __IP_ADDR_TO_NAME_H_ */
