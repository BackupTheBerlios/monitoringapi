/*
 *	stolen from tcpdump
 */

#ifndef __ETHER_ADDR_TO_NAME_H_
#define __ETHER_ADDR_TO_NAME_H_

#define HASHNAMESIZE 16

struct hnamemem 
{
	u32 addr;
	char *name;
	struct hnamemem *nxt;
};

static struct hnamemem eprototable[HASHNAMESIZE];

static inline char *etherproto_to_string(u16 type)
{
	register struct hnamemem *tp;
	register u32 i = type;
	char buf[10];

	for(tp = &eprototable[i & (HASHNAMESIZE-1)] ; tp->nxt ; tp = tp->nxt)
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

	sprintf(buf,"%.2x",type);
	
	if((tp->name = kmalloc(sizeof(*buf),GFP_ATOMIC)) == NULL)
	{
		return NULL;
	}

	memcpy(tp->name,buf,sizeof(*buf));
	
	return tp->name;
}

struct eproto 
{
	char *ascii;
	
	u16 id;
};

/* Static data base of ether protocol types. */

struct eproto eproto_db[] = 
{
	{"loop"		,ETH_P_LOOP	}	,
	{"ip"		,ETH_P_IP	}	,
	{"arp"		,ETH_P_ARP	}	,
	{"rarp"		,ETH_P_RARP	}	,
	{"ipv6"		,ETH_P_IPV6	}	,
	{NULL		,0 		}
};

static inline int init_eprotoarray(void)
{
	register int i;
	register struct hnamemem *table;

	for(i = 0 ; eproto_db[i].ascii ; i++)
	{
		int j = ntohs(eproto_db[i].id) & (HASHNAMESIZE-1);
		
		table = &eprototable[j];
		
		while(table->name)
		{
			table = table->nxt;
		}

		table->name = eproto_db[i].ascii;
		table->addr = ntohs(eproto_db[i].id);
		
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

static inline void deinit_eprotoarray(void)
{
	register int i;
	register struct hnamemem *table;

	for(i = 0 ; i < HASHNAMESIZE ; i++)
	{
		table = &eprototable[i];
		
		free_proto_array_line(table,0);
	}
}

#endif /* __ETHER_ADDR_TO_NAME_H_ */
