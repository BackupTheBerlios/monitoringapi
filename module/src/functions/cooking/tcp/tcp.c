#include <linux/ip.h>
#include <linux/module.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/byteorder/generic.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#include <linux/mapi/common.h>
#include <linux/mapi/proto.h>
#include <linux/mapi/ioctl.h>
#include <mapitcp.h>
#include <mapihash.h>

PRIVATE int num_of_tcp_streams = 1024;
PRIVATE int num_of_hosts = 256;

#define FIN_SENT	120
#define FIN_CONFIRMED	121
#define COLLECT_cc	1
#define COLLECT_sc	2
#define COLLECT_ccu	4
#define COLLECT_scu	8

#define EXP_SEQ (snd->first_data_seq + rcv->count + rcv->urg_count)

PRIVATE struct tcp_stream **tcp_stream_table;
PRIVATE struct tcp_stream *streams_pool;
PRIVATE struct tcp_stream *free_streams;
PRIVATE struct tcp_stream *tcp_latest = NULL;
PRIVATE struct tcp_stream *tcp_oldest = NULL;
PRIVATE struct iphdr *ugly_iphdr;

PRIVATE int tcp_stream_table_size;
PRIVATE int tcp_num = 0;
PRIVATE int max_stream;

static inline int before(u32 seq1,u32 seq2)
{
	return ((int)(seq1 - seq2) < 0);
}

static inline int after(u32 seq1,u32 seq2)
{
	return ((int)(seq2 - seq1) < 0);
}

PRIVATE void purge_queue(struct half_stream *h)
{
	struct packet_struct *tmp,*p = h->list;

	while(p)
	{
		kfree(p->data);
		tmp = p->next;
		kfree(p);
		p = tmp;
	}

	h->list = h->listtail = 0;
	h->rmem_alloc = 0;
}

PRIVATE void free_tcp(struct tcp_stream *a_tcp)
{
	int hash_index = a_tcp->hash_index;

	purge_queue(&a_tcp->server);
	purge_queue(&a_tcp->client);

	if(a_tcp->next_node)
	{
		a_tcp->next_node->prev_node = a_tcp->prev_node;
	}

	if(a_tcp->prev_node)
	{
		a_tcp->prev_node->next_node = a_tcp->next_node;
	}
	else
	{
		tcp_stream_table[hash_index] = a_tcp->next_node;
	}

	if(a_tcp->client.data)
	{
		kfree(a_tcp->client.data);
	}
	if(a_tcp->server.data)
	{
		kfree(a_tcp->server.data);
	}
	if(a_tcp->next_time)
	{
		a_tcp->next_time->prev_time = a_tcp->prev_time;
	}
	if(a_tcp->prev_time)
	{
		a_tcp->prev_time->next_time = a_tcp->next_time;
	}
	if(a_tcp == tcp_oldest)
	{
		tcp_oldest = a_tcp->prev_time;
	}
	if(a_tcp == tcp_latest)
	{
		tcp_latest = a_tcp->next_time;
	}

	a_tcp->next_free = free_streams;
	free_streams = a_tcp;
	tcp_num--;
}

PRIVATE int mk_hash_index(struct tuple4 addr)
{
	int hash = mk_hash(addr.saddr, addr.source, addr.daddr, addr.dest);

	return hash % tcp_stream_table_size;
}

PRIVATE void add_new_tcp(struct tcphdr *this_tcphdr, struct iphdr *this_iphdr)
{
	struct tcp_stream *tolink;
	struct tcp_stream *a_tcp;
	int hash_index;
	struct tuple4 addr;

	addr.source = ntohs(this_tcphdr->source);
	addr.dest = ntohs(this_tcphdr->dest);
	addr.saddr = this_iphdr->saddr;
	addr.daddr = this_iphdr->daddr;
	hash_index = mk_hash_index(addr);

	if(tcp_num > max_stream)
	{
		/*struct lurker_node *i;

		tcp_oldest->con_state = CON_TIMED_OUT;
		
		for(i = tcp_oldest->listeners; i; i = i->next)
		{
			(i->item) (tcp_oldest, &i->data);
		}

		free_tcp(tcp_oldest);
		*/
	}
	
	a_tcp = free_streams;

	if(!a_tcp)
	{
		//error
		return;
	}

	free_streams = a_tcp->next_free;

	tcp_num++;
	tolink = tcp_stream_table[hash_index];
	
	memset(a_tcp,0,sizeof(struct tcp_stream));
	
	a_tcp->hash_index	= hash_index;
	a_tcp->addr		= addr;
	a_tcp->client.state	= TCP_SYN_SENT;
	a_tcp->client.seq	= ntohl(this_tcphdr->seq) + 1;
	a_tcp->client.first_data_seq = a_tcp->client.seq;
	a_tcp->client.window	= ntohs(this_tcphdr->window);
	a_tcp->server.state	= TCP_CLOSE;
	a_tcp->next_node	= tolink;
	a_tcp->prev_node	= 0;
	
	if(tolink)
	{
		tolink->prev_node = a_tcp;
	}

	tcp_stream_table[hash_index] = a_tcp;
	a_tcp->next_time = tcp_latest;
	a_tcp->prev_time = 0;
	
	if(!tcp_oldest)
	{
		tcp_oldest = a_tcp;
	}
	
	if(tcp_latest)
	{
		tcp_latest->prev_time = a_tcp;
	}

	tcp_latest = a_tcp;
}

PRIVATE void add2buf(struct half_stream *rcv, char *data, int datalen)
{
	if(datalen + rcv->count - rcv->offset > rcv->bufsize)
	{
		if(!rcv->data)
		{
			int toalloc;

			if(datalen < 2048)
			{
				toalloc = 4096;
			}
			else
			{
				toalloc = datalen * 2;
			}
			
			rcv->data = kmalloc(toalloc,GFP_ATOMIC);
			rcv->bufsize = toalloc;
		}
		else
		{
			char *data = rcv->data;
			int bufsize = rcv->bufsize;
			
			rcv->data = kmalloc(2 * rcv->bufsize,GFP_ATOMIC);
			rcv->bufsize *= 2;
			memcpy(rcv->data,data,bufsize);
			
			kfree(data);
		}
		
		if(!rcv->data)
		{
			//error no mem
			return;
		}
	}

	memcpy(rcv->data + rcv->count - rcv->offset, data, datalen);

	rcv->count_new = datalen;
	rcv->count += datalen;
}

PRIVATE void ride_lurkers(struct tcp_stream *a_tcp, char mask)
{
	/*struct lurker_node *i;
	char cc, sc, ccu, scu;

	for(i = a_tcp->listeners; i; i = i->next)
		if(i->whatto & mask)
		{
			cc = a_tcp->client.collect;
			sc = a_tcp->server.collect;
			ccu = a_tcp->client.collect_urg;
			scu = a_tcp->server.collect_urg;

			(i->item) (a_tcp, &i->data);
			if(cc < a_tcp->client.collect)
				i->whatto |= COLLECT_cc;
			if(ccu < a_tcp->client.collect_urg)
				i->whatto |= COLLECT_ccu;
			if(sc < a_tcp->server.collect)
				i->whatto |= COLLECT_sc;
			if(scu < a_tcp->server.collect_urg)
				i->whatto |= COLLECT_scu;
			if(cc > a_tcp->client.collect)
				i->whatto &= ~COLLECT_cc;
			if(ccu > a_tcp->client.collect_urg)
				i->whatto &= ~COLLECT_ccu;
			if(sc > a_tcp->server.collect)
				i->whatto &= ~COLLECT_sc;
			if(scu > a_tcp->server.collect_urg)
				i->whatto &= ~COLLECT_scu;
		}
	*/	
}

PRIVATE void notify(struct tcp_stream *a_tcp, struct half_stream *rcv)
{
	/*struct lurker_node *i, **prev_addr;
	char mask;

	if(rcv->count_new_urg)
	{
		if(!rcv->collect_urg)
			return;
		if(rcv == &a_tcp->client)
			mask = COLLECT_ccu;
		else
			mask = COLLECT_scu;
		ride_lurkers(a_tcp, mask);
		goto prune_listeners;
	}
	if(rcv->collect)
	{
		if(rcv == &a_tcp->client)
			mask = COLLECT_cc;
		else
			mask = COLLECT_sc;
		do
		{
			int total;
			a_tcp->read = rcv->count - rcv->offset;
			total = a_tcp->read;

			ride_lurkers(a_tcp, mask);
			if(a_tcp->read > total - rcv->count_new)
				rcv->count_new = total - a_tcp->read;

			if(a_tcp->read > 0)
			{
				memmove(rcv->data, rcv->data + a_tcp->read, rcv->count - rcv->offset - a_tcp->read);
				rcv->offset += a_tcp->read;
			}
		}
		while(nids_params.one_loop_less && a_tcp->read > 0 && rcv->count_new);
		
		rcv->count_new = 0;
	}
    prune_listeners:
	prev_addr = &a_tcp->listeners;
	i = a_tcp->listeners;
	while(i)
		if(!i->whatto)
		{
			*prev_addr = i->next;
			free(i);
			i = *prev_addr;
		}
		else
		{
			prev_addr = &i->next;
			i = i->next;
		}
	*/	
}

PRIVATE void add_from_skb(struct tcp_stream *a_tcp, struct half_stream *rcv, struct half_stream *snd, u_char * data, int datalen, u32 this_seq, char fin, char urg, u32 urg_ptr)
{
	u32 lost = EXP_SEQ - this_seq;
	int to_copy, to_copy2;

	if(urg && after(urg_ptr, EXP_SEQ - 1) && (!rcv->urg_seen || after(urg_ptr, rcv->urg_ptr)))
	{
		rcv->urg_ptr = urg_ptr;
		rcv->urg_seen = 1;
	}
	
	if(after(rcv->urg_ptr + 1, this_seq + lost) && before(rcv->urg_ptr, this_seq + datalen))
	{
		to_copy = rcv->urg_ptr - (this_seq + lost);
		
		if(to_copy > 0)
		{
			if(rcv->collect)
			{
				add2buf(rcv, data + lost, to_copy);
				notify(a_tcp, rcv);
			}
			else
			{
				rcv->count += to_copy;
			}
		}
		
		rcv->urgdata = data[rcv->urg_ptr - this_seq];
		rcv->count_new_urg = 1;
		notify(a_tcp, rcv);
		rcv->count_new_urg = 0;
		rcv->urg_count++;
		to_copy2 = this_seq + datalen - rcv->urg_ptr - 1;
		
		if(to_copy2 > 0)
		{
			if(rcv->collect)
			{
				add2buf(rcv, data + lost + to_copy + 1, to_copy2);
				notify(a_tcp, rcv);
			}
			else
			{
				rcv->count += to_copy2;
			}
		}
	}
	else
	{
		if(datalen - lost > 0)
		{
			if(rcv->collect)
			{
				add2buf(rcv, data + lost, datalen - lost);
				notify(a_tcp, rcv);
			}
			else
			{
				rcv->count += datalen - lost;
			}
		}
	}
	
	if(fin)
	{
		snd->state = FIN_SENT;
	}
}

PRIVATE void tcp_queue(struct tcp_stream *a_tcp,struct tcphdr *this_tcphdr,struct half_stream *snd,struct half_stream *rcv,char *data,int datalen,int skblen)
{
	u32 this_seq = ntohl(this_tcphdr->seq);
	struct packet_struct *packet;

	/*
	 * Did we get anything new to ack?
	 */

	if(!after(this_seq, EXP_SEQ))
	{
		if(after(this_seq + datalen + (this_tcphdr->fin), EXP_SEQ))
		{
			/*
			 * the packet straddles our window end 
			 */
			
			add_from_skb(a_tcp, rcv, snd, data, datalen, this_seq, (this_tcphdr->fin), (this_tcphdr->urg), ntohs(this_tcphdr->urg_ptr) + this_seq - 1);
			
			/*
			 * Do we have any old packets to ack that the above
			 * made visible? (Go forward from skb)
			 */
			packet = rcv->list;

			while(packet)
			{
				if(after(packet->seq, EXP_SEQ))
				{
					break;
				}
				
				if(after(packet->seq + packet->len, EXP_SEQ))
				{
					struct packet_struct *tmp;

					add_from_skb(a_tcp, rcv, snd, packet->data, packet->len, packet->seq, packet->fin, packet->urg, packet->urg_ptr + packet->seq - 1);
					rcv->rmem_alloc -= packet->truesize;
					
					if(packet->prev)
					{
						packet->prev->next = packet->next;
					}
					else
					{
						rcv->list = packet->next;
					}
					
					if(packet->next)
					{
						packet->next->prev = packet->prev;
					}
					else
					{
						rcv->listtail = packet->prev;
					}
					
					tmp = packet->next;
					kfree(packet->data);
					kfree(packet);
					packet = tmp;
				}
				else
				{
					packet = packet->next;
				}
			}
		}
		else
		{
			return;
		}
	}
	else
	{
		struct packet_struct *p = rcv->listtail;

		packet = (struct packet_struct *)kmalloc(sizeof(struct packet_struct),GFP_ATOMIC);
		packet->truesize = skblen;
		rcv->rmem_alloc += packet->truesize;
		packet->len = datalen;
		packet->data = kmalloc(datalen,GFP_ATOMIC);

		if(!packet->data)
		{
			//error no mem
			return;
		}
		
		//sleepy
		memcpy(packet->data, data, datalen);
		
		packet->fin = (this_tcphdr->fin);
		packet->seq = this_seq;
		packet->urg = (this_tcphdr->urg);
		packet->urg_ptr = ntohs(this_tcphdr->urg_ptr);
		
		for(;;)
		{
			if(!p || !after(p->seq, this_seq))
			{
				break;
			}
			p = p->prev;
		}
		
		if(!p)
		{
			packet->prev = 0;
			packet->next = rcv->list;
			rcv->list = packet;
			
			if(!rcv->listtail)
			{
				rcv->listtail = packet;
			}
		}
		else
		{
			packet->next = p->next;
			p->next = packet;
			packet->prev = p;
			
			if(packet->next)
			{
				packet->next->prev = packet;
			}
			else
			{
				rcv->listtail = packet;
			}
		}
	}
}

PRIVATE void prune_queue(struct half_stream *rcv, struct tcphdr *this_tcphdr)
{
	struct packet_struct *tmp,*p = rcv->list;

	while(p) 
	{
		kfree(p->data);
		tmp = p->next;
		kfree(p);
		p = tmp;
	}

	rcv->list = rcv->listtail = 0;
	rcv->rmem_alloc = 0;
}

PRIVATE void handle_ack(struct tcp_stream *a_tcp, struct half_stream *snd, struct half_stream *rcv, u32 acknum)
{
	int ackdiff;

	ackdiff = acknum - snd->ack_seq;
	
	if(ackdiff > 0)
	{
		snd->ack_seq = acknum;
	}
}

PRIVATE void check_flags(struct iphdr *iph, struct tcphdr *th)
{
	u_char flag = *(((u_char *) th) + 13);

	if(flag & 0x40 || flag & 0x80)
	{
		MAPI_DEBUG(if(net_ratelimit())
			   printk(KERN_DEBUG "TCP : Flags error: %u.%u.%u.%u:%u to %u.%u.%u.%u:%u\n",
				  NIPQUAD(iph->saddr),ntohs(th->source),
				  NIPQUAD(iph->daddr),ntohs(th->dest)));
	}
}

struct tcp_stream *find_stream(struct tcphdr *this_tcphdr, struct iphdr *this_iphdr, int *from_client)
{
	struct tuple4 this_addr,reversed;
	struct tcp_stream *a_tcp;
	int hash_index;

	this_addr.source	= ntohs(this_tcphdr->source);
	this_addr.dest		= ntohs(this_tcphdr->dest);
	this_addr.saddr		= this_iphdr->saddr;
	this_addr.daddr		= this_iphdr->daddr;
	hash_index		= mk_hash_index(this_addr);

	for(a_tcp = tcp_stream_table[hash_index]; a_tcp && !b_comp(a_tcp->addr, this_addr); a_tcp = a_tcp->next_node)
	{}
	
	if(a_tcp)
	{
		*from_client = 1;
		
		return a_tcp;
	}
	
	reversed.source		= ntohs(this_tcphdr->dest);
	reversed.dest		= ntohs(this_tcphdr->source);
	reversed.saddr		= this_iphdr->daddr;
	reversed.daddr		= this_iphdr->saddr;
	hash_index		= mk_hash_index(reversed);
	
	for(a_tcp = tcp_stream_table[hash_index]; a_tcp && !b_comp(a_tcp->addr, reversed); a_tcp = a_tcp->next_node)
	{}
	
	if(a_tcp)
	{
		*from_client = 0;
		
		return a_tcp;
	}
	else
	{
		return NULL;
	}
}

void clear_stream_buffers()
{
	/*int i;
	struct lurker_node *j;
	struct tcp_stream *a_tcp;

	for(i = 0 ; i < tcp_stream_table_size ; i++)
	{
		for(a_tcp = tcp_stream_table[i] ; a_tcp ; a_tcp = a_tcp->next_node)
		{
			for(j = a_tcp->listeners; j; j = j->next)
			{
				a_tcp->con_state = CON_EXITING;
				(j->item) (a_tcp, &j->data);
			}
		}
	}*/
}

u8 check_hdr(struct iphdr *iph,struct tcphdr *tcph)
{
	int iplen = ntohs(iph->tot_len);
	int datalen;

	if(iplen - 4 * iph->ihl < sizeof(struct tcphdr))
	{
		goto header_error;
	}
	
	datalen = iplen - 4 * iph->ihl - 4 * tcph->doff;

	if(datalen < 0)
	{
		goto header_error;
	}
	
	if((iph->saddr | iph->daddr) == 0)
	{
		goto header_error;
	}
	
	if(mapi_tcp_check(tcph,iplen - 4 * iph->ihl,iph->saddr,iph->daddr))
	{
		goto csum_error;
	}

	check_flags(iph,tcph);

	return datalen;
	
header_error:
	MAPI_DEBUG(if(net_ratelimit())
		   printk("COOK_TCP : Header error: %u.%u.%u.%u:%u to %u.%u.%u.%u:%u\n",
			   NIPQUAD(iph->saddr),ntohs(tcph->source),
			   NIPQUAD(iph->daddr),ntohs(tcph->dest)));
	return -1;
	
csum_error:
	MAPI_DEBUG(if(net_ratelimit())
		   printk("COOK_TCP : Csum error: %u.%u.%u.%u:%u to %u.%u.%u.%u:%u\n",
			   NIPQUAD(iph->saddr),ntohs(tcph->source),
			   NIPQUAD(iph->daddr),ntohs(tcph->dest)));
	return -1;
}

struct sk_buff *mapi_tcp(struct sk_buff *skb,struct sock *sk)
{
	struct iphdr *this_iphdr = proto_iphdr(skb);
	struct tcphdr *this_tcphdr = proto_tcphdr(skb,this_iphdr);
	struct tcp_stream *a_tcp;
	struct half_stream *snd;
	struct half_stream *rcv;
	int from_client = 1;
	int datalen;

	if((datalen = check_hdr(this_iphdr,this_tcphdr)) <= 0)
	{
		return NULL;
	}
	
	ugly_iphdr = this_iphdr;
	
	printk("syn = %1d ack = %1d rst = %1d\n",this_tcphdr->syn,this_tcphdr->ack,this_tcphdr->rst);
	
	if(!(a_tcp = find_stream(this_tcphdr,this_iphdr,&from_client)))
	{
		printk("OK - 1\n");
		
		if((this_tcphdr->syn) && !(this_tcphdr->ack) && !(this_tcphdr->rst))
		{
			add_new_tcp(this_tcphdr, this_iphdr);
			
			printk("OK - 2\n");
		}

		return NULL;
	}
	
	printk("OK - 3\n");
	
	if(from_client)
	{
		snd = &a_tcp->client;
		rcv = &a_tcp->server;
	}
	else
	{
		rcv = &a_tcp->client;
		snd = &a_tcp->server;
	}

	if((this_tcphdr->syn))
	{
		if(from_client || a_tcp->client.state != TCP_SYN_SENT || a_tcp->server.state != TCP_CLOSE || !(this_tcphdr->ack))
		{
			return NULL;
		}
		if(a_tcp->client.seq != ntohl(this_tcphdr->ack_seq))
		{
			return NULL;
		}
		
		a_tcp->server.state = TCP_SYN_RECV;
		a_tcp->server.seq = ntohl(this_tcphdr->seq) + 1;
		a_tcp->server.first_data_seq = a_tcp->server.seq;
		a_tcp->server.ack_seq = ntohl(this_tcphdr->ack_seq);
		a_tcp->server.window = ntohs(this_tcphdr->window);
		
		return NULL;
	}
	
	
	if(!before(ntohl(this_tcphdr->seq), rcv->ack_seq + rcv->window) || before(ntohl(this_tcphdr->seq) + datalen, rcv->ack_seq))
	{
		return NULL;
	}

	if((this_tcphdr->rst))
	{
		if(a_tcp->con_state == CON_DATA)
		{
			a_tcp->con_state = CON_RESET;
		}
		
		free_tcp(a_tcp);
		
		return NULL;
	}

	if((this_tcphdr->ack))
	{
		if(from_client && a_tcp->client.state == TCP_SYN_SENT && a_tcp->server.state == TCP_SYN_RECV)
		{
			if(ntohl(this_tcphdr->ack_seq) == a_tcp->server.seq)
			{
				a_tcp->client.state = TCP_ESTABLISHED;
				a_tcp->client.ack_seq = ntohl(this_tcphdr->ack_seq);
				{
					//struct proc_node *i;
					//struct lurker_node *j;
					//void *data;

					a_tcp->server.state = TCP_ESTABLISHED;
					a_tcp->con_state = CON_JUST_EST;
					
					/*for(i = tcp_procs; i; i = i->next)
					{
						char whatto = 0;
						char cc = a_tcp->client.collect;
						char sc = a_tcp->server.collect;
						char ccu = a_tcp->client.collect_urg;
						char scu = a_tcp->server.collect_urg;

						(i->item) (a_tcp, &data);
						
						if(cc < a_tcp->client.collect)
						{
							whatto |= COLLECT_cc;
						}
						if(ccu < a_tcp->client.collect_urg)
						{
							whatto |= COLLECT_ccu;
						}
						if(sc < a_tcp->server.collect)
						{
							whatto |= COLLECT_sc;
						}
						if(scu < a_tcp->server.collect_urg)
						{
							whatto |= COLLECT_scu;
						}
						if(nids_params.one_loop_less)
						{
							if(a_tcp->client.collect >= 2)
							{
								a_tcp->client.collect = cc;
								whatto &= ~COLLECT_cc;
							}
							if(a_tcp->server.collect >= 2)
							{
								a_tcp->server.collect = sc;
								whatto &= ~COLLECT_sc;
							}
						}
						if(whatto)
						{
							j = mk_new(struct lurker_node);
							j->item = i->item;
							j->data = data;
							j->whatto = whatto;
							j->next = a_tcp->listeners;
							a_tcp->listeners = j;
						}
					}*/
					
					/*if(!a_tcp->listeners)
					{
						free_tcp(a_tcp);
						
						return;
					}*/

					a_tcp->con_state = CON_DATA;
				}
			}
		}
	}
	
	
	if((this_tcphdr->ack))
	{
		handle_ack(a_tcp,snd,rcv,ntohl(this_tcphdr->ack_seq));
	
		if(rcv->state == FIN_SENT)
		{
			rcv->state = FIN_CONFIRMED;
		}
		
		if(rcv->state == FIN_CONFIRMED && snd->state == FIN_CONFIRMED)
		{
			a_tcp->con_state = CON_CLOSE;
			
			free_tcp(a_tcp);
			
			return NULL;
		}
	}

	if(datalen + (this_tcphdr->fin) > 0)
	{
		tcp_queue(a_tcp,this_tcphdr,snd,rcv,(char *)(this_tcphdr) + 4 * this_tcphdr->doff,datalen,skb->len);
	}
	
	snd->window = ntohs(this_tcphdr->window);
	
	if(rcv->rmem_alloc > 65535)
	{
		prune_queue(rcv,this_tcphdr);
	}
	
	/*if(!a_tcp->listeners)
	{
		free_tcp(a_tcp);
	}*/

	return NULL;
}

int mapi_tcp_init(struct cook_tcp_struct *cts)
{
	int i;
	
	if(num_of_tcp_streams <= 0)
	{
		return -EINVAL;
	}
	
	tcp_stream_table_size = num_of_tcp_streams;
	
	if((tcp_stream_table = kmalloc(tcp_stream_table_size * sizeof(struct tcp_stream *),GFP_KERNEL)) == NULL)
	{
		return -ENOMEM;	
	}

	memset(tcp_stream_table,0,tcp_stream_table_size * sizeof(struct tcp_stream *));

	max_stream = 3 * tcp_stream_table_size / 4;
	
	if((streams_pool = kmalloc((max_stream + 1) * sizeof(struct tcp_stream),GFP_KERNEL)) == NULL)
	{
		kfree(tcp_stream_table);
		
		return -ENOMEM;
	}
	
	for(i = 0 ; i < max_stream ; i++)
	{
		streams_pool[i].next_free = &(streams_pool[i + 1]);
	}

	streams_pool[max_stream].next_free = NULL;
	
	free_streams = streams_pool;
	
	init_hash();

	return 0;
}

void mapi_tcp_deinit(struct cook_tcp_struct *cts)
{
	kfree(tcp_stream_table);
	kfree(streams_pool);
}

MODULE_PARM(num_of_tcp_streams,"i");
MODULE_PARM_DESC(num_of_tcp_streams,"Maximum number of tcp streams (default = 1024)");

MODULE_PARM(num_of_hosts,"i");
MODULE_PARM_DESC(num_of_hosts,"Maximum number of hosts (default = 256)");
