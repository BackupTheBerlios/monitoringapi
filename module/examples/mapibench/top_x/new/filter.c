#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <linux/if_ether.h>
#include <net/bpf.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <sys/time.h>
#include <math.h>
#include <string.h>
#include <pcap.h>
#include <sys/ioctl.h>

#include <linux/mapi/ioctl.h>
#include <tconfig.h>
#include <subflow.h>
#include <top_x.h>

void apply_bpf_filter(int sock,struct decide_struct *ds,char *condition,__u8 direction)
{
	struct bpf_program bpf_filter;
	pcap_t *p;
	
	if((p = pcap_open_dead(DLT_EN10MB,SNAPLEN)) == NULL)
	{
		fprintf(stderr,"pcap_open_dead failed\n");
		
		exit(1);
	}
	
	printf("BPF : %s\n",condition);
	
	if(pcap_compile(p,&bpf_filter,condition,0,0xFFFFFF00))
	{
		pcap_perror(p,"pcap_compile");
		
		exit(1);
	}

	{
			struct bpf_filter_struct bfs;
			
			memcpy(&(bfs.fprog),&bpf_filter,sizeof(bpf_filter));
	
			if(ds != NULL)
			{
				ds->ioctl.cmd = SIOCSBPF_FILTER;
				ds->ioctl.arg = &bfs;
				ds->ioctl.direction = direction;
				
				do_ioctl(sock,SIOCIODECIDE,ds,"SIOCIODECIDE : SIOCSBPF_FILTER");
			}
			else
			{
				do_ioctl(sock,SIOCSBPF_FILTER,&bfs,"SIOCSBPF_FILTER");
			}
	}

	pcap_freecode(&bpf_filter);

	pcap_close(p);
}

void apply_bpf_hook(int sock,struct decide_struct *ds,char *condition,__u8 direction)
{
	struct bpf_program bpf_filter;
	pcap_t *p;
	
	if((p = pcap_open_dead(DLT_EN10MB,SNAPLEN)) == NULL)
	{
		fprintf(stderr,"pcap_open_dead failed\n");
		
		exit(1);
	}
	
	printf("BPF hook : %s\n",condition);
	
	if(pcap_compile(p,&bpf_filter,condition,0,0xFFFFFF00))
	{
		pcap_perror(p,"pcap_compile");
		
		exit(1);
	}

	{
			struct decide_bpf_hook_struct dbhs;
			
			memcpy(&(dbhs.fprog),&bpf_filter,sizeof(bpf_filter));
	
			if(ds != NULL)
			{
				ds->ioctl.cmd = SIOCSDECIDE_BPF_HOOK;
				ds->ioctl.arg = &dbhs;
				ds->ioctl.direction = direction;
				
				do_ioctl(sock,SIOCIODECIDE,ds,"SIOCIODECIDE : SIOCSDECIDE_BPF_HOOK");
			}
			else
			{
				do_ioctl(sock,SIOCSDECIDE_BPF_HOOK,&dbhs,"SIOCSDECIDE_BPF_HOOK");
			}
			
			/*struct decide_tee_hook_struct dths;
			
			if(ds != NULL)
			{
				ds->ioctl.cmd = SIOCSDECIDE_TEE_HOOK;
				ds->ioctl.arg = &dths;
				ds->ioctl.direction = direction;
				
				do_ioctl(sock,SIOCIODECIDE,ds,"SIOCIODECIDE : SIOCSDECIDE_TEE_HOOK");
			}
			else
			{
				do_ioctl(sock,SIOCSDECIDE_TEE_HOOK,&dths,"SIOCSDECIDE_TEE_HOOK");
			}*/
	}

	pcap_freecode(&bpf_filter);

	pcap_close(p);
}
