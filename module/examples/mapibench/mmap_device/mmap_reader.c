#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/types.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <asm/system.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if.h>

#include <linux/mapi/ioctl.h>
#include <mmap_dev.h>
#include <mapihandy.h>
#include <tconfig.h>
#include <mapirusage.h>

mem_slot_info *mem_info;
__u8 *mmaped_buf;
int fd;

void terminate()
{
	if(mmaped_buf)
	{
		munmap(mmaped_buf,MEM_MAP_SIZE);
	}
	
	close(fd);
}

void sigint_handler()
{
	if(end_time_and_usage())
	{
		perror("end_time_and_usage");
		exit(1);
	}
	
	printf("Process statistics : Total packets = %lld\n",mem_info->num_pkts);
	printf("Process statistics : Packets dropped = %lld\n",mem_info->dropped);
	printf("Process statistics : Avg copy time = %f CPU clock cycles\n",(double)(((double)mem_info->copy_time)/(mem_info->num_pkts == 0 ? 1 : mem_info->num_pkts)));

	print_rusage();
	
        exit(0);
}

void open_device()
{
	char *file_name;

	file_name = (char *)malloc(strlen("/proc/net/") + strlen(MODNAME) + 1);
	sprintf(file_name,"/proc/net/%s",MODNAME);

	if((fd = open(file_name,O_RDWR)) <= 0)
	{
		printf("Unable to open '%s' entry [%s]\n",file_name,strerror(errno));
		
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	if(start_time_and_usage())
	{
		perror("start_time_and_usage");
		exit(1);
	}

	open_device();
	
	atexit(terminate);
	
        signal(SIGINT,sigint_handler);

	if((mmaped_buf  = (char *)mmap(NULL,MEM_MAP_SIZE,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0)) == MAP_FAILED)
	{
		perror("mmap");
		
		return 1;
	}

	mem_info = (mem_slot_info *)mmaped_buf;
	
	if(mem_info->tot_num_slots == 0)
	{
		printf("Not enough slots!\n");
		
		return -1;
	}

	while(1)
	{
		fd_set rfds;
		mem_slot *slot;
		int displ;

		FD_ZERO(&rfds);
		FD_SET(fd,&rfds);

		if(select(fd + 1,&rfds,NULL,NULL,NULL) == -1)
		{
			perror("select");

			exit(1);
		}

		displ = mem_info->next_read_slot * mem_info->slot_len + sizeof(mem_slot_info);
		slot = (mem_slot *)&mmaped_buf[displ];
		
		if(FD_ISSET(fd,&rfds))
		{
			if(slot->slot_len > 0)
			{
				slot->slot_len = 0;
				mem_info->next_read_slot = (mem_info->next_read_slot + 1) % mem_info->tot_num_slots;

				mb();
			}
			else
			{
				printf("Slot id %d is empty!\n",mem_info->next_read_slot);
			}
		}
		else
		{
			FD_SET(fd,&rfds);
		}
	}

	return 0;
}
