#include <linux/types.h>
#include <linux/config.h>
#include <linux/module.h>
#include <asm/system.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/checksum.h>
#include <linux/tqueue.h>
#include <linux/delay.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <linux/wrapper.h>
#include <asm/io.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <mmap_dev.h>

EXPORT_NO_SYMBOLS;

struct proc_dir_entry *mmap_dev_file;

u8 *mmapped_buf;
u32 mmapped_buf_len;

u8 device_open;

mem_slot_info *mem_info;

spinlock_t mem_info_lock = SPIN_LOCK_UNLOCKED;
spinlock_t device_lock = SPIN_LOCK_UNLOCKED;

DECLARE_WAIT_QUEUE_HEAD(mmap_dev_waitqueue);

inline void flush_pages(u8 *start,u8 *end)
{
	struct page *p_start = virt_to_page(start);
	struct page *p_end = virt_to_page(end);

	while(p_start <= p_end)
	{
		flush_dcache_page(p_start);
		p_start++;
	}
}

int copy_packet(struct sk_buff *pskb)
{
	u32 size,displ;
	mem_slot *slot;

	if(pskb->dev == NULL || pskb->pkt_type == PACKET_LOOPBACK)
	{
		return 1;
	}

	spin_lock(&mem_info_lock);
	mem_info->num_pkts++;

	displ = mem_info->next_write_slot * mem_info->slot_len + sizeof(mem_slot_info);
	slot = (mem_slot *)&mmapped_buf[displ];

	if(slot->slot_len == 0)
	{

		size = (pskb->len < mem_info->cap_len) ? pskb->len : mem_info->cap_len; 
#ifdef DEBUG		
		{
			cycles_t start,end;
			
			start = get_cycles();
			{
				memcpy(slot->packet_data,pskb->data,size);
			}
			end = get_cycles();
			
			mem_info->copy_time += (end - start);
		}
#else
		memcpy(slot->packet_data,pskb->data,size);
#endif

		slot->slot_len = size;
		mem_info->next_write_slot = (mem_info->next_write_slot + 1) % mem_info->tot_num_slots;			
		
		flush_pages((u8 *)slot,(u8 *)slot + size);
	}
	else
	{
		mem_info->dropped++;
	}
	
	spin_unlock(&mem_info_lock);

	wake_up_interruptible(&mmap_dev_waitqueue);
	
	return 0;
}

unsigned int handle_packet(unsigned int hook, struct sk_buff **pskb,const struct net_device *indev, const struct net_device *outdev, int (*okfn) (struct sk_buff *))
{
	copy_packet(*pskb);

	return NF_ACCEPT;
}


int proc_open(struct inode *ino, struct file *filp)
{
	spin_lock(&device_lock);
	
	if(device_open)
	{
		spin_unlock(&device_lock);
	
		return -EBUSY; 
	}
	
	device_open++;

	spin_unlock(&device_lock);

	memset(mmapped_buf + sizeof(mem_slot_info),0,mmapped_buf_len - sizeof(mem_slot_info));

	mem_info->next_read_slot = 0;
	mem_info->next_write_slot = 0;
	mem_info->dropped = 0;
	mem_info->num_pkts = 0;
	mem_info->copy_time = 0;

	MOD_INC_USE_COUNT;
	
	return 0;
}

int proc_release(struct inode *ino, struct file *filp)
{
	spin_lock(&device_lock);
	
	device_open--;
	
	spin_unlock(&device_lock);
	
	MOD_DEC_USE_COUNT;
	
	return 0;
}

unsigned int proc_poll(struct file *fp, struct poll_table_struct *wait)
{
	mem_slot *slot = ((mem_slot *)&mmapped_buf[mem_info->next_read_slot * mem_info->slot_len + sizeof(mem_slot_info)]);

	if(slot->slot_len)
	{
		return POLLIN | POLLRDNORM;
	}

	poll_wait(fp,&mmap_dev_waitqueue,wait);

	if(slot->slot_len)
	{
		return POLLIN | POLLRDNORM;
	}
	else
	{
		return 0;
	}
}

int proc_mmap(struct file *filp,struct vm_area_struct *vma)
{
	unsigned long page,pos;
	unsigned long start = (unsigned long)vma->vm_start;
	unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);

	if(size > mmapped_buf_len)
	{
		return -EINVAL;
	}

	pos = (unsigned long)mmapped_buf;
	
	vma->vm_flags |= VM_LOCKED;

	while(size > 0)
	{
		page = virt_to_phys((void *)pos);

		if(remap_page_range(start,page,PAGE_SIZE,vma->vm_page_prot))
		{
			return -EAGAIN;
		}

		start += PAGE_SIZE;
		pos += PAGE_SIZE;
		size -= PAGE_SIZE;
	}

	return 0;
}

struct file_operations proc_operations = {
	.open = proc_open,
	.release = proc_release,
	.poll = proc_poll,
	.mmap = proc_mmap,
};

#ifdef CONFIG_PROC_FS
int mmap_dev_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = offset;
	int len = 0;
	
	len += sprintf(buffer + len,"Total_slots Slot_len Cap_len Total_Packets Dropped_packets Avg_copy Next_rd_slot\n");
	
	read_lock(&mem_info_lock);

	len += sprintf(buffer + len,"%.11d %.8d %.7d %.13lld %.15lld %.8d %.12d\n",mem_info->tot_num_slots,mem_info->slot_len,
		       mem_info->cap_len,mem_info->num_pkts,mem_info->dropped,(u32)(((float)(mem_info->copy_time))/(mem_info->num_pkts == 0 ? 1 : mem_info->num_pkts)),mem_info->next_read_slot);
	
	if(len >= length)
	{
		goto done;
	}
	
	*eof = 1;
done:	
	read_lock(&mem_info_lock);
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
#endif

int init_mmapped_dev()
{
	struct page *page;

	mmapped_buf_len = MEM_MAP_SIZE;
	
	if((mmapped_buf = (u8 *)__get_free_pages(GFP_KERNEL,get_order(mmapped_buf_len))) == NULL)
	{
		return -ENOMEM;
	}
	
	memset(mmapped_buf,0,mmapped_buf_len);

	mem_info 		= (mem_slot_info *)mmapped_buf;
	mem_info->cap_len	= CAPLEN;
	mem_info->slot_len	= sizeof(u16) + mem_info->cap_len;
	mem_info->tot_num_slots = (mmapped_buf_len - sizeof(mem_slot_info)) / mem_info->slot_len;

	for(page = virt_to_page(mmapped_buf); page < virt_to_page(mmapped_buf + mmapped_buf_len); page++)
	{
		mem_map_reserve(page);
	}

	return 0;
}

struct nf_hook_ops packet_all_ops = { {NULL, NULL}, handle_packet,
PF_INET, NF_IP_PRE_ROUTING,
NF_IP_PRI_FILTER - 1
};

int init_module()
{
	int err;
	
	if((err = init_mmapped_dev()) != 0)
	{
		return err;
	}
	
#ifdef CONFIG_PROC_FS
	if((mmap_dev_file = create_proc_entry(MODNAME,(S_IFREG | S_IRUGO | S_IWUGO) /*S_IFREG|S_IRUSR|S_IWUSR */,proc_net)) != NULL)
	{
		mmap_dev_file->proc_fops = &proc_operations;
	}
	
	if(create_proc_read_entry(MODNAME_PROC,0,proc_net,mmap_dev_read_proc,NULL) == NULL)
	{
		printk(KERN_ALERT "Error : Could not create proc file %s : %s,%i\n",MODNAME_PROC,__FILE__,__LINE__);

		return -EPERM;
	}
#else
	return -EPERM;
#endif
	if((err = nf_register_hook(&packet_all_ops)) != 0)
	{
		return err;
	}

	return err;
}

void cleanup_module()
{
	struct page *page;

	for(page = virt_to_page(mmapped_buf); page < virt_to_page(mmapped_buf + mmapped_buf_len); page++)
	{
		mem_map_unreserve(page);
	}

	free_pages((unsigned long)mmapped_buf,get_order(mmapped_buf_len));
		
	nf_unregister_hook(&packet_all_ops);
	
#ifdef CONFIG_PROC_FS
	remove_proc_entry(MODNAME,proc_net);
	remove_proc_entry(MODNAME_PROC,proc_net);
#endif	
}

MODULE_LICENSE("GPL");
