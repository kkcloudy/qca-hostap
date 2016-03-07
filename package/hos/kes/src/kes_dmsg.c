/**********************************************************************  
FILE NAME : kes_dmsg.c
Author : libing
Version : V1.0
Date : 201109013 
Description : 

Dependence :
	
Others : 
	
History: 
1. Date:20110913
Author: libing
Modification: V1.0
**********************************************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/time.h>
#include <asm/page.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <linux/fs.h>

#include "kes.h"

unsigned char *kes_dmsg_addr = NULL;
unsigned char *kes_dmsg_print_addr = NULL;
kes_mem_header_type *kes_dmsg_header = NULL;

unsigned int kes_dmsg_offset = 0;
unsigned char kes_dmsg_switch[2] = {'0',0};

/********************************************************************** 
memory name : 
	kes_dmsg_switch
Description : 
	kes dmsg switch ops
file open : 
	kes_dmsg_switch_proc_open
file read : 
	kes_dmsg_switch_proc_read
file write :
	kes_dmsg_switch_proc_write
handle write : 
	none
**********************************************************************/
static ssize_t kes_dmsg_switch_proc_write(struct file *flip, const char __user *buff, size_t len, loff_t *ppos)
{

    if(len > 2) //just a character and a '\0' is enough
    {
        printk(KERN_INFO "kes_dmsg_switch buffer is full.\n");
        return -ENOSPC;
    }

    if(copy_from_user(kes_dmsg_switch, buff, 2))
    {
        printk(KERN_INFO "kes_dmsg_switch copy_from_user error.\n");
        return -EFAULT;
    }

    if(kes_dmsg_switch[0] == '0')
        memset(kes_dmsg_addr, 0, KES_DMSG_BLOCK_SIZE);
    
    kes_dmsg_switch[0] = '1';

    return len;
}


static int kes_dmsg_switch_proc_read(struct seq_file *m, void *v)
{
    unsigned char tmp[8] = {0};
    memcpy(tmp, kes_dmsg_switch, 1);
    
    seq_printf(m,"kes_dmsg_switch = %s\n",tmp);
    return 0;
}


static int kes_dmsg_switch_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, kes_dmsg_switch_proc_read, NULL);
}


static const struct file_operations kes_dmsg_swtich_fops = {
	.owner		= THIS_MODULE,
	.open		= kes_dmsg_switch_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= kes_dmsg_switch_proc_write,
};

/********************************************************************** 
memory name : 
	kes_dmsg
Description : 
	kes dmsg ops
file open : 
	kes_dmsg_proc_open
file read : 
	none
file write :
	none
handle write : 
	print_msg_to_kes_dmsg
**********************************************************************/
int print_msg_to_kes_dmsg(char *buff, int size )
{
    static int is_first_dmsg = 0;

    if(buff == NULL)
    {
        return 0;
    }

    if('1' != kes_dmsg_switch[0])
    {
        return 0;
    }
    
    if(!is_first_dmsg)
    {
        memset(kes_dmsg_addr, 0, KES_DMSG_BLOCK_SIZE);
        memcpy(kes_dmsg_header->magic, "autelan", KES_MAGIC_LEN);
        memcpy(kes_dmsg_header->isenable, "enable", KES_ISENABLE_LEN);
        is_first_dmsg = 1;
    }
    
    if(size > (KES_DMSG_BLOCK_SIZE - kes_dmsg_offset - KES_MEM_HEADER_LEN))
    {
        kes_dmsg_offset = 0;
        memset(kes_dmsg_print_addr,0,KES_DMSG_BLOCK_SIZE - KES_MEM_HEADER_LEN);
        return 0;
    }
    
    memcpy((kes_dmsg_print_addr + kes_dmsg_offset),buff,size);

    kes_dmsg_offset += size;

    return size;
}


static int loff;

static void *kes_dmsg_start(struct seq_file *seq, loff_t *pos)
{
    unsigned char *start = (unsigned char *)kes_dmsg_addr+ 0x10;
    loff=(*pos)*KES_MEM_SHOW_LEN;

    if(*pos >= dmsg_page_count)
    {
        *pos = 0;
        //memset(kes_dmsg_addr, 0, KES_DMSG_BLOCK_SIZE);
        return NULL;
    }
    else
        return (void *)(start+ (*pos) * KES_MEM_SHOW_LEN);
}


static void *kes_dmsg_next(struct seq_file *seq, void *v, loff_t *pos)
{
    void *ptr_next = NULL;

    ptr_next = (void *)((unsigned char *)v + KES_MEM_SHOW_LEN);
    loff = (*pos)*KES_MEM_SHOW_LEN;
    (*pos)++;
    
    return ptr_next;
}


static int kes_dmsg_show(struct seq_file *seq, void *v)
{
    int i = 0;
    void *pt = v;

    if(NULL == pt)
    {
        return -1;
    }

    for(i = 0; i < KES_MEM_SHOW_LEN; i++)
    { 
        if(((unsigned char *)pt + i) >= (kes_dmsg_addr+0x100000) || \
            (((unsigned char *)pt + i) < kes_dmsg_addr))
            break;
        seq_printf(seq, "%c", *((unsigned char *)pt + i));
    }

    return 0;
} 


static void  kes_dmsg_stop(struct seq_file *seq, void *v)
{
	return;
}


struct seq_operations kes_dmsg_seq_ops = {
	.start = kes_dmsg_start,
	.next  = kes_dmsg_next,
	.show  = kes_dmsg_show,
	.stop  = kes_dmsg_stop,
};


static int kes_dmsg_proc_open(struct inode *inode, struct file *file)
{
    int retval = -1;

    if(NULL == file)
    {
        printk(KERN_INFO "kes file pointer is NULL.\n");
        return retval;
    }

    retval = seq_open(file, &kes_dmsg_seq_ops);
    if(retval)
    {
        printk(KERN_INFO "kes cannot open seq_file.\n");
        remove_proc_entry(KES_DMSG_NAME, NULL);
    }

    return retval;
}

struct file_operations kes_dmsg_ops = {
	.owner   = THIS_MODULE,
	.open    = kes_dmsg_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private,
};


int kes_dmsg_init()
{
    int retval = 0;
    unsigned int pfn;
    struct page *page;
    void *vtl_addr;
    struct proc_dir_entry *kes_dmsg_entry  = NULL;
    struct proc_dir_entry *kes_dmsg_swtich_entry  = NULL;

    /* get kes_dmsg_addr */
    //pfn =((MEM_SIZE+1)<<20) >> PAGE_SHIFT;
    pfn = (TRAPS_START_ADDR + KES_TRAPS_BLOCK_SIZE + KES_DEBUG_BLOCK_SIZE) >> PAGE_SHIFT;
    page=pfn_to_page(pfn);
    if(page == NULL)
    {
        printk("get the wrong page \n");
        return -1;
    }
    vtl_addr = (void *)page_to_virt(page);
    kes_dmsg_addr = vtl_addr;
    printk("kes_dmsg_addr=%p,size = %dKB\n",kes_dmsg_addr,(KES_DMSG_BLOCK_SIZE / 1024));

    /* kes dmsg handle */
    kes_dmsg_header = (kes_mem_header_type *)kes_dmsg_addr;
    kes_dmsg_print_addr = kes_dmsg_addr + KES_MEM_HEADER_LEN;
    kes_dmsg_print_handle = print_msg_to_kes_dmsg;

    /* create kes dmsg proc file system */
    kes_dmsg_swtich_entry = proc_create(KES_DMSG_SWITCH_NAME,0666,NULL,&kes_dmsg_swtich_fops);
    if(!kes_dmsg_swtich_entry)
    {
        printk(KERN_INFO "kes create %s error.\n", KES_DMSG_SWITCH_NAME);
        remove_proc_entry(KES_DMSG_SWITCH_NAME, NULL);
        retval = -1;
    }

    kes_dmsg_entry = proc_create(KES_DMSG_NAME,0666,NULL,&kes_dmsg_ops);
    if(!kes_dmsg_entry)
    {
        printk(KERN_INFO "kes create %s error.\n", KES_DMSG_NAME);
        retval = -1;
    }
    
    return retval;
}


