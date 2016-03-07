/**********************************************************************  
FILE NAME : kes_traps.c
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

static char trapsbuf[CVT_BUF_MAX + 1] = {0};

unsigned char *kes_traps_addr = NULL;
unsigned char *kes_traps_print_addr = NULL;
kes_mem_header_type *kes_traps_header = NULL;

unsigned int kes_traps_offset = 0;

/********************************************************************** 
memory name : 
	kes_traps
Description : 
	kes traps ops
file open : 
	kes_traps_proc_open
file read : 
	none
file write :
	none
handle write : 
	print_msg_to_kes_traps
**********************************************************************/
int print_msg_to_kes_traps(const char * fmt,...)
{
    int msg_size = 0;
    int input_len = 0;
    static int is_first = 0;
    va_list args;
    static int traps_count = 0;
    char logbuf[CVT_BUF_MAX + 1] = {0};
    char tmpbuf[CVT_BUF_MAX + 1] = {0};
    int size = 0;

    /*initialize the kes mem and fill the header*/
    if(!is_first)
    {
        memset(kes_traps_addr, 0, KES_TRAPS_BLOCK_SIZE);
        memcpy(kes_traps_header->magic, "autelan", KES_MAGIC_LEN);
        memcpy(kes_traps_header->isenable, "enable", KES_ISENABLE_LEN);
        is_first = 1;
    }

    strcpy(logbuf, fmt);
    print_current_time(logbuf);
    input_len = do_percentm(trapsbuf, logbuf);

    size = (((KES_TRAPS_BLOCK_SIZE - KES_MEM_HEADER_LEN - kes_traps_offset) >= \
    (CVT_BUF_MAX + 1)) ?(CVT_BUF_MAX + 1):(KES_TRAPS_BLOCK_SIZE - KES_MEM_HEADER_LEN - kes_traps_offset));

    va_start(args, fmt);
    msg_size = vsnprintf(tmpbuf, size, trapsbuf, args);
    va_end(args);

    if(KES_TRAPS_COUNT == traps_count)
        traps_count = 0;

    if(msg_size > (KES_TRAPS_BLOCK_SIZE - KES_MEM_HEADER_LEN - kes_traps_offset- traps_count* (KES_TRAPS_BLOCK_SIZE / KES_TRAPS_COUNT)))
    {
        traps_count ++;
        kes_traps_offset = traps_count * (KES_TRAPS_BLOCK_SIZE / KES_TRAPS_COUNT);
        memcpy(kes_traps_print_addr + kes_traps_offset, "#*#*#BEGIN#*#*#",16);
        kes_traps_offset += 16;
    }
    
    memcpy((char *)(kes_traps_print_addr + kes_traps_offset),tmpbuf,msg_size);

    kes_traps_offset += msg_size;

    return msg_size;
}


static int loff;

static void *kes_traps_start(struct seq_file *seq, loff_t *pos)
{
    unsigned char *start = (unsigned char *)kes_traps_addr + 0x10;
    loff=(*pos)*KES_MEM_SHOW_LEN;

    if(*pos >= traps_page_count)
    {
        *pos = 0;
        return NULL;
    }
    else
        return (void *)(start + (*pos) * KES_MEM_SHOW_LEN);
}


static void *kes_traps_next(struct seq_file *seq, void *v, loff_t *pos)
{
    void *ptr_next = NULL;

    ptr_next = (void *)((unsigned char *)v + KES_MEM_SHOW_LEN);
    loff = (*pos)*KES_MEM_SHOW_LEN;
    (*pos)++;
    
    return ptr_next;
}


static int kes_traps_show(struct seq_file *seq, void *v)
{
    int i = 0;
    void *pt = v;

    if(NULL == pt)
    {
        printk(KERN_INFO "kes_traps_mem show data pointer NULL.\n");
        return -1;
    }

    for(i = 0; i < KES_MEM_SHOW_LEN; i++)  
        seq_printf(seq, "%c", *((unsigned char *)pt + i));

    return 0;
} 


static void  kes_traps_stop(struct seq_file *seq, void *v)
{
	return;
}


struct seq_operations kes_traps_seq_ops = {
    .start = kes_traps_start,
    .next  = kes_traps_next,
    .show  = kes_traps_show,
    .stop  = kes_traps_stop,
};


static int kes_traps_proc_open(struct inode *inode, struct file *file)
{
	int retval = -1;

	if(NULL == file)
	{
		printk(KERN_INFO "kes file pointer is NULL.\n");
		return retval;
	}

	retval = seq_open(file, &kes_traps_seq_ops);
	if(retval)
	{
		printk(KERN_INFO "kes cannot open seq_file.\n");
		remove_proc_entry(KES_TRAPS_NAME, NULL);
	}

	return retval;
}

struct file_operations kes_traps_ops = {
	.owner   = THIS_MODULE,
	.open    = kes_traps_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private,
};


/********************************************************************** 
memory name : 
	kes_traps_flag
Description : 
	kes traps flag ops
file open : 
	kes_traps_flag_proc_open
file read : 
	kes_traps_flag_proc_read
file write :
	kes_traps_flag_proc_write
handle write : 
	none
**********************************************************************/
static ssize_t kes_traps_flag_proc_write(struct file *flip, const char __user *buff, size_t len, loff_t *ppos)
{
    if(len >= KES_ISENABLE_LEN)
    {
        printk(KERN_INFO "kes flag buffer is full.\n");
        return -ENOSPC;
    }

    memset(kes_traps_header->isenable, 0, KES_ISENABLE_LEN);

    if(copy_from_user(kes_traps_header->isenable, buff, len))
    {
        printk(KERN_INFO "kes flag copy_from_user error.\n");
        return -EFAULT;
    }

    return len;
}


static int kes_traps_flag_proc_read(struct seq_file *m, void *v)
{
    unsigned char tmp[8] = {0};

    memcpy(tmp, kes_traps_header->isenable, KES_ISENABLE_LEN);
    seq_printf(m,"kes_flag = %s\n",tmp);
    
    return 0;
}


static int kes_traps_flag_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, kes_traps_flag_proc_read, NULL);
}


static const struct file_operations kes_traps_flag_fops = {
	.owner		= THIS_MODULE,
	.open		= kes_traps_flag_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= kes_traps_flag_proc_write,
};


int kes_traps_init()
{
    int retval = 0;
    unsigned int pfn;
    struct page *page;
    void *vtl_addr;

    struct proc_dir_entry *kes_traps_entry = NULL;
    struct proc_dir_entry *kes_traps_flag_entry = NULL;

    /* get kes_traps_addr */
    pfn = TRAPS_START_ADDR >> PAGE_SHIFT;
    page = pfn_to_page(pfn);
    if(page == NULL)
    {
        printk("get the wrong page\n");
        return -1;
    }
    vtl_addr = (void *)page_to_virt(page);
    kes_traps_addr = vtl_addr;
    printk("kes_traps_addr=%p,size = %dKB\n",kes_traps_addr,(KES_TRAPS_BLOCK_SIZE / 1024));

    /* kes traps handle */
    kes_traps_header = (kes_mem_header_type *)kes_traps_addr;
    kes_traps_print_addr = kes_traps_addr + KES_MEM_HEADER_LEN;
    kes_traps_print_handle = print_msg_to_kes_traps;

    /* create kes traps proc file system */
    kes_traps_entry = proc_create(KES_TRAPS_NAME,0666,NULL,&kes_traps_ops);
    if(!kes_traps_entry)
    {
        printk(KERN_INFO "kes create %s error.\n", KES_TRAPS_NAME);
        retval = -1;
    }

    kes_traps_flag_entry = proc_create(KES_FLAG_NAME,0666,NULL,&kes_traps_flag_fops);
    if(!kes_traps_flag_entry)
    {
        printk(KERN_INFO "kes create %s error.\n", KES_FLAG_NAME);
		remove_proc_entry(KES_FLAG_NAME, NULL);
        retval = -1;
    }

    return retval;
}

