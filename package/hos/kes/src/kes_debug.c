/**********************************************************************  
FILE NAME : kes_debug.c
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

static char debugbuf[CVT_BUF_MAX + 1] = {0};

unsigned char *kes_debug_addr = NULL;
unsigned char *kes_debug_print_addr = NULL;
kes_mem_header_type *kes_debug_header = NULL;

unsigned int kes_debug_offset = 0;
unsigned char kes_debug_switch[2] = {'0',0};
unsigned char kes_debug_flag[2] = {'0',0};

/********************************************************************** 
memory name : 
	kes_debug_switch
Description : 
	kes debug switch ops
file open : 
	kes_debug_switch_proc_open
file read : 
	kes_debug_switch_proc_read
file write :
	kes_debug_switch_proc_write
handle write : 
	none
**********************************************************************/
static ssize_t kes_debug_switch_proc_write(struct file *flip, const char __user *buff, size_t len, loff_t *ppos)
{
    if(len > 2) //just a character and a '\0' is enough
    {
        printk(KERN_INFO "kes_debug_switch buffer is full.\n");
        return -ENOSPC;
    }

    if(copy_from_user(kes_debug_switch, buff, 2))
    {
        printk(KERN_INFO "kes_debug_switch copy_from_user error.\n");
        return -EFAULT;
    }

    if(kes_debug_switch[0] == '0')
        memset(kes_debug_addr, 0, KES_DEBUG_BLOCK_SIZE);

    kes_debug_switch[0] = '1';

    return len;
}


static int kes_debug_switch_proc_read(struct seq_file *m, void *v)
{
    unsigned char tmp[8] = {0};
    memcpy(tmp, kes_debug_switch, 1);
    
    seq_printf(m,"kes_debug_switch = %s\n",tmp);
    return 0;
}


static int kes_debug_switch_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, kes_debug_switch_proc_read, NULL);
}


static const struct file_operations kes_debug_swtich_fops = {
	.owner		= THIS_MODULE,
	.open		= kes_debug_switch_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= kes_debug_switch_proc_write,
};


/********************************************************************** 
memory name : 
	kes_debug_flag
Description : 
	kes debug flag ops
file open : 
	kes_debug_flag_proc_open
file read : 
	kes_debug_flag_proc_read
file write :
	kes_debug_flag_proc_write
handle write : 
	print_flag_to_kes_debug
**********************************************************************/
static ssize_t kes_debug_flag_proc_write(struct file *flip, const char __user *buff, size_t len, loff_t *ppos)
{
    if(len > 2) //just a character and a '\0' is enough
    {
        printk(KERN_INFO "kes_debug_flag buffer is full.\n");
        return -ENOSPC;
    }

    if(copy_from_user(kes_debug_flag, buff, 2))
    {
        printk(KERN_INFO "kes_debug_switch copy_from_user error.\n");
        return -EFAULT;
    }
    
    memcpy(&kes_debug_header->isenable[6],kes_debug_flag,1);

    return len;
}


static int kes_debug_flag_proc_read(struct seq_file *m, void *v)
{
    unsigned char tmp[2] = {0};
    
    kes_debug_flag[0] = kes_debug_header->isenable[6];
    memcpy(tmp, kes_debug_flag, 1);
    
    seq_printf(m,"kes_debug_flag = %s\n",tmp);
    
    return 0;
}


static int kes_debug_flag_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, kes_debug_flag_proc_read, NULL);
}


void print_flag_to_kes_debug(const char *s )
{
    if(s == NULL)
        return;
    memcpy(&kes_debug_header->isenable[6],s,1);
}


static const struct file_operations kes_debug_flag_fops = {
	.owner		= THIS_MODULE,
	.open		= kes_debug_flag_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= kes_debug_flag_proc_write,
};


/********************************************************************** 
memory name : 
	kes_debug
Description : 
	kes debug ops
file open : 
	kes_debug_proc_open
file read : 
	none
file write :
	kes_debug_write
handle write : 
	print_msg_to_kes_debug
**********************************************************************/
int print_msg_to_kes_debug(const char * fmt,...)
{
    int msg_size = 0;
    int input_len = 0;
    char logbuf[CVT_BUF_MAX + 1] = {0};
    char tmpbuf[CVT_BUF_MAX + 1] = {0};  //czb
    static int is_first_debug = 0;
    va_list args;
    int size = 0;

    if('1' != kes_debug_switch[0])
    {
        return msg_size;
    }
    
    /*initialize the kes debug mem and fill the header*/
    if(!is_first_debug)
    {
        memset(kes_debug_addr, 0, KES_DEBUG_BLOCK_SIZE);
        memcpy(kes_debug_header->magic, "autelan", KES_MAGIC_LEN);
        memcpy(kes_debug_header->isenable, "enable0", KES_ISENABLE_LEN);
        is_first_debug = 1;
    }

    strcpy(logbuf, fmt);
    print_current_time(logbuf);

    input_len = do_percentm(debugbuf, logbuf);
    size = (((KES_DEBUG_BLOCK_SIZE - KES_MEM_HEADER_LEN - kes_debug_offset) >= \
        (CVT_BUF_MAX + 1)) ?(CVT_BUF_MAX + 1):(KES_DEBUG_BLOCK_SIZE - KES_MEM_HEADER_LEN - kes_debug_offset));
    va_start(args, fmt);
    msg_size = vsnprintf(tmpbuf, size, debugbuf, args);
    va_end(args);

    if(msg_size > (KES_DEBUG_BLOCK_SIZE - KES_MEM_HEADER_LEN - kes_debug_offset))
    {
        memset(kes_debug_print_addr,0,KES_DEBUG_BLOCK_SIZE-KES_MEM_HEADER_LEN);
        kes_debug_offset = 0;
        return 0;
    }
    
    memcpy((char *)(kes_debug_print_addr + kes_debug_offset) ,tmpbuf ,msg_size);

    kes_debug_offset += msg_size;

    return msg_size;
}


static int loff;

static void *kes_debug_start(struct seq_file *seq, loff_t *pos)
{
    unsigned char *start = (unsigned char *)kes_debug_addr+ 0x10;
    loff=(*pos)*KES_MEM_SHOW_LEN;
    if(*pos >= debug_page_count)
    {
        *pos = 0;
        //memset(kes_debug_addr, 0, KES_DEBUG_BLOCK_SIZE);
        return NULL;
    }
    else
        return (void *)(start+ (*pos) * KES_MEM_SHOW_LEN);
}


static void *kes_debug_next(struct seq_file *seq, void *v, loff_t *pos)
{
    void *ptr_next = NULL;

    ptr_next = (void *)((unsigned char *)v + KES_MEM_SHOW_LEN);
    loff = (*pos)*KES_MEM_SHOW_LEN;
    (*pos)++;
    
    return ptr_next;
}


static int kes_debug_show(struct seq_file *seq, void *v)
{
    int i = 0;
    void *pt = v;
 
	if(NULL == pt)
	{
		printk(KERN_INFO "kes_debug_mem show data pointer NULL.\n");
		return -1;
	}

    for(i = 0; i < KES_MEM_SHOW_LEN; i++) 
        seq_printf(seq, "%c", *((unsigned char *)pt + i));

	return 0;
} 


static void kes_debug_stop(struct seq_file *seq, void *v)
{
	return;
}


struct seq_operations kes_debug_seq_ops = {
	.start = kes_debug_start,
	.next  = kes_debug_next,
	.show  = kes_debug_show,
	.stop  = kes_debug_stop,
};


static int kes_debug_proc_open(struct inode *inode, struct file *file)
{
	int retval = -1;

	if(NULL == file)
	{
		printk(KERN_INFO "kes file pointer is NULL.\n");
		return retval;
	}

	retval = seq_open(file, &kes_debug_seq_ops);
	if(retval)
	{
		printk(KERN_INFO "kes cannot open seq_file.\n");
		remove_proc_entry(KES_DEBUG_NAME, NULL);
	}

	return retval;
}


static ssize_t kes_debug_write(struct file * filp, const char __user * buf, size_t count, loff_t * f_pos)
{
	char msg[CVT_BUF_MAX+1] = {0};
	ssize_t msg_size = 0;
	
	if(count > CVT_BUF_MAX+1)
        return -EFAULT;
    
	if(copy_from_user(msg, buf, count))
		return -EFAULT;
	
	msg_size = print_msg_to_kes_debug(msg);
	return msg_size;
}



struct file_operations kes_debug_ops = {
	.owner   = THIS_MODULE,
	.open    = kes_debug_proc_open,
	.read    = seq_read,
	.write   = kes_debug_write,
	.llseek  = seq_lseek,
	.release = seq_release_private,
};


int kes_debug_init()
{
    int retval = 0;
    unsigned int pfn;
    struct page *page;
    void *vtl_addr;

    struct proc_dir_entry *kes_debug_entry = NULL;
    struct proc_dir_entry *kes_debug_flag_entry  = NULL;
    struct proc_dir_entry *kes_debug_swtich_entry  = NULL;

    /* get kes_debug_addr */
    pfn = (TRAPS_START_ADDR + KES_TRAPS_BLOCK_SIZE) >> PAGE_SHIFT;
    page = pfn_to_page(pfn);
    if(page == NULL)
    {
        printk("get the wrong page \n");
        return -1;
    }
    vtl_addr = (void *)page_to_virt(page);
    kes_debug_addr = vtl_addr;
    printk("kes_debug_addr=%p,size = %dKB\n",kes_debug_addr,(KES_DEBUG_BLOCK_SIZE / 1024));

    /* kes debug handle */
    kes_debug_header = (kes_mem_header_type *)kes_debug_addr;
    kes_debug_print_addr = kes_debug_addr + KES_MEM_HEADER_LEN;
    kes_debug_print_handle = print_msg_to_kes_debug;
    kes_debug_print_flag_handle = print_flag_to_kes_debug;

    /* create kes debug proc file system */
    kes_debug_swtich_entry = proc_create(KES_DEBUG_SWITCH_NAME,0666,NULL,&kes_debug_swtich_fops);
    if(!kes_debug_swtich_entry)
    {
        printk(KERN_INFO "kes create %s error.\n", KES_DEBUG_SWITCH_NAME);
        remove_proc_entry(KES_DEBUG_SWITCH_NAME, NULL);
        retval = -1;
    }

    kes_debug_flag_entry = proc_create(KES_DEBUG_FLAG_NAME,0666,NULL,&kes_debug_flag_fops);
    if(!kes_debug_flag_entry)
    {
        printk(KERN_INFO "kes create %s error.\n", KES_DEBUG_FLAG_NAME);
        remove_proc_entry(KES_DEBUG_FLAG_NAME, NULL);
        retval = -1;
    }

    kes_debug_entry = proc_create(KES_DEBUG_NAME,0666,NULL,&kes_debug_ops);
    if(!kes_debug_entry)
    {
        printk(KERN_INFO "kes create %s error.\n", KES_DEBUG_NAME);
        retval = -1;
    }

    return retval;
}

