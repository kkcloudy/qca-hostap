/**********************************************************************  
FILE NAME : kes_syslog.c
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

static char syslogbuf[CVT_BUF_MAX + 1] = {0};

unsigned char *kes_syslog_addr = NULL;

unsigned int kes_syslog_print_page = 0;
unsigned int kes_syslog_offset = 0;
unsigned int kes_syslog_page = 0;
unsigned int kes_syslog_page_offset = 0;
unsigned int kes_syslog_page_over = 0;

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
int print_msg_to_kes_syslog(const char * fmt,...)
{
    int msg_size = 0;
    int input_len = 0;
    char logbuf[CVT_BUF_MAX + 1] = {0};
    char tmpbuf[CVT_BUF_MAX + 1] = {0};  //czb
    static int is_first_debug = 0;
    va_list args;
    int size = 0;

    /*initialize the kes debug mem and fill the header*/
    if(!is_first_debug)
    {
        memset(kes_syslog_addr, 0, KES_SYSLOG_BLOCK_SIZE);
        is_first_debug = 1;
    }

    strcpy(logbuf, fmt);
    //print_current_time(logbuf);

    input_len = do_percentm(syslogbuf, logbuf);
    size = (((KES_SYSLOG_BLOCK_SIZE - kes_syslog_offset) >= \
        (CVT_BUF_MAX + 1)) ?(CVT_BUF_MAX + 1):(KES_SYSLOG_BLOCK_SIZE - kes_syslog_offset));
    va_start(args, fmt);
    msg_size = vsnprintf(tmpbuf, size, syslogbuf, args);
    va_end(args);

    /* calculation whether page offset exceeds KES_MEM_SHOW_LEN(4KB) */
    if(msg_size > (KES_MEM_SHOW_LEN - kes_syslog_page_offset))
    {
        /* calculation whether offset exceeds KES_SYSLOG_BLOCK_SIZE */
        if(msg_size > (KES_SYSLOG_BLOCK_SIZE - kes_syslog_offset))
        {
            kes_syslog_offset = 0;
            kes_syslog_page = 0;
            kes_syslog_page_offset = msg_size;
            /* KES_SYSLOG_BLOCK_SIZE is full, and need to writing from start addr*/
            kes_syslog_page_over = 1;
        }
        else
        {
            kes_syslog_page ++;
            kes_syslog_page_offset = kes_syslog_page_offset + msg_size - KES_MEM_SHOW_LEN; 
        }
        /* memset the next page region */
        memset(kes_syslog_addr + (kes_syslog_page * KES_MEM_SHOW_LEN), 0, KES_MEM_SHOW_LEN);
    }
    else
    {
        kes_syslog_page_offset += msg_size;
    }

    memcpy((char *)(kes_syslog_addr + kes_syslog_offset) ,tmpbuf ,msg_size);

    kes_syslog_offset += msg_size;

    return msg_size;
}

static int loff;

static void *kes_syslog_start(struct seq_file *seq, loff_t *pos)
{
    int oldest_page = 0;
    unsigned char *start;

    /* get the oldest page address and print content*/
    if(kes_syslog_page_over == 1)
    {
        oldest_page = kes_syslog_print_page + 1;
        start = (unsigned char *)(kes_syslog_addr + (oldest_page * KES_MEM_SHOW_LEN));
    }
    else
        start = (unsigned char *)kes_syslog_addr;
    
    loff=(*pos)*KES_MEM_SHOW_LEN;

    if(*pos >= syslog_page_count)
    {
        *pos = 0;
        return NULL;
    }
    else
    {
        if(kes_syslog_page_over == 1)
        {
            /* get syslog starting address and print content*/
            if((oldest_page + (*pos)) >= syslog_page_count)
            {
                start = (unsigned char *)kes_syslog_addr;
                return (void *)(start + (((*pos) + oldest_page - syslog_page_count) * KES_MEM_SHOW_LEN));
            }
        }
        
        return (void *)(start + ((*pos) * KES_MEM_SHOW_LEN));
    }
}


static void *kes_syslog_next(struct seq_file *seq, void *v, loff_t *pos)
{
    void *ptr_next = NULL;
    ptr_next = (void *)((unsigned char *)v + KES_MEM_SHOW_LEN);
    loff = (*pos)*KES_MEM_SHOW_LEN;
    (*pos)++;
    
    return ptr_next;
}

static int kes_syslog_show(struct seq_file *seq, void *v)
{
    int i = 0;
    int offset = 0;
    void *pt = v;
    int buff[KES_MEM_SHOW_LEN];

	if(NULL == pt)
	{
		printk(KERN_INFO "kes_debug_mem show data pointer NULL.\n");
		return -1;
	}

    for(i = 0; i < KES_MEM_SHOW_LEN; i++) 
        seq_printf(seq, "%c", *((unsigned char *)pt + i));

	return 0;
} 


static void  kes_syslog_stop(struct seq_file *seq, void *v)
{
	return;
}

struct seq_operations kes_syslog_seq_ops = {
	.start = kes_syslog_start,
	.next  = kes_syslog_next,
	.show  = kes_syslog_show,
	.stop  = kes_syslog_stop,
};


static int kes_syslog_proc_open(struct inode *inode, struct file *file)
{
    int retval = -1;

    /* get open tmp page in order to page increase*/
    if(kes_syslog_page_over == 1)
    {
        kes_syslog_print_page = kes_syslog_page;
    }

    if(NULL == file)
    {
        printk(KERN_INFO "kes file pointer is NULL.\n");
        return retval;
    }

    retval = seq_open(file, &kes_syslog_seq_ops);
    if(retval)
    {
        printk(KERN_INFO "kes cannot open seq_file.\n");
        remove_proc_entry(KES_DMSG_NAME, NULL);
    }

    return retval;
}


static ssize_t kes_syslog_write(struct file * filp, const char __user * buf, size_t count, loff_t * f_pos)
{
	char msg[CVT_BUF_MAX+1] = {0};
	ssize_t msg_size = 0;
	
	if(count > CVT_BUF_MAX+1)
        return -EFAULT;
    
	if(copy_from_user(msg, buf, count))
		return -EFAULT;
	
	msg_size = print_msg_to_kes_syslog(msg);
	return msg_size;
}


struct file_operations kes_syslog_fops = {
	.owner   = THIS_MODULE,
	.open    = kes_syslog_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private,
	.write	 = kes_syslog_write,
};

int kes_syslog_init()
{
    int retval = 0;
    unsigned int pfn;
    struct page *page;
    void *vtl_addr;
    struct proc_dir_entry *kes_syslog_entry  = NULL;

    /* get kes_syslog_addr */
    pfn = (TRAPS_START_ADDR + KES_TRAPS_BLOCK_SIZE + KES_DEBUG_BLOCK_SIZE + KES_DMSG_BLOCK_SIZE) >> PAGE_SHIFT;
    page=pfn_to_page(pfn);
    if(page == NULL)
    {
        printk("get the wrong page \n");
        return -1;
    }
    vtl_addr = (void *)page_to_virt(page);
    kes_syslog_addr = vtl_addr;
    printk("kes_syslog_addr=%p,size = %dKB\n",kes_syslog_addr,(KES_SYSLOG_BLOCK_SIZE / 1024));

    /* create kes syslog proc file system */
    kes_syslog_entry = proc_create(KES_SYSLOG_NAME,0666,NULL,&kes_syslog_fops);
    if(!kes_syslog_entry)
    {
        printk(KERN_INFO "kes create %s error.\n", KES_SYSLOG_NAME);
        remove_proc_entry(KES_SYSLOG_NAME, NULL);
        retval = -1;
    }


    return retval;
}

