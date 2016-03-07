/**********************************************************************  
FILE NAME : kes_main.c
Author : libing
Version : V1.0
Date : 201109013 
Description : 

Dependence :
	
Others : 
	
Function List :
7.do_percentm()
6.time_to_tm()
5.dump_msg_to_kes_mem()
4.kes_mem_addr_get()
3.kes_proc_init()
2.kes_init()
1.kes_exit()

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


/* Find %m in the input string and substitute an error message string. */
int do_percentm(char *obuf, const char *ibuf)
{
    const char *s = ibuf;
    char *p = obuf;
    int infmt = 0;
    const char *m;
    int len = 0;

    while (*s) 
    {
        if (infmt)
        {
            if (*s == 'm') 
            {		
                m = "<format error>";
                len += strlen (m);
                
                if (len > CVT_BUF_MAX)
                    goto out;
                
                strcpy (p - 1, m);
                p += strlen (p);
                ++s;
            } 
            else 
            {
                if (++len > CVT_BUF_MAX)
                    goto out;
                
                *p++ = *s++;
            }
            infmt = 0;
        }
        else
        {
            if (*s == '%')
                infmt = 1;
            
            if (++len > CVT_BUF_MAX)
                goto out;
            
            *p++ = *s++;
        }
    }
out:
    *p = 0;
    
    return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) 
extern void time_to_tm(time_t totalsecs, int offset, struct tm *result);
#else
static void time_to_tm(time_t totalsecs, int offset, struct tm *result)
{
	long days, rem, y;
	const unsigned short *ip;

	days = totalsecs / SECS_PER_DAY;
	rem = totalsecs % SECS_PER_DAY;
	rem += offset;
	while (rem < 0) {
		rem += SECS_PER_DAY;
		--days;
	}
	while (rem >= SECS_PER_DAY) {
		rem -= SECS_PER_DAY;
		++days;
	}

	result->tm_hour = rem / SECS_PER_HOUR;
	rem %= SECS_PER_HOUR;
	result->tm_min = rem / 60;
	result->tm_sec = rem % 60;

	/* January 1, 1970 was a Thursday. */
	result->tm_wday = (4 + days) % 7;
	if (result->tm_wday < 0)
		result->tm_wday += 7;

	y = 1970;

	while (days < 0 || days >= (__isleap(y) ? 366 : 365)) {
		/* Guess a corrected year, assuming 365 days per year. */
		long yg = y + math_div(days, 365);

		/* Adjust DAYS and Y to match the guessed year. */
		days -= (yg - y) * 365 + leaps_between(y, yg);
		y = yg;
	}

	result->tm_year = y - 1900;

	result->tm_yday = days;

	ip = __mon_yday[__isleap(y)];
	for (y = 11; days < ip[y]; y--)
		continue;
	days -= ip[y];

	result->tm_mon = y;
	result->tm_mday = days + 1;
}
#endif


void print_current_time(char * buf)
{
    struct timeval tv;
    struct tm tm;
    int len = 0;

    len = strlen(buf);
    do_gettimeofday(&tv);
    time_to_tm(tv.tv_sec, 480, &tm);
    if(buf[len - 1] == '\n')
    {
        sprintf(&buf[len - 1], "[%ld-%d-%d %d:%d:%d]\n",tm.tm_year+1900, \
            tm.tm_mon+1, tm.tm_mday,tm.tm_hour, tm.tm_min, tm.tm_sec);
    }
    
    return;
}

#if 0
/********************************************************************** 
Function : 
	dump_msg_to_kes_mem
Description : 
	dump message to the kes mem
Input : 
	message buffer and size
Output : 
	none
Return :
	successfully print message length 
Others : 
	none
**********************************************************************/
int dump_msg_to_kes_mem(char *buff, int size )
{
    if(NULL == buff)
    {
        printk(KERN_INFO "kes input buffer pointer is NULL.\n");
        return 0;
    }

    if(size > (KES_TRAPS_BLOCK_SIZE - kes_traps_offset - KES_MEM_HEADER_LEN))
    {
        kes_traps_offset = 0;
        return 0;
    }

    memcpy((kes_traps_addr + kes_traps_offset + KES_MEM_HEADER_LEN), buff, size);
    kes_traps_offset = kes_traps_offset + size;

    return size;
}


/********************************************************************** 
Function : 
	kes_mem_addr_get
Description : 
	get kes mem the uboot alloced
Input : 
	void
Output : 
	kes_mem_addr
Return :
	kes_mem pointer
Others : 
	none
**********************************************************************/
static unsigned char *kes_mem_addr_get(void)
{   
    unsigned int pfn;
    struct page *page;
    void *vtl_addr;

    /* kes_traps_addr */
    pfn = TRAPS_START_ADDR >> PAGE_SHIFT;
    page = pfn_to_page(pfn);
    if(page == NULL)
    {
        printk("get the wrong page\n");
        return NULL;
    }
    vtl_addr = (void *)page_to_virt(page);
    kes_traps_addr = vtl_addr;
    printk("kes_traps_addr=%p,%s,%d\n",kes_traps_addr,__func__,__LINE__);

    /* kes_debug_addr */
    pfn = (TRAPS_START_ADDR + KES_TRAPS_BLOCK_SIZE) >> PAGE_SHIFT;
    page = pfn_to_page(pfn);
    if(page == NULL)
    {
        printk("get the wrong page \n");
        return NULL;
    }
    vtl_addr = (void *)page_to_virt(page);
    kes_debug_addr = vtl_addr;
    printk("kes_debug_addr=%p,%s,%d\n",kes_debug_addr,__func__,__LINE__);

    /* kes_dmsg_addr */
    //pfn =((MEM_SIZE+1)<<20) >> PAGE_SHIFT;
    pfn = (TRAPS_START_ADDR + KES_TRAPS_BLOCK_SIZE + KES_DEBUG_BLOCK_SIZE) >> PAGE_SHIFT;
    page=pfn_to_page(pfn);
    if(page == NULL)
    {
        printk("get the wrong page \n");
        return NULL;
    }
    vtl_addr = (void *)page_to_virt(page);
    kes_dmsg_addr = vtl_addr;
    printk("kes_dmsg_addr=%p,%s,%d\n",kes_dmsg_addr,__func__,__LINE__);

    return kes_dmsg_addr;
}
#endif

extern char *saved_command_line;

static int __init kes_init(void)
{
    char *pargs = NULL;
    char *pmem = NULL;
    long unsigned int mem = 0;
    unsigned int pos = 0;
    
    pargs = strstr(saved_command_line, "ramdisk_size");
    if(pargs == NULL)
    {
        return -1;
    }
    
    pmem = strstr(pargs,"=");
    if(pmem == NULL)
    {
        return -1;
    }
    
    pmem++;

    while(((pos =(*pmem - 0x30))>= 0) && (pos <= 9))
    {
        mem *=10;
        mem += pos;
        pmem++;
    }

    printk("%s memory_size = %luM, phy_mem = %luM\n",__func__,MEM_SIZE,mem);

    if(((mem - MEM_SIZE) * 1024) != (KES_MEM_BLOCK_SIZE / 1024))
    {
        printk("kes memory size error!\n");
        return -1;
    }

    if(kes_traps_init() != 0)
    {
        printk("kes traps init failed!\n");
        return -1;
    }

    if(kes_debug_init() != 0)
    {
        printk("kes debug init failed!\n");
        return -1;
    }

    if(kes_dmsg_init() != 0)
    {
        printk("kes dmsg init failed!\n");
        return -1;
    }

    if(kes_syslog_init() != 0)
    {
        printk("kes syslog init failed!\n");
        return -1;
    }

    //kes_mem_dump_handle = dump_msg_to_kes_mem;
    print_current_time_handle = print_current_time;

    printk(KERN_INFO "kes module loaded.\n");
    
	return 0;
}


static void __exit kes_exit(void)
{
    //kes_mem_dump_handle = NULL;
    print_current_time_handle = NULL;

    kes_traps_print_handle = NULL;
    kes_dmsg_print_handle = NULL;
    kes_debug_print_handle = NULL;
    kes_debug_print_flag_handle = NULL;

    remove_proc_entry(KES_DMSG_NAME, NULL);
    remove_proc_entry(KES_DEBUG_NAME, NULL);
    remove_proc_entry(KES_TRAPS_NAME, NULL);
    remove_proc_entry(KES_FLAG_NAME, NULL);
    remove_proc_entry(KES_DMSG_SWITCH_NAME, NULL);
    remove_proc_entry(KES_DEBUG_SWITCH_NAME, NULL);
    remove_proc_entry(KES_DEBUG_FLAG_NAME, NULL);

    printk(KERN_INFO "kes module unloaded.\n");
}


module_init(kes_init);
module_exit(kes_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("<libing@autelan.com>");
MODULE_DESCRIPTION("Kernel Exception Saver Module");

