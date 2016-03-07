#ifndef _KES_H 
#define _KES_H

#include <linux/version.h>


#define KES_FLAG_NAME           "kes_flag"
#define KES_TRAPS_NAME          "kes_traps"

#define KES_DMSG_NAME           "kes_dmsg"
#define KES_DMSG_SWITCH_NAME    "kes_dmsg_switch"

#define KES_DEBUG_NAME          "kes_debug"
#define KES_DEBUG_SWITCH_NAME   "kes_debug_switch"
#define KES_DEBUG_FLAG_NAME     "kes_debug_flag"

#define KES_SYSLOG_NAME         "kes_syslog"

#define KES_TRAPS_BLOCK_SIZE    128 * 1024
#define KES_DEBUG_BLOCK_SIZE    384 * 1024
#define KES_DMSG_BLOCK_SIZE     512 * 1024
#define KES_SYSLOG_BLOCK_SIZE   1 * 1024 * 1024

#define KES_MEM_BLOCK_SIZE      \
    (KES_DMSG_BLOCK_SIZE + KES_DEBUG_BLOCK_SIZE + KES_TRAPS_BLOCK_SIZE + KES_SYSLOG_BLOCK_SIZE)

#define KES_TRAPS_COUNT         32

#define CVT_BUF_MAX             1023
#define KES_MEM_HEADER_LEN      32
#define KES_PEOTECT_LEN         16
#define KES_MAGIC_LEN           8
#define KES_ISENABLE_LEN        8

#define KES_MEM_SHOW_LEN        PAGE_SIZE

#define traps_page_count        (KES_TRAPS_BLOCK_SIZE   / KES_MEM_SHOW_LEN)
#define debug_page_count        (KES_DEBUG_BLOCK_SIZE   / KES_MEM_SHOW_LEN)
#define dmsg_page_count         (KES_DMSG_BLOCK_SIZE    / KES_MEM_SHOW_LEN)
#define syslog_page_count       (KES_SYSLOG_BLOCK_SIZE  / KES_MEM_SHOW_LEN)


#define TRAPS_START_ADDR        (MEM_SIZE << 20)
#define page_to_virt(page)      ((((page) - mem_map) << PAGE_SHIFT) + PAGE_OFFSET)


extern unsigned long num_physpages;

#define   MEM_SIZE              \
    ((num_physpages << (PAGE_SHIFT - 10)) / 1024)      //auto get mem size


typedef struct
{
	unsigned char protect[KES_PEOTECT_LEN];
	unsigned char magic[KES_MAGIC_LEN];
	unsigned char isenable[KES_ISENABLE_LEN];
}kes_mem_header_type;


//extern int dump_msg_to_kes_mem(char *buff, int size );
//extern int print_msg_to_kes_traps(const char * fmt, ...);
//extern int print_msg_to_kes_debug(const char * fmt, ...);
//extern int print_msg_to_kes_dmsg(char *buff, int size );


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)

#define SECS_PER_HOUR	(60 * 60)
#define SECS_PER_DAY	(SECS_PER_HOUR * 24)
static const unsigned short __mon_yday[2][13] = {
	/* Normal years. */
	{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365},
	/* Leap years. */
	{0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366}
};

static int __isleap(long year)
{
	return (year) % 4 == 0 && ((year) % 100 != 0 || (year) % 400 == 0);
}

/* do a mathdiv for long type */
static long math_div(long a, long b)
{
	return a / b - (a % b < 0);
}

/* How many leap years between y1 and y2, y1 must less or equal to y2 */
static long leaps_between(long y1, long y2)
{
	long leaps1 = math_div(y1 - 1, 4) - math_div(y1 - 1, 100)
		+ math_div(y1 - 1, 400);
	long leaps2 = math_div(y2 - 1, 4) - math_div(y2 - 1, 100)
		+ math_div(y2 - 1, 400);
	return leaps2 - leaps1;
}

#endif

//extern int (*kes_mem_dump_handle)(char *buff, int size);
extern void (*print_current_time_handle)(char * buf);

extern int (*kes_traps_print_handle)(const char *fmt, ...);
extern int (*kes_dmsg_print_handle)(char *buff, int size);
extern int (*kes_debug_print_handle)(const char *fmt, ...);

extern void (*kes_debug_print_flag_handle)(const char *s);

void print_current_time(char * buf);
int do_percentm(char *obuf, const char *ibuf);

int kes_dmsg_init(void);
int kes_debug_init(void);
int kes_traps_init(void);
int kes_syslog_init(void);

#endif

