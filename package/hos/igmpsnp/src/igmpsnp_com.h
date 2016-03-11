/*********************************************************************************************
*			Copyright(c), 2008, Autelan Technology Co.,Ltd.
*						All Rights Reserved
*
**********************************************************************************************
$RCSfile:igmp_snoop_com.c
$Author: Rock
$Revision: 1.00
$Date:2008-3-8 11:11
***********************************************************************************************/
#ifndef __IGMPSNP_COM_H__
#define __IGMPSNP_COM_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <pthread.h>


/* IGMP-SNOOPING branch */
#define IGMPSNP_RETURN_CODE_BASE                        (0x80000)                                                       /* return code base  */
#define IGMPSNP_RETURN_CODE_OK                          (IGMPSNP_RETURN_CODE_BASE)              /* success   */
#define IGMPSNP_RETURN_CODE_ERROR                       (IGMPSNP_RETURN_CODE_BASE + 0x1)        /* error     */
#define IGMPSNP_RETURN_CODE_ALREADY_SET                 (IGMPSNP_RETURN_CODE_BASE + 0x2)        /* already been setted */
#define IGMPSNP_RETURN_CODE_OUT_RANGE                   (IGMPSNP_RETURN_CODE_BASE + 0x3)        /* timer value or count out of range  */
#define IGMPSNP_RETURN_CODE_STA_NOT_EXIST              	(IGMPSNP_RETURN_CODE_BASE + 0x4)        /* stauib not exixt   */
#define IGMPSNP_RETURN_CODE_GROUP_NOTEXIST              (IGMPSNP_RETURN_CODE_BASE + 0x5)       /* multicast group not exist */
#define IGMPSNP_RETURN_CODE_ALLOC_MEM_NULL              (IGMPSNP_RETURN_CODE_BASE + 0x6)       /* alloc memory null   */
#define IGMPSNP_RETURN_CODE_NULL_PTR                    (IGMPSNP_RETURN_CODE_BASE + 0x7)       /* parameter pointer is null  */
#define IGMPSNP_RETURN_CODE_CREATE_TIMER_ERROR			(IGMPSNP_RETURN_CODE_BASE + 0x8)       /* create timer failed  */
#define IGMPSNP_RETURN_CODE_ADD_TIMER_ERROR             (IGMPSNP_RETURN_CODE_BASE + 0x9)       /* add timer failed  */




struct cfg_element{	
	char	*str;		/*string*/	
	int		min;	
	int		max;	
	int		def_value;	
	void 	(*func)(struct cfg_element *cur,void *value);	/*callback function*/
};

/********************************** timer structure****************************************/
typedef struct timer_element_s{
	struct timer_element_s	*next;
	unsigned int	id;
	unsigned int	type;
	unsigned int	priority;
	unsigned long	expires;
	unsigned long	current;
	void			*data;
	unsigned int 	datalen;
	void			(*func)(struct timer_element_s *);
}timer_element;

typedef struct timer_list_s{
	timer_element *first_timer;
	unsigned int	cnt;
	unsigned int	lock;
}timer_list;


#define	TIMER_TYPE_MIN	0
#define TIMER_TYPE_LOOP	1
#define TIMER_TYPE_NOLOOP	2
#define TIMER_TYPE_MAX	10

#define TIMER_PRIORI_LOW	0
#define TIMER_PRIORI_NORMAL	1
#define TIMER_PRIORI_HIGH	2

#define TIMER_LIST_MAX	256


timer_list igmp_timer_list;

extern unsigned int create_timer(unsigned int type,unsigned int pri,
				unsigned long interval,void (*func)(timer_element *),
				void *data,unsigned int datalen,timer_element  *new_timer);
extern int add_timer(timer_list *head, timer_element *new_timer, unsigned long *ptimer_id);
extern int del_timer(timer_list *head, unsigned int timer_id);
extern int del_all_timer(timer_list *head);


#ifdef __cplusplus
}
#endif

#endif

