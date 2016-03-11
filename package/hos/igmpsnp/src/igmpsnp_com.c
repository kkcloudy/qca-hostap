/*********************************************************************************************
*			Copyright(c), 2008, Autelan Technology Co.,Ltd.
*						All Rights Reserved
*
**********************************************************************************************
$RCSfile:igmp_snoop_com.c
$Author: Rock
$Revision: 1.00
$Date:2008-3-8 09:12
***********************************************************************************************/
#include "igmpsnp_com.h"

timer_list igmp_timer_list;


/*读取配置文件的默认函数*/
void *def_func(struct cfg_element *cur,void *value)
{	
	return;
}


/*********************************增加定时器***************************/
/*******************************************************************************
 * add_timer
 *
 * DESCRIPTION:
 * 		add a new timer to the timer list  	
 *
 * INPUTS:
 * 		head - timelist head pointer
 *		new timer - pointer to created new timer
 *
 * OUTPUTS:
 *    	ptimer_id - the timer id which add to the timer list
 *
 * RETURNS:
 *		IGMPSNP_RETURN_CODE_OK - add success
 *		IGMPSNP_RETURN_CODE_NULL_PTR - the timerlist or new timer is null
 *		IGMPSNP_RETURN_CODE_OUT_RANGE - timer list is full
 * COMMENTS:
 *  
 ********************************************************************************/

int add_timer(timer_list *head, timer_element *new_timer, unsigned long *ptimer_id)
{
	int i,timer_id,flag;
	timer_element *tnext = NULL;
	timer_element *tprev = NULL;
	
	if( !head || !new_timer )
	{
		igmp_snp_syslog_err("add_timer:parameter error.\n");
		return IGMPSNP_RETURN_CODE_NULL_PTR;
	}
	timer_id = rand();
	while(head->lock)
		head->lock = 0;
	
	if( head->cnt >= (TIMER_LIST_MAX - 1) )
	{
		head->lock = 1;
		igmp_snp_syslog_err("add_timer:timer element too many.\n");
		return IGMPSNP_RETURN_CODE_OUT_RANGE;
	}
	flag = 1;
	do{
		tnext = head->first_timer;
		while(tnext)
		{
			if( tnext->id == timer_id )
			{
				timer_id = rand();
				break;
			}
			tnext = tnext->next;
		}
	}while(tnext);	/*timers assigned different timer_id with each other. */
	
	new_timer->id = timer_id;
	if( NULL != ptimer_id )
		*ptimer_id = timer_id;
	if( NULL == head->first_timer )
	{
		head->first_timer = new_timer;
		head->cnt = 1;
	}
	else
	{
		tnext = head->first_timer;
		tprev = head->first_timer;
		
		while(tnext->type > new_timer->type)/*type decrease */
		{
			tprev = tnext;
			tnext = tnext->next;
			if( NULL == tnext )
				break;
		}
		if( NULL == tnext )	/*链表尾*/
		{
			tprev->next = new_timer;
		}
		else
		{
			while( tnext->priority >= new_timer->priority )/*priority decrease*/
			{
				tprev = tnext;
				tnext = tnext->next;
				if( NULL == tnext )
					break;
			}
			tprev->next = new_timer;
			new_timer->next = tnext;
		}
		head->cnt++;
	}
	head->lock = 1;
	return IGMPSNP_RETURN_CODE_OK;
}


/*************************************建立定时器************************/
/*******************************************************************************
 * create_timer
 *
 * DESCRIPTION:
 * 		create a new timer add use pointer new timer point to it  	
 *
 * INPUTS:
 * 		type - the timer type (loop or noloop)
 *		pri - the timer priority in the timer list
 *		interval - the time value
 *		func -when the time is over to run the function
 *		data - the timer's data info
 *		datalen -data length
 *
 * OUTPUTS:
 *    	new_timer - the timer id which will be added to the timer list
 *
 * RETURNS:
 *		IGMPSNP_RETURN_CODE_OK - add success
 *		IGMPSNP_RETURN_CODE_NULL_PTR - the timerlist or new timer is null
 *		IGMPSNP_RETURN_CODE_OUT_RANGE - the type or priority out of the range
 *		IGMPSNP_RETURN_CODE_ALLOC_MEM_NULL - malloc memery for new timer fail
 *
 * COMMENTS:
 *  
 ********************************************************************************/
unsigned int create_timer
(	unsigned int type,
	unsigned int pri,
	unsigned long interval,
	void (*func)(timer_element *),
	void *data,
	unsigned int datalen,
	timer_element * new_timer )
{
	igmp_snp_syslog_dbg("START:create_timer\n");

	if( TIMER_TYPE_MAX < type )/*type = TIMER_TYPE_LOOP*/
	{
		igmp_snp_syslog_err("type error.\n");
		return IGMPSNP_RETURN_CODE_OUT_RANGE;
	}
	if( TIMER_PRIORI_HIGH < pri )/*pri = TIMER_PRIORI_NORMAL*/
	{
		igmp_snp_syslog_err("priority error.\n");
		return IGMPSNP_RETURN_CODE_OUT_RANGE;
	}
	if( NULL == func)
	{
		igmp_snp_syslog_err("handle function is not existence.\n");
		return IGMPSNP_RETURN_CODE_NULL_PTR;
	}
	
	new_timer = (timer_element *)malloc(sizeof(timer_element));
	if( NULL == new_timer )
	{
		igmp_snp_syslog_err("new_timer malloc memory failed.\n");
		return IGMPSNP_RETURN_CODE_ALLOC_MEM_NULL;
	}

	
	memset(new_timer,0,sizeof(timer_element));
	new_timer->next = NULL;
	new_timer->type = type;
	new_timer->priority = pri;
	new_timer->expires = interval;/*interval = 1*/
	new_timer->current = 0;
	new_timer->data = data;
	new_timer->datalen = datalen;
	new_timer->func = func;
	

	igmp_snp_syslog_dbg("END:create_timer\n");


	 if( IGMPSNP_RETURN_CODE_OK != add_timer(&igmp_timer_list,new_timer,NULL))
	{
		 igmp_snp_syslog_err("add timer failed.\n");
		 igmp_snp_syslog_dbg("END:init_igmp_snp_timer\n");
		 return IGMPSNP_RETURN_CODE_ADD_TIMER_ERROR;
	}
	
	return IGMPSNP_RETURN_CODE_OK;
}



/*********************************删除定时器***************************/
/*******************************************************************************
 * del_timer
 *
 * DESCRIPTION:
 * 		delete the timer in the timerlist based the timer_id  	
 *
 * INPUTS:
 * 		head - timelist head pointer
 *		timer_id - the timer id which will be delete
 *
 * OUTPUTS:
 *    	
 *
 * RETURNS:
 *		IGMPSNP_RETURN_CODE_OK - delete success
 *		-1 - the timerlist or timer id is null or can find timer based the timer id
 *
 * COMMENTS:
 *  
 ********************************************************************************/

int del_timer(timer_list *head, unsigned int timer_id)
{
    int ret = -1;
	timer_element *tnext = NULL;
	timer_element *tprev = NULL;
	
	if( !head || !timer_id )
	{
		igmp_snp_syslog_err("del_timer:parameter failed.\n");
		return ret;
	}
	
	while(head->lock)
		head->lock = 0;
		
	tnext = head->first_timer;
	tprev = head->first_timer;
	while(tnext)
	{
		if( tnext->id == timer_id )
		{
			if( tprev != tnext )
			{
				tprev->next = tnext->next;
			}
			else
			{
				head->first_timer = tnext->next;
			}
			head->lock = 1;
			free(tnext);
			head->cnt--;
			if( 0 == head->cnt )
				head->first_timer = NULL;
			return IGMPSNP_RETURN_CODE_OK;
		}
		tprev = tnext;
		tnext = tnext->next;
	}
	igmp_snp_syslog_err("del_timer:can not find timer.\n");
	return ret;
}

/**********************************删除所有定时器***************************/
/*******************************************************************************
 * del_all_timer
 *
 * DESCRIPTION:
 * 		delete all the timer in the timerlist  	
 *
 * INPUTS:
 * 		head - timelist head pointer
 *
 * OUTPUTS:
 *    	
 *
 * RETURNS:
 *		IGMPSNP_RETURN_CODE_OK - delete success
 *		IGMPSNP_RETURN_CODE_NULL_PTR - the pointer is null
 *
 * COMMENTS:
 *  
 ********************************************************************************/

int del_all_timer(timer_list *head)
{
	int id,cnt;
	
	if( !head )
	{
		igmp_snp_syslog_err("add_timer:parameter error.\n");
		return IGMPSNP_RETURN_CODE_NULL_PTR;
	}
	
	cnt = head->cnt;
	while(cnt)
	{
		if( NULL != head->first_timer )
		{
			id = head->first_timer->id;
			del_timer(head,id);
		}
		cnt--;
	}
	return IGMPSNP_RETURN_CODE_OK;
}


