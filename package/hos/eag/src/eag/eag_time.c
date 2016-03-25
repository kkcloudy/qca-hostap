
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include "eag_log.h"
#include "eag_errcode.h"
#include "eag_util.h"
#include "eag_time.h"
#include "eag_conf.h"


/*
* 为了防止时间突变，建立了一个相对时间的处理。
*如果你调用时间是为了计算时间差，建议用相对时间处理。
*如果你是为了获得当前的时间点，就需要用本身的函数。
*/
#define MAX_SECONDS_UPGREADE_PER_CALL	10

/* Struct timeval's tv_usec one second value.  */
#define TIMER_SECOND_MICRO 1000000L

static struct timeval eag_time ={0};
static struct timeval tv_prev;





int 
eag_time_set_time(struct timeval *time)
{
	if( NULL == time ){
		eag_log_err( "eag_time_set_time input param error!" );
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	eag_log_info( "eag_time_set_time be called set time to tv_sec:%lu tv_usec:%lu",
					time->tv_sec, time->tv_usec );
	eag_time.tv_sec = time->tv_sec;
	eag_time.tv_usec = time->tv_usec;
	return EAG_RETURN_OK;
}
#if 0
int
eag_time_set_backup_type(eag_hansi_t* eaghansi)
{
	time_res = eag_hansi_register_backup_type(eaghansi,EAG_TIME_SYN_TYPE,
	 								NULL,set_eag_time);
	if(NULL == time_res){
		return EAG_ERR_REG_ERR;
	}
	return EAG_RETURN_OK;
}
int 
master_backup_eag_time(eag_hansi_t * eaghansi)
{
	unsigned long datalen = 0;
	datalen = (unsigned long)sizeof(struct timeval);
	backup_pkg_t data_time;
	data_time.type = EAG_TIME_SYN_TYPE;
	data_time.pkglen = datalen;
	memcpy(data_time.data,&eag_time,datalen);
	eag_hansi_queue_data(eaghansi,time_res,&(data_time.data),datalen);		 
	return EAG_RETURN_OK;	
}

#endif


int
eag_time_init(){
	int ret;
	ret = gettimeofday(&tv_prev,NULL);
	eag_time = tv_prev;
	return ret;
}

#if 0
void
eag_time_get_relativetime( struct timeval *tp )
{
	*tp = eag_time;
	return;
}
#endif

int 
eag_time_gettimeofday(struct timeval *tp, void *tzp)
{
	struct timeval tv_now={0};
	struct timeval diff;
	int ret;

	ret = gettimeofday(&tv_now,tzp);

	if( ret != 0 ){
		eag_log_err("eag_time_gettimeofday gettimeofday error!");
		return ret;
	}	

	if (timeval_cmp (tv_now, tv_prev) < 0){
		eag_log_warning("eag_time_gettimeofday get time litter "\
						"than prev  %lu! system time be changed!", 
						(unsigned long)(tv_prev.tv_sec - tv_now.tv_sec) );		
		eag_time.tv_sec++;
		eag_time.tv_usec = 0;
	}
	else{
		diff = timeval_subtract(tv_now, tv_prev);
#ifdef MAX_SECONDS_UPGREADE_PER_CALL
		if( diff.tv_sec > MAX_SECONDS_UPGREADE_PER_CALL ){
			eag_log_warning("eag_time_gettimeofday get time larger "\
							"than prev %lu! system time may be change!", 
							(unsigned long)(tv_now.tv_sec - tv_prev.tv_sec) );
			eag_time.tv_sec ++;
			eag_time.tv_usec = 0;
			eag_time = timeval_adjust(eag_time);
		}else
#endif
		{
			eag_time.tv_sec += diff.tv_sec;
			eag_time.tv_usec += diff.tv_usec;
			eag_time = timeval_adjust(eag_time);
		}
	}
	tv_prev = tv_now;
	*tp = eag_time;

	return ret;
}

/* Adjust so that tv_usec is in the range [0,TIMER_SECOND_MICRO).
   And change negative values to 0. */
struct timeval
timeval_adjust(struct timeval a)
{
	while (a.tv_usec >= TIMER_SECOND_MICRO) {
		a.tv_usec -= TIMER_SECOND_MICRO;
		a.tv_sec++;
	}

	while (a.tv_usec < 0) {
		a.tv_usec += TIMER_SECOND_MICRO;
		a.tv_sec--;
	}

	if (a.tv_sec < 0) {
		/* Change negative timeouts to 0. */
		a.tv_sec = a.tv_usec = 0;
	}

	return a;
}

struct timeval
timeval_subtract(struct timeval a, struct timeval b)
{
	struct timeval ret;

	ret.tv_usec = a.tv_usec - b.tv_usec;
	ret.tv_sec = a.tv_sec - b.tv_sec;

	return timeval_adjust(ret);
}

long
timeval_cmp(struct timeval a, struct timeval b)
{
	return (a.tv_sec == b.tv_sec
		? a.tv_usec - b.tv_usec : a.tv_sec - b.tv_sec);
}

unsigned long
timeval_elapsed(struct timeval a, struct timeval b)
{
	return (((a.tv_sec - b.tv_sec) * TIMER_SECOND_MICRO)
		+ (a.tv_usec - b.tv_usec));
}


