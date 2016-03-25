/*******************************************************************************
Copyright (C) Autelan Technology


This software file is owned and distributed by Autelan Technology 
********************************************************************************


THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
********************************************************************************
* portal_ha.c
*
*
* CREATOR:
* autelan.software.xxx. team
*
* DESCRIPTION:
* xxx module main routine
*
*
*******************************************************************************/

/* eag_log.h */
#ifndef _EAG_LOG_H
#define _EAG_LOG_H
#include <syslog.h>

//#ifdef  __cplusplus
//extern "C" {
//#endif
#define EAG_DAEMON_LOG_CLOSE				(0)				/* daemon log is close	*/
#define EAG_DAEMON_LOG_OPEN				(1)				/* daemon log is open	*/

/*syslog  level*/
#define LOG_EMERG_MASK			(LOG_MASK(LOG_EMERG))
#define LOG_ALERT_MASK			(LOG_MASK(LOG_ALERT))
#define LOG_CRIT_MASK			(LOG_MASK(LOG_CRIT))
#define LOG_ERR_MASK			(LOG_MASK(LOG_ERR))
#define LOG_WARNING_MASK		(LOG_MASK(LOG_WARNING))
#define LOG_NOTICE_MASK			(LOG_MASK(LOG_NOTICE))
#define LOG_INFO_MASK			(LOG_MASK(LOG_INFO))
#define LOG_DEBUG_MASK			(LOG_MASK(LOG_DEBUG))
#define LOG_USER_MASK			(LOG_MASK(LOG_USER))

#define LOG_AT_LEAST_ALERT		(LOG_EMERG_MASK|LOG_ALERT_MASK)
#define LOG_AT_LEAST_CRIT		(LOG_AT_LEAST_ALERT|LOG_CRIT_MASK)
#define LOG_AT_LEAST_ERR		(LOG_AT_LEAST_CRIT|LOG_ERR_MASK)
#define LOG_AT_LEAST_WARNING	(LOG_AT_LEAST_ERR|LOG_WARNING_MASK)
#define LOG_AT_LEAST_NOTICE		(LOG_AT_LEAST_WARNING|LOG_NOTICE_MASK)
#define LOG_AT_LEAST_INFO		(LOG_AT_LEAST_NOTICE|LOG_INFO_MASK)
#define LOG_AT_LEAST_DEBUG		(LOG_AT_LEAST_INFO|LOG_DEBUG_MASK)
#define LOG_AT_LEAST_USER		(LOG_AT_LEAST_DEBUG|LOG_USER_MASK)

/* eag syslog flag */
extern unsigned int eag_daemon_log_open;
extern unsigned int eag_log_level;
extern char STR_EAG[32];
extern int user_log_switch;
extern int autelan_log_switch;
extern int henan_log_switch;

int 
eag_log_init( char *daemon );
int
eag_log_uninit();
void 
eag_log_set_level(int level);
int 
eag_log_add_filter(char *filter);
int 
eag_log_del_filter(char *filter);
int 
eag_log_is_filter_register(const char *match);
int
eag_set_user_log(int status);
int
eag_set_log_format(int key, int status);
int 
eag_log_set_debug_value(unsigned int val_mask);
int 
eag_log_set_no_debug_value(unsigned int val_mask);
void 
eag_log_get_openlog_name(char *daemon);
int 
is_print_log(int level);

const char *
safe_strerror(int errnum);

extern int log_forward;

#if 0

#define SYSLOG(level,fmt,args...) if(log_forward){printf("file:%s line:%d   "fmt,__FILE__,__LINE__, ##args );printf("\n");} \
									else syslog(level,fmt, ##args )

#define eag_log_syslog( level, match, fmt, args... ) \
			if( EAG_TRUE == eag_log_is_filter_register(match) ) \
			{	\
				if(log_forward) {printf("file:%s line:%d   "fmt, __FILE__,__LINE__, ## args);printf("\n");} \
				else syslog( level, "file:%s line:%d   "fmt, __FILE__,__LINE__, ## args ); \
			}

#else
#define SYSLOG(level,fmt,args...) \
			do{ \
				if (log_forward){printf(fmt, ##args );printf("\n");} \
				else syslog(level,"%s:%d:"fmt,__FILE__,__LINE__,##args); \
			} while (0)
#define eag_log_syslog( level, match, fmt, args... ) \
			do { \
				if( EAG_TRUE == eag_log_is_filter_register(match) ) \
				{	\
					if(log_forward) {printf(fmt, ## args);printf("\n");} \
					else syslog( level, fmt, ## args ); \
				} \
			} while (0)

#endif

#define eag_log_debug( match, fmt, args... )  \
		do{ \
			if(0 == is_print_log(LOG_DEBUG))  \
				eag_log_syslog(LOG_DEBUG,match,"%s:%d:"fmt,__FILE__,__LINE__,## args); \
		}while(0)
#define eag_log_info( fmt, args... )  \
		do{ \
			if(0 == is_print_log(LOG_INFO))  \
			SYSLOG(LOG_INFO,fmt,## args); \
		}while(0)
#define eag_log_notice( fmt, args... )  \
		do{\
			if(0 == is_print_log(LOG_NOTICE))  \
				SYSLOG(LOG_NOTICE,fmt,## args); \
		}while(0)
#define eag_log_warning( fmt, args... )  \
		do{ \
			if(0 == is_print_log(LOG_WARNING))  \
				SYSLOG(LOG_WARNING,fmt,## args); \
		}while(0)
#define eag_log_err( fmt, args... )  \
		do{ \
			if(0 == is_print_log(LOG_ERR))  \
				SYSLOG(LOG_ERR,fmt,## args); \
		}while(0)
#define eag_log_crit( fmt, args... )  \
		do{ \
			if(0 == is_print_log(LOG_CRIT))  \
				SYSLOG(LOG_CRIT,fmt,## args); \
		}while(0)
#define admin_log_notice( fmt, args...)  \
		do{ \
			if(1 == autelan_log_switch) {	\
				if(0 == is_print_log(LOG_NOTICE)) {	\
					if (log_forward){printf(fmt, ##args );printf("\n");} \
					else syslog(LOG_LOCAL7|LOG_NOTICE,fmt,##args); \
				}	\
			}	\
		}while(0)
#define eag_henan_log_warning( fmt, args...)  \
		do{	\
			if(1 == henan_log_switch) {    \
				if(0 == is_print_log(LOG_WARNING)) {   \
					if (log_forward){printf(fmt, ##args );printf("\n");} \
					else syslog(LOG_LOCAL3|LOG_WARNING,fmt,##args); \
				}   \
			}   \
		}while(0)
#define eag_henan_log_notice( fmt, args...)  \
		do{	\
			if(1 == henan_log_switch) {	\
				if(0 == is_print_log(LOG_NOTICE)) {	\
					if (log_forward){printf(fmt, ##args );printf("\n");} \
					else syslog(LOG_LOCAL3|LOG_NOTICE,fmt,##args); \
				}	\
			}	\
		}while(0)
#define eag_log_filter( match, fmt, args... ) 	\
		do{ \
			if(1 == user_log_switch) {	\
				if(0 == is_print_log(LOG_DEBUG)) \
				syslog(LOG_DEBUG|LOG_LOCAL6,"%s "fmt,match,##args);	\
			} \
		}while(0)

#if 1
#define DEBUG_FUNCTION_BEGIN() 	eag_log_debug("function", "func %s begin", __func__)
#define DEBUG_FUNCTION_END()	eag_log_debug("function", "func %s end", __func__)
#else
#define DEBUG_FUNCTION_BEGIN()
#define DEBUG_FUNCTION_END()
#endif





//#ifdef  __cplusplus
//}
//#endif
#endif				/* _EAG_LOG_H */
