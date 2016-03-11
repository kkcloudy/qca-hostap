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
* igmp_snp_log.c
*
*
* CREATOR:
* 		jinpc@autelan.com
*
* DESCRIPTION:
* 		igmp inter source, handle igmp log infomation.
*
* DATE:
*		10/14/2008
*
* FILE REVISION NUMBER:
*  		$Revision: 1.10 $
*
*******************************************************************************/
#ifdef __cplusplus
extern "C"
{
#endif
#include <syslog.h>
//#include <dbus/dbus.h>
#include <stdarg.h>

#include "igmpsnp_log.h"
//#include "sysdef/returncode.h"
#include "igmpsnp_com.h"



#if 0
unsigned int igmp_snp_log_level = SYSLOG_DBG_DEF;
#else
unsigned int igmp_snp_log_level = SYSLOG_DBG_ALL;
#endif
unsigned int igmp_snp_daemon_log_open = 0;

/**********************************************************************************
 *  igmp_snoop_log_set_debug_value
 * 
 *  DESCRIPTION:
 *		This function set up one igmp snoop debug level
 *
 *  INPUT:
 * 	 	val_mask - debug level value stands for one level 
 *  
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 	 	IGMPSNP_RETURN_CODE_ALREADY_SET - if debug level has already been set before.
 *	 	IGMPSNP_RETURN_CODE_OK - debug level setup successfully.
 *
 **********************************************************************************/
int igmp_snoop_log_set_debug_value
(
	unsigned int val_mask
)
{
	unsigned int level = 0;
	
	if (igmp_snp_log_level & val_mask) {
		return IGMPSNP_RETURN_CODE_ALREADY_SET;
	}
	
	igmp_snp_log_level |= val_mask;

	return IGMPSNP_RETURN_CODE_OK;
}

/**********************************************************************************
 *	igmp_snoop_log_set_no_debug_value
 * 
 *  DESCRIPTION:
 *		This function remove one npd debug level
 *
 *  INPUT:
 * 	 	val_mask - debug level value stands for one level 
 *  
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		 IGMPSNP_RETURN_CODE_ALREADY_SET - if debug level has been set before.
 *		 IGMPSNP_RETURN_CODE_OK - remove debug level successfully.
 *
 **********************************************************************************/
int igmp_snoop_log_set_no_debug_value
(
	unsigned int val_mask
)
{
	unsigned int level = 0;
	
	if(igmp_snp_log_level & val_mask) {
		igmp_snp_log_level &= ~val_mask;
		return IGMPSNP_RETURN_CODE_OK;
	}
	else 
		return IGMPSNP_RETURN_CODE_ALREADY_SET;
}

/**********************************************************************************
 * igmp_snp_syslog_err
 *
 *  DESCRIPTION:
 *		output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_err
(
	char *format,...
)
{

	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};
    char *ident = "IGMP_SNP";


	// event not triggered
	if(0 == (SYSLOG_DBG_ERR & igmp_snp_log_level)) {
		return;
	}

	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	// assure log file open only once globally
	if(!igmp_snp_daemon_log_open) {
		openlog(ident, 0, LOG_DAEMON);
		igmp_snp_daemon_log_open = 1;
	}

	// put log
	va_start(ptr, format);
	vsprintf(buf,format,ptr);
	va_end(ptr);
	syslog(LOG_DEBUG,buf);


	return; 
}

/**********************************************************************************
 * igmp_snp_syslog_dbg
 *
 *  DESCRIPTION:
 *		output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_dbg
(
	char *format,...
)
{
	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};
    char *ident = "IGMP_SNP";

	// event not triggered
	if(0 == (SYSLOG_DBG_DBG & igmp_snp_log_level)) {
		return;
	}

	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	// assure log file open only once globally
	if(!igmp_snp_daemon_log_open) {
		openlog(ident, 0, LOG_DAEMON);
		igmp_snp_daemon_log_open = 1;
	}

	// put log
	va_start(ptr, format);
	vsprintf(buf,format,ptr);
	va_end(ptr);
	syslog(LOG_DEBUG,buf);


	return;
}

/**********************************************************************************
 * igmp_snp_syslog_event
 *
 *  DESCRIPTION:
 *		output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_event
(
	char *format,...
)
{
	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};
    char *ident = "IGMP_SNP";

	// event not triggered
	if(0 == (SYSLOG_DBG_EVT & igmp_snp_log_level)) {
		return;
	}
	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	// assure log file open only once globally
	if(!igmp_snp_daemon_log_open) {
		openlog(ident, 0, LOG_DAEMON);
		igmp_snp_daemon_log_open = 1;
	}

	// put log
	va_start(ptr, format);
	vsprintf(buf,format,ptr);
	va_end(ptr);
	syslog(LOG_DEBUG,buf);

	return;
}

/**********************************************************************************
 * igmp_snp_syslog_pkt_send
 *
 *  DESCRIPTION:
 *		output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_pkt_send
(
	char *format,
	...
)
{
	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};
    char *ident = "IGMP_SNP";

	// event not triggered
	if(0 == (SYSLOG_DBG_PKT_SED & igmp_snp_log_level)) {
		return;
	}

	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	// assure log file open only once globally
	if(!igmp_snp_daemon_log_open) {
		openlog(ident, 0, LOG_DAEMON);
		igmp_snp_daemon_log_open = 1;
	}

	// put log
	va_start(ptr, format);
	vsprintf(buf, format, ptr);
	va_end(ptr);
	syslog(LOG_DEBUG, buf);

	return;	
}
/**********************************************************************************
 * igmp_snp_syslog_pkt_rev
 *
 *  DESCRIPTION:
 *		output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_pkt_rev
(
	char *format,
	...
)
{
	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};
    char *ident = "IGMP_SNP";

	// event not triggered
	if(0 == (SYSLOG_DBG_PKT_REV & igmp_snp_log_level)) {
		return;
	}

	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	// assure log file open only once globally
	if(!igmp_snp_daemon_log_open) {
		openlog(ident, 0, LOG_DAEMON);
		igmp_snp_daemon_log_open = 1;
	}

	// put log
	va_start(ptr, format);
	vsprintf(buf, format, ptr);
	va_end(ptr);
	syslog(LOG_DEBUG, buf);

	return;	
}

/**********************************************************************************
 * igmp_snp_syslog_warn
 *
 *  DESCRIPTION:
 *		output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 *   		char *format - the output info as used in printf()
 *
 *  OUTPUT:
 * 		 NULL
 *
 *  RETURN:
 * 		NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_warn
(
	char *format,...
)
{
	va_list ptr;
	char buf[IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE] = {0};
    char *ident = "IGMP_SNP";

	// event not triggered
	if(0 == (SYSLOG_DBG_WAR & igmp_snp_log_level)) {
		return;
	}
	// ident null or format message null
	if(!ident || !format) {
		return;
	}

	// assure log file open only once globally
	if(!igmp_snp_daemon_log_open) {
		openlog(ident, 0, LOG_DAEMON);
		igmp_snp_daemon_log_open = 1;
	}

	// put log
	va_start(ptr, format);
	vsprintf(buf,format,ptr);
	va_end(ptr);
	syslog(LOG_DEBUG,buf);

	return;
}

#ifdef __cplusplus
}
#endif

