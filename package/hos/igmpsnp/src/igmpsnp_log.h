#ifndef _IGMP_SNP_LOG_H
#define _IGMP_SNP_LOG_H

/*
 * Logging levels for IGMP Snooping daemon
 */

#define SYSLOG_LOG_EMERG    LOG_EMERG
#define SYSLOG_LOG_ALERT    LOG_ALERT
#define SYSLOG_LOG_CRIT     LOG_CRIT
#define SYSLOG_LOG_ERR      LOG_ERR
#define SYSLOG_LOG_WARNING  LOG_WARNING
#define SYSLOG_LOG_NOTICE   LOG_NOTICE
#define SYSLOG_LOG_INFO     LOG_INFO

/* syslog line buffer size used in igmp snooping  */
#define IGMP_SNP_SYSLOG_LINE_BUFFER_SIZE	(256)	

typedef enum {
	SYSLOG_DBG_DEF = 0x0,	// default value
	SYSLOG_DBG_DBG = 0x1,	// packet
	SYSLOG_DBG_WAR = 0x2,	//normal 
	SYSLOG_DBG_ERR = 0x4,	//warning
	SYSLOG_DBG_EVT = 0x8,	// error
	SYSLOG_DBG_PKT_REV = 0x10,	// event
	SYSLOG_DBG_PKT_SED = 0x20,
	SYSLOG_DBG_PKT_ALL = 0x30,
	SYSLOG_DBG_ALL = 0xFF	// all
};

/**********************************************************************************
 *  igmp_snoop_log_set_debug_value
 * 
 *  DESCRIPTION:
 *	This function set up one igmp snoop debug level
 *
 *  INPUT:
 * 	 	val_mask - debug level value stands for one level 
 *  
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 1 - if debug level has already been set before.
 *	 0 - debug level setup successfully.
 *
 **********************************************************************************/
int igmp_snoop_log_set_debug_value
(
	unsigned int val_mask
);

/**********************************************************************************
 *	igmp_snoop_log_set_no_debug_value
 * 
 *  DESCRIPTION:
 *	This function remove one npd debug level
 *
 *  INPUT:
 * 	 	val_mask - debug level value stands for one level 
 *  
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 1 - if debug level has not been set before.
 *	 0 - remove debug level successfully.
 *
 **********************************************************************************/
int igmp_snoop_log_set_no_debug_value
(
	unsigned int val_mask
);

/**********************************************************************************
 *igmp_snp_syslog_err
 * output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 * 	 
 *
 *   char *format: the output info as used in printf();
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 NULL
 * 	 
 *
 **********************************************************************************/
void igmp_snp_syslog_err
(
	char *format,...
);

/**********************************************************************************
 *igmp_snp_syslog_dbg
 *
 * output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 * 	 
 *
 *   char *format: the output info as used in printf();
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 NULL
 * 	 
 *
 **********************************************************************************/
void igmp_snp_syslog_dbg
(
	char *format,...
);
/**********************************************************************************
 *igmp_snp_syslog_event
 *	output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 * 	 
 *
 *   char *format: the output info as used in printf();
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_event
(
	char *format,...
);

/**********************************************************************************
 *	igmp_snp_syslog_pkt_send
 * 
 *	output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 * 	 	event - 
 *		format - 
 *  
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 NULL
 * 	 
 *
 **********************************************************************************/
void igmp_snp_syslog_pkt_send
(
	char *format,
	...
);

/**********************************************************************************
 *	igmp_snp_syslog_pkt_rev
 * 
 *	output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 * 	 	event - 
 *		format - 
 *  
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 NULL
 * 	 
 *
 **********************************************************************************/
void igmp_snp_syslog_pkt_rev
(
	char *format,
	...
);

/**********************************************************************************
 *igmp_snp_syslog_warn
 *	output the daemon debug info to /var/log/daemon.log
 *
 *  INPUT:
 * 	 
 *
 *   char *format: the output info as used in printf();
 *  OUTPUT:
 * 	 NULL
 *
 *  RETURN:
 * 	 NULL
 * 	 
 **********************************************************************************/
void igmp_snp_syslog_warn
(
	char *format,...
);

#endif
