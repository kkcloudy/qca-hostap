#ifndef _DRV_MONITOR_H
#define _DRV_MONITOR_H

#include <linux/time.h>
#include "ar9300/ar9300reg.h"
#include "ieee80211_var.h"

extern int (*kes_debug_print_handle)(const char *fmt, ...);
extern void (*kes_debug_print_flag_handle)(const char *s); 

	
extern u_int32_t bb_hang;
extern u_int32_t mac_hang;
extern u_int32_t beacon_complete;
extern u_int32_t bstuck_check_num;


typedef struct {
	const char*	label;
	u_int		reg;
} HAL_REG;


typedef enum
{
    AUTE_DRV_NO_ERR      = 0,
    AUTE_DRV_SOFT_TX_STUCK_ERR = 1,  //memory leak, no buffer abailable
    AUTE_DRV_SOFT_RX_STUCK_ERR = 2,
    AUTE_DRV_HW_STUCK_ERR = 3,  
    AUTE_DRV_AIR_LATENCY_ERR = 4,
    AUTE_DRV_IFID_NOT_CREATE = 5,
} aute_drv_monitor_err_t;

typedef enum
{
    AUTE_MONITOR_NO_REBOOT      = 0,
    AUTE_MONITOR_REBOOT_PERIOD   = 1, 
    AUTE_MONITOR_REBOOT_NOW   = 2, 
    
} aute_drv_monitor_act_t;

/*--monitor switch--*/
extern u_int32_t autelan_drv_monitor_enable;
extern u_int32_t autelan_drv_monitor_reboot;
extern u_int32_t autelan_drv_hang_reboot;
extern u_int32_t autelan_drv_monitor_period;

/*--hw stuck--*/
extern u_int32_t bstuck_enable;
extern u_int32_t bmiss_check;
extern u_int32_t aute_bb_hang_check;
extern u_int32_t aute_mac_hang_check;
extern u_int32_t data_txq ;	
/*--stats--*/
extern u_int32_t ps_bufcnt;
extern u_int32_t ps_acqcnt;
extern u_int32_t  tid_period_sec;
extern u_int32_t  tid_period_us;


extern void autelan_get_queueinfo(struct ath_softc *sc);
extern void autelan_DumpRegs(struct ath_hal *ah);

//extern void kernel_restart(char *cmd);
extern void aute_kernel_restart(u_int32_t error_code); 
u_int32_t drv_rx_buffer_dump(struct ath_softc *sc);
 OS_TIMER_FUNC(autelan_drv_monitor);

 #endif //_DRV_MONITOR_H





