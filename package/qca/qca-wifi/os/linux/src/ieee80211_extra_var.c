#include <_ieee80211.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/init.h>


/* Begin:Add by chenxf for powersave performance 2014-06-05 */
#if ATOPT_POWERSAVE_PERF
u_int32_t ps_drop = 0;
EXPORT_SYMBOL(ps_drop);
u_int32_t ps_ac_reorder = 1;
EXPORT_SYMBOL(ps_ac_reorder);
u_int32_t ps_fifo_depth = 8;
EXPORT_SYMBOL(ps_fifo_depth);
#endif
/* End:Add by chenxf for powersave performance 2014-06-05 */
#if ATOPT_DRV_MONITOR
u_int32_t autelan_drv_monitor_enable = 1;
EXPORT_SYMBOL(autelan_drv_monitor_enable);
u_int32_t autelan_drv_monitor_reboot = 1;
EXPORT_SYMBOL(autelan_drv_monitor_reboot);
u_int32_t autelan_drv_hang_reboot = 0;
EXPORT_SYMBOL(autelan_drv_hang_reboot);

/*--hw stuck*/
u_int32_t bstuck_enable = 1;
EXPORT_SYMBOL(bstuck_enable);
u_int32_t bmiss_check = 60;
EXPORT_SYMBOL(bmiss_check);
u_int32_t aute_bb_hang_check = 2;
EXPORT_SYMBOL(aute_bb_hang_check);
u_int32_t aute_mac_hang_check = 2;
EXPORT_SYMBOL(aute_mac_hang_check);
u_int32_t data_txq = 0;	
EXPORT_SYMBOL(data_txq);
u_int32_t autelan_drv_monitor_period = 1000;//ms
EXPORT_SYMBOL(autelan_drv_monitor_period);

/*stats*/
u_int32_t ps_bufcnt = 0;
EXPORT_SYMBOL(ps_bufcnt);
u_int32_t ps_acqcnt = 0;
EXPORT_SYMBOL(ps_acqcnt);
u_int32_t      	 tid_period_sec;
EXPORT_SYMBOL(tid_period_sec);
u_int32_t      	 tid_period_us;
EXPORT_SYMBOL(tid_period_us);


#endif

