
#include <linux/netdevice.h>
#include <osdep.h>
#include "osif_private.h"
#include "ieee80211_var.h"
#include "if_athvar.h"
#include "ieee80211_defines.h"
#include "at_proc_command.h"

#if ATOPT_THINAP
u_int32_t thinap = 0;
EXPORT_SYMBOL(thinap);
u_int32_t thinap_state = 0;
EXPORT_SYMBOL(thinap_state);
u_int32_t thinap_check_timer = 0;
EXPORT_SYMBOL(thinap_check_timer);
u_int32_t thinap_check_threshold = 0;
EXPORT_SYMBOL(thinap_check_threshold);
#endif

#if ATOPT_5G_PRIORITY
u_int32_t join5g_enable = 1;
EXPORT_SYMBOL(join5g_enable);
u_int32_t scantime_thr = 500; 
EXPORT_SYMBOL(scantime_thr);
u_int32_t agingtime_thr = 900000; 
EXPORT_SYMBOL(agingtime_thr);
u_int32_t discard_count = 2; 
EXPORT_SYMBOL(discard_count);
u_int32_t join5g_debug = 0;
EXPORT_SYMBOL(join5g_debug);
u_int32_t stacount_thr = 30;
EXPORT_SYMBOL(stacount_thr);
/*station's 2.4G signal strength threshold, RSSI. */
u_int32_t sta_signal_strength_thr = 0; 
EXPORT_SYMBOL(sta_signal_strength_thr);
#endif

enum {
#if ATOPT_THINAP
    ATH_THINAP = 0,
    ATH_THINAP_STATE = 1,
    ATH_THINAP_CHECK_TIMER = 2,
    ATH_THINAP_CHECK_THRESHOLD = 3,
#endif

#if ATOPT_5G_PRIORITY
    ATH_JOIN5G_ENABLE = 4,
    ATH_SCANTIME_THR = 5,
    ATH_AGINGTIME_THR = 6,
    ATH_DISCARD_COUNT = 7,
    ATH_JOIN5G_DEBUG = 8,
    ATH_STA_COUNT = 9,
    ATH_STA_SIGNAL_STRENGTH_THR = 10,   
#endif

/* Begin:Add by chenxf for powersave performance 2014-06-05 */
#if ATOPT_POWERSAVE_PERF
    ATH_PS_REORDER = 11,
    ATH_PS_DROP = 12,
    ATH_PS_FIFO_DETPH = 13,
#endif
/* End:Add by chenxf for powersave performance 2014-06-05 */
#if ATOPT_DRV_MONITOR
    AUTELAN_DRV_MONITOR_ENABLE =14,
    AUTELAN_DRV_MONITOR_REBOOT=15,
    AUTELAN_DRV_HANG_REBOOT = 16,
    BSTUCK_ENBALE =17,
    BMISS_CHECK = 18,
    AUTE_BB_HANG_CHECK = 19,
    AUTE_MAC_HANG_CHECK = 20,
    AUTE_DATA_TXQ = 21,
#endif

ATH_NONE = 65535,
};

static int
ATH_SYSCTL_DECL(ath_sysctl_halparam, ctl, write, filp, buffer, lenp, ppos)
{
        static u_int val;
        int ret=0;
        struct ath_softc_net80211   *scn = (struct ath_softc_net80211 *)ctl->extra1;
        struct ieee80211com *ic = &scn->sc_ic;

        ctl->data = &val;
        ctl->maxlen = sizeof(val);
        if (write) {
        ret = ATH_SYSCTL_PROC_DOINTVEC(ctl, write, filp, buffer,
                lenp, ppos);
        if (0 == ret) {
            switch ((long)ctl->extra2) {
                
#if ATOPT_THINAP
                case ATH_THINAP:
                    thinap = val;
                    break;
                case ATH_THINAP_STATE:
                    thinap_state= val;
                    break;
                case ATH_THINAP_CHECK_TIMER:
                    thinap_check_timer= val;
                    break;
                case ATH_THINAP_CHECK_THRESHOLD:
                    thinap_check_threshold= val;
                    break;

#endif
#if ATOPT_5G_PRIORITY 
                case ATH_JOIN5G_ENABLE:
                    join5g_enable = val;
                    break;
                    
                case ATH_SCANTIME_THR:
                    scantime_thr = val;
                    break;

                case ATH_AGINGTIME_THR:
                    agingtime_thr = val;
                    break;

                case ATH_DISCARD_COUNT:
                    discard_count = val;
                    break;

                case ATH_JOIN5G_DEBUG:
                    join5g_debug = val;
                    break;

                case ATH_STA_COUNT:
                    stacount_thr = val;
                    break;

                case ATH_STA_SIGNAL_STRENGTH_THR:
                    {
                        int signal_strength = (int)val;
                        if(signal_strength >= -95 && signal_strength <= 0)
                        {
                            sta_signal_strength_thr = signal_strength - ATH_DEFAULT_NOISE_FLOOR; /* Convert dBm to RSSI. */
                        }
                    }
                    break;
#endif

/* Begin:Add by chenxf for powersave performance 2014-06-05 */
#if ATOPT_POWERSAVE_PERF
                case ATH_PS_DROP:
                    ps_drop = val;
                    break;
                case ATH_PS_REORDER:
                    ps_ac_reorder = val;
                    break;
                case ATH_PS_FIFO_DETPH:
                    if (ps_fifo_depth > 8)
                        ps_fifo_depth = 8;
                    else if (ps_fifo_depth <= 0)
                        ps_fifo_depth = 1;
                    else
                        ps_fifo_depth = val;
                    break;
#endif
/* End:Add by chenxf for powersave performance 2014-06-05 */
#if ATOPT_DRV_MONITOR

                    case AUTELAN_DRV_MONITOR_ENABLE:
                        autelan_drv_monitor_enable=val;
                        break;
                    case AUTELAN_DRV_MONITOR_REBOOT:
                        autelan_drv_monitor_reboot = val;
                        break; 
                    case AUTELAN_DRV_HANG_REBOOT:
                        autelan_drv_hang_reboot = val;
                        break; 
                    case BSTUCK_ENBALE:
                        bstuck_enable = val;
                        break;
                    case BMISS_CHECK:
                        bmiss_check = val;
                        break;
                    case AUTE_BB_HANG_CHECK:
                        aute_bb_hang_check = val;
                        break;
                    case AUTE_MAC_HANG_CHECK:
                        aute_mac_hang_check = val;
                        break;
                    case AUTE_DATA_TXQ: 
                        data_txq = val;
                        break; 
#endif
                    default:
                        return -EINVAL;
                }
            }
        } else {
            switch ((long)ctl->extra2) {
#if ATOPT_THINAP
                case ATH_THINAP:
                    val = thinap;
                    break;
                case ATH_THINAP_STATE:
                    val = thinap_state;
                    break;
                case ATH_THINAP_CHECK_TIMER:
                    val = thinap_check_timer;
                    break;
                case ATH_THINAP_CHECK_THRESHOLD:
                    val = thinap_check_threshold;
                    break;
#endif

#if ATOPT_5G_PRIORITY
                case ATH_JOIN5G_ENABLE:
                    val = join5g_enable;
                    break;

                case ATH_SCANTIME_THR:
                    val = scantime_thr;
                    break;

                case ATH_AGINGTIME_THR:
                    val = agingtime_thr;
                    break;
                case ATH_DISCARD_COUNT:
                    val = discard_count;
                    break;

                case ATH_JOIN5G_DEBUG:
                    val = join5g_debug;
                    break;

                case ATH_STA_COUNT:
                    val = stacount_thr;
                    break;

                case ATH_STA_SIGNAL_STRENGTH_THR:
                    val = sta_signal_strength_thr + ATH_DEFAULT_NOISE_FLOOR; /* Convert RSSI to dBm. */;
                    break;
#endif

            /* Begin:Add by chenxf for powersave performance 2014-06-05 */
#if ATOPT_POWERSAVE_PERF
                case ATH_PS_DROP:
                    val = ps_drop;
                    break;

                case ATH_PS_REORDER:
                    val = ps_ac_reorder;
                    break;
                case ATH_PS_FIFO_DETPH:
                    val = ps_fifo_depth;
                    break;
#endif
/* End:Add by chenxf for powersave performance 2014-06-05 */
#if ATOPT_DRV_MONITOR

                case AUTELAN_DRV_MONITOR_ENABLE:
                    val = autelan_drv_monitor_enable;
                    break;
                case AUTELAN_DRV_MONITOR_REBOOT:
                    val = autelan_drv_monitor_reboot;
                    break; 
                case AUTELAN_DRV_HANG_REBOOT:
                    val = autelan_drv_hang_reboot;
                    break;
                case BSTUCK_ENBALE:
                    val = bstuck_enable;
                    break;
                case BMISS_CHECK:
                    val = bmiss_check;
                    break;
                case AUTE_BB_HANG_CHECK:
                    val = aute_bb_hang_check;
                    break;
                case AUTE_MAC_HANG_CHECK:
                    val = aute_mac_hang_check;
                    break; 
                case AUTE_DATA_TXQ: 
                    val = data_txq;
                    break; 
#endif
                default:
                    return -EINVAL;
            }
            ret = ATH_SYSCTL_PROC_DOINTVEC(ctl, write, filp, buffer,
                                lenp, ppos);
    }
    return ret;
}

static const ctl_table at_wifi_sysctl[] = {
#if ATOPT_THINAP
    { CTL_NAME_AUTO
      .procname         = "thinap",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_THINAP,
    },   
    { CTL_NAME_AUTO
      .procname         = "thinap_state",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_THINAP_STATE,
    },   
    { CTL_NAME_AUTO
      .procname         = "thinap_check_timer",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_THINAP_CHECK_TIMER,
    },   
    { CTL_NAME_AUTO
      .procname         = "thinap_check_threshold",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_THINAP_CHECK_THRESHOLD,
    },   

#endif

#if ATOPT_5G_PRIORITY
    { CTL_NAME_AUTO
      .procname         = "join5g_enable",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_JOIN5G_ENABLE,  
    },
    { CTL_NAME_AUTO
      .procname         = "scantime_thr",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_SCANTIME_THR,  
    },
    { CTL_NAME_AUTO
      .procname         = "agingtime_thr",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_AGINGTIME_THR,  
    },
    { CTL_NAME_AUTO
      .procname         = "discard_count",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_DISCARD_COUNT,  
    },
    { CTL_NAME_AUTO
      .procname         = "join5g_debug",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_JOIN5G_DEBUG,  
    },
    { CTL_NAME_AUTO
      .procname         = "stacount_thr",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_STA_COUNT,  
    },
    /* Begin:gengzongjie transplanted for apv8 2014-2-24 */
    /*Begin, station's 2.4G signal strength threshold, wangjia 2012-10-16. */
    { CTL_NAME_AUTO
      .procname         = "sta_signal_strength_thr",
      .mode             = 0644, 
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_STA_SIGNAL_STRENGTH_THR,	
    },
#endif

    /* Begin:Add by chenxf for powersave performance 2014-06-05 */
#if ATOPT_POWERSAVE_PERF

    { CTL_NAME_AUTO
      .procname         = "ps_drop",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_PS_DROP,
    },
    { CTL_NAME_AUTO
      .procname         = "ps_ac_reorder",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_PS_REORDER,
    },
    { CTL_NAME_AUTO
      .procname         = "ps_fifo_depth",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)ATH_PS_FIFO_DETPH,
    },
#endif
/* End:Add by chenxf for powersave performance 2014-06-05 */
#if ATOPT_DRV_MONITOR

    { CTL_NAME_AUTO
      .procname         = "autelan_drv_monitor_enable",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)AUTELAN_DRV_MONITOR_ENABLE,  
    },
    {CTL_NAME_AUTO
      .procname         = "autelan_drv_monitor_reboot",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)AUTELAN_DRV_MONITOR_REBOOT,  
    },
    { CTL_NAME_AUTO
      .procname         = "autelan_drv_hang_reboot",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)AUTELAN_DRV_HANG_REBOOT,  
    },
    { CTL_NAME_AUTO
      .procname         = "bstuck_enable",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)BSTUCK_ENBALE,  
    },

    { CTL_NAME_AUTO
      .procname         = "bmiss_check",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)BMISS_CHECK,
    },
    { CTL_NAME_AUTO
      .procname         = "aute_bb_hang_check",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)AUTE_BB_HANG_CHECK,
    },
    { CTL_NAME_AUTO
      .procname         = "aute_mac_hang_check",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)AUTE_MAC_HANG_CHECK,
    },
    { CTL_NAME_AUTO
      .procname         = "data_txq",
      .mode             = 0644,
      .proc_handler     = ath_sysctl_halparam,
      .extra2           = (void *)AUTE_DATA_TXQ,
    },
#endif
    { 0 }
};

void at_wifi_sysctl_register(struct ath_softc_net80211 * scn)
{
        int i, space;
        char *devname = scn->sc_osdev->netdev->name ;

        space = 5*sizeof(struct ctl_table) + sizeof(at_wifi_sysctl);
        scn->sc_sysctls = kmalloc(space, GFP_KERNEL);
        if (scn->sc_sysctls == NULL) {
                printk("%s: no memory for sysctl table!\n", __func__);
                return;
        }

        /* setup the table */
        memset(scn->sc_sysctls, 0, space);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
        scn->sc_sysctls[0].ctl_name = CTL_DEV;
#endif
        scn->sc_sysctls[0].procname = "dev";
        scn->sc_sysctls[0].mode = 0555;
        scn->sc_sysctls[0].child = &scn->sc_sysctls[2];
        /* [1] is NULL terminator */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
        scn->sc_sysctls[2].ctl_name = CTL_AUTO;
#endif

        scn->sc_sysctls[2].procname = devname ;
        scn->sc_sysctls[2].mode = 0555;
        scn->sc_sysctls[2].child = &scn->sc_sysctls[4];
        /* [3] is NULL terminator */
        /* copy in pre-defined data */
        memcpy(&scn->sc_sysctls[4], at_wifi_sysctl,
                sizeof(at_wifi_sysctl));

        /* add in dynamic data references */
        for (i = 4; scn->sc_sysctls[i].procname; i++)
                if (scn->sc_sysctls[i].extra1 == NULL)
                        scn->sc_sysctls[i].extra1 = scn;

        /* and register everything */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,20)
        scn->sc_sysctl_header = register_sysctl_table(scn->sc_sysctls);
#else
        scn->sc_sysctl_header = register_sysctl_table(scn->sc_sysctls, 1);
#endif
        if (!scn->sc_sysctl_header) {
                printk("%s: failed to register sysctls!\n", devname);
                kfree(scn->sc_sysctls);
                scn->sc_sysctls = NULL;
        }
}

void at_wifi_sysctl_unregister(struct ath_softc_net80211 * scn)
{
        if (scn->sc_sysctl_header) {
                unregister_sysctl_table(scn->sc_sysctl_header);
                scn->sc_sysctl_header = NULL;
        }
        if (scn->sc_sysctls) {
                kfree(scn->sc_sysctls);
                scn->sc_sysctls = NULL;
        }
}
/* Autelan-End: zhaoyang1 adds sysctl 2015-01-08 */




static int
ATH_SYSCTL_DECL(at_vap_sysctl_splitmac, ctl, write, filp, buffer,
    lenp, ppos)
{
    struct ieee80211vap *vap = ctl->extra1;
    u_int val;
    int ret;

    ctl->data = &val;
    ctl->maxlen = sizeof(val);
    if (write) {
        ret = ATH_SYSCTL_PROC_DOINTVEC(ctl, write, filp, buffer,
                lenp, ppos);
    if (ret == 0)
        vap->vap_splitmac = val;
    } else {
        val = vap->vap_splitmac;
        ret = ATH_SYSCTL_PROC_DOINTVEC(ctl, write, filp, buffer,
                lenp, ppos);
    }
    return ret;
}


static const ctl_table at_vap_sysctl[] = {
    /* NB: must be last entry before NULL */
#if ATOPT_THINAP
    { CTL_NAME_AUTO
      .procname     = "vap_splitmac",
      .mode         = 0644,
      .proc_handler = at_vap_sysctl_splitmac
    },
#endif
    {0}
};

void at_vap_sysctl_register(struct ieee80211vap *vap)
{
    int i, space;
    struct net_device * dev = NULL;
    osif_dev * osifp = NULL;
    //dev = OSIF_TO_NETDEV(vap->iv_ifp);
    osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    dev = osifp->netdev;
    if(dev == NULL)
    {
        printk("%s dev is null!\n",__func__);
        return;
    }
    space = 5*sizeof(struct ctl_table) + sizeof(at_vap_sysctl);
    vap->iv_sysctls = kmalloc(space, GFP_KERNEL);
    if (vap->iv_sysctls == NULL)
    {
        printk("%s: no memory for sysctl table!\n", __func__);
        return;
    }

    /* setup the table */
    memset(vap->iv_sysctls, 0, space);
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
    vap->iv_sysctls[0].ctl_name = CTL_NET;
#endif

    vap->iv_sysctls[0].procname = "net";
    vap->iv_sysctls[0].mode = 0555;
    vap->iv_sysctls[0].child = &vap->iv_sysctls[2];
    /* [1] is NULL terminator */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
    vap->iv_sysctls[2].ctl_name = CTL_AUTO;
#endif
    vap->iv_sysctls[2].procname = dev->name;/* XXX bad idea? */
    vap->iv_sysctls[2].mode = 0555;
    vap->iv_sysctls[2].child = &vap->iv_sysctls[4];
    /* [3] is NULL terminator */
    /* copy in pre-defined data */
    memcpy(&vap->iv_sysctls[4], at_vap_sysctl,
        sizeof(at_vap_sysctl));

    /* add in dynamic data references */
    for (i = 4; vap->iv_sysctls[i].procname; i++)
        if (vap->iv_sysctls[i].extra1 == NULL)
            vap->iv_sysctls[i].extra1 = vap;

        /* tack on back-pointer to parent device */
        vap->iv_sysctls[i-1].data = vap->iv_ic->ic_osdev->netdev->name;	/* XXX? */
    /* and register everything */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,20)
    vap->iv_sysctl_header = register_sysctl_table(vap->iv_sysctls);
#else
    vap->iv_sysctl_header = register_sysctl_table(vap->iv_sysctls, 1);
#endif
    if (!vap->iv_sysctl_header)
    {
        printk("%s: failed to register sysctls!\n", dev->name);
        kfree(vap->iv_sysctls);
        vap->iv_sysctls = NULL;
    }
}

void at_vap_sysctl_unregister(struct ieee80211vap *vap)
{
    if (vap->iv_sysctl_header)
    {
        unregister_sysctl_table(vap->iv_sysctl_header);
        vap->iv_sysctl_header = NULL;
    }
    if (vap->iv_sysctls)
    {
        kfree(vap->iv_sysctls);
        vap->iv_sysctls = NULL;
    }
}


/*AUTELAN-Begin:Added by WangJia for traffic limit. 2012-11-02, transplant by zhouke */
#if ATOPT_TRAFFIC_LIMIT
extern u_int32_t tl_tasklet_timeslice;
extern u_int32_t tl_dequeue_threshold;
extern u_int32_t tl_debug_flag;

#define NETDEV_TO_VAP(_dev) (((osif_dev *)netdev_priv(_dev))->os_if)

int
ieee80211_ioctl_autelan_traffic_limit(struct net_device *dev, struct iwreq *iwr)
{
    /*xiaruixin modify for traffic limit reset*/
    wlan_if_t vap = NETDEV_TO_VAP(dev);
    /*xiaruixin modify end*/
    struct ieee80211com   *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL ;
    struct ieee80211_autelan_traffic_limit ik;
    struct ieee80211_node_table *nt = &ic->ic_sta; 

    u_int32_t rate = 0;
    u_int64_t cir = 0;

    u_int32_t loop = 0;
    u_int32_t flag = 0;
    
    struct ieee80211_tl_srtcm *ni_tl_up = NULL;
    struct ieee80211_tl_srtcm *ni_tl_down = NULL;
    struct ieee80211_tl_srtcm *vap_tl_up = NULL;
    struct ieee80211_tl_srtcm *vap_tl_down = NULL;
    struct ieee80211_tl_srtcm *vap_tl_ev_up = NULL;
    struct ieee80211_tl_srtcm *vap_tl_ev_down = NULL;    

    vap_tl_up = &(vap->vap_tl_up_srtcm_vap);
    vap_tl_down = &(vap->vap_tl_down_srtcm_vap);

    vap_tl_ev_up = &(vap->vap_tl_up_srtcm_ev);
    vap_tl_ev_down = &(vap->vap_tl_down_srtcm_ev);
    
    memset(&ik, 0x00, sizeof(ik));

    if (copy_from_user(&ik, iwr->u.data.pointer, sizeof(ik))) {
        return -EFAULT;
    }
    
    switch (ik.type) { 
        case SET_VAP_TRAFFIC_LIMIT_FLAG:
            if(1 == ik.arg1) {
                vap->vap_tl_vap_enable = IEEE80211_TL_ENABLE;
            } else if(0 == ik.arg1) {
                vap->vap_tl_vap_enable = IEEE80211_TL_DISABLE;
            } else {
                return -EINVAL;
            }
            break;

        case GET_VAP_TRAFFIC_LIMIT_FLAG:
            flag = vap->vap_tl_vap_enable;
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));
            break;

        case SET_VAP_TRAFFIC_LIMIT:
            rate = ik.arg1;
            IEEE80211_TL_SRTCM_SET_CIR(vap_tl_up, rate);
            break;

        case GET_VAP_TRAFFIC_LIMIT :
            cir = vap_tl_up->sr_cir;
            rate = IEEE80211_TL_CIR_TO_RATE(cir);
            copy_to_user(iwr->u.data.pointer, &rate, sizeof(rate));
            break;

        case SET_EVERY_NODE_TRAFFIC_LIMIT_FLAG:
            if(1 == ik.arg1) {
                vap->vap_tl_ev_enable = IEEE80211_TL_ENABLE;
            } else if(0 == ik.arg1) {
                vap->vap_tl_ev_enable = IEEE80211_TL_DISABLE;
            } else {
                return -EINVAL;
            }
                
            TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
                if((ni->ni_vap != vap) || (ni == ni->ni_vap->iv_bss))
                {
                    continue;
                }

                ni->ni_tl_ev_enable = vap->vap_tl_ev_enable;
                /**
                 *  when EVERY node is set, whenever is turn ON/OFF, 
                 *  turn OFF every node's SPECIFIC flag;
                 */
                ni->ni_tl_sp_enable = IEEE80211_TL_DISABLE;
            }
            break;

        case GET_EVERY_NODE_TRAFFIC_LIMIT_FLAG:
            flag = vap->vap_tl_ev_enable;
            copy_to_user(iwr->u.data.pointer, &flag, sizeof(flag));
            break;

        case SET_EVERY_NODE_TRAFFIC_LIMIT:
            rate = ik.arg1;   
            IEEE80211_TL_SRTCM_SET_CIR(vap_tl_ev_up, rate);
            TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
                if((ni->ni_vap != vap) || (ni == ni->ni_vap->iv_bss))
                {
                    continue;
                }
                ni_tl_up = &(ni->ni_tl_up_srtcm_ev);
                IEEE80211_TL_SRTCM_SET_CIR(ni_tl_up, rate);
            }
            break;

        case GET_EVERY_NODE_TRAFFIC_LIMIT :
            cir = vap_tl_ev_up->sr_cir;
            rate = IEEE80211_TL_CIR_TO_RATE(cir);
            copy_to_user(iwr->u.data.pointer, &rate, sizeof(rate));

            break;

        case SET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG:
            ni = ieee80211_find_node(&ic->ic_sta, ik.macaddr);
            if (ni == NULL)
                return -EINVAL;

            ni_tl_up = &(ni->ni_tl_up_srtcm_sp);
            if(1 == ik.arg1) {
                ni->ni_tl_sp_enable = IEEE80211_TL_ENABLE;
            } else if(0 == ik.arg1) {
                ni->ni_tl_sp_enable = IEEE80211_TL_DISABLE;
            } else {
                ieee80211_free_node(ni);
                return -EINVAL;
            }
            ieee80211_free_node(ni);
            break;

        case GET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG:
            ni = ieee80211_find_node(&ic->ic_sta, ik.macaddr);
            if (ni == NULL)
                return -EINVAL;

            flag = ni->ni_tl_sp_enable;
            copy_to_user(iwr->u.data.pointer, &flag, sizeof(flag));

            ieee80211_free_node(ni);
            break;
            
        case SET_SPECIFIC_NODE_TRAFFIC_LIMIT:
            ni = ieee80211_find_node(&ic->ic_sta, ik.macaddr);

            if (ni == NULL)
                return -EINVAL; 
            rate = ik.arg1;
            ni_tl_up = &(ni->ni_tl_up_srtcm_sp);
            IEEE80211_TL_SRTCM_SET_CIR(ni_tl_up, rate);
            
            ieee80211_free_node(ni);
            break;

        case GET_SPECIFIC_NODE_TRAFFIC_LIMIT :
            ni = ieee80211_find_node(&ic->ic_sta, ik.macaddr);
            
            if (ni == NULL)
                return -EINVAL; 

            ni_tl_up = &(ni->ni_tl_up_srtcm_sp);
            cir = ni_tl_up->sr_cir;
            rate = IEEE80211_TL_CIR_TO_RATE(cir);
            copy_to_user(iwr->u.data.pointer, &rate, sizeof(rate));
            
            ieee80211_free_node(ni);
            break;

        case SET_VAP_TRAFFIC_LIMIT_SEND:
            rate = ik.arg1;
            IEEE80211_TL_SRTCM_SET_CIR(vap_tl_down, rate);

            break;

        case GET_VAP_TRAFFIC_LIMIT_SEND:
            cir = vap_tl_down->sr_cir;
            rate = IEEE80211_TL_CIR_TO_RATE(cir);
            copy_to_user(iwr->u.data.pointer, &rate, sizeof(rate));
            break;
            
        case SET_EVERY_NODE_TRAFFIC_LIMIT_SEND:
            rate = ik.arg1;
            IEEE80211_TL_SRTCM_SET_CIR(vap_tl_ev_down, rate);
            
            TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
                if((ni->ni_vap != vap) || (ni == ni->ni_vap->iv_bss))
                {
                    continue;
                }
                ni_tl_down = &(ni->ni_tl_down_srtcm_ev);
                IEEE80211_TL_SRTCM_SET_CIR(ni_tl_down, rate);
            }            
            break;

        case GET_EVERY_NODE_TRAFFIC_LIMIT_SEND:
            cir = vap_tl_ev_down->sr_cir;
            rate = IEEE80211_TL_CIR_TO_RATE(cir);
            copy_to_user(iwr->u.data.pointer, &rate, sizeof(rate));
            break;

        case SET_SPECIFIC_NODE_TRAFFIC_LIMIT_SEND:
            ni = ieee80211_find_node(&ic->ic_sta, ik.macaddr);

            if (ni == NULL)
                return -EINVAL;

            rate = ik.arg1;
            ni_tl_down = &(ni->ni_tl_down_srtcm_sp);
            IEEE80211_TL_SRTCM_SET_CIR(ni_tl_down, rate);
            
            ieee80211_free_node(ni);
            break;

            case GET_SPECIFIC_NODE_TRAFFIC_LIMIT_SEND:
            ni = ieee80211_find_node(&ic->ic_sta, ik.macaddr);

            if (ni == NULL)
                return -EINVAL;

            ni_tl_down = &(ni->ni_tl_down_srtcm_sp);
            cir = ni_tl_down->sr_cir;
            rate = IEEE80211_TL_CIR_TO_RATE(cir);
            copy_to_user(iwr->u.data.pointer, &rate, sizeof(rate));
            
            ieee80211_free_node(ni);

            break;
        /*AUTELAN-Added-Begin: Added by WangJia, for traffic limit. 2012-11-02.*/
        case TL_GET_TRAFFIC_LIMIT_STATUS:
            printf("Vap  Sum           :     %s, Down - %llukbps, Up - %llukbps\r\n", 
                   (IEEE80211_TL_ENABLE == vap->vap_tl_vap_enable) ? " ON" : "OFF", 
                   IEEE80211_TL_CIR_TO_RATE(vap_tl_down->sr_cir), 
                   IEEE80211_TL_CIR_TO_RATE(vap_tl_up->sr_cir));
            
            printf("Node List          : ");
            TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
                if((ni->ni_vap != vap) || (ni == ni->ni_vap->iv_bss))
                {
                    continue;
                }
                ni_tl_up = &(ni->ni_tl_up_srtcm_ev);
                ni_tl_down = &(ni->ni_tl_down_srtcm_ev);
                if(IEEE80211_TL_ENABLE == ni->ni_tl_sp_enable)
                {
                    ni_tl_up = &(ni->ni_tl_up_srtcm_sp);
                    ni_tl_down = &(ni->ni_tl_down_srtcm_sp);
                }

                flag = 1;
                printf("\r\n[%02X:", ni->ni_macaddr[0]);
                for(loop = 1; loop < 5; loop++)
                {
                    printf("%02X:", ni->ni_macaddr[loop]);
                }
                printf("%02X]: ", ni->ni_macaddr[5]);
                printf("%s, ", (IEEE80211_TL_ENABLE == ni->ni_tl_sp_enable) ? "SP NODE ON" :
                               (IEEE80211_TL_ENABLE == ni->ni_tl_ev_enable) ? "EV NODE ON" : "    OFF");

                printf("Down - %llukbps, Up - %llukbps", 
                    IEEE80211_TL_CIR_TO_RATE(ni_tl_down->sr_cir),
                    IEEE80211_TL_CIR_TO_RATE(ni_tl_up->sr_cir));
            }
            if(flag == 0)
            {
                printf("No Stations.");
            }
            printf("\r\n");
            break;
        case TL_SET_TASKLET_TIMESLICE:
            tl_tasklet_timeslice = ik.arg1;
            break;

        case TL_GET_TASKLET_TIMESLICE:
            printf("tl_tasklet_timeslice = %d\r\n", tl_tasklet_timeslice);
            break;

        case TL_SET_DEQUEUE_THRESHOLD:
            tl_dequeue_threshold = ik.arg1;
            break;
            
        case TL_GET_DEQUEUE_THRESHOLD:
            printf("tl_dequeue_threshold = %d\r\n", tl_dequeue_threshold);
            break;
            
        case TL_GET_EVERYNODE_QUEUE_LEN:
            printf("VAP                 : UP - %u, DOWN - %u\r\n", 
                    vap->vap_tl_up_cacheq.cq_len, 
                    vap->vap_tl_down_cacheq.cq_len);
            TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
                if((ni->ni_vap != vap) || (ni == ni->ni_vap->iv_bss))
                {
                    continue;
                }
                printf("[");
                for(loop = 0; loop < 5; loop++)
                {
                    printf("%02X:", ni->ni_macaddr[loop]);
                }
                printf("%02X] : UP - %u, DOWN - %u\r\n", ni->ni_macaddr[5],
                    ni->ni_tl_up_cacheq.cq_len, ni->ni_tl_down_cacheq.cq_len);
                flag = 1;
            }
            if(flag == 0)
            {
                printf("No Stations.\r\n");
            }
            break;
        case TL_SET_DEBUG_FLAG:
            if(ik.arg1 & IEEE80211_TL_LOG_INFO || ik.arg1 & IEEE80211_TL_LOG_WARNING || 
               ik.arg1 & IEEE80211_TL_LOG_ERROR) 
            {
                tl_debug_flag = (ik.arg1 & IEEE80211_TL_LOG_INFO) | 
                                (ik.arg1 & IEEE80211_TL_LOG_WARNING) | 
                                (ik.arg1 & IEEE80211_TL_LOG_ERROR);
            }
            break;
        case TL_GET_DEBUG_FLAG:
            printf("Current traffic limit debug switch: 0X%02X [ ", tl_debug_flag);
            if(tl_debug_flag & IEEE80211_TL_LOG_INFO)
                printf(" INFO ");
            if(tl_debug_flag & IEEE80211_TL_LOG_WARNING)
                printf(" WARNING ");
            if(tl_debug_flag & IEEE80211_TL_LOG_ERROR)
                printf(" ERROR ");
            printf("]\r\n");
            break;
        /*AUTELAN-Added-End: Added by WangJia, for traffic limit. 2012-11-02.*/
        default :
            return -EFAULT;
    }
    return 0;
}
#endif
/* AUTELAN-End:Added by WangJia for traffic limit. 2012-11-02, transplant by zhouke  */


#if ATOPT_SYNC_INFO
int
ath_ioctl_autelan_sync_info(struct net_device *dev, struct iwreq *iwr)
{
    struct ieee80211_autelan_sync_info ik;
    u_int32_t flag = 0;
    u_int8_t buf[MAX_BUF] = {0};
    
    memset(&ik, 0x00, sizeof(ik));

    if (copy_from_user(&ik, iwr->u.data.pointer, sizeof(ik))) {
        return -EFAULT;
    }

    switch (ik.type) {
        case GET_LOCAL_TABLE:
            iwr->u.data.length = show_local_table(buf);
            copy_to_user(iwr->u.data.pointer, buf, iwr->u.data.length);
            break;
        case GET_NEIGHBOUR_DEV:
            iwr->u.data.length = show_neighbour_dev(buf);
            copy_to_user(iwr->u.data.pointer, buf, iwr->u.data.length);
            break;
        case GET_NEIGHBOUR_TABLE:
            show_neighbour_table();
            //send_sync_info_all();
            break;
        case GET_NEIGHBOUR_STA_BY_MAC:
            iwr->u.data.length = show_neighbour_user_by_mac(buf,ik.sta_mac);
            copy_to_user(iwr->u.data.pointer, buf, iwr->u.data.length);
            break;
        case SYNC_SWITCH:
            set_sync_switch(ik.arg1);
            break;
        case GET_SYNC_SWITCH:
            flag = get_sync_switch();            
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));
            break;
        case SYNC_DEBUG:
            set_sync_debug(ik.arg1);
            break;
        case GET_SYNC_DEBUG:
            flag = get_sync_debug();            
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));
            break;
        case SYNC_TIME:
            set_sync_time(ik.arg1);
            break;
        case GET_SYNC_TIME:
            flag = get_sync_time();
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));
            break;
        case GET_SCAN_LIST:
            show_scan_list();
            break;
        case SYNC_AUTO_GROUP:
            set_sync_auto_group(ik.arg1);
            break;
        case GET_SYNC_AUTO_GROUP:
            flag = get_sync_auto_group();            
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));
            break;
        case SYNC_NEIGHBOR_RSSI_LIMIT:
            set_sync_neighbor_rssi_limit(ik.arg1);
            break;
        case GET_SYNC_NEIGHBOR_RSSI_LIMIT:
            flag = get_sync_neighbor_rssi_limit();            
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));
            break;
        default :
            return -EFAULT;
    }
    return 0;
}

int
ath_ioctl_autelan_connect_rule(struct net_device *dev, struct iwreq *iwr)
{
    struct ieee80211_autelan_sync_info ik;
    u_int32_t flag = 0;

    memset(&ik, 0x00, sizeof(ik));

    if (copy_from_user(&ik, iwr->u.data.pointer, sizeof(ik))) {
        return -EFAULT;
    }

    switch (ik.type) {
        case CONNECT_TO_BEST_DEBUG:
            set_connect_to_best_debug(ik.arg1);
            break;
        case GET_CONNECT_TO_BEST_DEBUG:
            flag = get_connect_to_best_debug();            
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));
            break;
        case CONNECT_TO_BEST:
            set_connect_to_best(ik.arg1);
            break;
        case GET_CONNECT_TO_BEST:
            flag = get_connect_to_best();
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));        
        case CONNECT_BALANCE:
            set_connect_balance(ik.arg1);
            break;
        case GET_CONNECT_BALANCE:
            flag = get_connect_balance();
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));
        case MAX_DV:
            set_max_dv(ik.arg1);
            break;
        case GET_MAX_DV:
            flag = get_max_dv();
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));
            break;
        case INACTIVE_TIME:
            set_inactive_time(ik.arg1);
            break;
        case GET_INACTIVE_TIME:
            flag = get_inactive_time();
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));
            break;
        case WATING_TIME:
            set_wating_time(ik.arg1);
            break;
        case GET_WATING_TIME:
            flag = get_wating_time();
            copy_to_user(iwr->u.data.pointer, &(flag), sizeof(flag));
            break;
        default :
            return -EFAULT;
    }
    return 0;
}
#endif
/* AUTELAN-End: Added by zhouke for sync info.2015-02-06*/