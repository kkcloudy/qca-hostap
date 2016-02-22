/* ***************************************************************
 * Filename: drv_monitor.c
 * Description: a module for wireless modules stuck monitor.
 * Project: Autelan ap 2015
 * Author: zhaoenjuan
 * Date: 2015-01-20
 ****************************************************************/

#include "if_athvar.h"
#include "drv_monitor.h"
#include <linux/platform_device.h>

u_int32_t hw_tx_buffer_monitor(struct ath_softc *sc)
{
    u_int32_t ret = AUTE_DRV_NO_ERR;
	
    if(bmiss_check != 0)
    {
        if(bstuck_check_num > bmiss_check)
        {
            printk("Warning,continues hw beacon stuck\n");
            printk("autelan--%s: stuck beacon; resetting(bmiss count %u),bb_hang=%d,mac_hang=%d,bstuck_check_num=%u,beacon_complete=%u\n",
               __func__, sc->sc_bmisscount,bb_hang,mac_hang,bstuck_check_num,beacon_complete);
            if(kes_debug_print_handle)
            {
                kes_debug_print_handle(KERN_EMERG "Warning,continues hw beacon stuck\n");
                kes_debug_print_handle(KERN_EMERG "autelan--%s: stuck beacon; resetting(bmiss count %u),bb_hang=%d,mac_hang=%d,bstuck_check_num=%u,beacon_complete=%u\n",
               __func__, sc->sc_bmisscount,bb_hang,mac_hang,bstuck_check_num,beacon_complete);
            }
            ret = AUTE_DRV_HW_STUCK_ERR;
        }
        else
        {
            bstuck_check_num = 0;
        }
    }
    if((aute_bb_hang_check!=0)||(aute_mac_hang_check!=0))
    {
        if((bb_hang > aute_bb_hang_check)||(mac_hang > aute_mac_hang_check))
        {
            printk("Warning,continues hw bb_hang or mac_hang stuck\n");
            printk("autelan--%s:bb_hang=%d,mac_hang=%d\n",__func__, bb_hang,mac_hang);
            if(kes_debug_print_handle)
            {
                kes_debug_print_handle(KERN_EMERG "Warning,continues hw bb_hang or mac_hang stuck\n");
                kes_debug_print_handle(KERN_EMERG "autelan--%s:bb_hang=%d,mac_hang=%d\n",__func__, bb_hang,mac_hang);
            }
            if(!autelan_drv_hang_reboot)
            {
                bb_hang = 0;
                mac_hang = 0;
            }
            ret = AUTE_DRV_HW_STUCK_ERR;
        }
        else
        {
            bb_hang = 0;
            mac_hang = 0;
        }
    }	
	return ret;	

}
u_int32_t soft_tx_buffer_monitor(struct ath_softc *sc)
{
    u_int32_t pkts_sum = 0;
    u_int32_t aggr_pkts_sum = 0;
    u_int32_t nobuf_sum = 0;    
    static u_int32_t last_pkts_sum[2] = {0};
    static u_int32_t last_aggr_pkts_sum[2] = {0};
    static u_int32_t last_nobuffs_sum[2] = {0};
	u_int8_t wifi_num = 0;
	if(memcmp(sc->sc_osdev->netdev->name,"wifi0",5) == 0)
	{
		wifi_num = 0;
	}
	else if(memcmp(sc->sc_osdev->netdev->name,"wifi1",5) == 0)
	{
		wifi_num = 1;
	}
    //monitor the data queue stats
   pkts_sum = sc->sc_stats.ast_txq_packets[0]+sc->sc_stats.ast_txq_noaggr_packets[0];
    pkts_sum += sc->sc_stats.ast_txq_packets[1]+sc->sc_stats.ast_txq_noaggr_packets[1];
    pkts_sum += sc->sc_stats.ast_txq_packets[2]+sc->sc_stats.ast_txq_noaggr_packets[2];
    pkts_sum += sc->sc_stats.ast_txq_packets[3]+sc->sc_stats.ast_txq_noaggr_packets[3];
    aggr_pkts_sum = sc->sc_stats.ast_txq_packets[0];
    aggr_pkts_sum += sc->sc_stats.ast_txq_packets[1];
    aggr_pkts_sum += sc->sc_stats.ast_txq_packets[2];
    aggr_pkts_sum += sc->sc_stats.ast_txq_packets[3];
    nobuf_sum = sc->sc_stats.ast_txq_nobuf[0] + sc->sc_stats.ast_txq_nobuf[1];
   nobuf_sum += sc->sc_stats.ast_txq_nobuf[2];
    nobuf_sum += sc->sc_stats.ast_txq_nobuf[3];
	/*According to protocol stack downstream statistic count, the subsequent to add*/
    //lutao tag ast_tx_from_stack
    //if(last_tx_from_stack != sc->sc_stats.ast_tx_from_stack)  
    {
        /*can not put new packets to the defered queue*/	
        if(pkts_sum == last_pkts_sum[wifi_num])
        {
            /*can not malloc new bf for the packet, nobuf continue increase*/
            if(last_nobuffs_sum[wifi_num] != nobuf_sum)
            {
                printk("Can not malloc new buffer for the packet.\n");
                printk("packet tx cur=%d,old=%d,nobuf=%d,oldnobuf=%d\n",pkts_sum,last_pkts_sum[wifi_num],nobuf_sum,last_nobuffs_sum[wifi_num]);
				printk("pkts_sum[0] = %u,\ttxq_packets[0] = %u,\ttxq_noaggr_packets[0] = %u,\ttxq_nobuf[0] = %u\n",
					sc->sc_stats.ast_txq_packets[0]+sc->sc_stats.ast_txq_noaggr_packets[0],
					sc->sc_stats.ast_txq_packets[0],sc->sc_stats.ast_txq_noaggr_packets[0],sc->sc_stats.ast_txq_nobuf[0]);
				printk("pkts_sum[1] = %u,\ttxq_packets[1] = %u,\ttxq_noaggr_packets[1] = %u,\ttxq_nobuf[1] = %u\n",
					sc->sc_stats.ast_txq_packets[1]+sc->sc_stats.ast_txq_noaggr_packets[1],
					sc->sc_stats.ast_txq_packets[1],sc->sc_stats.ast_txq_noaggr_packets[1],sc->sc_stats.ast_txq_nobuf[1]);
				printk("pkts_sum[2] = %u,\ttxq_packets[2] = %u,\ttxq_noaggr_packets[2] = %u,\ttxq_nobuf[2] = %u\n",
					sc->sc_stats.ast_txq_packets[2]+sc->sc_stats.ast_txq_noaggr_packets[2],
					sc->sc_stats.ast_txq_packets[2],sc->sc_stats.ast_txq_noaggr_packets[2],sc->sc_stats.ast_txq_nobuf[2]);
				printk("pkts_sum[3] = %u,\ttxq_packets[3] = %u,\ttxq_noaggr_packets[3] = %u,\ttxq_nobuf[3] = %u\n",
					sc->sc_stats.ast_txq_packets[3]+sc->sc_stats.ast_txq_noaggr_packets[3],
					sc->sc_stats.ast_txq_packets[3],sc->sc_stats.ast_txq_noaggr_packets[3],sc->sc_stats.ast_txq_nobuf[3]);

                printk("soft_tx_buffer_monitor: Find soft queue stuck, reason maybe is:memory leak/hw stuck/no tasklet schedule\n");
				printk("ath_tx_schedule states:aute_tx_schedule = %u, tx_schednone = %u\n",sc->sc_stats.ast_11n_stats.aute_tx_schedule,sc->sc_stats.ast_11n_stats.tx_schednone);
                if(kes_debug_print_handle)
                {
                    kes_debug_print_handle(KERN_EMERG "Can not malloc new buffer for the packet.\n");
                    kes_debug_print_handle(KERN_EMERG "packet tx cur=%d,old=%d,nobuf=%d,oldnobuf=%d\n",pkts_sum,last_pkts_sum[wifi_num],nobuf_sum,last_nobuffs_sum[wifi_num]);
					kes_debug_print_handle(KERN_EMERG "pkts_sum[0] = %u,\ttxq_packets[0] = %u,\ttxq_noaggr_packets[0] = %u,\ttxq_nobuf[0] = %u\n",
						sc->sc_stats.ast_txq_packets[0]+sc->sc_stats.ast_txq_noaggr_packets[0],sc->sc_stats.ast_txq_packets[0],sc->sc_stats.ast_txq_noaggr_packets[0],sc->sc_stats.ast_txq_nobuf[0]);
					kes_debug_print_handle(KERN_EMERG "pkts_sum[1] = %u,\ttxq_packets[1] = %u,\ttxq_noaggr_packets[1] = %u,\ttxq_nobuf[1] = %u\n",
						sc->sc_stats.ast_txq_packets[1]+sc->sc_stats.ast_txq_noaggr_packets[1],sc->sc_stats.ast_txq_packets[1],sc->sc_stats.ast_txq_noaggr_packets[1],sc->sc_stats.ast_txq_nobuf[1]);
					kes_debug_print_handle(KERN_EMERG "pkts_sum[2] = %u,\ttxq_packets[2] = %u,\ttxq_noaggr_packets[2] = %u,\ttxq_nobuf[2] = %u\n",
						sc->sc_stats.ast_txq_packets[2]+sc->sc_stats.ast_txq_noaggr_packets[2],sc->sc_stats.ast_txq_packets[2],sc->sc_stats.ast_txq_noaggr_packets[2],sc->sc_stats.ast_txq_nobuf[2]);
					kes_debug_print_handle(KERN_EMERG "pkts_sum[3] = %u,\ttxq_packets[3] = %u,\ttxq_noaggr_packets[3] = %u,\ttxq_nobuf[3] = %u\n",
						sc->sc_stats.ast_txq_packets[3]+sc->sc_stats.ast_txq_noaggr_packets[3],sc->sc_stats.ast_txq_packets[3],sc->sc_stats.ast_txq_noaggr_packets[3],sc->sc_stats.ast_txq_nobuf[3]);
					kes_debug_print_handle(KERN_EMERG "soft_tx_buffer_monitor: Find soft queue stuck, reason maybe is:memory leak/hw stuck/no tasklet schedule\n");
                    kes_debug_print_handle(KERN_EMERG "ath_tx_schedule states:aute_tx_schedule = %u, tx_schednone = %u\n",sc->sc_stats.ast_11n_stats.aute_tx_schedule,sc->sc_stats.ast_11n_stats.tx_schednone);
                }
                //last_tx_from_stack = sc->sc_stats.ast_tx_from_stack;
                last_pkts_sum[wifi_num] = pkts_sum;
                last_nobuffs_sum[wifi_num] = nobuf_sum;
                return AUTE_DRV_SOFT_TX_STUCK_ERR;	
            }
            else
            {
                printk("soft_tx_buffer_monitor: Can not put the packet to the deferred queue, but there is available buffer\n");//should not be here do nothing,if here, fix me
                if(kes_debug_print_handle)
                {
                    kes_debug_print_handle(KERN_WARNING "soft_tx_buffer_monitor: Can not put the packet to the deferred queue, but there is available buffer\n");
                }
            }
        }
        else if(aggr_pkts_sum == last_aggr_pkts_sum[wifi_num])
        {
            /*can not malloc new bf for the packet, nobuf continue increase*/
            if(last_nobuffs_sum[wifi_num] != nobuf_sum)
            {
                {
                    printk("soft_buffer_monitor: find hw queue stuck, reset the hardware queue...\n");
                    if(kes_debug_print_handle)
                    {
                        kes_debug_print_handle(KERN_EMERG "soft_buffer_monitor: find hw queue stuck, reset the hardware queue...\n");
                    }
                    autelan_get_queueinfo(sc);
                    OS_DELAY(1000000);
                    autelan_get_queueinfo(sc);
                    sc->sc_reset_type = ATH_RESET_NOLOSS;
                    ath_internal_reset(sc);
                    ath_radio_disable(sc);
                    ath_radio_enable(sc);	
                    sc->sc_reset_type = ATH_RESET_DEFAULT;
                    sc->sc_stats.ast_resetOnError++;
                    last_aggr_pkts_sum[wifi_num] = aggr_pkts_sum;
                    last_nobuffs_sum[wifi_num] = nobuf_sum;
                    return AUTE_DRV_HW_STUCK_ERR;					
                }
  
    			
                //last_tx_from_stack = sc->sc_stats.ast_tx_from_stack;
                last_aggr_pkts_sum[wifi_num] = aggr_pkts_sum;
                last_nobuffs_sum[wifi_num] = nobuf_sum;
                return AUTE_DRV_SOFT_TX_STUCK_ERR;	
            }
        }
    }
	if(data_txq)
	{
		printk("\n*****************************soft_tx_buffer_monitor debug--start**************************\n");
		printk("pkts_sum[0] = %u,\ttxq_packets[0] = %u,\ttxq_noaggr_packets[0] = %u,\ttxq_nobuf[0] = %u\n",
			sc->sc_stats.ast_txq_packets[0]+sc->sc_stats.ast_txq_noaggr_packets[0],
			sc->sc_stats.ast_txq_packets[0],sc->sc_stats.ast_txq_noaggr_packets[0],sc->sc_stats.ast_txq_nobuf[0]);
		printk("TXQ[0]:axq_num_buf_used = %d,\taxq_minfree = %d,\tsc_txbuf_free = %d\n\n",
	 		sc->sc_txq[0].axq_num_buf_used,sc->sc_txq[0].axq_minfree,sc->sc_txbuf_free);
		printk("pkts_sum[1] = %u,\ttxq_packets[1] = %u,\ttxq_noaggr_packets[1] = %u,\ttxq_nobuf[1] = %u\n",
			sc->sc_stats.ast_txq_packets[1]+sc->sc_stats.ast_txq_noaggr_packets[1],
			sc->sc_stats.ast_txq_packets[1],sc->sc_stats.ast_txq_noaggr_packets[1],sc->sc_stats.ast_txq_nobuf[1]);
		printk("TXQ[1]:axq_num_buf_used = %d,\taxq_minfree = %d,\tsc_txbuf_free = %d\n\n",
	 		sc->sc_txq[1].axq_num_buf_used,sc->sc_txq[1].axq_minfree,sc->sc_txbuf_free);
		printk("pkts_sum[2] = %u,\ttxq_packets[2] = %u,\ttxq_noaggr_packets[2] = %u,\ttxq_nobuf[2] = %u\n",
			sc->sc_stats.ast_txq_packets[2]+sc->sc_stats.ast_txq_noaggr_packets[2],
			sc->sc_stats.ast_txq_packets[2],sc->sc_stats.ast_txq_noaggr_packets[2],sc->sc_stats.ast_txq_nobuf[2]);
		printk("TXQ[2]:axq_num_buf_used = %d,\taxq_minfree = %d,\tsc_txbuf_free = %d\n\n",
	 		sc->sc_txq[2].axq_num_buf_used,sc->sc_txq[2].axq_minfree,sc->sc_txbuf_free);
		printk("pkts_sum[3] = %u,\ttxq_packets[3] = %u,\ttxq_noaggr_packets[3] = %u,\ttxq_nobuf[3] = %u\n",
			sc->sc_stats.ast_txq_packets[3]+sc->sc_stats.ast_txq_noaggr_packets[3],
			sc->sc_stats.ast_txq_packets[3],sc->sc_stats.ast_txq_noaggr_packets[3],sc->sc_stats.ast_txq_nobuf[3]);
		printk("TXQ[3]:axq_num_buf_used = %d,\taxq_minfree = %d,\tsc_txbuf_free = %d\n\n",
	 		sc->sc_txq[3].axq_num_buf_used,sc->sc_txq[3].axq_minfree,sc->sc_txbuf_free);
		printk("ath_tx_schedule states:aute_tx_schedule = %u, tx_schednone = %u\n",
			sc->sc_stats.ast_11n_stats.aute_tx_schedule,sc->sc_stats.ast_11n_stats.tx_schednone);
		printk("tid_period_sec= %d,\ttid_period_us= %d,\tps_bufcnt = %u,\tps_acqcnt = %u\n",
			tid_period_sec,tid_period_us,ps_bufcnt,ps_acqcnt);
		printk("*******************************soft_tx_buffer_monitor debug--end****************************\n");
	}
    //last_tx_from_stack = sc->sc_stats.ast_tx_from_stack;
    last_pkts_sum[wifi_num] = pkts_sum;    
    last_aggr_pkts_sum[wifi_num] = aggr_pkts_sum;
    last_nobuffs_sum[wifi_num] = nobuf_sum;
    return AUTE_DRV_NO_ERR;	
}
u_int32_t soft_rx_buffer_monitor(struct ath_softc *sc)
{
    static u_int32_t rx_intr_last_times[2] = {0};
    static u_int32_t rx_stuck_times[2] = {0};
    static u_int32_t rx_stuck_intr[2] = {0};
    static u_int32_t rx_stuck_hplp[2] = {0};
    static u_int32_t loop_n = 0;
    static u_int32_t rx_pkts_stuck_times[2] = {0}, rx_pkts_last_time[2] = {0};
    u_int8_t wifi_num = 0;
	
    if(memcmp(sc->sc_osdev->netdev->name,"wifi0",5) == 0)
    {
        wifi_num = 0;
    }
    else if(memcmp(sc->sc_osdev->netdev->name,"wifi1",5) == 0)
    {
        wifi_num = 1;
    }
    if (atomic_read(&sc->sc_nap_vaps_up)) //check whether any vap is up
    {
        loop_n++;
        if((1 == wifi_num) && ((loop_n % 3)  != 0))//per 5*3=15 sec check wifi1
            return AUTE_DRV_NO_ERR;
        
        if (0 == sc->sc_stats.ast_11n_stats.rx_pkts) {
            rx_pkts_stuck_times[wifi_num]++;
        } else if (0 == rx_pkts_last_time[wifi_num]) {
            rx_pkts_last_time[wifi_num] = sc->sc_stats.ast_11n_stats.rx_pkts;
        } else if (rx_pkts_last_time[wifi_num] == sc->sc_stats.ast_11n_stats.rx_pkts) {
            drv_rx_buffer_dump(sc);
            rx_pkts_stuck_times[wifi_num]++;
        } else {
            rx_pkts_stuck_times[wifi_num] = 0;
            rx_pkts_last_time[wifi_num] = sc->sc_stats.ast_11n_stats.rx_pkts;
        }

        if (0 == sc->sc_stats.ast_rx) //check whether the rx interrupt is zero
        {
            rx_stuck_times[wifi_num]++;
        }
        else if (0 == rx_intr_last_times[wifi_num]) //check whether the old rx interrupt is initial value
        {    
            rx_pkts_last_time[wifi_num] = sc->sc_stats.ast_rx;
        }
        else if (rx_intr_last_times[wifi_num] == sc->sc_stats.ast_rx) //check whether the rx interrupt is not change
        {
        	drv_rx_buffer_dump(sc);
            rx_stuck_times[wifi_num]++;
        }
        else
        {        	
            rx_intr_last_times[wifi_num] = sc->sc_stats.ast_rx; //the rx intr is change, reset the stuck times           
            if((rx_stuck_intr[wifi_num] != (sc->sc_stats.ast_rxorn + sc->sc_stats.ast_rxeol)) &&
				(rx_stuck_hplp[wifi_num] == (sc->rx_hp_cnt + sc->rx_lp_cnt)))
            {
            
                printk("soft_rx_buffer_monitor: Find hw queue stuck, reason is:no packets in the rxqueue\n");
                printk("rx_stuck_intr[%d] = %u,rx_stuck_hplp[%d] = %u\n",wifi_num,rx_stuck_intr[wifi_num],wifi_num,rx_stuck_hplp[wifi_num]);
                if(kes_debug_print_handle)
                {
                    kes_debug_print_handle(KERN_EMERG "soft_rx_buffer_monitor: Find hw queue stuck, reason is:no packets in the rxqueue\n");
                    kes_debug_print_handle(KERN_EMERG "rx_stuck_intr[%d] = %u,rx_stuck_hplp[%d] = %u\n",wifi_num,rx_stuck_intr[wifi_num],wifi_num,rx_stuck_hplp[wifi_num]);
                }
                drv_rx_buffer_dump(sc);
                rx_stuck_intr[wifi_num] = sc->sc_stats.ast_rxorn + sc->sc_stats.ast_rxeol;
                rx_stuck_hplp[wifi_num] = sc->rx_hp_cnt + sc->rx_lp_cnt;
                rx_stuck_times[wifi_num]++; 
            }
            else
            {
                rx_stuck_intr[wifi_num] = sc->sc_stats.ast_rxorn + sc->sc_stats.ast_rxeol;
                rx_stuck_hplp[wifi_num] = sc->rx_hp_cnt + sc->rx_lp_cnt;
                rx_stuck_times[wifi_num] = 0; 
            }
        }

        if (2 < rx_stuck_times[wifi_num]) //check whether the rx stuck times greater than 3
        {   
            printk("soft_rx_buffer_monitor: Find soft queue stuck, reason is:rx interrupt is not change for a long time\n");
			printk("sc->sc_stats.ast_rx = %u,rx_intr_last_times[%d] = %u\n",sc->sc_stats.ast_rx,wifi_num,rx_intr_last_times[wifi_num]);
            if(kes_debug_print_handle)
            {
                kes_debug_print_handle(KERN_EMERG "soft_rx_buffer_monitor: Find soft queue stuck, reason is:rx interrupt is not change for a long time\n");
                kes_debug_print_handle(KERN_EMERG "sc->sc_stats.ast_rx = %u,rx_intr_last_times[%d] = %u\n",sc->sc_stats.ast_rx,wifi_num,rx_intr_last_times[wifi_num]);
            }
			drv_rx_buffer_dump(sc);
            sc->sc_reset_type = ATH_RESET_NOLOSS;
            ath_internal_reset(sc);
            ath_radio_disable(sc);
            ath_radio_enable(sc);           
            sc->sc_reset_type = ATH_RESET_DEFAULT;
            sc->sc_stats.ast_resetOnError++;
            rx_stuck_times[wifi_num] = 0; 
            
            return AUTE_DRV_SOFT_RX_STUCK_ERR;
        }


        if (2 < rx_pkts_stuck_times[wifi_num]) //check whether the rx pkts stuck times greater than 3
        {   
            printk("soft_rx_buffer_monitor: Find soft queue stuck, reason is:rx pkts is not change for a long time\n");
			printk("sc->sc_stats.ast_11n_stats.rx_pkts = %u,rx_pkts_last_time[%d] = %u\n",sc->sc_stats.ast_11n_stats.rx_pkts, wifi_num,rx_pkts_last_time[wifi_num]);
            if(kes_debug_print_handle)
            {
                kes_debug_print_handle(KERN_EMERG "soft_rx_buffer_monitor: Find soft queue stuck, reason is:rx pkts is not change for a long time\n");
			    kes_debug_print_handle(KERN_EMERG "sc->sc_stats.ast_11n_stats.rx_pkts = %u,rx_pkts_last_time[%d] = %u\n",sc->sc_stats.ast_11n_stats.rx_pkts, wifi_num,rx_pkts_last_time[wifi_num]);
            }
			drv_rx_buffer_dump(sc);
            sc->sc_reset_type = ATH_RESET_NOLOSS;
            ath_internal_reset(sc);
            ath_radio_disable(sc);
            ath_radio_enable(sc);           
            sc->sc_reset_type = ATH_RESET_DEFAULT;
            sc->sc_stats.ast_resetOnError++;
            rx_pkts_stuck_times[wifi_num] = 0; 
            
            return AUTE_DRV_SOFT_RX_STUCK_ERR;
        }
    }
    return AUTE_DRV_NO_ERR;	

}

void aute_tx_node_queue_stats(struct ath_softc *sc)
{
	int tidno;
	struct ath_atx_tid *tid;
	int count=0,total_count=0;
	struct ath_buf *bf;
	struct ieee80211com *ic =NULL;
	struct ieee80211_node *ni= NULL;
	struct ieee80211_node_table *nt = NULL;
	struct ieee80211vap *vap = NULL;
	
	ic = (struct ieee80211com *)(sc->sc_ieee);
	nt = &ic->ic_sta; 

	TAILQ_FOREACH(ni, &nt->nt_node, ni_list)
	{
		struct ath_node *an = ((struct ath_node_net80211 *)(ni))->an_sta;
		int is_bss = 0;
		TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next)
		{	
			if(vap->iv_bss == ni)
			{
				is_bss = 1;
				break;
			}	
		}
		
		if(is_bss == 1)
		{
			continue;
		}

		for (tidno = 0; tidno < WME_AC_BK/*WME_NUM_TID*/; tidno++) {
			
			//tid = &an->an_tx_tid[tidno];
			tid = ATH_AN_2_TID(an, tidno);
			bf = TAILQ_FIRST(&tid->buf_q);
			if (bf == NULL) {
				printk("TID %d (tid %p) has no buffered packet\n",tidno, tid);
				printk("%s: NODE[%s] TID:[%d] frames: %d seqstart %d paused %d sched %d pause-period sec:%d,us:%d addtrace(%d|%d|%d|%d|%d|%d|%d|%d)  subtrace(%d|%d|%d|%d|%d|%d|%d|%d) add index=%d,sub index=%d"
						,__func__,ether_sprintf(ni->ni_macaddr), tidno, count, tid->seq_start,tid->paused,tid->sched,tid->paused_period_sec,tid->paused_period_us,
						tid->add_paused_trace[0],tid->add_paused_trace[1],tid->add_paused_trace[2],tid->add_paused_trace[3],
						tid->add_paused_trace[4],tid->add_paused_trace[5],tid->add_paused_trace[6],tid->add_paused_trace[7],
						tid->sub_paused_trace[0],tid->sub_paused_trace[1],tid->sub_paused_trace[2],tid->sub_paused_trace[3],
						tid->sub_paused_trace[4],tid->sub_paused_trace[5],tid->sub_paused_trace[6],tid->sub_paused_trace[7],
						tid->add_trace_index,tid->sub_trace_index);
				printk("baw num=%d, pause num=%d, depth num=%d, tid period sec=%d: us = %d\n"
				,tid->error_trace_baw,tid->error_trace_pause,tid->error_trace_depth,tid_period_sec,tid_period_us);
				continue;
			}
			count=0;
			while(bf) {
				bf = TAILQ_NEXT(bf, bf_list);
				++count;
			}

			printk("%s: NODE[%s] TID:[%d] frames: %d seqstart %d paused %d sched %d pause-period sec:%d,us:%d addtrace(%d|%d|%d|%d|%d|%d|%d|%d)  subtrace(%d|%d|%d|%d|%d|%d|%d|%d) add index=%d,sub index=%d\n"
					,__func__,ether_sprintf(ni->ni_macaddr), tidno, count, tid->seq_start,tid->paused,tid->sched,tid->paused_period_sec,tid->paused_period_us,
					tid->add_paused_trace[0],tid->add_paused_trace[1],tid->add_paused_trace[2],tid->add_paused_trace[3],
					tid->add_paused_trace[4],tid->add_paused_trace[5],tid->add_paused_trace[6],tid->add_paused_trace[7],
					tid->sub_paused_trace[0],tid->sub_paused_trace[1],tid->sub_paused_trace[2],tid->sub_paused_trace[3],
					tid->sub_paused_trace[4],tid->sub_paused_trace[5],tid->sub_paused_trace[6],tid->sub_paused_trace[7],
					tid->add_trace_index,tid->sub_trace_index);

				printk("baw num=%d, pause num=%d, depth num=%d, txq period sec=%d: us = %d\n"
				,tid->error_trace_baw,tid->error_trace_pause,tid->error_trace_depth,tid_period_sec,tid_period_us);
		}
		total_count = total_count + count;
	}	
	printk("%s,Total buffered packet counter in the defered queue [%d]\n", __func__,total_count);

}
void aute_dump_tid_buf(struct ath_softc *sc)
{
    
	struct ath_txq *txq;
	struct ath_atx_ac *ac;
	struct ath_atx_tid *tid;
    u_int32_t q_num;
	int axq_cnt = 0, j = 0, bufQCount = 0, tidBufcnt = 0, pertidBufcnt;
	struct ath_buf *buf;
	printk(" Free buffer count %d \n", sc->sc_txbuf_free);

	for (q_num= 0; q_num < HAL_NUM_TX_QUEUES;q_num++) 
    {
		if (ATH_TXQ_SETUP(sc, q_num)) 
        {
			printk("\nsc_txq[%d] : ", q_num);
            ATH_TXBUF_LOCK(sc);
			txq = &sc->sc_txq[q_num];
            ATH_TXBUF_UNLOCK(sc);    
			TAILQ_FOREACH(ac, &txq->axq_acq, ac_qelem) 
            {
				TAILQ_FOREACH(tid, &ac->tid_q, tid_qelem) 
                {
					pertidBufcnt = 0;
					for (j = 0;j < ATH_TID_MAX_BUFS; j++) 
                    {
						if (TX_BUF_BITMAP_IS_SET(tid->tx_buf_bitmap, j)){

                            tidBufcnt++;
						}
					}
					
					TAILQ_FOREACH(buf, &tid->buf_q, bf_list) {
						
						
						bufQCount ++;
						pertidBufcnt++;
						}
					printk("\n");
					printk("\npertidBufCount %d \n  ",pertidBufcnt);

					printk("seqstart %d paused %d sched %d filtered %d cleanup %d seqnext %d addbastate %d\n", 
						tid->seq_start,tid->paused,tid->sched,tid->filtered,tid->cleanup_inprogress,tid->seq_next,tid->addba_exchangecomplete);
					printk("bawhead %d bawtail %d\n", tid->baw_head,tid->baw_tail);
					printk("\n ------------------------------- \n");

				}
			}
			TAILQ_FOREACH(buf, &txq->axq_q, bf_list) {
				axq_cnt ++;
				}
			printk("\nsc_txq[%d] : depth  is %d \n aggr_depth is %d tidBufcnt %d  bufQcnt %d axq_cnt %d\n  ", txq->axq_qnum, txq->axq_depth, txq->axq_aggr_depth, tidBufcnt, bufQCount, axq_cnt);
			
        }
    }

}

void aute_dump_txq_desc(struct ath_softc *sc, struct ath_txq *txq)
{
     struct ath_hal *ah = sc->sc_ah;
     struct ath_buf *bf,*lastbf;
     struct ath_desc *ds, *ds0;
     HAL_STATUS status;
     u_int32_t loop_num = 0;
     u_int8_t  tailindex = txq->axq_tailindex;

     printk("%s: TXQ[%d] TXDP 0x%08x txq->axq_depth %d pending %d\n",__func__,
         txq->axq_qnum, ath_hal_gettxbuf(sc->sc_ah,txq->axq_qnum), txq->axq_depth, ath_hal_numtxpending(sc->sc_ah,txq->axq_qnum));
	 printk("TXQ[%d]:axq_num_buf_used = %d,axq_minfree = %d,sc_txbuf_free = %d\n\n",
	 	txq->axq_qnum,txq->axq_num_buf_used,txq->axq_minfree,sc->sc_txbuf_free);

	 if (sc->sc_enhanceddmasupport)
     {
         ATH_TXQ_LOCK(txq);
         bf = TAILQ_FIRST(&txq->axq_fifo[tailindex]);
         ATH_TXQ_UNLOCK(txq);
    	 
         if (bf == NULL) {
             printk("%s:HW no buffered packet for queue %d \n",__func__,txq->axq_qnum);
             if (txq->axq_headindex != txq->axq_tailindex)
                 printk("aute_dump_txq_desc: ERR head %d tail %d!!!\n",txq->axq_headindex, txq->axq_tailindex);
             return;
         }
         printk("%s: Stuck descriptor dump for queue %d \n",__func__,txq->axq_qnum);

	 while(tailindex < txq->axq_headindex)
	 {
             TAILQ_FOREACH(bf, &txq->axq_fifo[tailindex], bf_list) {
                 ATH_TXQ_LOCK(txq);
                 ds0 = (struct ath_desc *)bf->bf_desc;
                 ds = ds0;
                 status = ath_hal_txprocdesc(ah, ds);
                 
                 if (status == HAL_EINPROGRESS) {
                     //aute_dump_desc(sc,bf,txq->axq_qnum);
                 }
                 ATH_TXQ_UNLOCK(txq);
                 loop_num++;
             }
             tailindex++;
        }
     } 
     else
     {
         ATH_TXQ_LOCK(txq);
         bf = TAILQ_FIRST(&txq->axq_q);
         ATH_TXQ_UNLOCK(txq);
    	 
         if (bf == NULL) {
             printk("%s: no buffered packet for queue %d \n",__func__,txq->axq_qnum);
             return;
         }
         printk("%s: Stuck descriptor dump for queue %d \n",__func__,txq->axq_qnum);
	 
         TAILQ_FOREACH(bf, &txq->axq_q, bf_list) {
             ATH_TXQ_LOCK(txq);
             ds0 = (struct ath_desc *)bf->bf_desc;
             ds = ds0;
             status = ath_hal_txprocdesc(ah, ds);
         
             if (status == HAL_EINPROGRESS) {
                 //aute_dump_desc(sc,bf,txq->axq_qnum);
             }
			 
             ATH_TXQ_UNLOCK(txq);
             loop_num++;
         }
     }
     
     printk("%s: total bufferd  packet for "
         " queue %d number = %d\n",__func__,txq->axq_qnum, loop_num);

}


void softsc_buffer_dump(struct ath_softc *sc)
{
    struct ath_buf *bf;
    u_int32_t loop_num = 0;
		
    ATH_TXBUF_LOCK(sc);
    bf = TAILQ_FIRST(&sc->sc_txbuf);
    ATH_TXBUF_UNLOCK(sc);
	
    if (bf == NULL) {
        printk( "softsc_buffer_dump -- Warning: No abailable buffers for packet transmit, sc_txbuf_free=%d\n",sc->sc_txbuf_free);
        return;
    }
    
    TAILQ_FOREACH(bf, &sc->sc_txbuf, bf_list){
        ATH_TXBUF_LOCK(sc);
        //could dump all the bufffer pointer here
        ATH_TXBUF_UNLOCK(sc);
        loop_num++;
    }

    printk("Soft buffer dump end, available buffer number = %u,but sc_txbuf_free=%d\n",loop_num,sc->sc_txbuf_free);
	
}

u_int32_t drv_tx_buffer_dump(struct ath_softc *sc)
{
    printk("\n-------------------------------------Soft buffer info--------------------------------------\n");	
    softsc_buffer_dump(sc);
    printk("\n-------------------------------------------------------------------------------------------\n");


    printk("\n-----------------------------Deferred handle queue buffer info-----------------------------\n");
    aute_tx_node_queue_stats(sc);
    printk("\n-------------------------------------------------------------------------------------------\n");


    printk("\n-------------------------------------HW queue buffer info----------------------------------\n");
    aute_dump_txq_desc(sc, &sc->sc_txq[0]);
    aute_dump_txq_desc(sc, &sc->sc_txq[1]);
    aute_dump_txq_desc(sc, &sc->sc_txq[2]);
    aute_dump_txq_desc(sc, &sc->sc_txq[3]);
    aute_dump_txq_desc(sc, sc->sc_cabq);
    printk("\n-------------------------------------------------------------------------------------------\n");

    printk("\n------------------------------------Pending ac-tid info------------------------------------\n");
    aute_dump_tid_buf(sc);
    printk("\n-------------------------------------------------------------------------------------------\n");

    return AUTE_MONITOR_REBOOT_PERIOD;

}

u_int32_t drv_rx_buffer_dump(struct ath_softc *sc)	
{
	struct ath_rx_edma *rxedma;	
	printk("####################%s RX INFO######################\n", sc->sc_osdev->netdev->name);
	printk("RX rx_tasklet count is %d\n",sc->sc_stats.ast_rx);
	printk("RX overrun count is %d\n",sc->sc_stats.ast_rxorn);
	printk("RX eol count is %d\n",sc->sc_stats.ast_rxeol);
	printk("recv incomplete %d	Null wbuf %d\n",sc->rx_incomplete_cnt,sc->rx_null_cnt);
	printk("recv intr cnt RX_INTR_HP %d	RX_INTR_LP %d RX_INTR %d RX_INTR_NOEDMA %d\n",sc->rx_intr_hp,sc->rx_intr_lp,sc->rx_intr,sc->rx_intr_noedma);
	rxedma = &sc->sc_rxedma[0];
	printk("RX HPQ depth is %d fifo size is %d headidx(%d) tailidx(%d) rx_hp_cnt %d\n",rxedma->rxfifodepth,rxedma->rxfifohwsize,rxedma->rxfifoheadindex,rxedma->rxfifotailindex,sc->rx_hp_cnt);
	rxedma = &sc->sc_rxedma[1];
	printk("RX HPQ depth is %d fifo size is %d headidx(%d) tailidx(%d) rx_lp_cnt %d\n",rxedma->rxfifodepth,rxedma->rxfifohwsize,rxedma->rxfifoheadindex,rxedma->rxfifotailindex,sc->rx_lp_cnt);
	printk("###############################################\n");
    return  AUTE_MONITOR_NO_REBOOT;
}

u_int32_t drv_hw_buffer_dump(struct ath_softc *sc)	
{
    if(autelan_drv_hang_reboot)
    {
        return AUTE_MONITOR_REBOOT_NOW;
    }
    else
    {
        return AUTE_MONITOR_NO_REBOOT;
    }
}
extern u_int32_t watchdog;
void aute_kernel_restart(u_int32_t error_code)
{
    printk("Restating system due to the error:%u.\n",error_code);
    if(kes_debug_print_handle)
    {
        kes_debug_print_handle(KERN_EMERG "Restating system due to the error:%u.\n",error_code);
    }
    //kes_debug_print_flag_handle("E"); 
	watchdog = 0;
	printk("Autelan drv monitor: Watchdog restating system...");
}
EXPORT_SYMBOL(aute_kernel_restart);

/*Currently monitor function is mutually exclusive,
If errors are found in front of the monitor function,following monitor function will not do detection*/
OS_TIMER_FUNC(autelan_drv_monitor)
{
    struct ath_softc *sc;
    OS_GET_TIMER_ARG(sc, struct ath_softc *);
    u_int32_t error_code=0;
    u_int32_t reboot_flag=AUTE_MONITOR_NO_REBOOT;
    static u_int32_t loop_num;
    static u_int32_t last_error;
    struct ieee80211com *ic =NULL;
    struct ieee80211vap *vap = NULL;
    struct ath_hal *ah;   
    int flag =0;
	struct ieee80211_node *ni= NULL;
    struct ieee80211_node_table *nt = NULL;
    int authorized_flag = 0;
	ah = sc->sc_ah;
    if(autelan_drv_monitor_enable == 0)
    {
        OS_SET_TIMER(&sc->sc_drv_monitor, autelan_drv_monitor_period*6);
        return;
    }
    
    ic = (struct ieee80211com *)(sc->sc_ieee);
	nt = &ic->ic_sta;
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next)
    {   
        if(vap->iv_sta_assoc > 0)
        {
            flag =1;
            break;
        }	
    }
    TAILQ_FOREACH(ni, &nt->nt_node, ni_list)
    {
        if(ni->ni_flags & IEEE80211_NODE_AUTH)
        {
            authorized_flag = 1;
            break;
        }
    }

    loop_num++;

    if(autelan_drv_monitor_enable & 0x10)

	{
		autelan_DumpRegs(ah);
        sc->sc_reset_type = ATH_RESET_NOLOSS;
        ath_internal_reset(sc);
        ath_radio_disable(sc);
        ath_radio_enable(sc);           
        sc->sc_reset_type = ATH_RESET_DEFAULT;
        sc->sc_stats.ast_resetOnError++;
        printk("reset radio(%s) by manual.\n",sc->sc_osdev->netdev->name);
		autelan_drv_monitor_enable = (autelan_drv_monitor_enable & 0x0f);
        if(kes_debug_print_handle)
        {
           kes_debug_print_handle(KERN_EMERG "reset radio(%s) by manual.\n",sc->sc_osdev->netdev->name);
        }
    }

    /*If your monitor fun does not care about whether there are associated users or not, 
        add here*/
	if(vap)	//lisongbai add for canel the when there is no vap in the ic.
	{
		if((loop_num % 180)  == 0) //per 3 min check
		{
			error_code = hw_tx_buffer_monitor(sc);
			if(error_code > 0) 
				goto handle;           
		}  
		if((loop_num % 5)  == 0)//per 5 sec check
		{
			error_code = soft_rx_buffer_monitor(sc);
			if(error_code > 0)
				goto handle;  
		}
	}

    if(flag == 0)
    {
        /*if you need add some specific fun for no user associated useage, add here*/
        
    }
    else if(flag == 1 && authorized_flag == 1 )
    {
        /*there are associated users, add monitor fun here*/
       do{
            if((loop_num % 10)  == 0)
            {
                error_code = soft_tx_buffer_monitor(sc);
                if(error_code > 0)	
                    goto handle;
            }
        } while(0);
    }
    
    OS_SET_TIMER(&sc->sc_drv_monitor, autelan_drv_monitor_period);
    return;

handle:

    switch (error_code)
    {
        case AUTE_DRV_SOFT_TX_STUCK_ERR:
            reboot_flag = drv_tx_buffer_dump(sc); //if the monitor need not reboot the system, return the flag to zero
            break;
        case AUTE_DRV_SOFT_RX_STUCK_ERR:
            reboot_flag = drv_rx_buffer_dump(sc);
            break;
        case AUTE_DRV_HW_STUCK_ERR:
            reboot_flag = drv_hw_buffer_dump(sc);
            break;

        default:
            printk("ERROR:autelan_drv_monitor received invalid error code:%u.\n",error_code);
            reboot_flag = 0;
            break;
    }

    if(autelan_drv_monitor_reboot > 0)
    {
        if(reboot_flag == AUTE_MONITOR_REBOOT_PERIOD)
        {
            if(loop_num > 180) //60*3*1000/autelan_drv_monitor_period, 3minutes
            {
                if(loop_num < last_error)
                    last_error = 0;
                
                if((loop_num - last_error) <= 18)
                {
                    aute_kernel_restart(error_code);
                }
                else 
                    last_error = loop_num;
            }
        }
        else if(reboot_flag == AUTE_MONITOR_REBOOT_NOW)
        {
            aute_kernel_restart(error_code);   
        }
    }
	
    OS_SET_TIMER(&sc->sc_drv_monitor, autelan_drv_monitor_period);
    return;
} 
EXPORT_SYMBOL(autelan_drv_monitor);

