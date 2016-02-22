/* ***************************************************************
 * Filename: drv_monitor.c
 * Description: a module for wireless modules stuck monitor.
 * Project: Autelan ap 2015
 * Author: zhaoenjuan
 * Date: 2015-01-20
 ****************************************************************/

#include "ath_internal.h"
#include "if_athvar.h"
#include "drv_monitor.h"
const char *ieee80211_mgt_subtype_name[] = {
    "assoc_req",    "assoc_resp",   "reassoc_req",  "reassoc_resp",
    "probe_req",    "probe_resp",   "reserved#6",   "reserved#7",
    "beacon",       "atim",         "disassoc",     "auth",
    "deauth",       "action",       "reserved#14",  "reserved#15"
};

void
aute_dump_pkt_debug(const u_int8_t *buf)
{
	const struct ieee80211_frame *wh;
	int type, subtype;
	wh = (const struct ieee80211_frame *)buf;
	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	subtype = (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) >> IEEE80211_FC0_SUBTYPE_SHIFT;
	switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) {
		case IEEE80211_FC1_DIR_NODS:
             printk("|  |TID(NODE MAC: %s TIME STAMP: %lu)\n", ether_sprintf(wh->i_addr3), (unsigned long) OS_GET_TIMESTAMP());
             printk("|  |   --------------TID FIRST PKT INFO---------------\n");
			 printk("|  |   STA->STA %s", ether_sprintf(wh->i_addr2));
			 printk("->%s\n", ether_sprintf(wh->i_addr1));
			 break;
		case IEEE80211_FC1_DIR_TODS:            
            printk("|  |TID(NODE MAC: %s TIME STAMP: %lu)\n", ether_sprintf(wh->i_addr1), (unsigned long) OS_GET_TIMESTAMP());
            printk("|  |   --------------TID FIRST PKT INFO---------------\n");
			printk("|  |   STA->AP %s", ether_sprintf(wh->i_addr2));
			printk("->%s\n", ether_sprintf(wh->i_addr3));
			break;
		case IEEE80211_FC1_DIR_FROMDS:
            printk("|  |TID(NODE MAC: %s TIME STAMP: %lu)\n", ether_sprintf(wh->i_addr2), (unsigned long) OS_GET_TIMESTAMP());
			printk("|  |   AP->STA %s", ether_sprintf(wh->i_addr3));
			printk("->%s\n", ether_sprintf(wh->i_addr1));
			break;
		case IEEE80211_FC1_DIR_DSTODS:
            printk("|  |TID(NODE MAC: %s -> %s TIME STAMP: %lu)\n", ether_sprintf(wh->i_addr2),ether_sprintf(wh->i_addr1), (unsigned long) OS_GET_TIMESTAMP());
			printk("|  |   AP->AP %s", ether_sprintf((u_int8_t *)&wh[1]));
			printk("->%s\n", ether_sprintf(wh->i_addr3));
			break;
	}
	switch (type) {
		case IEEE80211_FC0_TYPE_DATA:
			 printk("|  |   FRAME TYPE: data\n");
			 break;
		case IEEE80211_FC0_TYPE_MGT:
			 printk("|  |   FRAME TYPE: %s\n", ieee80211_mgt_subtype_name[subtype]);
			 break;
	     default:
		 	 printk("|  |   FRAME TYPE: type#%d\n", type);
			 break;
	}
	if (IEEE80211_QOS_HAS_SEQ(wh)) {
		const struct ieee80211_qosframe *qwh = 
			(const struct ieee80211_qosframe *)buf;
		printk("|  |   QoS [TID %u%s]\n", qwh->i_qos[0] & IEEE80211_QOS_TID,
			qwh->i_qos[0] & IEEE80211_QOS_ACKPOLICY ? " ACM" : "");
		}
}
void
aute_dump_txquedepth(struct ath_softc *sc)
{
	int i = 0;
	struct ath_txq *txq = NULL;
	struct ath_atx_ac *ac = NULL;
	struct ath_atx_tid *tid = NULL;
	int axq_cnt = 0,fifoq_cnt = 0,j = 0 ,bufQCount = 0,tidBufCount = 0,pertidBufCount = 0,tailindex = 0;
	struct ath_buf *buf;
	ATH_TXBUF_LOCK(sc);
    printk("\n|================================EVERY TXQ INFO====================================\n");
	printk("|Free buffer count %d \n", sc->sc_txbuf_free);
	for (i = 0; i < HAL_NUM_TX_QUEUES;i++) {
		if (ATH_TXQ_SETUP(sc, i)) {
            tidBufCount = 0;
			bufQCount = 0;
			axq_cnt = 0;
			txq = &sc->sc_txq[i];
            if(txq == NULL)
                continue;
			TAILQ_FOREACH(buf, &txq->axq_q, bf_list) {
				axq_cnt ++;
		    }
            tailindex = txq->axq_tailindex;
            buf = NULL;
			fifoq_cnt = 0;
            if(txq->axq_depth != 0)
            {
            	for(;;){
            		buf = TAILQ_FIRST(&txq->axq_fifo[tailindex]);
            		if (buf == NULL) {
            			break;
            		}
            		fifoq_cnt++;
            		tailindex--;
            	}
            }
			printk("|TXQ[%d] : depth(%d)  aggr_depth(%d) fifoq(%d) axq_q(%d)\n", txq->axq_qnum, txq->axq_depth, txq->axq_aggr_depth,fifoq_cnt,axq_cnt);
			TAILQ_FOREACH(ac, &txq->axq_acq, ac_qelem) {
				TAILQ_FOREACH(tid, &ac->tid_q, tid_qelem) {
					pertidBufCount = 0;
					for (j = 0;j < ATH_TID_MAX_BUFS; j++) {
						if (TX_BUF_BITMAP_IS_SET(tid->tx_buf_bitmap, j)) {
							tidBufCount ++;
						}
					}
					TAILQ_FOREACH(buf, &tid->buf_q, bf_list) {
						if(pertidBufCount ==0)
                        {                  
							aute_dump_pkt_debug((const u_int8_t *) buf->bf_vdata);
							printk("|  |   -----------------------------------------------\n");
						}
                        if(pertidBufCount == 0)  
						    printk("|  |   SEQ_NUM: %d ~ ",buf->bf_seqno);
                        if(TAILQ_NEXT((buf), bf_list) == NULL)
                            printk("%d\n",buf->bf_seqno);
						bufQCount ++;
						pertidBufCount++;
				    }
                    printk("|  |   TidBufCount(%d) pause(%d) sched(%d)\n",pertidBufCount,tid->paused,tid->sched);
                    printk("|  |   filtered(%d) cleanup(%d) seqnext(%d) addbastate(%d) bawhead(%d) bawtail(%d)\n",
                            tid->filtered,tid->cleanup_inprogress,tid->seq_next,tid->addba_exchangecomplete,tid->baw_head,tid->baw_tail);
				}
			}
            printk("|  TOTAL: AllTidBufCount(%d)\n",bufQCount);
		}
	}
    axq_cnt = 0;
    txq = sc->sc_cabq;
    TAILQ_FOREACH(buf, &txq->axq_q, bf_list) {
        axq_cnt ++;
    }
    tailindex = txq->axq_tailindex;
    buf = NULL;
    fifoq_cnt = 0;
    if(txq->axq_depth != 0)
    {
        for(;;){
            buf = TAILQ_FIRST(&txq->axq_fifo[tailindex]);
            if (buf == NULL) {
                break;
            }
            fifoq_cnt++;
            tailindex--;
        }
    }
    printk("|CABQ   : depth(%d)  aggr_depth(%d) fifoq(%d) axq_q(%d)\n",txq->axq_depth, txq->axq_aggr_depth,fifoq_cnt,axq_cnt);
	ATH_TXBUF_UNLOCK(sc);    
    printk("\n|==================================================================================\n");
}
void autelan_get_queueinfo(struct ath_softc *sc)
{
    u_int16_t i = 0;
    struct ieee80211com *ic = sc->sc_ieee;
    struct ieee80211_node *ni= NULL;
    struct ieee80211_node_table *nt = NULL;
    if(sc == NULL || ic == NULL)
        return;
	if(memcmp(sc->sc_osdev->netdev->name,"wifi0",5) == 0)
	{
		printk("SHOW WIFI0 QUEUE INFO\n");
	}
	else if(memcmp(sc->sc_osdev->netdev->name,"wifi1",5) == 0)
	{		
        printk("SHOW WIFI1 QUEUE INFO\n");
	}
    printk("\n|=================================TXQ PKT COUNT=====================================\n");
    for(i = 0; i < HAL_NUM_TX_QUEUES; i ++){
        printk("|TXQ[%d]: axq_num_buf_used(%d)   axq_minfree(%d)   sc_txbuf_free(%d)\n",
               i,sc->sc_txq[i].axq_num_buf_used,sc->sc_txq[i].axq_minfree,sc->sc_txbuf_free);
        printk("|        SEND PKT SUM(%d)  txq_packets(%d)  txq_noaggr_packets(%d)  txq_nobuf(%d)\n",
            sc->sc_stats.ast_txq_packets[i]+sc->sc_stats.ast_txq_noaggr_packets[i],
            sc->sc_stats.ast_txq_packets[i],sc->sc_stats.ast_txq_noaggr_packets[i],sc->sc_stats.ast_txq_nobuf[i]);
    }
    printk("|==================================================================================\n");
    printk("\n|============================EVERY NODE TID INFO===================================\n");
    nt = &ic->ic_sta;
    TAILQ_FOREACH(ni, &nt->nt_node, ni_list)
    {
         u_int16_t tidno,acno;
         struct ath_atx_tid *tid = NULL;
         struct ath_atx_ac *ac = NULL;
         struct ath_buf *tmp_bf = NULL;
         u_int32_t tidbufcnt[WME_NUM_TID]={0};
         u_int32_t ac_tidcnt[WME_NUM_AC]={0};
         struct ath_node *an = ((struct ath_node_net80211 *)(ni))->an_sta;
         ATH_TXBUF_LOCK(sc);
         printk("|NODE[%s] txbuf_free(%d) ADDR(%p)\n",ether_sprintf(ni->ni_macaddr),sc->sc_txbuf_free,an);
         printk("|  |\n");
         printk("|  |TID info:\n");
         for (tidno = 0; tidno < 17; tidno++)
         {
              tid = &an->an_tx_tid[tidno];
              if(tid!=NULL)
              {  
                   TAILQ_FOREACH(tmp_bf, &tid->buf_q, bf_list)
                   {
                        tidbufcnt[tidno]++;
                   }
                   if(tidbufcnt[tidno])
                       printk("|  |TID[%d]: TID-ADDR(%p)  tidbufcnt(%d)  tid_pausd(%d)  tid_sched(%d)\n",tidno,tid,tidbufcnt[tidno],tid->paused,tid->sched);
              }else{
                   printk("|  |TID[%d] is NULL\t",tidno);
              }                 
         }
         printk("|  |AC info:\n");
         for (acno = 0; acno < WME_NUM_AC; acno++)
         {
              tid = NULL;
              ac = &an->an_tx_ac[acno];
              if (ac!=NULL)
              {
                   if(TAILQ_FIRST(&ac->tid_q) != NULL)
                   {
                        TAILQ_FOREACH(tid, &ac->tid_q, tid_qelem)
                        {
                             if(tid == NULL)
                                  break;
                             ac_tidcnt[acno]++;
                        }
                   }
                   printk("|  |AC[%d]: AC-ADDR(%p)  ac_tidcnt(%u)\n",acno,ac,ac_tidcnt[acno]);
              }else{
                   printk("|  |AC[%d] is NULL \n",acno);
              }
         }
         printk("|\n");
         ATH_TXBUF_UNLOCK(sc);
    }
    printk("|==================================================================================\n");
    printk("\n|============================TX SCHEDULE INFO======================================\n");
    printk("|TX SCHEDULE COUNT: %d NONE SCHEDULE COUNT:%d\n",sc->sc_stats.ast_11n_stats.aute_tx_schedule,sc->sc_stats.ast_11n_stats.tx_schednone);
    printk("|LAST SCHEDULE INTERVAL: %ds %dus\n",tid_period_sec,tid_period_us);
    printk("|PS SCHEDULE COUNT: %d\n",ps_bufcnt);
    printk("|LAST PS SCHEDULE PROCESS PKT: %d\n",ps_acqcnt);
    printk("|==================================================================================\n");
    aute_dump_txquedepth(sc);    
}
EXPORT_SYMBOL(autelan_get_queueinfo);

/*--regs stats--*/
void
autelan_hal_dumpregs(const HAL_REG regs[], u_int nregs,struct ath_hal *ah)
{
	int i;

	for (i = 0; i+3 < nregs; i += 4)
	{
		if(kes_debug_print_handle)
		{
			kes_debug_print_handle(KERN_EMERG "%-8s %08x  %-8s %08x  %-8s %08x  %-8s %08x\n"
			, regs[i+0].label, OS_REG_READ(ah, regs[i+0].reg)
			, regs[i+1].label, OS_REG_READ(ah, regs[i+1].reg)
			, regs[i+2].label, OS_REG_READ(ah, regs[i+2].reg)
			, regs[i+3].label, OS_REG_READ(ah, regs[i+3].reg));
		}
	}
	switch (nregs - i) {
	case 3:
		if(kes_debug_print_handle)
		{
			kes_debug_print_handle(KERN_EMERG "%-8s %08x  %-8s %08x  %-8s %08x\n"
			, regs[i+0].label, OS_REG_READ(ah, regs[i+0].reg)
			, regs[i+1].label, OS_REG_READ(ah, regs[i+1].reg)
			, regs[i+2].label, OS_REG_READ(ah, regs[i+2].reg));
		}
		break;
	case 2:
		if(kes_debug_print_handle)
		{
			kes_debug_print_handle(KERN_EMERG "%-8s %08x  %-8s %08x\n"
			, regs[i+0].label, OS_REG_READ(ah, regs[i+0].reg)
			, regs[i+1].label, OS_REG_READ(ah, regs[i+1].reg));
		}
		break;
	case 1:
		if(kes_debug_print_handle)
		{
			kes_debug_print_handle(KERN_EMERG "%-8s %08x\n"
				, regs[i+0].label, OS_REG_READ(ah, regs[i+0].reg));
		}
		break;
	}
}
void
autelan_hal_dumpkeycache( int nkeys, int micEnabled,struct ath_hal *ah)
{
	static const char *keytypenames[] = {
		"WEP-40", 	/* AR_KEYTABLE_TYPE_40 */
		"WEP-104",	/* AR_KEYTABLE_TYPE_104 */
		"#2",
		"WEP-128",	/* AR_KEYTABLE_TYPE_128 */
		"TKIP",		/* AR_KEYTABLE_TYPE_TKIP */
		"AES-OCB",	/* AR_KEYTABLE_TYPE_AES */
		"AES-CCM",	/* AR_KEYTABLE_TYPE_CCM */
		"CLR",		/* AR_KEYTABLE_TYPE_CLR */
	};
	u_int8_t mac[IEEE80211_ADDR_LEN];
	u_int8_t ismic[128/NBBY];
	int entry;
	int first = 1;

	memset(ismic, 0, sizeof(ismic));
	for (entry = 0; entry < nkeys; entry++) {
		u_int32_t macLo, macHi, type;
		u_int32_t key0, key1, key2, key3, key4;
		macHi = OS_REG_READ(ah, AR_KEYTABLE_MAC1(entry));
		if ((macHi & AR_KEYTABLE_VALID) == 0 && isclr(ismic, entry))
			continue;
		macLo = OS_REG_READ(ah, AR_KEYTABLE_MAC0(entry));
		macHi <<= 1;
		if (macLo & (1<<31))
			macHi |= 1;
		macLo <<= 1;
		mac[4] = macHi & 0xff;
		mac[5] = macHi >> 8;
		mac[0] = macLo & 0xff;
		mac[1] = macLo >> 8;
		mac[2] = macLo >> 16;
		mac[3] = macLo >> 24;
		type = OS_REG_READ(ah, AR_KEYTABLE_TYPE(entry));
		if ((type & 7) == AR_KEYTABLE_TYPE_TKIP && micEnabled)
			setbit(ismic, entry+64);
		key0 = OS_REG_READ(ah, AR_KEYTABLE_KEY0(entry));
		key1 = OS_REG_READ(ah, AR_KEYTABLE_KEY1(entry));
		key2 = OS_REG_READ(ah, AR_KEYTABLE_KEY2(entry));
		key3 = OS_REG_READ(ah, AR_KEYTABLE_KEY3(entry));
		key4 = OS_REG_READ(ah, AR_KEYTABLE_KEY4(entry));
		if (first) {
		    if(kes_debug_print_handle)
			{
				kes_debug_print_handle(KERN_EMERG "\n");
			}
			first = 0;
		}
		if(kes_debug_print_handle)
		{
			kes_debug_print_handle(KERN_EMERG "KEY[%03u] MAC %s %-7s %02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x\n"
			, entry
			, ether_sprintf(mac)
			, isset(ismic, entry) ? "MIC" : keytypenames[type & 7]
			, (key0 >>  0) & 0xff
			, (key0 >>  8) & 0xff
			, (key0 >> 16) & 0xff
			, (key0 >> 24) & 0xff
			, (key1 >>  0) & 0xff
			, (key1 >>  8) & 0xff
			, (key2 >>  0) & 0xff
			, (key2 >>  8) & 0xff
			, (key2 >> 16) & 0xff
			, (key2 >> 24) & 0xff
			, (key3 >>  0) & 0xff
			, (key3 >>  8) & 0xff
			, (key4 >>  0) & 0xff
			, (key4 >>  8) & 0xff
			, (key4 >> 16) & 0xff
			, (key4 >> 24) & 0xff
			);
		}
	}
}


void
autelan_DumpRegs(struct ath_hal *ah)
{
#define N(a)    (sizeof(a) / sizeof(a[0]))
    static const HAL_REG regs[] = {
        /* NB: keep these sorted by address */
        { "CR",     AR_CR },
        { "HPRXDP", AR_HP_RXDP },
        { "LPRXDP", AR_LP_RXDP },
        { "CFG",    AR_CFG },
        { "IER",    AR_IER },
        { "TXCFG",  AR_TXCFG },
        { "RXCFG",  AR_RXCFG },
        { "MIBC",   AR_MIBC },
        { "TOPS",   AR_TOPS },
        { "RXNPTO", AR_RXNPTO },
        { "TXNPTO", AR_TXNPTO },
        { "RPGTO",  AR_RPGTO },
        { "MACMISC", AR_MACMISC },
        { "D_SIFS", AR_D_GBL_IFS_SIFS },
        { "D_SEQNUM", AR_D_SEQNUM },
        { "D_SLOT", AR_D_GBL_IFS_SLOT },
        { "D_EIFS", AR_D_GBL_IFS_EIFS },
        { "D_MISC", AR_D_GBL_IFS_MISC },
        { "D_TXPSE", AR_D_TXPSE },
        { "RC",     AR9300_HOSTIF_OFFSET(HOST_INTF_RESET_CONTROL) },
        { "SREV",   AR9300_HOSTIF_OFFSET(HOST_INTF_SREV) },
        { "STA_ID0",    AR_STA_ID0 },
        { "STA_ID1",    AR_STA_ID1 },
        { "BSS_ID0",    AR_BSS_ID0 },
        { "BSS_ID1",    AR_BSS_ID1 },
        { "TIME_OUT",   AR_TIME_OUT },
        { "RSSI_THR",   AR_RSSI_THR },
        { "USEC",   AR_USEC },
        { "RX_FILTR",   AR_RX_FILTER },
        { "MCAST_0",    AR_MCAST_FIL0 },
        { "MCAST_1",    AR_MCAST_FIL1 },
        { "DIAG_SW",    AR_DIAG_SW },
        { "TSF_L32",    AR_TSF_L32 },
        { "TSF_U32",    AR_TSF_U32 },
        { "TST_ADAC",   AR_TST_ADDAC },
        { "DEF_ANT",    AR_DEF_ANTENNA },
        { "LAST_TST",   AR_LAST_TSTP },
        { "NAV",    AR_NAV },
        { "RTS_OK",     AR_RTS_OK },
        { "RTS_FAIL",   AR_RTS_FAIL },
        { "ACK_FAIL",   AR_ACK_FAIL },
        { "FCS_FAIL",   AR_FCS_FAIL },
        { "BEAC_CNT",   AR_BEACON_CNT },
#ifdef AH_SUPPORT_XR
        { "XRMODE", AR_XRMODE },
        { "XRDEL",  AR_XRDEL },
        { "XRTO",   AR_XRTO },
        { "XRCRP",  AR_XRCRP },
        { "XRSTMP", AR_XRSTMP },
#endif /* AH_SUPPORT_XR */
        { "SLEEP1", AR_SLEEP1 },
        { "SLEEP2", AR_SLEEP2 },
        { "BSSMSKL",    AR_BSSMSKL },
        { "BSSMSKU",    AR_BSSMSKU },
        { "TPC",    AR_TPC },
        { "TFCNT",  AR_TFCNT },
        { "RFCNT",  AR_RFCNT },
        { "RCCNT",  AR_RCCNT },
        { "CCCNT",  AR_CCCNT },
        { "PHY_ERR",    AR_PHY_ERR },

    };
    int i;
    int reg;
    autelan_hal_dumpregs(regs, N(regs),ah);
   /* Interrupt registers */
    if(kes_debug_print_handle)
	{
		kes_debug_print_handle(KERN_EMERG "\n");
    }
    if(kes_debug_print_handle)
	{
		kes_debug_print_handle(KERN_EMERG "IMR: %08x S0 %08x S1 %08x S2 %08x S3 %08x S4 %08x\n"
        , OS_REG_READ(ah, AR_IMR)
        , OS_REG_READ(ah, AR_IMR_S0)
        , OS_REG_READ(ah, AR_IMR_S1)
        , OS_REG_READ(ah, AR_IMR_S2)
        , OS_REG_READ(ah, AR_IMR_S3)
        , OS_REG_READ(ah, AR_IMR_S4)
        );
    }
    if(kes_debug_print_handle)
	{
		kes_debug_print_handle(KERN_EMERG "ISR: %08x S0 %08x S1 %08x S2 %08x S3 %08x S4 %08x\n"
        , OS_REG_READ(ah, AR_ISR)
        , OS_REG_READ(ah, AR_ISR_S0)
        , OS_REG_READ(ah, AR_ISR_S1)
        , OS_REG_READ(ah, AR_ISR_S2)
        , OS_REG_READ(ah, AR_ISR_S3)
        , OS_REG_READ(ah, AR_ISR_S4)
        );
    }
    /* QCU registers */
   
    if(kes_debug_print_handle)
	{
		kes_debug_print_handle(KERN_EMERG "\n");
    }
    if(kes_debug_print_handle)
	{
		kes_debug_print_handle(KERN_EMERG "%-8s %08x  %-8s %08x  %-8s %08x\n"
        , "Q_TXE", OS_REG_READ(ah, AR_Q_TXE)
        , "Q_TXD", OS_REG_READ(ah, AR_Q_TXD)
        , "Q_RDYTIMSHD", OS_REG_READ(ah, AR_Q_RDYTIMESHDN)
    	);
    }
    if(kes_debug_print_handle)
	{
		kes_debug_print_handle(KERN_EMERG "Q_ONESHOTARM_SC %08x  Q_ONESHOTARM_CC %08x\n"
        , OS_REG_READ(ah, AR_Q_ONESHOTARM_SC)
        , OS_REG_READ(ah, AR_Q_ONESHOTARM_CC)
    	);
    }
    for (i = 0; i < 10; i++)
    {
	    if(kes_debug_print_handle)
		{
			kes_debug_print_handle(KERN_EMERG "Q[%u] TXDP %08x CBR %08x RDYT %08x MISC %08x STS %08x\n"
	        , i
	        , OS_REG_READ(ah, AR_QTXDP(i))
	        , OS_REG_READ(ah, AR_QCBRCFG(i))
	        , OS_REG_READ(ah, AR_QRDYTIMECFG(i))
	        , OS_REG_READ(ah, AR_QMISC(i))
	        , OS_REG_READ(ah, AR_QSTS(i))
	    	);
	    }
    }
     /* DCU registers */
    
    if(kes_debug_print_handle)
	{
		kes_debug_print_handle( "\n");
    }
    for (i = 0; i < 10; i++)
    {
        if(kes_debug_print_handle)
		{
			kes_debug_print_handle(KERN_EMERG "D[%u] MASK %08x IFS %08x RTRY %08x CHNT %08x MISC %06x\n"
            , i
            , OS_REG_READ(ah, AR_DQCUMASK(i))
            , OS_REG_READ(ah, AR_DLCL_IFS(i))
            , OS_REG_READ(ah, AR_DRETRY_LIMIT(i))
            , OS_REG_READ(ah, AR_DCHNTIME(i))
            , OS_REG_READ(ah, AR_DMISC(i))
        	);
        }
    }
    for (i = 0; i < 10; i++) {
        u_int32_t f0 = OS_REG_READ(ah, AR_D_TXBLK_DATA((i<<8)|0x00));
        u_int32_t f1 = OS_REG_READ(ah, AR_D_TXBLK_DATA((i<<8)|0x40));
        u_int32_t f2 = OS_REG_READ(ah, AR_D_TXBLK_DATA((i<<8)|0x80));
        u_int32_t f3 = OS_REG_READ(ah, AR_D_TXBLK_DATA((i<<8)|0xc0));
        if (f0 || f1 || f2 || f3)
        {
            if(kes_debug_print_handle)
			{
				kes_debug_print_handle(KERN_EMERG "D[%u] XMIT MASK %08x %08x %08x %08x\n",
                i, f0, f1, f2, f3);
            }
        }
    }
   
    autelan_hal_dumpkeycache(128,
    OS_REG_READ(ah, AR_STA_ID1) & AR_STA_ID1_CRPT_MIC_ENABLE ,ah);
    if(kes_debug_print_handle)
	{
		kes_debug_print_handle(KERN_EMERG "\n");
    }
#if 0

    for(reg = 0x9800; reg <= 0xa480; reg += 4) {
        printk("%X %.8X\n", reg, OS_REG_READ(ah, reg));
    }

    ath_hal_dumprange(fd, 0x9800, 0x987c);
    ath_hal_dumprange(fd, 0x9900, 0x995c);
    ath_hal_dumprange(fd, 0x9c00, 0x9c1c);
    ath_hal_dumprange(fd, 0xa180, 0xa238);
#endif
    for (reg = AR_MAC_PCU_TRACE_REG_START, i = 0; reg < AR_MAC_PCU_TRACE_REG_END; reg += 16) {
       if(kes_debug_print_handle)
	   {
		   kes_debug_print_handle(KERN_EMERG "0x%X: 0x%.8X 0x%.8X 0x%.8X 0x%.8X\n", reg, 
               OS_REG_READ(ah, reg + 0),
               OS_REG_READ(ah, reg + 4),
               OS_REG_READ(ah, reg + 8),
               OS_REG_READ(ah, reg + 12));
       }
    
    }
    for (reg = AR_DMADBG_0, i = 0; reg <= AR_DMADBG_7; reg += 4) {
        if(kes_debug_print_handle)
		{
			kes_debug_print_handle(KERN_EMERG "0x%X: 0x%.8X\n", reg, OS_REG_READ(ah, reg));
        }
    
    }
#undef N
} 
