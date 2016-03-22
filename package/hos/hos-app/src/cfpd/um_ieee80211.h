#ifndef __UM_IEEE80211_H__
#define __UM_IEEE80211_H__


#define UM_IEEE80211_ADDR_LEN 6
#define UM_IEEE80211_RATE_MAXSIZE 36

/*
 * Per/node (station) statistics available when operating as an AP.
 */
struct rate_count{
    u_int64_t   count;
    u_int8_t    dot11Rate;
};

struct rssi_stats{
  u_int64_t   ns_rx_data;
};

struct ieee80211_nodestats {
    u_int32_t    ns_rx_data;             /* rx data frames */
    u_int32_t    ns_rx_mgmt;             /* rx management frames */
    u_int32_t    ns_rx_ctrl;             /* rx control frames */
    u_int32_t    ns_rx_ucast;            /* rx unicast frames */
    u_int32_t    ns_rx_mcast;            /* rx multi/broadcast frames */
    u_int64_t    ns_rx_bytes;            /* rx data count (bytes) */
    u_int64_t    ns_rx_beacons;          /* rx beacon frames */
    u_int32_t    ns_rx_proberesp;        /* rx probe response frames */

    u_int32_t    ns_rx_dup;              /* rx discard 'cuz dup */
    u_int32_t    ns_rx_noprivacy;        /* rx w/ wep but privacy off */
    u_int32_t    ns_rx_wepfail;          /* rx wep processing failed */
    u_int32_t    ns_rx_demicfail;        /* rx demic failed */
       
    /* We log MIC and decryption failures against Transmitter STA stats.
       Though the frames may not actually be sent by STAs corresponding
       to TA, the stats are still valuable for some customers as a sort
       of rough indication.
       Also note that the mapping from TA to STA may fail sometimes. */
    u_int32_t    ns_rx_tkipmic;          /* rx TKIP MIC failure */
    u_int32_t    ns_rx_ccmpmic;          /* rx CCMP MIC failure */
    u_int32_t    ns_rx_wpimic;           /* rx WAPI MIC failure */
    u_int32_t    ns_rx_tkipicv;          /* rx ICV check failed (TKIP) */
    u_int32_t    ns_rx_decap;            /* rx decapsulation failed */
    u_int32_t    ns_rx_defrag;           /* rx defragmentation failed */
    u_int32_t    ns_rx_disassoc;         /* rx disassociation */
    u_int32_t    ns_rx_deauth;           /* rx deauthentication */
    u_int32_t    ns_rx_action;           /* rx action */
    u_int32_t    ns_rx_decryptcrc;       /* rx decrypt failed on crc */
    u_int32_t    ns_rx_unauth;           /* rx on unauthorized port */
    u_int32_t    ns_rx_unencrypted;      /* rx unecrypted w/ privacy */

    u_int32_t    ns_tx_data;             /* tx data frames */
    u_int32_t    ns_tx_data_success;     /* tx data frames successfully
                                            transmitted (unicast only) */
    u_int32_t    ns_tx_mgmt;             /* tx management frames */
    u_int32_t    ns_tx_ucast;            /* tx unicast frames */
    u_int32_t    ns_tx_mcast;            /* tx multi/broadcast frames */
    u_int64_t    ns_tx_bytes;            /* tx data count (bytes) */
    u_int64_t    ns_tx_bytes_success;    /* tx success data count - unicast only
                                            (bytes) */
    u_int32_t    ns_tx_probereq;         /* tx probe request frames */
    u_int32_t    ns_tx_uapsd;            /* tx on uapsd queue */
    u_int32_t    ns_tx_discard;          /* tx dropped by NIC */
    u_int32_t    ns_is_tx_not_ok;        /* tx not ok */
    u_int32_t    ns_tx_novlantag;        /* tx discard 'cuz no tag */
    u_int32_t    ns_tx_vlanmismatch;     /* tx discard 'cuz bad tag */

    u_int32_t    ns_tx_eosplost;         /* uapsd EOSP retried out */

    u_int32_t    ns_ps_discard;          /* ps discard 'cuz of age */

    u_int32_t    ns_uapsd_triggers;      /* uapsd triggers */
    u_int32_t    ns_uapsd_duptriggers;    /* uapsd duplicate triggers */
    u_int32_t    ns_uapsd_ignoretriggers; /* uapsd duplicate triggers */
    u_int32_t    ns_uapsd_active;         /* uapsd duplicate triggers */
    u_int32_t    ns_uapsd_triggerenabled; /* uapsd duplicate triggers */
    u_int32_t    ns_last_tx_rate;
    u_int32_t    ns_last_rx_rate;
    u_int32_t    ns_is_tx_nobuf;

    /* MIB-related state */
    u_int32_t    ns_tx_assoc;            /* [re]associations */
    u_int32_t    ns_tx_assoc_fail;       /* [re]association failures */
    u_int32_t    ns_tx_auth;             /* [re]authentications */
    u_int32_t    ns_tx_auth_fail;        /* [re]authentication failures*/
    u_int32_t    ns_tx_deauth;           /* deauthentications */
    u_int32_t    ns_tx_deauth_code;      /* last deauth reason */
    u_int32_t    ns_tx_disassoc;         /* disassociations */
    u_int32_t    ns_tx_disassoc_code;    /* last disassociation reason */
    u_int32_t    ns_psq_drops;           /* power save queue drops */
    
    /* IQUE-HBR related state */
	u_int32_t	ns_tx_dropblock;	/* tx discard 'cuz headline block */
	/* Autelan-Begin: zhaoyang1 transplants statistics 2015-01-27 */
	u_int64_t    ns_rx_ucast_bytes;
    u_int64_t    ns_rx_mcast_bytes;
    u_int32_t    ns_rx_fcserr;
	u_int32_t    ns_rx_tkipreplay;      /* rx seq# violation (TKIP) */
	u_int32_t    ns_rx_tkipformat;      /* rx format bad (TKIP) */
	u_int32_t    ns_rx_ccmpformat;      /* rx format bad (CCMP) */
	u_int32_t    ns_rx_ccmpreplay;      /* rx seq# violation (CCMP) */
	u_int32_t    ns_rx_wpireplay;       /* rx seq# violation (WPI) */
	u_int32_t    ns_rx_discard;         /* rx dropped by NIC */
	u_int32_t    ns_rx_badkeyid;           /* rx w/ incorrect keyid */
	u_int32_t    ns_tx_mcast_bytes;
    u_int32_t    ns_tx_ucast_bytes;
	u_int32_t 	 ns_re_wpi;
	u_int32_t 	 ns_wpi_mic;  
	u_int32_t 	 ns_wpi_no_key_error;
    
	u_int32_t 	 ns_tx_retry_packets;
	u_int64_t 	 ns_tx_retry_bytes;
	u_int32_t 	 ns_rx_retry_packets;
	u_int64_t 	 ns_rx_retry_bytes;

#ifndef RSSI_RANGE_NUM
#define RSSI_RANGE_NUM  17
#endif
	struct rssi_stats ns_rssi_stats[RSSI_RANGE_NUM];
    struct rate_count   ns_rx_rate_index[12];
    u_int64_t   ns_rx_mcs_count[24];
	struct rate_count   ns_tx_rate_index[12];
    u_int64_t   ns_tx_mcs_count[24];
	/* Autelan-End: zhaoyang1 transplants statistics 2015-01-27 */
};

/*
 * Retrieve per-node statistics.
 */
struct ieee80211req_sta_stats {
	union {
		/* NB: explicitly force 64-bit alignment */
		u_int8_t	macaddr[UM_IEEE80211_ADDR_LEN];
		u_int64_t	pad;
	} is_u;
	struct ieee80211_nodestats is_stats;
};

/*
 * Station information block; the mac address is used
 * to retrieve other data like stats, unicast key, etc.
 */
struct ieee80211req_sta_info {
	u_int16_t	isi_len;		/* length (mult of 4) */
	u_int16_t	isi_freq;		/* MHz */
    u_int32_t   isi_flags;      /* channel flags */
	u_int16_t	isi_state;		/* state flags */
	u_int8_t	isi_authmode;		/* authentication algorithm */
	int8_t	    	isi_rssi;
	u_int16_t	isi_capinfo;		/* capabilities */
	u_int8_t	isi_athflags;		/* Atheros capabilities */
	u_int8_t	isi_erp;		/* ERP element */
	u_int8_t	isi_ps;	    	/* psmode */
	u_int8_t	isi_macaddr[UM_IEEE80211_ADDR_LEN];
	u_int8_t	isi_nrates;
						/* negotiated rates */
	u_int8_t	isi_rates[UM_IEEE80211_RATE_MAXSIZE];
	u_int8_t	isi_txrate;		/* index to isi_rates[] */
    u_int32_t   isi_txratekbps; /* tx rate in Kbps, for 11n */
	u_int16_t	isi_ie_len;		/* IE length */
	u_int16_t	isi_associd;		/* assoc response */
	u_int16_t	isi_txpower;		/* current tx power */
	u_int16_t	isi_vlan;		/* vlan tag */
	u_int16_t	isi_txseqs[17];		/* seq to be transmitted */
	u_int16_t	isi_rxseqs[17];		/* seq previous for qos frames*/
	u_int16_t	isi_inact;		/* inactivity timer */
	u_int8_t	isi_uapsd;		/* UAPSD queues */
	u_int8_t	isi_opmode;		/* sta operating mode */
	u_int8_t	isi_cipher;
        u_int32_t 	isi_assoc_time;         /* sta association time */
	struct timespec	isi_tr069_assoc_time;	/* sta association time in timespec format */


    u_int16_t   isi_htcap;      /* HT capabilities */
    u_int32_t   isi_rxratekbps; /* rx rate in Kbps */
                                /* We use this as a common variable for legacy rates
                                   and lln. We do not attempt to make it symmetrical
                                   to isi_txratekbps and isi_txrate, which seem to be
                                   separate due to legacy code. */
	/* XXX frag state? */
	/* variable length IE data */
    u_int8_t isi_maxrate_per_client; /* Max rate per client */
	u_int16_t   isi_stamode;        /* Wireless mode for connected sta */
};

#endif
