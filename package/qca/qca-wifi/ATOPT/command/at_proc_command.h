#ifndef _AT_PROC_COMMAND_H_
#define _AT_PROC_COMMAND_H_

/* Autelan-Begin: zhaoyang1 adds sysctl  2015-01-08 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#define  CTL_NAME_AUTO  .ctl_name = CTL_AUTO,
#else
#define  CTL_NAME_AUTO   
#endif
/* Autelan-End: zhaoyang1 adds sysctl  2015-01-08 */


/*AUTELAN-Begin:Added by WangJia for traffic limit. 2012-11-02, transplant by zhouke */
#if ATOPT_TRAFFIC_LIMIT
#define IEEE80211_IOCTL_TRAFFIC_LIMIT	(SIOCDEVPRIVATE+18) /*autelan private traffic limit*/
#endif
#define IEEE80211_IOCTL_CHANNEL_UTILITY (SIOCDEVPRIVATE+21) /* AUTELAN-zhaoenjuan transplant (lisongbai) for get channel utility 2013-12-27 */
/* AUTELAN-End:Added by WangJia for traffic limit. 2012-11-02, transplant by zhouke  */

/*AUTELAN-Begin:Added by duanmingzhe for for mgmt debug. 2015-01-06, transplant by zhouke */
#if ATOPT_MGMT_DEBUG
#define IEEE80211_IOCTL_MGMT_DEBUG      (SIOCDEVPRIVATE+23) /*AUTELAN-Added: Added by dongzw for mgmt debug, transplant by duanmingzhe */
#define IEEE80211_IOCTL_PACKET_TRACE	(SIOCDEVPRIVATE+26)	//AUTELAN-zhaoenjuan add for packet_trace
#endif
/* AUTELAN-End:Added by duanmingzhe for for mgmt debug. 2015-01-06, transplant by zhouke  */

/*AUTELAN-Begin:Added by zhouke for sync info.2015-02-06*/
#if ATOPT_SYNC_INFO
#define IEEE80211_IOCTL_SYNC_INFO       (SIOCDEVPRIVATE+28)
#endif
/* AUTELAN-End: Added by zhouke for sync info.2015-02-06*/


/*AUTELAN-Begin:Added by WangJia for traffic limit. 2012-11-02, transplant by zhouke */
#if ATOPT_TRAFFIC_LIMIT
struct ieee80211_autelan_traffic_limit {

#define SET_VAP_TRAFFIC_LIMIT	1
#define GET_VAP_TRAFFIC_LIMIT	2
#define SET_SPECIFIC_NODE_TRAFFIC_LIMIT	3
#define GET_SPECIFIC_NODE_TRAFFIC_LIMIT	4
#define SET_EVERY_NODE_TRAFFIC_LIMIT	5
#define GET_EVERY_NODE_TRAFFIC_LIMIT	6
#define SET_VAP_TRAFFIC_LIMIT_FLAG	7
#define GET_VAP_TRAFFIC_LIMIT_FLAG	8
#define SET_EVERY_NODE_TRAFFIC_LIMIT_FLAG	9
#define GET_EVERY_NODE_TRAFFIC_LIMIT_FLAG	10
#define SET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG	11
#define GET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG	12

/*ljy--add begin to separate traffic limit between rx and tx*/
#define SET_VAP_TRAFFIC_LIMIT_SEND	13
#define GET_VAP_TRAFFIC_LIMIT_SEND	14
#define SET_SPECIFIC_NODE_TRAFFIC_LIMIT_SEND	15
#define GET_SPECIFIC_NODE_TRAFFIC_LIMIT_SEND	16
#define SET_EVERY_NODE_TRAFFIC_LIMIT_SEND	17
#define GET_EVERY_NODE_TRAFFIC_LIMIT_SEND	18
/*ljy--add end*/

/*Begin: Added by wangjia, for add extra commands. 2012-11-02*/
#define TL_GET_TRAFFIC_LIMIT_STATUS 19
#define TL_SET_TASKLET_TIMESLICE    20
#define TL_GET_TASKLET_TIMESLICE    21
#define TL_SET_DEQUEUE_THRESHOLD    22
#define TL_GET_DEQUEUE_THRESHOLD    23
#define TL_GET_EVERYNODE_QUEUE_LEN  24
#define TL_SET_DEBUG_FLAG           25
#define TL_GET_DEBUG_FLAG           26
/*End: Added by wangjia, for add extra commands. 2012-11-02*/  

	unsigned char   type;  			/* request type*/
	unsigned int 	arg1;
	u_int8_t macaddr[IEEE80211_ADDR_LEN];
};
#endif
/* AUTELAN-End:Added by WangJia for traffic limit. 2012-11-02, transplant by zhouke  */

/*AUTELAN-Begin:Added by zhouke for sync info.2015-02-06*/
#if ATOPT_SYNC_INFO
struct ieee80211_autelan_sync_info{

#define GET_LOCAL_TABLE 1
#define GET_NEIGHBOUR_TABLE 2
#define GET_NEIGHBOUR_STA_BY_MAC 3
#define SYNC_DEBUG 4
#define GET_SYNC_DEBUG 5
#define SYNC_TIME 6
#define GET_SYNC_TIME 7
#define GET_NEIGHBOUR_DEV 8
#define GET_SCAN_LIST 9
#define SYNC_AUTO_GROUP 10
#define GET_SYNC_AUTO_GROUP 11
#define SYNC_NEIGHBOR_RSSI_LIMIT 12
#define GET_SYNC_NEIGHBOR_RSSI_LIMIT 13
#define SYNC_SWITCH 14
#define GET_SYNC_SWITCH 15

    unsigned char   type; /* request type*/
    unsigned int    arg1;
    u_int8_t base_mac[IEEE80211_ADDR_LEN];
    u_int8_t sta_mac[IEEE80211_ADDR_LEN];
};

struct ieee80211_autelan_connect_rule{

#define CONNECT_TO_BEST_DEBUG 1
#define GET_CONNECT_TO_BEST_DEBUG 2
#define CONNECT_TO_BEST 3
#define GET_CONNECT_TO_BEST 4
#define INACTIVE_TIME 5
#define GET_INACTIVE_TIME 6
#define MAX_DV 7
#define GET_MAX_DV 8
#define WATING_TIME 9
#define GET_WATING_TIME 10
#define CONNECT_BALANCE 11
#define GET_CONNECT_BALANCE 12

    unsigned char   type; /* request type*/
    unsigned int    arg1;
};
#endif
/* AUTELAN-End: Added by zhouke for sync info.2015-02-06*/

extern u_int32_t thinap;


void at_vap_sysctl_register(struct ieee80211vap *vap);
void at_vap_sysctl_unregister(struct ieee80211vap *vap);

int ieee80211_ioctl_autelan_traffic_limit(struct net_device *dev, struct iwreq *iwr);
int ath_ioctl_autelan_sync_info(struct net_device *dev, struct iwreq *iwr);
int ath_ioctl_autelan_connect_rule(struct net_device *dev, struct iwreq *iwr);
#endif
