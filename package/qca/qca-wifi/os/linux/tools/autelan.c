/* ****************************************************************************************************
 * Filename: autelan.c
 *    Description: autelan private command for ap.
 * Project: autelan ap 2010
 * Author: xmeng
 * Date: 11/25/2008
 *****************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <netinet/ether.h>

#include <signal.h>
#include <unistd.h>
#include <errno.h>

#define autelan_debug printf

#define    IEEE80211_IOCTL_AUTELAN_WMM        (SIOCDEVPRIVATE+17) /*autelan private wmm configure*/
#define    IEEE80211_IOCTL_TRAFFIC_LIMIT    (SIOCDEVPRIVATE+18) /*autelan private traffic limit*/
#define    IEEE80211_IOCTL_QUICK_ROAMING    (SIOCDEVPRIVATE+19) /*autelan private wds roaming*/
#define    IEEE80211_IOCTL_MAC_BINDING        (SIOCDEVPRIVATE+20)    /*ljy--add to develop the policy of mac binding*/
#define IEEE80211_IOCTL_CHANNEL_UTILITY (SIOCDEVPRIVATE+21)/* AUTELAN-zhaoenjuan transplant (lisongbai) for get channel utility 2013-12-27 */
#define IEEE80211_IOCTL_ARP_FILTER      (SIOCDEVPRIVATE+22)/*AUTELAN-zhaoenjuan transplant (WangJia) for arp filter */
#define IEEE80211_IOCTL_MGMT_DEBUG      (SIOCDEVPRIVATE+23) /*Added by dongzw for mgmt debug*/
#define IEEE80211_IOCTL_SET_NIFLAG      (SIOCDEVPRIVATE+24) /*zhaoyang add for data forward base users*/
#define    IEEE80211_IOCTL_80211_CACHE        (SIOCDEVPRIVATE+25)    /*Added by duanmingzhe for 80211 cache*/
#define    IEEE80211_IOCTL_PACKET_TRACE    (SIOCDEVPRIVATE+26)    //AUTELAN-zhaoenjuan add for packet_trace
#define SIOCSATHSYNCINFO                (SIOCDEVPRIVATE+11)
#define SIOCSATHCONNECTRULE             (SIOCDEVPRIVATE+12)

#define IEEE80211_ADDR_LEN 6

/*AUTELAN-Begin:zhaoenjuan add for packet_trace*/
struct ieee80211_autelan_packet_trace{

#define SET_MAC            1
#define GET_MAC            2
    unsigned char   type;              /* request type*/
    unsigned int     arg1;
    u_int8_t macaddr[IEEE80211_ADDR_LEN];
};
/*AUTELAN-End:zhaoenjuan add for packet_trace*/

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

struct  userinfo_table_record
{
    u_int8_t    user_mac[IEEE80211_ADDR_LEN];
    u_int8_t    user_cap;
    u_int8_t    inact;
    u_int8_t    identify_count;
    u_int8_t    identify;
    u_int8_t    avg_mgmt_rssi;
    u_int8_t    avg_data_rssi;
    u_int8_t    assoc;
    u_int16_t   recv_probe_2g;
    u_int16_t   recv_auth_2g;
    u_int16_t   recv_probe_5g;
    u_int16_t   recv_auth_5g;
    u_int32_t   assoc_cnt;
    u_int32_t   stamp_time;
};

struct sync_dev_info{
    u_int8_t dev_mac[6];
    u_int8_t essid[32];
    u_int8_t work_mode; //1=2.4G;2=5.8G
    u_int8_t is_up;
    u_int8_t channel;
    u_int8_t txpower;
    u_int8_t user_cnt;
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


/*xmeng add for autelan private wmm configure*/
struct ieee80211_autelan_wmm_params {

#define TOS_FLAG     1
#define GET_TOS_FLAG    2
#define TOS_INGRESS     3
#define GET_TOS_INGRESS    4
#define TOS_EGRESS    5
#define GET_TOS_EGRESS    6
#define VLAN_FLAG    7
#define GET_VLAN_FLAG    8
#define VLAN_INGRESS     9
#define GET_VLAN_INGRESS    10
#define VLAN_EGRESS        11
#define GET_VLAN_EGRESS        12

/*ljy--add begin to append the switch modified the best effort parameter*/
#define BE_FLAG        13
#define GET_BE_FLAG        14
/*ljy--add end*/

    unsigned char   type;              /* request type*/
    unsigned int     arg1;
    unsigned int     arg2;
    unsigned int     index; 
};
/*xmeng add for autelan private traffic limit*/


/*AUTELAN-Begin:zhaoenjuan transplant (WangJia) for arp filter */
struct ieee80211_autelan_arp_filter {
#define IEEE80211_PARAM_ARP_FILTER_SET_SWITCH 1
#define IEEE80211_PARAM_ARP_FILTER_GET_SWITCH 2
#define IEEE80211_PARAM_ARP_FILTER_ADD_MAC 3
#define IEEE80211_PARAM_ARP_FILTER_DEL_MAC 4
#define IEEE80211_PARAM_ARP_FILTER_LIST_MAC 5
    
    unsigned char   type;           /* request type*/
    unsigned int    arg1;
    u_int8_t macaddr[IEEE80211_ADDR_LEN];
};
/*AUTELAN-End:zhaoenjuan transplant (WangJia) for arp filter */

/* Begin: Added by dongzw for mgmt debug */
struct ieee80211_autelan_mgmt_debug {
#define IEEE80211_PARAM_MGMT_DEBUG_SET_SWITCH 1
#define IEEE80211_PARAM_MGMT_DEBUG_GET_SWITCH 2
    unsigned char   type;           /* request type*/
    unsigned int    arg;
};
/* End: Added by dongzw for mgmt debug*/
/* AUTELAN-Begin:zhaoenjuan transplant (lisongbai) for get channel utility 2013-12-27 */
struct ieee80211_channel_utility {
    unsigned long timestamps_sec;
    u_int32_t cyclecount;
    u_int32_t rxclearcount;
    u_int32_t rxfrmaecount;
    u_int32_t txfrmaecount;
};
/* AUTELAN-End:zhaoenjuan transplant (lisongbai) for get channel utility 2013-12-27 */

struct ieee80211_autelan_traffic_limit {

#define SET_VAP_TRAFFIC_LIMIT    1
#define GET_VAP_TRAFFIC_LIMIT    2
#define SET_SPECIFIC_NODE_TRAFFIC_LIMIT    3
#define GET_SPECIFIC_NODE_TRAFFIC_LIMIT    4
#define SET_EVERY_NODE_TRAFFIC_LIMIT    5
#define GET_EVERY_NODE_TRAFFIC_LIMIT    6
#define SET_VAP_TRAFFIC_LIMIT_FLAG    7
#define GET_VAP_TRAFFIC_LIMIT_FLAG    8
#define SET_EVERY_NODE_TRAFFIC_LIMIT_FLAG    9
#define GET_EVERY_NODE_TRAFFIC_LIMIT_FLAG    10
#define SET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG    11
#define GET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG    12

/*ljy--add begin to separate traffic limit between rx and tx*/
#define SET_VAP_TRAFFIC_LIMIT_SEND    13
#define GET_VAP_TRAFFIC_LIMIT_SEND    14
#define SET_SPECIFIC_NODE_TRAFFIC_LIMIT_SEND    15
#define GET_SPECIFIC_NODE_TRAFFIC_LIMIT_SEND    16
#define SET_EVERY_NODE_TRAFFIC_LIMIT_SEND    17
#define GET_EVERY_NODE_TRAFFIC_LIMIT_SEND    18
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

    unsigned char   type;              /* request type*/
    unsigned int     arg1;
    u_int8_t macaddr[IEEE80211_ADDR_LEN];
};

struct ieee80211_autelan_quick_roaming {

#define SET_FLAG    1
#define GET_FLAG    2
#define ADD_NODE    3
#define DEL_NODE    4    
    unsigned char   type;              /* request type*/
    unsigned int     arg1;
};

/*zhaoyang add for data forward base users*/
struct ieee80211_autelan_tunnel_ctl{
#define SET_NIFLAG            1
/*Begin: zhaoyang1 add for getting infomation of niflag 2013-03-23*/
#define GET_NIFLAG            2
/*End: zhaoyang1 add for getting infomation of niflag 2013-03-23*/

    unsigned char   type;              /* request type*/
    u_int8_t        ni_macaddr[IEEE80211_ADDR_LEN];
    u_int16_t       ni_localflags;
    u_int8_t        ni_portal_ipaddr[4]; //record the portal server IP addr 
};
/*zhaoyang modify end*/

/*ljy--add begin to develop the policy of mac binding*/
struct ieee80211_autelan_mac_binding {

#define SET_DHCP_ENABLE            1
#define GET_DHCP_ENABLE            2
#define SET_IP_AUTO_LEARNING    3
#define GET_IP_AUTO_LEARNING    4
#define SET_IP                    5
#define GET_IP                    6
#define SET_VLAN                7
#define GET_VLAN                8
//sheyanbin--add to through the pppoe frame
#define SET_PPPOE_ENABLE        9
#define GET_PPPOE_ENABLE        10
//sheyanbin--add end


    unsigned char   type;              /* request type*/
    unsigned int     arg1;
    u_int8_t macaddr[IEEE80211_ADDR_LEN];
    u_int8_t ipaddr[4];
};
/*ljy--add end*/

/*Begin:added by duanmingzhe for 80211 cache*/
struct ieee80211_autelan_80211_cache{
#define SET_ENABLE               1
#define GET_ENABLE               2
#define SET_CACHE_ENABLE         3
#define GET_CACHE_ENABLE         4
#define SET_CACHE_LIMIT          5
#define GET_CACHE_LIMIT          6
#define SET_CACHE_THRESHOLD_B    7
#define GET_CACHE_THRESHOLD_B    8
#define SET_CACHE_THRESHOLD_G    9
#define GET_CACHE_THRESHOLD_G    10
#define SET_CACHE_THRESHOLD_N    11
#define GET_CACHE_THRESHOLD_N    12
#define SET_CACHE_PRIORITY_B     13
#define GET_CACHE_PRIORITY_B     14
#define SET_CACHE_PRIORITY_G     15
#define GET_CACHE_PRIORITY_G     16
#define SET_CACHE_PRIORITY_N     17
#define GET_CACHE_PRIORITY_N     18
#define SET_CACHE_QUEUE_MAXLEN_B 19
#define GET_CACHE_QUEUE_MAXLEN_B 20
#define SET_CACHE_QUEUE_MAXLEN_G 21
#define GET_CACHE_QUEUE_MAXLEN_G 22
#define SET_CACHE_QUEUE_MAXLEN_N 23
#define GET_CACHE_QUEUE_MAXLEN_N 24
#define GET_CACHE_SEND_COUNT     25


    unsigned char   type;              /* request type*/
    unsigned int    arg1;
};
/*End:added by duanmingzhe for 80211 cache*/
/*
 *autelan wmm help information
 */
static void autelan_wmm_help () 
{
    //printf("\nusage:: autelan wmm COMMAND [OPTION] ... \n");
    printf("\nusage:: wlanset wmm COMMAND [OPTION] ... \n");
    printf("OPTIONS: \n");
    printf("\ttos_flag\t\t[interface]\t[0|1]\n");
    printf("\tget_tos_flag\t\t[interface]\t\n");
    printf("\ttos_egress_map\t\t[interface]\t[wmm-priority]\t[tos-qos]\n");
    printf("\tget_tos_egress_map\t[interface]\t\n");
    printf("\ttos_ingress_map\t\t[interface]\t[wmm-priority]\t[tos-qos]\n");
    printf("\tget_tos_ingress_map\t[interface]\t\n");
    printf("\t1p_flag\t\t\t[interface]\t[0|1]\n");
    printf("\tget_1p_flag\t\t[interface]\n");
    printf("\t1p_egress_map\t\t[interface]\t[wmm-priority]\t[vlan-qos]\n");
    printf("\tget_1p_egress_map\t[interface]\n");
    printf("\t1p_ingress_map\t\t[interface]\t[wmm-priority]\t[vlan-qos]\n");
    printf("\tget_1p_ingress_map\t[interface]\n");
    /*ljy--add begin to append the switch modified the best effort parameter*/
    printf("\tbe_flag\t\t\t[interface]\t[0|1]\n");
    printf("\tget_be_flag\t\t[interface]\t\n");
    /*ljy--add end*/
    printf("\n");
    //return 0;
}

static int autelan_ioctl(struct iwreq *iwr, int cmd) 
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        printf("1 function ioctl::socket error ; %s\n", strerror(errno));
        return -1;
    }
    
    if (ioctl(s, cmd, iwr) < 0) {
        printf("2 function ioctl::ioctl error ; %s %x\n", strerror(errno),(unsigned int)ioctl);
        close(s);
        return -1;
    }
    close(s);

    return 0;
    
}

/*zhaoyang add for data forward base users*/
void autelan_tunnel_ctl_help()
{
    printf("\nusage:: autelan tunnel ctl COMMAND [OPTION] ... \n");
    printf("OPTIONS: \n");    
    printf("\t[interface]\t\tsetniflag [MAC] [flag] [protal IP addr]\n");
    /*Begin: zhaoyang1 add for getting infomation of niflag 2013-03-23*/
    printf("\t[interface]\t\tgetniflag [MAC]\n");
    /*End: zhaoyang1 add for getting infomation of niflag 2013-03-23*/
    printf("\n");
}

static void setniflag(int argc, char** argv)
{
     if(argc != 10){
        autelan_tunnel_ctl_help();
        return ;
        
     } else{    
        struct ieee80211_autelan_tunnel_ctl parm;         
        u_int8_t buf[1024];        
        
        parm.type = SET_NIFLAG;
        parm.ni_localflags = atoi(argv[5]);
        //set the portal server IP addr
        parm.ni_portal_ipaddr[0] = atoi(argv[6]); 
        parm.ni_portal_ipaddr[1] = atoi(argv[7]);
        parm.ni_portal_ipaddr[2] = atoi(argv[8]);
        parm.ni_portal_ipaddr[3] = atoi(argv[9]);
        int i,j;
        char low,high;
        int low32,high32,result32;
        for(i=0;i<6;i++)
        {
            j = i*3;
            high = argv[4][j];
            low = argv[4][j+1];    
        
            if(high >=48 && high <= 57)//0 to 9
                high32 = high - 48;
            else if(high >= 65 && high <= 70)//A to F
                high32 = high - 55;
            else if(high >=97 && high <= 102)//a to f
                high32 = high - 87;
            else 
            {
                printf("autelan.c:MAC error!\n");
                return ;
            }
            
            if(low >= 48 && low <= 57)//0 to 9
                low32 = low - 48;
            else if(low >= 65 && low <= 70)//A to F
                low32 = low - 55;
            else if(low >=97 && low <= 102)//a to f
                low32 = low - 87;
            else 
            {
                printf("autelan.c:MAC error!\n");
                return ;
            }
            result32 = high32 * 16 + low32;
            parm.ni_macaddr[i] = result32;
        }
               
        memset(buf, 0x00, 1024);
        memcpy(buf, &parm, sizeof(struct ieee80211_autelan_tunnel_ctl));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        if(autelan_ioctl(&iwr, IEEE80211_IOCTL_SET_NIFLAG) !=0)
            printf("autelan.c:set ni localflag error.\n");
     }
}

/*Begin: zhaoyang1 add for getting infomation of niflag 2013-03-23*/
static void getniflag(int argc, char** argv)
{
     if(argc != 5){
        autelan_tunnel_ctl_help();
        return ;
        
     } else{    
        struct ieee80211_autelan_tunnel_ctl parm = {0};
                
        u_int8_t buf[1024];        
        
        parm.type = GET_NIFLAG;
        //set the portal server IP addr
        int i,j;
        char low,high;
        int low32,high32,result32;
        for(i=0;i<6;i++)
        {
            j = i*3;
            high = argv[4][j];
            low = argv[4][j+1];    
        
            if(high >=48 && high <= 57)//0 to 9
                high32 = high - 48;
            else if(high >= 65 && high <= 70)//A to F
                high32 = high - 55;
            else if(high >=97 && high <= 102)//a to f
                high32 = high - 87;
            else 
            {
                printf("autelan.c:MAC error!\n");
                return ;
            }
            
            if(low >= 48 && low <= 57)//0 to 9
                low32 = low - 48;
            else if(low >= 65 && low <= 70)//A to F
                low32 = low - 55;
            else if(low >=97 && low <= 102)//a to f
                low32 = low - 87;
            else 
            {
                printf("autelan.c:MAC error!\n");
                return ;
            }
            result32 = high32 * 16 + low32;
            parm.ni_macaddr[i] = result32;
        }
               
        memset(buf, 0x00, 1024);
        memcpy(buf, &parm, sizeof(struct ieee80211_autelan_tunnel_ctl));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        if(autelan_ioctl(&iwr, IEEE80211_IOCTL_SET_NIFLAG) !=0)
            printf("autelan.c:get ni localflag error.\n");

        printf("%02X:%02X:%02X:%02X:%02X:%02X\n",  
                parm.ni_macaddr[0], parm.ni_macaddr[1], parm.ni_macaddr[2], 
                parm.ni_macaddr[3], parm.ni_macaddr[4], parm.ni_macaddr[5]);

        memset(&parm, 0, sizeof(struct ieee80211_autelan_tunnel_ctl));
        memcpy(&parm, buf, sizeof(struct ieee80211_autelan_tunnel_ctl));
        
        printf("niflag: %d \nportal ip: %d.%d.%d.%d\n", parm.ni_localflags, 
                parm.ni_portal_ipaddr[0], parm.ni_portal_ipaddr[1], 
                parm.ni_portal_ipaddr[2], parm.ni_portal_ipaddr[3]);
     }
}
/*End: zhaoyang1 add for getting infomation of niflag 2013-03-23*/

/*
 *this function deal with set ni flag
 */
int autelan_tunnel_ctl(int argc, char** argv)
{
     
    /*check arc number*/
    if (argc < 5) {
        
        /*should print autelan_tunnel_ctl help information*/
        autelan_tunnel_ctl_help ();
        return -1;
    }

    if (strncmp (argv[3], "setniflag", strlen("setniflag")) == 0) {

        setniflag(argc, argv);
    } 
    /*Begin: zhaoyang1 add for getting infomation of niflag 2013-03-23*/
    else if (strncmp (argv[3], "getniflag", strlen("getniflag")) == 0) {
        getniflag(argc, argv);
    }
    /*End: zhaoyang1 add for getting infomation of niflag 2013-03-23*/
    else {

           autelan_tunnel_ctl_help();
    }
        
    return 0;
}
/*zhaoyang modify end*/

static int tos_flag (int argc, char** argv) 
{
    if (argc < 5) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        int i = atoi(argv[4]);
        if (i < 0 || i > 1) {
            
            printf("Invalid tos flag value\n");
        } else {

            //autelan_debug("------get tos flg : %d \n", i);

            u_int8_t buf[1024];
            struct ieee80211_autelan_wmm_params a = {0};
            a.type = TOS_FLAG;
            a.arg1 = i;
            a.arg2 = 0;
            a.index = 0;
            memset(buf, 0x00, 1024);
            memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
            
            struct iwreq iwr;
            (void) memset(&iwr, 0, sizeof(iwr));
            (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
            iwr.u.data.pointer = (void *) buf;
            iwr.u.data.length = sizeof(buf);
            autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        }
        
    }

    return 0;
    
}

static int get_tos_flag (int argc, char** argv) 
{
    if (argc < 4) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_wmm_params a = {0};
        a.type = GET_TOS_FLAG;
        a.arg1 = 0;
        a.arg2 = 0;
        a.index = 0;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        printf("wlanset wmm config : get tos flag :: %d\n", buf[0]);
    }

    return 0;
    
}

int tos_ingress_map (int argc, char** argv) 
{
    if (argc < 6) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        int i = atoi(argv[4]);
        int j = atoi(argv[5]);
        if (i < 0 || j < 0 || i > 7 || j > 255) {//Modified by zhaoyang1 for optimize map of tos vlan & 80211e up 2013-01-28
            
            printf("Invalid ip tos map value\n");
        } else {

            //autelan_debug("------get tos ingress map : %d ::%d \n", i, j);


            u_int8_t buf[1024];
            struct ieee80211_autelan_wmm_params a = {0};
            a.type = TOS_INGRESS;
            a.arg1 = i;
            a.arg2 = j;
            a.index = 0;
            memset(buf, 0x00, 1024);
            memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
            
            struct iwreq iwr;
            (void) memset(&iwr, 0, sizeof(iwr));
            (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
            iwr.u.data.pointer = (void *) buf;
            iwr.u.data.length = sizeof(buf);
            autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        }
        
    }

    return 0;
    
}

static int get_tos_ingress_map (int argc, char** argv) 
{
    int i = 0;
    if (argc < 4) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        static unsigned char buf[1024];
        struct ieee80211_autelan_wmm_params a = {0};
        a.type = GET_TOS_INGRESS;
        a.arg1 = 0;
        a.arg2 = 0;
        a.index = 0;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        printf("wlanset wmm config , get tos  ingress map :\n");
        printf("\t\twmm-qos\t::\ttos-qos\n");

        for ( ; i < 8; i++ ) {
            printf("\t\t0x%02x\t::\t0x%02x\n", i , buf[i]);
        }
    }

    return 0;
    
}

int tos_egress_map (int argc, char** argv) 
{
    if (argc < 6) {//Begin:Modified by zhaoyang1 for optimize map of tos vlan & 80211e up 2013-01-28
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        //int index = atoi(argv[4]);
        int i = atoi(argv[4]);
        int j = atoi(argv[5]);
        if (i < 0 || j < 0 || i > 7 || j > 63) {
            
            printf("Invalid ip tos map value\n");
        } else {

            //autelan_debug("------get tos ingress map : %d ::%d \n", i, j);

            u_int8_t buf[1024];
            struct ieee80211_autelan_wmm_params a = {0};
            a.type = TOS_EGRESS;
            a.arg1 = i;
            a.arg2 = j;
            a.index = 0;
            memset(buf, 0x00, 1024);
            memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
            
            struct iwreq iwr;
            (void) memset(&iwr, 0, sizeof(iwr));
            (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
            iwr.u.data.pointer = (void *) buf;
            iwr.u.data.length = sizeof(buf);
            autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        }
        
    }

    return 0;
    
}

static int get_tos_egress_map (int argc, char** argv) 
{
    int i = 0;
    if (argc < 4) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        static unsigned char buf[1024];
        struct ieee80211_autelan_wmm_params a = {0};
        a.type = GET_TOS_EGRESS;
        a.arg1 = 0;
        a.arg2 = 0;
        a.index = 0;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        printf("wlanset wmm config , get tos  egress map :\n");
        printf("\ttos-qos\t::\twmm-qos\n");

        for ( ; i < 64; i++ ) {
            printf("\t0x%02x\t::\t0x%02x\n", i, buf[i]);
        }
    }

    return 0;
    
}

int vlan_flag (int argc, char** argv) 
{
    if (argc < 5) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        int i = atoi(argv[4]);
        if (i < 0 || i > 1) {
            
            printf("Invalid 1p flag value\n");
        } else {

            //autelan_debug("------get ip flg : %d \n", i);

            u_int8_t buf[1024];
            struct ieee80211_autelan_wmm_params a = {0};
            a.type = VLAN_FLAG;
            a.arg1 = i;
            a.arg2 = 0;
            a.index = 0;
            memset(buf, 0x00, 1024);
            memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
            
            struct iwreq iwr;
            (void) memset(&iwr, 0, sizeof(iwr));
            (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
            iwr.u.data.pointer = (void *) buf;
            iwr.u.data.length = sizeof(buf);
            autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        }
        
    }

    return 0;
    
}

static int get_vlan_flag (int argc, char** argv) 
{
    if (argc < 4) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_wmm_params a = {0};
        a.type = GET_VLAN_FLAG;
        a.arg1 = 0;
        a.arg2 = 0;
        a.index = 0;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        printf("wlanset wmm config : get 1p flag :: %d\n", buf[0]);
    }

    return 0;
    
}

int vlan_egress_map (int argc, char** argv) 
{
    if (argc < 6) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        int i = atoi(argv[4]);
        int j = atoi(argv[5]);
        if (i < 0 || j < 0 ||i > 7 || j > 7) {//Begin:Modified by zhaoyang1 for optimize map of tos vlan & 80211e up 2013-01-28
            
            printf("Invalid 1p map value\n");
        } else {

            //autelan_debug("------get tos egress map : %d ::%d \n", i, j);

            u_int8_t buf[1024];
            struct ieee80211_autelan_wmm_params a = {0};
            a.type = VLAN_EGRESS;
            a.arg1 = i;
            a.arg2 = j;
            a.index = 0;
            memset(buf, 0x00, 1024);
            memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
            
            struct iwreq iwr;
            (void) memset(&iwr, 0, sizeof(iwr));
            (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
            iwr.u.data.pointer = (void *) buf;
            iwr.u.data.length = sizeof(buf);
            autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        }
        
    }

    return 0;
    
}

static int get_vlan_egress_map (int argc, char** argv) 
{
    int i = 0;
    if (argc < 4) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_wmm_params a = {0};
        a.type = GET_VLAN_EGRESS;
        a.arg1 = 0;
        a.arg2 = 0;
        a.index = 0;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        printf("wlanset wmm config , get 1p vlan egress map :\n");
        printf("\t\tvlan-qos\t::\twmm-qos\n");
        for ( ; i < 8; i++ ) {
            
            printf("\t\t%d\t::\t%d\n", i , buf[i]);
        }
    }

    return 0;
    
}

int vlan_ingress_map (int argc, char** argv) 
{
    if (argc < 6) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        int i = atoi(argv[4]);
        int j = atoi(argv[5]);
        if (i < 0 || j < 0 || i > 7 || j > 7) {//Begin:Modified by zhaoyang1 for optimize map of tos vlan & 80211e up 2013-01-28
            
            printf("Invalid 1p map value\n");
        } else {

            //autelan_debug("------get tos ingress map : %d ::%d \n", i, j);

            u_int8_t buf[1024];
            struct ieee80211_autelan_wmm_params a = {0};
            a.type = VLAN_INGRESS;
            a.arg1 = i;
            a.arg2 = j;
            a.index = 0;
            memset(buf, 0x00, 1024);
            memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
            
            struct iwreq iwr;
            (void) memset(&iwr, 0, sizeof(iwr));
            (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
            iwr.u.data.pointer = (void *) buf;
            iwr.u.data.length = sizeof(buf);
            autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        }
        
    }

    return 0;
    
}

static int get_vlan_ingress_map (int argc, char** argv) 
{
    int i = 0;
    if (argc < 4) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_wmm_params a = {0};
        a.type = GET_VLAN_INGRESS;
        a.arg1 = 0;
        a.arg2 = 0;
        a.index = 0;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        printf("wlanset wmm config , get 1p vlan ingress map :\n");
        printf("\t\twmm-qos\t::\tvlan-qos\n");

        for ( ; i < 8; i++ ) {//Begin:Modified by zhaoyang1 for optimize map of tos vlan & 80211e up 2013-01-28
            
            printf("\t\t%d\t::\t%d\n", i , buf[i]);
        }
    }

    return 0;
    
}

/*ljy--add begin to append the switch modified the best effort parameter*/
static int be_flag (int argc, char** argv) 
{
    if (argc < 5) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        int i = atoi(argv[4]);
        if (i < 0 || i > 1) {
            
            printf("Invalid tos flag value\n");
        } else {

            u_int8_t buf[1024];
            struct ieee80211_autelan_wmm_params a = {0};
            a.type = BE_FLAG;
            a.arg1 = i;
            a.arg2 = 0;
            a.index = 0;
            memset(buf, 0x00, 1024);
            memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
            
            struct iwreq iwr;
            (void) memset(&iwr, 0, sizeof(iwr));
            (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
            iwr.u.data.pointer = (void *) buf;
            iwr.u.data.length = sizeof(buf);
            autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        }
        
    }

    return 0;
    
}

static int get_be_flag (int argc, char** argv) 
{
    if (argc < 4) {
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;    
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_wmm_params a = {0};
        a.type = GET_BE_FLAG;
        a.arg1 = 0;
        a.arg2 = 0;
        a.index = 0;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_wmm_params));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[3], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_AUTELAN_WMM);
        printf("wlanset wmm config : get be flag :: %d\n", buf[0]);
    }

    return 0;
    
}
/*ljy--add end*/

/*
 *this function deal with wmm stuff
 */
int autelan_wmm (int argc, char** argv)
{

    /*check arc number*/
    if (argc < 3) {
        
        /*should print autelan wmm help information*/
        autelan_wmm_help ();
        return -1;
    }

    if (strncmp (argv[2], "tos_flag", strlen("tos_flag")) == 0) {
        
        tos_flag(argc, argv);
    
    } else if (strncmp (argv[2], "get_tos_flag", strlen("get_tos_flag")) == 0) {
        
        get_tos_flag(argc, argv);
    
    } else if (strncmp (argv[2], "1p_flag", strlen("1p_flag")) == 0) {
        
        vlan_flag(argc, argv);
    
    } else if (strncmp (argv[2], "get_1p_flag", strlen("get_1p_flag")) == 0) {
        
        get_vlan_flag(argc, argv);
    
    }else if (strncmp (argv[2], "1p_egress_map", strlen("1p_egress-map")) == 0) {
        
        vlan_egress_map(argc, argv);
    
    } else if (strncmp (argv[2], "get_1p_egress_map", strlen("get_1p_egress-map")) == 0) {
        
        get_vlan_egress_map(argc, argv);
    
    } else if (strncmp (argv[2], "1p_ingress_map", strlen("1p_ingress_map")) == 0) {
        
        vlan_ingress_map(argc, argv);
    
    } else if (strncmp (argv[2], "get_1p_ingress_map", strlen("get_1p_ingress_map")) == 0) {
        
        get_vlan_ingress_map(argc, argv);
    
    } else if (strncmp (argv[2], "tos_ingress_map", strlen("tos_ingress_map")) == 0) {
        
        tos_ingress_map(argc, argv);
    
    } else if (strncmp (argv[2], "get_tos_ingress_map", strlen("get_tos_ingress_map")) == 0) {
        
        get_tos_ingress_map(argc, argv);
    
    } else if (strncmp (argv[2], "tos_egress_map", strlen("tos_egress_map")) == 0) {
        
        tos_egress_map(argc, argv);
    
    } else if (strncmp (argv[2], "get_tos_egress_map", strlen("get_tos_egress_map")) == 0) {
        
        get_tos_egress_map(argc, argv);
    
    /*ljy--add begin to append the switch modified the best effort parameter*/
    } else if (strncmp (argv[2], "be_flag", strlen("be_flag")) == 0) {
        
        be_flag(argc, argv);
    
    } else if (strncmp (argv[2], "get_be_flag", strlen("get_be_flag")) == 0) {
        
        get_be_flag(argc, argv);
    
    /*ljy--add end*/
    } else {
        //*should print autelan wmm help information*/
        autelan_wmm_help ();
    }
    
    return 0;

}

/*AUTELAN-Added-Begin: Modified by WangJia, for traffic limit. 2012-11-02.*/
/*
 *autelan traffic limit help information
 */
static void autelan_traffic_limit_help () 
{
    //printf("\nUSAGE : autelan traffic_limit [OPTION]\n");
    printf("\nUSAGE : wlanset traffic_limit [OPTION]\n");
    printf("OPTION: \n");
    printf("\t[IFNAME]\tset_vap_flag\t\t\t[0|1]\n");
    printf("\t[IFNAME]\tget_vap_flag\n");
    
    printf("\t[IFNAME]\tset_vap\t\t\t\t[traffic number]\n");
    printf("\t[IFNAME]\tget_vap\n");

    /*ljy--add begin to separate traffic limit between rx and tx*/
    printf("\t[IFNAME]\tset_vap_send\t\t\t[traffic number]\n");
    printf("\t[IFNAME]\tget_vap_send\n");
    /*ljy--add end*/

    printf("\t[IFNAME]\tset_every_node_flag\t\t[0|1]\n");
    printf("\t[IFNAME]\tget_every_node_flag\n");
    
    printf("\t[IFNAME]\tset_every_node\t\t\t[traffic number]\n");
    printf("\t[IFNAME]\tget_every_node\n");

    /*ljy--add begin to separate traffic limit between rx and tx*/
    printf("\t[IFNAME]\tset_every_node_send\t\t[traffic number]\n");
    printf("\t[IFNAME]\tget_every_node_send\n");
    /*ljy--add end*/

    /*ljy--modified begin to adjust policy of traffic limit*/
    printf("\t[IFNAME]\tset_specific_node_flag\t\t[node_mac]\t[0|1]\n");
    printf("\t[IFNAME]\tget_specific_node_flag\t\t[node_mac]\n");
    /*ljy--modified end*/

    printf("\t[IFNAME]\tset_specific_node\t\t[node_mac]\t[traffic number]\n");
    printf("\t[IFNAME]\tget_specific_node\t\t[node_mac]\n");

    /*ljy--add begin to separate traffic limit between rx and tx*/
    printf("\t[IFNAME]\tset_specific_node_send\t\t[node_mac]\t[traffic number]\n");
    printf("\t[IFNAME]\tget_specific_node_send\t\t[node_mac]\n");
    /*ljy--add end*/

    printf("\t[IFNAME]\tshow_status\n");
    printf("\t[IFNAME]\tset_dequeue_threshold\n");
    printf("\t[IFNAME]\tset_tasklet_timeslice\n");
    printf("\t[IFNAME]\tset_debug_flag FLAG\n");
    printf("\t[IFNAME]\tget_debug_flag\n");
    printf("\t[IFNAME]\tget_everynode_queue_len\n");
    
    printf("\n");
}
/*AUTELAN-Added-End: Modified by WangJia, for traffic limit. 2012-11-02.*/

/*AUTELAN-Added-Begin: Added by WangJia, for traffic limit. 2012-11-02.*/
int get_vap_traffic_limit_status(int argc, char** argv)
{
    if (argc < 4) {
        autelan_traffic_limit_help() ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = TL_GET_TRAFFIC_LIMIT_STATUS;

        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
    }
    
    return 0;
}

int set_dequeue_threshold(int argc, char** argv)
{
    if (argc < 5) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {
        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};

        a.type = TL_SET_DEQUEUE_THRESHOLD;
        a.arg1 = atoi(argv[4]);            // offset 1 byte, tasklet time slice
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
    }
    return 0;
}

int get_dequeue_threshold(int argc, char** argv)
{
    if (argc < 4) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {
        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = TL_GET_DEQUEUE_THRESHOLD;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *)buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
    }
    return 0;
}

int set_tasklet_timeslice(int argc, char** argv)
{
    if (argc < 5) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {
        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};

        a.type = TL_SET_TASKLET_TIMESLICE;
        a.arg1 = atoi(argv[4]);            // tasklet time slice
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
    }
    return 0;
}

int get_tasklet_timeslice(int argc, char** argv)
{
    if (argc < 4) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {
        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = TL_GET_TASKLET_TIMESLICE;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *)buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
    }
    return 0;
}

int set_traffig_limit_debug_flag(int argc, char** argv)
{
    if (argc < 5) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {
        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = TL_SET_DEBUG_FLAG;
        a.arg1 = atoi(argv[4]);            // debug flag
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *)buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
    }
    return 0;

}

int get_traffig_limit_debug_flag(int argc, char** argv)
{
    if (argc < 4) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {
        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = TL_GET_DEBUG_FLAG;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *)buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
    }
    return 0;

}

int get_everynode_queue_len(int argc, char** argv)
{
    if (argc < 4) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {
        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = TL_GET_EVERYNODE_QUEUE_LEN;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *)buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
    }
    return 0;

}
/*AUTELAN-Added-End: Added by WangJia, for traffic limit. 2012-11-02.*/


/*
 *this function deal with multicast stuff
 */
int set_vap_traffic_limit (int argc, char** argv)
{
    if (argc < 5) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = SET_VAP_TRAFFIC_LIMIT;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);

    }
    return 0;
    
}

/*
 *this function deal with multicast stuff
 */
int get_vap_traffic_limit (int argc, char** argv)
{
    if (argc < 4) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        memset(buf, 0x00, 1024);
        struct ieee80211_autelan_traffic_limit a = {0};
        memset(&a, 0x00, sizeof(struct ieee80211_autelan_traffic_limit));
        a.type = GET_VAP_TRAFFIC_LIMIT;
        
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
        printf("wlanset traffic_limit %s get_vap %d \n", argv[2], *((int *)buf));

    }
    return 0;
    
}


/*
 *this function deal with multicast stuff
 */
int set_specific_node_traffic_limit (int argc, char** argv)
{
    if (argc < 6) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
        a.type = SET_SPECIFIC_NODE_TRAFFIC_LIMIT;
        a.arg1 = atoi(argv[5]);
        sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
        a.macaddr[0] = a0;
        a.macaddr[1] = a1;
        a.macaddr[2] = a2;
        a.macaddr[3] = a3;
        a.macaddr[4] = a4;
        a.macaddr[5] = a5;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);

    }
    return 0;
    
}

/*
 *this function deal with multicast stuff
 */
int get_specific_node_traffic_limit (int argc, char** argv)
{
    int ret = 0;
    if (argc < 5) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
        a.type = GET_SPECIFIC_NODE_TRAFFIC_LIMIT;
        a.arg1 = 0;
        sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
        a.macaddr[0] = a0;
        a.macaddr[1] = a1;
        a.macaddr[2] = a2;
        a.macaddr[3] = a3;
        a.macaddr[4] = a4;
        a.macaddr[5] = a5;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        ret = autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
        if (ret >= 0) {
            printf("wlanset traffic_limit %s get_node %02x:%02x:%02x:%02x:%02x:%02x :: %d \n", 
                argv[2], a.macaddr[0],a.macaddr[1],a.macaddr[2],a.macaddr[3],
                a.macaddr[4],a.macaddr[5], *((int *)buf));
        }
    }
    return 0;
    
}


/*
 *this function deal with traffic_limit
 */
int set_every_node_traffic_limit (int argc, char** argv)
{
    if (argc < 5) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = SET_EVERY_NODE_TRAFFIC_LIMIT;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);

    }
    return 0;
    
}

/*
 *this function deal with traffic_limit
 */
int get_every_node_traffic_limit (int argc, char** argv)
{
    if (argc < 4) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = GET_EVERY_NODE_TRAFFIC_LIMIT;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
        printf("wlanset traffic_limit %s get_every_node %d\n", argv[2], *((int *)buf));

    }
    return 0;
    
}


/*
 *this function deal with traffic_limit
 */
int set_vap_traffic_limit_flag (int argc, char** argv)
{
    if (argc < 5) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = SET_VAP_TRAFFIC_LIMIT_FLAG;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);

    }
    return 0;
    
}

/*
 *this function deal with traffic_limit
 */
int get_vap_traffic_limit_flag (int argc, char** argv)
{
    if (argc < 4) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = GET_VAP_TRAFFIC_LIMIT_FLAG;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
        printf("wlanset traffic_limit %s get_vap_flag %d\n",argv[2], *((int *)buf));

    }
    return 0;
    
}


/*
 *this function deal with traffic_limit
 */
int set_every_node_traffic_limit_flag (int argc, char** argv)
{
    if (argc < 5) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = SET_EVERY_NODE_TRAFFIC_LIMIT_FLAG;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);

    }
    return 0;
    
}

/*
 *this function deal with traffic_limit
 */
int get_every_node_traffic_limit_flag (int argc, char** argv)
{
    if (argc < 4) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = GET_EVERY_NODE_TRAFFIC_LIMIT_FLAG;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
        printf("wlanset traffic_limit %s get_every_node_flag %d\n", argv[2], *((int *)buf));

    }
    return 0;
    
}


/*
 *this function deal with traffic_limit
 */
int set_specific_node_traffic_limit_flag (int argc, char** argv)
{
    if (argc < 6) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {
        /*ljy--modified begin to adjust policy of traffic limit*/
        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a;
        int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
        a.type = SET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG;
        a.arg1 = atoi(argv[5]);
        sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
        a.macaddr[0] = a0;
        a.macaddr[1] = a1;
        a.macaddr[2] = a2;
        a.macaddr[3] = a3;
        a.macaddr[4] = a4;
        a.macaddr[5] = a5;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
        /*ljy--modified end*/
    }
    return 0;
    
}

/*
 *this function deal with traffic_limit
 */
int get_specific_node_traffic_limit_flag (int argc, char** argv)
{
    if (argc < 5) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {
        /*ljy--modified begin to adjust policy of traffic limit*/
        #if 0
        static u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = GET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
        printf("Autelan traffic_limit %s get_specific_node_flag %d\n", argv[2], buf[0]);
        #endif
        int ret = 0;
        static u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a;
        int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
        a.type = GET_SPECIFIC_NODE_TRAFFIC_LIMIT_FLAG;
        a.arg1 = 0;
        sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
        a.macaddr[0] = a0;
        a.macaddr[1] = a1;
        a.macaddr[2] = a2;
        a.macaddr[3] = a3;
        a.macaddr[4] = a4;
        a.macaddr[5] = a5;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        ret = autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
        if (ret >= 0) {
            printf("wlanset traffic_limit %s get_specific_node_flag %02x:%02x:%02x:%02x:%02x:%02x :: %d \n", 
                argv[2], a.macaddr[0],a.macaddr[1],a.macaddr[2],a.macaddr[3],
                a.macaddr[4],a.macaddr[5], *((int *)buf));
        }
        /*ljy--modified end*/
    }
    return 0;
    
}


/*ljy--add begin to separate traffic limit between rx and tx*/
/*
 *this function deal with multicast stuff
 */
int set_vap_traffic_limit_send (int argc, char** argv)
{
    if (argc < 5) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = SET_VAP_TRAFFIC_LIMIT_SEND;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);

    }
    return 0;
    
}

/*
 *this function deal with multicast stuff
 */
int get_vap_traffic_limit_send (int argc, char** argv)
{
    if (argc < 4) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        memset(buf, 0x00, 1024);
        struct ieee80211_autelan_traffic_limit a = {0};
        memset(&a, 0x00, sizeof(struct ieee80211_autelan_traffic_limit));
        a.type = GET_VAP_TRAFFIC_LIMIT_SEND;
        
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
        printf("wlanset traffic_limit %s get_vap_send %d \n", argv[2], *((int *)buf));

    }
    return 0;
    
}

/*
 *this function deal with multicast stuff
 */
int set_specific_node_traffic_limit_send (int argc, char** argv)
{
    if (argc < 6) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
        a.type = SET_SPECIFIC_NODE_TRAFFIC_LIMIT_SEND;
        a.arg1 = atoi(argv[5]);
        sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
        a.macaddr[0] = a0;
        a.macaddr[1] = a1;
        a.macaddr[2] = a2;
        a.macaddr[3] = a3;
        a.macaddr[4] = a4;
        a.macaddr[5] = a5;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);

    }
    return 0;
    
}

/*
 *this function deal with multicast stuff
 */
int get_specific_node_traffic_limit_send (int argc, char** argv)
{
    int ret = 0;
    if (argc < 5) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
        a.type = GET_SPECIFIC_NODE_TRAFFIC_LIMIT_SEND;
        a.arg1 = 0;
        sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
        a.macaddr[0] = a0;
        a.macaddr[1] = a1;
        a.macaddr[2] = a2;
        a.macaddr[3] = a3;
        a.macaddr[4] = a4;
        a.macaddr[5] = a5;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        ret = autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
        if (ret >= 0) {
            printf("wlanset traffic_limit %s get_node_send %02x:%02x:%02x:%02x:%02x:%02x :: %d \n", 
                   argv[2], a.macaddr[0],a.macaddr[1],a.macaddr[2],a.macaddr[3],
                   a.macaddr[4],a.macaddr[5], *((int *)buf));
        }
    }
    return 0;
    
}

/*
 *this function deal with traffic_limit
 */
int set_every_node_traffic_limit_send (int argc, char** argv)
{
    if (argc < 5) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = SET_EVERY_NODE_TRAFFIC_LIMIT_SEND;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);

    }
    return 0;
    
}

/*
 *this function deal with traffic_limit
 */
int get_every_node_traffic_limit_send (int argc, char** argv)
{
    if (argc < 4) {
        autelan_traffic_limit_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_traffic_limit a = {0};
        a.type = GET_EVERY_NODE_TRAFFIC_LIMIT_SEND;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_traffic_limit));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_TRAFFIC_LIMIT);
        printf("wlanset traffic_limit %s get_every_node_send %d\n", argv[2], *((int *)buf));

    }
    return 0;
    
}
/*ljy--add end*/

/*AUTELAN-Added-Begin: Added by WangJia, for traffic limit. 2013-03-06.*/
typedef struct autelan_traffic_limit_handler 
{
    const char *cmd_name;
    int (*cmd_handler)(int argc, char** argv);
} autelan_traffic_limit_handler;

static const autelan_traffic_limit_handler traffic_limit_handlers[] =
{
    {"set_vap_flag",   set_vap_traffic_limit_flag}, 
    {"get_vap_flag",   get_vap_traffic_limit_flag},
    {"set_vap",        set_vap_traffic_limit},
    {"get_vap",        get_vap_traffic_limit}, 
    {"set_vap_send",   set_vap_traffic_limit_send}, 
    {"get_vap_send",   get_vap_traffic_limit_send}, 
    {"set_every_node_flag",   set_every_node_traffic_limit_flag}, 
    {"get_every_node_flag",   get_every_node_traffic_limit_flag},
    {"set_every_node",        set_every_node_traffic_limit}, 
    {"get_every_node",        get_every_node_traffic_limit}, 
    {"set_every_node_send",   set_every_node_traffic_limit_send}, 
    {"get_every_node_send",   get_every_node_traffic_limit_send}, 
    {"set_specific_node_flag",   set_specific_node_traffic_limit_flag}, 
    {"get_specific_node_flag",   get_specific_node_traffic_limit_flag}, 
    {"set_specific_node",        set_specific_node_traffic_limit}, 
    {"get_specific_node",        get_specific_node_traffic_limit}, 
    {"set_specific_node_send",   set_specific_node_traffic_limit_send}, 
    {"get_specific_node_send",   get_specific_node_traffic_limit_send}, 
    {"show_status",              get_vap_traffic_limit_status}, 
    {"set_dequeue_threshold",    set_dequeue_threshold}, 
    {"get_dequeue_threshold",    get_dequeue_threshold}, 
    {"set_tasklet_timeslice",    set_tasklet_timeslice},
    {"get_tasklet_timeslice",    get_tasklet_timeslice}, 
    {"set_debug_flag",           set_traffig_limit_debug_flag},
    {"get_debug_flag",           get_traffig_limit_debug_flag}, 
    {"get_everynode_queue_len",  get_everynode_queue_len}, 
    {"", NULL}
};
/*AUTELAN-Added-End: Added by WangJia, for traffic limit. 2013-03-06.*/

/*AUTELAN-Added-Begin: Modified by WangJia, for traffic limit. 2013-03-06.*/
/*
 *this function deal with traffic limit stuff
 */
int autelan_traffic_limit (int argc, char** argv)
{
    int index = 0;
    
    /*check arg number*/
    if (argc < 4) {
        
        /*should print autelan traffic limit help information*/
        autelan_traffic_limit_help ();
        return -1;
    }

    for(index = 0; traffic_limit_handlers[index].cmd_handler != NULL; index++)
    {
        if(strlen(traffic_limit_handlers[index].cmd_name) == strlen(argv[3]) &&
           strncmp(argv[3], traffic_limit_handlers[index].cmd_name, strlen(argv[3])) == 0)
        {   
            traffic_limit_handlers[index].cmd_handler(argc, argv);
            break ;
        }
    }

    if(NULL == traffic_limit_handlers[index].cmd_handler)
    {
        autelan_traffic_limit_help();
    }

    return 0;
}
/*AUTELAN-Added-End: Modified by WangJia, for traffic limit. 2013-03-06.*/

/*************************begin wds roaming **********************/

/*
 *autelan quick roaming help information
 */
static void autelan_quick_roaming_help () 
{
    //printf("\nusage:: autelan quick_roaming COMMAND [OPTION] ... \n");
    printf("\nusage:: wlanset quick_roaming COMMAND [OPTION] ... \n");
    printf("OPTIONS: \n");
    printf("\t[interface]\t\tset_flag\t\t\t[ 0 | 1]\n");
    printf("\t[interface]\t\tget_flag\t\t\t[ 0 | 1]\n");
    printf("\t[interface]\t\tadd_node\t\t\t[macaddr]\n");
    printf("\n");
    //return 0;
}

int quick_roaming_set_flag(int argc, char** argv) 
{

    if (argc < 5) {
        autelan_quick_roaming_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_quick_roaming a = {0};
        a.type = SET_FLAG;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_quick_roaming));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_QUICK_ROAMING);

    }
    return 0;
;
}

int quick_roaming_get_flag(int argc, char** argv) 
{

    if (argc < 4) {

        autelan_quick_roaming_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_quick_roaming a = {0};
        a.type = GET_FLAG;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_quick_roaming));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_QUICK_ROAMING);
        printf("wlanset quick_roaming %s get_flag %d\n", argv[2], buf[0]);

    }
    return 0;
;
}

int quick_roaming_add_node(int argc, char** argv) 
{
    return 0;
}

/*
 *this function deal with wds roaming stuff
 */
int autelan_quick_roaming (int argc, char** argv)
{

    /*check arc number*/
    if (argc < 4) {
        
        /*should print autelan quick roaming help information*/
        autelan_quick_roaming_help ();
        return -1;
    }

    if (strncmp (argv[3], "set_flag", strlen("set_flag")) == 0) {
        
        quick_roaming_set_flag(argc, argv);
    
    } else if (strncmp (argv[3], "get_flag", strlen("get_flag")) == 0) { 
        
        quick_roaming_get_flag(argc, argv);
    
    } else {
        
        autelan_quick_roaming_help ();
    
    }
    
    return 0;

}


/*ljy--add begin to develop the policy of mac binding*/
/*
 *autelan mac binding help information
 */
static void autelan_mac_binding_help () 
{
    //printf("\nusage:: autelan mac binding COMMAND [OPTION] ... \n");
    printf("\nusage:: wlanset quick_roaming COMMAND [OPTION] ... \n");
    printf("OPTIONS: \n");
    printf("\t[interface]\t\tset_dhcp_enable\t\t\t[0 | 1]\n");
    printf("\t[interface]\t\tget_dhcp_enable\n");
    printf("\t[interface]\t\tset_ip_auto_learning\t\t[0 | 1]\n");
    printf("\t[interface]\t\tget_ip_auto_learning\n");
    printf("\t[interface]\t\tset_ip\t\t\t\t[node_mac]\t\t[ip address]\n");
    printf("\t[interface]\t\tget_ip\t\t\t\t[node_mac]\n");
    printf("\t[interface]\t\tset_vlan\t\t\t[node_mac]\t\t[vlan id]\n");
    printf("\t[interface]\t\tget_vlan\t\t\t[node_mac]\n");
    //sheyanbin--add to through the pppoe frame
    printf("\t[interface]\t\tset_pppoe_enable\t\t[0 | 1]\n");
    printf("\t[interface]\t\tget_pppoe_enable\n");
    //sheyanbin--add end
    printf("\n");
}

//sheyanbin--add to through the pppoe frame
int mac_binding_set_pppoe_enable (int argc, char** argv)
{
    if (argc < 5) {
        autelan_mac_binding_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_mac_binding a = {0};
        a.type = SET_PPPOE_ENABLE;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_mac_binding));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_MAC_BINDING);

    }
    return 0;
    
}

int mac_binding_get_pppoe_enable (int argc, char** argv)
{
    if (argc < 4) {
        autelan_mac_binding_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_mac_binding a = {0};
        a.type = GET_PPPOE_ENABLE;
        a.arg1 = 0;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_mac_binding));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_MAC_BINDING);
        printf("wlanset mac_binding %s get_pppoe_enable %d\n", argv[2], buf[0]);

    }
    return 0;
    
}
//sheyanbin--add end

int mac_binding_set_dhcp_enable (int argc, char** argv)
{
    if (argc < 5) {
        autelan_mac_binding_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_mac_binding a = {0};
        a.type = SET_DHCP_ENABLE;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_mac_binding));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_MAC_BINDING);

    }
    return 0;
    
}

int mac_binding_get_dhcp_enable (int argc, char** argv)
{
    if (argc < 4) {
        autelan_mac_binding_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_mac_binding a = {0};
        a.type = GET_DHCP_ENABLE;
        a.arg1 = 0;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_mac_binding));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_MAC_BINDING);
        printf("wlanset mac_binding %s get_dhcp_enable %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

int mac_binding_set_ip_auto_learning (int argc, char** argv)
{
    if (argc < 5) {
        autelan_mac_binding_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_mac_binding a = {0};
        a.type = SET_IP_AUTO_LEARNING;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_mac_binding));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_MAC_BINDING);

    }
    return 0;
    
}

int mac_binding_get_ip_auto_learning (int argc, char** argv)
{
    int ret = 0;
    if (argc < 4) {
        autelan_mac_binding_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_mac_binding a = {0};
        a.type = GET_IP_AUTO_LEARNING;
        a.arg1 = 0;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_mac_binding));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        ret = autelan_ioctl(&iwr, IEEE80211_IOCTL_MAC_BINDING);
        if (ret >= 0) {
            printf("wlanset mac_binding %s get_ip_auto_learning %d\n", argv[2], buf[0]);
        }
    }
    return 0;
    
}

int mac_binding_set_ip (int argc, char** argv)
{
    if (argc < 6) {
        autelan_mac_binding_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_mac_binding a = {0};
        int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
        a.type = SET_IP;
        a.arg1 = 0;
        sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0, &a1, &a2, &a3, &a4, &a5);
        a.macaddr[0] = a0;
        a.macaddr[1] = a1;
        a.macaddr[2] = a2;
        a.macaddr[3] = a3;
        a.macaddr[4] = a4;
        a.macaddr[5] = a5;
        a0 = a1 = a2 = a3 = a4 = a5 = 0;
        sscanf(argv[5], "%d.%d.%d.%d",&a0, &a1, &a2, &a3);
        a.ipaddr[0] = a0;
        a.ipaddr[1] = a1;
        a.ipaddr[2] = a2;
        a.ipaddr[3] = a3;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_mac_binding));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_MAC_BINDING);

    }
    return 0;
    
}

int mac_binding_get_ip (int argc, char** argv)
{
    int ret = 0;
    if (argc < 5) {
        autelan_mac_binding_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_mac_binding a = {0};
        int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
        a.type = GET_IP;
        a.arg1 = 0;
        sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
        a.macaddr[0] = a0;
        a.macaddr[1] = a1;
        a.macaddr[2] = a2;
        a.macaddr[3] = a3;
        a.macaddr[4] = a4;
        a.macaddr[5] = a5;
        memset(a.ipaddr, 0x00, sizeof(a.ipaddr));
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_mac_binding));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        ret = autelan_ioctl(&iwr, IEEE80211_IOCTL_MAC_BINDING);
        if (ret >= 0) {
            memcpy(&a, buf, sizeof(struct ieee80211_autelan_mac_binding));
            printf("wlanset mac_binding %s get_ip %02x:%02x:%02x:%02x:%02x:%02x :: %d.%d.%d.%d\n", argv[2], a.macaddr[0], a.macaddr[1], a.macaddr[2], a.macaddr[3], a.macaddr[4], a.macaddr[5], a.ipaddr[0], a.ipaddr[1], a.ipaddr[2], a.ipaddr[3]);
        }
    }
    return 0;
    
}

int mac_binding_set_vlan (int argc, char** argv)
{
    if (argc < 6) {
        autelan_mac_binding_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_mac_binding a = {0};
        int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
        a.type = SET_VLAN;
        a.arg1 = atoi(argv[5]);
        sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0, &a1, &a2, &a3, &a4, &a5);
        a.macaddr[0] = a0;
        a.macaddr[1] = a1;
        a.macaddr[2] = a2;
        a.macaddr[3] = a3;
        a.macaddr[4] = a4;
        a.macaddr[5] = a5;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_mac_binding));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_MAC_BINDING);

    }
    return 0;
    
}

int mac_binding_get_vlan (int argc, char** argv)
{
    int ret = 0;
    if (argc < 5) {
        autelan_mac_binding_help () ;
        return -1;
    } else {

        static u_int8_t buf[1024];
        struct ieee80211_autelan_mac_binding a = {0};
        int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
        a.type = GET_VLAN;
        a.arg1 = 0;
        sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
        a.macaddr[0] = a0;
        a.macaddr[1] = a1;
        a.macaddr[2] = a2;
        a.macaddr[3] = a3;
        a.macaddr[4] = a4;
        a.macaddr[5] = a5;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_mac_binding));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        ret = autelan_ioctl(&iwr, IEEE80211_IOCTL_MAC_BINDING);
        if (ret >= 0) {
            printf("wlanset mac_binding %s get_vlan %02x:%02x:%02x:%02x:%02x:%02x :: %d\n", argv[2], a.macaddr[0], a.macaddr[1], a.macaddr[2], a.macaddr[3], a.macaddr[4], a.macaddr[5], *((u_int16_t *)buf));
        }
    }
    return 0;
    
}

/*
 *this function deal with mac binding
 */
int autelan_mac_binding (int argc, char** argv)
{

    /*check arc number*/
    if (argc < 4) {
        
        /*should print autelan mac binding help information*/
        autelan_mac_binding_help ();
        return -1;
    }

    if (strncmp (argv[3], "set_dhcp_enable", strlen("set_dhcp_enable")) == 0) {
        
        mac_binding_set_dhcp_enable(argc, argv);
    
    } else if (strncmp (argv[3], "get_dhcp_enable", strlen("get_dhcp_enable")) == 0) { 
        
        mac_binding_get_dhcp_enable(argc, argv);
    
    } else if (strncmp (argv[3], "set_ip_auto_learning", strlen("set_ip_auto_learning")) == 0) { 
        
        mac_binding_set_ip_auto_learning(argc, argv);
    
    } else if (strncmp (argv[3], "get_ip_auto_learning", strlen("get_ip_auto_learning")) == 0) { 
        
        mac_binding_get_ip_auto_learning(argc, argv);
    
    } else if (strncmp (argv[3], "set_ip", strlen("set_ip")) == 0) { 
        
        mac_binding_set_ip(argc, argv);
    
    } else if (strncmp (argv[3], "get_ip", strlen("get_ip")) == 0) { 
        
        mac_binding_get_ip(argc, argv);
    
    } else if (strncmp (argv[3], "set_vlan", strlen("set_vlan")) == 0) { 
        
        mac_binding_set_vlan(argc, argv);
    
    } else if (strncmp (argv[3], "get_vlan", strlen("get_vlan")) == 0) { 
        
        mac_binding_get_vlan(argc, argv);
        
    //sheyanbin--add to through the pppoe frame
    }
    else if (strncmp (argv[3], "set_pppoe_enable", strlen("set_pppoe_enable")) == 0) 
    {     
        mac_binding_set_pppoe_enable(argc, argv);    
    } 
    else if (strncmp (argv[3], "get_pppoe_enable", strlen("get_pppoe_enable")) == 0) 
    {         
        mac_binding_get_pppoe_enable(argc, argv);        
    //sheyanbin--add end
    } else {
        
        autelan_mac_binding_help ();
    
    }
    
    return 0;

}
/*ljy--add end*/


/*
 *autelan help information
 */
static void autelan_help () 
{
    //printf("\nusage:: autelan COMMAND [OPTION] ... \n");
    printf("\nusage:: wlanset COMMAND [OPTION] ... \n");
    printf("OPTIONS: \n");
    //printf("\twmm\t\t... ...\n");
    printf("\ttraffic_limit\t... ...\n");
    //printf("\tquick_roaming\t... ...\n");
    /*ljy--add begin to develop the policy of mac binding*/
    //printf("\tmac_binding\t... ...\n");
    /*ljy--add end*/
    //printf("\t80211_cache\t... ...\n");//Added by duanmingzhe for 80211 cache
    //printf("\ttunnel_ctl\t... ...\n");//zhaoyang add for data forward base users
    //printf("\tarp_filter\t... ...\n");/*AUTELAN-zhaoenjuan transplant (WangJia) for arp filter */
    printf("\tmgmt_debug\t... ...\n");         //Added by dongzw for mgmt debug
    //printf("\tchannel_utility\t... ...\n");         //AUTELAN-zhaoenjuan transplant (lisongbai) for get channel_utility 2013-12-27
    //printf("\tpacket_trace\t... ...\n"); //AUTELAN-zhaoenjuan add for packet_trace
    printf("\tsync_info\t... ...\n"); 
    printf("\tconnect_rule\t... ...\n");
    printf("\n");
    //return 0;
}


/*Begin:added by duanmingzhe for 80211 cache*/
static void autelan_80211_cache_help () 
{
    //printf("\nusage:: autelan 80211_cache  COMMAND [OPTION] ... \n");
    printf("\nusage:: wlanset 80211_cache  COMMAND [OPTION] ... \n");
    printf("OPTIONS: \n");    
    printf("\t[interface]\t\tset_enable\t\t\t\t[0 | 1]\n");
    printf("\t[interface]\t\tget_enable\n");
    printf("\t[interface]\t\tset_cache_enable\t\t\t[0 | 1]\n");
    printf("\t[interface]\t\tget_cache_enable\t\t\n");
    printf("\t[interface]\t\tset_cache_queue_maxlen_b\t\t[num]\n");
    printf("\t[interface]\t\tget_cache_queue_maxlen_b\t\t\n");
    printf("\t[interface]\t\tset_cache_queue_maxlen_g\t\t[num]\n");
    printf("\t[interface]\t\tget_cache_queue_maxlen_g\t\t\n");
    printf("\t[interface]\t\tset_cache_queue_maxlen_n\t\t[num]\n");
    printf("\t[interface]\t\tget_cache_queue_maxlen_n\t\t\n");
    printf("\t[interface]\t\tset_cache_threshold_b\t\t\t[num]\n");
    printf("\t[interface]\t\tget_cache_threshold_b\t\t\n");
    printf("\t[interface]\t\tset_cache_threshold_g\t\t\t[num]\n");    
    printf("\t[interface]\t\tget_cache_threshold_g\t\t\n");
    printf("\t[interface]\t\tset_cache_threshold_n\t\t\t[num]\n");
    printf("\t[interface]\t\tget_cache_threshold_n\t\t\n");
    printf("\t[interface]\t\tset_cache_limit\t\t\t\t[num]\n");
    printf("\t[interface]\t\tget_cache_limit\t\t\n");    
    printf("\t[interface]\t\tset_cache_priority_b\t\t\t[num]\n");
    printf("\t[interface]\t\tget_cache_priority_b\t\t\n");
    printf("\t[interface]\t\tset_cache_priority_g\t\t\t[num]\n");
    printf("\t[interface]\t\tget_cache_priority_g\t\t\n");
    printf("\t[interface]\t\tset_cache_priority_n\t\t\t[num]\n");
    printf("\t[interface]\t\tget_cache_priority_n\t\t\n");
    printf("\t[interface]\t\tget_cache_send_count\t\t\t\n");
    printf("\n");
}

int set_enable (int argc, char** argv)
{
    if (argc < 5) {
    autelan_80211_cache_help () ;
    return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_ENABLE;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));

        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;

}

int get_enable (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_ENABLE;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}


int set_cache_enable (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_ENABLE;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_enable (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_ENABLE;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("wlanset 80211_cache %s get_cache_enable %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

int set_cache_threshold_b (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_THRESHOLD_B;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_threshold_b (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_THRESHOLD_B;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("wlanset 80211_cache %s get_cache_threshold_b %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

int set_cache_threshold_g (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_THRESHOLD_G;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_threshold_g (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_THRESHOLD_G;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("wlanset 80211_cache %s get_cache_threshold_g %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

int set_cache_threshold_n (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_THRESHOLD_N;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_threshold_n (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_THRESHOLD_N;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("wlanset 80211_cache %s get_cache_threshold_n %d\n", argv[2], buf[0]);

    }
    return 0;
    
}


int set_cache_limit (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_LIMIT;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_limit (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_LIMIT;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("wlanset 80211_cache %s get_cache_limit %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

int set_cache_priority_b (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_PRIORITY_B;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_priority_b (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_PRIORITY_B;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("wlanset 80211_cache %s get_cache_priority_b %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

int set_cache_priority_g (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_PRIORITY_G;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_priority_g (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_PRIORITY_G;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("wlanset 80211_cache %s get_cache_priority_g %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

int set_cache_priority_n (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_PRIORITY_N;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_priority_n (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_PRIORITY_N;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("wlanset 80211_cache %s get_cache_priority_n %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

int set_cache_queue_maxlen_b (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_QUEUE_MAXLEN_B;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_queue_maxlen_b (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_QUEUE_MAXLEN_B;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("wlanset 80211_cache %s get_cache_queue_maxlen %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

int set_cache_queue_maxlen_g (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_QUEUE_MAXLEN_G;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_queue_maxlen_g (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_QUEUE_MAXLEN_G;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("wlanset 80211_cache %s get_cache_queue_maxlen %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

int set_cache_queue_maxlen_n (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_QUEUE_MAXLEN_N;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_queue_maxlen_n (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_QUEUE_MAXLEN_N;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("wlanset 80211_cache %s get_cache_queue_maxlen %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

#if 0
int set_cache_port (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_PORT;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_port (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_PORT;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("Autelan 80211_cache %s get_cache_port %d\n", argv[2], buf[0]);

    }
    return 0;
    
}


int set_cache_lost (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_LOST;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_lost (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_LOST;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("Autelan 80211_cache %s get_cache_lost %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

int set_cache_tos (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_TOS;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}

int get_cache_tos (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_TOS;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        printf("Autelan 80211_cache %s get_cache_send_count %d\n", argv[2], buf[0]);

    }
    return 0;
    
}

int set_cache_reserved_qlen (int argc, char** argv)
{
    if (argc < 5) {
        autelan_80211_cache_help () ;
        return -1;
    } else {
        u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = SET_CACHE_RESERVED_QLEN;
        a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}


int get_cache_node_len (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_NODE_LEN;
        //a.arg1 = atoi(argv[4]);
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);
        //printf("Autelan 80211_cache %s get_cache_send_count %d\n", argv[2], buf[0]);

    }
    return 0;
    
}
#endif
int get_cache_send_count (int argc, char** argv)
{
    if (argc < 4) {
        autelan_80211_cache_help () ;
        return -1;
    } else {

        static u_int32_t buf[1024];
        struct ieee80211_autelan_80211_cache a = {0};
        a.type = GET_CACHE_SEND_COUNT;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_80211_cache));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_80211_CACHE);

    }
    return 0;
    
}


int autelan_80211_cache(int argc, char** argv)
{

    /*check arc number*/
    if (argc < 4) {
        
        /*should print autelan mac binding help information*/
        autelan_80211_cache_help ();
        return -1;
    }

    if (strncmp (argv[3], "set_enable", strlen("set_enable")) == 0) {
            
        set_enable(argc, argv);
        
    } else if (strncmp (argv[3], "get_enable", strlen("get_enable")) == 0) { 
            
        get_enable(argc, argv);
        
    }else if (strncmp (argv[3], "set_cache_enable", strlen("set_cache_enable")) == 0) {
        
        set_cache_enable(argc, argv);
    
    } else if (strncmp (argv[3], "get_cache_enable", strlen("get_cache_enable")) == 0) { 
        
        get_cache_enable(argc, argv);
    
    } else if (strncmp (argv[3], "set_cache_threshold_b", strlen("set_cache_threshold_b")) == 0) { 
        
        set_cache_threshold_b(argc, argv);
    
    } else if (strncmp (argv[3], "get_cache_threshold_b", strlen("get_cache_threshold_b")) == 0) { 
        
        get_cache_threshold_b(argc, argv);
    
    }else if (strncmp (argv[3], "set_cache_threshold_g", strlen("set_cache_threshold_g")) == 0) { 
        
        set_cache_threshold_g(argc, argv);
    
    } else if (strncmp (argv[3], "get_cache_threshold_g", strlen("get_cache_threshold_g")) == 0) { 
        
        get_cache_threshold_g(argc, argv);
    
    }else if (strncmp (argv[3], "set_cache_threshold_n", strlen("set_cache_threshold_n")) == 0) { 
        
        set_cache_threshold_n(argc, argv);
    
    } else if (strncmp (argv[3], "get_cache_threshold_n", strlen("get_cache_threshold_n")) == 0) { 
        
        get_cache_threshold_n(argc, argv);
    
    }else if (strncmp (argv[3], "set_cache_queue_maxlen_b", strlen("set_cache_queue_maxlen_b")) == 0) { 
        
        set_cache_queue_maxlen_b(argc, argv);
    
    } else if (strncmp (argv[3], "get_cache_queue_maxlen_b", strlen("get_cache_queue_maxlen_b")) == 0) { 
        
        get_cache_queue_maxlen_b(argc, argv);
    
    }else if (strncmp (argv[3], "set_cache_queue_maxlen_g", strlen("set_cache_queue_maxlen_g")) == 0) { 
        
        set_cache_queue_maxlen_g(argc, argv);
    
    } else if (strncmp (argv[3], "get_cache_queue_maxlen_g", strlen("get_cache_queue_maxlen_g")) == 0) { 
        
        get_cache_queue_maxlen_g(argc, argv);
    
    }else if (strncmp (argv[3], "set_cache_queue_maxlen_n", strlen("set_cache_queue_maxlen_n")) == 0) { 
        
        set_cache_queue_maxlen_n(argc, argv);
    
    } else if (strncmp (argv[3], "get_cache_queue_maxlen_n", strlen("get_cache_queue_maxlen_n")) == 0) { 
        
        get_cache_queue_maxlen_n(argc, argv);
    
    }else if (strncmp (argv[3], "set_cache_limit", strlen("set_cache_limit")) == 0) { 
        
        set_cache_limit(argc, argv);
    
    } else if (strncmp (argv[3], "get_cache_limit", strlen("get_cache_limit")) == 0) { 
        
        get_cache_limit(argc, argv);
    
    }
    else if (strncmp (argv[3], "set_cache_priority_b", strlen("set_cache_priority_b")) == 0) 
    {     
        set_cache_priority_b(argc, argv);    
    } 
    else if (strncmp (argv[3], "get_cache_priority_b", strlen("get_cache_priority_b")) == 0) 
    {         
        get_cache_priority_b(argc, argv);    
        
    }else if (strncmp (argv[3], "set_cache_priority_g", strlen("set_cache_priority_g")) == 0) 
    {     
        set_cache_priority_g(argc, argv);    
    } 
    else if (strncmp (argv[3], "get_cache_priority_g", strlen("get_cache_priority_g")) == 0) 
    {         
        get_cache_priority_g(argc, argv);    
        
    }else if (strncmp (argv[3], "set_cache_priority_n", strlen("set_cache_priority_n")) == 0) 
    {     
        set_cache_priority_n(argc, argv);    
    } 
    else if (strncmp (argv[3], "get_cache_priority_n", strlen("get_cache_priority_n")) == 0) 
    {         
        get_cache_priority_n(argc, argv);    
        
    }
    #if 0
    else if (strncmp (argv[3], "set_cache_port", strlen("set_cache_port")) == 0) { 
        
        set_cache_port(argc, argv);
    
    } else if (strncmp (argv[3], "get_cache_port", strlen("get_cache_port")) == 0) { 
        
        get_cache_port(argc, argv);
        
    }
    else if (strncmp (argv[3], "set_cache_lost", strlen("set_cache_lost")) == 0) 
    {     
        set_cache_lost(argc, argv);    
    } 
    else if (strncmp (argv[3], "set_cache_lost", strlen("set_cache_lost")) == 0) 
    {         
        get_cache_lost(argc, argv);    
        
    }
    else if (strncmp (argv[3], "set_cache_tos", strlen("set_cache_tos")) == 0) 
    {     
        set_cache_tos(argc, argv);    
    } 
    else if (strncmp (argv[3], "get_cache_tos", strlen("get_cache_tos")) == 0) 
    {         
        get_cache_tos(argc, argv);    
        
    }else if (strncmp (argv[3], "get_cache_node_len", strlen("get_cache_node_len")) == 0) 
    {         
        get_cache_node_len(argc, argv);    
        
    }else if (strncmp (argv[3], "set_cache_reserved_qlen", strlen("set_cache_reserved_qlen")) == 0) 
    {         
        set_cache_reserved_qlen(argc, argv);    
        
    }
    #endif
    else if (strncmp (argv[3], "get_cache_send_count", strlen("get_cache_send_count")) == 0) 
    {         
        get_cache_send_count(argc, argv);    
        
    }else {
        
        autelan_80211_cache_help ();
    
    }
    
    return 0;

}
/*End:added by duanmingzhe for 80211 cache*/

/*AUTELAN-Begin:zhaoenjuan transplant (WangJia) for arp filter */
#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN 6
#endif

static void autelan_arp_filter_help()
{
    printf("\nUSAGE : autelan arp_filter [OPTION]\r\n");
    printf("OPTION: \r\n");
    printf("\t[IFNAME]  set_flag  [0|1]\r\n");
    printf("\t[IFNAME]  get_flag\r\n");

    printf("\t[IFNAME]  add       [AA:BB:CC:DD:EE:FF]\r\n");
    printf("\t[IFNAME]  del       [AA:BB:CC:DD:EE:FF]\r\n");
    printf("\t[IFNAME]  list\r\n");
}

int autelan_arp_filter(int argc, char** argv)
{
    if (argc < 4) {
        autelan_arp_filter_help ();
        return -1;
    }

    int ret = 0;
    struct iwreq iwr;
    static u_int8_t buf[1024];
    struct ieee80211_autelan_arp_filter af = {0};
    int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
    
    memset(buf, 0x00, 1024);
    memset(&iwr, 0, sizeof(iwr));
    
    if((strlen(argv[3]) == strlen("set_flag")) &&
       (strncmp (argv[3], "set_flag", strlen("set_flag")) == 0)) {
        if (argc > 5) {
            autelan_arp_filter_help ();
            return -1;
        }
        af.type = IEEE80211_PARAM_ARP_FILTER_SET_SWITCH;
        af.arg1 = atoi(argv[4]);
        if(0 != af.arg1 && 1 != af.arg1) {
            autelan_arp_filter_help ();
            return -1;
        }
    } else if((strlen(argv[3]) == strlen("get_flag")) &&
              (strncmp (argv[3], "get_flag", strlen("get_flag")) == 0)) {
        if (argc > 4) {
            autelan_arp_filter_help ();
            return -1;
        }
        af.type = IEEE80211_PARAM_ARP_FILTER_GET_SWITCH;
    } else if((strlen(argv[3]) == strlen("add")) &&
              (strncmp (argv[3], "add", strlen("add")) == 0)) {
        if (argc > 5) {
            autelan_arp_filter_help ();
            return -1;
        }
        af.type = IEEE80211_PARAM_ARP_FILTER_ADD_MAC;
        
        ret = sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
        /*find out whether the MAC is valid */
        if(ret != 6 || (a0<0 || a0>0xFF) || (a1<0 || a1>0xFF) || (a2<0 || a2>0xFF) ||
           (a3<0 || a3>0xFF) || (a4<0 || a4>0xFF) || (a5<0 || a5>0xFF)) {
            printf("Autelan arp filter, MAC address error!\r\n");
            return -1;
        }
        af.macaddr[0] = a0;
        af.macaddr[1] = a1;
        af.macaddr[2] = a2;
        af.macaddr[3] = a3;
        af.macaddr[4] = a4;
        af.macaddr[5] = a5;    
    } else if((strlen(argv[3]) == strlen("del")) &&
              (strncmp (argv[3], "del", strlen("del")) == 0)) {
        if (argc > 5) {
            autelan_arp_filter_help ();
            return -1;
        }
        af.type = IEEE80211_PARAM_ARP_FILTER_DEL_MAC;

        ret = sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
        /*find out whether the MAC is valid */
        if(ret != 6 || (a0<0 || a0>0xFF) || (a1<0 || a1>0xFF) || (a2<0 || a2>0xFF) ||
           (a3<0 || a3>0xFF) || (a4<0 || a4>0xFF) || (a5<0 || a5>0xFF)) {
            printf("Autelan arp filter, MAC address error!\r\n");
            return -1;
        }
        af.macaddr[0] = a0;
        af.macaddr[1] = a1;
        af.macaddr[2] = a2;
        af.macaddr[3] = a3;
        af.macaddr[4] = a4;
        af.macaddr[5] = a5;
    } else if((strlen(argv[3]) == strlen("list")) &&
       (strncmp (argv[3], "list", strlen("list")) == 0)) {
        if (argc > 4) {
            autelan_arp_filter_help ();
            return -1;
        }
        af.type = IEEE80211_PARAM_ARP_FILTER_LIST_MAC;
    } else {
        autelan_arp_filter_help ();
        return -1;
    }

    memcpy(buf, &af, sizeof(struct ieee80211_autelan_arp_filter));
    strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *)buf;
    iwr.u.data.length = sizeof(buf);
    ret = autelan_ioctl(&iwr, IEEE80211_IOCTL_ARP_FILTER);

    if(0 == ret) {
        switch(af.type) {
            case IEEE80211_PARAM_ARP_FILTER_SET_SWITCH:
                break;
            case IEEE80211_PARAM_ARP_FILTER_GET_SWITCH:
                printf("Autelan arp filter, switch: %s\r\n", *((int *)buf) ? "ON":"OFF");
                break;
            case IEEE80211_PARAM_ARP_FILTER_ADD_MAC:
                if(0 == *((int *)buf)) {
                    printf("Autelan arp filter, %02X:%02X:%02X:%02X:%02X:%02X added OK!\r\n",
                           a0, a1 , a2 , a3 , a4 , a5);
                } else {
                    printf("Autelan arp filter, %02X:%02X:%02X:%02X:%02X:%02X added Failed! ",
                           a0, a1 , a2 , a3 , a4 , a5);
                    if(ENOMEM == *((int *)buf)) {
                        printf("Too many MACs already!");
                    } 
                    printf("\r\n");
                }
                break;
            case IEEE80211_PARAM_ARP_FILTER_DEL_MAC:
                if(0 == *((int *)buf)) {
                    printf("Autelan arp filter, %02X:%02X:%02X:%02X:%02X:%02X deleted OK!\r\n",
                           a0, a1 , a2 , a3 , a4 , a5);
                } else {
                    printf("Autelan arp filter, %02X:%02X:%02X:%02X:%02X:%02X deleted Failed! ",
                           a0, a1 , a2 , a3 , a4 , a5);
                    if(ENOENT == *((int *)buf)) {
                        printf("No such entry!");
                    } 
                    printf("\r\n");
                }                
                break;
            case IEEE80211_PARAM_ARP_FILTER_LIST_MAC:
                {
                    int i = 0;
                    int mac_num = iwr.u.data.length;
                    
                    printf("Autelan arp filter, MAC list: %s\r\n", (mac_num==0)?"Empty!":"");
                    for(; i < mac_num; i++) {
                        printf("\t[%d]: %02X:%02X:%02X:%02X:%02X:%02X\r\n", i+1,
                            buf[MAC_ADDR_LEN*i+0], buf[MAC_ADDR_LEN*i+1],
                            buf[MAC_ADDR_LEN*i+2], buf[MAC_ADDR_LEN*i+3],
                            buf[MAC_ADDR_LEN*i+4], buf[MAC_ADDR_LEN*i+5]);
                    }
                }
                break;
        }
    }
    return 0;
}

#undef MAC_ADDR_LEN
/*AUTELAN-End:zhaoenjuan transplant (WangJia) for arp filter */

/*Begin:Added by dongzw for mgmt debug */
static void autelan_mgmt_debug_help()
{
    printf("\nUSAGE : autelan mgmt_debug [OPTION]\r\n");
    printf("OPTION: \r\n");
    printf("\t[IFNAME]  set_mgmt_debug  [0|1]\r\n");
    printf("\t[IFNAME]  get_mgmt_debug\r\n");
}

int autelan_mgmt_debug(int argc, char** argv)
{
    if (argc < 4) {
        autelan_mgmt_debug_help ();
        return -1;
    }

    int ret = 0;
    struct iwreq iwr;
    static u_int8_t buf[1024];
    struct ieee80211_autelan_mgmt_debug md = {0};

    memset(buf, 0x00, 1024);
    memset(&iwr, 0, sizeof(iwr));

    if((strlen(argv[3]) == strlen("set_mgmt_debug")) &&
        (strncmp (argv[3], "set_mgmt_debug", strlen("set_mgmt_debug")) == 0)) {
        if (argc > 5) {
            autelan_mgmt_debug_help ();
            return -1;
        }
        md.type = IEEE80211_PARAM_MGMT_DEBUG_SET_SWITCH;
        md.arg = atoi(argv[4]);
        if(0 != md.arg && 1 != md.arg) {
            autelan_mgmt_debug_help ();
            return -1;
        }
    } else if((strlen(argv[3]) == strlen("get_mgmt_debug")) &&
    (strncmp (argv[3], "get_mgmt_debug", strlen("get_mgmt_debug")) == 0)) {
        if (argc > 4) {
        autelan_mgmt_debug_help ();
        return -1;
        }
        md.type = IEEE80211_PARAM_MGMT_DEBUG_GET_SWITCH;
    } else {
        autelan_mgmt_debug_help ();
        return -1;
    }

    memcpy(buf, &md, sizeof(struct ieee80211_autelan_mgmt_debug));
    strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *)buf;
    iwr.u.data.length = sizeof(buf);
    ret = autelan_ioctl(&iwr, IEEE80211_IOCTL_MGMT_DEBUG);

    if(0 == ret) {
        switch(md.type) {
            case IEEE80211_PARAM_MGMT_DEBUG_SET_SWITCH:
                break;
            case IEEE80211_PARAM_MGMT_DEBUG_GET_SWITCH:
                printf("autelan mgmt debug, switch: %s\r\n", *((int *)buf) ? "enable" : "disable");
                break;
            default:
                break;
        }
    }
    return 0;
}
/* End: Added by dongzw for mgmt debug */

/* AUTELAN-Begin:zhaoenjuan transplant (lisongbai) for get channel utility 2013-12-27 */
static void autelan_channel_utility_help()
{
    printf("\nUSAGE : autelan channel_utility [OPTION]\r\n");
    printf("OPTION: \r\n");
    printf("\t[IFNAME]  N(m/h)\r\n");    
}

u_int32_t autelan_str2num(char * buf)
{
    u_int32_t retval = 0;
    char c;
    char * ptr = buf;
    while(c = *ptr++)
    {
        if(c >= '0' && c <= '9')
        {
            retval = retval * 10 + (c - '0');
        }
        else if(c == 'h')    //hour
        {
            retval = retval * 60;
            break;
        }
        else
        {
            break;
        }
    }
    return retval;
}

int autelan_print_ch_utility(char * cp, size_t timeintval)
{
#define SECS(n) (n) % 60
#define MINS(n) ((n) / 60) % 60
#define HRS(n)  (n) / 3600 %24    //hours -> 24h
    struct ieee80211_channel_utility *temp_cu;
    int counter = 0;
    u_int32_t space, p_ch_utility;
    u_int8_t rc_pct = 0, rf_pct = 0, tf_pct = 0;
    int i = 0, j = 0;

    p_ch_utility = *(u_int32_t *)cp;
    cp += 4;
    space =  *(u_int32_t *)cp;
    cp += 4;
    
    if(timeintval > 5)
        counter = timeintval;
    else
        counter = 12 * timeintval;
        
//        printf("index     time     rx_clear  rx_frame  tx_frame\n");
    printf("index     time     ch_util_rate  rx_rate  tx_rate\n");
    printf("|--------------------------------------------------|\n");
    for(i = 0; i < counter; i++)
    {
        j = 0;
        if(p_ch_utility <= i)
        {
            if(timeintval > 5)
                j = 1440;
            else
                j = 60;
        }
        temp_cu = (struct ieee80211_channel_utility *)((struct ieee80211_channel_utility *)cp + p_ch_utility + j - i);
        if((temp_cu->timestamps_sec == 0) || (temp_cu->cyclecount == 0))
            continue;
        if (temp_cu->cyclecount < 0xFFFFFFFF /100) {
            rc_pct = temp_cu->rxclearcount * 100 / temp_cu->cyclecount;
            rf_pct = temp_cu->rxfrmaecount * 100 / temp_cu->cyclecount;
            tf_pct = temp_cu->txfrmaecount * 100 / temp_cu->cyclecount;
        }
        else
        {
            rc_pct = temp_cu->rxclearcount / (temp_cu->cyclecount / 100);
            rf_pct = temp_cu->rxfrmaecount / (temp_cu->cyclecount / 100);
            tf_pct = temp_cu->txfrmaecount / (temp_cu->cyclecount / 100);
        }

        printf("| %-3d  %02lu:%02lu:%02lu       %3u%%         %3u%%      %3u%%  |\n", i, HRS(temp_cu->timestamps_sec), \
            MINS(temp_cu->timestamps_sec), SECS(temp_cu->timestamps_sec), rc_pct, rf_pct, tf_pct);
    }
    printf("|--------------------------------------------------|\n");
    return 0;
}

int autelan_channel_utility(int argc, char** argv)
{
#define CHANNEL_UTILITY_ALLOC_SIZE 40 *1024

    struct iwreq iwr;
    char *cp;
    static u_int8_t buf[CHANNEL_UTILITY_ALLOC_SIZE];
    unsigned int timeintval = 0;
    int ret = 0;
    
    if (argc < 4) {
        autelan_channel_utility_help ();
        return -1;
    }
    timeintval = autelan_str2num(argv[3]);

    if(timeintval > 1440)
    {
        printf("the hours is out of range(0-24h), the db just support 24 hour before, so just return the ch_utility_data of the last day\n");
        timeintval = 1440;
    }
    memset(buf, 0x00, CHANNEL_UTILITY_ALLOC_SIZE);
    memset(&iwr, 0, sizeof(iwr));
    memcpy(buf, &timeintval, sizeof(u_int32_t));
    strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *)buf;
    iwr.u.data.length = sizeof(buf);
    
    ret = autelan_ioctl(&iwr, IEEE80211_IOCTL_CHANNEL_UTILITY);
    if(ret== -1)
        printf("no result!the ch_util_open may be off!\n");
    else if(ret == -2)
        printf("the 11ac chip is not support the functions!\n");
    else
    {
        cp = buf;
        autelan_print_ch_utility(cp, timeintval);
    }
    return 0;
}
/* AUTELAN-End:zhaoenjuan transplant (lisongbai) for get channel utility 2013-12-27 */

/*AUTELAN-Begin:zhaoenjuan add for packet_trace*/
static void autelan_packet_trace_help () 
{
    printf("\nusage:: autelan packet trace COMMAND [OPTION] ... \n");
    printf("OPTIONS: \n");
    printf("\t\t[INTERFACE] set_filter_mac\t\t[MAC ADDRESS]\n");
    printf("\t\t[INTERFACE] get_filter_mac\n");
    printf("\n");
}

int packet_trace_set_mac (int argc, char** argv)
{
    int ret = 0;
    if (argc < 2) {
        autelan_packet_trace_help () ;
        return -1;
    } else {

        u_int8_t buf[1024];
        struct ieee80211_autelan_packet_trace a;
        int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
        a.type = SET_MAC;
        //a.arg1 = atoi(argv[4]);
        ret = sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
        /*find out whether the MAC is valid */
        if(ret != 6 || (a0<0 || a0>0xFF) || (a1<0 || a1>0xFF) || (a2<0 || a2>0xFF) ||
           (a3<0 || a3>0xFF) || (a4<0 || a4>0xFF) || (a5<0 || a5>0xFF)) {
            printf("Autelan packet_trace, MAC address error!\r\n");
            return -1;
        }
        a.macaddr[0] = a0;
        a.macaddr[1] = a1;
        a.macaddr[2] = a2;
        a.macaddr[3] = a3;
        a.macaddr[4] = a4;
        a.macaddr[5] = a5;
        memset(buf, 0x00, 1024);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_packet_trace));
        
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *) buf;
        iwr.u.data.length = sizeof(buf);
        autelan_ioctl(&iwr, IEEE80211_IOCTL_PACKET_TRACE);

    }
    return 0;
    
}

int packet_trace_get_mac (int argc, char** argv)
{
    int ret = 0;
    if (argc < 3) {
        autelan_packet_trace_help () ;
        return -1;
    } else {

        struct ieee80211_autelan_packet_trace a;
        u_int8_t mac[6]= {0};
        memset(&a, 0x00, sizeof(a));
        a.type = GET_MAC;
        a.arg1 = 0;
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *)&a;
        iwr.u.data.length = sizeof(a);
        ret = autelan_ioctl(&iwr, IEEE80211_IOCTL_PACKET_TRACE);
        if(0==ret)
        {
            
            mac[0] = a.macaddr[0];
            mac[1] = a.macaddr[1];
            mac[2] = a.macaddr[2];
            mac[3] = a.macaddr[3];
            mac[4] = a.macaddr[4];
            mac[5] = a.macaddr[5];
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
        }
        
    }
    return 0;
    
}



int autelan_packet_trace_cmd(int argc, char** argv)
{

    /*check arc number*/
    if (argc < 2) {
        
        /*should print autelan mac binding help information*/
        autelan_packet_trace_help ();
        return -1;
    }

    if (strncmp (argv[3], "set_filter_mac", strlen("set_filter_mac")) == 0) {
        
        packet_trace_set_mac(argc, argv);
    
    } else if (strncmp (argv[3], "get_filter_mac", strlen("get_filter_mac")) == 0) { 
        
        packet_trace_get_mac(argc, argv);
    
    }else {
        autelan_packet_trace_help ();
    
    }
    
    return 0;

}
/*AUTELAN-End:zhaoenjuan add for packet_trace*/

static void autelan_sync_info_help () 
{
    printf("\nusage:: autelan sync_info COMMAND [OPTION] ... \n");
    printf("OPTIONS: \n");
    printf("\t\t[WIFI INTERFACE] get_local_table\t\t\n");
    printf("\t\t[WIFI INTERFACE] get_neighbor_dev\n");
    printf("\t\t[WIFI INTERFACE] get_neighbor_table\n");
    printf("\t\t[WIFI INTERFACE] get_neighbor_user_by_mac\n");
    printf("\t\t[WIFI INTERFACE] get_scan_list\n");
    printf("\t\t[WIFI INTERFACE] sync_switch [VALUE]\n");
    printf("\t\t[WIFI INTERFACE] get_sync_switch\n");
    printf("\t\t[WIFI INTERFACE] sync_time  [VALUE]\n");
    printf("\t\t[WIFI INTERFACE] get_sync_time\n");
    printf("\t\t[WIFI INTERFACE] sync_debug [VALUE]\n");
    printf("\t\t[WIFI INTERFACE] get_sync_debug\n");
    printf("\t\t[WIFI INTERFACE] sync_auto_group [VALUE]\n");
    printf("\t\t[WIFI INTERFACE] get_sync_auto_group\n");
    printf("\t\t[WIFI INTERFACE] sync_neighbor_rssi_limit [VALUE]\n");
    printf("\t\t[WIFI INTERFACE] get_sync_neighbor_rssi_limit\n");
    printf("\n");
}


const char*
ethera_sprintf(const u_int8_t *mac)
{
	static char etherbuf[18];
	snprintf(etherbuf, sizeof(etherbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return etherbuf;
}

int get_local_table(int argc, char** argv)
{
    int ret = 0;
    u_int16_t len = 0;
    u_int16_t count = 0;
    u_int8_t *cp = NULL;
    u_int8_t buf[2048];
    
    if (argc < 2) {
        autelan_sync_info_help () ;
        return -1;
    } else {

        struct ieee80211_autelan_sync_info a;
        u_int8_t mac[6]= {0};
        memset(&a, 0x00, sizeof(a));
        a.type = GET_LOCAL_TABLE;
        a.arg1 = 0;
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        memset(buf, 0x00, 2048);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_sync_info));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *)buf;
        iwr.u.data.length = sizeof(buf);
        ret = autelan_ioctl(&iwr, SIOCSATHSYNCINFO);

        if(0 == ret) {
            len = iwr.u.data.length;

            if((len < sizeof(u_int16_t)) || (len > 2048))
            {
                printf("GET LOCAL USER INFO ERROR! LEN :%d\n",len);
                return -1;
            }

            cp = buf;
            count = *((u_int16_t *)cp);
            
            printf("==============================================SHOW LOCAL TABLE================================================\n");
            printf("GET LOCAL USER COUNT %d\n",count);
            
            cp += sizeof(u_int16_t);
            len -= sizeof(u_int16_t);

            while(len >= sizeof(struct userinfo_table_record))
            {
                struct userinfo_table_record *user;
                user = (struct userinfo_table_record *)cp;
                if(user != NULL)
                {
                    printf("MAC[%s] cap=(0x%x)\tidentify=%d identify_count=%d 2G(pro %d, auth %d)\t5G(pro %d, auth %d)\tavg_rssi(%d)\t avg_data_rssi(%d)\tassoc(%d) assoc_cnt(%d) TIME(%d)\n",\
                        ethera_sprintf(user->user_mac),user->user_cap,user->identify,user->identify_count,\
                        user->recv_probe_2g,user->recv_auth_2g,user->recv_probe_5g,user->recv_auth_5g,user->avg_mgmt_rssi,user->avg_data_rssi,user->assoc,user->assoc_cnt,user->stamp_time);
                    
                    cp += sizeof(struct userinfo_table_record);
                    len -= sizeof(struct userinfo_table_record);
                }
                else
                {
                    printf("GET LOCAL USER INFO ERROR!\n");
                }
            }
            printf("==============================================================================================================\n");
        }
    }
    return 0;

}
int get_neighbour_table(int argc, char** argv)
{
    int ret = 0;
    if (argc < 2) {
        autelan_sync_info_help () ;
        return -1;
    } else {

        struct ieee80211_autelan_sync_info a;
        u_int8_t mac[6]= {0};
        memset(&a, 0x00, sizeof(a));
        a.type = GET_NEIGHBOUR_TABLE;
        a.arg1 = 0;
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *)&a;
        iwr.u.data.length = sizeof(a);
        ret = autelan_ioctl(&iwr, SIOCSATHSYNCINFO);
    }
    return 0;

}

int get_neighbour_dev(int argc, char** argv)
{
    int ret = 0;
    int i = 0,j = 0;
    u_int16_t len = 0;
    u_int8_t ap_count = 0,vap_count = 0;
    u_int8_t *cp = NULL;
    u_int8_t buf[2048];
    
    if (argc < 2) {
        autelan_sync_info_help () ;
        return -1;
    } else {

        struct ieee80211_autelan_sync_info a;
        u_int8_t mac[6]= {0};
        memset(&a, 0x00, sizeof(a));
        a.type = GET_NEIGHBOUR_DEV;
        a.arg1 = 0;
        struct iwreq iwr;
        memset(buf, 0x00, 2048);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_sync_info));
        memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *)buf;
        iwr.u.data.length = sizeof(buf);
        ret = autelan_ioctl(&iwr, SIOCSATHSYNCINFO);

        if(0 == ret) {
            len = iwr.u.data.length;

            if((len < sizeof(u_int8_t)) || (len > 2048))
            {
                printf("GET MEIGHBOUR DEV INFO ERROR! LEN :%d\n",len);
                return -1;
            }
            printf("============================================SHOW NEIGHBOUR DEV==============================================\n");

            cp = buf;
            ap_count = *((u_int8_t *)cp);
            cp += sizeof(u_int8_t);
            len -= sizeof(u_int8_t);

            printf("GET MEIGHBOUR DEV COUNT %d\n",ap_count);

            for(i = 0; i < ap_count; i++)
            {
                printf("---NEIGHBOUR AP: %s\n",ethera_sprintf(cp));

                cp += IEEE80211_ADDR_LEN;
                len -= IEEE80211_ADDR_LEN;
                vap_count = *((u_int8_t *)cp);
                printf("GET DEV VAP COUNT %d\n",vap_count);
                cp += sizeof(u_int8_t);
                len -= sizeof(u_int8_t);

                for(j = 0; j < vap_count; j++)
                {
                    struct sync_dev_info *dev_info;
                    dev_info = (struct sync_dev_info *)cp;

                    printf("|VAP(%s) ESSID(%s)\n",ethera_sprintf(dev_info->dev_mac),dev_info->essid);
                    printf("|MODE(%s) STATE(%s) CHANNEL(%d) TXPOWER(%d) STA_CNT(%d)\n",dev_info->work_mode==1?"2.4G":"5.8G",\
                        dev_info->is_up?"UP":"DOWN",dev_info->channel,dev_info->txpower,dev_info->user_cnt);
                    
                    cp += sizeof(struct sync_dev_info);
                    len -= sizeof(struct sync_dev_info);
                }
                printf("\n");
            }
            
            printf("==============================================================================================================\n");
        }

        
    }
    return 0;

}


int get_neighbour_user_by_mac(int argc, char** argv)
{
    int ret = 0;
    u_int16_t len = 0;
    u_int8_t *cp = NULL;
    u_int8_t *ap_mac = NULL;
    u_int8_t ap_count;
    u_int8_t buf[2048];
    struct userinfo_table_record *user;
    
    int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
    if (argc < 3) {
        autelan_sync_info_help () ;
        return -1;
    } else {

        struct ieee80211_autelan_sync_info a;
        u_int8_t mac[6]= {0};
        memset(&a, 0x00, sizeof(a));
        a.type = GET_NEIGHBOUR_STA_BY_MAC;
        a.arg1 = 0;
        
        sscanf(argv[4], "%x:%x:%x:%x:%x:%x",&a0, &a1, &a2, &a3, &a4, &a5);
        a.sta_mac[0] = a0;
        a.sta_mac[1] = a1;
        a.sta_mac[2] = a2;
        a.sta_mac[3] = a3;
        a.sta_mac[4] = a4;
        a.sta_mac[5] = a5;
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        memset(buf, 0x00, 2048);
        memcpy(buf, &a, sizeof(struct ieee80211_autelan_sync_info));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *)buf;
        iwr.u.data.length = sizeof(buf);
        ret = autelan_ioctl(&iwr, SIOCSATHSYNCINFO);

        if(0 == ret) {
            len = iwr.u.data.length;

            if((len < 0) || (len > 2048))
            {
                printf("sta %s get mgmt frame info error! len :%d\n",argv[4],len);
                return 0;
            }

            printf("============================================SHOW NEIGHBOUR STA BY MAC==============================================\n");
            printf("|Local table:\n");
            if(len == 0)
            {
                printf("|Can't found sta[%s] in local table\n",argv[4]);
                return 0;
            }
            
            cp = buf;
            user = (struct userinfo_table_record *)cp;

            printf("|MAC[%s] cap=(0x%x) identify=%d identify_count=%d 2G(pro %d, auth %d)\t5G(pro %d, auth %d)\tavg_rssi(%d)\tavg_data_rssi(%d)\tassoc(%d) assoc_cnt(%d) TIME(%d)\n\n",\
                ethera_sprintf(user->user_mac),user->user_cap,user->identify,user->identify_count,user->recv_probe_2g,user->recv_auth_2g,user->recv_probe_5g,\
                user->recv_auth_5g,user->avg_mgmt_rssi,user->avg_data_rssi,user->assoc,user->assoc_cnt,user->stamp_time);

            cp += sizeof(struct userinfo_table_record);
            len -= sizeof(struct userinfo_table_record);
            ap_count = *(u_int8_t *)cp;
            cp += sizeof(u_int8_t);
            len -= sizeof(u_int8_t);
            
            printf("|Neighbour table:\n");
            while(len >= (sizeof(struct userinfo_table_record) + IEEE80211_ADDR_LEN))
            {
                ap_mac = cp;
                printf("|AP[%s] ",ethera_sprintf(ap_mac));

                cp += IEEE80211_ADDR_LEN;
                len -= IEEE80211_ADDR_LEN;

                user = (struct userinfo_table_record *)cp;
                if(user != NULL)
                {
                
                    printf("STATION[%s] \tWORK_CAP(%d)\tIS_ASSOC(%d) ASSOC_CNT(%d) AVG_RSSI(%d) UPDATE_TIME(%d) INACTIVE(%d)\n",\
                        ethera_sprintf(user->user_mac),
                        user->user_cap,user->assoc,user->assoc_cnt,user->avg_mgmt_rssi,
                        user->stamp_time,user->inact);
                    
                    cp += sizeof(struct userinfo_table_record);
                    len -= sizeof(struct userinfo_table_record);
                }
                else
                {
                    printf("get mgmt frame info error!\n");
                }
            }
        }
        printf("\n================================================================================================================\n");
    }
    return 0;

}


int get_scan_list(int argc, char** argv)
{
    int ret = 0;
    if (argc < 2) {
        autelan_sync_info_help () ;
        return -1;
    } else {

        struct ieee80211_autelan_sync_info a;
        u_int8_t mac[6]= {0};
        memset(&a, 0x00, sizeof(a));
        a.type = GET_SCAN_LIST;
        a.arg1 = 0;
        struct iwreq iwr;
        (void) memset(&iwr, 0, sizeof(iwr));
        (void) strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
        iwr.u.data.pointer = (void *)&a;
        iwr.u.data.length = sizeof(a);
        ret = autelan_ioctl(&iwr, SIOCSATHSYNCINFO);
    }
    return 0;

}

int sync_switch(int argc, char** argv)
{
    if (argc < 4) {
        autelan_sync_info_help ();
        return -1;
    }

    int ret = 0;
    struct iwreq iwr;
    static u_int8_t buf[1024];
    struct ieee80211_autelan_sync_info md = {0};
    
    memset(buf, 0x00, 1024);
    memset(&iwr, 0, sizeof(iwr));
    
    if((strlen(argv[3]) == strlen("sync_switch")) &&
       (strncmp (argv[3], "sync_switch", strlen("sync_switch")) == 0)) {
        if (argc > 5) {
            autelan_sync_info_help ();
            return -1;
        }
        md.type = SYNC_SWITCH;
        md.arg1 = atoi(argv[4]);
    } else if((strlen(argv[3]) == strlen("get_sync_switch")) &&
              (strncmp (argv[3], "get_sync_switch", strlen("get_sync_switch")) == 0)) {
        if (argc > 4) {
            autelan_sync_info_help ();
            return -1;
        }
        md.type = GET_SYNC_SWITCH;
    } else {
        autelan_sync_info_help ();
        return -1;
    }

    memcpy(buf, &md, sizeof(struct ieee80211_autelan_sync_info));
    strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *)buf;
    iwr.u.data.length = sizeof(buf);
    ret = autelan_ioctl(&iwr, SIOCSATHSYNCINFO);

    if(0 == ret) {
        switch(md.type) {
            case SYNC_SWITCH:
                break;
            case GET_SYNC_SWITCH:
                printf("SYNC SWITCH: %s\r\n", *((int *)buf) ? "enable" : "disable");
                break;
            default:
                break;
        }
    }
    return 0;
}

int sync_debug(int argc, char** argv)
{
    if (argc < 4) {
        autelan_sync_info_help ();
        return -1;
    }

    int ret = 0;
    struct iwreq iwr;
    static u_int8_t buf[1024];
    struct ieee80211_autelan_sync_info md = {0};
    
    memset(buf, 0x00, 1024);
    memset(&iwr, 0, sizeof(iwr));
    
    if((strlen(argv[3]) == strlen("sync_debug")) &&
       (strncmp (argv[3], "sync_debug", strlen("sync_debug")) == 0)) {
        if (argc > 5) {
            autelan_sync_info_help ();
            return -1;
        }
        md.type = SYNC_DEBUG;
        md.arg1 = atoi(argv[4]);
    } else if((strlen(argv[3]) == strlen("get_sync_debug")) &&
              (strncmp (argv[3], "get_sync_debug", strlen("get_sync_debug")) == 0)) {
        if (argc > 4) {
            autelan_sync_info_help ();
            return -1;
        }
        md.type = GET_SYNC_DEBUG;
    } else {
        autelan_sync_info_help ();
        return -1;
    }

    //memcpy(buf, &md, sizeof(struct ieee80211_autelan_mgmt_debug));
    memcpy(buf, &md, sizeof(struct ieee80211_autelan_sync_info));
    strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *)buf;
    iwr.u.data.length = sizeof(buf);
    ret = autelan_ioctl(&iwr, SIOCSATHSYNCINFO);

    if(0 == ret) {
        switch(md.type) {
            case SYNC_DEBUG:
                break;
            case GET_SYNC_DEBUG:
                printf("SYNC DEBUG: %s\r\n", *((int *)buf) ? "enable" : "disable");
                break;
            default:
                break;
        }
    }
    return 0;
}


int sync_time(int argc, char** argv)
{
    if (argc < 4) {
        autelan_sync_info_help ();
        return -1;
    }

    int ret = 0;
    struct iwreq iwr;
    static u_int8_t buf[1024];
    struct ieee80211_autelan_sync_info md = {0};
    
    memset(buf, 0x00, 1024);
    memset(&iwr, 0, sizeof(iwr));
    
    if((strlen(argv[3]) == strlen("sync_time")) &&
       (strncmp (argv[3], "sync_time", strlen("sync_time")) == 0)) {
        if (argc > 5) {
            autelan_sync_info_help ();
            return -1;
        }
        md.type = SYNC_TIME;
        md.arg1 = atoi(argv[4]);
    } else if((strlen(argv[3]) == strlen("get_sync_time")) &&
              (strncmp (argv[3], "get_sync_time", strlen("get_sync_time")) == 0)) {
        if (argc > 4) {
            autelan_sync_info_help ();
            return -1;
        }
        md.type = GET_SYNC_TIME;
    } else {
        autelan_sync_info_help ();
        return -1;
    }

    //memcpy(buf, &md, sizeof(struct ieee80211_autelan_mgmt_debug));
    memcpy(buf, &md, sizeof(struct ieee80211_autelan_sync_info));
    strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *)buf;
    iwr.u.data.length = sizeof(buf);
    ret = autelan_ioctl(&iwr, SIOCSATHSYNCINFO);

    if(0 == ret) {
        switch(md.type) {
            case SYNC_TIME:
                break;
            case GET_SYNC_TIME:
                printf("SYNC TIME: %d\r\n", *((int *)buf));
                break;
            default:
                break;
        }
    }
    return 0;
}


int sync_auto_group(int argc, char** argv)
{
    if (argc < 4) {
        autelan_sync_info_help ();
        return -1;
    }

    int ret = 0;
    struct iwreq iwr;
    static u_int8_t buf[1024];
    struct ieee80211_autelan_sync_info md = {0};
    
    memset(buf, 0x00, 1024);
    memset(&iwr, 0, sizeof(iwr));
    
    if((strlen(argv[3]) == strlen("sync_auto_group")) &&
       (strncmp (argv[3], "sync_auto_group", strlen("sync_auto_group")) == 0)) {
        if (argc > 5) {
            autelan_sync_info_help ();
            return -1;
        }
        md.type = SYNC_AUTO_GROUP;
        md.arg1 = atoi(argv[4]);
    } else if((strlen(argv[3]) == strlen("get_sync_auto_group")) &&
              (strncmp (argv[3], "get_sync_auto_group", strlen("get_sync_auto_group")) == 0)) {
        if (argc > 4) {
            autelan_sync_info_help ();
            return -1;
        }
        md.type = GET_SYNC_AUTO_GROUP;
    } else if((strlen(argv[3]) == strlen("sync_neighbor_rssi_limit")) &&
       (strncmp (argv[3], "sync_neighbor_rssi_limit", strlen("sync_neighbor_rssi_limit")) == 0)) {
        if (argc > 5) {
            autelan_sync_info_help ();
            return -1;
        }
        md.type = SYNC_NEIGHBOR_RSSI_LIMIT;
        md.arg1 = atoi(argv[4]);
    } else if((strlen(argv[3]) == strlen("get_sync_neighbor_rssi_limit")) &&
              (strncmp (argv[3], "get_sync_neighbor_rssi_limit", strlen("get_sync_neighbor_rssi_limit")) == 0)) {
        if (argc > 4) {
            autelan_sync_info_help ();
            return -1;
        }
        md.type = GET_SYNC_NEIGHBOR_RSSI_LIMIT;
    } else {
        autelan_sync_info_help ();
        return -1;
    }

    memcpy(buf, &md, sizeof(struct ieee80211_autelan_sync_info));
    strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *)buf;
    iwr.u.data.length = sizeof(buf);
    ret = autelan_ioctl(&iwr, SIOCSATHSYNCINFO);

    if(0 == ret) {
        switch(md.type) {
            case GET_SYNC_AUTO_GROUP:                
                printf("SYNC AUTO GROUP: %d\r\n", *((int *)buf));
                break;
            case GET_SYNC_NEIGHBOR_RSSI_LIMIT:
                printf("SYNC NEIGHBOR RSSI LIMIT: %d\r\n", *((int *)buf));
                break;
            default:
                break;
        }
    }
    return 0;
}

int autelan_sync_info_cmd(int argc, char** argv)
{

    /*check arc number*/
    if (argc < 4) {
        /*should print autelan mac binding help information*/
        autelan_sync_info_help ();
        return -1;
    }

    if (strncmp (argv[3], "get_local_table", strlen("get_local_table")) == 0) {

        get_local_table(argc, argv);

    } else if (strncmp (argv[3], "get_neighbor_dev", strlen("get_neighbor_dev")) == 0) { 

        get_neighbour_dev(argc, argv);

    }else if (strncmp (argv[3], "get_neighbor_table", strlen("get_neighbor_table")) == 0) { 

        get_neighbour_table(argc, argv);

    } else if (strncmp (argv[3], "get_neighbor_user_by_mac", strlen("get_neighbor_user_by_mac")) == 0) { 

        get_neighbour_user_by_mac(argc, argv);

    } else if (strncmp (argv[3], "get_scan_list", strlen("get_scan_list")) == 0) { 

        get_scan_list(argc, argv);

    } else if (strncmp (argv[3], "sync_switch", strlen("sync_switch")) == 0) { 

        sync_switch(argc, argv);

    } else if (strncmp (argv[3], "get_sync_switch", strlen("get_sync_switch")) == 0) { 

        sync_switch(argc, argv);

    } else if (strncmp (argv[3], "sync_debug", strlen("sync_debug")) == 0) { 

        sync_debug(argc, argv);

    }else if (strncmp (argv[3], "get_sync_debug", strlen("get_sync_debug")) == 0) { 

        sync_debug(argc, argv);

    } else if (strncmp (argv[3], "sync_time", strlen("sync_time")) == 0) { 

        sync_time(argc, argv);

    }else if (strncmp (argv[3], "get_sync_time", strlen("get_sync_time")) == 0) { 

        sync_time(argc, argv);

    }else if (strncmp (argv[3], "sync_auto_group", strlen("sync_auto_group")) == 0) { 

        sync_auto_group(argc, argv);

    }else if (strncmp (argv[3], "get_sync_auto_group", strlen("get_sync_auto_group")) == 0) { 

        sync_auto_group(argc, argv);

    }else if (strncmp (argv[3], "sync_neighbor_rssi_limit", strlen("sync_neighbor_rssi_limit")) == 0) { 

        sync_auto_group(argc, argv);

    }else if (strncmp (argv[3], "get_sync_neighbor_rssi_limit", strlen("get_sync_neighbor_rssi_limit")) == 0) { 

        sync_auto_group(argc, argv);
        
    }else {
        autelan_sync_info_help ();
    }

    return 0;

}

static void autelan_connect_rule_help () 
{
    printf("\nusage:: autelan connect_rule COMMAND [OPTION] ... \n");
    printf("OPTIONS: \n");
    printf("\t\t[WIFI INTERFACE] connect_to_best [VALUE]\n");
    printf("\t\t[WIFI INTERFACE] get_connect_to_best\n");
    printf("\t\t[WIFI INTERFACE] connect_balance [VALUE]\n");
    printf("\t\t[WIFI INTERFACE] get_connect_balance\n");
    printf("\t\t[WIFI INTERFACE] connect_to_best_debug [VALUE]\n");
    printf("\t\t[WIFI INTERFACE] get_connect_to_best_debug\n"); 
    printf("\t\t[WIFI INTERFACE] inactive_time [VALUE]\n");
    printf("\t\t[WIFI INTERFACE] get_inactive_time\n");
    printf("\t\t[WIFI INTERFACE] wating_time [VALUE]\n");
    printf("\t\t[WIFI INTERFACE] get_wating_time\n");
    printf("\t\t[WIFI INTERFACE] max_dv [VALUE]\n");
    printf("\t\t[WIFI INTERFACE] get_max_dv\n");
    printf("\n");
}

int connect_to_best_debug(int argc, char** argv)
{
    if (argc < 4) {
        autelan_connect_rule_help ();
        return -1;
    }

    int ret = 0;
    struct iwreq iwr;
    static u_int8_t buf[1024];
    struct ieee80211_autelan_connect_rule md = {0};
    
    memset(buf, 0x00, 1024);
    memset(&iwr, 0, sizeof(iwr));
    
    if((strlen(argv[3]) == strlen("connect_to_best_debug")) &&
       (strncmp (argv[3], "connect_to_best_debug", strlen("connect_to_best_debug")) == 0)) {
        if (argc > 5) {
            autelan_connect_rule_help ();
            return -1;
        }
        md.type = CONNECT_TO_BEST_DEBUG;
        md.arg1 = atoi(argv[4]);
    } else if((strlen(argv[3]) == strlen("get_connect_to_best_debug")) &&
              (strncmp (argv[3], "get_connect_to_best_debug", strlen("get_connect_to_best_debug")) == 0)) {
        if (argc > 4) {
            autelan_connect_rule_help ();
            return -1;
        }
        md.type = GET_CONNECT_TO_BEST_DEBUG;
    } else {
        autelan_connect_rule_help ();
        return -1;
    }

    memcpy(buf, &md, sizeof(struct ieee80211_autelan_mgmt_debug));
    strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *)buf;
    iwr.u.data.length = sizeof(buf);
    ret = autelan_ioctl(&iwr, SIOCSATHCONNECTRULE);

    if(0 == ret) {
        switch(md.type) {
            case CONNECT_TO_BEST_DEBUG:
                break;
            case GET_CONNECT_TO_BEST_DEBUG:
                printf("CONNECT_TO_BEST DEBUG: %s\r\n", *((int *)buf) ? "enable" : "disable");
                break;
            default:
                break;
        }
    }
    return 0;
}


int connect_to_best(int argc, char** argv)
{
    if (argc < 4) {
        autelan_connect_rule_help ();
        return -1;
    }

    int ret = 0;
    struct iwreq iwr;
    static u_int8_t buf[1024];
    struct ieee80211_autelan_connect_rule md = {0};
    
    memset(buf, 0x00, 1024);
    memset(&iwr, 0, sizeof(iwr));
    
    if((strlen(argv[3]) == strlen("connect_to_best")) &&
       (strncmp (argv[3], "connect_to_best", strlen("connect_to_best")) == 0)) {
        if (argc > 5) {
            autelan_connect_rule_help ();
            return -1;
        }
        md.type = CONNECT_TO_BEST;
        md.arg1 = atoi(argv[4]);
    } else if((strlen(argv[3]) == strlen("get_connect_to_best")) &&
              (strncmp (argv[3], "get_connect_to_best", strlen("get_connect_to_best")) == 0)) {
        if (argc > 4) {
            autelan_connect_rule_help ();
            return -1;
        }
        md.type = GET_CONNECT_TO_BEST;
    } else if((strlen(argv[3]) == strlen("connect_balance")) &&
       (strncmp (argv[3], "connect_balance", strlen("connect_balance")) == 0)) {
        if (argc != 5) {
            autelan_connect_rule_help ();
            return -1;
        }
        md.type = CONNECT_BALANCE;
        md.arg1 = atoi(argv[4]);
    } else if((strlen(argv[3]) == strlen("get_connect_balance")) &&
              (strncmp (argv[3], "get_connect_balance", strlen("get_connect_balance")) == 0)) {
        if (argc != 4) {
            autelan_connect_rule_help ();
            return -1;
        }
        md.type = GET_CONNECT_BALANCE;
    }else if((strlen(argv[3]) == strlen("max_dv")) &&
              (strncmp (argv[3], "max_dv", strlen("max_dv")) == 0)) {
        if (argc > 5) {
            autelan_connect_rule_help ();
            return -1;
        }
        md.type = MAX_DV;
        md.arg1 = atoi(argv[4]);
    }else if((strlen(argv[3]) == strlen("get_max_dv")) &&
              (strncmp (argv[3], "get_max_dv", strlen("get_max_dv")) == 0)) {
        if (argc > 4) {
            autelan_connect_rule_help ();
            return -1;
        }
        md.type = GET_MAX_DV;
    }else if((strlen(argv[3]) == strlen("inactive_time")) &&
              (strncmp (argv[3], "inactive_time", strlen("inactive_time")) == 0)) {
        if (argc > 5) {
            autelan_connect_rule_help ();
            return -1;
        }
        md.type = INACTIVE_TIME;
        md.arg1 = atoi(argv[4]);
    }else if((strlen(argv[3]) == strlen("get_inactive_time")) &&
              (strncmp (argv[3], "get_inactive_time", strlen("get_inactive_time")) == 0)) {
        if (argc > 4) {
            autelan_connect_rule_help ();
            return -1;
        }
        md.type = GET_INACTIVE_TIME;
    }else if((strlen(argv[3]) == strlen("wating_time")) &&
              (strncmp (argv[3], "wating_time", strlen("wating_time")) == 0)) {
        if (argc > 5) {
            autelan_connect_rule_help ();
            return -1;
        }
        md.type = WATING_TIME;
        md.arg1 = atoi(argv[4]);
    }else if((strlen(argv[3]) == strlen("get_wating_time")) &&
              (strncmp (argv[3], "get_wating_time", strlen("get_wating_time")) == 0)) {
        if (argc > 4) {
            autelan_connect_rule_help ();
            return -1;
        }
        md.type = GET_WATING_TIME;
    } else {
        autelan_connect_rule_help ();
        return -1;
    }

    memcpy(buf, &md, sizeof(struct ieee80211_autelan_mgmt_debug));
    strncpy(iwr.ifr_name, argv[2], sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *)buf;
    iwr.u.data.length = sizeof(buf);
    ret = autelan_ioctl(&iwr, SIOCSATHCONNECTRULE);

    if(0 == ret) {
        switch(md.type) {
            case GET_CONNECT_TO_BEST:
                printf("CONNECT_TO_BEST: %s\r\n", *((int *)buf) ? "enable" : "disable");
                break;
            case GET_CONNECT_BALANCE:
                printf("CONNECT_BALANCE: %s\r\n", *((int *)buf) ? "enable" : "disable");
                break;
            case GET_MAX_DV:
                printf("MAX DV: %d\r\n", *((int *)buf));
                break;
            case GET_INACTIVE_TIME:
               printf("INACTIVE TIME: %d\r\n", *((int *)buf));
                break;
            case GET_WATING_TIME:
                printf("WATING TIME: %d\r\n", *((int *)buf));
                break;
            default:
                break;
        }
    }
    return 0;
}

int autelan_connect_rule_cmd(int argc, char** argv)
{

    /*check arc number*/
    if (argc < 4) {
        /*should print autelan mac binding help information*/
        autelan_connect_rule_help ();
        return -1;
    }

    if (strncmp (argv[3], "connect_to_best_debug", strlen("connect_to_best_debug")) == 0) { 

        connect_to_best_debug(argc, argv);

    }else if (strncmp (argv[3], "get_connect_to_best_debug", strlen("get_connect_to_best_debug")) == 0) { 

        connect_to_best_debug(argc, argv);

    }else if (strncmp (argv[3], "connect_to_best", strlen("connect_to_best")) == 0) { 

        connect_to_best(argc, argv);

    }else if (strncmp (argv[3], "get_connect_to_best", strlen("get_connect_to_best")) == 0) { 

        connect_to_best(argc, argv);

    }else if (strncmp (argv[3], "connect_balance", strlen("connect_balance")) == 0) { 

        connect_to_best(argc, argv);

    }else if (strncmp (argv[3], "get_connect_balance", strlen("get_connect_balance")) == 0) { 

        connect_to_best(argc, argv);

    }else if (strncmp (argv[3], "inactive_time", strlen("inactive_time")) == 0) { 

        connect_to_best(argc, argv);

    }else if (strncmp (argv[3], "get_inactive_time", strlen("get_inactive_time")) == 0) { 

        connect_to_best(argc, argv);

    }else if (strncmp (argv[3], "wating_time", strlen("wating_time")) == 0) { 

        connect_to_best(argc, argv);

    }else if (strncmp (argv[3], "get_wating_time", strlen("get_wating_time")) == 0) { 

        connect_to_best(argc, argv);

    }else if (strncmp (argv[3], "max_dv", strlen("max_dv")) == 0) { 

        connect_to_best(argc, argv);

    }else if (strncmp (argv[3], "get_max_dv", strlen("get_max_dv")) == 0) { 

        connect_to_best(argc, argv);

    }
    else {
        autelan_connect_rule_help ();
    }

    return 0;

}


/*
 *the main function for autelan private command
 */
int main (int argc, char** argv)
{
    /*check the arc number*/
    if(argc < 2) {
        autelan_help () ;
        //printf("AUTELAN private command error: incomplete command\n");
        printf("wlanset command error: incomplete command\n");
        return 0;
    }

    if (strncmp (argv[1], "wmm", strlen("wmm")) == 0) {

        //autelan_debug("---begin autelan_wmm\n")    ;
        
        if (autelan_wmm(argc, argv) < 0) {

        //printf("AUTELAN private command wmm: wrong format\n");
        printf("wlanset command  wmm: wrong format\n");    
        }

    } else if (strncmp (argv[1], "traffic_limit", strlen("traffic_limit")) == 0) {

        //autelan_debug("---begin autelan_traffic_limit\n")    ;
        
        if (autelan_traffic_limit(argc, argv) < 0) {

            //printf("AUTELAN private command traffic_limit: wrong format\n");
            printf("wlanset command  traffic_limit: wrong format\n");
        }
    } else if (strncmp (argv[1], "quick_roaming", strlen("quick_roaming")) == 0) { 

        if (autelan_quick_roaming(argc, argv) < 0) {

            //printf("AUTELAN private command quick_roaming: wrong format\n");        
            printf("wlanset command  quick_roaming: wrong format\n");        
        }
    /*ljy--add begin to develop the policy of mac binding*/
    } else if (strncmp (argv[1], "mac_binding", strlen("mac_binding")) == 0) {

        if (autelan_mac_binding(argc, argv) < 0) {

        //printf("AUTELAN private command mac_binding: wrong format\n");        
        printf("wlanset command  mac_binding: wrong format\n");        
        }
    /*ljy--add end*/
        /*Begin:added by duanmingzhe for 80211 cache*/
    }else if (strncmp (argv[1], "80211_cache", strlen("80211_cache")) == 0) {

        if (autelan_80211_cache(argc, argv) < 0) {

        //    printf("AUTELAN private command 80211_cache: wrong format\n");    
        printf("wlanset command  80211_cache: wrong format\n");    
        }
        /*End:added by duanmingzhe for 80211 cache*/
        /*zhaoyang add for data forward base users*/
    } else if (strncmp (argv[1], "tunnel_ctl", strlen("tunnel_ctl")) == 0){
        if(autelan_tunnel_ctl(argc,argv) < 0) {
            printf("AUTELAN private command autelan_tunnel_ctl: wrong format\n");
        }
    /*zhaoyang add end*/
/*AUTELAN-Begin:zhaoenjuan transplant (WangJia) for arp filter */
    }else if((strlen(argv[1]) == strlen("arp_filter")) &&
             (strncmp (argv[1], "arp_filter", strlen("arp_filter")) == 0)) {
        if (autelan_arp_filter(argc, argv) < 0 ) {
            printf("AUTELAN private command arp filter: wrong format\n");    
        }
/*AUTELAN-End:zhaoenjuan transplant (WangJia) for arp filter */
     /* Begin: Added by dongzw for mgmt debug */
    }else if((strlen(argv[1]) == strlen("mgmt_debug")) &&
             (strncmp (argv[1], "mgmt_debug", strlen("mgmt_debug")) == 0)) {
        if (autelan_mgmt_debug(argc, argv) < 0 ) {
            printf("AUTELAN private command mgmt debug: wrong format\n");    
        }
    /* End: Added by dongzw for mgmt debug */
    } 
/* AUTELAN-Begin:zhaoenjuan transplant (lisongbai) for get channel utility 2013-12-27 */
    else if((strlen(argv[1]) == strlen("channel_utility")) && 
        (strncmp(argv[1], "channel_utility", strlen("channel_utility")) == 0))
    {
        if(autelan_channel_utility(argc, argv) < 0) {
            printf("AUTELAN private command channel_utility: wrong format\n");
        }
    }
/* AUTELAN-End:zhaoenjuan transplant (lisongbai) for get channel utility 2013-12-27 */
/*AUTELAN-Begin:zhaoenjuan add for packet_trace*/
     else if (strncmp (argv[1], "packet_trace", strlen("packet_trace")) == 0) {
    

        if (autelan_packet_trace_cmd(argc, argv) < 0) {

            printf("AUTELAN private command packet_trace: wrong format\n");        
        }
   
/*AUTELAN-End:zhaoenjuan add for packet_trace*/
    }
    else if(strncmp (argv[1], "sync_info", strlen("sync_info")) == 0){
        if (autelan_sync_info_cmd(argc, argv) < 0) {
            printf("AUTELAN private command sync_info: wrong format\n");        
        }
    }
    else if(strncmp (argv[1], "connect_rule", strlen("connect_rule")) == 0){
        if (autelan_connect_rule_cmd(argc, argv) < 0) {
            printf("AUTELAN private command connect_rule: wrong format\n");
        }
    }
    else {
        //printf("AUTELAN private command error: unknow command name\n");
        printf("wlanset command  error: unknow command name\n");
        autelan_help();
    }
    return 0;
    
}
