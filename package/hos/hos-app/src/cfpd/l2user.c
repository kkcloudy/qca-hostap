#include "utils.h"
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <math.h>
#include "um_ieee80211.h"
#include "tid.h"
#include "um.h"

#define SIOCDEVPRIVATE	0x89F0
#define	IEEE80211_RATE_VAL			0x7f
#define	IEEE80211_IOCTL_STA_STATS	(SIOCDEVPRIVATE+5)
#define	IEEE80211_IOCTL_STA_INFO	(SIOCDEVPRIVATE+6)
#define LIST_STATION_ALLOC_SIZE 24*1024
#define MAC80211

static uint8_t *g_sta_buf = NULL;

int
um_create_stabuf(void)
{
    g_sta_buf = malloc(LIST_STATION_ALLOC_SIZE);
    if (NULL == g_sta_buf) {
        return -EINVAL1;
    }

    return EINVAL0;
}

static void 
l2user_update(bool created, struct apuser *dst, struct apuser *src)
{
    time_t now = time(NULL);
    
    /*
    * dst is new created
    */
    if (created) {
        dst->wifi.uptime = now;
    } else {
        /*
        * call update callback, before change dst
        */
        um_ubus_update_cb(dst, src);
    }
#if 0
    if (dst->wifi.uptime) {
        dst->wifi.livetime = now - dst->wifi.uptime;
    }
#endif
   
    os_maccpy(dst->ap, src->ap);
    os_strdcpy(dst->ifname, src->ifname);
    os_maccpy(dst->vap, src->vap);
    
    dst->local = src->local;
    dst->radioid = src->radioid;
    dst->wlanid = src->wlanid;
    dst->ip = src->ip;
    dst->wifi.uptime = src->wifi.uptime;
    dst->wifi.livetime = src->wifi.livetime;

    os_objdcpy(&dst->wifi.rx, &src->wifi.rx);
    os_objdcpy(&dst->wifi.tx, &src->wifi.tx);
    
    dst->wifi.signal = src->wifi.signal;

    dst->portal.type = src->portal.type;
    dst->portal.state = src->portal.state;
    dst->portal.enable = src->portal.enable;
    dst->rx_retr = src->rx_retr;
    dst->tx_retr = src->tx_retr;

    debug_l2timer_trace("[um]:l2user %s %s", um_macstring(src->mac), created?"create":"update");    

    return;
}


char*  get_ap_macaddr(void)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    static char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));	
#ifdef MAC80211
    strcpy( str_tmp_cmd,  "/sbin/ifconfig br-wan| /bin/grep 'HWaddr'|/usr/bin/awk '{print $5}'");
#else
    strcpy(str_tmp_cmd,"echo 0000");
#endif	

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return szVal;
}


char* get_vap_macaddr(char * ifname)
{
	FILE *fp = NULL;
	char str_tmp_cmd[SPRINT_MAX_LEN];
	static char szVal[SPRINT_MAX_LEN];
	memset(str_tmp_cmd, 0, SPRINT_MAX_LEN );
	memset(szVal, 0x00, sizeof(szVal));	
#ifdef MAC80211
    sprintf(str_tmp_cmd,  "/sbin/ifconfig %s| /bin/grep 'HWaddr'|/usr/bin/awk '{print $5}'",ifname);
#else
    strcpy(str_tmp_cmd,"echo 0000");
#endif

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return (szVal);		
}

char*  get_sta_macaddr(char * ifname,int stanum)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    static char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));	
#ifdef MAC80211
    sprintf( str_tmp_cmd, " /usr/sbin/iw dev %s station dump|/bin/grep 'Station'|/usr/bin/awk '{print $2}'| /bin/sed -n '%dp'",ifname,stanum);
#else
    strcpy(str_tmp_cmd,"echo 0000");
#endif

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return (szVal);
}


char* get_sta_ipaddr(char * stamacaddr)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    static char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));	
#ifdef MAC80211	
    sprintf( str_tmp_cmd, "/bin/cat /var/dhcp.leases |/bin/grep  '%s'|/usr/bin/awk '{print $3}'",stamacaddr);
#else
    ;;
#endif

    fp=popen(str_tmp_cmd,"r");
    if(fp)
	{
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }
    
    return (szVal);		
}

uint32_t  get_sta_uptime(char* phy ,char* ifname,char * stamacaddr)
{
    FILE *fp;
    uint32_t year,month,day,hour,minute,second;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    static char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));	
#ifdef MAC80211
    sprintf( str_tmp_cmd, "/bin/cat /sys/kernel/debug/ieee80211/%s/netdev:%s/stations/%s/connected_time |/usr/bin/awk  '{print  $3 }'|/bin/sed -n '1p'",phy,ifname,stamacaddr);
    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }
    year = (atoi(szVal))*365*24*3600;

    sprintf(str_tmp_cmd, "/bin/cat /sys/kernel/debug/ieee80211/%s/netdev:%s/stations/%s/connected_time |/usr/bin/awk  '{print  $3 }'|/bin/sed -n '2p'",phy,ifname,stamacaddr);
    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }
    month = (atoi(szVal))*30*24*3600; 

    sprintf(str_tmp_cmd, "/bin/cat /sys/kernel/debug/ieee80211/%s/netdev:%s/stations/%s/connected_time |/usr/bin/awk  '{print  $3 }'|/bin/sed -n '3p'",phy,ifname,stamacaddr);	
    fp = popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }
    day = (atoi(szVal))*24*3600; 

    sprintf( str_tmp_cmd, "/bin/cat /sys/kernel/debug/ieee80211/%s/netdev:%s/stations/%s/connected_time |/usr/bin/awk  '{print  $3 }'|/bin/sed -n '4p'|/usr/bin/cut -d: -f1",phy,ifname,stamacaddr);
    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }
    hour=(atoi(szVal))*3600; 

    sprintf( str_tmp_cmd, "/bin/cat /sys/kernel/debug/ieee80211/%s/netdev:%s/stations/%s/connected_time |/usr/bin/awk  '{print  $3 }'|/bin/sed -n '4p'|/usr/bin/cut -d: -f2",phy,ifname,stamacaddr);
    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }
    minute=(atoi(szVal))*60; 

    sprintf( str_tmp_cmd, "/bin/cat /sys/kernel/debug/ieee80211/%s/netdev:%s/stations/%s/connected_time |/usr/bin/awk  '{print  $3 }'|/bin/sed -n '4p'|/usr/bin/cut -d: -f3",phy,ifname,stamacaddr);
    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }
    second=(atoi(szVal))+ minute + hour + day + month + year; 
#else
    ;;
#endif
    return second;
}

int get_sta_livetime(char * ifname,int stanum)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));
#ifdef MAC80211
    sprintf( str_tmp_cmd,  "/usr/sbin/iw dev %s station dump|/bin/grep 'inactive time'|/usr/bin/awk '{print $3}'| /bin/sed -n '%dp'",ifname,stanum);
#else
    ;;
#endif

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return atoi(szVal);
}

long long  get_rx_bytes(char * ifname, int stanum)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));	

#ifdef MAC80211
    sprintf( str_tmp_cmd,  "/usr/sbin/iw dev %s station dump|/bin/grep 'rx bytes'|/usr/bin/cut -d: -f2| /bin/sed -n '%dp'",ifname,stanum);
#else
    ;;
#endif

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return atoll(szVal);
}

int get_rx_packets(char * ifname,int stanum)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));
#ifdef MAC80211
    sprintf( str_tmp_cmd,  "/usr/sbin/iw dev %s station dump|/bin/grep 'rx packets'|/usr/bin/cut -d: -f2| /bin/sed -n '%dp'",ifname,stanum);
#else
    ;;
#endif

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return atoi(szVal);
}


int get_rx_bitrate(char * ifname, int stanum)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));
#ifdef MAC80211
    sprintf( str_tmp_cmd,  "/usr/sbin/iw dev %s station dump|/bin/grep 'rx bitrate'|/usr/bin/awk '{print $3}'|/bin/sed -n '%dp'",ifname,stanum);
#else
    ;;
#endif

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return (atof(szVal)*1000);
}

long long get_tx_bytes(char * ifname, int stanum)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));	
#ifdef MAC80211
    sprintf( str_tmp_cmd,  "/usr/sbin/iw dev %s station dump|/bin/grep 'tx bytes'|/usr/bin/cut -d: -f2| /bin/sed -n '%dp'",ifname,stanum);
#else
    ;;
#endif

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';	
        pclose(fp);
    }

    return atoll(szVal);
}

int get_tx_packets(char * ifname, int stanum)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));
#ifdef MAC80211
    sprintf( str_tmp_cmd,  "/usr/sbin/iw dev %s station dump|/bin/grep 'tx packets'|/usr/bin/cut -d: -f2| /bin/sed -n '%dp'",ifname,stanum);
#else
    ;;
#endif
	
    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return atoi(szVal);
}

int get_tx_bitrate(char * ifname, int stanum)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));
#ifdef MAC80211
    sprintf( str_tmp_cmd,  "/usr/sbin/iw dev %s station dump|/bin/grep 'tx bitrate'|/usr/bin/awk '{print $3}'|/bin/sed -n '%dp'",ifname,stanum);	
#else
    ;;
#endif	

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return (atof(szVal)*1000) ;	
}


int get_sta_signal(char * ifname, int stanum)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));
#ifdef MAC80211
    sprintf( str_tmp_cmd,  "/usr/sbin/iw dev %s station dump|/bin/grep 'signal:'|/usr/bin/awk '{print $2}'|/usr/bin/cut -d- -f2|/bin/sed -n '%dp'",ifname,stanum);	
#else
    ;;
#endif	
    fp=popen(str_tmp_cmd,"r");
    if(fp)
	{
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return atoi(szVal);
}


int get_sta_signalavg(char * ifname, int stanum)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));
#ifdef MAC80211
    sprintf( str_tmp_cmd,  "/usr/sbin/iw dev %s station dump|/bin/grep 'signal avg:'|/usr/bin/awk '{print $3}'|/usr/bin/cut -d- -f2|/bin/sed -n '%dp'",ifname,stanum);	
#else
    ;;
#endif	

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return atoi(szVal);
}

int get_sta_portalstate()
{
    return  UM_WIFIDOG_STATE_KNOW;
}

int get_sta_total(char * ifname)
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));
#ifdef MAC80211
    sprintf(str_tmp_cmd,  "/usr/sbin/iw dev %s station dump|/bin/grep 'Station'|/usr/bin/wc -l",ifname);
#else
    ;;
#endif	

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }
    
    return atoi(szVal);
}

int get_wlan_total()
{
    FILE *fp;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char szVal[SPRINT_MAX_LEN];
    memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    memset(szVal, 0x00, sizeof(szVal));
#ifdef MAC80211
    strcpy( str_tmp_cmd,  "/usr/bin/iwinfo | /bin/grep 'wlan' |/usr/bin/wc -l");
#else
    ;;
#endif	

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        szVal[strlen(szVal)-1] = '\0';
        pclose(fp);
    }

    return atoi(szVal);
}

static int get_sta_portalenable(unsigned char *stamac)
{
    FILE *fp = NULL;
    int ret = 0;
    char strstamac[20] = {0};
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char szVal[SPRINT_MAX_LEN];

    memset(str_tmp_cmd, 0, sizeof(str_tmp_cmd));
    memset(szVal, 0, sizeof(szVal));
    sprintf(strstamac, "%02x:%02x:%02x:%02x:%02x:%02x", stamac[0], stamac[1], stamac[2], 
                                                        stamac[3], stamac[4], stamac[5]);
    sprintf(str_tmp_cmd,  "/usr/sbin/get_portal_user_uplink_statistics | grep %s -i", strstamac);
    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        fgets(szVal,sizeof(szVal),fp);
        pclose(fp);
    }
    if (0 != strlen(szVal))
    {
        ret = 1;
    }
    
    return ret;
}

#if 1
static double l2user_pow10(int n)
{
    double ret = 1;
    
    if (n > 0)
    {
        while (n > 0)
        {
            ret *= 10;
            n--;
        }
    }
    else if (n < 0)
    {
        while (n <= 0)
        {
            ret /= 10;
            n++;
        }
    }
    else
    {
        ret = 1;
    }

    return ret;
}

static unsigned int l2user_wifirate(char *ifname)
{
    double maxrate = 0;
   	char str_tmp_cmd[SPRINT_MAX_LEN];
   	char szVal[SPRINT_MAX_LEN];
    FILE *fp;
    int i = 0;
    int n = 0;

   	memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    sprintf(str_tmp_cmd,  "iwconfig %s | grep 'Rate' | awk '{print $2}' | cut -b 6-100", ifname);
   	fp=popen(str_tmp_cmd,"r");
	if(fp)
	{
		fgets(szVal,sizeof(szVal),fp);
		szVal[strlen(szVal)-1] = '\0';
		pclose(fp);
	}
    while ('\0' != szVal[i])
    {
        if (('0' <= szVal[i]) && (szVal[i] <= '9'))
        {
            maxrate *= 10;
            maxrate += (szVal[i] - '0');
        }
        if ('.' == szVal[i])
        {
            n = 0;
        }
        i++;
        n++;
    }
    maxrate = maxrate * l2user_pow10(4 - n);
   	memset( str_tmp_cmd, 0, SPRINT_MAX_LEN );
    sprintf(str_tmp_cmd,  "iwconfig %s | grep 'Rate' | awk '{print $3}'", ifname);
   	fp=popen(str_tmp_cmd,"r");
	if(fp)
	{
		fgets(szVal,sizeof(szVal),fp);
		szVal[strlen(szVal)-1] = '\0';
		pclose(fp);
	}
    if (0 == strncasecmp(szVal, "Gb/s", 4))
    {
        maxrate = maxrate * 1000;
    }

    return (unsigned int)maxrate;
}

static void l2user_getbytes(struct apuser *info)
{
	int s = -1;
    struct iwreq iwr;
	struct ieee80211req_sta_stats stats;

  	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0){
		debug_l2timer_waring("[um]: create socket failed for station stats");

        return;
	}

    memset(&stats, 0, sizeof(stats));
	(void) memset(&iwr, 0, sizeof(iwr));
	(void) strncpy(iwr.ifr_name, info->ifname, sizeof(iwr.ifr_name));
    iwr.ifr_name[sizeof(iwr.ifr_name) - 1] = '\0';
	iwr.u.data.pointer = (void *) &stats;
	iwr.u.data.length = sizeof(stats);
	memcpy(stats.is_u.macaddr, info->mac, sizeof(stats.is_u.macaddr));

	if (ioctl(s, IEEE80211_IOCTL_STA_STATS, &iwr) < 0)
    {   
		debug_l2timer_waring("[um]: unable to get station stats");
        close(s);
        
        return;
    }

    info->wifi.rx.bytes = stats.is_stats.ns_rx_bytes;
    info->wifi.tx.bytes = stats.is_stats.ns_tx_bytes;
    info->wifi.rx.packets = stats.is_stats.ns_rx_data /*+ stats.is_stats.ns_rx_mgmt*/;
    info->wifi.tx.packets = stats.is_stats.ns_tx_data /*+ stats.is_stats.ns_tx_mgmt*/;
    info->rx_retr = 100 * stats.is_stats.ns_rx_retry_packets / (stats.is_stats.ns_rx_retry_packets + stats.is_stats.ns_rx_data + 1);
    info->tx_retr = 100 * stats.is_stats.ns_tx_retry_packets / (stats.is_stats.ns_tx_retry_packets + stats.is_stats.ns_tx_data + 1);
    
    close(s);
    return;
}

static int l2user_timer(struct um_intf *intf)
{
    struct apuser info, *user;
	uint8_t *buf = NULL;
	struct iwreq iwr;
	uint8_t *cp;
	int s, len;
   	int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;

    um_user_init(&info, true);
	buf = g_sta_buf;
	if(!buf) {
	  debug_l2timer_waring("[um]: unable to allocate memory for station list");
	  return 0;
	} 

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0){
		debug_l2timer_waring("[um]: create socket failed for station info");;

        return 0;
	}

	(void) memset(&iwr, 0, sizeof(iwr));
	(void) strncpy(iwr.ifr_name, intf->ifname, sizeof(iwr.ifr_name));
	iwr.u.data.pointer = (void *) buf;
	iwr.u.data.length = LIST_STATION_ALLOC_SIZE;
	if (ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr) < 0){
		debug_l2timer_waring("[um]: unable to get station information");
        close(s);
        
        return 0;
	}
	len = iwr.u.data.length;
	if (len < sizeof(struct ieee80211req_sta_info)){
        debug_l2timer_trace("[um]: =============no  no   no   no  sta  sta  sta ===================");
        close(s);
		return 0;
    }
	cp = buf;
	do {
		struct ieee80211req_sta_info *si;
		sscanf(get_ap_macaddr(), "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
	    info.ap[0] = a0;
	    info.ap[1] = a1;
	    info.ap[2] = a2;
		info.ap[3] = a3;
		info.ap[4] = a4;
		info.ap[5] = a5;

        sscanf(get_vap_macaddr(intf->ifname), "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
			   info.vap[0] = a0;
			   info.vap[1] = a1;
			   info.vap[2] = a2;
			   info.vap[3] = a3;
			   info.vap[4] = a4;
			   info.vap[5] = a5;

		si = (struct ieee80211req_sta_info *) cp;
		info.wifi.uptime = si->isi_tr069_assoc_time.tv_sec;
        info.wifi.livetime = si->isi_inact;
        memcpy(info.mac, si->isi_macaddr, sizeof(info.mac));
        strcpy(info.ifname, intf->ifname);
        if(si->isi_txratekbps == 0)
            info.wifi.tx.rate = (si->isi_rates[si->isi_txrate] & IEEE80211_RATE_VAL)/2 * 1000;
        else
            info.wifi.tx.rate = si->isi_txratekbps;
        info.wifi.rx.rate = si->isi_rxratekbps;
        info.wifi.tx.wifirate = l2user_wifirate(info.ifname);
        info.wifi.rx.wifirate = l2user_wifirate(info.ifname);
        l2user_getbytes(&info);	 
		info.wifi.signal = si->isi_rssi;
        info.wlanid = intf->wlanid;
		info.radioid = intf->radioid;
		info.portal.type = UM_PORTAL_TYPE_WIFIDOG;
	    info.portal.state = get_sta_portalstate();
        info.portal.enable = get_sta_portalenable(info.mac);

		cp += si->isi_len, len -= si->isi_len;
        user = um_user_update(&info, l2user_update);

        if (NULL==user)
        {
            close(s);
            return -ENOMEM;
        }
	} while (len >= sizeof(struct ieee80211req_sta_info));
	
    close(s);

    return 0;
}
#else
/*static int 
l2user_timer(struct um_intf *intf)*/
static int 
l2user_timer(struct um_intf *intf)
{
    struct apuser info, *user;
   //struct apuser info;

	int statotal = 0;
	int stanum = 0;
	int a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
    char stamacaddr[18]={0}; 
    char phy[8] = {0};

    
    um_user_init(&info, true);
    
    /*
    * TODO: get l2user from iw/wlanconfig
    *   mac80211: iw <dev> <wlan> station dump
    *   madwifi:  wlanconfig <wlan> list
    */
    statotal = get_sta_total(intf->ifname);

    
	if(0 == statotal)
	{
	    debug_l2timer_trace("[um]:=============no  no   no   no  sta  sta  sta ===================");
        return 0; 
	}
	else
    {

	    for(stanum =1; stanum <= statotal; stanum++)
	    {
		    sscanf(get_sta_macaddr(intf->ifname, stanum), "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
			info.mac[0] = a0;
			info.mac[1] = a1;
			info.mac[2] = a2;
			info.mac[3] = a3;
			info.mac[4] = a4;
			info.mac[5] = a5;	
		    sscanf(get_ap_macaddr(), "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
			info.ap[0] = a0;
			info.ap[1] = a1;
			info.ap[2] = a2;
			info.ap[3] = a3;
			info.ap[4] = a4;
			info.ap[5] = a5;
		    sscanf(get_vap_macaddr(intf->ifname), "%x:%x:%x:%x:%x:%x",&a0,&a1 ,&a2 ,&a3 ,&a4 ,&a5);
			info.vap[0] = a0;
			info.vap[1] = a1;
			info.vap[2] = a2;
			info.vap[3] = a3;
			info.vap[4] = a4;
			info.vap[5] = a5;
		    sprintf(stamacaddr,"%02x:%02x:%02x:%02x:%02x:%02x",info.mac[0],info.mac[1],info.mac[2],info.mac[3]
			        ,info.mac[4],info.mac[5]);
		
		    info.ip = inet_addr(get_sta_ipaddr(stamacaddr));			
		    strcpy(info.ifname, intf->ifname);
		    info.wifi.rx.bytes = get_rx_bytes(intf->ifname,stanum);	
		    info.wifi.rx.packets = get_rx_packets(intf->ifname,stanum);
		    info.wifi.rx.rate= get_rx_bitrate(intf->ifname,stanum);
		    info.wifi.tx.bytes = get_tx_bytes(intf->ifname,stanum);	
		    info.wifi.tx.packets = get_tx_packets(intf->ifname,stanum);
		    info.wifi.tx.rate = get_tx_bitrate(intf->ifname,stanum);
		    info.wifi.signal = get_sta_signal(intf->ifname,stanum);
		    info.wlanid = intf->wlanid;
		    info.radioid = intf->radioid;
            sprintf(phy, "phy%d", intf->radioid);
		    info.wifi.uptime = get_sta_uptime(phy, intf->ifname, stamacaddr);
		    info.wifi.livetime = get_sta_livetime(intf->ifname, stanum);
		    info.portal.type = UM_PORTAL_TYPE_WIFIDOG;
		    info.portal.state = get_sta_portalstate();
#if 0
#if 1 /* test data */
    static int imac = 0;
    
   // os_strdcpy(info.ifname, intf->ifname);

    while(0==(info.mac[5] = (++imac) & os_mask(3))) {
        ;
    }
#endif
#endif   
            user = um_user_update(&info, l2user_update);
            if (NULL==user) {
                return -ENOMEM;
            }
		
	    }
    }

    return 0;
}
#endif

int
um_l2user_timer(void)
{

    struct um_intf *intf;
    int err = 0;
   
   //foreach intf in wlan cfg
    
    list_for_each_entry(intf, &umc.uci.wlan.cfg, node) {
        err = l2user_timer(intf);
        
        if (err<0) {
            return err;
        }
    }

    return 0;
}

/******************************************************************************/
