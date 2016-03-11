/* ****************************************************************************************************
 * Filename: autelan.c
 *	Description: autelan private command for ap.
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


#define	IEEE80211_IOCTL_HAN_PRIV	(SIOCDEVPRIVATE+17)
#define ATH_IOCTL_HAN_PRIV			(SIOCDEVPRIVATE+18)

#define IEEE80211_ADDR_LEN 6
#define WLANSET_STRING_EQ(s1, s2)	(0 == strncmp((s1), (s2), strlen(s2)))
#define WLANSET_STRING_CP(s1, s2)	(strncpy((s1), (s2), strlen(s2)))


/*Begin:pengdecai for han private wmm*/
#pragma pack(push, 1)

enum han_ioctl_priv {
	HAN_IOCTL_PRIV_BANDSTEERING = 0,
	HAN_IOCTL_PRIV_WIRELESSQOS = 1,
};

#define HAN_IOCTL_WMM_ENABLE 0
#define HAN_IOCTL_WMM_DSCP_ENABLE 1
#define HAN_IOCTL_WMM_8021P_ENABLE 2
#define HAN_IOCTL_WMM_DSCP_TO_BK 3
#define HAN_IOCTL_WMM_DSCP_TO_BE 4
#define HAN_IOCTL_WMM_DSCP_TO_VI 5
#define HAN_IOCTL_WMM_DSCP_TO_VO 6
#define HAN_IOCTL_WMM_BK_TO_DSCP 7
#define HAN_IOCTL_WMM_BE_TO_DSCP 8
#define HAN_IOCTL_WMM_VI_TO_DSCP 9
#define HAN_IOCTL_WMM_VO_TO_DSCP 10
#define HAN_IOCTL_WMM_8021P_TO_BK 11
#define HAN_IOCTL_WMM_8021P_TO_BE 12
#define HAN_IOCTL_WMM_8021P_TO_VI 13
#define HAN_IOCTL_WMM_8021P_TO_VO 14
#define HAN_IOCTL_WMM_BK_TO_8021P 15
#define HAN_IOCTL_WMM_BE_TO_8021P 16
#define HAN_IOCTL_WMM_VI_TO_8021P 17
#define HAN_IOCTL_WMM_VO_TO_8021P 18
#define HAN_IOCTL_WMM_STATISTICS  19
#define HAN_IOCTL_WMM_DEBUG  20


#define OP_SET 	0x01
#define OP_GET	0x02
#define AC_MAX_ARGS  8

struct wireless_qos{
		unsigned int subtype;
		unsigned int op;
		unsigned int arg_num;
		union  wmm_args {
			/*Switch*/
			u_int8_t wmm_enable;
			u_int8_t dscp_enable;
			u_int8_t vlan_enable;
			u_int8_t debug;
			/*WMM priority to DSCP prioriy*/
			u_int8_t bk_to_dscp;
			u_int8_t be_to_dscp;
			u_int8_t vi_to_dscp;
			u_int8_t vo_to_dscp;
			/*DSCP prioriy to WMM priority*/
			u_int8_t dscp_to_bk[AC_MAX_ARGS];
			u_int8_t dscp_to_be[AC_MAX_ARGS];
			u_int8_t dscp_to_vi[AC_MAX_ARGS];
			u_int8_t dscp_to_vo[AC_MAX_ARGS];
			
			/*WMM priority to 8021p prioriy*/
			u_int8_t bk_to_vlan;
			u_int8_t be_to_vlan;
			u_int8_t vi_to_vlan;
			u_int8_t vo_to_vlan;
			
			/*8021p prioriy to WMM priority*/
			u_int8_t vlan_to_bk[AC_MAX_ARGS];
			u_int8_t vlan_to_be[AC_MAX_ARGS];
			u_int8_t vlan_to_vi[AC_MAX_ARGS];
			u_int8_t vlan_to_vo[AC_MAX_ARGS];
		} wmm_args;
		struct wmm_stat {
			u_int8_t wmm_enable;
			u_int8_t dscp_enable;
			u_int8_t vlan_enable;
			u_int64_t dscp_to_wmm_packets_ok;
			u_int64_t dscp_to_wmm_packets_error;
			u_int64_t wmm_to_dscp_packets_ok;
			u_int64_t wmm_to_dscp_packets_error;
			u_int64_t vlan_to_wmm_packets_ok;
			u_int64_t vlan_to_wmm_packets_error;
			u_int64_t wmm_to_vlan_packets_ok;
			u_int64_t wmm_to_vlan_packets_error;
		} wmm_stat;
};
/*End:pengdecai for han private wmm*/
struct han_ioctl_priv_args {
	enum han_ioctl_priv type;
	union {
		struct {
#define HAN_IOCTL_BANDSTEERING_ENABLE 0
#define HAN_IOCTL_BANDSTEERING_RSS_THRESHOLD 1
#define HAN_IOCTL_BANDSTEERING_ACCESS_LOAD 2
#define HAN_IOCTL_BANDSTEERING_DENY_COUNT 3
#define HAN_IOCTL_BANDSTEERING_DEBUG 4
#define HAN_IOCTL_BANDSTEERING_STATISTICS 5
#define OP_SET 	0x01
#define OP_GET	0x02

			unsigned int subtype;
			unsigned int op;
			int value;
			struct  {
				//non 5G capable
				u_int32_t	non_5g_capable;
				//5G capable
				u_int32_t	persist_to_2g;
				u_int32_t	excessive_load_5g_capable_to_5g;
				u_int32_t	excessive_load_5g_capable_to_2g;
				u_int32_t	steer_to_5g;
				u_int32_t	weak_2g_signal;
				//totally
				u_int32_t	total_2g;
				u_int32_t	total_5g;
			} bs_stat;
		} bandsteering;
		
		struct wireless_qos wmm; //pengdecai for han private wmm

		/*New cmd struct*/
	} u;
};

#pragma pack(pop)  //pengdecai for han private wmm


static int han_ioctl(struct iwreq *iwr, int cmd) 
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

void
han_bandsteering_help(void)
{
	printf("\nusage:: wlanset bandsteering COMMAND [OPTION] ... \n");
	printf("OPTIONS: \n");
	printf("\tset_enable\t\t[0|1]\n");
	printf("\tget_enable\n");

	printf("\tset_2g_rss_threshold\tvalue\n");
	printf("\tget_2g_rss_threshold\n");

	printf("\tset_5g_access_load\t\tvalue\n");
	printf("\tget_5g_access_load\n");

	printf("\tset_deny_count\t\tvalue\n");
	printf("\tget_deny_count\n");

	printf("\tset_debug\t\t[0|1]\n");
	printf("\tget_debug\n");

	printf("\tget_statistics\n");
}


static int
han_bandsteering(int argc, char** argv)
{
#define CALC(a, t)	((t) ? ((a) * 100 / (t)) : 0)

	struct iwreq iwr;
	unsigned char buf[1024] = {0};
	struct han_ioctl_priv_args a = {0};
	
	if (argc < 3) {
		han_bandsteering_help();
		return -1;
	} else {
		a.type = HAN_IOCTL_PRIV_BANDSTEERING;
		if (WLANSET_STRING_EQ(argv[2], "set_enable")) {
			a.u.bandsteering.subtype = HAN_IOCTL_BANDSTEERING_ENABLE;
			a.u.bandsteering.op = OP_SET;
			
		} else if (WLANSET_STRING_EQ(argv[2], "get_enable")) {
			a.u.bandsteering.subtype = HAN_IOCTL_BANDSTEERING_ENABLE;
			a.u.bandsteering.op = OP_GET;
			
		} else if (WLANSET_STRING_EQ(argv[2], "set_2g_rss_threshold")) {

			a.u.bandsteering.subtype = HAN_IOCTL_BANDSTEERING_RSS_THRESHOLD;
			a.u.bandsteering.op = OP_SET;
			
		} else if (WLANSET_STRING_EQ(argv[2], "get_2g_rss_threshold")) {
			a.u.bandsteering.subtype = HAN_IOCTL_BANDSTEERING_RSS_THRESHOLD;
			a.u.bandsteering.op = OP_GET;
			
		} else if (WLANSET_STRING_EQ(argv[2], "set_5g_access_load")) {
			a.u.bandsteering.subtype = HAN_IOCTL_BANDSTEERING_ACCESS_LOAD;
			a.u.bandsteering.op = OP_SET;

		} else if (WLANSET_STRING_EQ(argv[2], "get_5g_access_load")) {
			a.u.bandsteering.subtype = HAN_IOCTL_BANDSTEERING_ACCESS_LOAD;
			a.u.bandsteering.op = OP_GET;

		} else if (WLANSET_STRING_EQ(argv[2], "set_deny_count")) {
			a.u.bandsteering.subtype = HAN_IOCTL_BANDSTEERING_DENY_COUNT;
			a.u.bandsteering.op = OP_SET;
			
		} else if (WLANSET_STRING_EQ(argv[2], "get_deny_count")) {
			a.u.bandsteering.subtype = HAN_IOCTL_BANDSTEERING_DENY_COUNT;
			a.u.bandsteering.op = OP_GET;
			
		} else if (WLANSET_STRING_EQ(argv[2], "set_debug")) {
			a.u.bandsteering.subtype = HAN_IOCTL_BANDSTEERING_DEBUG;
			a.u.bandsteering.op = OP_SET;
			
		} else if (WLANSET_STRING_EQ(argv[2], "get_debug")) {
			a.u.bandsteering.subtype = HAN_IOCTL_BANDSTEERING_DEBUG;
			a.u.bandsteering.op = OP_GET;

		} else if (WLANSET_STRING_EQ(argv[2], "get_statistics")) {
			a.u.bandsteering.subtype = HAN_IOCTL_BANDSTEERING_STATISTICS;
		} else 
			return -1;

		if (OP_SET == a.u.bandsteering.op)
			a.u.bandsteering.value = atoi(argv[3]);
		
		memset(buf, 0, sizeof(buf));
		memcpy(buf, &a, sizeof(struct han_ioctl_priv_args));

		memset(&iwr, 0, sizeof(iwr));
		WLANSET_STRING_CP(iwr.ifr_name, "wifi0");
		iwr.u.data.pointer = (void *) buf;
		iwr.u.data.length = sizeof(buf);
		
		han_ioctl(&iwr, ATH_IOCTL_HAN_PRIV);
		if (HAN_IOCTL_BANDSTEERING_STATISTICS == a.u.bandsteering.subtype) {

			u_int32_t	total_statistics = 0;
			memcpy(&a, buf, sizeof(struct han_ioctl_priv_args));
			total_statistics = a.u.bandsteering.bs_stat.total_2g + a.u.bandsteering.bs_stat.total_5g;
			
			printf("Band Steering Global Access Statistics:\n");
			printf("\tAccess to 2G: %d, %d%%, \n\tAccess to 5G: %d, %d%%\n\n", 
					a.u.bandsteering.bs_stat.total_2g, CALC(a.u.bandsteering.bs_stat.total_2g, total_statistics), 
					a.u.bandsteering.bs_stat.total_5g, CALC(a.u.bandsteering.bs_stat.total_5g, total_statistics));
			
			
			printf("Non 5G capable Clients: %d, %d%%\n\n", 
					a.u.bandsteering.bs_stat.non_5g_capable, 
					CALC(a.u.bandsteering.bs_stat.non_5g_capable, total_statistics));

			printf("5G capable Clients:\n");
			printf("\tExcessive load, 5G capable Clients to 2G: %d, %d%%\n", 
					a.u.bandsteering.bs_stat.excessive_load_5g_capable_to_2g, 
					CALC(a.u.bandsteering.bs_stat.excessive_load_5g_capable_to_2g, total_statistics));
			
			printf("\tWeak 2G Signal, Clients Access to 2G: %d, %d%%\n", 
					a.u.bandsteering.bs_stat.weak_2g_signal, 
					CALC(a.u.bandsteering.bs_stat.weak_2g_signal, total_statistics));

			printf("\t5G capable Clients persist to Access to 2G: %d, %d%%\n", 
					a.u.bandsteering.bs_stat.persist_to_2g, 
					CALC(a.u.bandsteering.bs_stat.persist_to_2g, total_statistics));
			
			printf("\tExcessive load, 5G capable Clients to 5G: %d, %d%%\n", 
					a.u.bandsteering.bs_stat.excessive_load_5g_capable_to_5g, 
					CALC(a.u.bandsteering.bs_stat.excessive_load_5g_capable_to_5g, total_statistics));
			
			printf("\tSteer Clients to 5G: %d, %d%%\n\n", 
					a.u.bandsteering.bs_stat.steer_to_5g, 
					CALC(a.u.bandsteering.bs_stat.steer_to_5g, total_statistics));

			printf("5G capable Clients Access to 5G: %d, %d%%\n", 
					a.u.bandsteering.bs_stat.total_5g,
					CALC(a.u.bandsteering.bs_stat.total_5g, 
					(a.u.bandsteering.bs_stat.total_2g - 
					a.u.bandsteering.bs_stat.non_5g_capable + 
					a.u.bandsteering.bs_stat.total_5g)));


			return 0;
		}
		if (OP_GET == a.u.bandsteering.op) {
			memcpy(&a, buf, sizeof(struct han_ioctl_priv_args));
			printf("BandSteering %s: %d\n", argv[2], a.u.bandsteering.value);
		}

	}
	return 0;

}
/*Begin:pengdecai for han private wmm*/
void
han_wirelessqos_help(void)
{
	printf("\nusage:: wlanset wmm COMMAND [OPTION] ... \n");
	printf("OPTIONS: \n");
	printf("\t[interface]\tset_enable\t\t[0|1]\n");
	printf("\t[interface]\tget_enable\n");
	
	printf("\t[interface]\tset_dscp_enable\t\t[0|1]\n");
	printf("\t[interface]\tget_dscp_enable\n");
	
	printf("\t[interface]\tset_8021p_enable\t\t[0|1]\n");
	printf("\t[interface]\tget_8021p_enable\n");
	
	printf("\t[interface]\tset_dscp_to_background\t\t[dscp priority list]\n");
	printf("\t[interface]\tget_dscp_to_background\n");
	
	printf("\t[interface]\tset_dscp_to_besteffort \t\t[dscp priority list]\n");
	printf("\t[interface]\tget_dscp_to_besteffort \n");

	printf("\t[interface]\tset_dscp_to_video\t\t[dscp priority list]\n");
	printf("\t[interface]\tget_dscp_to_video\n");

	printf("\t[interface]\tset_dscp_to_voice\t\t[dscp priority list]\n");
	printf("\t[interface]\tget_dscp_to_voice\n");
	
	printf("\t[interface]\tset_background_to_dscp\t\t[dscp priority]\n");
	printf("\t[interface]\tget_background_to_dscp\n");
	
	printf("\t[interface]\tset_besteffort_to_dscp\t\t[dscp priority]\n");
	printf("\t[interface]\tget_besteffort_to_dscp\n");
		
	printf("\t[interface]\tset_video_to_dscp\t\t[dscp priority]\n");
	printf("\t[interface]\tget_video_to_dscp\n");
	
	printf("\t[interface]\tset_voice_to_dscp\t\t[dscp priority]\n");
	printf("\t[interface]\tget_voice_to_dscp\n");

	printf("\t[interface]\tset_8021p_to_background\t\t[8021p priority list]\n");
	printf("\t[interface]\tget_8021p_to_background\n");
	
	printf("\t[interface]\tset_8021p_to_besteffort \t\t[8021p priority list]\n");
	printf("\t[interface]\tget_8021p_to_besteffort \n");

	printf("\t[interface]\tset_8021p_to_video\t\t[8021p priority list]\n");
	printf("\t[interface]\tget_8021p_to_video\n");

	printf("\t[interface]\tset_8021p_to_voice\t\t[8021p priority list]\n");
	printf("\t[interface]\tget_8021p_to_voice\n");
	
	printf("\t[interface]\tset_background_to_8021p\t\t[8021p priority]\n");
	printf("\t[interface]\tget_background_to_8021p\n");
	
	printf("\t[interface]\tset_besteffort_to_8021p\t\t[8021p priority]\n");
	printf("\t[interface]\tget_besteffort_to_8021p\n");
		
	printf("\t[interface]\tset_video_to_8021p\t\t[8021p priority]\n");
	printf("\t[interface]\tget_video_to_8021p\n");
	
	printf("\t[interface]\tset_voice_to_8021p\t\t[8021p priority]\n");
	printf("\t[interface]\tget_voice_to_8021p\n");
	printf("\t[interface]\tget_statistics\n");
	printf("\t[interface]\tset_debug\n");
	printf("\t[interface]\tget_debug\n");
}


#define IS_RIGHT_DSCP(arg) ((0 <= (arg))&&((arg) < 64) ? 1 : 0)
#define IS_RIGHT8021P(arg) ((0 <= (arg))&&((arg) < 8) ? 1 : 0)
#define     PERIOD_STAT64(fmt,x) \
     { printf(fmt"\t\t\t",(long long unsigned int)x);}\
   
#define PRINT_PARM(buf, len) { \
   int i=0; \
   for (i=0; i<len;i++) { \
   printf("%d ", ((unsigned char*)buf)[i]); } \
   printf("\n");}
   
/*delete a string left and right space*/
char  *trimleftright(char *string)
{
	int	len;
	char *p1, *p2;

	if(!strlen(string))
		return string; 
	if(isspace(*string))
	{
		len = strlen(string);
		p1 = (char *)malloc(len+1);
		p2 = p1;
		strcpy(p2, string);
		while(isspace(*p2))
			p2 ++;
		strcpy(string, p2);
		free(p1);
       }
	len = strlen(string);
	while(isspace(string[--len]))
		string[len] = '\0';
	return string;
}   

static int 
han_wirelessqos_deal_paramter(int argc, char** argv,char *store)
{
    int i = 0;
	int set_argc = argc - 4;
		
	int is_dscp_cmd = 0;
	int is_8021p_cmd = 0;
	const char *pcomma = ",";
	char * p = NULL;
    u_int8_t tmp = 0;
    int real_arg_num = 0;
	char *parg = NULL;
	
    if(set_argc > 0){

		if(strstr(argv[3],"dscp")){
			is_dscp_cmd = 1;
		}
		else if(strstr(argv[3],"8021p")){
			is_8021p_cmd = 1;
		}

        for (i = 0; i < set_argc ; i ++){

		   if (strstr(argv[4+i],pcomma)){
			    char arg[32]={0};
		   	    memcpy(arg,argv[4+i],strlen(argv[4+i]));
				parg = trimleftright(arg);
				p = strtok(parg,pcomma);
				while(p != NULL){
					
					tmp = atoi(p);
    	            if(is_dscp_cmd && (!IS_RIGHT_DSCP(tmp))){
                       printf("dscp parameter error!\n");
                       return -1;
                    }else if (is_8021p_cmd && (!IS_RIGHT8021P(tmp))){
                       printf("8021p parameter error!\n");
                       return -1;
                    }
					
 					store[real_arg_num ++] = tmp;	
					p = strtok(NULL,pcomma);
				}
				continue; 
		   }
	   
		   tmp= atoi(argv[4 + i]);
		  
		   
		   store[real_arg_num ++] = tmp;
	   }
   }
   return real_arg_num;
}

static int han_wirelessqos(int argc, char** argv)
{
    int ret = 0;
	struct iwreq iwr;
	unsigned char buf[1024] = {0};
	unsigned char arg[32] = {0};
	struct han_ioctl_priv_args a = {0};
	unsigned char real_arg_num = 0;
	int i = 0;
	if (argc < 4) {
		han_wirelessqos_help();
		return -1;
	} else {
		a.type = HAN_IOCTL_PRIV_WIRELESSQOS;
	}	
	
	if(strstr(argv[3],"set")){ 
	    a.u.wmm.op = OP_SET;
		real_arg_num = han_wirelessqos_deal_paramter(argc,argv,arg);
	}else if (strstr(argv[3],"get")){
		a.u.wmm.op = OP_GET;
	}else {
		printf("command error!");
		han_wirelessqos_help();
	    return -1;
	}
   	
	a.u.wmm.arg_num = real_arg_num;
	
	if (WLANSET_STRING_EQ(argv[3], "set_enable")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_ENABLE;
		a.u.wmm.wmm_args.wmm_enable = atoi(argv[4]);
		
	}else if (WLANSET_STRING_EQ(argv[3], "get_enable")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_ENABLE;
		
	}else if (WLANSET_STRING_EQ(argv[3], "set_dscp_enable")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_DSCP_ENABLE;
		a.u.wmm.wmm_args.dscp_enable = atoi(argv[4]);

	}else if (WLANSET_STRING_EQ(argv[3], "get_dscp_enable")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_DSCP_ENABLE;

	}else if (WLANSET_STRING_EQ(argv[3], "set_8021p_enable")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_8021P_ENABLE;
		a.u.wmm.wmm_args.vlan_enable = atoi(argv[4]);

	}else if (WLANSET_STRING_EQ(argv[3], "get_8021p_enable")) {
		a.u.wmm.subtype =  HAN_IOCTL_WMM_8021P_ENABLE;

	}else if (WLANSET_STRING_EQ(argv[3], "set_debug")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_DEBUG;
		a.u.wmm.wmm_args.debug = atoi(argv[4]);
	}else if (WLANSET_STRING_EQ(argv[3], "get_debug")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_DEBUG;
	}else if (WLANSET_STRING_EQ(argv[3], "set_dscp_to_background")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_DSCP_TO_BK;
        memcpy(a.u.wmm.wmm_args.dscp_to_bk,arg,real_arg_num);
	}else if (WLANSET_STRING_EQ(argv[3], "get_dscp_to_background")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_DSCP_TO_BK;

	}else if (WLANSET_STRING_EQ(argv[3], "set_dscp_to_besteffort")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_DSCP_TO_BE;
        memcpy(a.u.wmm.wmm_args.dscp_to_bk,arg,real_arg_num);

	}else if (WLANSET_STRING_EQ(argv[3], "get_dscp_to_besteffort")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_DSCP_TO_BE;

	}else if (WLANSET_STRING_EQ(argv[3], "set_dscp_to_video")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_DSCP_TO_VI;
        memcpy(a.u.wmm.wmm_args.dscp_to_vi,arg,real_arg_num);

	}else if (WLANSET_STRING_EQ(argv[3], "get_dscp_to_video")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_DSCP_TO_VI;

	}else if (WLANSET_STRING_EQ(argv[3], "set_dscp_to_voice")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_DSCP_TO_VO;
        memcpy(a.u.wmm.wmm_args.dscp_to_vo,arg,real_arg_num);

	}else if (WLANSET_STRING_EQ(argv[3], "get_dscp_to_voice")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_DSCP_TO_VO;

	}else if (WLANSET_STRING_EQ(argv[3], "set_background_to_dscp")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_BK_TO_DSCP;
		a.u.wmm.wmm_args.bk_to_dscp = arg[0];

	}else if (WLANSET_STRING_EQ(argv[3], "get_background_to_dscp")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_BK_TO_DSCP;

	}else if (WLANSET_STRING_EQ(argv[3], "set_besteffort_to_dscp")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_BE_TO_DSCP;
		a.u.wmm.wmm_args.be_to_dscp = arg[0];

	}else if (WLANSET_STRING_EQ(argv[3], "get_besteffort_to_dscp")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_BE_TO_DSCP;

	}else if (WLANSET_STRING_EQ(argv[3], "set_video_to_dscp")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_VI_TO_DSCP;
		a.u.wmm.wmm_args.vi_to_dscp = arg[0];

	}else if (WLANSET_STRING_EQ(argv[3], "get_video_to_dscp")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_VI_TO_DSCP;

	}else if (WLANSET_STRING_EQ(argv[3], "set_voice_to_dscp")) {
	    a.u.wmm.subtype = HAN_IOCTL_WMM_VO_TO_DSCP;
		a.u.wmm.wmm_args.vo_to_dscp = arg[0];
	}else if (WLANSET_STRING_EQ(argv[3], "get_voice_to_dscp")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_VO_TO_DSCP;

	}else if (WLANSET_STRING_EQ(argv[3], "set_8021p_to_background")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_8021P_TO_BK;
        memcpy(a.u.wmm.wmm_args.vlan_to_bk,arg,real_arg_num);

	}else if (WLANSET_STRING_EQ(argv[3], "get_8021p_to_background")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_8021P_TO_BK;

	}else if (WLANSET_STRING_EQ(argv[3], "set_8021p_to_besteffort")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_8021P_TO_BE;
        memcpy(a.u.wmm.wmm_args.vlan_to_be,arg,real_arg_num);

	}else if (WLANSET_STRING_EQ(argv[3], "get_8021p_to_besteffort")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_8021P_TO_BE;

	}else if (WLANSET_STRING_EQ(argv[3], "set_8021p_to_video")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_8021P_TO_VI;
        memcpy(a.u.wmm.wmm_args.vlan_to_vi,arg,real_arg_num);

	}else if (WLANSET_STRING_EQ(argv[3], "get_8021p_to_video")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_8021P_TO_VI;

	}else if (WLANSET_STRING_EQ(argv[3], "set_8021p_to_voice")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_8021P_TO_VO;
        memcpy(a.u.wmm.wmm_args.vlan_to_vo,arg,real_arg_num);

	}else if (WLANSET_STRING_EQ(argv[3], "get_8021p_to_voice")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_8021P_TO_VO;
		
	}else if (WLANSET_STRING_EQ(argv[3], "set_background_to_8021p")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_BK_TO_8021P;
		a.u.wmm.wmm_args.bk_to_vlan = arg[0];

	}else if (WLANSET_STRING_EQ(argv[3], "get_background_to_8021p")) {
		a.u.wmm.subtype =  HAN_IOCTL_WMM_BK_TO_8021P;

	}else if (WLANSET_STRING_EQ(argv[3], "set_besteffort_to_8021p")) {
		a.u.wmm.subtype =  HAN_IOCTL_WMM_BE_TO_8021P;
		a.u.wmm.wmm_args.be_to_vlan = arg[0];

	}else if (WLANSET_STRING_EQ(argv[3], "get_besteffort_to_8021p")) {
		a.u.wmm.subtype =  HAN_IOCTL_WMM_BE_TO_8021P;

	}else if (WLANSET_STRING_EQ(argv[3], "set_video_to_8021p")) {
		a.u.wmm.subtype =  HAN_IOCTL_WMM_VI_TO_8021P;
		a.u.wmm.wmm_args.vi_to_vlan = arg[0];

	}else if (WLANSET_STRING_EQ(argv[3], "get_video_to_8021p")) {
		a.u.wmm.subtype =  HAN_IOCTL_WMM_VI_TO_8021P;

	}else if (WLANSET_STRING_EQ(argv[3], "set_voice_to_8021p")) {
		a.u.wmm.subtype =  HAN_IOCTL_WMM_VO_TO_8021P;
		a.u.wmm.wmm_args.vo_to_vlan = arg[0];
		
	}else if (WLANSET_STRING_EQ(argv[3], "get_voice_to_8021p")) {
		a.u.wmm.subtype =  HAN_IOCTL_WMM_VO_TO_8021P;
	}else if (WLANSET_STRING_EQ(argv[3], "get_statistics")) {
		a.u.wmm.subtype = HAN_IOCTL_WMM_STATISTICS;
	}else {
		printf("command error!");
		han_wirelessqos_help();
		return -1;
	}
	
   memset(buf, 0, sizeof(buf));
   memcpy(buf, &a, sizeof(struct han_ioctl_priv_args));
	
   memset(&iwr, 0, sizeof(iwr));
   WLANSET_STRING_CP(iwr.ifr_name, argv[2]);
   iwr.u.data.pointer = (void *) buf;
   iwr.u.data.length = sizeof(buf);
		
   ret = han_ioctl(&iwr, IEEE80211_IOCTL_HAN_PRIV);
   if (ret < 0 ){
		printf("han ioctl error !\n");	
		return -1;
   }
   
   if(OP_GET == a.u.wmm.op){
   	
		memcpy(&a, buf, sizeof(struct han_ioctl_priv_args));
		
		if(HAN_IOCTL_WMM_ENABLE == a.u.wmm.subtype){
			printf("%d\n",a.u.wmm.wmm_args.wmm_enable);
			
		}else if(HAN_IOCTL_WMM_DSCP_ENABLE == a.u.wmm.subtype){
			printf("%d\n",a.u.wmm.wmm_args.dscp_enable);

		}else if(HAN_IOCTL_WMM_8021P_ENABLE == a.u.wmm.subtype){
			printf("%d\n",a.u.wmm.wmm_args.vlan_enable);

		}else if(HAN_IOCTL_WMM_DEBUG == a.u.wmm.subtype){
			printf("%d\n",a.u.wmm.wmm_args.debug);

		}else if(HAN_IOCTL_WMM_DSCP_TO_BK == a.u.wmm.subtype){
			PRINT_PARM(a.u.wmm.wmm_args.dscp_to_bk,a.u.wmm.arg_num);

		}else if(HAN_IOCTL_WMM_DSCP_TO_BE == a.u.wmm.subtype){
			PRINT_PARM(a.u.wmm.wmm_args.dscp_to_be,a.u.wmm.arg_num);

		}else if(HAN_IOCTL_WMM_DSCP_TO_VI == a.u.wmm.subtype){
			PRINT_PARM(a.u.wmm.wmm_args.dscp_to_vi,a.u.wmm.arg_num);

		}else if(HAN_IOCTL_WMM_DSCP_TO_VO == a.u.wmm.subtype){
			PRINT_PARM(a.u.wmm.wmm_args.dscp_to_vo,a.u.wmm.arg_num);

		}else if(HAN_IOCTL_WMM_BK_TO_DSCP == a.u.wmm.subtype){
  			printf("%d\n",a.u.wmm.wmm_args.bk_to_dscp);
			
		}else if(HAN_IOCTL_WMM_BE_TO_DSCP == a.u.wmm.subtype){
  			printf("%d\n",a.u.wmm.wmm_args.be_to_dscp);
			
		}else if(HAN_IOCTL_WMM_VI_TO_DSCP == a.u.wmm.subtype){
  			printf("%d\n",a.u.wmm.wmm_args.vi_to_dscp);
			
		}else if(HAN_IOCTL_WMM_VO_TO_DSCP == a.u.wmm.subtype){
  			printf("%d\n",a.u.wmm.wmm_args.vo_to_dscp);
			
		}else if(HAN_IOCTL_WMM_8021P_TO_BK == a.u.wmm.subtype){
			PRINT_PARM(a.u.wmm.wmm_args.vlan_to_bk,a.u.wmm.arg_num);

		}else if(HAN_IOCTL_WMM_8021P_TO_BE == a.u.wmm.subtype){
			PRINT_PARM(a.u.wmm.wmm_args.vlan_to_be,a.u.wmm.arg_num);
			
		}else if(HAN_IOCTL_WMM_8021P_TO_VI == a.u.wmm.subtype){
			PRINT_PARM(a.u.wmm.wmm_args.vlan_to_vi,a.u.wmm.arg_num);
			
		}else if(HAN_IOCTL_WMM_8021P_TO_VO == a.u.wmm.subtype){
			PRINT_PARM(a.u.wmm.wmm_args.vlan_to_vo,a.u.wmm.arg_num);
			
		}else if(HAN_IOCTL_WMM_BK_TO_8021P == a.u.wmm.subtype){
  			printf("%d\n",a.u.wmm.wmm_args.bk_to_vlan);
			
		}else if(HAN_IOCTL_WMM_BE_TO_8021P == a.u.wmm.subtype){
  			printf("%d\n",a.u.wmm.wmm_args.be_to_vlan);

		}else if(HAN_IOCTL_WMM_VI_TO_8021P == a.u.wmm.subtype){
  			printf("%d\n",a.u.wmm.wmm_args.vi_to_vlan);

		}else if(HAN_IOCTL_WMM_VO_TO_8021P == a.u.wmm.subtype){
  			printf("%d\n",a.u.wmm.wmm_args.vo_to_vlan);

		}else if(HAN_IOCTL_WMM_STATISTICS == a.u.wmm.subtype){
		
			printf("\nSwitch status:\n");
			
			printf("wmm_swtich: \t%d\n",a.u.wmm.wmm_stat.wmm_enable);
			printf("dscp_swtich: \t%d\n",a.u.wmm.wmm_stat.dscp_enable);
			printf("8021p_swtich: \t%d\n\n",a.u.wmm.wmm_stat.vlan_enable);
			
			printf("Statistics:\n");
			
			printf("dscp_to_wmm_packets_ok:\t\t%llu\n",a.u.wmm.wmm_stat.dscp_to_wmm_packets_ok);	
			printf("dscp_to_wmm_packets_error:\t\t%llu\n",a.u.wmm.wmm_stat.dscp_to_wmm_packets_error);
			printf("wmm_to_dscp_packets_ok:\t\t%llu\n",a.u.wmm.wmm_stat.wmm_to_dscp_packets_ok);
			printf("wmm_to_dscp_packets_error:\t\t%llu\n",a.u.wmm.wmm_stat.wmm_to_dscp_packets_error);
			printf("8021p_to_wmm_packets_ok:\t\t%llu\n",a.u.wmm.wmm_stat.vlan_to_wmm_packets_ok);
			printf("8021p_to_wmm_packets_error:\t\t%llu\n",a.u.wmm.wmm_stat.vlan_to_wmm_packets_error);
			printf("wmm_to_8021p_packets_ok:\t\t%llu\n",a.u.wmm.wmm_stat.vlan_to_wmm_packets_ok);
			printf("wmm_to_8021P_packets_error:\t\t%llu\n",a.u.wmm.wmm_stat.vlan_to_wmm_packets_error);
			
		}else {
			printf("han ioctl wmm get subtype error!");
			return -1;
		}

   }
 
}
/*End:pengdecai for han private wmm*/
static void 
han_help (void) 
{
	printf("\nusage:: wlanset COMMAND [OPTION] ... \n");
	printf("OPTIONS: \n");
	printf("\tbandsteering\t\t... ...\n");
	printf("\ttraffic_limit\t... ...\n");
	printf("\twmm\t... ...\n");
	printf("\n");
}

/*
 *the main function for autelan private command
 */
int main (int argc, char** argv)
{
	/*check the arc number*/
	if(argc < 2) {
		han_help () ;
		printf("wlanset command error: incomplete command\n");
		return 0;
	}

	if (WLANSET_STRING_EQ(argv[1], "bandsteering")){
		if (han_bandsteering(argc, argv) < 0)
			printf("wlanset command  bandsteering: wrong format\n");	
	} else if (WLANSET_STRING_EQ(argv[1], "wmm")){
		if(han_wirelessqos(argc, argv) < 0)
		printf("wlanset command  wmm: wrong format\n");	
	}
	else if (WLANSET_STRING_EQ(argv[1], "traffic_limit"))
		//if (autelan_traffic_limit(argc, argv) < 0)
			//printf("wlanset command  traffic_limit: wrong format\n");
	return 0;
	
}
