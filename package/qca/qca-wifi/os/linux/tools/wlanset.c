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



enum han_ioctl_priv {
	HAN_IOCTL_PRIV_BANDSTEERING = 0,
};

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

		/*New cmd struct*/
	} u;
};



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


static void 
han_help (void) 
{
	printf("\nusage:: wlanset COMMAND [OPTION] ... \n");
	printf("OPTIONS: \n");
	printf("\tbandsteering\t\t... ...\n");
	printf("\ttraffic_limit\t... ...\n");
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

	if (WLANSET_STRING_EQ(argv[1], "bandsteering"))
		if (han_bandsteering(argc, argv) < 0)
			printf("wlanset command  bandsteering: wrong format\n");	
	else if (WLANSET_STRING_EQ(argv[1], "traffic_limit"))
		//if (autelan_traffic_limit(argc, argv) < 0)
			//printf("wlanset command  traffic_limit: wrong format\n");
	return 0;
	
}
