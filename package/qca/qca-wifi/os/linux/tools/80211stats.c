/*
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*
 * 80211stats [-i interface]
 * (default interface is ath0).
 */
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <netinet/ether.h>
#include <linux/types.h>
#include <linux/if.h> //zhaoyang1 transplants statistics 2015-01-27



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

/*
 * Linux uses __BIG_ENDIAN and __LITTLE_ENDIAN while BSD uses _foo
 * and an explicit _BYTE_ORDER.  Sorry, BSD got there first--define
 * things in the BSD way...
 */
#ifndef	_LITTLE_ENDIAN
#define	_LITTLE_ENDIAN	1234	/* LSB first: i386, vax */
#endif
#ifndef	_BIG_ENDIAN
#define	_BIG_ENDIAN	4321	/* MSB first: 68000, ibm, net */
#endif
#ifndef ATH_SUPPORT_LINUX_STA
#include <asm/byteorder.h>
#endif
#if defined(__LITTLE_ENDIAN)
#define	_BYTE_ORDER	_LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define	_BYTE_ORDER	_BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif

#include "os/linux/include/ieee80211_external.h"

#ifndef SIOCG80211STATS
#define	SIOCG80211STATS	(SIOCDEVPRIVATE+2)
#endif

const unsigned char rssi_range[17][16] = {
						"-10 +",
						"-19 ~ -10",
						"-39 ~ -20",
					    "-49 ~ -40",
					    "-59 ~ -50",
					    "-64 ~ -60",
					    "-67 ~ -65",
					    "-70 ~ -68",
					    "-73 ~ -71",
					    "-76 ~ -74",
					    "-79 ~ -77",
					    "-82 ~ -80",
					    "-85 ~ -83",
					    "-88 ~ -86",
					    "-91 ~ -89",
					    "-94 ~ -92",
					    "-95 -",
};

static void
printstats(FILE *fd, const struct ieee80211_stats *stats)
{
#define	N(a)	(sizeof(a) / sizeof(a[0]))
#define	STAT(x,fmt) \
	if (stats->is_##x) fprintf(fd, "%u " fmt "\n", stats->is_##x)
	STAT(rx_badversion,	"rx frame with bad version");
	STAT(rx_tooshort,	"rx frame too short");
	STAT(rx_wrongbss,	"rx from wrong bssid");
#ifdef NOT_YET
	STAT(rx_dup,		"rx discard 'cuz dup");
#endif
	STAT(rx_wrongdir,	"rx w/ wrong direction");
	STAT(rx_mcastecho,	"rx discard 'cuz mcast echo");
	STAT(rx_notassoc,	"rx discard 'cuz sta !assoc");
	STAT(rx_noprivacy,	"rx w/ wep but privacy off");
#ifdef NOT_YET
	STAT(rx_unencrypted,	"rx w/o wep and privacy on");
	STAT(rx_wepfail,	"rx wep processing failed");
#endif
	STAT(rx_decap,		"rx decapsulation failed");
	STAT(rx_mgtdiscard,	"rx discard mgt frames");
	STAT(rx_ctl,		"rx discard ctrl frames");
	STAT(rx_beacon,		"rx beacon frames");
	STAT(rx_rstoobig,	"rx rate set truncated");
	STAT(rx_elem_missing,	"rx required element missing");
	STAT(rx_elem_toobig,	"rx element too big");
	STAT(rx_elem_toosmall,	"rx element too small");
	STAT(rx_elem_unknown,	"rx element unknown");
	STAT(rx_badchan,	"rx frame w/ invalid chan");
	STAT(rx_chanmismatch,	"rx frame chan mismatch");
	STAT(rx_nodealloc,	"nodes allocated (rx)");
	STAT(rx_ssidmismatch,	"rx frame ssid mismatch");
	STAT(rx_auth_unsupported,"rx w/ unsupported auth alg");
	STAT(rx_auth_fail,	"rx sta auth failure");
	STAT(rx_auth_countermeasures,
		"rx sta auth failure 'cuz of TKIP countermeasures");
	STAT(rx_assoc_bss,	"rx assoc from wrong bssid");
	STAT(rx_assoc_notauth,	"rx assoc w/o auth");
	STAT(rx_assoc_capmismatch,"rx assoc w/ cap mismatch");
	STAT(rx_assoc_norate,	"rx assoc w/ no rate match");
	STAT(rx_assoc_badwpaie,	"rx assoc w/ bad WPA IE");
	STAT(rx_deauth,		"rx deauthentication");
	STAT(rx_disassoc,	"rx disassociation");
	STAT(rx_action,		"rx action mgt");
	STAT(rx_badsubtype,	"rx frame w/ unknown subtype");
	STAT(rx_nobuf,		"rx failed for lack of sk_buffer");
#ifdef NOT_YET
	STAT(rx_decryptcrc,	"rx decrypt failed on crc");
#endif
	STAT(rx_ahdemo_mgt,
		"rx discard mgmt frame received in ahdoc demo mode");
	STAT(rx_bad_auth,	"rx bad authentication request");
	STAT(rx_unauth,		"rx discard 'cuz port unauthorized");
#ifdef NOT_YET
	STAT(rx_badkeyid,	"rx w/ incorrect keyid");
	STAT(rx_ccmpreplay,	"rx seq# violation (CCMP)");
	STAT(rx_ccmpformat,	"rx format bad (CCMP)");
	STAT(rx_ccmpmic,	"rx MIC check failed (CCMP)");
	STAT(rx_tkipreplay,	"rx seq# violation (TKIP)");
	STAT(rx_tkipformat,	"rx format bad (TKIP)");
	STAT(rx_tkipmic,	"rx MIC check failed (TKIP)");
	STAT(rx_tkipicv,	"rx ICV check failed (TKIP)");
#endif
	STAT(rx_badcipher,	"rx failed 'cuz bad cipher/key type");
	STAT(rx_nocipherctx,	"rx failed 'cuz key/cipher ctx not setup");
	STAT(rx_acl,		"rx discard 'cuz acl policy");
	STAT(rx_ffcnt,		"rx fast frames");
	STAT(rx_badathtnl,   	"rx fast frame failed 'cuz bad tunnel header");
	STAT(tx_nobuf,		"tx failed for lack of sk_buffer");
	STAT(tx_nonode,		"tx failed for no node");
	STAT(tx_unknownmgt,	"tx of unknown mgt frame");
	STAT(tx_badcipher,	"tx failed 'cuz bad ciper/key type");
	STAT(tx_nodefkey,	"tx failed 'cuz no defkey");
	STAT(tx_noheadroom,	"tx failed 'cuz no space for crypto hdrs");
	STAT(tx_ffokcnt,	"tx atheros fast frames successful");
	STAT(tx_fferrcnt,	"tx atheros fast frames failed");
	STAT(scan_active,	"active scans started");
	STAT(scan_passive,	"passive scans started");
	STAT(node_timeout,	"nodes timed out inactivity");
	STAT(crypto_nomem,	"cipher context malloc failed");
	STAT(crypto_tkip,	"tkip crypto done in s/w");
	STAT(crypto_tkipenmic,	"tkip tx MIC done in s/w");
	STAT(crypto_tkipdemic,	"tkip rx MIC done in s/w");
	STAT(crypto_tkipcm,	"tkip dropped frames 'cuz of countermeasures");
	STAT(crypto_ccmp,	"ccmp crypto done in s/w");
	STAT(crypto_wep,	"wep crypto done in s/w");
	STAT(crypto_setkey_cipher,"setkey failed 'cuz cipher rejected data");
	STAT(crypto_setkey_nokey,"setkey failed 'cuz no key index");
	STAT(crypto_delkey,	"driver key delete failed");
	STAT(crypto_badcipher,	"setkey failed 'cuz unknown cipher");
	STAT(crypto_nocipher,	"setkey failed 'cuz cipher module unavailable");
	STAT(crypto_attachfail,	"setkey failed 'cuz cipher attach failed");
	STAT(crypto_swfallback,	"crypto fell back to s/w implementation");
	STAT(crypto_keyfail,	"setkey faied 'cuz driver key alloc failed");
    STAT(crypto_enmicfail, "en-MIC failed ");
    STAT(ibss_capmismatch, " merge failed-cap mismatch");
    STAT(ibss_norate," merge failed-rate mismatch");
    STAT(ps_unassoc,"ps-poll for unassoc. sta ");
    STAT(ps_badaid, " ps-poll w/ incorrect aid ");
    STAT(ps_qempty," ps-poll w/ nothing to send ");

	/* Autelan-Begin: zhaoyang1 transplants statistics 2015-01-27 */
    fprintf(fd, "\n****** Association deny statistics ******\n");
	STAT(rx_assoc_bss,	"rx assoc from wrong bssid");
	STAT(rx_assoc_notauth,	"rx assoc w/o auth");
	STAT(rx_assoc_capmismatch,"rx assoc w/ cap mismatch");
	STAT(rx_assoc_norate,	"rx assoc w/ no rate match");
	STAT(rx_assoc_badwpaie,	"rx assoc w/ bad WPA IE");
    STAT(rx_assoc_puren_mismatch, "rx assoc no ht rate puren mismatch");
    STAT(rx_assoc_traffic_balance_too_many_stations, "rx assoc traffic balance too many sta");
    STAT(rx_reassoc_bss,	"rx reassoc from wrong bssid");
	STAT(rx_reassoc_notauth,	"rx reassoc w/o auth");
	STAT(rx_reassoc_capmismatch,"rx reassoc w/ cap mismatch");
	STAT(rx_reassoc_norate,	"rx reassoc w/ no rate match");
	STAT(rx_reassoc_badwpaie,	"rx reassoc w/ bad WPA IE");
    STAT(rx_reassoc_puren_mismatch, "rx reassoc no ht rate puren mismatch");
    STAT(rx_reassoc_traffic_balance_too_many_stations, "rx reassoc traffic balance too many sta");
    fprintf(fd, "%u tx_assoc_respon_deny\n", stats->is_rx_reassoc_capmismatch
                                            + stats->is_rx_reassoc_norate
                                            + stats->is_rx_reassoc_puren_mismatch
                                            + stats->is_rx_reassoc_traffic_balance_too_many_stations
                                            + stats->is_rx_assoc_capmismatch
                                            + stats->is_rx_assoc_norate
                                            + stats->is_rx_assoc_puren_mismatch
                                            + stats->is_rx_assoc_traffic_balance_too_many_stations);
    fprintf(fd, "\n***** TX  Deauth  Frame  statistics *****\n");
    STAT(deauth_not_authed, "rx data from sta not authed");
    STAT(ps_unassoc,"rx pspoll from sta not assoc");
    STAT(deauth_expire, "sta timeout");
    STAT(deauth_excessive_retries, "excessive retries");
    STAT(deauth_data_lower_rssi, "rx data from lower rssi sta");
    STAT(deauth_ioctl_kicknode, "kick sta send deauth");
    fprintf(fd, "%u tx deauth\n", stats->is_deauth_not_authed
                                + stats->is_ps_unassoc
                                + stats->is_deauth_expire
                                + stats->is_deauth_excessive_retries
                                + stats->is_rx_reassoc_notauth
                                + stats->is_rx_assoc_notauth
                                + stats->is_rx_reassoc_badscie
                                + stats->is_rx_assoc_badwpaie
                                + stats->is_deauth_data_lower_rssi
                                + stats->is_deauth_ioctl_kicknode);
    fprintf(fd, "\n***** TX Disassoc  Frame statistics *****\n");
    STAT(tx_disassoc_not_assoc, "recv data from not assoc");
    STAT(tx_disassoc_ioctl_kicknode, "kick sta send disassoc");
    STAT(tx_disassoc_bss_stop, "stop bss kick all stas");
    fprintf(fd, "%u tx disassoc\n", stats->is_tx_disassoc_not_assoc
                                  + stats->is_tx_disassoc_ioctl_kicknode
                                  + stats->is_tx_disassoc_bss_stop);
    STAT(tx_auth_failed, "send auth deny");
	/* Autelan-Begin: zhaoyang1 modifies for client access statistics 2015-03-27 */
	fprintf(fd, "\n***** Clinet    Access   statistics *****\n");
	fprintf(fd, "%u client access totally cnt\n", 
								stats->is_client_access_totally_cnt);
	fprintf(fd, "%u client access successfully cnt\n", 
								stats->is_client_access_successfully_cnt);
	fprintf(fd, "%u client access failed cnt\n", 
		stats->is_client_access_totally_cnt - stats->is_client_access_successfully_cnt);
	/* Autelan-End: zhaoyang1 modifies for client access statistics 2015-03-27 */
    fprintf(fd, "\n***** RX   data    Rssi  statistics *****\n");
    {
        int i = 0, count = 1;
        for(i = 0; i < 17 ; i++) {
            fprintf(fd,"rssi[%s] = %llu  ", rssi_range[i], stats->is_rssi_stats[i].ns_rx_data);  
            if ((count++) % 5 == 0)
                fprintf(fd,"\n");
        }
    }
    fprintf(fd, "\n\n***** RX   data    Rate  statistics *****\n");
    {
        int i = 0, count = 1;
        for (i = 0; i < 12; i++) {
            fprintf(fd, "%dM: %llu  ", 
                          stats->is_rx_rate_index[i].dot11Rate/2, stats->is_rx_rate_index[i].count);
            if ((count++) % 6 == 0)
                fprintf(fd,"\n");
        }
        count = 1;
        for (i = 0; i < 24; i++) {
            fprintf(fd, "MCS[%d]: %llu  ", i, stats->is_rx_mcs_count[i]);
            if ((count++) % 8 == 0)
                fprintf(fd,"\n");
        }
        count = 1;
        fprintf(fd, "\n*****  TX   data    Rate  statistics *****\n");
        for (i = 0; i < 12; i++) {
           fprintf(fd, "%dM: %llu  ", 
                          stats->is_tx_rate_index[i].dot11Rate/2, stats->is_tx_rate_index[i].count);
           if ((count++) % 6 == 0)
                fprintf(fd,"\n");
        }
        count = 1;
        for (i = 0; i < 24; i++) {
            fprintf(fd, "MCS[%d]: %llu  ", i, stats->is_tx_mcs_count[i]);
            if ((count++) % 8 == 0)
                fprintf(fd, "\n");
        }
        fprintf(fd, "\n");
    }
	/* Autelan-End: zhaoyang1 transplants statistics 2015-01-27 */
#undef STAT
#undef N
}

static void
print_mac_stats(FILE *fd, const struct ieee80211_mac_stats *stats, int unicast)
{
/* Autelan-Begin: zhaoyang1 transplants statistics 2015-01-27 */
#define	STAT(x,fmt) \
	if (stats->ims_##x) fprintf(fd, "%llu " fmt "\n", stats->ims_##x)

    int i=0;
	
    if (0 == unicast) {
        fprintf(fd, "\n******    Multicast    statistics  ******\n");
    } else if (1 == unicast){
        fprintf(fd, "\n******    Unicast      statistics  ******\n");
    } 
	
    STAT(tx_packets, "frames successfully transmitted ");
    STAT(tx_bytes, "bytes successfully transmitted ");
    STAT(rx_packets, "frames successfully received ");
    STAT(rx_bytes, "bytes successfully received ");

    STAT(tx_retry_packets, "frames retry transmitted ");
    STAT(tx_retry_bytes, "bytes retry transmitted ");
    STAT(rx_retry_packets, "frame retry received ");
    STAT(rx_retry_bytes, "bytes retry received ");
/* Autelan-End: zhaoyang1 transplants statistics 2015-01-27 */

    /* Decryption errors */
    STAT(rx_unencrypted, "rx w/o wep and privacy on ");
    STAT(rx_badkeyid,    "rx w/ incorrect keyid ");
    STAT(rx_decryptok,   "rx decrypt okay ");
    STAT(rx_decryptcrc,  "rx decrypt failed on crc ");
    STAT(rx_wepfail,     "rx wep processing failed ");
    STAT(rx_tkipreplay,  "rx seq# violation (TKIP) ");
    STAT(rx_tkipformat,  "rx format bad (TKIP) ");
    STAT(rx_tkipmic,     "rx MIC check failed (TKIP) ");
    STAT(rx_tkipicv,     "rx ICV check failed (TKIP) ");
    STAT(rx_ccmpreplay,  "rx seq# violation (CCMP) ");
    STAT(rx_ccmpformat,  "rx format bad (CCMP) ");
    STAT(rx_ccmpmic,     "rx MIC check failed (CCMP) ");

    /* Other Tx/Rx errors */
    STAT(tx_discard,     "tx dropped by NIC ");
    STAT(rx_discard,     "rx dropped by NIC ");
    STAT(rx_countermeasure, "rx TKIP countermeasure activation count ");
#undef STAT
}

struct ifreq ifr;
int	s;

static void
print_sta_stats(FILE *fd, const u_int8_t macaddr[IEEE80211_ADDR_LEN])
{
#define	STAT(x,fmt) \
	if (ns->ns_##x) { fprintf(fd, "%s" #x " " fmt, sep, ns->ns_##x); sep = " "; }
#define	STAT64(x,fmt) \
	if (ns->ns_##x) { fprintf(fd, "%s" #x " " fmt, sep, (long long unsigned int) ns->ns_##x); sep = " "; }
	struct iwreq iwr;
	struct ieee80211req_sta_stats stats;
	const struct ieee80211_nodestats *ns = &stats.is_stats;
	const char *sep;

	(void) memset(&iwr, 0, sizeof(iwr));
	(void) strncpy(iwr.ifr_name, ifr.ifr_name, sizeof(iwr.ifr_name));
    iwr.ifr_name[sizeof(iwr.ifr_name) - 1] = '\0';
	iwr.u.data.pointer = (void *) &stats;
	iwr.u.data.length = sizeof(stats);
	memcpy(stats.is_u.macaddr, macaddr, IEEE80211_ADDR_LEN);
	if (ioctl(s, IEEE80211_IOCTL_STA_STATS, &iwr) < 0)
		err(1, "unable to get station stats for %s",
			ether_ntoa((const struct ether_addr*) macaddr));

	fprintf(fd, "%s:\n", ether_ntoa((const struct ether_addr*) macaddr));

	sep = "\t";
	STAT(rx_data, "%u");
	STAT(rx_bytes, "%llu"); //zhaoyang1 transplants statistics 2015-01-27
	STAT(rx_mgmt, "%u");
	STAT(rx_ctrl, "%u");
	STAT64(rx_beacons, "%llu");
	STAT(rx_proberesp, "%u");
	STAT(rx_ucast, "%u");
	STAT(rx_ucast_bytes, "%llu"); //zhaoyang1 transplants statistics 2015-01-27
	STAT(rx_mcast, "%u");
	STAT(rx_mcast_bytes, "%llu"); //zhaoyang1 transplants statistics 2015-01-27
	STAT(rx_bytes, "%llu");
	STAT(rx_dup, "%u");
	STAT(rx_noprivacy, "%u");
	STAT(rx_wepfail, "%u");
	STAT(rx_demicfail, "%u");
	STAT(rx_decap, "%u");
	STAT(rx_defrag, "%u");
	STAT(rx_disassoc, "%u");
	STAT(rx_deauth, "%u");
	STAT(rx_action, "%u");
	STAT(rx_decryptcrc, "%u");
	STAT(rx_unauth, "%u");
	STAT(rx_unencrypted, "%u");
	STAT(rx_retry_packets, "%u"); //zhaoyang1 transplants statistics 2015-01-27
	STAT(rx_retry_bytes, "%llu"); //zhaoyang1 transplants statistics 2015-01-27
	fprintf(fd, "\n");

	sep = "\t";
	STAT(tx_data, "%u");
	STAT(tx_bytes, "%llu"); //zhaoyang1 transplants statistics 2015-01-27
	STAT(tx_mgmt, "%u");
	STAT(tx_probereq, "%u");
	STAT(tx_ucast, "%u");
	STAT(tx_ucast_bytes, "%llu"); //zhaoyang1 transplants statistics 2015-01-27
	STAT(tx_mcast, "%u");
	STAT(tx_mcast_bytes, "%llu"); //zhaoyang1 transplants statistics 2015-01-27
	STAT(tx_bytes, "%llu");
	STAT(tx_novlantag, "%u");
	STAT(tx_vlanmismatch, "%u");
	fprintf(fd, "\n");

	sep = "\t";
	STAT(tx_assoc, "%u");
	STAT(tx_assoc_fail, "%u");
	STAT(tx_auth, "%u");
	STAT(tx_auth_fail, "%u");
	STAT(tx_deauth, "%u");
	STAT(tx_deauth_code, "%u");
	STAT(tx_disassoc, "%u");
	STAT(tx_disassoc_code, "%u");
	STAT(tx_retry_packets, "%u"); 
	STAT(tx_retry_bytes, "%llu"); //zhaoyang1 transplants statistics 2015-01-27
	STAT(psq_drops, "%u");
	fprintf(fd, "\n");

	sep = "\t";
	STAT(tx_uapsd, "%u");
	STAT(uapsd_triggers, "%u");
	fprintf(fd, "\n");
	sep = "\t";
	STAT(uapsd_duptriggers, "%u");
	STAT(uapsd_ignoretriggers, "%u");
	fprintf(fd, "\n");
	sep = "\t";
	STAT(uapsd_active, "%u");
	STAT(uapsd_triggerenabled, "%u");
	fprintf(fd, "\n");
	sep = "\t";
	STAT(tx_eosplost, "%u");
	/* Autelan-Begin: zhaoyang1 transplants statistics 2015-01-27 */
	sep = "\t";
    STAT(rx_unencrypted, "%u");
    STAT(rx_badkeyid, "%u");
    STAT(rx_decryptcrc, "%u");
    STAT(rx_wepfail, "%u");
    STAT(rx_tkipreplay, "%u");
	STAT(rx_fcserr, "%u");
    STAT(rx_tkipformat, "%u");
    STAT(rx_tkipmic, "%u");
    STAT(rx_tkipicv, "%u");
    STAT(rx_ccmpreplay, "%u");
    STAT(rx_ccmpformat, "%u");
    STAT(rx_ccmpmic, "%u");
    STAT(rx_wpireplay, "%u");
    STAT(rx_wpimic, "%u");
    STAT(tx_discard, "%u");
    STAT(rx_discard, "%u");
	fprintf(fd, "\n");

	fprintf(fd, "\n***** RX   data    Rssi  statistics *****\n");
    {
        int i = 0, count = 1;
        for(i = 0; i < 17 ; i++) {
            fprintf(fd,"rssi[%s] = %llu  ", rssi_range[i], ns->ns_rssi_stats[i].ns_rx_data);  
            if ((count++) % 5 == 0)
                fprintf(fd,"\n");
        }
    }

    fprintf(fd, "\n\n***** RX   data    Rate  statistics *****\n");
    {
        int i = 0, count = 1;
        for (i = 0; i < 12; i++) {
            fprintf(fd, "%dM: %llu  ", 
                          ns->ns_rx_rate_index[i].dot11Rate/2, ns->ns_rx_rate_index[i].count);
            if ((count++) % 6 == 0)
                fprintf(fd,"\n");
        }

        count = 1;
        for (i = 0; i < 24; i++) {
            fprintf(fd, "MCS[%d]: %llu  ", i, ns->ns_rx_mcs_count[i]);
            if ((count++) % 8 == 0)
                fprintf(fd,"\n");
        }
            
        count = 1;
        fprintf(fd, "\n*****  TX   data    Rate  statistics *****\n");
        for (i = 0; i < 12; i++) {
           fprintf(fd, "%dM: %llu  ", 
                          ns->ns_tx_rate_index[i].dot11Rate/2, ns->ns_tx_rate_index[i].count);
           if ((count++) % 6 == 0)
                fprintf(fd,"\n");
        }

        count = 1;
        for (i = 0; i < 24; i++) {
            fprintf(fd, "MCS[%d]: %llu  ", i, ns->ns_tx_mcs_count[i]);
            if ((count++) % 8 == 0)
                fprintf(fd, "\n");
        }
        fprintf(fd, "\n");
    }
	/* Autelan-End: zhaoyang1 transplants statistics 2015-01-27 */
#undef STAT
#undef STAT64
}
/* Autelan-Begin: zhaoyang1 transplants statistics 2015-01-27 */
 static struct ieee80211_mac_stats *
 data_statistic(struct ieee80211_mac_stats *total,struct ieee80211_mac_stats * mstats,int is_unicast)
{
	struct ieee80211_mac_stats *unicast = NULL;
	struct ieee80211_mac_stats *multicast = NULL;
	struct ieee80211_mac_stats *braodcast = NULL;
	if(is_unicast == 1) {
		unicast = mstats;
		total->ims_rx_packets += unicast->ims_rx_packets;
		total->ims_rx_bytes   += unicast->ims_rx_bytes; 

		total->ims_tx_packets += unicast->ims_tx_packets;
		total->ims_tx_bytes   += unicast->ims_tx_bytes; 

        total->ims_rx_retry_packets += unicast->ims_rx_retry_packets;
        total->ims_rx_retry_bytes += unicast->ims_rx_retry_bytes;

        total->ims_tx_retry_packets += unicast->ims_tx_retry_packets;
        total->ims_tx_retry_bytes += unicast->ims_tx_retry_bytes;
		
	}
	if(is_unicast == 0) {
		multicast = mstats;
		total->ims_rx_packets += multicast->ims_rx_packets;
		total->ims_rx_bytes   += multicast->ims_rx_bytes; 

		total->ims_tx_packets += multicast->ims_tx_packets;
		total->ims_tx_bytes   += multicast->ims_tx_bytes; 

        total->ims_rx_retry_packets += multicast->ims_rx_retry_packets;
        total->ims_rx_retry_bytes += multicast->ims_rx_retry_bytes;

        total->ims_tx_retry_packets += multicast->ims_tx_retry_packets;
        total->ims_tx_retry_bytes += multicast->ims_tx_retry_bytes;
		
	}
	return total;
}

static void
print_mstats(struct ieee80211_mac_stats *mstats)
{

    printf("******      Total    statistics    ******\n");
    printf("tx_packets = %llu,\ttx_bytes = %llu\n",mstats->ims_tx_packets,mstats->ims_tx_bytes);
    printf("tx_retry_packets = %llu,\ttx_retry_bytes = %llu\n",mstats->ims_tx_retry_packets,mstats->ims_tx_retry_bytes);
	printf("rx_packets = %llu,\trx_bytes = %llu\n",mstats->ims_rx_packets,mstats->ims_rx_bytes);
    printf("rx_retry_packets = %llu,\trx_retry_bytes = %llu\n",mstats->ims_rx_retry_packets,mstats->ims_rx_retry_bytes);
    
}
/* Autelan-End: zhaoyang1 transplants statistics 2015-01-27 */

int
main(int argc, char *argv[])
{
	int c, len;
	struct ieee80211req_sta_info *si;
	u_int8_t buf[24*1024], *cp;
	struct iwreq iwr;
	int allnodes = 0;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		err(1, "socket");
	strncpy(ifr.ifr_name, "ath0", sizeof (ifr.ifr_name));
	while ((c = getopt(argc, argv, "ai:")) != -1)
		switch (c) {
		case 'a':
			allnodes++;
			break;
		case 'i':
			strncpy(ifr.ifr_name, optarg, sizeof (ifr.ifr_name));
            ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
			break;
		default:
			errx(1, "usage: %s [-a] [-i device] [mac...]\n");
			/*NOTREACHED*/
		}

	if (argc == optind && !allnodes) {
		struct ieee80211_stats *stats;

		struct ieee80211_mac_stats *total = NULL;
		/* no args, just show global stats */
        /* fetch both ieee80211_stats, and mac_stats, including multicast and unicast stats */
		//zhaoyang1 transplants statistics 2015-01-27
        stats = malloc(sizeof(struct ieee80211_stats)+ 3* sizeof(struct ieee80211_mac_stats));
		memset(stats,0,(sizeof(struct ieee80211_stats)+ 3* sizeof(struct ieee80211_mac_stats)));
		total = malloc(sizeof(struct ieee80211_mac_stats));
		memset(total,0,sizeof(struct ieee80211_mac_stats));
        if (!stats) {
            fprintf (stderr, "Unable to allocate memory for stats\n");
            return -1;
        }
		ifr.ifr_data = (caddr_t) stats;
		if (ioctl(s, SIOCG80211STATS, &ifr) < 0)
			err(1, ifr.ifr_name);
		printstats(stdout, stats);
        /* MAC stats uses, u_int64_t, there is a 8 byte hole in between stats and mac stats, 
         * account for that.
         */
		//zhaoyang1 transplants statistics 2015-01-27
		data_statistic(total, (struct ieee80211_mac_stats*)(((void*)stats)+sizeof(*stats)),1);
		data_statistic(total, &((struct ieee80211_mac_stats*)(((void*)stats)+sizeof(*stats)))[1],0);
		print_mstats(total); 
	    free(total);  
        /* Unicast stats*/
        print_mac_stats(stdout, (struct ieee80211_mac_stats*)(((void*)stats)+sizeof(*stats)), 1); 
        /* multicast stats */
        print_mac_stats(stdout, &((struct ieee80211_mac_stats *)(((void*)stats)+sizeof(*stats)))[1], 0);
  /*AUTELAN-End:zhaoenjuan modified for _U64(32->64)*/                  
        free(stats);
		return 0;
	}
	if (allnodes) {
		/*
		 * Retrieve station/neighbor table and print stats for each.
		 */
		(void) memset(&iwr, 0, sizeof(iwr));
		(void) strncpy(iwr.ifr_name, ifr.ifr_name, sizeof(iwr.ifr_name));
        iwr.ifr_name[sizeof(iwr.ifr_name) - 1] = '\0';
		iwr.u.data.pointer = (void *) buf;
		iwr.u.data.length = sizeof(buf);
		if (ioctl(s, IEEE80211_IOCTL_STA_INFO, &iwr) < 0)
			err(1, "unable to get station information");
		len = iwr.u.data.length;
		if (len >= sizeof(struct ieee80211req_sta_info)) {
			cp = buf;
			do {
				si = (struct ieee80211req_sta_info *) cp;
				print_sta_stats(stdout, si->isi_macaddr);
				cp += si->isi_len, len -= si->isi_len;
			} while (len >= sizeof(struct ieee80211req_sta_info));
		}
	} else {
		/*
		 * Print stats for specified stations.
		 */
		for (c = optind; c < argc; c++) {
			const struct ether_addr *ea = ether_aton(argv[c]);
			if (ea != NULL)
				print_sta_stats(stdout, ea->ether_addr_octet);
		}
	}
}
