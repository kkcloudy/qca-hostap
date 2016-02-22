/*
*pengdecai add this file for process vap parameter in 11ac code 
*
*/
#include <ieee80211_var.h>
#include <ol_if_athvar.h>
#include <ieee80211_smart_ant_api.h>
#include <ol_txrx_types.h>
#include "ol_tx_desc.h"

/*Begin:pengdecai @ record rssi states for vap_rssi and ni_rssi for 11ac*/
int ol_rx_rssi_statistics(struct ol_txrx_peer_t * peer, u_int16_t npackets, u_int8_t rssi)
{
	struct ol_txrx_vdev_t *vdev = NULL;
	struct ieee80211vap *vap = NULL;
	struct ieee80211_node *ni = NULL;
	int status = -1;
	int level = 0, index  = 0;

	struct ol_ath_softc_net80211 *scn =
	    (struct ol_ath_softc_net80211 *)peer->vdev->pdev->ctrl_pdev;

	vap = ol_ath_vap_get(scn, peer->vdev->vdev_id);
	if(!vap)
	    return status;

	ni = ieee80211_find_node(&vap->iv_ic->ic_sta,peer->mac_addr.raw);

	/*
	index   level range (unit:dBm)
	0	    > -10
	1	    -10  ~ -19
	2	    -20  ~ -39
	3	    -40  ~ -49
	4	    -50  ~ -59
	5	    -60  ~ -64
	6	    -65  ~ -67
	7	    -68  ~ -70
	8	    -71  ~ -73
	9	    -74  ~ -76
	10	    -77  ~ -79
	11	    -80  ~ -82
	12	    -83  ~ -85
	13	    -86  ~ -88
	14	    -89  ~ -91
	15	    -92  ~ -94
	16	     < -94
	e.g.-19 : level >= -19 && level <= -10
	*/

	level = -95 + rssi;
	if (level > -10)
		index = 0;
	else if (level >= -19)
		index = 1;
	else if (level >= -39)
		index = 2;
	else if (level >= -49)
		index = 3;
	else if (level >= -59)
		index = 4;
	else if (level >= -64)
		index = 5;
	else if (level >= -67)
		index = 6;
	else if (level >= -70)
		index = 7;
	else if (level >= -73)
		index = 8;
	else if (level >= -76)
		index = 9;
	else if (level >= -79)
		index = 10;
	else if (level >= -82)
		index = 11;
	else if (level >= -85)
		index = 12;
	else if (level >= -88)
		index = 13;
	else if (level >= -91)
		index = 14;
	else if (level >= -94)
		index = 15;
	else 
		index = 16;
	
    vap->iv_stats.is_rssi_stats[index].ns_rx_data += npackets;
	   
    if (ni) {
        ni->ni_stats.ns_rssi_stats[index].ns_rx_data += npackets;
        ieee80211_free_node(ni);		
    }
    status = 0;
    return status;
}
/*End:pengdecai @ record rssi states for vap_rssi and ni_rssi for 11ac*/

/*Autelan-Added-Begin:pengdecai for 11ac station timeout*/
int ol_node_activity(struct ol_txrx_peer_t *peer)
{
	int status = 0;
    struct ieee80211vap *vap = NULL;
    struct ieee80211_node *ni = NULL;
	
    struct ol_ath_softc_net80211 *scn =
        (struct ol_ath_softc_net80211 *)peer->vdev->pdev->ctrl_pdev;

    vap = ol_ath_vap_get(scn, peer->vdev->vdev_id);
    if(!vap)
        return status;
    ni = ieee80211_find_node(&vap->iv_ic->ic_sta,
            peer->mac_addr.raw);

    if (ni) {
        ni->ni_inact = ni->ni_inact_reload;
        ieee80211_free_node(ni);
    }
    return status;
}
/*Autelan-Added-End:pengdecai for 11ac station timeout*/







