/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

/*
 Air Time Fairness module
*/
#if QCA_AIRTIME_FAIRNESS

#include <ieee80211_var.h>
#include "airtime_fairness_priv.h"
#include <ieee80211_ioctl.h>  /* for ieee80211req_athdbg */
#include "ieee80211_airtime_fairness.h"
#include "if_athvar.h"

/* Definition */
#define IEEE80211_INVALID_MAC(addr) \
    ((!addr[0]) && (!addr[1]) && (!addr[2]) && \
     (!addr[3]) && (!addr[4]) && (!addr[5]))

/* forward declaration */
static OS_TIMER_FUNC(wlan_atf_token_allocate_timeout_handler);

/* declaration */
#if QCA_AIRTIME_FAIRNESS
unsigned int atf_mode = 0;
module_param(atf_mode, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(atf_mode,
                "Do ATF Mode Configuration");
EXPORT_SYMBOL(atf_mode);

unsigned int atf_msdu_desc = 0;
module_param(atf_msdu_desc, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(atf_msdu_desc,
                "Controls MSDU desc in ATF Mode");
EXPORT_SYMBOL(atf_msdu_desc);

unsigned int atf_peers = 0;
module_param(atf_peers, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(atf_peers,
                "Controls peers in ATF mode");
EXPORT_SYMBOL(atf_peers);

unsigned int atf_max_vdevs = 0;
module_param(atf_max_vdevs, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(atf_max_vdevs,
                "Controls max vdevs in ATF mode");
EXPORT_SYMBOL(atf_max_vdevs);

#endif

/**
 * @brief For every entry in the atf structure, find the corresponding node & update the
    per node atf_unit.
 *
 * @param [in] ic  the handle to the radio
 *
 * @return true if handle is valid; otherwise false
 */
int
update_atf_nodetable(struct ieee80211com *ic)
{
    struct     ieee80211_node *ni = NULL;
    int32_t i;

    /* For each entry in atfcfg structure, find corresponding entry in the node table */
    if(ic->atfcfg_set.peer_num_cal != 0)
    {
        for (i = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++)
        {
            if((ic->atfcfg_set.peer_id[i].index_vap != 0)&&(ic->atfcfg_set.peer_id[i].sta_assoc_status == 1))
            {
                ni = ieee80211_find_node(&ic->ic_sta, ic->atfcfg_set.peer_id[i].sta_mac);
                if(ni == NULL) {
                    continue;
                } else {
                    /* Update atf_units in the node table entry */
                    ni->atf_units =  ic->atfcfg_set.peer_id[i].sta_cal_value;

                    /* Mark atf capable clients - if there is a corresponding VAP entry
                       Peers without corresponding VAP entry is considered as non-atf clients*/
                    if(ic->ic_atf_maxclient)
                    {
                        if(ic->atfcfg_set.peer_id[i].index_vap !=0xFF)
                        {
                            ni->ni_atfcapable = 1;
                        } else {
                            ni->ni_atfcapable = 0;
                        }
                    } else {
                            ni->ni_atfcapable = 1;
                    }

                    ieee80211_free_node(ni);
                }
            }
        }
    }
    return EOK;
}

/**
 * @brief Derive txtokens based on the airtime assigned for the node.
 *
 * @param [in] node table, airtime, token distribution timer interval.
 *
 * @return None
 */
static u_int32_t ieee80211_atf_compute_txtokens(struct ieee80211com *ic,
                               u_int32_t atf_units, u_int32_t token_interval_ms)
{
    u_int32_t tx_tokens;

    if (!atf_units) {
        return 0;
    }

    if (ic->ic_atf_sched & IEEE80211_ATF_SCHED_OBSS) {
        /* If OBSS scheduling is enabled, use the actual availabe tokens */
        token_interval_ms = ic->atf_avail_tokens;
    }

    /* if token interval is 1 sec & atf_units assigned is 100 %,
       tx_tokens = 1000000
     */
    tx_tokens = token_interval_ms * 1000; /* Convert total token time to uses. */
    /* Derive tx_tokens for this peer, w.r.t. ATF denomination and scheduler token_units */
    tx_tokens = (atf_units * tx_tokens) / WMI_ATF_DENOMINATION;
    return tx_tokens;
}

/**
 * @brief Check if the peer if valid
 *
 * @param [in] node table
 *
 * @return node table entry
 */
struct ieee80211_node *ieee80211_atf_valid_peer(struct ieee80211_node *ni)
{
    /* uninitialized peer */
    if( IEEE80211_INVALID_MAC(ni->ni_macaddr) ) {
        goto peer_invalid;
    }

    /* skip peers that aren't attached to a VDEV */
    if( ni->ni_vap == NULL ) {
        goto peer_invalid;
    }

    /* skip non-AP vdevs */
    if( ni->ni_vap->iv_opmode != IEEE80211_M_HOSTAP ) {
        goto peer_invalid;
    }

    /* skip NAWDS-AP vdevs */

    /* skip AP BSS peer */
    if( ni == ni->ni_bss_node ) {
        goto peer_invalid;
    }

    return ni;

peer_invalid:
    return NULL;
}

static u_int32_t ieee80211_atf_avail_tokens(struct ieee80211com *ic)
{
  u_int8_t ctlrxc, extrxc, rfcnt, tfcnt, obss;
  u_int32_t avail = ATF_TOKEN_INTVL_MS;

  /* get individual percentages */
  ctlrxc = ic->ic_atf_chbusy & 0xff;
  extrxc = (ic->ic_atf_chbusy & 0xff00) >> 8;
  rfcnt = (ic->ic_atf_chbusy & 0xff0000) >> 16;
  tfcnt = (ic->ic_atf_chbusy & 0xff000000) >> 24;

  if ((ctlrxc == 255) || (extrxc == 255) || (rfcnt == 255) || (tfcnt == 255))
    return ic->atf_avail_tokens;

  if (ic->ic_curchan->ic_flags & IEEE80211_CHAN_HT20)
      obss = ctlrxc - tfcnt;
  else
      obss = (ctlrxc + extrxc) - tfcnt;

  /* availabe % is 100 minus obss usage */
  avail = (100 - obss);

  /* Add a scaling factor and calculate the tokens*/
  if (ic->atf_obss_scale) {
      avail += avail * ic->atf_obss_scale / 100;
      avail = (avail * ATF_TOKEN_INTVL_MS / 100);
  }
  else {
      avail = (avail * ATF_TOKEN_INTVL_MS / 100) + 15;
  }

  /* Keep a min of 30 tokens */
  if (avail < 30)
    avail = 30;

  return (avail < ATF_TOKEN_INTVL_MS) ? avail : ATF_TOKEN_INTVL_MS;
}

/**
 * @brief If the peer is valid, update txtokens to the lmac layer
 * Txtokens will be used for Tx scheduling
 *
 * @param [in] ic  the handle to the radio
 *
 * @return true if handle is valid; otherwise false
 */
static void ieee80211_node_iter_dist_txtokens_strictq(void *arg, struct ieee80211_node *ni)
{
    u_int32_t atf_units = 0;
    struct ieee80211com *ic = (struct ieee80211com *)arg;

    if (!ni->ni_associd)
        return;

    ic->ic_atf_capable_node(ic, ni, ni->ni_atfcapable);

    if(!ni->ni_atfcapable)
        return;

    /* Check for Valid peer*/
    if(ieee80211_atf_valid_peer(ni) == NULL) {
        IEEE80211_DPRINTF_IC(ic,
                IEEE80211_VERBOSE_NORMAL,
                IEEE80211_MSG_ATF,
                "%s invalid peer \n\r",__func__);
        /* Assign max atf units if node is AP Self node (ni->ni_bss_node)
           or if the opmode is STA
         */
        if ( (ni == ni->ni_bss_node) ||
                (ni->ni_vap->iv_opmode == IEEE80211_M_STA) )
        {
            atf_units = WMI_ATF_DENOMINATION;
        }
    }
    else {
        atf_units = ni->atf_units;
    }
    ni->ni_atf_stats.tot_contribution = 0;
    ni->ni_atf_stats.contribution = 0;
    ni->ni_atf_stats.borrow = 0;
    ni->ni_atf_stats.unused = 0;
    ni->ni_atf_stats.tokens = ni->shadow_tx_tokens;
    ni->ni_atf_stats.total = ic->ic_shadow_alloted_tx_tokens;
    ni->ni_atf_stats.timestamp = OS_GET_TIMESTAMP();
    
    ni->tx_tokens = ieee80211_atf_compute_txtokens(ic, atf_units, ATF_TOKEN_INTVL_MS);
    ni->shadow_tx_tokens = ni->tx_tokens;
    ic->ic_atf_update_node_txtoken(ic, ni, &ni->ni_atf_stats);

    ni->ni_atf_stats.tokens_common = ic->ic_txtokens_common;
    ic->ic_alloted_tx_tokens += ni->tx_tokens;

    /* Don't want to take the lock if logging to history buffer isn't enabled */
    if (ni->ni_atf_debug) {
        IEEE80211_NODE_STATE_LOCK(ni);
        /* Make sure that the history bufer didn't get freed while taking the lock */
        if (ni->ni_atf_debug) {
            ni->ni_atf_debug[ni->ni_atf_debug_id++] = ni->ni_atf_stats;
            ni->ni_atf_debug_id &= ni->ni_atf_debug_mask;
        }
        IEEE80211_NODE_STATE_UNLOCK(ni);
    }
}

/**
 * @brief Iterates through the node table.
 *        Nodes with the borrow flag set will get be alloted its share
 *        from the contributable token pool
 *
 * @param [in] arg  the handle to the radio
               ni   pointer to the node table
 *
 * @return none
 */
static void ieee80211_node_iter_dist_txtokens_fairq(void *arg, struct ieee80211_node *ni)
{
    u_int32_t contributabletokens_perclient = 0, contributabletokens_per_group = 0;
    struct ieee80211com *ic = (struct ieee80211com *)arg;
    u_int32_t i =0, num = 0;

    if ( (!ni->ni_associd) || (!ni->ni_atfcapable) )
        return;

    for (i = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++) {
        if (ic->atfcfg_set.peer_id[i].sta_assoc_status == 1) {
            num++;
        }
    }

    if( !(ic->ic_atf_sched & IEEE80211_ATF_GROUP_SCHED_POLICY) &&
        ic->atfcfg_set.grp_num_cfg )
    {
        /* Fair-queue sched across groups */
        if( !ic->atf_total_num_clients_borrow )
        {
            /* No Clients looking to borrow, distribute unassigned tokens */
            if (num)
                ni->ni_borrowedtokens = ic->atf_tokens_unassigned / num;
            else
                ni->ni_borrowedtokens = 0;

            ni->tx_tokens += ni->ni_borrowedtokens;

            /* No clients looking to borrow; Distribute contributable tokens to all clients equally */
            contributabletokens_perclient =  ic->atf_total_contributable_tokens / num;

            ni->tx_tokens += contributabletokens_perclient;
            ni->ni_atf_group->atf_contributabletokens -= contributabletokens_perclient;
            ni->ni_contributedtokens = 0;
        } else if(ni->ni_atfborrow) {
            /* For clients looking to borrow:
                Distribute any unassigned tokens (if any) equally
                Distribute tokens from global contributable pool equally */
            contributabletokens_perclient = (ic->atf_total_contributable_tokens + ic->atf_tokens_unassigned)/ ic->atf_total_num_clients_borrow;
            //Update borrowed tokens for this node.
            ni->ni_borrowedtokens = contributabletokens_perclient;
            ni->tx_tokens += contributabletokens_perclient;
        }
    } else {
        /* Strict-queue across groups or Groups not configured */
        if(!ni->ni_atf_group->atf_num_clients_borrow) {
            /* No groups looking to borrow, distribute unassigned tokens */
            if(!ic->atf_groups_borrow) {
                if (num)
                    ni->ni_borrowedtokens = ic->atf_tokens_unassigned / num;
                else
                    ni->ni_borrowedtokens = 0;
                ni->tx_tokens += ni->ni_borrowedtokens;
            }

            /* In the group, If there are'nt  clients looking to borrow,
               distribute contributable tokens to all connected clients in the group*/
            if(ni->ni_atf_group->atf_num_clients) {
                contributabletokens_perclient =  ni->ni_atf_group->atf_contributabletokens / ni->ni_atf_group->atf_num_clients;
            }

            ni->tx_tokens += contributabletokens_perclient;
            ni->ni_atf_group->atf_contributabletokens -= contributabletokens_perclient;
            ni->ni_contributedtokens = 0;
        } else if(ni->ni_atfborrow) {
            /* For nodes with 'borrow' enabled, allocate additional tokens from contributable token pool */

            /* Distribute any unassigned tokens (if any) equally to groups looking to borrow*/
            contributabletokens_per_group = ic->atf_tokens_unassigned / ic->atf_groups_borrow;
            contributabletokens_perclient = (ni->ni_atf_group->atf_contributabletokens + contributabletokens_per_group)/ni->ni_atf_group->atf_num_clients_borrow;

            //Update borrowed tokens for this node.
            ni->ni_borrowedtokens = contributabletokens_perclient;

            IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                "%s() Node : %s atf_num_clients_borrow : %d tot atf_contributabletokens %d cont per client : %d  tokens : %d --> %d  \n\r",
                __func__, ether_sprintf(ni->ni_macaddr), ni->ni_atf_group->atf_num_clients_borrow,
                ni->ni_atf_group->atf_contributabletokens, contributabletokens_perclient,
                ni->tx_tokens, (ni->tx_tokens + contributabletokens_perclient));

            ni->tx_tokens += contributabletokens_perclient;
        }
    }

    ni->shadow_tx_tokens = ni->tx_tokens;
    ic->ic_atf_update_node_txtoken(ic, ni, &ni->ni_atf_stats);
    ni->ni_atf_stats.tokens_common = ic->ic_txtokens_common;
    ic->ic_alloted_tx_tokens += ni->tx_tokens;

    /* Don't want to take the lock if logging to history buffer isn't enabled */
    if (ni->ni_atf_debug) {
        IEEE80211_NODE_STATE_LOCK(ni);
        /* Make sure that the history bufer didn't get freed while taking the lock */
        if (ni->ni_atf_debug) {
            ni->ni_atf_debug[ni->ni_atf_debug_id++] = ni->ni_atf_stats;
            ni->ni_atf_debug_id &= ni->ni_atf_debug_mask;
        }
        IEEE80211_NODE_STATE_UNLOCK(ni);
    }
}

/**
 * @brief Iterates through the node table.
 *        Identifies clients looking to borrow & contribute tokens
 *        Computes total tokens available for contribution
 *
 * @param [in] arg  the handle to the radio
               ni   pointer to the node table
 *
 * @return none
 */
static void ieee80211_node_iter_fairq_algo(void *arg, struct ieee80211_node *ni)
{
    u_int32_t atf_units = 0, weighted_unusedtokens_percent = 0, node_unusedtokens = 0;
    int32_t i = 0, j = 0, node_index = 0;
    struct ieee80211com *ic = (struct ieee80211com *)arg;
    int32_t unusedairtime_weights[ATF_DATA_LOG_SIZE] = {60, 30, 10};

    if (!ni->ni_associd)
    {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
		                     "Node(%s) not associated. Returning \n\r", ether_sprintf(ni->ni_macaddr));
        return;
    }

    ic->ic_atf_capable_node(ic, ni, ni->ni_atfcapable);

    if(!ni->ni_atfcapable)
        return;

    /* Check for Valid peer*/
    if(ieee80211_atf_valid_peer(ni) == NULL) {

        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                "%s invalid peer %s \n\r",__func__, ether_sprintf(ni->ni_macaddr));

        /* Assign max atf units if node is AP Self node (ni->ni_bss_node)
           or if the opmode is STA
         */
        if ( (ni == ni->ni_bss_node) ||
                (ni->ni_vap->iv_opmode == IEEE80211_M_STA) )
        {
            atf_units = WMI_ATF_DENOMINATION;
        }
    }
    else {
        atf_units = ni->atf_units;
    }
    /* convert user %(atf_units) to txtokens (ni->txtokens) */
    ni->tx_tokens = ieee80211_atf_compute_txtokens(ic, atf_units, ATF_TOKEN_INTVL_MS);

    /* Get unused tokens from the previous iteration */
    ic->ic_atf_get_unused_txtoken(ic, ni, &node_unusedtokens);
    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
		                "%s() - Node MAC:%s, atf_units: %d ni->tx_tokens: %d unused tokens: %d INTVL: %d\n\r",
                          __func__,ether_sprintf(ni->ni_macaddr),atf_units, ni->tx_tokens,
                            node_unusedtokens,ATF_TOKEN_INTVL_MS);

    ni->ni_atf_stats.tot_contribution = ni->ni_atf_group->shadow_atf_contributabletokens;
    ni->ni_atf_stats.contribution = ni->ni_contributedtokens;
    ni->ni_atf_stats.borrow = ni->ni_borrowedtokens;
    ni->ni_atf_stats.unused = node_unusedtokens;
    ni->ni_atf_stats.tokens = ni->shadow_tx_tokens;
    ni->ni_atf_stats.raw_tx_tokens = ni->raw_tx_tokens;
    ni->ni_atf_stats.total = ic->ic_shadow_alloted_tx_tokens;
    ni->ni_atf_stats.timestamp = OS_GET_TIMESTAMP();

    /* If atfdata history not available for the node */
    if(ni->ni_atfdata_logged < ATF_DATA_LOG_SIZE)
    {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
		    "%s - Node History not available \n\r", ether_sprintf(ni->ni_macaddr));
        if(ni->ni_atfindex)
        {
            /* tx_tokens will be zero until atfcfg_timer updates atf_units */
            if( (node_unusedtokens <= ni->raw_tx_tokens) && (ni->raw_tx_tokens) )
            {
                ni->ni_unusedtokenpercent[ni->ni_atfindex -1 ] = ((node_unusedtokens/ni->raw_tx_tokens) * 100);
            }
            else
            {
                ni->ni_unusedtokenpercent[ni->ni_atfindex -1 ] = 0;
            }
        }

        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
		    "(node %s) atfdata_logged : %d ni_atfindex : %d \n\r",
                ether_sprintf(ni->ni_macaddr), ni->ni_atfdata_logged, ni->ni_atfindex);
        ni->ni_atfdata_logged++;
        ni->ni_atfindex++;

        if (ni->ni_atfindex >= ATF_DATA_LOG_SIZE)
        {
            IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
		        "%s ni_atfindex > %d . reset to 0 \n\r",ether_sprintf(ni->ni_macaddr), ATF_DATA_LOG_SIZE);
            ni->ni_atfindex = 0;
        }
        return;
    }

    /*  Compute unused tokens.
        If this node had borrowed tokens in the previous iteration,
        do not account borrowed tokens in unusedtoken compuation.
     */
    if(ni->ni_atfborrow)
    {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
		                    "%s -  Borrow set  : unused : %d borrowed : %d\n\r",
                            ether_sprintf(ni->ni_macaddr), node_unusedtokens,
                            ni->ni_borrowedtokens);
        node_unusedtokens = (node_unusedtokens > ni->ni_borrowedtokens) ? (node_unusedtokens - ni->ni_borrowedtokens): 0;
    }

    switch(ni->ni_atfindex)
    {
        case 0:
            node_index = (ATF_DATA_LOG_SIZE - 1);
            break;
        case ATF_DATA_LOG_SIZE:
            node_index = 0;
            break;
        default:
            node_index = (ni->ni_atfindex - 1);
    }

    /* Update unused token percentage */
    /* tx_tokens will be zero until atfcfg_timer updates atf_units */
    if( (node_unusedtokens <= (ni->raw_tx_tokens - ni->ni_contributedtokens)) && (ni->raw_tx_tokens) )
    {
        ni->ni_unusedtokenpercent[ node_index ] =
                ((node_unusedtokens * 100)/ (ni->raw_tx_tokens - ni->ni_contributedtokens));
    }
    else
    {
        ni->ni_unusedtokenpercent[ node_index ] = 0;
    }
    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
	                    "%s - unusedtoken percent[%d]: %d \n\r",
                        ether_sprintf(ni->ni_macaddr), (node_index),
                        ni->ni_unusedtokenpercent[node_index]);

    /* Calculate avg unused tokens */
    for(j = node_index, i =0 ; i < ATF_DATA_LOG_SIZE; i++)
    {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                             "i: %d index : %d weight : %d , unusedtokenpercent : %d weighted_cal : %d \n\r",
                              i, j, unusedairtime_weights[i], ni->ni_unusedtokenpercent[j],
                              ((ni->ni_unusedtokenpercent[j] * unusedairtime_weights[i]) / 100) );
        weighted_unusedtokens_percent += ((ni->ni_unusedtokenpercent[j] * unusedairtime_weights[i]) / 100);
        j++;
        if (j == ATF_DATA_LOG_SIZE)
        {
            j = 0;
        }
    }
    ni->ni_contributedtokens = 0;
    ni->raw_tx_tokens = ni->tx_tokens;
    ni->ni_atf_stats.weighted_unusedtokens_percent = weighted_unusedtokens_percent;

    if(weighted_unusedtokens_percent > ATF_UNUSEDTOKENS_CONTRIBUTE_THRESHOLD)
    {
        /* Compute the node tokens that can be contributed and deduct it from node tokens */
        ni->ni_atfborrow = 0;
        ni->ni_atf_group->atf_num_clients++;
        /* tx_tokens will be zero until atfcfg_timer updates atf_units */
        if(ni->tx_tokens)
        {
            ni->ni_contributedtokens = ( ((weighted_unusedtokens_percent - ATF_RESERVERD_TOKEN_PERCENT) * ni->tx_tokens) / 100 );
            ni->tx_tokens -= ni->ni_contributedtokens;

            /* set a lower threshold for ni->tx_tokens */
            if (ni->tx_tokens < (ATF_RESERVERD_TOKEN_PERCENT * ATF_TOKEN_INTVL_MS * 10) && ic->ic_node_buf_held(ni)) { /* 2% of airtime */
                u_int32_t compensation = (ATF_RESERVERD_TOKEN_PERCENT * ATF_TOKEN_INTVL_MS * 10) - ni->tx_tokens;
                /* can compensate back upto a max of what the node was contributing */
                if (compensation > ni->ni_contributedtokens)
                    compensation = ni->ni_contributedtokens;
                ni->tx_tokens += compensation;
                ni->ni_contributedtokens -= compensation;
            }
        }
        else
        {
             ni->ni_contributedtokens = ni->tx_tokens = 0;
        }
        ni->ni_atf_group->atf_contributabletokens += ni->ni_contributedtokens;
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                            "%s, Tokens to contribute : %d total_contributable tokens : %d tx_tokens : %d\n\r",
                            ether_sprintf(ni->ni_macaddr), ni->ni_contributedtokens,
                            ni->ni_atf_group->atf_contributabletokens, ni->tx_tokens);
    }
    else
    {
        /* If average unused tokens percentage is less than a min threshold, set borrow flag */
        ni->ni_atfborrow = 1;

        ni->ni_atf_group->atf_num_clients_borrow++;
        ni->ni_atf_group->atf_num_clients++;
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ATF,
                             "Node MAC:%s, borrow enabled! atf_num_clients_borrow : %d tx_tokens : %d \n\r",
                             ether_sprintf(ni->ni_macaddr), ni->ni_atf_group->atf_num_clients_borrow, ni->tx_tokens);
    }

    /* Increment node index */
    ni->ni_atfindex++;
    if (ni->ni_atfindex >= ATF_DATA_LOG_SIZE)
        ni->ni_atfindex = 0;
}

/**
 * @brief Iterate atf peer table, get the total atf_units alloted.
 *        convert unalloted atf_units to tokens and add to the
 *        contributable token pool
 * @param [in] ic  the handle to the radio
 *
 * @return unalloted tokens
 */
u_int32_t ieee80211_atf_airtime_unassigned(struct ieee80211com *ic)
{
    u_int32_t i = 0, airtime_assigned = 0, airtime_unassigned = 0;

    if(ic->atfcfg_set.grp_num_cfg)
    {
        for (i = 0; i < ic->atfcfg_set.grp_num_cfg; i++) {
            airtime_assigned += ic->atfcfg_set.atfgroup[i].grp_cfg_value;
        }
    } else if (ic->atfcfg_set.vap_num_cfg) {
        for (i = 0; i < ic->atfcfg_set.vap_num_cfg; i++) {
            airtime_assigned += ic->atfcfg_set.vap[i].vap_cfg_value;
        }
    } else {
        for (i = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++) {
            if (ic->atfcfg_set.peer_id[i].sta_assoc_status == 1)
                airtime_assigned += ic->atfcfg_set.peer_id[i].sta_cal_value;
        }
    }

    airtime_unassigned = WMI_ATF_DENOMINATION - airtime_assigned;

    return airtime_unassigned;
}


/**
 * @brief Timer that Iterates the node table & distribute tokens
 *  atf_units is updated in node table by update_atf_nodetable routine
 *
 * @param [in] ic  the handle to the radio
 *
 * @return true if handle is valid; otherwise false
 */
static OS_TIMER_FUNC(wlan_atf_token_allocate_timeout_handler)
{
    struct ieee80211com *ic;
    struct ath_softc_net80211 *scn;
    u_int32_t airtime_unassigned = 0;
    u_int32_t txtokens_unassigned = 0, group_noclients_txtokens = 0;
    struct group_list *tmpgroup = NULL;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    scn = ATH_SOFTC_NET80211(ic);

    /* Calculate 'Unassigned airtime' (1000 - Total configured airtime for VAPS)
       & update lmac layer */
    airtime_unassigned = ieee80211_atf_airtime_unassigned(ic);
    txtokens_unassigned = ieee80211_atf_compute_txtokens(ic, airtime_unassigned, ATF_TOKEN_INTVL_MS);

    /* Is OBSS scheduling enabled */
    if (ic->ic_atf_sched & IEEE80211_ATF_SCHED_OBSS) {
        /* get the channel busy stats percentage */
        ic->ic_atf_chbusy = scn->sc_ops->get_chbusyper(scn->sc_dev);
        /* calculate the actual available tokens based on channel busy percentage */
        ic->atf_avail_tokens = ieee80211_atf_avail_tokens(ic);
    } else {
        /* Just use the total tokens */
      ic->atf_avail_tokens = ATF_TOKEN_INTVL_MS;
    }

    if (ic->ic_atf_sched & IEEE80211_ATF_SCHED_STRICT) {
        /* ATF - strictq algorithm
           Parse Node table , Derive txtokens & update node structure
         */
        ic->ic_alloted_tx_tokens = 0;

        if (ic->ic_atf_maxclient && (ic->ic_sta_assoc > ATF_ACTIVED_MAX_CLIENTS))
            ic->ic_atf_tokens_unassigned(ic, txtokens_unassigned);

        ieee80211_iterate_node(ic, ieee80211_node_iter_dist_txtokens_strictq, ic);

        if (ic->ic_atf_maxclient && (ic->ic_sta_assoc > ATF_ACTIVED_MAX_CLIENTS)) {
            ic->ic_alloted_tx_tokens += txtokens_unassigned;
            ic->ic_txtokens_common = txtokens_unassigned;
         } else
            ic->ic_txtokens_common = 0;
        ic->ic_shadow_alloted_tx_tokens = ic->ic_alloted_tx_tokens;
    } else {
        /* ATF - fairq alogrithm */

        /* Reset the atf_ic variables at the start*/
        ic->atf_groups_borrow = 0;  // set if there are clients looking to borrow
        /* Parse through the group list and reset variables */
        TAILQ_FOREACH(tmpgroup, &ic->ic_atfgroups, group_next) {
            tmpgroup->shadow_atf_contributabletokens = tmpgroup->atf_contributabletokens;
            tmpgroup->atf_num_clients_borrow = 0;
            tmpgroup->atf_num_clients = 0;
            tmpgroup->atf_contributabletokens = 0;
        }

        /* Loop1 : Iterates through node table,
                   Identifies clients looking to borrow & Contribute tokens
                   Computes total tokens available for contribution
         */
        ieee80211_iterate_node(ic, ieee80211_node_iter_fairq_algo, ic);

        ic->atf_total_num_clients_borrow = 0;
        ic->atf_total_contributable_tokens = 0;
        /* Loop through the group list & find number of groups looking to borrow */
        TAILQ_FOREACH(tmpgroup, &ic->ic_atfgroups, group_next) {
            if( !(ic->ic_atf_sched & IEEE80211_ATF_GROUP_SCHED_POLICY) &&
                ic->atfcfg_set.grp_num_cfg )
            {
                ic->atf_total_num_clients_borrow += tmpgroup->atf_num_clients_borrow;
                ic->atf_total_contributable_tokens += tmpgroup->atf_contributabletokens;

                /* If there aren't any clients in the group, add group's airtime
                   to the common contributable pool */
                if( !tmpgroup->atf_num_clients)
                {
                    group_noclients_txtokens = ieee80211_atf_compute_txtokens(ic, tmpgroup->group_airtime, ATF_TOKEN_INTVL_MS);
                    ic->atf_total_contributable_tokens += (group_noclients_txtokens - ( (ATF_RESERVERD_TOKEN_PERCENT * group_noclients_txtokens) / 100) );
                }
            }

            if( tmpgroup->atf_num_clients_borrow ) {
                ic->atf_groups_borrow++;
            }
        }

        /* If max client support is enabled & if the total number of clients
           exceeds the number supported in ATF, do not contribute unalloted tokens.
           Unalloted tokens will be used by non-atf capable clients */
        if (ic->ic_atf_maxclient && (ic->ic_sta_assoc > ATF_ACTIVED_MAX_CLIENTS)) {
            ic->ic_atf_tokens_unassigned(ic, txtokens_unassigned);
            /* With Maxclient feature enabled, unassigned tokens are used by non-atf clients
               Hence, do not add unassigned tokens to node tokens */
            ic->atf_tokens_unassigned = 0;
        } else {
            /* Add unassigned tokens to the contributable token pool*/
            if (txtokens_unassigned) {
                txtokens_unassigned -= ((ATF_RESERVED_UNALLOTED_TOKEN_PERCENT * txtokens_unassigned) / 100);
            }
            /* Unassigned tokens will be added to node tokens */
            ic->atf_tokens_unassigned = txtokens_unassigned;

        }

        /* Loop2 :  Distributes tokens
                    Nodes looking to borrow tokens will get its share
                    from the contributable token pool*/
        ic->ic_alloted_tx_tokens = 0;

        ieee80211_iterate_node(ic, ieee80211_node_iter_dist_txtokens_fairq, ic);

        if (ic->ic_atf_maxclient && (ic->ic_sta_assoc > ATF_ACTIVED_MAX_CLIENTS)) {
            ic->ic_alloted_tx_tokens += txtokens_unassigned;
            ic->ic_txtokens_common = txtokens_unassigned;
        } else
            ic->ic_txtokens_common = 0;

        ic->ic_shadow_alloted_tx_tokens = ic->ic_alloted_tx_tokens;
    }
    update_atf_nodetable(ic);

    if(ic->atf_commit)
        OS_SET_TIMER(&ic->atf_tokenalloc_timer, ATF_TOKEN_INTVL_MS);
}

void ieee80211_atf_node_join_leave(struct ieee80211_node *ni,const u_int8_t type)
{
    struct ieee80211com *ic = ni->ni_ic;
    u_int8_t  i, j;
    u_int64_t calbitmap;
    struct group_list *group = NULL;

    if(type)
    { /* Add join node */
       for (i = 0, calbitmap = 1; i < ATF_ACTIVED_MAX_CLIENTS; i++)
       {
           if (ic->atfcfg_set.peer_id[i].index_vap == 0)
           {
               /* printk("\n Join sta MAC addr:%02x:%02x:%02x:%02x:%02x:%02x \n",
                        ni->ni_macaddr[0],ni->ni_macaddr[1],ni->ni_macaddr[2],
                        ni->ni_macaddr[3],ni->ni_macaddr[4],ni->ni_macaddr[5]); */

               OS_MEMCPY((char *)(ic->atfcfg_set.peer_id[i].sta_mac),(char *)(ni->ni_macaddr),IEEE80211_ADDR_LEN);
               ic->atfcfg_set.peer_id[i].index_vap = 0xff;
               ic->atfcfg_set.peer_id[i].sta_assoc_status = 1;
               ic->atfcfg_set.peer_cal_bitmap |= (calbitmap<<i);
               break;
           } else {
               if (IEEE80211_ADDR_EQ((char *)(ic->atfcfg_set.peer_id[i].sta_mac), (char *)(ni->ni_macaddr)))
               {

                   if (ic->atfcfg_set.peer_id[i].cfg_flag)
                   {
                       ic->atfcfg_set.peer_id[i].sta_assoc_status = 1;
                       break;
                   }else
                       return;

                }
            }
        }
        if(!ic->ic_is_mode_offload(ic))
        {
            /* Point node to the default group list */
            group = TAILQ_FIRST(&ic->ic_atfgroups);
            ni->ni_atf_group = group;
        }
    } else {
        /* Remove leave node */
        for (i = 0, j = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++)
        {
            if (ic->atfcfg_set.peer_id[i].index_vap != 0)
                j = i;
        }
        for (i = 0, calbitmap = 1; i < ATF_ACTIVED_MAX_CLIENTS; i++)
       {
           if ((ic->atfcfg_set.peer_id[i].index_vap != 0)&&
               (IEEE80211_ADDR_EQ((char *)(ic->atfcfg_set.peer_id[i].sta_mac), (char *)(ni->ni_macaddr))))
           {
              /* printk("Leave sta MAC addr:%02x:%02x:%02x:%02x:%02x:%02x \n",
                        ni->ni_macaddr[0],ni->ni_macaddr[1],ni->ni_macaddr[2],
                        ni->ni_macaddr[3],ni->ni_macaddr[4],ni->ni_macaddr[5]); */

               if(j != i)
               {
                   if (ic->atfcfg_set.peer_id[i].cfg_flag)
                   {
                       /*ic->atfcfg_set.peer_num_cfg--;*/
                       ic->atfcfg_set.peer_id[i].index_vap = 0xff;
                       ic->atfcfg_set.peer_id[i].sta_cal_value = 0;
                       ic->atfcfg_set.peer_id[i].sta_assoc_status = 0;
                   }else{
                       ic->atfcfg_set.peer_id[i].cfg_flag = ic->atfcfg_set.peer_id[j].cfg_flag;
                       ic->atfcfg_set.peer_id[i].sta_cfg_mark = ic->atfcfg_set.peer_id[j].sta_cfg_mark;
                       ic->atfcfg_set.peer_id[i].sta_cfg_value = ic->atfcfg_set.peer_id[j].sta_cfg_value;
                       ic->atfcfg_set.peer_id[i].index_vap = ic->atfcfg_set.peer_id[j].index_vap;
                       ic->atfcfg_set.peer_id[i].sta_cal_value = ic->atfcfg_set.peer_id[j].sta_cal_value;
                       ic->atfcfg_set.peer_id[i].sta_assoc_status = ic->atfcfg_set.peer_id[j].sta_assoc_status;
                       OS_MEMCPY((char *)(ic->atfcfg_set.peer_id[i].sta_mac),(char *)(ic->atfcfg_set.peer_id[j].sta_mac),IEEE80211_ADDR_LEN);
                       ic->atfcfg_set.peer_id[i].index_group = ic->atfcfg_set.peer_id[j].index_group;

                       ic->atfcfg_set.peer_id[j].cfg_flag = 0;
                       ic->atfcfg_set.peer_id[j].sta_cfg_mark = 0;
                       ic->atfcfg_set.peer_id[j].sta_cfg_value = 0;
                       memset(&(ic->atfcfg_set.peer_id[j].sta_mac[0]),0,IEEE80211_ADDR_LEN);
                       ic->atfcfg_set.peer_id[j].index_vap = 0;
                       ic->atfcfg_set.peer_id[j].sta_cal_value = 0;
                       ic->atfcfg_set.peer_id[j].sta_assoc_status = 0;
                       ic->atfcfg_set.peer_cal_bitmap &= ~(calbitmap<<j);
                       ic->atfcfg_set.peer_id[j].index_group = 0;
                   }
                   break;
               }else{
                   if (ic->atfcfg_set.peer_id[i].cfg_flag)
                   {
                       ic->atfcfg_set.peer_id[i].index_vap = 0xff;
                   }else{
                       memset(&(ic->atfcfg_set.peer_id[i].sta_mac[0]),0,IEEE80211_ADDR_LEN);
                       ic->atfcfg_set.peer_id[i].index_vap = 0;
                       ic->atfcfg_set.peer_id[i].index_group = 0;
                       ic->atfcfg_set.peer_cal_bitmap &= ~(calbitmap<<i);
                   }
                   ic->atfcfg_set.peer_id[i].sta_cal_value = 0;
                   ic->atfcfg_set.peer_id[i].sta_assoc_status = 0;
                   break;
               }
           }
       }
    }
    if ( i == ATF_ACTIVED_MAX_CLIENTS)
    {
        /* printk("ieee80211_atf_node_join_leave-- Either join or leave failed!! \n"); */
        return;
    }
    /* Wake up timer to update alloc table*/
    spin_lock(&ic->atf_lock);
    if((ic->atf_fmcap)&&(ic->atf_mode))
    {
        if (ic->atf_tasksched == 0)
        {
            ic->atf_tasksched = 1;
            ic->atf_vap_handler = ni->ni_vap;
            OS_SET_TIMER(&ic->atfcfg_timer, IEEE80211_ATF_WAIT*1000);
        } else {
            /*printk("\n delay some secs, come back again??\n");*/
        }
    }
    spin_unlock(&ic->atf_lock);

}

/**
  * @brief function to send the atf table which has to be sent down to the Firmware
  *
  * @param ic the handle to the radio
  *
  * @return true if handle is valid; otherwise false
  */
    int
build_atf_for_fm(struct ieee80211com *ic)
{
    struct     wmi_pdev_atf_req  *wmi_req = &(ic->wmi_atfreq);
    struct     wmi_pdev_atf_peer_ext_request *wmi_peer_ext_req = &(ic->wmi_atf_peer_req);
    struct     wmi_pdev_atf_ssid_group_req *wmi_group_req = &(ic->wmi_atf_group_req);
    int32_t    retv = 0;
    u_int8_t   i, j;

    /*printk("build_atf_for_fm: ic->atfcfg_set.peer_num_cal=%d\n",ic->atfcfg_set.peer_num_cal);*/
    if(ic->atfcfg_set.peer_num_cal != 0)
    {
        wmi_req->percentage_uint = ic->atfcfg_set.percentage_unit;
        wmi_req->num_peers = ic->atfcfg_set.peer_num_cal;
        for (i = 0, j = 0; (i < ATF_ACTIVED_MAX_CLIENTS)&&(j < ic->atfcfg_set.peer_num_cal); i++)
        {
            if(ic->atfcfg_set.peer_id[i].sta_assoc_status == 1)
            {
                if (ic->atfcfg_set.peer_id[i].index_group == 0xff)
                    wmi_peer_ext_req->atf_peer_ext_info[j].group_index = ic->atfcfg_set.peer_id[i].index_group;
                else
                    wmi_peer_ext_req->atf_peer_ext_info[j].group_index = (ic->atfcfg_set.peer_id[i].index_group - 1); 
                wmi_peer_ext_req->atf_peer_ext_info[j].atf_units_reserved = 0xff;
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr31to0 = 0;
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr47to32 = 0;
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr31to0 |= (ic->atfcfg_set.peer_id[i].sta_mac[0] & 0xff);
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[1]<<8;
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[2]<<16;
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[3]<<24;
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr47to32 |= (ic->atfcfg_set.peer_id[i].sta_mac[4] & 0xff);
                wmi_peer_ext_req->atf_peer_ext_info[j].peer_macaddr.mac_addr47to32 |= ic->atfcfg_set.peer_id[i].sta_mac[5]<<8;

                wmi_req->atf_peer_info[j].percentage_peer = ic->atfcfg_set.peer_id[i].sta_cal_value;
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr31to0 = 0;
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr47to32 = 0;
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr31to0 |= (ic->atfcfg_set.peer_id[i].sta_mac[0] & 0xff);
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[1]<<8;
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[2]<<16;
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr31to0 |= ic->atfcfg_set.peer_id[i].sta_mac[3]<<24;
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr47to32 |= (ic->atfcfg_set.peer_id[i].sta_mac[4] & 0xff);
                wmi_req->atf_peer_info[j].peer_macaddr.mac_addr47to32 |= ic->atfcfg_set.peer_id[i].sta_mac[5]<<8;
                j++;
            }
        }
    }
    else {
        printk(" No peer in allocation table, no action to firmware!\n");
    }
    wmi_group_req->num_groups =  ic->atfcfg_set.grp_num_cfg;
    for (i = 0; (i < ATF_ACTIVED_MAX_ATFGROUPS) && (i < ic->atfcfg_set.grp_num_cfg); i++)
    {
        wmi_group_req->atf_group_info[i].percentage_group = ic->atfcfg_set.atfgroup[i].grp_cfg_value;
        wmi_group_req->atf_group_info[i].atf_group_units_reserved = 0xff;
    }

    return retv;
}

/**
 * @brief allocate memory for the atf table
 *
 * @param ic the handle to the radio
 *
 * @return true if handle is valid; otherwise false
 */

int build_atf_alloc_tbl(struct ieee80211com *ic)
{
    struct     ieee80211_node_table *nt = &ic->ic_sta;
    struct     ieee80211vap *vap = NULL;
    struct     ieee80211_node *ni;
    int32_t    retv = 0;
    u_int8_t   i,vap_index = 0, k=0;
    u_int32_t  group_index = 0;
    struct group_list *group = NULL;

    /* Peer by Peer look up vap in alloc table, then program peer table*/
    for (i = 0, ic->atfcfg_set.peer_num_cal = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++)
    {
       if((ic->atfcfg_set.peer_id[i].index_vap != 0)&&(ic->atfcfg_set.peer_id[i].sta_assoc_status == 1))
            ic->atfcfg_set.peer_num_cal++;
    }

    if (ic->atfcfg_set.percentage_unit == 0)
        ic->atfcfg_set.percentage_unit = PER_UNIT_1000;

    /* 1. Check vap is in alloc table.
       yes-->save vap (index+1) from vap table for peer table
       no--->save 0xff as vap_index for peer table.
       2. loop peer table and find match peer mac or new peer,
       put vap_index and new peer mac addr.
     */
    if(ic->atfcfg_set.peer_num_cal!= 0)
    {
        TAILQ_FOREACH(ni, &nt->nt_node, ni_list) {

            vap = ni->ni_vap;
            /*
              Search for this vap in the atfgroup table & find the group id
            */
            group_index = 0xFF;
            for (i = 0; i < ic->atfcfg_set.grp_num_cfg; i++)
            {
                for (k = 0; k < ic->atfcfg_set.atfgroup[i].grp_num_ssid; k++)
                {
                    if (strncmp(ic->atfcfg_set.atfgroup[i].grp_ssid[k], vap->iv_bss->ni_essid, IEEE80211_NWID_LEN) == 0)
                    {
                        group_index = i + 1;
                        break;
                    }
                }
            }

            for (i = 0, vap_index = 0xff; i < ic->atfcfg_set.vap_num_cfg; i++)
            {
                if (adf_os_str_cmp(ic->atfcfg_set.vap[i].essid,vap->iv_bss->ni_essid) == 0)
                {
                    vap_index = i+1;
                    break;
                }
            }

            if (ni->ni_associd != 0)
            {
                /* Fill peer alloc table */
                for (i = 0; i < ATF_ACTIVED_MAX_CLIENTS; i++)
                {
                    if(ic->atfcfg_set.peer_id[i].index_vap != 0)
                    {
                        if(OS_MEMCMP(ic->atfcfg_set.peer_id[i].sta_mac,ni->ni_macaddr,IEEE80211_ADDR_LEN) == 0)
                        {
                            ic->atfcfg_set.peer_id[i].index_vap = vap_index;

                            /* update the peer group index
                               group_index = 0xFF, if vap not part of any ATF groups
                               group_index = 1 - 32(index), if vap part of an ATF group
                             */
                            ic->atfcfg_set.peer_id[i].index_group = group_index;

                            if(!ic->ic_is_mode_offload(ic))
                            {
                                if(group_index == 0xFF)
                                {
                                    group = TAILQ_FIRST(&ic->ic_atfgroups);
                                    /* Point to the default group */
                                    ni->ni_atf_group = group;
                                } else {
                                    ni->ni_atf_group = ic->atfcfg_set.atfgroup[group_index - 1].grplist_entry;
                                }
                            }

                            if(ic->atfcfg_set.peer_id[i].sta_cfg_mark)
                                ic->atfcfg_set.peer_id[i].sta_cfg_mark = 0;

                                /* printk("build_atf_alloc_tbl--found station---suceessful!!  \n"); */
                            break;
                        } else {
                            /* printk("Continue to look up empty alloc table entry,current index entry=%d\n",i); */
                        }
                    } else {
                        if(OS_MEMCMP(vap->iv_myaddr,ni->ni_macaddr,IEEE80211_ADDR_LEN) !=0 )
                        {
                            OS_MEMCPY(&(ic->atfcfg_set.peer_id[i].sta_mac[0]),&(ni->ni_macaddr[0]),IEEE80211_ADDR_LEN);
                            ic->atfcfg_set.peer_id[i].index_vap = vap_index;

                            /* update the peer group index
                               group_index = 0xFF, if vap not part of any ATF groups
                               group_index = 1 - 32(index), if vap part of an ATF group
                             */
                            ic->atfcfg_set.peer_id[i].index_group = group_index;

                            if(!ic->ic_is_mode_offload(ic))
                            {
                                if(group_index == 0xFF)
                                {
                                    /* Point to the default group */
                                    group = TAILQ_FIRST(&ic->ic_atfgroups);
                                    ni->ni_atf_group = group;
                                } else {
                                    ni->ni_atf_group = ic->atfcfg_set.atfgroup[group_index - 1].grplist_entry;
                                }
                            }
                        }
                        break;
                    }
                }
                if(i == ATF_ACTIVED_MAX_CLIENTS)
                {
                    break;
                }
            }
        }
    } else {
        /* printk("Empty table,no para setting to pass firmware! \n"); */
        retv = -1;
    }
    return retv;
}

int
vrf_atf_cfg_value(struct ieee80211com *ic)
{
    int32_t    retv = 0;
    u_int32_t  vap_cfg_added = 0;
    u_int32_t  peer_cfg_added = 0;
    u_int8_t   vap_num = 0;
    u_int8_t   i = 0, j =0;

    vap_num = ic->atfcfg_set.vap_num_cfg;
    for (i = 0; (i< ATF_CFG_NUM_VDEV)&&(vap_num != 0); i++)
    {
        if(ic->atfcfg_set.vap[i].cfg_flag)
        {
            vap_cfg_added += ic->atfcfg_set.vap[i].vap_cfg_value;
            vap_num--;
        }
    }

    if(vap_cfg_added > ic->atfcfg_set.percentage_unit)
    {
        retv = -1;
        printk("\n VAPs configuration value assigment wrong!!\n");
        goto end_vrf_atf_cfg;
    }

    vap_num = ic->atfcfg_set.vap_num_cfg;
    for (i = 0; (i< ATF_CFG_NUM_VDEV)&&(vap_num != 0); i++)
    {
        if(ic->atfcfg_set.vap[i].cfg_flag)
        {
            vap_num--;
            peer_cfg_added = 0;
            for ( j = 0; j<ATF_ACTIVED_MAX_CLIENTS; j++)
            {
                if(ic->atfcfg_set.peer_id[j].index_vap == (i+1))
                {
                    if(ic->atfcfg_set.peer_id[j].cfg_flag)
                    {
                        peer_cfg_added += ((ic->atfcfg_set.vap[i].vap_cfg_value * ic->atfcfg_set.peer_id[j].sta_cfg_value) / ic->atfcfg_set.percentage_unit);
                    }
                }
            }

            if ( peer_cfg_added > ic->atfcfg_set.vap[i].vap_cfg_value)
            {
                printk("\n Peers configuration value assignment wrong !!! Reassign the values\n");
                retv = -1;
                goto end_vrf_atf_cfg;
            }
        }
    }

end_vrf_atf_cfg:
    return retv;
}

int
vrf_atf_peer_value(struct ieee80211com *ic)
{
    int32_t    retv = 0;
    u_int32_t  peer_cfg_added = 0;
    u_int8_t   i = 0;

    for (i=0; i<ATF_ACTIVED_MAX_CLIENTS; i++)
    {
        if(ic->atfcfg_set.peer_id[i].cfg_flag)
        {
            peer_cfg_added += ic->atfcfg_set.peer_id[i].sta_cfg_value;
        }
    }
    if(peer_cfg_added > ic->atfcfg_set.percentage_unit)
    {
        retv = -1;
        printk("\n Peers configuration value assignment wrong!!\n");
    }
    return retv;
}


/**
 * @brief calculate the percentage value and update the atf table
 *
 * @param ic the handle to the radio
 *
 * @return true if handle is valid; otherwise false
 */

int cal_atf_alloc_tbl(struct ieee80211com *ic)
{
    int32_t    retv = 0;
    u_int8_t   calcnt,stacnt,j,i = 0;
    u_int32_t  calavgval = 0;
    u_int64_t  peerbitmap,calbitmap;
    u_int32_t  per_unit = 0;
    u_int8_t   vap_num = 0, grp_num = 0;
    u_int32_t  vap_per_unit = 0;
    u_int8_t   peer_total_cnt = 0;
    u_int8_t   un_assoc_cfg_peer = 0;
    u_int8_t   peer_cfg_cnt = 0;
    u_int32_t  grp_per_unit = 0;
    struct group_list *tmpgroup = NULL;

    if (ic->atfcfg_set.grp_num_cfg) {
        if(!ic->ic_is_mode_offload(ic))
        {
            /* Parse the group list and remove any group marked for deletion */
            TAILQ_FOREACH(tmpgroup, &ic->ic_atfgroups, group_next) {
                if(tmpgroup->group_del == 1)
                {
                    TAILQ_REMOVE(&ic->ic_atfgroups, tmpgroup, group_next);
                }
            }
        }

        peer_total_cnt = ic->atfcfg_set.peer_num_cal;
        grp_num = ic->atfcfg_set.grp_num_cfg;
        per_unit = ic->atfcfg_set.percentage_unit;
        for (i = 0; (i< ATF_CFG_NUM_VDEV)&&(grp_num != 0); i++)
        {
            grp_per_unit = ic->atfcfg_set.atfgroup[i].grp_cfg_value;
            per_unit -= grp_per_unit;
            grp_num--;
            for ( j = 0, stacnt=0, peerbitmap = 0, calbitmap=1; j<ATF_ACTIVED_MAX_CLIENTS; j++)
            {
                if(ic->atfcfg_set.peer_id[j].index_group == (i+1))
                {
                    peerbitmap |= (calbitmap<<j);
                    stacnt++;
                }
            }
            if (stacnt)
            {
                calavgval = grp_per_unit/stacnt;
                for ( j = 0, calbitmap = 1; j<ATF_ACTIVED_MAX_CLIENTS; j++)
                {
                    if(peerbitmap &(calbitmap<<j))
                        ic->atfcfg_set.peer_id[j].sta_cal_value = calavgval;
                }
                peer_total_cnt -= stacnt;
            }
        } /*End of loop*/
        /*Handle left stations that do not include in config vap*/
        /*  printk("VAP host config mode--cal left sta Units stacnt=%d lefttotalcnt=%d\n",stacnt,peer_total_cnt);*/
        if(peer_total_cnt != 0)
        {
            calavgval = per_unit/peer_total_cnt;
            for ( j = 0; j<ATF_ACTIVED_MAX_CLIENTS; j++)
            {
                if (ic->atfcfg_set.peer_id[j].index_group == 0xFF)
                {
                    if (ic->atfcfg_set.peer_id[j].sta_assoc_status == 1)
                        ic->atfcfg_set.peer_id[j].sta_cal_value = calavgval;
                    else{
                        ic->atfcfg_set.peer_id[j].sta_cal_value = 0;
                        un_assoc_cfg_peer++;
                    }
                }
            }
        }
    } else if(ic->atfcfg_set.vap_num_cfg) {
        retv = vrf_atf_cfg_value(ic);
        if(retv != 0)
            goto end_cal_atf;

        peer_total_cnt = ic->atfcfg_set.peer_num_cal;
        vap_num = ic->atfcfg_set.vap_num_cfg;
        per_unit = ic->atfcfg_set.percentage_unit;
        peer_cfg_cnt = ic->atfcfg_set.peer_num_cfg;
        for (i = 0; (i< ATF_CFG_NUM_VDEV)&&(vap_num != 0); i++)
        {
            if(ic->atfcfg_set.vap[i].cfg_flag)
            {
                vap_per_unit = ic->atfcfg_set.vap[i].vap_cfg_value;
                per_unit -= vap_per_unit;
                vap_num--;
                for ( j = 0, stacnt=0, peerbitmap = 0, calbitmap=1; j<ATF_ACTIVED_MAX_CLIENTS; j++)
                {
                    if(ic->atfcfg_set.peer_id[j].index_vap == (i+1))
                    {
                        if(ic->atfcfg_set.peer_id[j].cfg_flag)
                        {
                            if (ic->atfcfg_set.peer_id[j].sta_assoc_status == 1)
                            {
                            ic->atfcfg_set.peer_id[j].sta_cal_value =
                                (ic->atfcfg_set.vap[i].vap_cfg_value*ic->atfcfg_set.peer_id[j].sta_cfg_value)/
                                ic->atfcfg_set.percentage_unit;
                            vap_per_unit -= ic->atfcfg_set.peer_id[j].sta_cal_value;
                            peer_total_cnt--;
                            }else{
                                ic->atfcfg_set.peer_id[j].sta_cal_value = 0;
                                un_assoc_cfg_peer++;
                            }
                            peer_cfg_cnt--;
                        } else {
                            peerbitmap |= (calbitmap<<j);
                            stacnt++;
                        }
                    }
                }
                if (stacnt)
                {
                    calavgval = vap_per_unit/stacnt;
                    for ( j = 0, calbitmap = 1; j<ATF_ACTIVED_MAX_CLIENTS; j++)
                    {
                        if(peerbitmap &(calbitmap<<j))
                            ic->atfcfg_set.peer_id[j].sta_cal_value = calavgval;
                    }
                    peer_total_cnt -= stacnt;
                }
            }
        } /*End of loop*/
        /*Handle left stations that do not include in config vap*/
        /* printk("VAP host config mode--cal left sta Units stacnt=%d lefttotalcnt=%d\n",stacnt,peer_total_cnt);*/
        if(peer_total_cnt != 0)
        {
            if (peer_cfg_cnt > 0)
            {
                for ( j = 0; j<ATF_ACTIVED_MAX_CLIENTS; j++)
                {
                    if ((ic->atfcfg_set.peer_id[j].index_vap == 0xff) && (ic->atfcfg_set.peer_id[j].cfg_flag == 1))
                    {
                        if (ic->atfcfg_set.peer_id[j].sta_assoc_status == 1)
                        {
                            ic->atfcfg_set.peer_id[j].sta_cal_value = (per_unit*ic->atfcfg_set.peer_id[j].sta_cfg_value)/
                                ic->atfcfg_set.percentage_unit;
                            per_unit -= ic->atfcfg_set.peer_id[j].sta_cal_value;
                            peer_total_cnt--;
                        }else{
                            ic->atfcfg_set.peer_id[j].sta_cal_value = 0;
                            un_assoc_cfg_peer++;
                        }
                        peer_cfg_cnt--;
                    }
                }
            }
            if(peer_total_cnt > 0)
            {
                calavgval = per_unit/peer_total_cnt;
                for ( j = 0; j<ATF_ACTIVED_MAX_CLIENTS; j++)
                {
                    if ((ic->atfcfg_set.peer_id[j].index_vap == 0xff)&& (ic->atfcfg_set.peer_id[j].cfg_flag == 0))
                    {
                        if (ic->atfcfg_set.peer_id[j].sta_assoc_status == 1)
                        {
                            ic->atfcfg_set.peer_id[j].sta_cal_value = calavgval;
                            peer_total_cnt--;
                        }else{
                            ic->atfcfg_set.peer_id[j].sta_cal_value = 0;
                            un_assoc_cfg_peer++;
                        }
                    }
                }
            }
        }
    } else {
        /* printk("cal_atf_alloc_tbl -- NO VAP host config mode\n"); */
        if(ic->atfcfg_set.peer_num_cfg)
        {
            retv = vrf_atf_peer_value(ic);
            if(retv != 0)
                goto end_cal_atf;
            per_unit = ic->atfcfg_set.percentage_unit;
            for (i=0, calcnt=ic->atfcfg_set.peer_num_cfg, calbitmap = 1; ((i<ATF_ACTIVED_MAX_CLIENTS)&& (calcnt!=0)); i++)
            {
                if(ic->atfcfg_set.peer_id[i].cfg_flag)
                {
                    if(ic->atfcfg_set.peer_id[i].sta_cfg_value <= per_unit )
                    {
                        if (ic->atfcfg_set.peer_id[i].sta_assoc_status == 1)
                        {
                            ic->atfcfg_set.peer_id[i].sta_cal_value = ic->atfcfg_set.peer_id[i].sta_cfg_value;
                            per_unit -=ic->atfcfg_set.peer_id[i].sta_cfg_value;
                        } else {
                            ic->atfcfg_set.peer_id[i].sta_cal_value = 0;
                            un_assoc_cfg_peer++;
                        }
                        calcnt--;
                    } else {
                        printk("Wrong input percentage value for peer!!\n");
                        retv = -1;
                        break;
                    }
                }
            }
            if (ic->atfcfg_set.peer_num_cal >= (ic->atfcfg_set.peer_num_cfg - un_assoc_cfg_peer))
            {
                calcnt = ic->atfcfg_set.peer_num_cal - (ic->atfcfg_set.peer_num_cfg - un_assoc_cfg_peer);
                if(calcnt)
                {
                    calavgval = per_unit/calcnt;
                    for (i=0, calbitmap = 1; i<ATF_ACTIVED_MAX_CLIENTS ; i++)
                    {
                        if(ic->atfcfg_set.peer_id[i].cfg_flag == 0)
                        {
                            if(ic->atfcfg_set.peer_cal_bitmap & (calbitmap<<i))
                            {
                                ic->atfcfg_set.peer_id[i].sta_cal_value = calavgval;
                                /*printk("calavgval=%d i=%d sta_cal_value=%d\n",calavgval,i,ic->atfcfg_set.peer_id[i].sta_cal_value);*/
                            }
                        }
                    }
                }
            } else {
                printk("Wrong input percentage value for peer!\n");
                retv = -1;
            }
        } else {
            if(ic->atfcfg_set.peer_num_cal)
            {
                calavgval = ic->atfcfg_set.percentage_unit/ic->atfcfg_set.peer_num_cal;
                for (i=0, calbitmap = 1; i<ATF_ACTIVED_MAX_CLIENTS; i++)
                {
                    if(ic->atfcfg_set.peer_cal_bitmap &(calbitmap<<i))
                    {
                        ic->atfcfg_set.peer_id[i].sta_cal_value = calavgval;
                    }
                }
            } else {
                printk("Empty table, no para setting to pass firmware!\n");
                retv = -1;
            }
        }
    }

end_cal_atf:
        return retv;
}

/**
 * @brief timer function to upate the atf table and calculate the percentage value
 *
 * @param atf timer
 *
 * @return true if handle is valid; otherwise false
 */

static OS_TIMER_FUNC(ieee80211_atfcfg_timer)
{
    struct ieee80211com *ic;
    int32_t   retv = 0;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    spin_lock(&ic->atf_lock);

    /*1.build atf table ic-->vap<-->ic_sta*/
    retv = build_atf_alloc_tbl(ic);
    if(retv != 0) {
        goto exit_atf_timer;
    }

    /*2.cal vpa and sta % for whole table*/
    retv = cal_atf_alloc_tbl(ic);
    if(retv != 0) {
        goto exit_atf_timer;
    }

    if(!ic->ic_is_mode_offload(ic))
    {
        retv= update_atf_nodetable(ic);
        if(retv != 0)
            goto exit_atf_timer;
    } else {
        /*3.copy contents from table to structure for fm*/
        retv = build_atf_for_fm(ic);
        if(retv != 0) {
            goto exit_atf_timer;
        }

        if(ic->atf_vap_handler != NULL) {
            ic->ic_vap_set_param(ic->atf_vap_handler,IEEE80211_ATF_OPT,1);
            ic->ic_vap_set_param(ic->atf_vap_handler,IEEE80211_ATF_PEER_REQUEST,1);
            ic->ic_vap_set_param(ic->atf_vap_handler,IEEE80211_ATF_GROUPING,1);
        }
    }

exit_atf_timer:
    ic->atf_tasksched = 0;
    spin_unlock(&ic->atf_lock);
}

static void ieee80211_node_atf_node_resume(void *arg, struct ieee80211_node *ni)
{
    struct ieee80211com *ic = (struct ieee80211com *) arg;
    if(ni)
    {
        ic->ic_atf_node_resume(ic, ni);
    }
}

/**
 * @brief function that is called during attach time to start the timer
 *
 * @param ic the handle to the radio
 *
 */
void ieee80211_atf_attach(struct ieee80211com *ic)
{
    struct group_list *group = NULL;

    spin_lock_init(&ic->atf_lock);

    if(!ic->ic_is_mode_offload(ic))
    {
        //Inter group default policy - strict sched across groups
        ic->ic_atf_sched |= IEEE80211_ATF_GROUP_SCHED_POLICY;

        /* Enable ATF by default - for DA
           ATF scheduling can be enabled/disabled using commitatf command */
        ic->atf_mode = 1;
        ic->atf_fmcap = 1;
        ic->atf_obss_scale = 0;

        /* Creating Default group */
        TAILQ_INIT(&ic->ic_atfgroups);
        group = (struct group_list *)OS_MALLOC(ic->ic_osdev, sizeof(struct group_list), GFP_KERNEL);
        strncpy(group->group_name, DEFAULT_GROUPNAME, sizeof(DEFAULT_GROUPNAME));
        group->atf_num_clients_borrow = 0;
        group->atf_num_clients = 0;
        group->atf_contributabletokens = 0;
        group->shadow_atf_contributabletokens = 0;
        TAILQ_INSERT_TAIL(&ic->ic_atfgroups, group, group_next);
    }

    /* Fair queue and OBSS scheduling enabled by default.
     * To change default behaviour to strictq, set the variable accordingly */
    ic->ic_atf_sched = 0; /* reset */
    ic->ic_atf_sched &= ~IEEE80211_ATF_SCHED_STRICT; /* disable strict queue */
    ic->ic_atf_sched |= IEEE80211_ATF_SCHED_OBSS; /* enable OBSS */

    OS_INIT_TIMER(ic->ic_osdev, &(ic->atfcfg_timer), ieee80211_atfcfg_timer, (void *) (ic));
    OS_INIT_TIMER(ic->ic_osdev, &ic->atf_tokenalloc_timer, wlan_atf_token_allocate_timeout_handler, (void *) ic);
}

int32_t ieee80211_atf_detach(struct ieee80211com *ic)
{
    spin_lock(&ic->atf_lock);
    if (ic->atf_tasksched) {
        ic->atf_tasksched = 0;
    }
    spin_unlock(&ic->atf_lock);
    OS_FREE_TIMER(&ic->atfcfg_timer);

    OS_FREE_TIMER(&ic->atf_tokenalloc_timer);
    spin_lock_destroy(&ic->atf_lock);

    printk("%s: ATF terminated\n", __func__);
    return EOK;
}

int32_t ieee80211_atf_set(struct ieee80211vap *vap, u_int8_t enable)
{

    struct ieee80211com *ic = vap->iv_ic;
    int32_t retv = EOK;

    if(!ic->ic_is_mode_offload(ic))
    {
        /* If atf_maxclient, set max client limit to IEEE80211_AID_DEF */
        if( (ic->ic_atf_maxclient) &&  (ic->ic_num_clients != IEEE80211_AID_DEF) )
        {
            retv = IEEE80211_AID_DEF;
        }

        /* if atf_maxclient is not enabled, set max client limit to IEEE80211_ATF_AID_DEF */
        if( (!ic->ic_atf_maxclient) &&  (ic->ic_num_clients != IEEE80211_ATF_AID_DEF) )
        {
            retv = IEEE80211_ATF_AID_DEF;
        }

        ic->ic_atf_set_enable(ic, enable);
    }

    ic->atf_commit = !!enable;
    if((ic->atf_fmcap)&&(ic->atf_mode))
    {
        if (ic->atf_tasksched == 0)
        {
            spin_lock(&ic->atf_lock);
            ic->atf_tasksched = 1;
            ic->atf_vap_handler = vap;
            OS_SET_TIMER(&ic->atfcfg_timer, IEEE80211_ATF_WAIT*1000);

            if(!ic->ic_is_mode_offload(ic))
                OS_SET_TIMER(&ic->atf_tokenalloc_timer, ATF_TOKEN_INTVL_MS);

            spin_unlock(&ic->atf_lock);
        }
        /* send wmi command to target */
        if ( ic->ic_is_mode_offload(ic) && ic->atf_vap_handler ) {
            ic->ic_vap_set_param(ic->atf_vap_handler, IEEE80211_ATF_DYNAMIC_ENABLE, 1);
        }
    }else{
        printk("Either firmware capability or host ATF configuration not support!!\n");
    }

    return retv;
}

int32_t ieee80211_atf_clear(struct ieee80211vap *vap, u_int8_t val)
{
    struct ieee80211com *ic = vap->iv_ic;
    int32_t retv = EOK;

    if(!ic->ic_is_mode_offload(ic))
    {
        /* When ATF is disabled, set ic_num_clients to default value */
        if ( ic->ic_num_clients != IEEE80211_AID_DEF) {
            retv = IEEE80211_AID_DEF;
        }

        /* Before disabling ATF, resume any paused nodes */
        ieee80211_iterate_node(ic,ieee80211_node_atf_node_resume,ic);
        ic->ic_atf_set_disable(ic, val);
    } else {
        /* Send WMI command to target */
        if(ic->atf_vap_handler) {
            ic->ic_vap_set_param(ic->atf_vap_handler, IEEE80211_ATF_DYNAMIC_ENABLE, 0);
        }
    }

    ic->atf_commit = !!val;
    if (ic->atf_tasksched == 1)
    {
        spin_lock(&ic->atf_lock);
        ic->atf_tasksched = 0;
        ic->atf_vap_handler = NULL;
        spin_unlock(&ic->atf_lock);
    }
    return retv;
}

int ieee80211_atf_get_debug_dump(struct ieee80211_node *ni)
{
    struct atf_stats *temp_atf_debug = NULL;
    u_int16_t temp_atf_debug_mask, temp_atf_debug_id;
    int i;

    IEEE80211_NODE_STATE_LOCK_BH(ni);

    if (ni->ni_atf_debug) {
        temp_atf_debug = OS_MALLOC(ni->ni_ic->ic_osdev,
                                   (ni->ni_atf_debug_mask + 1) * sizeof(struct atf_stats), GFP_ATOMIC);
        if (temp_atf_debug) {
            OS_MEMCPY(temp_atf_debug, ni->ni_atf_debug, (ni->ni_atf_debug_mask + 1) * sizeof(struct atf_stats));
            temp_atf_debug_mask = ni->ni_atf_debug_mask;
            temp_atf_debug_id = ni->ni_atf_debug_id;
        }
    }

    IEEE80211_NODE_STATE_UNLOCK_BH(ni);

    if (temp_atf_debug) {
        /* The read index is equal to write index incremented by the size, modulo size */
        temp_atf_debug_id += temp_atf_debug_mask + 1;
        temp_atf_debug_id &= temp_atf_debug_mask;

        printk("                     total   actual            actual           contrib    total                        max      min    nobuf   txbufs  txbytes    weighted     raw\n");
        printk("    time    allot    allot    allot   common   common   unused  contrib  contrib   borrow    allow     held     held     drop     sent     sent     unused%     allot\n");
        for (i = 0; i < temp_atf_debug_mask + 1; i++) {
            printk("%8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d\n",
                   temp_atf_debug[temp_atf_debug_id].timestamp, temp_atf_debug[temp_atf_debug_id].tokens,
                   temp_atf_debug[temp_atf_debug_id].total, temp_atf_debug[temp_atf_debug_id].act_tokens,
                   temp_atf_debug[temp_atf_debug_id].tokens_common, temp_atf_debug[temp_atf_debug_id].act_tokens_common,
                   temp_atf_debug[temp_atf_debug_id].unused, temp_atf_debug[temp_atf_debug_id].contribution,
                   temp_atf_debug[temp_atf_debug_id].tot_contribution, temp_atf_debug[temp_atf_debug_id].borrow,
                   temp_atf_debug[temp_atf_debug_id].allowed_bufs, temp_atf_debug[temp_atf_debug_id].max_num_buf_held,
                   temp_atf_debug[temp_atf_debug_id].min_num_buf_held, temp_atf_debug[temp_atf_debug_id].pkt_drop_nobuf,
                   temp_atf_debug[temp_atf_debug_id].num_tx_bufs, temp_atf_debug[temp_atf_debug_id].num_tx_bytes, 
                   temp_atf_debug[temp_atf_debug_id].weighted_unusedtokens_percent, temp_atf_debug[temp_atf_debug_id].raw_tx_tokens);

            temp_atf_debug_id++;
            temp_atf_debug_id &= temp_atf_debug_mask;
        }
        OS_FREE(temp_atf_debug);
    }

    return 0;
}

int ieee80211_atf_set_debug_size(struct ieee80211_node *ni, int size)
{
    IEEE80211_NODE_STATE_LOCK_BH(ni);

    /* Free old history */
    if (ni->ni_atf_debug) {
        OS_FREE(ni->ni_atf_debug);
        ni->ni_atf_debug = NULL;
    }

    if (size > 0) {
        if (size <= 16)
            size = 16;
        else if (size <= 32)
            size = 32;
        else if (size <= 64)
            size = 64;
        else if (size <= 128)
            size = 128;
        else if (size <= 256)
            size = 256;
        else if (size <= 512)
            size = 512;
        else
            size = 1024;

        /* Allocate new history */
        ni->ni_atf_debug = OS_MALLOC(ni->ni_ic->ic_osdev,
                                     size * sizeof(struct atf_stats), GFP_ATOMIC);
        if (ni->ni_atf_debug) {
            ni->ni_atf_debug_mask = size - 1;
            ni->ni_atf_debug_id = 0;
        }
    }

    IEEE80211_NODE_STATE_UNLOCK_BH(ni);

    return 0;
}
#endif
