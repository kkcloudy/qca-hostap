// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stamon.c
 *
 * @Abstract: Implementation of station monitor public APIs
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <dbg.h>
#include <evloop.h>

#ifdef LBD_DBG_MENU
#include <cmd.h>
#endif

#include "internal.h"
#include "lbd_assert.h"
#include "module.h"
#include "profile.h"
#include "stadb.h"
#include "steerexec.h"
#include "bandmon.h"
#include "steeralg.h"
#include "estimator.h"

#include "stamon.h"

/**
 * @brief Internal state for the station monitor module.
 */
static struct {
    struct dbgModule *dbgModule;

    /// Configuration data obtained at init time
    struct {
        /// The number of inst RSSI measurements per-band
        u_int8_t instRSSINumSamples[wlanif_band_invalid];

        /// Number of seconds allowed for a measurement to
        /// be considered as recent
        u_int8_t freshnessLimit;

        /// Number of probes required when non-associted band RSSI is valid
        u_int8_t probeCountThreshold;

        /// The lower-bound Tx rate value (Mbps) below which a client on 5GHz
        /// is eligible for downgrade to 2.4GHz.
        lbd_linkCapacity_t lowTxRateCrossingThreshold;

        /// The upper-bound Tx rate value (Mbps) above which a client on 2.4GHz
        /// is eligible for upgrade to 5GHz.
        lbd_linkCapacity_t highTxRateCrossingThreshold;

        /// The lower-bound RSSI value below which a client on 5GHz
        /// is eligible for downgrade to 2.4GHz.
        u_int8_t lowRateRSSIXingThreshold;

        /// When evaluating a STA for upgrade from 2.4GHz to 5GHz, the RSSI must
        /// also exceed this value.
        u_int8_t highRateRSSIXingThreshold;
    } config;
} stamonState;

// Forward decls
static void stamonActivityObserver(stadbEntry_handle_t entry, void *cookie);
static void stamonSteeringObserver(stadbEntry_handle_t entry, void *cookie);
static void stamonEstimatorObserver(stadbEntry_handle_t entry, void *cookie);
static void stamonRSSIObserver(stadbEntry_handle_t entry,
                               stadb_rssiUpdateReason_e reason, void *cookie);

static void stamonHandleSTABecomeActive(stadbEntry_handle_t entry);
static void stamonHandleSTABecomeIdle(stadbEntry_handle_t entry);
static void stamonMakeSteerDecisionIdle(stadbEntry_handle_t entry);
static void stamonHandleUtilizationChange(struct mdEventNode *event);
static void stamonHandleOverloadChange(struct mdEventNode *event);
static void stamonHandleTxRateXing(struct mdEventNode *event);
static void stamonStaDBIterateCB(stadbEntry_handle_t entry, void *cookie);
static void stamonStaDBIterateUtilizationCB(stadbEntry_handle_t entry, void *cookie);
static steerexec_steerEligibility_e stamonDetermineSteerEligibility(stadbEntry_handle_t entry);
static LBD_BOOL stamonIsSteerCandidate(stadbEntry_handle_t handle, LBD_BOOL *isActive);
static void stamonAttemptRateBasedActiveSteer(stadbEntry_handle_t entry,
                                              const struct ether_addr *staAddr,
                                              const lbd_bssInfo_t *bss,
                                              wlanif_band_e band,
                                              u_int32_t tx_rate,
                                              lbd_rssi_t rssi,
                                              steeralg_rateSteerEligibility_e eligibility);
static LBD_STATUS stamonGetUplinkRSSI(stadbEntry_handle_t entry, lbd_rssi_t *rssiOut);

/**
 * @brief Default configuration values.
 *
 * These are used if the config file does not specify them.
 */
static struct profileElement stamonElementDefaultTable[] = {
    { STAMON_RSSI_MEASUREMENT_NUM_SAMPLES_W2_KEY, "5" },
    { STAMON_RSSI_MEASUREMENT_NUM_SAMPLES_W5_KEY, "5" },
    { STAMON_AGE_LIMIT_KEY,                       "5" },
    // From wlanifBSteerControl
    { STAMON_HIGH_TX_RATE_XING_THRESHOLD,         "50000"},
    { STAMON_LOW_TX_RATE_XING_THRESHOLD,          "6000"},
    { STAMON_LOW_RATE_RSSI_XING_THRESHOLD,        "0"},
    { STAMON_HIGH_RATE_RSSI_XING_THRESHOLD,       "40"},
    { NULL, NULL }
};


// ====================================================================
// Public API
// ====================================================================

LBD_STATUS stamon_init(void) {
    stamonState.dbgModule = dbgModuleFind("stamon");
    stamonState.dbgModule->Level = DBGINFO;

    if (stadb_registerActivityObserver(stamonActivityObserver, &stamonState) != LBD_OK ||
        stadb_registerRSSIObserver(stamonRSSIObserver, &stamonState) != LBD_OK ||
        steerexec_registerSteeringAllowedObserver(stamonSteeringObserver,
                                                  &stamonState) != LBD_OK ||
        estimator_registerSTADataMetricsAllowedObserver(stamonEstimatorObserver,
                                                        &stamonState) != LBD_OK) {
        return LBD_NOK;
    }

    stamonState.config.instRSSINumSamples[wlanif_band_24g] =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_RSSI_MEASUREMENT_NUM_SAMPLES_W2_KEY,
                          stamonElementDefaultTable);
    stamonState.config.instRSSINumSamples[wlanif_band_5g] =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_RSSI_MEASUREMENT_NUM_SAMPLES_W5_KEY,
                          stamonElementDefaultTable);
    stamonState.config.freshnessLimit =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_AGE_LIMIT_KEY,
                          stamonElementDefaultTable);

    u_int32_t rate =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_LOW_TX_RATE_XING_THRESHOLD,
                          stamonElementDefaultTable);

    // Convert from the Kbps config value to Mbps
    stamonState.config.lowTxRateCrossingThreshold = rate / 1000;

    rate = profileGetOptsInt(mdModuleID_StaMon,
                             STAMON_HIGH_TX_RATE_XING_THRESHOLD,
                             stamonElementDefaultTable);

    // Convert from the Kbps config value to Mbps
    stamonState.config.highTxRateCrossingThreshold = rate / 1000;

    // Don't do any checking of the wlanif variables here - wlanif will
    // restart lbd if necessary.

    stamonState.config.lowRateRSSIXingThreshold =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_LOW_RATE_RSSI_XING_THRESHOLD,
                          stamonElementDefaultTable);

    stamonState.config.highRateRSSIXingThreshold =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_HIGH_RATE_RSSI_XING_THRESHOLD,
                          stamonElementDefaultTable);

    mdListenTableRegister(mdModuleID_BandMon, bandmon_event_overload_change,
                          stamonHandleOverloadChange);

    mdListenTableRegister(mdModuleID_BandMon, bandmon_event_utilization_update,
                          stamonHandleUtilizationChange);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_tx_rate_xing,
                          stamonHandleTxRateXing);

    return LBD_OK;
}

LBD_STATUS stamon_fini(void) {
    LBD_STATUS status = LBD_OK;
    status |=
        stadb_unregisterActivityObserver(stamonActivityObserver, &stamonState);
    status |=
        stadb_unregisterRSSIObserver(stamonRSSIObserver, &stamonState);
    status |=
        steerexec_unregisterSteeringAllowedObserver(stamonSteeringObserver,
                                                    &stamonState);
    status |=
        estimator_unregisterSTADataMetricsAllowedObserver(stamonEstimatorObserver,
                                                          &stamonState);
    return status;
}

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Handle the activity status update about a STA become active
 *
 * @param [in] entry  the STA that becomes active
 */
static void stamonHandleSTABecomeActive(stadbEntry_handle_t entry) {
    // Determine if this steer should be aborted.
    if (steerexec_shouldAbortSteerForActive(entry)) {
        steerexec_abort(entry, NULL);
        return;
    }

    // If the device can be steered while active, there is nothing
    // further to do.
}

/**
 * @brief Determine if a STA can be steered while active based
 *        on the rate (non-overload case).  Will attempt to
 *        upgrade from 2.4GHz to 5GHz if the rate is
 *        sufficiently high, or downgrade from 5GHz to 2.4GHz if
 *        the rate is sufficiently low.
 *
 * @pre STA is associated
 *
 * @param [in] entry STA to evaluate for steering by rate
 * @param [in] eligibility steering eligibilty of this STA
 */
static void stamonMakeRateBasedSteerDecisionActive(
    stadbEntry_handle_t entry,
    steerexec_steerEligibility_e eligibility) {
    if (eligibility != steerexec_steerEligibility_active) {
        // This device can not be steered while active, return.
        return;
    }

    // Should not be possible to get here with an unassociated STA.

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(stamonState.dbgModule, staAddr);
    stadbEntry_bssStatsHandle_t servingBSS = stadbEntry_getServingBSS(entry, NULL);
    const lbd_bssInfo_t *bss = stadbEntry_resolveBSSInfo(servingBSS);
    lbDbgAssertExit(stamonState.dbgModule, bss);
    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(bss->channelId);
    lbDbgAssertExit(stamonState.dbgModule, band != wlanif_band_invalid);

    // Check the Tx rate - is this device eligible for upgrade or downgrade?
    wlanif_staStatsSnapshot_t staStats;
    if (wlanif_sampleSTAStats(bss, staAddr, LBD_TRUE /* rateOnly */,
                              &staStats) != LBD_OK) {
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Failed to get Tx rate information for " lbMACAddFmt(":")
             " on " lbBSSInfoAddFmt(),
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             lbBSSInfoAddData(bss));
        return;
    }

    steeralg_rateSteerEligibility_e rateEligibility =
        steeralg_determineRateSteerEligibility(staStats.lastTxRate, band);

    lbd_rssi_t rssi = LBD_INVALID_RSSI;
    if ((rateEligibility == steeralg_rateSteer_none) && (band == wlanif_band_24g)) {
        // For upgrade, both rate and rssi need to exceed their respective thresholds
        // Rate is neither sufficient for upgrade or downgrade.
        return;
    } else if ((rateEligibility == steeralg_rateSteer_none) ||
               (band == wlanif_band_24g)) {
        // For downgrade, either rate or rssi needs to exeed their respective thresholds.
        // The rate is not sufficient for downgrade, but check RSSI as well.
        // For upgrade, the rate was sufficient for upgrade, but still need to check RSSI.
        if (stamonGetUplinkRSSI(entry, &rssi) == LBD_NOK) {
            return;
        }

        if ((rssi < stamonState.config.lowRateRSSIXingThreshold) && 
            (band == wlanif_band_5g)) {
            // RSSI is below the low threshold, downgrade.
            rateEligibility = steeralg_rateSteer_downgrade;
        }

        if (rateEligibility == steeralg_rateSteer_none) {
            return;
        }
    }

    // Attempt to steer if possible.
    stamonAttemptRateBasedActiveSteer(entry, staAddr, bss,
                                      band, staStats.lastTxRate, rssi, rateEligibility);
}

/**
 * @brief Handle the activity status update about a STA become idle
 *
 * @param [in] entry  the STA that becomes idle
 */
static void stamonHandleSTABecomeIdle(stadbEntry_handle_t entry) {
    stamonMakeSteerDecisionIdle(entry);
}

/**
 * @brief Get the latest uplink RSSI measurement on serving BSS and make estimation
 *        on non-serving BSSes
 *
 * @pre entry is valid and associated
 *
 * @param [in] entry  the entry to check RSSI 
 * @param [out] rssiOut if non-NULL, just return the RSSI in
 *                      this parameter and don't estimate on the
 *                      non-serving BSSes
 *
 * @return LBD_OK if all RSSI info are up-to-date; otherwise return LBD_NOK
 */
static LBD_STATUS stamonGetUplinkRSSI(stadbEntry_handle_t entry,
                                      lbd_rssi_t *rssiOut) {
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(stamonState.dbgModule, staAddr);
    stadbEntry_bssStatsHandle_t servingBSS = stadbEntry_getServingBSS(entry, NULL);
    const lbd_bssInfo_t *bss = stadbEntry_resolveBSSInfo(servingBSS);
    lbDbgAssertExit(stamonState.dbgModule, bss);

    time_t ageSecs = 0xFFFFFFFF;
    u_int8_t probeCount = 0;
    lbd_rssi_t rssi = stadbEntry_getUplinkRSSI(entry, servingBSS, &ageSecs, &probeCount);
    if (rssi == LBD_INVALID_RSSI ||
        ageSecs > stamonState.config.freshnessLimit ||
        probeCount) {
        // RSSI is either too old or invalid, need to re-measure
        // Since probe RSSI will be ignored on serving BSS, it is very unlikely
        // to have a recent valid probe RSSI. So probe RSSI will be ignored here
        wlanif_band_e associatedBand = wlanif_resolveBandFromChannelNumber(bss->channelId);
        if (LBD_NOK == wlanif_requestStaRSSI(bss, staAddr,
                                             stamonState.config.instRSSINumSamples[associatedBand])) {
            dbgf(stamonState.dbgModule, DBGERR,
                 "%s: Failed to request RSSI measurement for " lbMACAddFmt(":")
                 " on " lbBSSInfoAddFmt(),
                  __func__, lbMACAddData(staAddr->ether_addr_octet),
                  lbBSSInfoAddData(bss));
        }
        return LBD_NOK;
    }

    if (rssiOut) {
        *rssiOut = rssi;
        return LBD_OK;
    }

    if (LBD_NOK == estimator_estimateNonServingUplinkRSSI(entry)) {
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Failed to estimate non-serving RSSI for "lbMACAddFmt(":"),
             __func__, lbMACAddData(staAddr->ether_addr_octet));
        return LBD_NOK;
    }

    return LBD_OK;
}

/**
 * @brief Make a steering decision for an idle client
 *
 * @pre entry is dual band, associated and idle
 *
 * @param [in] entry  the STA that needs to be checked
 * @param [in] final  flag indicating whether this is a final decision, meaning
 *                    it cannot request RSSI measurement and must make an RSSI
 *                    estimation based on available RSSI information
 * @param [in] realMeasurementOnly  flag indicating if the steering decision has to be made
 *                                  based on RSSI on the target band. No RSSI estimation is
 *                                  allowed
 */
static void stamonMakeSteerDecisionIdle(stadbEntry_handle_t entry) {
    if (bandmon_areAllChannelsOverloaded()) {
        // No steering is performed if there are no non-overloaded channels.
        // We just let the client decide, as there is not really anything we
        // can do to make the situation better.
        return;
    }

    if (LBD_NOK == stamonGetUplinkRSSI(entry, NULL)) {
        // RSSI information not ready
        return;
    }

    steeralg_steerIdleClient(entry);
}

/**
 * @brief Either an activity change or steering allowed event
 *        has occurred for a STA.
 *
 * @param [in] entry STA to evaluate
 * @param [in] activityUpdate LBD_TRUE if the triggering event was an
 *                            activity change (transition to active or
 *                            inactive)
 */
static void stamonTriggerActivityOrSteering(stadbEntry_handle_t entry,
                                            LBD_BOOL activityUpdate) {
    // We ignore the cookie here, since our state is static anyways.
    LBD_BOOL isActive;
    if (!stamonIsSteerCandidate(entry, &isActive)) {
        return;
    }

    steerexec_steerEligibility_e eligibility = steerexec_steerEligibility_none;
    if (!isActive || !activityUpdate) {
        eligibility = steerexec_determineSteeringEligibility(entry);
    }

    if (isActive) {
        if (!activityUpdate) {
            // Triggered by STA becoming steerable or became eligible for
            // its data metrics to be measured again.
            stamonMakeRateBasedSteerDecisionActive(entry, eligibility);
        } else {
            // Triggered by STA becoming active.
            stamonHandleSTABecomeActive(entry);
        }
    } else {
        if (eligibility != steerexec_steerEligibility_none) {
            // Action is the same for Idle STAs, regardless of the trigger.
            stamonHandleSTABecomeIdle(entry);
        }
    }
}

/**
 * @brief Callback function invoked by the station database module when
 *        the activity status for a specific STA has been
 *        updated.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] cookie  the pointer to our internal state
 */
static void stamonActivityObserver(stadbEntry_handle_t entry, void *cookie) {
    stamonTriggerActivityOrSteering(entry,
                                    LBD_TRUE /* activityUpdate */);
}

/**
 * @brief Callback function invoked by the steering executor module when
 *        a specific STA has become eligible to be steered.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] cookie  the pointer to our internal state
 */
static void stamonSteeringObserver(stadbEntry_handle_t entry, void *cookie) {
    stamonTriggerActivityOrSteering(entry,
                                    LBD_FALSE /* activityUpdate */);
}

/**
 * @brief Callback function invoked by the estimator module when
 *        a specific STA has become eligible to have its data metrics measured
 *        again.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] cookie  the pointer to our internal state
 */
static void stamonEstimatorObserver(stadbEntry_handle_t entry, void *cookie) {
    stamonTriggerActivityOrSteering(entry,
                                    LBD_FALSE /* activityUpdate */);
}

/**
 * @brief Callback function invoked by the station database module when
 *        the RSSI for a specific STA has been updated.
 *
 * For a dual-band and idle STA, estimate RSSI value on the other band
 * based on the RSSI measurement received, and make the steering decision
 * based on the estimated RSSI value.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] reason  the reason for the updated RSSI measurement
 * @param [in] cookie  the pointer to our internal state
 */
static void stamonRSSIObserver(stadbEntry_handle_t entry,
                               stadb_rssiUpdateReason_e reason, void *cookie) {
    steerexec_steerEligibility_e eligibility = stamonDetermineSteerEligibility(entry);
    if (eligibility == steerexec_steerEligibility_idle) {
        stamonMakeSteerDecisionIdle(entry);
    } else if (eligibility == steerexec_steerEligibility_active) {
        stamonMakeRateBasedSteerDecisionActive(entry, eligibility);
    }
}

/**
 * @brief React to an event providing the updated overload status information
 */
static void stamonHandleOverloadChange(struct mdEventNode *event) {
    if (stadb_iterate(stamonStaDBIterateCB, NULL) != LBD_OK) {
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Failed to iterate over STA DB; will wait for RSSI "
             "or inactivity updates", __func__);
        return;
    }
}

/**
 * @brief React to an event indicating utilization is updated
 */
static void stamonHandleUtilizationChange(struct mdEventNode *event) {
    const bandmon_utilizationUpdateEvent_t *util =
        (const bandmon_utilizationUpdateEvent_t *)event->Data;

    if (!util) {
        return;
    }

    lbd_channelId_t channels[WLANIF_MAX_RADIOS];

    // Get the set of channels from wlanif.
    u_int8_t channelCount = wlanif_getChannelList(&channels[0],
                                                  WLANIF_MAX_RADIOS);

    if (util->numOverloadedChannels >= channelCount) {
        // All channels are overloaded, so can't do anything now.
        // Request notification for the next utilization update.
        bandmon_enableOneShotUtilizationEvent();

        return;
    }

    if (stadb_iterate(stamonStaDBIterateUtilizationCB, NULL) != LBD_OK) {
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Failed to iterate over STA DB (triggered by utilization update)", __func__);
        return;
    }
}

/**
 * @brief An event that can trigger active steering has occurred 
 *        (either a RSSI or Tx rate crossing).  General
 *        evaluation to determine if we should now steer the
 *        STA.
 * 
 * @param [in] staAddr MAC address of the STA that generated the 
 *                     event
 * @param [in] bss BSS the STA is associated on
 * @param [in] band  band the STA is associated on
 * @param [in] tx_rate  last Tx rate used to the STA (0 if 
 *                      unknown)
 * @param [in] xing  crossing direction  
 */
static void stamonEventTriggeredActiveSteer(
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *bss,
    wlanif_band_e band,
    u_int32_t txRate,
    wlanif_xingDirection_e xing) {
    // Get the stadb entry for the event
    stadbEntry_handle_t entry = stadb_find(staAddr);
    if (!entry) {
        // Unknown MAC address
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Received Tx rate crossing event from unknown MAC address: "
             lbMACAddFmt(":") " on BSS " lbBSSInfoAddFmt(),
             __func__, lbMACAddData(staAddr),
             lbBSSInfoAddData(bss));
        return;
    }

    if (steerexec_steerEligibility_active !=
            stamonDetermineSteerEligibility(entry)) {
        // This device can not be steered while active, return.
        // If it can be steered later, we will revisit this STA then.
        return;
    }

    lbd_rssi_t rssi = LBD_INVALID_RSSI;
    if (xing == wlanif_xing_up) {
        // RSSI not ready
        if (stamonGetUplinkRSSI(entry, &rssi) == LBD_NOK) {
            return;
        }
    }

    stamonAttemptRateBasedActiveSteer(entry, staAddr, bss,
                                      band, txRate, rssi,
                                      (xing == wlanif_xing_up) ?
                                      steeralg_rateSteer_upgrade :
                                      steeralg_rateSteer_downgrade);
}

/**
 * @brief React to an event indicating Tx rate has crossed a
 *        threshold.
 */
static void stamonHandleTxRateXing(struct mdEventNode *event) {
    const wlanif_txRateXingEvent_t *xing =
        (const wlanif_txRateXingEvent_t *)event->Data;

    if (!xing) {
        return;
    }

    // Check this is an event we need to act on.
    if ((xing->xing != wlanif_xing_up) && (xing->xing != wlanif_xing_down)) {
        // Invalid crossing.
        return;
    }

    // Get the band this event occurred on.
    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(xing->bss.channelId);
    if (band >= wlanif_band_invalid) {
        // Invalid band.
        return;
    }

    // Shouldn't ever get a Tx rate crossing event with a rate of 0
    if (!xing->tx_rate) {
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Received Tx rate crossing in direction %d on band %d"
             " from MAC address " lbMACAddFmt(":") " on BSS " lbBSSInfoAddFmt()
             " with a Tx rate of 0, ignoring",
             __func__, xing->xing, band, lbMACAddData(xing->sta_addr.ether_addr_octet),
             lbBSSInfoAddData(&xing->bss));
        return;
    }

    // Check the direction of the crossing corresponds to the band it occured on.
    if (((band == wlanif_band_5g) && (xing->xing != wlanif_xing_down)) ||
        ((band == wlanif_band_24g) && (xing->xing != wlanif_xing_up))) {
        // Will only attempt to upgrade 2.4GHz clients and downgrade 5GHz clients.
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Received unexpected Tx rate crossing in direction %d on band %d"
             " from MAC address " lbMACAddFmt(":") " on BSS " lbBSSInfoAddFmt(),
             __func__, xing->xing, band, lbMACAddData(xing->sta_addr.ether_addr_octet),
             lbBSSInfoAddData(&xing->bss));
        return;
    }

    stamonEventTriggeredActiveSteer(&xing->sta_addr, &xing->bss, band,
                                    xing->tx_rate, xing->xing);
}

/**
 * @brief Attempt to steer a STA due to the Tx rate being either
 *        too low on 5GHz or too high on 2.4GHz.
 *
 * @param [in] entry STA to attempt to steer
 * @param [in] staAddr MAC address of the STA
 * @param [in] bss BSS the STA is associated on
 * @param [in] band band the STA is associated on
 * @param [in] tx_rate last rate this STA transmitted at (in
 *                     Kbps)
 * @param [in] rssi RSSI to the STA 
 * @param [in] xing rate crossing direction (used to determine
 *                  if this is an upgrade or a downgrade for
 *                  logging purposes)
 */
static void stamonAttemptRateBasedActiveSteer(
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *bss,
    wlanif_band_e band,
    u_int32_t tx_rate,
    lbd_rssi_t rssi,
    steeralg_rateSteerEligibility_e eligibility) {

    // When downgrading a STA, any 2.4GHz channel is an acceptable target
    // (even if the channel is overloaded / past the safety threshold), and
    // downgrade can still happen during steering blackout.
    if (band == wlanif_band_24g) {
        // When upgrading a STA, the RSSI has to exceed the HighRateRSSIXingThreshold
        if (rssi <= stamonState.config.highRateRSSIXingThreshold) {
            dbgf(stamonState.dbgModule, DBGDEBUG,
                 "%s: Device " lbMACAddFmt(":")
                 " eligible for %s at rate %u, but RSSI %u does not exceed the high crossing threshold %u",
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 (eligibility == steeralg_rateSteer_upgrade) ? "upgrade" : "downgrade",
                 tx_rate, rssi, stamonState.config.highRateRSSIXingThreshold);
            return;
        }

        // Check if there is at least one channel this STA can be directed to.
        if (!bandmon_canOffloadClientFromBand(band)) {
            dbgf(stamonState.dbgModule, DBGDEBUG,
                 "%s: Device " lbMACAddFmt(":") " eligible for active steering due to rate, "
                 " but all potential destination channels exceed safety threshold",
                 __func__, lbMACAddData(staAddr->ether_addr_octet));

            // Request notification for utilization update.
            bandmon_enableOneShotUtilizationEvent();
            return;
        }

        if (bandmon_isInSteeringBlackout()) {
            // During steering blackout, can only downgrade 5GHz clients.

            dbgf(stamonState.dbgModule, DBGDEBUG,
                 "%s: Device " lbMACAddFmt(":") " eligible for upgrade to 5GHz band, "
                 " but postponed due to steering blackout",
                 __func__, lbMACAddData(staAddr->ether_addr_octet));

            // Request notification for utilization update.
            bandmon_enableOneShotUtilizationEvent();
            return;
        }
    }

    // Device can be steered while active, and we're not in a blackout period.
    // Check if there's anywhere it can be steered to.
    LBD_STATUS status = estimator_estimateSTADataMetrics(entry);
    dbgf(stamonState.dbgModule, DBGINFO,
         "%s: Device " lbMACAddFmt(":")
         " eligible for %s at rate %u, collecting metrics, return code %d",
         __func__, lbMACAddData(staAddr->ether_addr_octet),
         (eligibility == steeralg_rateSteer_upgrade) ? "upgrade" : "downgrade",
         tx_rate, status);
}

/**
 * @brief Handler for each entry in the station database.
 *
 * @param [in] entry  the current entry being examined
 * @param [in] cookie  the parameter provided in the stadb_iterate call
 */
static void stamonStaDBIterateCB(stadbEntry_handle_t entry, void *cookie) {
    steerexec_steerEligibility_e eligibility = stamonDetermineSteerEligibility(entry);
    if (eligibility == steerexec_steerEligibility_idle) {
        stamonMakeSteerDecisionIdle(entry);
    }
}

/**
 * @brief Handler for each entry in the station database.
 *        Triggered by utilization update.
 *
 * @param [in] entry  the current entry being examined
 * @param [in] cookie  the parameter provided in the stadb_iterate call
 */
static void stamonStaDBIterateUtilizationCB(stadbEntry_handle_t entry, void *cookie) {
    steerexec_steerEligibility_e eligibility = stamonDetermineSteerEligibility(entry);
    if (eligibility == steerexec_steerEligibility_active) {
        stamonMakeRateBasedSteerDecisionActive(entry, eligibility);
    }
}

/**
 * @brief Check if a given STA can be a steering candidate
 *
 * @param [in] entry  the handle of the given STA
 *
 * @return Eligibility for steering based on the activity.  If
 *         the client can be steered while active or idle and is
 *         currently idle, will return
 *         steerexec_steerEligibility_idle.  If the client can
 *         be steered while active and is currently active, will
 *         return steerexec_steerEligibility_active.  If the
 *         client can't be steered, will return
 *         steerexec_steerEligibility_none.
 */
static steerexec_steerEligibility_e
stamonDetermineSteerEligibility(stadbEntry_handle_t entry) {
    LBD_BOOL isActive;
    if (!stamonIsSteerCandidate(entry, &isActive)) {
        return steerexec_steerEligibility_none;
    }

    steerexec_steerEligibility_e eligibility =
        steerexec_determineSteeringEligibility(entry);
    if (((eligibility == steerexec_steerEligibility_idle) && isActive) ||
        (eligibility == steerexec_steerEligibility_none)) {
        return steerexec_steerEligibility_none;
    }

    // We can steer this device, return eligibility based on activity
    if (isActive) {
        return steerexec_steerEligibility_active;
    }
    return steerexec_steerEligibility_idle;
}

/**
 * @brief Check if a client can be steered
 *
 * @param [in] entry  the handle to the client to check
 * @param [out] isActive  whether the client is active or not
 *
 * return LBD_TRUE if the client is associated, dual band capable
 *                 with valid activity status and does not have
 *                 reserved airtime on serving BSS; otherwise, return
 *                 LBD_FALSE
 */
static LBD_BOOL stamonIsSteerCandidate(stadbEntry_handle_t entry,
                                       LBD_BOOL *isActive) {
    stadbEntry_bssStatsHandle_t servingBSS = stadbEntry_getServingBSS(entry, NULL);
    return servingBSS && stadbEntry_isDualBand(entry) &&
           LBD_OK == stadbEntry_getActStatus(entry, isActive, NULL) &&
           LBD_INVALID_AIRTIME == stadbEntry_getReservedAirtime(entry, servingBSS);
}
