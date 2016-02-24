// vim: set et sw=4 sts=4 cindent:
/*
 * @File: steeralg.c
 *
 * @Abstract: Implementation of BSS steeralg
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
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
#include "bandmon.h"
#include "steerexec.h"
#include "estimator.h"

#include "steeralg.h"

/**
 * @brief Internal structure for offloading candidate
 */
typedef struct steeralgOffloadingCandidateEntry_t {
    /// The handle to the candidate STA
    stadbEntry_handle_t entry;

    /// The metric of this candidate, used for sorting
    /// Bit 15:  Set if prefered to be offloaded
    /// Bit 0-7: The estimated airtime of this STA
    u_int16_t metric;
#define STEERALG_OFFLOADING_CANDIDATE_PREFER_BIT 15
#define STEERALG_OFFLOADING_CANDIDATE_AIRTIME_MASK 0xFF
} steeralgOffloadingCandidateEntry_t;

/**
 * @brief Internal state for the BSS steeralg module.
 */
static struct {
    struct dbgModule *dbgModule;

    /// Configuration data obtained at init time
    struct {
        /// RSSI threshold when inactive
        lbd_rssi_t inactRSSIXingThreshold[wlanif_band_invalid];

        /// Low Tx rate threshold on 5 GHz (Mbps)
        lbd_linkCapacity_t lowTxRateThreshold;

        /// High Tx rate threshold on 2.4 GHz (Mbps)
        lbd_linkCapacity_t highTxRateThreshold;

        /// Minimum rate improvement over the lowTxRateThreshold
        /// when steering from 2.4GHz to 5GHz
        lbd_linkCapacity_t minTxRateIncreaseThreshold;

        /// The lower-bound RSSI value below which a client on 5GHz
        /// is eligible for downgrade to 2.4GHz.
        u_int8_t lowRateRSSIXingThreshold;

        /// When evaluating a STA for upgrade from 2.4GHz to 5GHz, the RSSI must
        /// also exceed this value.
        u_int8_t highRateRSSIXingThreshold;

        /// Number of seconds allowed for a measurement to
        /// be considered as recent
        u_int8_t freshnessLimit;

        /// Whether to consider PHY capability when sorting BSSes or clients
        /// for idle steering, offloading or selecting 11k channel
        LBD_BOOL phyBasedPrioritization;

        /// The RSSI threshold serving channel RSSI must be above to consider
        /// 2.4 GHz BSS as idle offloading candidate
        u_int8_t rssiSafetyThreshold;
    } config;

    /// A queue holding overloaded channels that have been offloaded
    struct {
        /// Channel ID, LBD_CHANNEL_INVALID if this entry is invalid
        lbd_channelId_t channelId;

        /// the time when it was served
        time_t lastServingTime;
    } servedChannels[WLANIF_MAX_RADIOS];

    /// Offloading overloaded channel related info
    struct {
        /// Whether there is an airtime estimate pending
        LBD_BOOL airtimeEstimatePending : 1;

        /// Whether offloading by steering clients away is in progress.
        /// This should happen after airtime estimation completes.
        LBD_BOOL inProgress : 1;

        /// The channel being offloaded
        lbd_channelId_t channelId;

        /// A list of clients that can be offloaded;
        /// it should be sorted based on the occupied airtime.
        steeralgOffloadingCandidateEntry_t *candidateList;

        /// Number of clients in candidateList
        size_t numCandidates;

        /// Index of the client in candidateList that has an 802.11k
        /// measuremnt pending; candidates before the index should have
        /// been processed.
        size_t headIdx;

        /// Total airtime that has been offloaded from
        /// the overloaded channel.
        lbd_airtime_t totalAirtimeOffloaded;
    } offloadState;
} steeralgState;

/**
 * @brief Serving BSS information
 */
typedef struct steeralgServingBSSInfo_t {
    stadbEntry_bssStatsHandle_t stats;
    const lbd_bssInfo_t *bssInfo;
    wlanif_band_e band;
    lbd_linkCapacity_t dlRate;
    LBD_BOOL isOverloaded;
    steeralg_rateSteerEligibility_e rateSteerEligibility;
    wlanif_phymode_e bestPHYMode;
    LBD_BOOL isOnStrongest5G;
} steeralgServingBSSInfo_t;

/**
 * @brief Paramters used when iterating over STA database to determine
 *        the active steering candidate for offloading channel
 */
typedef struct steeralgSelectOffloadingCandidatesParams_t {
    /// The channel on which to select offloading candidates
    lbd_channelId_t channelId;

    /// Number of candidates allowed in candidateList
    size_t numCandidatesAllocated;

    /// If the channel to offload is on 5 GHz, whether it is
    /// the strongest 5 GHz channel (with highest Tx power)
    LBD_BOOL isStrongestChannel5G;
} steeralgSelectOffloadingCandidatesParams_t;

// Forward declarations
static u_int32_t steeralgIdleSteerCallback(stadbEntry_handle_t entry,
                                           stadbEntry_bssStatsHandle_t bssHandle,
                                           void *cookie);
static LBD_STATUS steeralgDoSteering(stadbEntry_handle_t entry, size_t numBSS,
                                     const lbd_bssInfo_t *bssCandidates,
                                     steerexec_steerReason_e reason);
static LBD_STATUS steeralgFindCandidatesForIdleClient(
        stadbEntry_handle_t entry, size_t *maxNumBSS,
        steeralgServingBSSInfo_t *servingBSS, lbd_bssInfo_t *bssCandidates);
static void steeralgHandleOverloadChangeEvent(struct mdEventNode *event);
static void steeralgHandleUtilizationUpdateEvent(struct mdEventNode *event);
static void steeralgHandleUtilizationUpdate(size_t numOverloadedChannels);
static void steeralgHandleSTAMetricsCompleteEvent(struct mdEventNode *event);
static time_t steeralgGetTimestamp(void);
static lbd_channelId_t steeralgSelectOverloadedChannel(
        size_t numChannels, const lbd_channelId_t *channelList);
static void steeralgOffloadOverloadedChannel(size_t numOverloadedChannels);
static void steeralgResetServedChannels(void);
static LBD_BOOL steeralgIsChannelServedBefore(lbd_channelId_t channelId,
                                              time_t *lastServedTime);
static void steeralgAddChannelToServedChannels(lbd_channelId_t channelId);
static u_int32_t steeralgComputeIdleSteerMetric(
        stadbEntry_handle_t handle, stadbEntry_bssStatsHandle_t bssStats,
        wlanif_phymode_e bestPHYMode);
static void steeralgHandlePerSTAAirtimeCompleteEvent(struct mdEventNode *event);
static void steeralgSelectOffloadingCandidateCB(stadbEntry_handle_t entry,
                                                void *cookie);
static void steeralgContinueSteerActiveClientsOverload(lbd_airtime_t offloadedAirtime,
                                                       LBD_BOOL lastComplete);
static void steeralgRecordOffloadingCandidate(
        stadbEntry_handle_t entry, steeralgSelectOffloadingCandidatesParams_t *params,
        lbd_airtime_t airtime);
static void steeralgSortOffloadCandidates(void);
static int steeralgCompareOffloadCandidates(const void *candidate1, const void *candidate2);
static void steeralgFinishOffloading(LBD_BOOL requestOneShotUtil);
static LBD_BOOL steeralgIsSTAMetricsTriggeredByOffloading(
        stadbEntry_handle_t entry, lbd_airtime_t *occupiedAirtime);
static LBD_BOOL steeralgCanBSSSupportClient(stadbEntry_handle_t entry,
                                            stadbEntry_bssStatsHandle_t bssHandle,
                                            const lbd_bssInfo_t *bss,
                                            lbd_airtime_t *availableAirtime);
static LBD_BOOL steeralgIsRateAboveThreshold(stadbEntry_handle_t entry,
                                             stadbEntry_bssStatsHandle_t bssHandle,
                                             const lbd_bssInfo_t *bss,
                                             lbd_linkCapacity_t threshold,
                                             lbd_linkCapacity_t dlEstimate,
                                             time_t ageSecs);
static LBD_STATUS steeralgUpdateCandidateProjectedAirtime(
        stadbEntry_handle_t entry, LBD_BOOL isDowngrade,
        const lbd_bssInfo_t *candidateList, size_t maxNumBSS);
static u_int32_t steeralgSelect11kChannelCallback(stadbEntry_handle_t entry,
                                                  stadbEntry_bssStatsHandle_t bssHandle,
                                                  void *cookie);
static u_int32_t steeralgComputeBSSMetric(stadbEntry_handle_t entry,
                                          stadbEntry_bssStatsHandle_t bssHandle,
                                          wlanif_band_e preferedBand,
                                          wlanif_phymode_e bestPHYMode,
                                          u_int32_t offsetBand,
                                          u_int32_t offsetPHYCap,
                                          u_int32_t offsetReservedAirtime,
                                          u_int32_t offsetSafety,
                                          u_int32_t offsetUtil);

/**
 * @brief Default configuration values.
 *
 * These are used if the config file does not specify them.
 */
static struct profileElement steeralgElementDefaultTable[] = {
    { STEERALG_INACT_RSSI_THRESHOLD_W2_KEY,          "5" },
    { STEERALG_INACT_RSSI_THRESHOLD_W5_KEY,         "30" },
    { STEERALG_HIGH_TX_RATE_XING_THRESHOLD,         "50000"},
    { STEERALG_HIGH_RATE_RSSI_XING_THRESHOLD,       "40"},
    { STEERALG_LOW_TX_RATE_XING_THRESHOLD,          "6000" },
    { STEERALG_LOW_RATE_RSSI_XING_THRESHOLD,        "0"},
    { STEERALG_MIN_TXRATE_INCREASE_THRESHOLD_KEY,   "53"},
    { STEERALG_AGE_LIMIT_KEY,                        "5" },
    { STEERALG_PHY_BASED_PRIORITIZATION,             "0" },
    { STEERALG_RSSI_SAFETY_THRESHOLD_KEY,            "20" },
    { NULL, NULL }
};


// ====================================================================
// Public API
// ====================================================================

LBD_STATUS steeralg_init(void) {
    steeralgState.dbgModule = dbgModuleFind("steeralg");
    steeralgState.dbgModule->Level = DBGINFO;

    steeralgState.config.inactRSSIXingThreshold[wlanif_band_24g] =
        profileGetOptsInt(mdModuleID_SteerAlg,
                          STEERALG_INACT_RSSI_THRESHOLD_W2_KEY,
                          steeralgElementDefaultTable);
    steeralgState.config.inactRSSIXingThreshold[wlanif_band_5g] =
        profileGetOptsInt(mdModuleID_SteerAlg,
                          STEERALG_INACT_RSSI_THRESHOLD_W5_KEY,
                          steeralgElementDefaultTable);

    u_int32_t rateThreshold =
        profileGetOptsInt(mdModuleID_SteerAlg,
                          STEERALG_HIGH_TX_RATE_XING_THRESHOLD,
                          steeralgElementDefaultTable);

    // Convert to Mbps for steeralg
    steeralgState.config.highTxRateThreshold = rateThreshold / 1000;

    rateThreshold =
        profileGetOptsInt(mdModuleID_SteerAlg,
                          STEERALG_LOW_TX_RATE_XING_THRESHOLD,
                          steeralgElementDefaultTable);

    // Convert to Mbps for steeralg
    steeralgState.config.lowTxRateThreshold = rateThreshold / 1000;

    steeralgState.config.minTxRateIncreaseThreshold =
        profileGetOptsInt(mdModuleID_SteerAlg,
                          STEERALG_MIN_TXRATE_INCREASE_THRESHOLD_KEY,
                          steeralgElementDefaultTable);

    steeralgState.config.freshnessLimit =
        profileGetOptsInt(mdModuleID_SteerAlg,
                          STEERALG_AGE_LIMIT_KEY,
                          steeralgElementDefaultTable);

    steeralgState.config.lowRateRSSIXingThreshold =
        profileGetOptsInt(mdModuleID_SteerAlg,
                          STEERALG_LOW_RATE_RSSI_XING_THRESHOLD,
                          steeralgElementDefaultTable);

    steeralgState.config.highRateRSSIXingThreshold =
        profileGetOptsInt(mdModuleID_SteerAlg,
                          STEERALG_HIGH_RATE_RSSI_XING_THRESHOLD,
                          steeralgElementDefaultTable);

    steeralgState.config.phyBasedPrioritization =
        profileGetOptsInt(mdModuleID_SteerAlg,
                          STEERALG_PHY_BASED_PRIORITIZATION,
                          steeralgElementDefaultTable) > 0;

    steeralgState.config.rssiSafetyThreshold =
        profileGetOptsInt(mdModuleID_SteerAlg,
                          STEERALG_RSSI_SAFETY_THRESHOLD_KEY,
                          steeralgElementDefaultTable);

    mdListenTableRegister(mdModuleID_BandMon, bandmon_event_overload_change,
                          steeralgHandleOverloadChangeEvent);
    mdListenTableRegister(mdModuleID_BandMon, bandmon_event_utilization_update,
                          steeralgHandleUtilizationUpdateEvent);
    mdListenTableRegister(mdModuleID_Estimator,
                          estimator_event_staDataMetricsComplete,
                          steeralgHandleSTAMetricsCompleteEvent);
    mdListenTableRegister(mdModuleID_Estimator, estimator_event_perSTAAirtimeComplete,
                          steeralgHandlePerSTAAirtimeCompleteEvent);

    steeralgResetServedChannels();

    return LBD_OK;
}

LBD_STATUS steeralg_fini(void) {
    steeralgFinishOffloading(LBD_FALSE /* requestOneShotUtil */);
    return LBD_OK;
}

LBD_STATUS steeralg_steerIdleClient(stadbEntry_handle_t entry) {
    if (!entry || !stadbEntry_getServingBSS(entry, NULL)) {
        // Ignore disassociated STA
        return LBD_NOK;
    }

    steeralgServingBSSInfo_t servingBSS;

    size_t maxNumBSS = STEEREXEC_MAX_CANDIDATES;
    lbd_bssInfo_t bss[STEEREXEC_MAX_CANDIDATES] = {{0}};
    if (LBD_NOK == steeralgFindCandidatesForIdleClient(entry, &maxNumBSS,
                                                       &servingBSS, bss) ||
        !maxNumBSS) {
        return LBD_NOK;
    }

    // Determine the reason for the steer
    steerexec_steerReason_e reason;
    if (servingBSS.isOverloaded) {
        reason = steerexec_steerReasonIdleOffload;
    } else if (servingBSS.band == wlanif_band_24g) {
        reason = steerexec_steerReasonIdleUpgrade;
    } else {
        reason = steerexec_steerReasonIdleDowngrade;
    }

    lbDbgAssertExit(steeralgState.dbgModule, maxNumBSS <= STEEREXEC_MAX_CANDIDATES);
    return steeralgDoSteering(entry, maxNumBSS, bss, reason);
}

lbd_channelId_t steeralg_select11kChannel(stadbEntry_handle_t entry) {
    if (!entry) {
        return LBD_CHANNEL_INVALID;
    }

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(steeralgState.dbgModule, staAddr);

    steeralgServingBSSInfo_t servingBSS = {0};

    servingBSS.stats = stadbEntry_getServingBSS(entry, NULL);
    lbDbgAssertExit(steeralgState.dbgModule, servingBSS.stats);
    servingBSS.bssInfo = stadbEntry_resolveBSSInfo(servingBSS.stats);
    lbDbgAssertExit(steeralgState.dbgModule, servingBSS.bssInfo);
    servingBSS.band =
        wlanif_resolveBandFromChannelNumber(servingBSS.bssInfo->channelId);
    lbDbgAssertExit(steeralgState.dbgModule,
                    servingBSS.band != wlanif_band_invalid);
    servingBSS.bestPHYMode = stadbEntry_getBestPHYMode(entry);
    lbDbgAssertExit(steeralgState.dbgModule,
                    servingBSS.bestPHYMode != wlanif_phymode_invalid);

    // Only need to pick the best channel for 11k measurement
    size_t maxNumBSS = 1;
    lbd_bssInfo_t selectedBSS = {0};

    if (LBD_NOK == stadbEntry_iterateBSSStats(
                entry, steeralgSelect11kChannelCallback, &servingBSS, &maxNumBSS, &selectedBSS)) {
        dbgf(steeralgState.dbgModule, DBGERR,
             "%s: Failed to iterate BSS info for "lbMACAddFmt(":"),
             __func__, lbMACAddData(staAddr->ether_addr_octet));
        return LBD_CHANNEL_INVALID;
    } else if (maxNumBSS == 0) {
        dbgf(steeralgState.dbgModule, DBGDEBUG,
             "%s: No BSS candidate for 802.11k measurement for "lbMACAddFmt(":"),
             __func__, lbMACAddData(staAddr->ether_addr_octet));
        return LBD_CHANNEL_INVALID;
    }

    return selectedBSS.channelId;
}

steeralg_rateSteerEligibility_e steeralg_determineRateSteerEligibility(
    lbd_linkCapacity_t txRate,
    wlanif_band_e band) {
    // Never attempt to do rate based steering with a rate of 0
    if (!txRate) {
        return steeralg_rateSteer_none;
    }

    if ((band == wlanif_band_5g) &&
        (txRate < steeralgState.config.lowTxRateThreshold)) {
        // Eligible for downgrade.
        return steeralg_rateSteer_downgrade;
    } else if ((band == wlanif_band_24g) &&
               (txRate > steeralgState.config.highTxRateThreshold)) {
        // Eligible for upgrade.
        return steeralg_rateSteer_upgrade;
    } else {
        // Rate is neither sufficient for upgrade or downgrade.
        return steeralg_rateSteer_none;
    }
}

/********************************************************************
 * Internal functions
 ********************************************************************/
/**
 * @brief Get a timestamp in seconds for use in delta computations.
 *
 * @return the current time in seconds
 */
static time_t steeralgGetTimestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec;
}

/**
 * @brief Get the metric used to evaluate active clients
 *
 * @pre At this point, the BSS has been selected as an active
 *      steering candidate, so it must have a valid available airtime.
 *      Since estimator will estimate DL rate info before estimating airtime,
 *      the DL rate info must also be valid at this point.
 *
 * The following rules are used to compute metric:
 * bit 31: set if STA has reserved airtime on the BSS
 * bit 0-30: the product of DL rate and available airtime
 *
 * @param [in] entry  STA entry to calculate metric for
 * @param [in] bssHandle  stats handle for the BSS
 * @param [in] bss  BSS entry to calculate metric for
 * @param [in] dlEstimate  estimated Tx rate
 * @param [in] availableAirtime  available airtime on the BSS
 *
 * @return Calculated metric
 */
static u_int32_t steeralgGetActiveClientMetric(stadbEntry_handle_t entry,
                                               stadbEntry_bssStatsHandle_t bssHandle,
                                               const lbd_bssInfo_t *bss,
                                               lbd_linkCapacity_t dlEstimate,
                                               lbd_airtime_t availableAirtime) {
#define METRIC_OFFSET_RESERVED_AIRTIME 31
    lbDbgAssertExit(steeralgState.dbgModule, availableAirtime != LBD_INVALID_AIRTIME);
    lbDbgAssertExit(steeralgState.dbgModule, dlEstimate != LBD_INVALID_LINK_CAP);

    u_int32_t metric = dlEstimate * availableAirtime;
    // Since the DL estimate is in Mbps, there should be no chance for the MSB to be set.
    lbDbgAssertExit(steeralgState.dbgModule, metric >> METRIC_OFFSET_RESERVED_AIRTIME == 0);

    // Prefer BSS on which STA has reserved airtime
    if (stadbEntry_getReservedAirtime(entry, bssHandle) != LBD_INVALID_AIRTIME) {
        metric |= 1 << METRIC_OFFSET_RESERVED_AIRTIME;
    }

    return metric;
#undef METRIC_OFFSET_RESERVED_AIRTIME
}

/**
 * @brief Helper function to compute metric for idle steering candidate BSS
 *
 * The following rules are used to compute metric:
 * bit 0: always set for all candidates
 * bit 31: set if STA has reserved airtime on the BSS
 * bit 30: set if utilization below safety threshold
 * bit 29: set if 5 GHz channel
 * bit 28: set if a channel with higher Tx power for 11ac clients
 *         or if a channel with lower Tx power for non-11ac clients
 * bit 20-27: set with medium utilization measured on this channel
 *
 * @param [in] entry  the entry to find idle steering candidate for
 * @param [in] bssStats  the candidate BSS
 * @param [in] bestPHYMode  the best PHY mode the client supports
 *
 * @return the computed metric
 */
static u_int32_t steeralgComputeIdleSteerMetric(
        stadbEntry_handle_t entry, stadbEntry_bssStatsHandle_t bssStats,
        wlanif_phymode_e bestPHYMode) {
#define METRIC_OFFSET_RESERVED_AIRTIME 31
#define METRIC_OFFSET_SAFETY (METRIC_OFFSET_RESERVED_AIRTIME - 1)
#define METRIC_OFFSET_BAND (METRIC_OFFSET_SAFETY - 1)
#define METRIC_OFFSET_PHY_CAP (METRIC_OFFSET_BAND - 1)
#define METRIC_OFFSET_UTIL (METRIC_OFFSET_PHY_CAP - sizeof(lbd_airtime_t) * 8)
    u_int32_t metric =  steeralgComputeBSSMetric(entry, bssStats,
                                                 wlanif_band_5g, // Always prefer 5 GHz
                                                 bestPHYMode,
                                                 METRIC_OFFSET_BAND,
                                                 METRIC_OFFSET_PHY_CAP,
                                                 METRIC_OFFSET_RESERVED_AIRTIME,
                                                 METRIC_OFFSET_SAFETY,
                                                 METRIC_OFFSET_UTIL);

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(steeralgState.dbgModule, staAddr);
    const lbd_bssInfo_t *bssInfo = stadbEntry_resolveBSSInfo(bssStats);
    lbDbgAssertExit(steeralgState.dbgModule, bssInfo);
    dbgf(steeralgState.dbgModule, DBGDEBUG,
         "%s: " lbBSSInfoAddFmt() "is selected as idle steering candidate with metric 0x%x "
         "for " lbMACAddFmt(":"),
         __func__, lbBSSInfoAddData(bssInfo), metric, lbMACAddData(staAddr->ether_addr_octet));
    return metric;
#undef METRIC_OFFSET_RESERVED_AIRTIME
#undef METRIC_OFFSET_SAFETY
#undef METRIC_OFFSET_BAND
#undef METRIC_OFFSET_PHY_CAP
#undef METRIC_OFFSET_UTIL
}

/**
 * @brief Callback function to check if a BSS is a candidate for idle steering
 *
 * If a BSS is a candidate, it must return a non-zero metric.
 *
 * @pre the STA entry is associated
 *
 * @param [in] entry  the STA entry
 * @param [in] bssHandle  the BSS handle to check
 * @param [in] cookie  currently not used
 *
 * @return the non-zero metric if the BSS is a steering candidate;
 *         otherwise return 0
 */
static u_int32_t steeralgIdleSteerCallback(stadbEntry_handle_t entry,
                                           stadbEntry_bssStatsHandle_t bssHandle,
                                           void *cookie) {
    lbDbgAssertExit(steeralgState.dbgModule, cookie);
    steeralgServingBSSInfo_t *servingBSS = (steeralgServingBSSInfo_t *)cookie;
    if (servingBSS->stats == bssHandle) {
        // Ignore current BSS
        return 0;
    }

    const lbd_bssInfo_t *bssInfo = stadbEntry_resolveBSSInfo(bssHandle);
    lbDbgAssertExit(steeralgState.dbgModule, bssInfo);

    const struct ether_addr *addr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(steeralgState.dbgModule, addr);

    LBD_BOOL isOverloaded = LBD_FALSE;
    if (LBD_NOK == bandmon_isChannelOverloaded(bssInfo->channelId, &isOverloaded) ||
        isOverloaded) {
        // Ignore all overloaded channels
        dbgf(steeralgState.dbgModule, DBGDUMP,
             "%s: " lbBSSInfoAddFmt() " is not a candidate for "
             lbMACAddFmt(":") " due to overload",
             __func__, lbBSSInfoAddData(bssInfo), lbMACAddData(addr));
        return 0;
    }

    wlanif_band_e targetBand = wlanif_resolveBandFromChannelNumber(bssInfo->channelId);
    lbd_rssi_t rssi = LBD_INVALID_RSSI;
    LBD_BOOL isCandidate = LBD_FALSE;

    if (servingBSS->isOverloaded) {
        isCandidate = LBD_TRUE;
    } else { // Current channel is not overloaded
        if (servingBSS->band == wlanif_band_24g &&
            targetBand == wlanif_band_5g) {
            rssi = stadbEntry_getUplinkRSSI(entry, bssHandle, NULL, NULL);
            if (rssi != LBD_INVALID_RSSI &&
                rssi > steeralgState.config.inactRSSIXingThreshold[targetBand]) {
                isCandidate = LBD_TRUE;
            }
        } else if (servingBSS->band == wlanif_band_5g) {
            rssi = stadbEntry_getUplinkRSSI(entry, bssHandle, NULL, NULL);
            if (rssi != LBD_INVALID_RSSI) {
                if (targetBand == wlanif_band_24g &&
                    rssi < steeralgState.config.inactRSSIXingThreshold[targetBand]) {
                    // Idle downgrade
                    isCandidate = LBD_TRUE;
                } else if (steeralgState.config.phyBasedPrioritization &&
                           targetBand == wlanif_band_5g &&
                           rssi > steeralgState.config.inactRSSIXingThreshold[targetBand]) {
                    LBD_BOOL isStrongestChannel = LBD_FALSE;
                    if (LBD_NOK == wlanif_isBSSOnStrongestChannel(
                                       bssInfo, &isStrongestChannel)) {
                        dbgf(steeralgState.dbgModule, DBGERR,
                             "%s: Failed to check Tx power status for " lbBSSInfoAddFmt(),
                             __func__, lbBSSInfoAddData(bssInfo));
                    } else {
                        // Idle upgrade 11ac capable client from weaker 5 GHz channel to
                        // the strongest one, or idle downgrade 11ac non-capable client
                        // from stronger 5 GHz channel to a weaker one
                        isCandidate = (servingBSS->bestPHYMode == wlanif_phymode_vht &&
                                           !servingBSS->isOnStrongest5G &&
                                           isStrongestChannel) ||
                                      (servingBSS->bestPHYMode != wlanif_phymode_vht &&
                                           servingBSS->isOnStrongest5G &&
                                           !isStrongestChannel);
                    }
                }
            }
        }
    }

    if (isCandidate) {
        return steeralgComputeIdleSteerMetric(entry, bssHandle, servingBSS->bestPHYMode);
    } else {
        dbgf(steeralgState.dbgModule, DBGDUMP,
             "%s: " lbBSSInfoAddFmt() " is not a candidate for "
             lbMACAddFmt(":") " due to RSSI %u",
             __func__, lbBSSInfoAddData(bssInfo), lbMACAddData(addr), rssi);
        return 0;
    }
}

/**
 * @brief Determine if a target BSS can be a steering candidate for
 *        STA during offloading
 *
 * Target channel must be able to accommodate the traffic of the client
 * and MCS higher than Th_L5 + Th_MinMCSIncrease if on 5 GHz.
 *
 * Note: To simplify offloading logic, we assume that if the Th_MinMCSIncrease is high
 * enough, the uplink RSSI must be greater than LowTxRateXingThreshold. So RSSI check
 * is skipped here.
 *
 * @param [in] entry  the handle to the STA to offload
 * @param [in] targetBSS  the handle to the target BSS to check
 * @param [in] bssInfo  basic info for target BSS
 * @param [in] dlEstimate  the estimated Tx rate
 * @param [in] deltaSecs  seconds since the Tx rate was estimated
 * @param [out] availableAirtime  available airtime on the BSS
 *
 * @return LBD_TRUE if the target BSS is a steering candidate for offloading;
 *         otherwise return LBD_FALSE
 */
static LBD_BOOL steeralgIsCandidateForOffloadingSTA(
        stadbEntry_handle_t entry, stadbEntry_bssStatsHandle_t targetBSS,
        const lbd_bssInfo_t *bssInfo, lbd_linkCapacity_t dlEstimate,
        time_t deltaSecs, lbd_airtime_t *availableAirtime) {
    wlanif_band_e targetBand = wlanif_resolveBandFromChannelNumber(bssInfo->channelId);
    return (steeralgCanBSSSupportClient(entry, targetBSS, bssInfo, availableAirtime) &&
            (targetBand == wlanif_band_24g ||
             steeralgIsRateAboveThreshold(entry, targetBSS, bssInfo,
                                          steeralgState.config.lowTxRateThreshold +
                                              steeralgState.config.minTxRateIncreaseThreshold,
                                          dlEstimate, deltaSecs)));
}

/**
 * @brief Callback function to check if a BSS is a candidate for
 *        active steering
 *
 * @pre the STA entry is associated
 *
 * @param [in] entry  the STA entry
 * @param [in] bssHandle  the BSS handle to check
 * @param [in] cookie  pointer to steeralgServingBSSInfo_t
 *
 * @return LBD_TRUE if the BSS is a steering candidate; otherwise return LBD_FALSE
 */
static u_int32_t steeralgActiveSteerCallback(stadbEntry_handle_t entry,
                                             stadbEntry_bssStatsHandle_t bssHandle,
                                             void *cookie) {
    lbDbgAssertExit(steeralgState.dbgModule, cookie);
    steeralgServingBSSInfo_t *servingBSS = (steeralgServingBSSInfo_t *)cookie;

    if (servingBSS->stats == bssHandle) {
        // Ignore current BSS
        return 0;
    }

    const lbd_bssInfo_t *bssInfo = stadbEntry_resolveBSSInfo(bssHandle);
    lbDbgAssertExit(steeralgState.dbgModule, bssInfo);

    wlanif_band_e targetBand = wlanif_resolveBandFromChannelNumber(bssInfo->channelId);

    LBD_BOOL isCandidate = LBD_FALSE;
    lbd_airtime_t availableAirtime = LBD_INVALID_AIRTIME;

    time_t deltaSecs = 0xFFFFFFFF;
    lbd_linkCapacity_t dlEstimate = stadbEntry_getFullCapacity(entry, bssHandle, &deltaSecs);

    if (servingBSS->band == wlanif_band_5g) {
        // For a 5 GHz serving BSS, it shall be either for downgrade or for offloading
        if ((servingBSS->rateSteerEligibility == steeralg_rateSteer_downgrade) ||
            (servingBSS->rateSteerEligibility == steeralg_rateSteer_downgradeRSSI)) {
            // Downgrade operation: Must be 2.4GHz BSS that can accommodate the traffic
            if (targetBand == wlanif_band_24g &&
                steeralgCanBSSSupportClient(entry, bssHandle, bssInfo, &availableAirtime)) {
                isCandidate = LBD_TRUE;
            }
        } else { // For offloading
            lbDbgAssertExit(steeralgState.dbgModule, servingBSS->isOverloaded);
            isCandidate = steeralgIsCandidateForOffloadingSTA(
                               entry, bssHandle, bssInfo, dlEstimate,
                               deltaSecs, &availableAirtime);
        }
    } else {
        // For a 2.4 GHz serving BSS, it shall be either for offloading or for upgrade
        if (servingBSS->isOverloaded) {
            isCandidate = steeralgIsCandidateForOffloadingSTA(
                               entry, bssHandle, bssInfo, dlEstimate,
                               deltaSecs, &availableAirtime);
        } else {
            lbDbgAssertExit(steeralgState.dbgModule,
                            servingBSS->rateSteerEligibility == steeralg_rateSteer_upgrade);
            // Upgrade operation: target channel must be able to accommodate the traffic
            // of the client and offer higher MCS rate
            if (targetBand == wlanif_band_5g &&
                steeralgCanBSSSupportClient(entry, bssHandle, bssInfo, &availableAirtime) &&
                steeralgIsRateAboveThreshold(entry, bssHandle, bssInfo, servingBSS->dlRate,
                                             dlEstimate, deltaSecs)) {
                isCandidate = LBD_TRUE;
            }
        }
    }

    if (isCandidate) {
        u_int32_t metric = steeralgGetActiveClientMetric(entry, bssHandle, bssInfo,
                                                         dlEstimate, availableAirtime);
        const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
        lbDbgAssertExit(steeralgState.dbgModule, staAddr);

        dbgf(steeralgState.dbgModule, DBGDEBUG,
             "%s: BSS " lbBSSInfoAddFmt()
             " [metric 0x%x] added as an active steering candidate for "
             lbMACAddFmt(":"), __func__, lbBSSInfoAddData(bssInfo),
             metric, lbMACAddData(staAddr->ether_addr_octet));
        return metric;
    }

    // Not selected as an active steering candidate, the reason should have been printed
    return 0;
}

/**
 * @brief Perform the steering operation
 *
 * @pre There is at least one candidate BSS.
 *
 * @param [in] entry  the STA that needs to be steered
 * @param [in] numBSS  number of candidate BSSes
 * @param [in] bssCandidates  candidate BSSes
 * @param [in] reason  reason for the steer
 *
 * @return LBD_OK if the STA has been successfully steered;
 *         otherwise return LBD_NOK
 */
static LBD_STATUS steeralgDoSteering(stadbEntry_handle_t entry, size_t numBSS,
                                     const lbd_bssInfo_t *bssCandidates,
                                     steerexec_steerReason_e reason) {
    LBD_STATUS result = LBD_NOK;
    LBD_BOOL ignored;
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(steeralgState.dbgModule, staAddr);

    if (LBD_NOK == steerexec_steer(entry, numBSS, bssCandidates, reason,
                                   &ignored)) {
        dbgf(steeralgState.dbgModule, DBGERR,
             "%s: Failed to steer " lbMACAddFmt(":"),
              __func__, lbMACAddData(staAddr->ether_addr_octet));
    } else if (!ignored){
        char prefix[100];
        snprintf(prefix, sizeof(prefix), lbMACAddFmt(":") " is being steered to",
                 lbMACAddData(staAddr->ether_addr_octet));
        lbLogBSSInfoCandidates(steeralgState.dbgModule, DBGINFO,
                               __func__, prefix, numBSS, bssCandidates);
        result = LBD_OK;
    }

    return result;
}

/**
 * @brief Find candidate BSS(es) to steer for an idle client
 *
 * @param [in] entry  the handle to the idle client
 * @param [inout] maxNumBSS  on input, it specifies maximum number of BSS info entries
 *                           allowed; on output, it returns the number of BSS info
 *                           entries populated on success
 * @param [out] servingBSS  information about the serving BSS
 * @param [out] bssCandidates  the BSSes that are eligible to steer to on success
 *
 * @return LBD_NOK if failed to iterate all BSSes; otherwise return LBD_OK
 */
static LBD_STATUS steeralgFindCandidatesForIdleClient(
        stadbEntry_handle_t entry, size_t *maxNumBSS,
        steeralgServingBSSInfo_t *servingBSS,
        lbd_bssInfo_t *bssCandidates) {

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(steeralgState.dbgModule, staAddr);

    servingBSS->stats = stadbEntry_getServingBSS(entry, NULL);
    lbDbgAssertExit(steeralgState.dbgModule, servingBSS->stats);
    servingBSS->bssInfo = stadbEntry_resolveBSSInfo(servingBSS->stats);
    lbDbgAssertExit(steeralgState.dbgModule, servingBSS->bssInfo);
    servingBSS->band =
        wlanif_resolveBandFromChannelNumber(servingBSS->bssInfo->channelId);
    lbDbgAssertExit(steeralgState.dbgModule,
                    servingBSS->band != wlanif_band_invalid);

    if (steeralgState.config.phyBasedPrioritization) {
        servingBSS->bestPHYMode = stadbEntry_getBestPHYMode(entry);
        lbDbgAssertExit(steeralgState.dbgModule,
                        servingBSS->bestPHYMode != wlanif_phymode_invalid);
        if (servingBSS->band == wlanif_band_5g) {
            // When it's associated on 5 GHz, check if it can be upgraded to a
            // stronger 5 GHz channel for 11ac capable clients or downgraded to
            // a weaker 5 GHz channel for 11ac non-capable clients.
            // We do not want to apply this logic on 2.4 GHz, since if the power becomes
            // weaker on 2.4 GHz, it will break some of our assumptions, e.g RSSI mapping
            // between 2.4 GHz and 5 GHz, and trigger more changes.
            if (LBD_NOK == wlanif_isBSSOnStrongestChannel(
                               servingBSS->bssInfo, &servingBSS->isOnStrongest5G)) {
                dbgf(steeralgState.dbgModule, DBGERR,
                     "%s: Failed to check Tx power status for channel %u",
                     __func__, servingBSS->bssInfo->channelId);
                return LBD_NOK;
            }
        }
    }

    if (LBD_NOK == bandmon_isChannelOverloaded(servingBSS->bssInfo->channelId,
                                               &servingBSS->isOverloaded)) {
        dbgf(steeralgState.dbgModule, DBGERR,
             "%s: Failed to get overload status on channel %u for "
             lbMACAddFmt(":"),
             __func__, servingBSS->bssInfo->channelId,
             lbMACAddData(staAddr->ether_addr_octet));
        return LBD_NOK;
    } else if (servingBSS->isOverloaded) {
        // Idle steering will only be triggered after RSSI on all BSSes are valid and
        // recent. So there is no need to check RSSI age here.
        lbd_rssi_t rssi = stadbEntry_getUplinkRSSI(entry, servingBSS->stats, NULL, NULL);
        lbDbgAssertExit(steeralgState.dbgModule, rssi != LBD_INVALID_RSSI);

        if (rssi <= steeralgState.config.rssiSafetyThreshold) {
            dbgf(steeralgState.dbgModule, DBGERR,
                 "%s: No BSS can be idle offloading candidate due to "
                 "serving channel RSSI not high enough (%u dB)",
                 __func__, rssi);
            return LBD_NOK;
        }
    }

    if (LBD_NOK == stadbEntry_iterateBSSStats(
                entry, steeralgIdleSteerCallback, servingBSS, maxNumBSS, bssCandidates)) {
        dbgf(steeralgState.dbgModule, DBGERR,
             "%s: Failed to iterate BSS info for "lbMACAddFmt(":"),
             __func__, lbMACAddData(staAddr->ether_addr_octet));
        return LBD_NOK;
    } else if (*maxNumBSS == 0) {
        dbgf(steeralgState.dbgModule, DBGDEBUG,
             "%s: No BSS candidate for idle steering for "lbMACAddFmt(":"),
             __func__, lbMACAddData(staAddr->ether_addr_octet));
    }

    return LBD_OK;
}

/**
 * @brief Find candidate BSS(es) to steer for an active client
 *
 * @param [in] entry  the handle to the client
 * @param [in] staAddr MAC address of the client
 * @param [in] servingBSS set of parameters for the serving BSS
 * @param [inout] maxNumBSS  on input, it specifies maximum number of BSS info entries
 *                           allowed; on output, it returns the number of BSS info
 *                           entries populated on success
 * @param [out] bssCandidates  the BSSes that are eligible to steer to on success
 *
 * @return LBD_NOK if failed to iterate all BSSes; otherwise return LBD_OK
 */
static LBD_STATUS steeralgFindCandidatesForActiveClient(
        stadbEntry_handle_t entry, const struct ether_addr *staAddr,
        steeralgServingBSSInfo_t *servingBSS,
        size_t *maxNumBSS,
        lbd_bssInfo_t *bssCandidates) {

    if (LBD_NOK == stadbEntry_iterateBSSStats(
                entry, steeralgActiveSteerCallback, servingBSS, maxNumBSS, bssCandidates)) {
        dbgf(steeralgState.dbgModule, DBGERR,
             "%s: Failed to iterate BSS info for "lbMACAddFmt(":"),
             __func__, lbMACAddData(staAddr->ether_addr_octet));
        return LBD_NOK;
    } else if (!(*maxNumBSS)) {
        dbgf(steeralgState.dbgModule, DBGDEBUG,
             "%s: No BSS candidate for rate based active steering for "lbMACAddFmt(":"),
             __func__, lbMACAddData(staAddr->ether_addr_octet));
    }

    return LBD_OK;
}

/**
 * @brief React to the event indicating overload status change
 *
 * @param [in] event  the event received
 */
static void steeralgHandleOverloadChangeEvent(struct mdEventNode *event) {
    const bandmon_overloadChangeEvent_t *overloadChangeEvent =
        (const bandmon_overloadChangeEvent_t *) event->Data;

    lbDbgAssertExit(steeralgState.dbgModule, overloadChangeEvent);

    steeralgHandleUtilizationUpdate(overloadChangeEvent->numOverloadedChannels);
}

/**
 * @brief React to the event indicating utilization has been updated
 *
 * @param [in] event  the event received
 */
static void steeralgHandleUtilizationUpdateEvent(struct mdEventNode *event) {
    const bandmon_utilizationUpdateEvent_t *utilizationUpdateEvent =
        (const bandmon_utilizationUpdateEvent_t *) event->Data;

    lbDbgAssertExit(steeralgState.dbgModule, utilizationUpdateEvent);

    steeralgHandleUtilizationUpdate(utilizationUpdateEvent->numOverloadedChannels);
}

/**
 * @brief Handle utilization and overloaded channels update
 *
 * @param [in] numOverloadedChannels  number of overloaded channels reported
 *                                    by bandmon
 */
static void steeralgHandleUtilizationUpdate(size_t numOverloadedChannels) {
    if (steeralgState.offloadState.inProgress) {
        // This is possibly due to 802.11k measurement take too long, stop offloading,
        // try on next utilization update.
        steeralgFinishOffloading(LBD_TRUE /* requestOneShotUtil */);
    }

    if (bandmon_isInSteeringBlackout()) {
        // When T_settleDown timer is running, do nothing
        return;
    }

    if (!numOverloadedChannels) {
        steeralgResetServedChannels();
    } else if (!steeralgState.offloadState.airtimeEstimatePending) {
        steeralgOffloadOverloadedChannel(numOverloadedChannels);
    }
}

/**
 * @brief Check the rate and RSSI to determine if this STA is
 *        eligible for active steering
 *
 * @param [in] entry  STA entry to check
 * @param [in] addr MAC address of STA
 * @param [in] servingBSS info about STA association
 * @param [out] rssi  filled in with the uplink RSSI, or
 *                    LBD_INVALID_RSSI if it is not measured or
 *                    invalid
 *
 * @return enum code indicating if STA is eligible for upgrade,
 *         downgrade, or none.
 */
steeralg_rateSteerEligibility_e steeralgEligibleActiveSteerRateAndRSSI(
    stadbEntry_handle_t entry,
    const struct ether_addr *addr,
    steeralgServingBSSInfo_t *servingBSS,
    lbd_rssi_t *rssi) {
    // Check the rate
    steeralg_rateSteerEligibility_e eligibility =
        steeralg_determineRateSteerEligibility(servingBSS->dlRate, servingBSS->band);

    if (((servingBSS->band == wlanif_band_5g) &&
         (eligibility == steeralg_rateSteer_downgrade)) ||
        ((servingBSS->band == wlanif_band_24g) &&
         (eligibility == steeralg_rateSteer_none))) {
        // For downgrade, need either rate or RSSI to be eligible
        // For upgrade, need rate and RSSI to be eligible
        // For either of these cases, don't need to check the RSSI as well
        *rssi = LBD_INVALID_RSSI;
        return eligibility;
    }

    // Check the RSSI
    time_t ageSecs = 0xFFFFFFFF;
    u_int8_t probeCount = 0;
    *rssi = stadbEntry_getUplinkRSSI(entry, servingBSS->stats,
                                     &ageSecs, &probeCount);
    if (*rssi == LBD_INVALID_RSSI ||
        ageSecs > steeralgState.config.freshnessLimit ||
        probeCount) {
        *rssi = LBD_INVALID_RSSI;
        // RSSI is either too old or invalid
        return steeralg_rateSteer_none;
    }

    if ((servingBSS->band == wlanif_band_5g) &&
        (*rssi < steeralgState.config.lowRateRSSIXingThreshold)) {
        // Eligible for downgrade.
        return steeralg_rateSteer_downgradeRSSI;
    } else if ((servingBSS->band == wlanif_band_24g) &&
               (*rssi > steeralgState.config.highRateRSSIXingThreshold)) {
        // Eligible for upgrade.
        return steeralg_rateSteer_upgrade;
    } else {
        // RSSI is neither sufficient for upgrade or downgrade.
        return steeralg_rateSteer_none;
    }
}

/**
 * @brief React to the event indicating metric collection is
 *        complete for a single STA.
 *
 * @param [in] event  the event received
 */
static void steeralgHandleSTAMetricsCompleteEvent(struct mdEventNode *event) {
    const estimator_staDataMetricsCompleteEvent_t *metricEvent =
        (const estimator_staDataMetricsCompleteEvent_t *)event->Data;

    lbDbgAssertExit(steeralgState.dbgModule, metricEvent);

    // Get the stadb entry for the event
    stadbEntry_handle_t entry = stadb_find(&metricEvent->addr);
    if (!entry) {
        // Unknown MAC address
        dbgf(steeralgState.dbgModule, DBGERR,
             "%s: Received STA metrics complete event from unknown MAC address: "
             lbMACAddFmt(":"),
             __func__, lbMACAddData(metricEvent->addr.ether_addr_octet));
        return;
    }

    lbd_airtime_t occupiedAirtime = LBD_INVALID_AIRTIME,
                  offloadedAirtime = LBD_INVALID_AIRTIME;
    LBD_BOOL offloadEntryComplete =
        steeralgIsSTAMetricsTriggeredByOffloading(entry, &occupiedAirtime);

    do {
        if (metricEvent->result != LBD_OK) {
            // Metric collection was not successful
            break;
        }

        steeralgServingBSSInfo_t servingBSS;

        servingBSS.stats = stadbEntry_getServingBSS(entry, NULL);
        if (!servingBSS.stats) {
            // Ignore disassociated STA
            break;
        }

        servingBSS.bssInfo = stadbEntry_resolveBSSInfo(servingBSS.stats);
        lbDbgAssertExit(steeralgState.dbgModule, servingBSS.bssInfo);
        servingBSS.band =
            wlanif_resolveBandFromChannelNumber(servingBSS.bssInfo->channelId);
        lbDbgAssertExit(steeralgState.dbgModule, servingBSS.band != wlanif_band_invalid);

        if (LBD_NOK == bandmon_isChannelOverloaded(servingBSS.bssInfo->channelId,
                                                   &servingBSS.isOverloaded)) {
            dbgf(steeralgState.dbgModule, DBGERR,
                 "%s: Failed to get overload status for serving channel %u",
                 __func__, servingBSS.bssInfo->channelId);
            break;
        }

        // Get the last measured rate.
        time_t deltaSecs;
        servingBSS.dlRate = stadbEntry_getFullCapacity(entry, servingBSS.stats,
                                                       &deltaSecs);
        if (servingBSS.dlRate == LBD_INVALID_LINK_CAP) {
            dbgf(steeralgState.dbgModule, DBGERR,
                 "%s: Couldn't get Tx rate for MAC address: "
                 lbMACAddFmt(":"),
                 __func__, lbMACAddData(metricEvent->addr.ether_addr_octet));
            break;
        }

        if (deltaSecs > steeralgState.config.freshnessLimit) {
            // Rate value is too old.
            dbgf(steeralgState.dbgModule, DBGINFO,
                 "%s: Collected metrics for MAC address: " lbMACAddFmt(":")
                  ", but Tx rate measurement is stale, will not steer",
                 __func__, lbMACAddData(metricEvent->addr.ether_addr_octet));
            break;
        }

        lbd_rssi_t rssi;
        servingBSS.rateSteerEligibility =
            steeralgEligibleActiveSteerRateAndRSSI(entry,
                                                   &metricEvent->addr,
                                                   &servingBSS,
                                                   &rssi);
        if (servingBSS.rateSteerEligibility == steeralg_rateSteer_none &&
            !servingBSS.isOverloaded) {
            dbgf(steeralgState.dbgModule, DBGINFO,
                 "%s: Collected metrics for MAC address: " lbMACAddFmt(":")
                 ", but it is not a candidate for either offloading or MCS "
                 "based steering (rate %u, rssi %u), will not steer",
                 __func__, lbMACAddData(metricEvent->addr.ether_addr_octet),
                 servingBSS.dlRate, rssi);
            break;
        }

        if (bandmon_isInSteeringBlackout()) {
            if (steeralgState.offloadState.inProgress) {
                steeralgFinishOffloading(LBD_TRUE /* requestOneShotUtil */);
            }
            if ((servingBSS.rateSteerEligibility != steeralg_rateSteer_downgrade) &&
                (servingBSS.rateSteerEligibility != steeralg_rateSteer_downgradeRSSI)) {
                dbgf(steeralgState.dbgModule, DBGINFO,
                     "%s: Only allow downgrade operation while in blackout period",
                     __func__);
                return;
            }
        }

        size_t maxNumBSS = STEEREXEC_MAX_CANDIDATES;
        lbd_bssInfo_t candidates[STEEREXEC_MAX_CANDIDATES];
        if (LBD_NOK ==
            steeralgFindCandidatesForActiveClient(entry, &metricEvent->addr,
                                                  &servingBSS, &maxNumBSS,
                                                  candidates) || !maxNumBSS) {
            break;
        }
        lbDbgAssertExit(steeralgState.dbgModule, maxNumBSS <= STEEREXEC_MAX_CANDIDATES);

        if (LBD_NOK == steeralgUpdateCandidateProjectedAirtime(
                           entry,
                           (servingBSS.rateSteerEligibility ==
                            steeralg_rateSteer_downgrade ||
                            servingBSS.rateSteerEligibility ==
                            steeralg_rateSteer_downgradeRSSI),
                           candidates, maxNumBSS)) {
            break;
        }

        // Determine the reason for the steer
        steerexec_steerReason_e reason;
        if (servingBSS.rateSteerEligibility == steeralg_rateSteer_downgrade) {
            reason = steerexec_steerReasonActiveDowngradeRate;
        } else if (servingBSS.rateSteerEligibility == steeralg_rateSteer_downgradeRSSI) {
            reason = steerexec_steerReasonActiveDowngradeRSSI;
        } else if (servingBSS.rateSteerEligibility == steeralg_rateSteer_upgrade) {
            reason = steerexec_steerReasonActiveUpgrade;
        } else {
            reason = steerexec_steerReasonActiveOffload;
        }

        if (LBD_NOK == steeralgDoSteering(entry, maxNumBSS, candidates, reason)) {
            break;
        }

        offloadedAirtime = occupiedAirtime;
    } while (0);

    if (steeralgState.offloadState.inProgress) {
        steeralgContinueSteerActiveClientsOverload(offloadedAirtime, offloadEntryComplete);
    }
}

/**
 * @brief Add projected airtime to all candidate BSSes when
 *        trying to steer a client
 *
 * @param [in] entry  the handle to the client
 * @param [in] isDowngrade  whether the steer is caused by downgrade
 * @param [in] candidateList  all candidate BSSes to add projected airtime
 * @param [in] maxNumBSS  number of BSSes in candidateList
 *
 * @return LBD_OK if estimated airtime has been added to all candidates successfully;
 *         otherwise return LBD_NOK
 */
static LBD_STATUS steeralgUpdateCandidateProjectedAirtime(
        stadbEntry_handle_t entry, LBD_BOOL isDowngrade,
        const lbd_bssInfo_t *candidateList, size_t maxNumBSS) {
    size_t i = 0;
    // Only allow projected airtime go above threshold for downgrade scenario
    LBD_BOOL allowAboveSafety = isDowngrade;
    for (i = 0; i < maxNumBSS; i++) {
        stadbEntry_bssStatsHandle_t bssHandle =
            stadbEntry_findMatchBSSStats(entry, &candidateList[i]);
        lbDbgAssertExit(steeralgState.dbgModule, bssHandle);

        lbd_airtime_t expectedAirtime = stadbEntry_getAirtime(entry, bssHandle, NULL);
        lbDbgAssertExit(steeralgState.dbgModule, expectedAirtime != LBD_INVALID_AIRTIME);

        if (LBD_NOK == bandmon_addProjectedAirtime(candidateList[i].channelId,
                                                   expectedAirtime,
                                                   allowAboveSafety)) {
            dbgf(steeralgState.dbgModule, DBGERR,
                 "%s: Failed to add projected airtime [%u%%] for BSS " lbBSSInfoAddFmt(),
                 __func__, expectedAirtime, lbBSSInfoAddData(&candidateList[i]));

            return LBD_NOK;
        }
    }
    return LBD_OK;
}

/**
 * @brief Reset served channel list for offloading
 */
static void steeralgResetServedChannels(void) {
    memset(steeralgState.servedChannels, 0,
           sizeof(steeralgState.servedChannels));
    size_t i;
    for (i = 0; i < WLANIF_MAX_RADIOS; ++i) {
        steeralgState.servedChannels[i].channelId = LBD_CHANNEL_INVALID;
    }
}

/**
 * @brief Offload overloaded channels by steering qualified active clients
 *
 * @pre at least one channel is overloaded
 *
 * @param [in] numOverloadedChannels  number of overloaded channels
 */
static void steeralgOffloadOverloadedChannel(size_t numOverloadedChannels) {
    size_t overloadedChannelCount = 0, numChannels = 0;
    lbd_channelId_t channels[WLANIF_MAX_RADIOS], overloadedChannels[WLANIF_MAX_RADIOS];

    numChannels = wlanif_getChannelList(channels, WLANIF_MAX_RADIOS);
    if (numChannels < numOverloadedChannels) {
        dbgf(steeralgState.dbgModule, DBGERR, "%s: Expect at least %u active channels, get %u",
             __func__, numOverloadedChannels, numChannels);
        return;
    }

    size_t i = 0;
    for (i = 0; i < numChannels; ++i) {
        LBD_BOOL isOverloaded = LBD_FALSE;
        if (LBD_OK == bandmon_isChannelOverloaded(channels[i], &isOverloaded) &&
            isOverloaded) {
            overloadedChannels[overloadedChannelCount++] = channels[i];
        }
    }

    if (overloadedChannelCount != numOverloadedChannels) {
        dbgf(steeralgState.dbgModule, DBGERR, "%s: Expect %u overloaded channels, get %u",
             __func__, numOverloadedChannels, overloadedChannelCount);
        return;
    }

    lbd_channelId_t overloadedSrcChannel =
        steeralgSelectOverloadedChannel(numOverloadedChannels, overloadedChannels);

    if (LBD_NOK == estimator_estimatePerSTAAirtimeOnChannel(overloadedSrcChannel)) {
        dbgf(steeralgState.dbgModule, DBGERR, "%s: Failed to request airtime estimate on channel %u",
             __func__, overloadedSrcChannel);
    } else {
        dbgf(steeralgState.dbgModule, DBGINFO, "%s: Requested airtime estimate on channel %u",
             __func__, overloadedSrcChannel);
        steeralgState.offloadState.airtimeEstimatePending = LBD_TRUE;
    }
}

/**
 * @brief Select one overloaded channel to do offloading
 *
 * @param [in] numChannels  number of channels in channelList
 * @param [in] channelList  list of overloaded channels
 */
static lbd_channelId_t steeralgSelectOverloadedChannel(size_t numChannels,
                                                       const lbd_channelId_t *channelList) {
    lbd_channelId_t selectedChannel = LBD_CHANNEL_INVALID;
    if (numChannels == 1) {
        // When there is only one overloaded channel, select it
        selectedChannel = channelList[0];
    } else {
        // When there are multiple overloaded channel, select based on last
        // serving time and load.
        lbd_channelId_t notServedChannel = LBD_CHANNEL_INVALID,
                        oldestServedChannel = LBD_CHANNEL_INVALID;
        lbd_airtime_t mostLoadedUtil = 0;
        size_t i;
        time_t oldestServedTime;

        for (i = 0; i < numChannels; ++i) {
            time_t lastServedTime;
            if (!steeralgIsChannelServedBefore(channelList[i], &lastServedTime)) {
                lbd_airtime_t util = bandmon_getMeasuredUtilization(channelList[i]);
                if (LBD_CHANNEL_INVALID == notServedChannel ||
                    mostLoadedUtil < util) {
                    notServedChannel = channelList[i];
                    mostLoadedUtil = util;
                }
            } else if (LBD_CHANNEL_INVALID == oldestServedChannel ||
                       lastServedTime < oldestServedTime) {
                oldestServedChannel = channelList[i];
                oldestServedTime = lastServedTime;
            }
        }

        selectedChannel = (notServedChannel != LBD_CHANNEL_INVALID) ?
                              notServedChannel : oldestServedChannel;
    }
    lbDbgAssertExit(steeralgState.dbgModule,
                    selectedChannel != LBD_CHANNEL_INVALID);

    steeralgAddChannelToServedChannels(selectedChannel);

    return selectedChannel;
}

/**
 * @brief Check if a channel has been served before
 *
 * @param [in] channelId  the channel to check
 * @param [out] lastServedTime  the timestamp of when the channel
 *                              was served last time if any
 *
 * @return LBD_TRUE if the channel has been served before, otherwise return LBD_FALSE
 */
static LBD_BOOL steeralgIsChannelServedBefore(lbd_channelId_t channelId,
                                              time_t *lastServedTime) {
    size_t j;
    for (j = 0; j < WLANIF_MAX_RADIOS; ++j) {
        if (LBD_CHANNEL_INVALID == steeralgState.servedChannels[j].channelId) {
            continue;
        } else if (channelId == steeralgState.servedChannels[j].channelId) {
            *lastServedTime = steeralgState.servedChannels[j].lastServingTime;
            return LBD_TRUE;
        }
    }

    return LBD_FALSE;
}

/**
 * @brief Add selected overloaded channel to served channel list
 *
 * If the channel already exists in the list, update timestamp;
 * otherwise, add it to the list.
 *
 * @param [in] channelId  the channel to be added
 */
static void steeralgAddChannelToServedChannels(lbd_channelId_t channelId) {
    size_t i, entryIdx = WLANIF_MAX_RADIOS;
    for (i = 0; i < WLANIF_MAX_RADIOS; ++i) {
        if (LBD_CHANNEL_INVALID == steeralgState.servedChannels[i].channelId) {
            // When there is an empty entry, remember it but still looking for a matching entry
            entryIdx = i;
        } else if (channelId == steeralgState.servedChannels[i].channelId) {
            // When there is a matching entry, do not look further
            entryIdx = i;
            break;
        }
    }

    lbDbgAssertExit(steeralgState.dbgModule, entryIdx < WLANIF_MAX_RADIOS);
    steeralgState.servedChannels[entryIdx].channelId = channelId;
    steeralgState.servedChannels[entryIdx].lastServingTime = steeralgGetTimestamp();
}

/**
 * @brief React to the event indicating per STA airtime estimate is complete
 *
 * @param [in] event  the event received
 */
static void steeralgHandlePerSTAAirtimeCompleteEvent(struct mdEventNode *event) {
    const estimator_perSTAAirtimeCompleteEvent_t *airtimeCompleteEvent =
        (const estimator_perSTAAirtimeCompleteEvent_t *) event->Data;

    lbDbgAssertExit(steeralgState.dbgModule, airtimeCompleteEvent);
    steeralgState.offloadState.airtimeEstimatePending = LBD_FALSE;

    if (airtimeCompleteEvent->channelId == LBD_CHANNEL_INVALID) {
        dbgf(steeralgState.dbgModule, DBGERR,
             "%s: Received perSTAAirtimeComplete event on invalid channel",
             __func__);
        return;
    }

    if (steeralgState.offloadState.inProgress) {
        dbgf(steeralgState.dbgModule, DBGERR,
             "%s: Unexpected perSTAAirtimeComplete event on channel %u "
             "due to offloading channel %u in progress",
             __func__, airtimeCompleteEvent->channelId,
             steeralgState.offloadState.channelId);
        return;
    } else if (!airtimeCompleteEvent->numSTAsEstimated) {
        dbgf(steeralgState.dbgModule, DBGINFO,
             "%s: Ignore perSTAAirtimeComplete event on channel %u "
             "due to no STA's airtime was estimated",
             __func__, airtimeCompleteEvent->channelId);
        // This should happen rarely, in the situation where the potential
        // candidate is still in 11k prohibit period. Request a new utilization
        // update to help find new steering opportunities
        steeralgFinishOffloading(LBD_TRUE /* requestOneShotUtil */);
        return;
    }

    if (bandmon_isInSteeringBlackout()) {
        dbgf(steeralgState.dbgModule, DBGINFO,
             "%s: Ignore perSTAAirtimeComplete event on channel %u "
             "due to T_settleDown timer is still running",
             __func__, airtimeCompleteEvent->channelId);
        return;
    }

    LBD_BOOL isOverloaded = LBD_FALSE;
    if (LBD_NOK == bandmon_isChannelOverloaded(airtimeCompleteEvent->channelId, &isOverloaded) ||
        !isOverloaded) {
        dbgf(steeralgState.dbgModule, DBGDEBUG,
             "%s: Ignore perSTAAirtimeComplete event on channel %u "
             "due to channel not overloaded or overload status is unknown",
             __func__, airtimeCompleteEvent->channelId);
        return;
    }

    // It's possible that some client's airtime is not estimated but still recent,
    // give us some extra headroom to reduce the chance of memory reallocation
    size_t numCandidatesAllocated = airtimeCompleteEvent->numSTAsEstimated + 5;
    steeralgState.offloadState.candidateList =
        calloc(numCandidatesAllocated, sizeof(steeralgOffloadingCandidateEntry_t));
    if (!steeralgState.offloadState.candidateList) {
        dbgf(steeralgState.dbgModule, DBGERR,
             "%s: Failed to allocate memory for offloading candidates",
             __func__);
        return;
    }

    do {
        steeralgSelectOffloadingCandidatesParams_t params = {
            airtimeCompleteEvent->channelId, numCandidatesAllocated,
            LBD_FALSE /* hasStrongerChannel5G */
        };
        if (steeralgState.config.phyBasedPrioritization &&
            wlanif_band_5g == wlanif_resolveBandFromChannelNumber(
                                  airtimeCompleteEvent->channelId)) {
            if (LBD_NOK == wlanif_isStrongestChannel(airtimeCompleteEvent->channelId,
                                                     &params.isStrongestChannel5G)) {
                dbgf(steeralgState.dbgModule, DBGERR,
                     "%s: Failed to check Tx power status on channel %u",
                     __func__, airtimeCompleteEvent->channelId);
                return;
            }
        }

        if (LBD_NOK == stadb_iterate(steeralgSelectOffloadingCandidateCB, &params)) {
            dbgf(steeralgState.dbgModule, DBGERR, "%s: Failed to iterate over STA database",
                 __func__);
            break;
        }

        if (steeralgState.offloadState.numCandidates) {
            steeralgSortOffloadCandidates();
            // Start offloading process
            steeralgState.offloadState.inProgress = LBD_TRUE;
            steeralgState.offloadState.channelId = airtimeCompleteEvent->channelId;
            steeralgState.offloadState.headIdx = 0;
            // No offloaded airtime and pending data measurement at start
            steeralgContinueSteerActiveClientsOverload(LBD_INVALID_AIRTIME,
                                                       LBD_TRUE /* lastComplete */);
        } else {
            dbgf(steeralgState.dbgModule, DBGDEBUG, "%s: No candidates to offload channel %u",
                 __func__, params.channelId);
            break;
        }

        return;
    } while(0);

    steeralgFinishOffloading(LBD_TRUE /* requestOneShotUtil */);
}

/**
 * @brief Sort all offload candidates based on metrics in descending order
 */
static void steeralgSortOffloadCandidates(void) {
    qsort(steeralgState.offloadState.candidateList,
          steeralgState.offloadState.numCandidates,
          sizeof(steeralgOffloadingCandidateEntry_t),
          steeralgCompareOffloadCandidates);
}

/**
 * @brief Helper function used by qsort() to compare two offload candidates
 *
 * The higher metric, the higher priority the candidate has.
 *
 * @param [in] candidate1  first candidate
 * @param [in] candidate2  second candidate
 *
 * @return the difference of metrics of two candidate STAs
 */
static int steeralgCompareOffloadCandidates(const void *candidate1, const void *candidate2) {
    const steeralgOffloadingCandidateEntry_t *entry1 =
        (const steeralgOffloadingCandidateEntry_t *)candidate1;
    const steeralgOffloadingCandidateEntry_t *entry2 =
        (const steeralgOffloadingCandidateEntry_t *)candidate2;

    return entry2->metric - entry1->metric;
}

/**
 * @brief Callback function for iterating station database for offloading candidate
 *
 * Clients that are active steering eligible will be added to the candidate list
 * sorted by descending estimated airtime.
 *
 * @param [in] entry  current STA entry to check
 * @param [inout] cookie  @see steeralgSelectOffloadingCandidatesParams_t for details
 */
static void steeralgSelectOffloadingCandidateCB(stadbEntry_handle_t entry,
                                                void *cookie) {
    steeralgSelectOffloadingCandidatesParams_t *params =
        (steeralgSelectOffloadingCandidatesParams_t *) cookie;
    lbDbgAssertExit(steeralgState.dbgModule, params);

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(steeralgState.dbgModule, staAddr);

    stadbEntry_bssStatsHandle_t bssStats = stadbEntry_getServingBSS(entry, NULL);
    if (!bssStats) {
        dbgf(steeralgState.dbgModule, DBGDUMP,
             "%s: " lbMACAddFmt(":") " is not an offloading candidate for channel %u "
             "due to not associated",
             __func__, lbMACAddData(staAddr->ether_addr_octet), params->channelId);
        return;
    }

    const lbd_bssInfo_t *bss = stadbEntry_resolveBSSInfo(bssStats);
    lbDbgAssertExit(steeralgState.dbgModule, bss);
    if (bss->channelId != params->channelId) {
        dbgf(steeralgState.dbgModule, DBGDUMP,
             "%s: " lbMACAddFmt(":") " is not an offloading candidate for channel %u "
             "due to associated on different channel [%u]",
             __func__, lbMACAddData(staAddr->ether_addr_octet), params->channelId,
             bss->channelId);
        return;
    }

    LBD_BOOL isActive = LBD_FALSE;
    if (LBD_NOK == stadbEntry_getActStatus(entry, &isActive, NULL) ||
        !isActive) {
        dbgf(steeralgState.dbgModule, DBGDUMP,
             "%s: " lbMACAddFmt(":") " is not an offloading candidate for channel %u "
             "due to not active or activity status unknown",
             __func__, lbMACAddData(staAddr->ether_addr_octet), params->channelId);
        return;
    }

    if (steerexec_steerEligibility_active !=
            steerexec_determineSteeringEligibility(entry)) {
        dbgf(steeralgState.dbgModule, DBGDEBUG,
             "%s: " lbMACAddFmt(":") " is not an offloading candidate for channel %u "
             "due to not eligible for active steering",
             __func__, lbMACAddData(staAddr->ether_addr_octet), params->channelId);
        return;
    }

    time_t ageSecs = 0xFFFFFFFF;
    lbd_airtime_t airtime = stadbEntry_getAirtime(entry, bssStats, &ageSecs);
    if (LBD_INVALID_AIRTIME == airtime ||
        ageSecs > steeralgState.config.freshnessLimit) {
        dbgf(steeralgState.dbgModule, DBGDEBUG,
             "%s: " lbMACAddFmt(":") " is not an offloading candidate for channel %u "
             "due to invalid or old airtime ([%u%%] %lu seconds)",
             __func__, lbMACAddData(staAddr->ether_addr_octet), params->channelId,
             airtime, ageSecs);
        return;
    }

    steeralgRecordOffloadingCandidate(entry, params, airtime);
}

/**
 * @brief Add a client to offloading candidate list
 *
 * It will resize the candidate array if there are more candidates than requested.
 *
 * @param [in] entry  the handle to the client
 * @param [inout] params  callback parameters containing offload candidates list selected
 * @param [in] airtime  the estimated airtime of this client
 */
static void steeralgRecordOffloadingCandidate(
        stadbEntry_handle_t entry, steeralgSelectOffloadingCandidatesParams_t *params,
        lbd_airtime_t airtime) {
    if (steeralgState.offloadState.numCandidates == params->numCandidatesAllocated) {
        // If there is no enough space, reallocate memory.
        // This will only happen if there are more than five clients
        // getting their airtime estimation through full data rate estimation
        // in last freshnessLimit (5) seconds. So the chance of this operation
        // should be very low.
        params->numCandidatesAllocated += 5;
        steeralgOffloadingCandidateEntry_t *tempCandidateList =
            (steeralgOffloadingCandidateEntry_t *)realloc(
                    steeralgState.offloadState.candidateList,
                    sizeof(lbd_bssInfo_t) * params->numCandidatesAllocated);
        if (!tempCandidateList) {
            dbgf(steeralgState.dbgModule, DBGERR,
                 "%s: Failed to reallocate memory for offload candidates",
                 __func__);
            params->numCandidatesAllocated -= 5;
            return;
        } else {
            steeralgState.offloadState.candidateList = tempCandidateList;
        }
    }

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(steeralgState.dbgModule, staAddr);

    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(params->channelId);
    lbDbgAssertExit(steeralgState.dbgModule, band != wlanif_band_invalid);

    steeralgOffloadingCandidateEntry_t *curEntry =
        &steeralgState.offloadState.candidateList[steeralgState.offloadState.numCandidates];
    curEntry->entry = entry;
    curEntry->metric = airtime;
    if (steeralgState.config.phyBasedPrioritization) {
        wlanif_phymode_e bestPHYMode = stadbEntry_getBestPHYMode(entry);
        LBD_BOOL preferedCandidate = LBD_FALSE;
        switch (bestPHYMode) {
            case wlanif_phymode_basic:
            case wlanif_phymode_ht:
                // Prefer 11n and basic clients if offloading stronger
                // 5 GHz channel
                preferedCandidate = (band == wlanif_band_5g) &&
                                    params->isStrongestChannel5G;
                break;
            case wlanif_phymode_vht:
                // Prefer 11ac clients if offloading 2.4 GHz or
                // weaker 5 GHz channel
                preferedCandidate = (band == wlanif_band_24g) ||
                                    !params->isStrongestChannel5G;
                break;
            default:
                // This should never happen now.
                dbgf(steeralgState.dbgModule, DBGERR,
                     "%s: " lbMACAddFmt(":") " unknown PHY mode %u",
                     __func__, lbMACAddData(staAddr->ether_addr_octet), bestPHYMode);
                break;
        }
        curEntry->metric |=
            preferedCandidate ? 1 << STEERALG_OFFLOADING_CANDIDATE_PREFER_BIT : 0;
    }
    ++steeralgState.offloadState.numCandidates;

    dbgf(steeralgState.dbgModule, DBGDEBUG,
         "%s: " lbMACAddFmt(":") " [%u%%][metric 0x%04x] is an offloading candidate for channel %u",
         __func__, lbMACAddData(staAddr->ether_addr_octet), airtime,
         curEntry->metric, params->channelId);
}

/**
 * @brief Finish offloading process
 *
 * Free allocated candidate list and clear offloading state. If not triggered
 * by fini, it will request one shot medium utilization event to get informed
 * of new measurement.
 *
 * @param [in] requestOneShotUtil  whether to request one shot
 *                                 medium utilization event
 */
static void steeralgFinishOffloading(LBD_BOOL requestOneShotUtil) {
    free(steeralgState.offloadState.candidateList);
    memset(&steeralgState.offloadState, 0, sizeof(steeralgState.offloadState));
    if (requestOneShotUtil) {
        bandmon_enableOneShotUtilizationEvent();
    }
}

/**
 * @brief Try to steer next active client listed in candidate list,
 *        until enough have been steered to mitigate overload condition
 *
 * @param [in] offloadedAirtime  the airtime offloaded from moving previous client
 * @param [in] lastComplete  whether offloading last entry has completed, if not,
 *                           it means there is a measurement pending, we may want to
 *                           avoid sending too many concurrent measurement requests
 */
static void steeralgContinueSteerActiveClientsOverload(lbd_airtime_t offloadedAirtime,
                                                       LBD_BOOL lastComplete) {
    if (offloadedAirtime != LBD_INVALID_AIRTIME) {
        steeralgState.offloadState.totalAirtimeOffloaded += offloadedAirtime;
    }

    LBD_BOOL isBelow;
    if (LBD_NOK == bandmon_isExpectedBelowSafety(steeralgState.offloadState.channelId,
                                                 steeralgState.offloadState.totalAirtimeOffloaded,
                                                 &isBelow)) {
        dbgf(steeralgState.dbgModule, DBGERR,
             "%s: Failed to check if the MU on channel %u is expected to go below safety threshold",
             __func__, steeralgState.offloadState.channelId);
        steeralgFinishOffloading(LBD_TRUE /* requestOneShotUtil */);
        return;
    } else if (isBelow) {
        dbgf(steeralgState.dbgModule, DBGINFO,
             "%s: Enough clients have been steered from channel %u, stop offloading",
             __func__, steeralgState.offloadState.channelId);
        steeralgFinishOffloading(LBD_TRUE /* requestOneShotUtil */);
        return;
    }

    if (!lastComplete) { return; }

    do {
        stadbEntry_handle_t entry = steeralgState.offloadState.candidateList[
                                        steeralgState.offloadState.headIdx].entry;
        if (entry &&
            LBD_OK == estimator_estimateSTADataMetrics(entry)) {
            return;
        }

        // If entry current head is not valid (probably due to concurrent
        // MCS bases steering) or failed to request STA metrics, continue
        // to next entry if any
        ++steeralgState.offloadState.headIdx;
    } while (steeralgState.offloadState.headIdx < steeralgState.offloadState.numCandidates);

    // If it reaches here, there must be no more candidate, finish offloading
    steeralgFinishOffloading(LBD_TRUE /* requestOneShotUtil */);
}

/**
 * @brief Check if a full data metric report is triggered by offloading
 *
 * If the entry is in offloading candidate list, the entry will be marked
 * as processed and its occupied airtime will be returned.
 *
 * @param [in] entry  the handle to the STA
 * @param [out] occupiedAirtime  the occupied airtime if the STA is an offloading
 *                               candidate, otherwise LBD_INVALID_AIRTIME
 *
 * @return LBD_TRUE if the STA is at the head of offloading candidate list;
 *         otherwise return LBD_FALSE
 */
static LBD_BOOL steeralgIsSTAMetricsTriggeredByOffloading(
        stadbEntry_handle_t entry, lbd_airtime_t *occupiedAirtime) {
    *occupiedAirtime = LBD_INVALID_AIRTIME;
    LBD_BOOL complete = LBD_FALSE;
    if (!steeralgState.offloadState.inProgress) {
        return complete;
    }

    size_t entryIdx = steeralgState.offloadState.numCandidates;
    if (entry == steeralgState.offloadState.candidateList[
                     steeralgState.offloadState.headIdx].entry) {
        entryIdx = steeralgState.offloadState.headIdx;
        ++steeralgState.offloadState.headIdx;
        complete = LBD_TRUE;
    } else {
        for (entryIdx = steeralgState.offloadState.headIdx;
             entryIdx < steeralgState.offloadState.numCandidates; ++entryIdx) {
            if (steeralgState.offloadState.candidateList[entryIdx].entry == entry) {
                break;
            }
        }
    }

    if (entryIdx < steeralgState.offloadState.numCandidates) {
        // Mark the entry as being processed
        steeralgState.offloadState.candidateList[entryIdx].entry = NULL;
        *occupiedAirtime = steeralgState.offloadState.candidateList[entryIdx].metric &
                               STEERALG_OFFLOADING_CANDIDATE_AIRTIME_MASK;
    }

    return complete;
}

/**
 * @brief Check if a BSS can be the target to steer the STA
 *
 * It will check:
 * 1. Channel overload condition
 * 2. After adding the STA, the BSS is still below safety threshold
 *
 * @param [in] entry  the handle to the STA
 * @param [in] bssHandle  the handle to the BSS
 * @param [in] bss  BSS information
 * @param [out] availableAirtime  if the BSS can support the STA, available
 *                                airtime left on this BSS; otherwise, set to
 *                                LBD_INVALID_AIRTIME
 *
 * @return LBD_TRUE if the BSS can be a steer target; otherwise return LBD_FALSE
 */
static LBD_BOOL steeralgCanBSSSupportClient(stadbEntry_handle_t entry,
                                            stadbEntry_bssStatsHandle_t bssHandle,
                                            const lbd_bssInfo_t *bss,
                                            lbd_airtime_t *availableAirtime) {
    *availableAirtime = LBD_INVALID_AIRTIME;

    LBD_BOOL isOverloaded = LBD_FALSE, canSupport = LBD_FALSE;
    if (LBD_NOK == bandmon_isChannelOverloaded(bss->channelId, &isOverloaded) ||
        isOverloaded) {
        dbgf(steeralgState.dbgModule, DBGDEBUG,
             "%s: BSS " lbBSSInfoAddFmt()
             " not a steering candidate because it is overloaded or overload status not found",
              __func__, lbBSSInfoAddData(bss));
        return LBD_FALSE;
    }

    lbd_airtime_t expectedAirtime = stadbEntry_getAirtime(entry, bssHandle, NULL);
    if (expectedAirtime == LBD_INVALID_AIRTIME) {
        // Couldn't estimate airtime
        dbgf(steeralgState.dbgModule, DBGDEBUG,
             "%s: BSS " lbBSSInfoAddFmt()
             " not a steering candidate because couldn't estimate airtime",
              __func__, lbBSSInfoAddData(bss));
    } else {
        *availableAirtime = bandmon_canSupportClient(bss->channelId, expectedAirtime);
        canSupport = (*availableAirtime != LBD_INVALID_AIRTIME);
        if (!canSupport) {
             dbgf(steeralgState.dbgModule, DBGDEBUG,
                 "%s: BSS " lbBSSInfoAddFmt()
                 " not a steering candidate because cannot support client "
                 "with expected airtime %u%%",
                  __func__, lbBSSInfoAddData(bss), expectedAirtime);
        }
    }

    return canSupport;
}

/**
 * @brief Check the validity of the rate of a STA on a BSS and
 *        whether it is above certain threshold
 *
 * @param [in] entry  the handle to the STA
 * @param [in] bssHandle  the handle to the BSS
 * @param [in] bss  basic BSS information
 * @param [in] threshold  the threshold to compare with
 * @param [in] dlEstimate  the estimated Tx rate
 * @param [in] ageSecs  seconds since the Tx rate was estimated
 *
 * @return LBD_TRUE if the rate if above the threshold; otherwise return LBD_FALSE
 */
static LBD_BOOL steeralgIsRateAboveThreshold(stadbEntry_handle_t entry,
                                             stadbEntry_bssStatsHandle_t bssHandle,
                                             const lbd_bssInfo_t *bss,
                                             lbd_linkCapacity_t threshold,
                                             lbd_linkCapacity_t dlEstimate,
                                             time_t ageSecs) {
    if (ageSecs > steeralgState.config.freshnessLimit) {
        // Capacity measurement is stale
        dbgf(steeralgState.dbgModule, DBGDEBUG,
             "%s: BSS " lbBSSInfoAddFmt()
             " not a steering candidate because capacity measurement is stale"
             " (age (%lu) > freshness limit (%u))",
             __func__, lbBSSInfoAddData(bss),
             ageSecs, steeralgState.config.freshnessLimit);
        return LBD_FALSE;
    } else if (dlEstimate == LBD_INVALID_LINK_CAP || dlEstimate <= threshold) {
         dbgf(steeralgState.dbgModule, DBGDEBUG,
             "%s: BSS " lbBSSInfoAddFmt() " not a steering candidate because "
             "link capacity (%u) not greater than threshold (%u)",
             __func__, lbBSSInfoAddData(bss), dlEstimate, threshold);
       return LBD_FALSE;
    }

    return LBD_TRUE;
}

/**
 * @brief Callback function to check if we want to measure the downlink RSSI by sending
 *        802.11k beacon report request on a BSS
 *
 * If a BSS is a candidate, it must return a non-zero metric.
 *
 * The following rules are used to compute metric:
 * bit 31: Set if BSS is on a different band from serving band
 * bit 30: Set if BSS has reserved airtime for the client
 * bit 29: Set if the utilization is below its safety threshold
 * bit 28: set if a channel with higher Tx power for 11ac clients
 *         or if a channel with lower Tx power for non-11ac clients
 * bit 20-27: set with medium utilization measured on this channel
 *
 * @pre the STA entry is associated
 *
 * @param [in] entry  the STA entry
 * @param [in] bssHandle  the BSS handle to check
 * @param [in] cookie  currently not used
 *
 * @return the non-zero metric if the BSS is an 802.11k candidate;
 *         otherwise return 0
 */
static u_int32_t steeralgSelect11kChannelCallback(stadbEntry_handle_t entry,
                                                  stadbEntry_bssStatsHandle_t bssHandle,
                                                  void *cookie) {
#define METRIC_OFFSET_BAND 31
#define METRIC_OFFSET_RESERVED_AIRTIME (METRIC_OFFSET_BAND - 1)
#define METRIC_OFFSET_SAFETY (METRIC_OFFSET_RESERVED_AIRTIME - 1)
#define METRIC_OFFSET_PHY_CAP (METRIC_OFFSET_SAFETY - 1)
#define METRIC_OFFSET_UTIL (METRIC_OFFSET_PHY_CAP - sizeof(lbd_airtime_t) * 8)
    steeralgServingBSSInfo_t *servingBSS = (steeralgServingBSSInfo_t *)cookie;
    const lbd_bssInfo_t *bssInfo = stadbEntry_resolveBSSInfo(bssHandle);
    lbDbgAssertExit(steeralgState.dbgModule, bssInfo);
    if (servingBSS->bssInfo->channelId == bssInfo->channelId) {
        // Ignore current channel
        return 0;
    }

    wlanif_band_e prefered11kReqBand = servingBSS->band == wlanif_band_24g ? wlanif_band_5g :
                                                                             wlanif_band_24g;
    u_int32_t metric = steeralgComputeBSSMetric(entry, bssHandle,
                                                prefered11kReqBand,
                                                servingBSS->bestPHYMode,
                                                METRIC_OFFSET_BAND,
                                                METRIC_OFFSET_PHY_CAP,
                                                METRIC_OFFSET_RESERVED_AIRTIME,
                                                METRIC_OFFSET_SAFETY,
                                                METRIC_OFFSET_UTIL);

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(steeralgState.dbgModule, staAddr);
    dbgf(steeralgState.dbgModule, DBGDEBUG,
         "%s: " lbBSSInfoAddFmt() "is selected as 11k candidate with metric 0x%x "
         "for " lbMACAddFmt(":"),
         __func__, lbBSSInfoAddData(bssInfo), metric, lbMACAddData(staAddr->ether_addr_octet));

    return metric;
#undef METRIC_OFFSET_RESERVED_AIRTIME
#undef METRIC_OFFSET_SAFETY
#undef METRIC_OFFSET_BAND
#undef METRIC_OFFSET_PHY_CAP
#undef METRIC_OFFSET_UTIL
}

/**
 * @brief Compute a metric for a given BSS based on its band, Tx power,
 *        reserved airtime and utilization info.
 *
 * This is currently used for determining 11k and idle steer candidate.
 * The weigh of each factor is based on the offset given.
 *
 * @param [in] entry  the client to compute this metric for
 * @param [in] bssHandle  the given BSS
 * @param [in] preferedBand  set the band bit in metric to 1 if the BSS
 *                           is operating on this prefered band
 * @param [in] bestPHYMode  the best PHY mode supported by the client
 * @param [in] offsetBand  offset in the metric for band
 * @param [in] offsetPHYCap  offset in the metric for PHY capability
 * @param [in] offsetReservedAirtime  offset in the metric for reserved airtime
 * @param [in] offsetSafety  offset in the metric for MU below safety threshold
 * @param [in] offsetUtil  offset in the metric for measured MU
 */
static u_int32_t steeralgComputeBSSMetric(stadbEntry_handle_t entry,
                                          stadbEntry_bssStatsHandle_t bssHandle,
                                          wlanif_band_e preferedBand,
                                          wlanif_phymode_e bestPHYMode,
                                          u_int32_t offsetBand,
                                          u_int32_t offsetPHYCap,
                                          u_int32_t offsetReservedAirtime,
                                          u_int32_t offsetSafety,
                                          u_int32_t offsetUtil) {
    u_int32_t metric = 1; // Bit 0 is used to mark it as a candidate
    const lbd_bssInfo_t *bssInfo = stadbEntry_resolveBSSInfo(bssHandle);
    lbDbgAssertExit(steeralgState.dbgModule, bssInfo);
    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(bssInfo->channelId);
    lbDbgAssertExit(steeralgState.dbgModule, band < wlanif_band_invalid);

    if (stadbEntry_getReservedAirtime(entry, bssHandle) != LBD_INVALID_AIRTIME) {
        metric |= 1 << offsetReservedAirtime;
    }
    if (bandmon_canSupportClient(bssInfo->channelId, 0 /* airtime */)
            != LBD_INVALID_AIRTIME) {
        metric |= 1 << offsetSafety;
    }
    if (band == preferedBand) {
        metric |= 1 << offsetBand;
    }

    if (steeralgState.config.phyBasedPrioritization && band == wlanif_band_5g) {
        // PHY capability bit only matters for 5 GHz target channel
        LBD_BOOL isStrongestChannel = LBD_FALSE;
        if (LBD_NOK == wlanif_isBSSOnStrongestChannel(bssInfo, &isStrongestChannel)) {
            dbgf(steeralgState.dbgModule, DBGERR,
                 "%s: Failed to check Tx power status for " lbBSSInfoAddFmt(),
                 __func__, lbBSSInfoAddData(bssInfo));
        } else if (!(isStrongestChannel ^ (bestPHYMode == wlanif_phymode_vht))) {
            metric |= 1 << offsetPHYCap;
        }
    }

    lbd_airtime_t util = bandmon_getMeasuredUtilization(bssInfo->channelId);
    if (util == LBD_INVALID_AIRTIME) {
        dbgf(steeralgState.dbgModule, DBGERR,
             "%s: Failed to get measured utilization on channel %u",
             __func__, bssInfo->channelId);
    } else {
        // The lower the utilization, the better
        metric |= (100 - util) << offsetUtil;
    }

    return metric;
}
