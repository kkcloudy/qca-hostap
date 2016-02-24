// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimator.c
 *
 * @Abstract: Implementation of rate estimator API.
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

#include "lbd.h"
#include "lbd_assert.h"
#include "internal.h"
#include "module.h"
#include "profile.h"
#include "stadb.h"
#include "steeralg.h"
#include "steerexec.h"
#include "diaglog.h"

#include "estimator.h"
#include "estimatorRCPIToPhyRate.h"
#include "estimatorDiaglogDefs.h"

// Currently only stamon needs to know when clients are eligible again
// to have their metrics measured. However, we allow up to two observers
// in case steeralg needs this in the future.
#define MAX_STA_DATA_METRICS_ALLOWED_OBSERVERS 2

/**
 * @brief Internal state for the rate estimator module.
 */
static struct {
    struct dbgModule *dbgModule;

    /// Special logging area for the raw byte count statistics and estimated
    /// throughput / rate for continuous throughput sampling mode.
    /// This is used to make it easier to suppress the logs that would
    /// otherwise fill up the console.
    struct dbgModule *statsDbgModule;

    /// Configuration data obtained at init time
    struct {
        /// Maximum age (in seconds) before some measurement is considered too
        /// old and thus must be re-measured.
        u_int32_t ageLimit;

        /// RSSI difference when estimating RSSI on 5 GHz from
        /// the one measured on 2.4 GHz
        int rssiDiffEstimate5gFrom24g;

        /// RSSI difference when estimating RSSI on 2.4 GHz from
        /// the one measured on 5 GHz
        int rssiDiffEstimate24gFrom5g;

        /// Number of probes required when non-associted band RSSI is valid
        u_int8_t probeCountThreshold;

        /// How frequently to sample the statistics for a node.
        unsigned statsSampleInterval;

        /// Maximum amount of time (in seconds) to allow for a client to
        /// respond to an 802.11k Beacon Report Request before giving up
        /// and declaring a failure.
        u_int8_t max11kResponseTime;

        /// Minimum amount of time (in seconds) between consecutive 802.11k
        /// requests for a given STA.
        unsigned dot11kProhibitTime;

        /// Percentage factor to apply the PHY rate before deriving the
        /// airtime from the rate and throughput information.
        u_int8_t phyRateScalingForAirtime;

        /// Whether to enable the continous throughput sampling mode
        /// (primarily for demo purposes) or not.
        LBD_BOOL enableContinuousThroughput;
    } config;

    /// Tracking information for an invocation of
    /// estimator_estimatePerSTAAirtimeOnChannel.
    struct estimatorAirtimeOnChannelState {
        /// The channel on which a measurement is being done, or
        /// LBD_CHANNEL_INVALID if one is not in progress.
        lbd_channelId_t channelId;

        /// The number of STAs for which an estimate is still pending.
        size_t numSTAsRemaining;

        /// The number of STAs for which airtime was successfully measured.
        size_t numSTAsSuccess;

        /// The number of STAs for which airtime could not be successfully
        /// measured. This is only for logging/debugging purposes.
        size_t numSTAsFailure;
    } airtimeOnChannelState;

    /// Observer for when a STA becomes eligible to have its data metrics
    /// measured again.
    struct estimatorSTADataMetricsAllowedObserver {
        LBD_BOOL isValid;
        estimator_staDataMetricsAllowedObserverCB callback;
        void *cookie;
    } staDataMetricsAllowedObservers[MAX_STA_DATA_METRICS_ALLOWED_OBSERVERS];

    /// Timer used to periodically sample the byte counter stats for STAs.
    struct evloopTimeout statsSampleTimer;

    /// Timer used to check for STAs that have not responded to an 802.11k
    /// request.
    struct evloopTimeout dot11kTimer;

    /// The time (in seconds) at which to next expire the 802.11k timer.
    struct timespec nextDot11kExpiry;

    /// The number of entries for which an 802.11k timer is running.
    size_t numDot11kTimers;
} estimatorState;

typedef enum estimatorMeasurementMode_e {
    /// No measurements are in progress.
    estimatorMeasurementMode_none,

    /// Full measurement, including non-serving metrics.
    estimatorMeasurementMode_full,

    /// Measuring throughput for estimates of airtime on a channel.
    estimatorMeasurementMode_airtimeOnChannel,

    /// Only measuring throughput for continuous sampling mode.
    estimatorMeasurementMode_throughputOnly,
} estimatorMeasurementMode_e;

typedef enum estimatorThroughputEstimationState_e {
    /// Nothing is being estimated.
    estimatorThroughputState_idle,

    /// Waiting for the first sample to be taken.
    estimatorThroughputState_awaitingFirstSample,

    /// Waiting for the second sample to be taken.
    estimatorThroughputState_awaitingSecondSample,
} estimatorThroughputEstimationState_e;

typedef enum estimator11kState_e {
    /// No 802.11k work is in progress.
    estimator11kState_idle,

    /// Waiting for the STA to send a Beacon Report Response.
    estimator11kState_awaiting11kBeaconReport,

    /// Cannot perform another 802.11k beacon report until a timer
    /// expires (to prevent too frequent measurements).
    estimator11kState_awaiting11kProhibitExpiry,
} estimator11kState_e;

/**
 * @brief State information stored on a per STA basis, for all STAs being
 *        managed by the estimator.
 */
typedef struct estimatorSTAState_t {
    /// The type of measurement currently being undertaken.
    estimatorMeasurementMode_e measurementMode;

    /// The stage in the throughput estimation process for this entry.
    estimatorThroughputEstimationState_e throughputState;

    /// The stage in the estimation process for 802.11k measurements.
    estimator11kState_e dot11kState;

    /// The BSS on which stats were enabled.
    lbd_bssInfo_t statsEnabledBSSInfo;

    /// The time at which the last sample was taken.
    struct timespec lastSampleTime;

    /// The statistics for the last sample.
    wlanif_staStatsSnapshot_t lastStatsSnapshot;

    /// Time (in seconds) at which the 802.11k timer for this entry is to
    /// expire.
    struct timespec dot11kTimeout;
} estimatorSTAState_t;

// Types used for temporary information during iteration.

/**
 * @brief Parameters that are needed for iterating over the supported
 *        BSSes when estimating the non-serving uplink RSSIs.
 */
typedef struct estimatorNonServingUplinkRSSIParams_t {
    /// The identity of the serving BSS.
    stadbEntry_bssStatsHandle_t  servingBSS;

    /// The identifying information for the serving BSS.
    const lbd_bssInfo_t *servingBSSInfo;

    /// The band on which the serving BSS operates.
    wlanif_band_e servingBand;

    /// The uplink RSSI on the serving BSS.
    lbd_rssi_t servingRSSI;

    /// The maximum transmit power on the BSS (from the AP's perspective).
    u_int8_t servingMaxTxPower;

    /// The result of the iterate (and thus the overall estimate).
    /// The callback will set this only on a failure.
    LBD_STATUS result;
} estimatorNonServingUplinkRSSIParams_t;

/**
 * @brief Parameters that are needed when iterating over the STAs to
 *        collect statistics.
 */
typedef struct estimatorSTAStatsSnapshotParams_t {
    /// The number of entries which still have stats pending.
    size_t numPending;
} estimatorSTAStatsSnapshotParams_t;

/**
 * @brief Parameters that are needed when iterating over the BSSes when
 *        writing back the estimated rates and airtime based on an 802.11k
 *        measurement.
 */
typedef struct estimatorNonServingRateAirtimeParams_t {
    /// Whether to consider it a result overall or not.
    LBD_STATUS result;

    /// Handle to the BSS that was measured.
    stadbEntry_bssStatsHandle_t measuredBSSStats;

    /// Value for the band that was measured (just to avoid re-resolving
    /// the band each time).
    wlanif_band_e measuredBand;

    /// Reference to the 802.11k Beacon Report Response event.
    const wlanif_beaconReportEvent_t *bcnrptEvent;

    /// Tx power on the BSS that was measured
    u_int8_t txPower;
} estimatorNonServingRateAirtimeParams_t;

/**
 * @brief Parameters that are needed when iterating over the STAs to start
 *        the per-STA airtime estimate on a specific channel.
 */
typedef struct estimatorPerSTAAirtimeOnChannelParams_t {
    /// The channel being estimated.
    lbd_channelId_t channelId;

    /// The number of STAs for which an estimate was begun.
    size_t numSTAsStarted;
} estimatorPerSTAAirtimeOnChannelParams_t;

// Forward decls
static void estimatorSTAFiniIterateCB(stadbEntry_handle_t entry,
                                      void *cookie);
static LBD_BOOL estimatorNonServingUplinkRSSICallback(
    stadbEntry_handle_t entryHandle, stadbEntry_bssStatsHandle_t bssHandle,
    void *cookie);
static LBD_STATUS estimatorStoreULRSSIEstimate(
        stadbEntry_handle_t entryHandle, wlanif_band_e servingBand,
        lbd_rssi_t servingRSSI, wlanif_band_e targetBand,
        int8_t powerDiff, stadbEntry_bssStatsHandle_t targetBSSStats);

static estimatorSTAState_t *estimatorGetOrCreateSTAState(stadbEntry_handle_t entry);
static void estimatorDestroySTAState(void *state);

static inline LBD_BOOL estimatorStateIsSampling(const estimatorSTAState_t *state);
static inline LBD_BOOL estimatorStateIsFirstSample(const estimatorSTAState_t *state);
static inline LBD_BOOL estimatorStateIsSecondSample(const estimatorSTAState_t *state);

static inline LBD_BOOL estimatorStateIs11kNotAllowed(const estimatorSTAState_t *state);

static LBD_STATUS estimatorEstimateSTADataMetricsImpl(
        stadbEntry_handle_t handle, estimatorMeasurementMode_e measurementMode);
static void estimatorCompletePerSTAAirtime(estimatorSTAState_t *state,
                                           LBD_BOOL isFailure);

static LBD_STATUS estimatorPerform11kMeasurement(stadbEntry_handle_t entry,
                                                 const struct ether_addr *addr,
                                                 estimatorSTAState_t *state);
static void estimatorStart11kTimeout(estimatorSTAState_t *state,
                                     unsigned durationSecs);
static void estimatorStart11kResponseTimeout(estimatorSTAState_t *state);
static void estimatorStart11kProhibitTimeout(estimatorSTAState_t *state);

static LBD_BOOL estimatorNonServingRateAirtimeCallback(
    stadbEntry_handle_t entryHandle, stadbEntry_bssStatsHandle_t bssHandle,
    void *cookie);
static void estimatorHandleBeaconReportEvent(struct mdEventNode *event);
static LBD_STATUS estimatorComputeAndStoreNonServingStats(
        stadbEntry_handle_t entry, const struct ether_addr *addr,
        stadbEntry_bssStatsHandle_t targetBSS, lbd_linkCapacity_t capacity);

static void estimatorNotifySTADataMetricsAllowedObservers(
        stadbEntry_handle_t entry);

static void estimatorSTAStatsSampleTimeoutHandler(void *cookie);
static void estimator11kTimeoutHandler(void *cookie);

static void estimatorDiaglogServingStats(const struct ether_addr *addr,
                                         const lbd_bssInfo_t *bssInfo,
                                         lbd_linkCapacity_t dlThroughput,
                                         lbd_linkCapacity_t ulThroughput,
                                         lbd_linkCapacity_t lastTxRate,
                                         lbd_airtime_t airtime);
static void estimatorDiaglogNonServingStats(const struct ether_addr *addr,
                                            const lbd_bssInfo_t *bssInfo,
                                            lbd_linkCapacity_t capacity,
                                            lbd_airtime_t airtime);

static void estimatorStartSTAAirtimeIterateCB(stadbEntry_handle_t entry,
                                              void *cookie);
static void estimatorGeneratePerSTAAirtimeCompleteEvent(
        lbd_channelId_t channelId, size_t numSTAsEstimated);

static void estimatorMenuInit(void);

/**
 * @brief Default configuration values.
 *
 * These are used if the config file does not specify them.
 */
static struct profileElement estimatorElementDefaultTable[] = {
    { ESTIMATOR_AGE_LIMIT_KEY,                        "5" },
    { ESTIMATOR_RSSI_DIFF_EST_W5_FROM_W2_KEY,       "-15" },
    { ESTIMATOR_RSSI_DIFF_EST_W2_FROM_W5_KEY,         "5" },
    { ESTIMATOR_PROBE_COUNT_THRESHOLD_KEY,            "3" },
    { ESTIMATOR_STATS_SAMPLE_INTERVAL_KEY,            "1" },
    { ESTIMATOR_11K_PROHIBIT_TIME_KEY,               "30" },
    { ESTIMATOR_PHY_RATE_SCALING_FOR_AIRTIME_KEY,    "50" },
    { ESTIMATOR_ENABLE_CONTINUOUS_THROUGHPUT_KEY ,    "0" },
    { NULL, NULL }
};

#define USECS_PER_SEC 1000000

// The maximum value for a percentage (assuming percentages are represented
// as integers).
#define MAX_PERCENT 100

/// Minimum and maximum values for the config parameter that scales the
/// PHY rate before computing airtime.
#define MIN_PHY_RATE_SCALING 50
#define MAX_PHY_RATE_SCALING MAX_PERCENT

/// Maximum age of the serving data metrics to avoid doing another estimate.
/// This is not being made a config parameter for the time being to avoid
/// further proliferation of config options.
#define MAX_SERVING_METRICS_AGE_SECS 1

// ====================================================================
// Public API
// ====================================================================

LBD_STATUS estimator_init(void) {
    estimatorState.dbgModule = dbgModuleFind("estimator");
    estimatorState.dbgModule->Level = DBGINFO;

    estimatorState.statsDbgModule = dbgModuleFind("ratestats");
    estimatorState.statsDbgModule->Level = DBGERR;

    estimatorState.airtimeOnChannelState.channelId = LBD_CHANNEL_INVALID;

    estimatorState.config.ageLimit =
        profileGetOptsInt(mdModuleID_Estimator,
                          ESTIMATOR_AGE_LIMIT_KEY,
                          estimatorElementDefaultTable);
    estimatorState.config.rssiDiffEstimate5gFrom24g =
        profileGetOptsInt(mdModuleID_Estimator,
                          ESTIMATOR_RSSI_DIFF_EST_W5_FROM_W2_KEY,
                          estimatorElementDefaultTable);
    estimatorState.config.rssiDiffEstimate24gFrom5g =
        profileGetOptsInt(mdModuleID_Estimator,
                          ESTIMATOR_RSSI_DIFF_EST_W2_FROM_W5_KEY,
                          estimatorElementDefaultTable);
    estimatorState.config.probeCountThreshold =
        profileGetOptsInt(mdModuleID_Estimator,
                          ESTIMATOR_PROBE_COUNT_THRESHOLD_KEY,
                          estimatorElementDefaultTable);
    estimatorState.config.statsSampleInterval =
        profileGetOptsInt(mdModuleID_Estimator,
                          ESTIMATOR_STATS_SAMPLE_INTERVAL_KEY,
                          estimatorElementDefaultTable);

    // The value is computed here so that the combined serving data metrics
    // and 802.11k measurement will be recent enough for steeralg to make a
    // decision.
    estimatorState.config.max11kResponseTime =
        estimatorState.config.ageLimit - MAX_SERVING_METRICS_AGE_SECS;

    estimatorState.config.dot11kProhibitTime =
        profileGetOptsInt(mdModuleID_Estimator,
                          ESTIMATOR_11K_PROHIBIT_TIME_KEY,
                          estimatorElementDefaultTable);
    estimatorState.config.phyRateScalingForAirtime =
        profileGetOptsInt(mdModuleID_Estimator,
                          ESTIMATOR_PHY_RATE_SCALING_FOR_AIRTIME_KEY,
                          estimatorElementDefaultTable);
    estimatorState.config.enableContinuousThroughput =
        profileGetOptsInt(mdModuleID_Estimator,
                          ESTIMATOR_ENABLE_CONTINUOUS_THROUGHPUT_KEY,
                          estimatorElementDefaultTable);

    // Sanity check the values
    if (estimatorState.config.max11kResponseTime >
            estimatorState.config.dot11kProhibitTime) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: 802.11k response timeout must be smaller than "
             "802.11k prohibit timeout", __func__);
        return LBD_NOK;
    }

    if (estimatorState.config.phyRateScalingForAirtime < MIN_PHY_RATE_SCALING ||
        estimatorState.config.phyRateScalingForAirtime > MAX_PHY_RATE_SCALING) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: PHY rate scaling factor for airtime must be in the range "
             "[%d, %d]", __func__, MIN_PHY_RATE_SCALING, MAX_PHY_RATE_SCALING);
        return LBD_NOK;
    }

    evloopTimeoutCreate(&estimatorState.statsSampleTimer,
                        "estimatorSTAStatsSampleTimeout",
                        estimatorSTAStatsSampleTimeoutHandler,
                        NULL);

    evloopTimeoutCreate(&estimatorState.dot11kTimer,
                        "estimator11kTimeout",
                        estimator11kTimeoutHandler,
                        NULL);

    mdEventTableRegister(mdModuleID_Estimator, estimator_event_maxnum);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_beacon_report,
                          estimatorHandleBeaconReportEvent);

    estimatorMenuInit();

    if (estimatorState.config.enableContinuousThroughput) {
        evloopTimeoutRegister(&estimatorState.statsSampleTimer,
                              estimatorState.config.statsSampleInterval,
                              0 /* usec */);
    }

    return LBD_OK;
}

LBD_STATUS estimator_estimateNonServingUplinkRSSI(stadbEntry_handle_t handle) {
    estimatorNonServingUplinkRSSIParams_t params;
    params.servingBSS = stadbEntry_getServingBSS(handle, NULL);
    if (!params.servingBSS) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: Called with an unassociated or invalid STA",
             __func__);
        return LBD_NOK;
    }

    params.servingBSSInfo = stadbEntry_resolveBSSInfo(params.servingBSS);
    lbDbgAssertExit(estimatorState.dbgModule, params.servingBSSInfo);

    params.servingBand =
        wlanif_resolveBandFromChannelNumber(params.servingBSSInfo->channelId);

    const wlanif_phyCapInfo_t *servingPhyCap =
        wlanif_getBSSPHYCapInfo(params.servingBSSInfo);
    if (!servingPhyCap || !servingPhyCap->valid) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: Unable to resolve the serving BSS PHY capabilities for "
             lbBSSInfoAddFmt(), __func__,
             lbBSSInfoAddData(params.servingBSSInfo));
        return LBD_NOK;
    }

    params.servingMaxTxPower = servingPhyCap->maxTxPower;

    // Note here that we do not care about the age or number of probes, as
    // it is a precondition of this function call that the serving RSSI
    // is up-to-date.
    params.servingRSSI = stadbEntry_getUplinkRSSI(handle, params.servingBSS,
                                                  NULL, NULL);
    if (LBD_INVALID_RSSI == params.servingRSSI) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: Unable to resolve the serving uplink RSSI",
             __func__);
        return LBD_NOK;
    }

    // Iterate to fill in any of the non-serving RSSIs.
    params.result = LBD_OK;
    if (stadbEntry_iterateBSSStats(handle,
                                   estimatorNonServingUplinkRSSICallback,
                                   &params, NULL, NULL) != LBD_OK) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: Failed to iterate over non-serving BSS stats",
             __func__);
        return LBD_NOK;
    }

    return params.result;
}

LBD_STATUS estimator_estimateSTADataMetrics(stadbEntry_handle_t handle) {
    return estimatorEstimateSTADataMetricsImpl(handle, estimatorMeasurementMode_full);
}

LBD_STATUS estimator_estimatePerSTAAirtimeOnChannel(lbd_channelId_t channelId) {
    if (LBD_CHANNEL_INVALID == channelId) {
        return LBD_NOK;
    }

    if (estimatorState.airtimeOnChannelState.channelId != LBD_CHANNEL_INVALID) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: Airtime measurement already in progress on channel [%u]; "
             "cannot service request for channel [%u]", __func__,
             estimatorState.airtimeOnChannelState.channelId, channelId);
        return LBD_NOK;
    }

    dbgf(estimatorState.dbgModule, DBGINFO,
         "%s: Estimating per-STA airtime on channel [%u]",
         __func__, channelId);

    estimatorPerSTAAirtimeOnChannelParams_t params;
    params.channelId = channelId;
    params.numSTAsStarted = 0;
    if (stadb_iterate(estimatorStartSTAAirtimeIterateCB, &params) != LBD_OK) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: Failed to iterate over STA DB; no estimates will be done",
             __func__);
        return LBD_NOK;
    }

    if (!params.numSTAsStarted) {
        estimatorGeneratePerSTAAirtimeCompleteEvent(channelId,
                                                    0 /* numSTAsEstimated */);
    } else {
        estimatorState.airtimeOnChannelState.channelId = channelId;
        estimatorState.airtimeOnChannelState.numSTAsRemaining =
            params.numSTAsStarted;
        estimatorState.airtimeOnChannelState.numSTAsSuccess = 0;
        estimatorState.airtimeOnChannelState.numSTAsFailure = 0;
    }

    return LBD_OK;
}

LBD_STATUS estimator_registerSTADataMetricsAllowedObserver(
        estimator_staDataMetricsAllowedObserverCB callback, void *cookie) {
    if (!callback) {
        return LBD_NOK;
    }

    struct estimatorSTADataMetricsAllowedObserver *freeSlot = NULL;
    size_t i;
    for (i = 0; i < MAX_STA_DATA_METRICS_ALLOWED_OBSERVERS; ++i) {
        struct estimatorSTADataMetricsAllowedObserver *curSlot =
            &estimatorState.staDataMetricsAllowedObservers[i];
        if (curSlot->isValid && curSlot->callback == callback &&
            curSlot->cookie == cookie) {
            dbgf(estimatorState.dbgModule, DBGERR,
                 "%s: Duplicate registration (func %p, cookie %p)",
                 __func__, callback, cookie);
           return LBD_NOK;
        }

        if (!freeSlot && !curSlot->isValid) {
            freeSlot = curSlot;
        }

    }

    if (freeSlot) {
        freeSlot->isValid = LBD_TRUE;
        freeSlot->callback = callback;
        freeSlot->cookie = cookie;
        return LBD_OK;
    }

    // No free entries found.
    return LBD_NOK;
}

LBD_STATUS estimator_unregisterSTADataMetricsAllowedObserver(
        estimator_staDataMetricsAllowedObserverCB callback, void *cookie) {
    if (!callback) {
        return LBD_NOK;
    }

    size_t i;
    for (i = 0; i < MAX_STA_DATA_METRICS_ALLOWED_OBSERVERS; ++i) {
        struct estimatorSTADataMetricsAllowedObserver *curSlot =
            &estimatorState.staDataMetricsAllowedObservers[i];
        if (curSlot->isValid && curSlot->callback == callback &&
            curSlot->cookie == cookie) {
            curSlot->isValid = LBD_FALSE;
            curSlot->callback = NULL;
            curSlot->cookie = NULL;
            return LBD_OK;
        }
    }

    // No match found
    return LBD_NOK;
}

LBD_STATUS estimator_fini(void) {
    // Need to disable the stats for any entries that are still in a sampling
    // mode.
    return stadb_iterate(estimatorSTAFiniIterateCB, NULL);
}

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Disable the statistics collection for any STAs where it was started.
 */
static void estimatorSTAFiniIterateCB(stadbEntry_handle_t entry,
                                      void *cookie) {
    estimatorSTAState_t *state = stadbEntry_getEstimatorState(entry);
    if (state && state->measurementMode != estimatorMeasurementMode_none) {
        wlanif_disableSTAStats(&state->statsEnabledBSSInfo);
    }
}

/**
 * @brief Check the RSSI for a given non-serving BSS and estimate it if
 *        it does not meet the recency/accuracy requirements.
 *
 * @param [in] entryHandle  the STA being processed
 * @param [in] bssHandle  the BSS for which to update the RSSI (if necesasry)
 * @param [in] cookie  the internal parameters for the iteration
 *
 * @return LBD_FALSE always (as it does not keep the BSSes around)
 */
static LBD_BOOL estimatorNonServingUplinkRSSICallback(
    stadbEntry_handle_t entryHandle, stadbEntry_bssStatsHandle_t bssHandle,
    void *cookie) {
    estimatorNonServingUplinkRSSIParams_t *params =
        (estimatorNonServingUplinkRSSIParams_t *) cookie;
    lbDbgAssertExit(estimatorState.dbgModule, params);

    if (params->servingBSS != bssHandle) {
        const lbd_bssInfo_t *targetBSSInfo =
            stadbEntry_resolveBSSInfo(bssHandle);
        lbDbgAssertExit(estimatorState.dbgModule, targetBSSInfo);

        // Must be from the same AP for us to be able to estimate.
        if (lbAreBSSInfoSameAP(params->servingBSSInfo, targetBSSInfo)) {
            time_t rssiAgeSecs;
            u_int8_t probeCount;
            lbd_rssi_t rssi = stadbEntry_getUplinkRSSI(entryHandle, bssHandle,
                                                       &rssiAgeSecs, &probeCount);
            if (LBD_INVALID_RSSI == rssi ||
                rssiAgeSecs > estimatorState.config.ageLimit ||
                (probeCount > 0 &&
                 probeCount < estimatorState.config.probeCountThreshold)) {
                const wlanif_phyCapInfo_t *nonServingPhyCap =
                    wlanif_getBSSPHYCapInfo(targetBSSInfo);
                if (nonServingPhyCap && nonServingPhyCap->valid) {
                    int8_t powerDiff =
                        nonServingPhyCap->maxTxPower - params->servingMaxTxPower;
                    wlanif_band_e targetBand =
                        wlanif_resolveBandFromChannelNumber(targetBSSInfo->channelId);
                    if (estimatorStoreULRSSIEstimate(entryHandle, params->servingBand,
                                                     params->servingRSSI,
                                                     targetBand, powerDiff,
                                                     bssHandle) != LBD_OK) {
                        dbgf(estimatorState.dbgModule, DBGERR,
                             "%s: Failed to store estimate for BSS: " lbBSSInfoAddFmt(),
                             __func__, lbBSSInfoAddData(targetBSSInfo));

                        // Store the failure so the overall result can be failed.
                        params->result = LBD_NOK;
                    }
                } else {
                    dbgf(estimatorState.dbgModule, DBGERR,
                         "%s: Unable to resolve the non-serving BSS PHY capabilities for "
                         lbBSSInfoAddFmt(), __func__, lbBSSInfoAddData(targetBSSInfo));
                    params->result = LBD_NOK;
                }
            }
        }
    }

    return LBD_FALSE;
}

/**
 * @brief Compupte the RSSI estimate for the specified BSS and store it.
 *
 * @param [in] entryHandle  the STA being processed
 * @param [in] servingBand  the handle to the serving BSS
 * @param [in] servingRSSI  the RSSI on the serving BSS
 * @param [in] targetBand  the target BSS's band
 * @param [in] powerDiff  the difference in Tx power between the serving and
 *                        non-serving BSSes
 * @param [in] targetBSS  the non-serving BSS to update
 *
 * @return LBD_OK if the estimate was stored successfully; otherwise LBD_NOK
 */
static LBD_STATUS estimatorStoreULRSSIEstimate(
        stadbEntry_handle_t entryHandle, wlanif_band_e servingBand,
        lbd_rssi_t servingRSSI, wlanif_band_e targetBand,
        int8_t powerDiff, stadbEntry_bssStatsHandle_t targetBSSStats) {
    // Since clients may be more limited in transmission power, we act
    // conservatively and say that any cases where the target BSS has
    // higher power than the source does not necessarily translate into
    // an improved uplink RSSI.
    if (powerDiff > 0) {
        powerDiff = 0;
    }

    // For now, if they are on the same band, we assume the RSSIs are
    // equal. In the future we can potentially consider any Tx power
    // limitations of the client (although clients do not always provide
    // meaningful values so this is likely not usable).
    int8_t deltaRSSI = powerDiff;
    if (servingBand != targetBand) {
        switch (targetBand) {
            case wlanif_band_24g:
                deltaRSSI += estimatorState.config.rssiDiffEstimate24gFrom5g;
                break;

            case wlanif_band_5g:
                deltaRSSI += estimatorState.config.rssiDiffEstimate5gFrom24g;
                break;

            default:
                // Somehow failed to resolve target band.
                dbgf(estimatorState.dbgModule, DBGERR,
                     "%s: Failed to resolve target band for BSS %p",
                     __func__, targetBSSStats);
                return LBD_NOK;
        }
    }

    // Need to make sure we did not underflow (and thus end up with a large
    // positive number). If so, we force the RSSI to 0 to indicate we likely
    // would be unable to associate on 5 GHz.
    //
    // We are assuming that we will never overflow, as the maximum serving
    // RSSI value plus the adjustment will be much less than the size of an
    // 8-bit integer.
    lbd_rssi_t targetRSSI;
    if (deltaRSSI < 0 && (-deltaRSSI > servingRSSI)) {
        targetRSSI = 0;
    } else {
        targetRSSI = servingRSSI + deltaRSSI;
    }

    return stadbEntry_setUplinkRSSI(entryHandle, targetBSSStats, targetRSSI);
}

/**
 * @brief Obtain the estimator state for the STA, creating it if it does not
 *        exist.
 *
 * @param [in] entry  the handle to the STA for which to set the state
 *
 * @return the state entry, or NULL if one could not be created
 */
static estimatorSTAState_t *estimatorGetOrCreateSTAState(
        stadbEntry_handle_t entry) {
    estimatorSTAState_t *state =
        (estimatorSTAState_t *) stadbEntry_getEstimatorState(entry);
    if (!state) {
        state = (estimatorSTAState_t *) calloc(1, sizeof(estimatorSTAState_t));
        if (!state) {
            return NULL;
        }

        stadbEntry_setEstimatorState(entry, state, estimatorDestroySTAState);
    }

    return state;
}

/**
 * @brief Destructor function used to clean up the STA state.
 */
static void estimatorDestroySTAState(void *state) {
    free(state);
}

/**
 * @brief Start/update the timer for 802.11k events.
 *
 * If the timer is already running and the expiry for this state is less than
 * the currently scheduled expiry, the timer is rescheduled.
 *
 * @param [in] state  the internal state object for the STA for which to start
 *                    the timer
 * @param [in] durationSecs  the amount of time for the timer (in seconds)
 */
static void estimatorStart11kTimeout(estimatorSTAState_t *state,
                                     unsigned durationSecs) {
    estimatorState.numDot11kTimers++;

    lbGetTimestamp(&state->dot11kTimeout);
    state->dot11kTimeout.tv_sec += durationSecs;

    if (estimatorState.numDot11kTimers == 1 ||
        lbIsTimeBefore(&state->dot11kTimeout,
                       &estimatorState.nextDot11kExpiry)) {
        // The + 1 is to ensure that we do not get an early expiry that causes
        // us to just quickly reschedule a 0 second timer.
        evloopTimeoutRegister(&estimatorState.dot11kTimer,
                              durationSecs + 1, 0);
        estimatorState.nextDot11kExpiry = state->dot11kTimeout;
    }  // else timer is already running and is shorter than this state needs
}

/**
 * @brief Start the timer that waits for an 802.11k beacon report response.
 *
 * @param [in] state  the internal state object for the STA for which to start
 *                    the timer
 */
static void estimatorStart11kResponseTimeout(estimatorSTAState_t *state) {
    state->dot11kState = estimator11kState_awaiting11kBeaconReport;
    estimatorStart11kTimeout(state, estimatorState.config.max11kResponseTime);
}

/**
 * @brief Start the timer that waits for enough time to elapse to allow for
 *        another 802.11k request.
 *
 * @param [in] state  the internal state object for the STA for which to start
 *                    the timer
 */
static void estimatorStart11kProhibitTimeout(estimatorSTAState_t *state) {
    state->dot11kState = estimator11kState_awaiting11kProhibitExpiry;
    estimatorStart11kTimeout(state, estimatorState.config.dot11kProhibitTime);
}

/**
 * @brief Mark the 802.11k measurement as complete.
 *
 * This will generate the event so other modules know it is complete and start
 * the necessary timer to throttle repeated 802.11k measurements.
 *
 * @param [in] state  the internal state object for the STA for which to start
 *                    the timer
 * @param [in] addr  the address which was completed
 * @param [in] result  whether the measurement was successful or not
 */
static void estimatorCompleteDot11kMeasurement(estimatorSTAState_t *state,
                                               const struct ether_addr *addr,
                                               LBD_STATUS result) {
    // Let steeralg know that the data is ready or that it failed.
    estimator_staDataMetricsCompleteEvent_t event;
    lbCopyMACAddr(addr->ether_addr_octet, event.addr.ether_addr_octet);
    event.result = result;

    mdCreateEvent(mdModuleID_Estimator, mdEventPriority_Low,
                  estimator_event_staDataMetricsComplete,
                  &event, sizeof(event));

    // Throttle the next 11k measurement to prevent clients from
    // getting unhappy with the AP requesting too many measurements.
    estimatorStart11kProhibitTimeout(state);
}

/**
 * @brief Estimate the rate and airtime for the BSS provided.
 *
 * @param [in] entryHandle  the STA being processed
 * @param [in] bssHandle  the BSS for which to update the RSSI (if necesasry)
 * @param [in] cookie  the internal parameters for the iteration
 *
 * @return LBD_FALSE always (as it does not keep the BSSes around)
 */
static LBD_BOOL estimatorNonServingRateAirtimeCallback(
    stadbEntry_handle_t entryHandle, stadbEntry_bssStatsHandle_t bssHandle,
    void *cookie) {
    estimatorNonServingRateAirtimeParams_t *params =
        (estimatorNonServingRateAirtimeParams_t *) cookie;
    lbDbgAssertExit(estimatorState.dbgModule, params);

    const lbd_bssInfo_t *targetBSSInfo = stadbEntry_resolveBSSInfo(bssHandle);
    lbDbgAssertExit(estimatorState.dbgModule, targetBSSInfo);

    if (wlanif_resolveBandFromChannelNumber(targetBSSInfo->channelId) !=
            params->measuredBand ||
            !lbAreBSSInfoSameAP(targetBSSInfo, &params->bcnrptEvent->reportedBss)) {
        // Ignored due to not the same band.
        return LBD_FALSE;
    }

    lbd_linkCapacity_t capacity =
        estimatorEstimateFullCapacityFromRCPI(
                estimatorState.dbgModule, entryHandle,
                targetBSSInfo, params->measuredBSSStats,
                params->bcnrptEvent->rcpi, params->txPower);
    if (LBD_INVALID_LINK_CAP == capacity) {
        // The caller will have already printed an appropriate
        // error.
        params->result = LBD_NOK;
        return LBD_FALSE;
    }

    // Compute the airtime and store it in the entry.
    LBD_STATUS result = estimatorComputeAndStoreNonServingStats(
            entryHandle, &params->bcnrptEvent->sta_addr,
            bssHandle, capacity);
    if (result != LBD_OK) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: Failed to write back capacity and airtime for "
             lbMACAddFmt(":") " on " lbBSSInfoAddFmt(),
             __func__,
             lbMACAddData(params->bcnrptEvent->sta_addr.ether_addr_octet),
             lbBSSInfoAddData(&params->bcnrptEvent->reportedBss));
    }

    params->result |= result;  // will only be updated on failure
    return LBD_FALSE;
}

/**
 * @brief React to 802.11k beacon report
 *
 * @param [in] event  the event carrying the beacon report
 */
static void estimatorHandleBeaconReportEvent(struct mdEventNode *event) {
    const wlanif_beaconReportEvent_t *bcnrptEvent =
        (const wlanif_beaconReportEvent_t *) event->Data;
    lbDbgAssertExit(estimatorState.dbgModule, bcnrptEvent);

    stadbEntry_handle_t entry = stadb_find(&bcnrptEvent->sta_addr);
    if (!entry) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: Beacon report for unknown STA " lbMACAddFmt(":"),
             __func__, lbMACAddData(bcnrptEvent->sta_addr.ether_addr_octet));
        return;
    }

    estimatorSTAState_t *state = stadbEntry_getEstimatorState(entry);
    if (state) {
        if (estimator11kState_awaiting11kBeaconReport == state->dot11kState) {
            // No longer need the response timer.
            estimatorState.numDot11kTimers--;

            estimatorNonServingRateAirtimeParams_t params;
            params.result = LBD_OK;
            do {
                if (!bcnrptEvent->valid) {
                    dbgf(estimatorState.dbgModule, DBGERR,
                         "%s: Invalid beacon report for " lbMACAddFmt(":"),
                         __func__,
                         lbMACAddData(bcnrptEvent->sta_addr.ether_addr_octet));
                    params.result = LBD_NOK;
                    break;
                }

                // Make sure the channel can be resolved to a band.
                params.measuredBand =
                    wlanif_resolveBandFromChannelNumber(bcnrptEvent->reportedBss.channelId);
                if (params.measuredBand == wlanif_band_invalid) {
                    dbgf(estimatorState.dbgModule, DBGERR,
                         "%s: Cannot resolve channel %u to band for " lbMACAddFmt(":"),
                         __func__, bcnrptEvent->reportedBss.channelId,
                         lbMACAddData(bcnrptEvent->sta_addr.ether_addr_octet));
                    params.result = LBD_NOK;
                    break;
                }

                stadbEntry_bssStatsHandle_t measuredBSSStats =
                    stadbEntry_findMatchBSSStats(entry, &bcnrptEvent->reportedBss);
                if (!measuredBSSStats) {
                    dbgf(estimatorState.dbgModule, DBGERR,
                         "%s: Failed to find matching stats for " lbMACAddFmt(":")
                         " on " lbBSSInfoAddFmt(), __func__,
                         lbMACAddData(bcnrptEvent->sta_addr.ether_addr_octet),
                         lbBSSInfoAddData(&bcnrptEvent->reportedBss));
                    params.result = LBD_NOK;
                    break;
                }

                params.measuredBSSStats = measuredBSSStats;

                params.bcnrptEvent = bcnrptEvent;

                const wlanif_phyCapInfo_t *phyCap = wlanif_getBSSPHYCapInfo(&bcnrptEvent->reportedBss);
                if (phyCap && phyCap->valid) {
                    params.txPower = phyCap->maxTxPower;
                } else {
                    // Even though unable to get PHY capability on the reported BSS, we still
                    // want to try other BSSes on the same band, since we can only do 11k measurement
                    // every 30 seconds by default.
                    dbgf(estimatorState.dbgModule, DBGERR,
                         "%s: Failed to resolve PHY capability on measured BSS ("
                         lbBSSInfoAddFmt() "), will assume no Tx power difference "
                         "when estimating rates on other same-band BSSes",
                         __func__, lbBSSInfoAddData(&bcnrptEvent->reportedBss));
                    params.txPower = 0;
                }

                if (stadbEntry_iterateBSSStats(entry,
                                               estimatorNonServingRateAirtimeCallback,
                                               &params, NULL, NULL) != LBD_OK) {
                    dbgf(estimatorState.dbgModule, DBGERR,
                         "%s: Failed to iterate over non-serving BSS stats",
                         __func__);
                    params.result = LBD_NOK;
                    break;
                }
            } while(0);

            estimatorCompleteDot11kMeasurement(state, &bcnrptEvent->sta_addr,
                                               params.result);
        } else {
            dbgf(estimatorState.dbgModule, DBGERR,
                 "%s: Beacon report for STA " lbMACAddFmt(":")
                 " in unexpected state %u",
                 __func__, lbMACAddData(bcnrptEvent->sta_addr.ether_addr_octet),
                 state->dot11kState);
        }
    }
}

/**
 * @brief Compute the number of microseconds that have elapsed between two
 *        time samples.
 *
 * @note This function assumes the two samples are close enough together
 *       that the computation will not experience an integer overflow.
 *
 * @param [in] start  the beginning timestamp
 * @param [in] end  the ending timestamp
 *
 * @return the elapsed microseconds
 */
static u_int32_t estimatorComputeTimeDiff(
        const struct timespec *start, const struct timespec *end) {
#define NSECS_PER_USEC 1000
#define NSECS_PER_SEC 1000000000

    u_int32_t elapsedUsec = (end->tv_sec - start->tv_sec) * USECS_PER_SEC;

    long endNsec = end->tv_nsec;
    if (endNsec < start->tv_nsec) {
        // If the nanoseconds wrapped around, the number of seconds must
        // also have advanced by at least 1. Account for this by moving
        // one second worth of time from the elapsed microseconds into the
        // ending nanoseconds so that the subtraction below will always
        // result in a positive number.
        elapsedUsec -= USECS_PER_SEC;
        endNsec += NSECS_PER_SEC;
    }

    elapsedUsec += ((endNsec - start->tv_nsec) / NSECS_PER_USEC);
    return elapsedUsec;

#undef NSECS_PER_SEC
#undef NSECS_PER_USEC
}

/**
 * @brief Compute the consumed airtime given uplink and downlink throughputs
 *        and the estimated link rate.
 *
 * @param [in] dlThroughput  the downlink throughput
 * @param [in] ulThroughput  the uplink throughput
 * @param [in] linkRate  the estimated link rate
 *
 * @return the percentage of airtime an an integer in the range [0, 100]
 */
static inline lbd_airtime_t estimatorComputeAirtime(
        u_int32_t dlThroughput, u_int32_t ulThroughput,
        lbd_linkCapacity_t linkRate) {
    // The link rate we have here is a PHY rate. To better represent an
    // upper layer rate (without MAC overheads), we apply a scaling factor.
    lbd_linkCapacity_t scaledLinkRate =
        (linkRate * estimatorState.config.phyRateScalingForAirtime) /
        MAX_PERCENT;

    // Either we got an invalid rate from the driver or the rate is so low
    // that when we scale it and perform integer division, it ends up being
    // 0. In either case, we avoid computing an airtime since we cannot
    // really determine what the value should actually be.
    if (0 == scaledLinkRate) {
        return LBD_INVALID_AIRTIME;
    }

    // Note that we multiply by 100 here so that we do not need to involve
    // floating point division. Integral division with truncation should
    // provide sufficient accuracy.
    //
    // A 32-bit number is being used here to account for scenarios where
    // the airtime might come out much larger than 100%. This generally
    // only will happen for the non-serving channel, but in such a situation,
    // it could overflow an 8-bit integer.
    u_int32_t rawAirtime =
        (dlThroughput + ulThroughput) * MAX_PERCENT / scaledLinkRate;


    // In case our link rate is not representative or we are estimating
    // a non-serving channel where there is no chance to support the
    // throughput, we should saturate the airtime at 100%.
    lbd_airtime_t airtime;
    if (rawAirtime > MAX_PERCENT) {
        airtime = MAX_PERCENT;
    } else {
        airtime = rawAirtime;
    }

    return airtime;
}

/**
 * @brief Compute the airtime, throughput, and capacity values and store them
 *        back in the entry.
 *
 * @param [in] entry  the entry to update
 * @param [in] addr  the address of the STA
 * @param [in] params  the state information for this entry
 * @param [in] endTime  the time at which the ending stats were sampled
 * @param [in] endStats  the ending stats snapshot
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
static LBD_STATUS estimatorComputeAndStoreServingStats(
        stadbEntry_handle_t entry,
        const struct ether_addr *addr,
        estimatorSTAState_t *state,
        const struct timespec *endTime,
        const wlanif_staStatsSnapshot_t *endStats) {
    stadbEntry_bssStatsHandle_t bssStats =
        stadbEntry_getServingBSS(entry, NULL);

    // First sanity check that the currently serving BSS is the one on which
    // the measurements were taken.
    if (!bssStats ||
        !lbAreBSSesSame(&state->statsEnabledBSSInfo,
                        stadbEntry_resolveBSSInfo(bssStats))) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: BSS " lbBSSInfoAddFmt() " used to measure stats for "
             lbMACAddFmt(":") " is no longer serving",
             __func__, lbBSSInfoAddData((&state->statsEnabledBSSInfo)),
             lbMACAddData(addr->ether_addr_octet));
        return LBD_NOK;
    }

    u_int64_t deltaBitsTx =
        (endStats->txBytes - state->lastStatsSnapshot.txBytes) * 8;
    u_int64_t deltaBitsRx =
        (endStats->rxBytes - state->lastStatsSnapshot.rxBytes) * 8;

    LBD_STATUS result;
    do {
        u_int32_t elapsedUsec =
            estimatorComputeTimeDiff(&state->lastSampleTime, endTime);

        // Should never really happen, but if the elapsed time is 0,
        // abort the whole metrics storage. Something strange must have
        // happened with the clock.
        if (0 == elapsedUsec) {
            dbgf(estimatorState.dbgModule, DBGERR,
                 "%s: No time elapsed between samples for " lbMACAddFmt(":")
                 "; cannot estimate throughputs and airtime",
                 __func__, lbMACAddData(addr->ether_addr_octet));
            result = LBD_NOK;
            break;
        }

        result = stadbEntry_setFullCapacity(entry, bssStats,
                                            endStats->lastTxRate);
        if (result != LBD_OK) { break; }

        lbd_linkCapacity_t dlThroughput = deltaBitsTx / elapsedUsec;
        lbd_linkCapacity_t ulThroughput = deltaBitsRx / elapsedUsec;
        result = stadbEntry_setLastDataRate(entry, dlThroughput, ulThroughput);
        if (result != LBD_OK) { break; }

        lbd_airtime_t airtime =
            estimatorComputeAirtime(dlThroughput, ulThroughput,
                    endStats->lastTxRate);
        if (LBD_INVALID_AIRTIME == airtime) {
            dbgf(estimatorState.dbgModule, DBGERR,
                 "%s: Unable to compute airtime for " lbMACAddFmt(":")
                 ": DL: %u Mbps, UL: %u Mbps, Link rate: %u Mbps",
                 __func__, lbMACAddData(addr->ether_addr_octet),
                 dlThroughput, ulThroughput, endStats->lastTxRate);

            // Write the airtime back as invalid so that we are not relying on
            // a value that is out of sync with the throughput.
            //
            // Note that the return value here is ignored since we've already
            // printed an error and there is not much else we can do.
            stadbEntry_setAirtime(entry, bssStats, LBD_INVALID_AIRTIME);

            result = LBD_NOK;
            break;
        }

        result = stadbEntry_setAirtime(entry, bssStats, airtime);
        if (result == LBD_OK) {
            // In order to not fill up the logs when continuous throughput is
            // enabled, only log them at DUMP level.
            struct dbgModule *logModule =
                (state->measurementMode ==
                 estimatorMeasurementMode_throughputOnly) ?
                estimatorState.statsDbgModule : estimatorState.dbgModule;
            dbgf(logModule, DBGINFO,
                 "%s: Estimates for " lbMACAddFmt(":") " on " lbBSSInfoAddFmt()
                 ": DL: %u Mbps, UL: %u Mbps, Link rate: %u Mbps, Airtime %u%%",
                 __func__, lbMACAddData(addr->ether_addr_octet),
                 lbBSSInfoAddData((&state->statsEnabledBSSInfo)),
                 dlThroughput, ulThroughput, endStats->lastTxRate, airtime);

            estimatorDiaglogServingStats(addr, &state->statsEnabledBSSInfo,
                                         dlThroughput, ulThroughput,
                                         endStats->lastTxRate, airtime);
        }
    } while (0);

    return result;
}

/**
 * @brief Compute the airtime from the serving throughput and write it along
 *        with the capacity to the provided entry.
 *
 * @param [in] entry  the entry to update
 * @param [in] addr  the address of the STA
 * @param [in] targetBSS  the BSS for which to store the information
 * @param [in] throughput  the last measured throughput for this STA
 * @param [in] capacity  the estimated capacity for this STA on the BSS
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
static LBD_STATUS estimatorComputeAndStoreNonServingStats(
        stadbEntry_handle_t entry, const struct ether_addr *addr,
        stadbEntry_bssStatsHandle_t targetBSSStats,
        lbd_linkCapacity_t capacity) {
    LBD_STATUS result;
    do {
        result = stadbEntry_setFullCapacity(entry, targetBSSStats, capacity);
        if (result != LBD_OK) { break; }

        lbd_linkCapacity_t dlThroughput, ulThroughput;
        result = stadbEntry_getLastDataRate(entry, &dlThroughput,
                                            &ulThroughput, NULL);
        if (result != LBD_OK) { break; }

        lbd_airtime_t airtime =
            estimatorComputeAirtime(dlThroughput, ulThroughput, capacity);
        result = stadbEntry_setAirtime(entry, targetBSSStats, airtime);

        if (result == LBD_OK) {
            const lbd_bssInfo_t *targetBSS =
                stadbEntry_resolveBSSInfo(targetBSSStats);
            lbDbgAssertExit(estimatorState.dbgModule, targetBSS);

            dbgf(estimatorState.dbgModule, DBGINFO,
                 "%s: Estimates for " lbMACAddFmt(":") " on " lbBSSInfoAddFmt()
                 ": Link rate: %u Mbps, Airtime %u%%",
                 __func__, lbMACAddData(addr->ether_addr_octet),
                 lbBSSInfoAddData(targetBSS), capacity, airtime);

            estimatorDiaglogNonServingStats(addr, targetBSS, capacity, airtime);
        }
    } while (0);

    return result;
}

/**
 * @brief Transition the STA stats sampling to the next state.
 *
 * If a failure occurred, it will go back to the idle state. Otherwise, it will
 * proceed to performing an 802.11k measurement.
 *
 * @param [in] entry  the full information for the STA
 * @param [in] addr  the address of the entry being aborted
 * @param [in] state  the internal state tracking this entry
 * @param [in] sampleTime  the time at which the stats were sampled
 * @param [in] stats  the last stats snapshot
 * @param [in] isFailure  whether the completion is due to a failure
 */
static void estimatorCompleteSTAStatsSample(stadbEntry_handle_t entry,
                                            const struct ether_addr *addr,
                                            estimatorSTAState_t *state,
                                            const struct timespec *sampleTime,
                                            const wlanif_staStatsSnapshot_t *stats,
                                            LBD_BOOL isFailure) {
    LBD_BOOL skipDisable = LBD_FALSE;

    // Always assume we are done. This will be adjusted in the continous
    // throughput mode below.
    state->throughputState = estimatorThroughputState_idle;
    if (isFailure) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: Aborting STA stats measurement for " lbMACAddFmt(":")
             " in state %u", __func__, lbMACAddData(addr->ether_addr_octet),
             state->throughputState);
    } else if (state->measurementMode == estimatorMeasurementMode_full) {
        estimatorPerform11kMeasurement(entry, addr, state);
    }

    if (!isFailure && estimatorState.config.enableContinuousThroughput) {
        // Store the last snapshot as the first sample and stay in the
        // state awaiting the second sample.
        lbDbgAssertExit(estimatorState.dbgModule, sampleTime);
        lbDbgAssertExit(estimatorState.dbgModule, stats);

        state->lastSampleTime = *sampleTime;
        state->lastStatsSnapshot = *stats;
        state->throughputState = estimatorThroughputState_awaitingSecondSample;
        skipDisable = LBD_TRUE;
    }

    if (!skipDisable) {
        wlanif_disableSTAStats(&state->statsEnabledBSSInfo);
    }

    estimatorCompletePerSTAAirtime(state, isFailure);

    if (!isFailure && estimatorState.config.enableContinuousThroughput) {
        state->measurementMode = estimatorMeasurementMode_throughputOnly;
    } else {
        state->measurementMode = estimatorMeasurementMode_none;
    }
}

/**
 * @brief Determine the channel to perform an 802.11k beacon report on and
 *        then request it.
 *
 * This will also start the 802.11k timer. Note that if no channel is
 * available, an error will be reported and the state will go back to idle.
 *
 * @param [in] entry  the STA for which to perform the measurement
 * @param [in] addr  the MAC address of the STA
 * @param [in] state  the current internal state of the STA
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
static LBD_STATUS estimatorPerform11kMeasurement(stadbEntry_handle_t entry,
                                                 const struct ether_addr *addr,
                                                 estimatorSTAState_t *state) {
    lbd_channelId_t dot11kChannel = steeralg_select11kChannel(entry);
    if (dot11kChannel != LBD_CHANNEL_INVALID) {
        if (wlanif_requestDownlinkRSSI(&state->statsEnabledBSSInfo, addr,
                                       stadbEntry_isRRMSupported(entry),
                                       1, &dot11kChannel) == LBD_OK) {
            estimatorStart11kResponseTimeout(state);
            return LBD_OK;
        } else {
            dbgf(estimatorState.dbgModule, DBGERR,
                 "%s: Failed to initiate 11k measuremrent for "
                 lbMACAddFmt(":") " on channel %u from serving BSS "
                 lbBSSInfoAddFmt(), __func__,
                 lbMACAddData(addr->ether_addr_octet), dot11kChannel,
                 lbBSSInfoAddData(&state->statsEnabledBSSInfo));
        }
    } else {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: No available channel for 11k measurement for "
             lbMACAddFmt(":"), __func__,
             lbMACAddData(addr->ether_addr_octet));
    }

    state->dot11kState = estimator11kState_idle;
    return LBD_NOK;
}

/**
 * @brief Update the state of the per-STA airtime estimation process.
 *
 * If all STAs that were having their airtime measured are complete, this
 * will generate the event indicating the number of successful measurements.
 *
 * @param [in] state  the internal state tracking this entry
 * @param [in] isFailure  whether the completion is due to a failure
 */
static void estimatorCompletePerSTAAirtime(estimatorSTAState_t *state,
                                           LBD_BOOL isFailure) {
    if (estimatorMeasurementMode_airtimeOnChannel == state->measurementMode) {
        if (!isFailure) {
            estimatorState.airtimeOnChannelState.numSTAsSuccess++;
        } else {
            estimatorState.airtimeOnChannelState.numSTAsFailure++;
        }

        estimatorState.airtimeOnChannelState.numSTAsRemaining--;
        if (0 == estimatorState.airtimeOnChannelState.numSTAsRemaining) {
            estimatorGeneratePerSTAAirtimeCompleteEvent(
                    estimatorState.airtimeOnChannelState.channelId,
                    estimatorState.airtimeOnChannelState.numSTAsSuccess);

            dbgf(estimatorState.dbgModule, DBGINFO,
                 "%s: Completed airtime on channel %u (success=%u, fail=%u)",
                 __func__, estimatorState.airtimeOnChannelState.channelId,
                 estimatorState.airtimeOnChannelState.numSTAsSuccess,
                 estimatorState.airtimeOnChannelState.numSTAsFailure);

            estimatorState.airtimeOnChannelState.channelId = LBD_CHANNEL_INVALID;
        }
    }
}

/**
 * @brief Dump the raw byte and rate stats to the debug logging stream.
 *
 * @param [in] state  the state object for the instance being logged
 * @param [in] addr  the MAC address for the STA
 * @param [in] stats  the snapshot to log
 */
static void estimatorLogSTAStats(estimatorSTAState_t *state,
                                 const struct ether_addr *addr,
                                 const wlanif_staStatsSnapshot_t *stats) {
    struct dbgModule *logModule =
        (state->measurementMode == estimatorMeasurementMode_throughputOnly) ?
        estimatorState.statsDbgModule : estimatorState.dbgModule;
    dbgf(logModule, DBGDUMP,
         "%s: Stats for " lbMACAddFmt(":") " on BSS " lbBSSInfoAddFmt()
         " for state %u: Tx bytes: %llu, Rx bytes: %llu, "
         "Tx rate: %u Mbps, Rx rate: %u Mbps",
         __func__, lbMACAddData(addr->ether_addr_octet),
         lbBSSInfoAddData((&state->statsEnabledBSSInfo)),
         state->throughputState,
         stats->txBytes, stats->rxBytes, stats->lastTxRate, stats->lastRxRate);
}

/**
 * @brief Send the measured statistics for the serving BSS for a specific STA
 *        out to diagnostic logging.
 *
 * @param [in] addr  the MAC address of the STA
 * @param [in] bssInfo  the BSS on which the STA is associated
 * @param [in] dlThroughput  the downlink throughput measured
 * @param [in] ulThroughput  the uplink throughput measured
 * @param [in] lastTxRate  the last MCS used on the downlink
 * @param [in] airtime  the estimated airtime (as computed from the
 *                      throughputs and rate)
 */
static void estimatorDiaglogServingStats(const struct ether_addr *addr,
                                         const lbd_bssInfo_t *bssInfo,
                                         lbd_linkCapacity_t dlThroughput,
                                         lbd_linkCapacity_t ulThroughput,
                                         lbd_linkCapacity_t lastTxRate,
                                         lbd_airtime_t airtime) {
    if (diaglog_startEntry(mdModuleID_Estimator,
                           estimator_msgId_servingDataMetrics,
                           diaglog_level_info)) {
        diaglog_writeMAC(addr);
        diaglog_writeBSSInfo(bssInfo);
        diaglog_write32(dlThroughput);
        diaglog_write32(ulThroughput);
        diaglog_write32(lastTxRate);
        diaglog_write8(airtime);
        diaglog_finishEntry();
    }
}

/**
 * @brief Send the estimated statistics for the non-serving BSS for a specific
 *        STA out to diagnostic logging.
 *
 * @param [in] addr  the MAC address of the STA
 * @param [in] bssInfo  the BSS on which the STA is associated
 * @param [in] capacity  the estimated full capacity for the STA on the BSS
 * @param [in] airtime  the estimated airtime (as computed from the
 *                      throughputs and rate)
 */
static void estimatorDiaglogNonServingStats(const struct ether_addr *addr,
                                            const lbd_bssInfo_t *bssInfo,
                                            lbd_linkCapacity_t capacity,
                                            lbd_airtime_t airtime) {
    if (diaglog_startEntry(mdModuleID_Estimator,
                           estimator_msgId_nonServingDataMetrics,
                           diaglog_level_info)) {
        diaglog_writeMAC(addr);
        diaglog_writeBSSInfo(bssInfo);
        diaglog_write32(capacity);
        diaglog_write8(airtime);
        diaglog_finishEntry();
    }
}

/**
 * @brief Determine if the serving data rate and airtime information is recent.
 *
 * @param [in] handle  the handle of the STA to check
 * @param [in] servingBSSStats  the stats to check for airtime recency
 *
 * @return LBD_TRUE if they are recent enough; otherwise LBD_FALSE
 */
static LBD_BOOL estimatorAreServingStatsRecent(
        const stadbEntry_handle_t handle,
        const stadbEntry_bssStatsHandle_t servingBSSStats) {
    lbd_linkCapacity_t dlRate, ulRate;
    time_t elapsedSecs;
    if (stadbEntry_getLastDataRate(handle, &dlRate, &ulRate,
                                   &elapsedSecs) == LBD_OK &&
            elapsedSecs <= MAX_SERVING_METRICS_AGE_SECS &&
            stadbEntry_getAirtime(handle, servingBSSStats, NULL) != LBD_INVALID_AIRTIME) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Determine if the estimator state indicates sampling is in progress
 *        for the STA.
 *
 * @param [in] state  the state object to check
 *
 * @return LBD_TRUE if sampling is in progress; otherwise LBD_FALSE
 */
static inline LBD_BOOL estimatorStateIsSampling(const estimatorSTAState_t *state) {
    return state->throughputState != estimatorThroughputState_idle;
}

/**
 * @brief Determine if the estimator state indicates the first sample still
 *        needs to be taken.
 *
 * @param [in] state  the state object to check
 *
 * @return LBD_TRUE if the first sample needs to be taken; otherwise LBD_FALSE
 */
static inline LBD_BOOL estimatorStateIsFirstSample(const estimatorSTAState_t *state) {
    return state->throughputState == estimatorThroughputState_awaitingFirstSample;
}

/**
 * @brief Determine if the estimator state indicates the second sample still
 *        needs to be taken.
 *
 * @param [in] state  the state object to check
 *
 * @return LBD_TRUE if the second sample needs to be taken; otherwise LBD_FALSE
 */
static inline LBD_BOOL estimatorStateIsSecondSample(const estimatorSTAState_t *state) {
    return state->throughputState == estimatorThroughputState_awaitingSecondSample;
}

/**
 * @brief Determine if the STA is in one of the 802.11k states where further
 *        full metrics measurements are not permitted.
 *
 * @param [in] state  the state object to check
 *
 * @return LBD_TRUE if the an 802.11k action is in progress; otherwise LBD_FALSE
 */
static inline LBD_BOOL estimatorStateIs11kNotAllowed(const estimatorSTAState_t *state) {
    return state->dot11kState != estimator11kState_idle;
}

/**
 * @brief Compute capacity and airtime information for the STA on the
 *        serving and optionally also the non-serving channels.
 *
 * This will result in the entry's serving channel full capacity, last data rate
 * and airtime information being updated. On the non-serving channel (if
 * requested), an estimated capacity and airtime will be stored. In the case
 * where both serving and non-serving are being estimeated, once both of these
 * are complete, an estimator_event_staDataMetricsComplete will be generated.
 * If only the serving channel is being estimated, once the estimate is done,
 * an estimator_perSTAAirtimeCompleteEvent will be generated.
 *
 * @param [in] handle  the handle of the STA for which to perform the estimate
 * @param [in] measurementMode  the type of measurement being undertaken
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
static LBD_STATUS estimatorEstimateSTADataMetricsImpl(
        stadbEntry_handle_t handle, estimatorMeasurementMode_e measurementMode) {
    stadbEntry_bssStatsHandle_t bssStats =
        stadbEntry_getServingBSS(handle, NULL);
    if (!bssStats) {
        // Invalid entry or not associated. Cannot measure the stats.
        return LBD_NOK;
    }

    const lbd_bssInfo_t *bssInfo = stadbEntry_resolveBSSInfo(bssStats);
    lbDbgAssertExit(estimatorState.dbgModule, bssInfo);

    estimatorSTAState_t *state = estimatorGetOrCreateSTAState(handle);
    if (!state) {
        const struct ether_addr *addr = stadbEntry_getAddr(handle);
        lbDbgAssertExit(estimatorState.dbgModule, addr);

        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: Failed to allocate estimator state for "
             lbMACAddFmt(":"), __func__,
             lbMACAddData(addr->ether_addr_octet));
        return LBD_NOK;
    }

    // When STA is either doing an 11k measurement or has the 11k prohibit
    // timer running, we do not permit a new measurement if we anticipate it
    // will need 11k immediately or shortly thereafter.
    if ((estimatorMeasurementMode_full == measurementMode ||
         estimatorMeasurementMode_airtimeOnChannel == measurementMode) &&
        (estimatorMeasurementMode_full == state->measurementMode ||
         estimatorStateIs11kNotAllowed(state))) {
        const struct ether_addr *addr = stadbEntry_getAddr(handle);
        lbDbgAssertExit(estimatorState.dbgModule, addr);

        dbgf(estimatorState.dbgModule, DBGINFO,
             "%s: Cannot perform estimate for "
             lbMACAddFmt(":") " as 11k estimate is in progress (state %u)",
             __func__, lbMACAddData(addr->ether_addr_octet),
             state->dot11kState);
        return LBD_NOK;
    }

    if (estimatorMeasurementMode_full == measurementMode) {
        if (estimatorStateIsSampling(state)) {
            // Upgrade the measurement to a full measurement.
            const struct ether_addr *addr = stadbEntry_getAddr(handle);
            lbDbgAssertExit(estimatorState.dbgModule, addr);

            dbgf(estimatorState.dbgModule, DBGINFO,
                 "%s: Upgrading to full metrics for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(addr->ether_addr_octet));

            if (estimatorMeasurementMode_airtimeOnChannel == state->measurementMode) {
                // An upgrade to full metrics should be considered a failure
                // since we do not want steeralg to consider it for offloading.
                estimatorCompletePerSTAAirtime(state, LBD_TRUE /* isFailure */);
            }

            state->measurementMode = measurementMode;
            return LBD_OK;
        } else if (estimatorAreServingStatsRecent(handle, bssStats)) {
            // No need to re-measure. Proceed immediately to 802.11k.
            const struct ether_addr *addr = stadbEntry_getAddr(handle);
            lbDbgAssertExit(estimatorState.dbgModule, addr);

            return estimatorPerform11kMeasurement(handle, addr, state);
        }
    }

    if (estimatorMeasurementMode_none == state->measurementMode) {
        // First enable the stats sampling on the radio. This will be a nop
        // if they are already enabled.
        if (wlanif_enableSTAStats(bssInfo) != LBD_OK) {
            // wlanif should have already printed an error message.
            return LBD_NOK;
        }
    }

    // Note that we are potentially resetting ourselves back to waiting for
    // the first sample. This is done to ensure that if we are doing an
    // airtime on channel estimate, all samples are performed at the same
    // time.
    state->measurementMode = measurementMode;
    state->throughputState = estimatorThroughputState_awaitingFirstSample;

    lbCopyBSSInfo(bssInfo, &state->statsEnabledBSSInfo);

    // If the timer is not already running, start it, but only if this
    // is not a continuous throughput estimate (since in that case the
    // timer always runs).
    if (estimatorMeasurementMode_throughputOnly != state->measurementMode) {
        unsigned secsRemaining, usecsRemaining;
        if (evloopTimeoutRemaining(&estimatorState.statsSampleTimer,
                                   &secsRemaining, &usecsRemaining)) {
            evloopTimeoutRegister(&estimatorState.statsSampleTimer,
                                  estimatorState.config.statsSampleInterval,
                                  0 /* usec */);
        }
    }

    return LBD_OK;
}

/**
 * @brief Handler for each entry when checking whether to update the STA
 *        statistics.
 *
 * @param [in] entry  the current entry being examined
 * @param [in] cookie  the parameter provided in the stadb_iterate call
 */
static void estimatorSTAStatsSampleIterateCB(stadbEntry_handle_t entry,
                                             void *cookie) {
    estimatorSTAStatsSnapshotParams_t *params =
        (estimatorSTAStatsSnapshotParams_t *) cookie;
    lbDbgAssertExit(estimatorState.dbgModule, params);

    estimatorSTAState_t *state = stadbEntry_getEstimatorState(entry);
    if (state) {
        const struct ether_addr *addr = stadbEntry_getAddr(entry);
        lbDbgAssertExit(estimatorState.dbgModule, addr);

        // Only need to do a sample in one of two states.
        if (estimatorStateIsFirstSample(state)) {
            // wlanif will check for a null BSS info and reject it.
            if (wlanif_sampleSTAStats(&state->statsEnabledBSSInfo, addr,
                                      LBD_FALSE /* rateOnly */,
                                      &state->lastStatsSnapshot) != LBD_OK) {
                estimatorCompleteSTAStatsSample(entry, addr, state,
                                                NULL, NULL, LBD_TRUE /* isFailure */);
            } else {
                lbGetTimestamp(&state->lastSampleTime);

                estimatorLogSTAStats(state, addr, &state->lastStatsSnapshot);

                state->throughputState = estimatorThroughputState_awaitingSecondSample;
                params->numPending++;
            }
        } else if (estimatorStateIsSecondSample(state)) {
            wlanif_staStatsSnapshot_t stats;
            if (wlanif_sampleSTAStats(&state->statsEnabledBSSInfo, addr,
                                      LBD_FALSE /* rateOnly */,
                                      &stats) != LBD_OK) {
                estimatorCompleteSTAStatsSample(entry, addr, state,
                                                NULL, NULL, LBD_TRUE /* isFailure */);
            } else {
                struct timespec curTime;
                lbGetTimestamp(&curTime);

                estimatorLogSTAStats(state, addr, &stats);

                if (stats.txBytes >= state->lastStatsSnapshot.txBytes &&
                    stats.rxBytes >= state->lastStatsSnapshot.rxBytes) {
                    LBD_BOOL isFailure = LBD_FALSE;
                    if (estimatorComputeAndStoreServingStats(entry, addr,
                                                             state, &curTime,
                                                             &stats) != LBD_OK) {
                        isFailure = LBD_TRUE;
                    }

                    estimatorCompleteSTAStatsSample(entry, addr, state,
                                                    &curTime, &stats, isFailure);
                } else {  // wraparound, so just set up for another sample
                    state->lastSampleTime = curTime;
                    state->lastStatsSnapshot = stats;
                    params->numPending++;
                }
            }
        } else if (estimatorState.config.enableContinuousThroughput &&
                   stadbEntry_getServingBSS(entry, NULL)) {
            // Restart the sampling.
            estimatorEstimateSTADataMetricsImpl(entry, estimatorMeasurementMode_throughputOnly);
        }
    } else if (estimatorState.config.enableContinuousThroughput &&
               stadbEntry_getServingBSS(entry, NULL)) {
        // Create the state and trigger the first sample.
        estimatorEstimateSTADataMetricsImpl(entry, estimatorMeasurementMode_throughputOnly);
    }
}

/**
 * @brief React to an expiry of the stats timeout handler.
 *
 * @param [in] cookie  ignored
 */
static void estimatorSTAStatsSampleTimeoutHandler(void *cookie) {
    estimatorSTAStatsSnapshotParams_t params = { 0 };
    if (stadb_iterate(estimatorSTAStatsSampleIterateCB, &params) != LBD_OK) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: Failed to iterate over STA DB; no updates will be done",
             __func__);
        return;
    }

    if (estimatorState.config.enableContinuousThroughput ||
        params.numPending > 0) {
        evloopTimeoutRegister(&estimatorState.statsSampleTimer,
                              estimatorState.config.statsSampleInterval,
                              0 /* usec */);
    }
}

/**
 * @brief Notify all registered oberservers that the provided entry can
 *        now have its data metrics measured again.
 *
 * @param [in] entry  the entry that was updated
 */
static void estimatorNotifySTADataMetricsAllowedObservers(
        stadbEntry_handle_t entry) {
    size_t i;
    for (i = 0; i < MAX_STA_DATA_METRICS_ALLOWED_OBSERVERS; ++i) {
        struct estimatorSTADataMetricsAllowedObserver *curSlot =
            &estimatorState.staDataMetricsAllowedObservers[i];
        if (curSlot->isValid) {
            curSlot->callback(entry, curSlot->cookie);
        }
    }
}

/**
 * @brief Determine whether the 802.11k response timer has elapsed for this
 *        STA.
 *
 * @param [in] state  the state for the STA to check
 * @param [in] curTime  the current timestamp
 *
 * @return LBD_TRUE if the timer has expired; otherwise LBD_FALSE
 */
static LBD_BOOL estimatorIsDot11kResponseTimeout(
        const estimatorSTAState_t *state, const struct timespec *curTime) {
    if (state->dot11kState == estimator11kState_awaiting11kBeaconReport &&
            lbIsTimeAfter(curTime, &state->dot11kTimeout)) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Determine whether the 802.11k prohibit timer has elapsed for this
 *        STA.
 *
 * @param [in] state  the state for the STA to check
 * @param [in] curTime  the current timestamp
 *
 * @return LBD_TRUE if the timer has expired; otherwise LBD_FALSE
 */
static LBD_BOOL estimatorIsDot11kProhibitTimeout(
        const estimatorSTAState_t *state, const struct timespec *curTime) {
    if (state->dot11kState == estimator11kState_awaiting11kProhibitExpiry &&
            lbIsTimeAfter(curTime, &state->dot11kTimeout)) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Examine a single entry to see if its 802.11k timer has elapsed.
 *
 * @param [in] entry  the entry to examine
 * @param [in] cookie  not used here
 */
static void estimatorDot11kIterateCB(stadbEntry_handle_t entry, void *cookie) {
    estimatorSTAState_t *state = stadbEntry_getEstimatorState(entry);
    if (state) {
        struct timespec curTime;
        lbGetTimestamp(&curTime);

        if (estimatorIsDot11kResponseTimeout(state, &curTime)) {
            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(estimatorState.dbgModule, addr);

            dbgf(estimatorState.dbgModule, DBGERR,
                 "%s: Timeout waiting for 802.11k response from "
                 lbMACAddFmt(":"), __func__,
                 lbMACAddData(addr->ether_addr_octet));

            estimatorState.numDot11kTimers--;
            estimatorCompleteDot11kMeasurement(state, addr, LBD_NOK);
        } else if (estimatorIsDot11kProhibitTimeout(state, &curTime)) {
            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(estimatorState.dbgModule, addr);

            dbgf(estimatorState.dbgModule, DBGINFO,
                 "%s: Prohibit timer expired for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(addr->ether_addr_octet));
            state->dot11kState = estimator11kState_idle;

            estimatorState.numDot11kTimers--;

            // Note that this should be done last to make sure the state has
            // been reset to idle before the upcall. This will allow the
            // observer to trigger a new measurement if necessary.
            estimatorNotifySTADataMetricsAllowedObservers(entry);
        } else if (estimatorStateIs11kNotAllowed(state) &&
                   lbIsTimeBefore(&state->dot11kTimeout,
                                  &estimatorState.nextDot11kExpiry)) {
            estimatorState.nextDot11kExpiry = state->dot11kTimeout;
        }
    }
}

/**
 * @brief React to an expiry of the timer for 802.11k operations.
 *
 * @param [in] cookie  ignored
 */
static void estimator11kTimeoutHandler(void *cookie) {
    struct timespec curTime;
    lbGetTimestamp(&curTime);

    // This is the worst case. The iteration will adjust this based on the
    // actual devices that are still under prohibition or awaiting 11k
    // response.
    estimatorState.nextDot11kExpiry = curTime;
    estimatorState.nextDot11kExpiry.tv_sec +=
         estimatorState.config.dot11kProhibitTime;

    if (stadb_iterate(estimatorDot11kIterateCB, NULL) != LBD_OK) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: Failed to iterate over station database", __func__);

        // For now we are falling through to reschedule the timer.
    }

    if (estimatorState.numDot11kTimers != 0) {
        // + 1 here to make sure the timer expires after the deadline
        // (to avoid having to schedule a quick timer).
        evloopTimeoutRegister(&estimatorState.dot11kTimer,
                              estimatorState.nextDot11kExpiry.tv_sec + 1 -
                              curTime.tv_sec, 0);
    }
}

/**
 * @brief Handler for each entry when checking whether to measure the STA
 *        airtime on a particular channel.
 *
 * @param [in] entry  the current entry being examined
 * @param [inout] cookie  the parameter provided in the stadb_iterate call
 */
static void estimatorStartSTAAirtimeIterateCB(stadbEntry_handle_t entry,
                                              void *cookie) {
    estimatorPerSTAAirtimeOnChannelParams_t *params =
        (estimatorPerSTAAirtimeOnChannelParams_t *) cookie;
    lbDbgAssertExit(estimatorState.dbgModule, params);

    stadbEntry_bssStatsHandle_t servingBSS = stadbEntry_getServingBSS(entry, NULL);
    if (!servingBSS) {
        // Not associated; nothing to do.
        return;
    }

    const struct ether_addr *addr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(estimatorState.dbgModule, addr);

    const lbd_bssInfo_t *servingBSSInfo = stadbEntry_resolveBSSInfo(servingBSS);
    lbDbgAssertExit(estimatorState.dbgModule, servingBSSInfo);
    if (servingBSSInfo->channelId != params->channelId ||
        stadbEntry_getReservedAirtime(entry, servingBSS) != LBD_INVALID_AIRTIME) {
        dbgf(estimatorState.dbgModule, DBGDEBUG,
             "%s: Not measuring " lbMACAddFmt(":") " due to channel mismatch "
             "or airtime reservation", __func__,
             lbMACAddData(addr->ether_addr_octet));
        return;
    }

    // Device must be active in order to have its airtime measured, regardless
    // of whether it is eligible for active steering or not.
    LBD_BOOL isActive = LBD_FALSE;
    if (stadbEntry_getActStatus(entry, &isActive, NULL /* age */) == LBD_NOK ||
        !isActive) {
        dbgf(estimatorState.dbgModule, DBGDEBUG,
             "%s: Not measuring " lbMACAddFmt(":") " due to not active",
             __func__, lbMACAddData(addr->ether_addr_octet));
        return;
    }

    // Only if the device is active steering eligible do we even consider it
    // for an airtime measurement (as when it is not, we either won't be able
    // to steer it because it is active or steering it won't reduce the
    // airtime because it is idle).
    if (steerexec_determineSteeringEligibility(entry) !=
            steerexec_steerEligibility_active) {
        dbgf(estimatorState.dbgModule, DBGDEBUG,
             "%s: Not measuring " lbMACAddFmt(":") " due to not active "
             "steering eligible", __func__, lbMACAddData(addr->ether_addr_octet));
        return;
    }

    // Attempt to start the airtime measurement. If this currently prohibited
    // (eg. due to it being done too recently ago), then we'll just skip this
    // entry.
    if (estimatorEstimateSTADataMetricsImpl(
                entry, estimatorMeasurementMode_airtimeOnChannel) == LBD_OK) {
        params->numSTAsStarted++;
    }
    // else, it probably is already running; an error message should have been
    // printed
}

/**
 * @brief Generate the event indicating that per-STA airtime estimates are
 *        complete on the provided channel.
 *
 * @param [in] channelId  the channel on which the estimate was done
 * @param [in] numSTAsEstimated  the number of STAs which had estimates
 *                               written
 */
static void estimatorGeneratePerSTAAirtimeCompleteEvent(
        lbd_channelId_t channelId, size_t numSTAsEstimated) {
    estimator_perSTAAirtimeCompleteEvent_t event;
    event.channelId = channelId;
    event.numSTAsEstimated = numSTAsEstimated;

    mdCreateEvent(mdModuleID_Estimator, mdEventPriority_Low,
                  estimator_event_perSTAAirtimeComplete,
                  &event, sizeof(event));
}

#ifdef LBD_DBG_MENU
static const char *estimatorThroughputEstimationStateStrs[] = {
    "Idle",
    "Awaiting 1st sample",
    "Awaiting 2nd sample",
    "Awaiting beacon report",
    "802.11k prohibited"
};

/**
 * @brief Obtain a string representation of the data rate estimation state.
 *
 * @param [in] state  the state for which to get the string
 *
 * @return  the string, or the empty string for an invalid state
 */
static const char *estimatorGetThroughputEstimationStateStr(
        estimatorThroughputEstimationState_e state) {
    // Should not be possible unless a new state is introduced without
    // updating the array.
    lbDbgAssertExit(estimatorState.dbgModule,
                    state < sizeof(estimatorThroughputEstimationStateStrs) /
                    sizeof(estimatorThroughputEstimationStateStrs[0]));

    return estimatorThroughputEstimationStateStrs[state];
}

static const char *estimator11kStateStrs[] = {
    "Idle",
    "Awaiting beacon report",
    "802.11k prohibited"
};

/**
 * @brief Obtain a string representation of the data rate estimation state.
 *
 * @param [in] state  the state for which to get the string
 *
 * @return  the string, or the empty string for an invalid state
 */
static const char *estimatorGet11kStateStr(estimator11kState_e state) {
    // Should not be possible unless a new state is introduced without
    // updating the array.
    lbDbgAssertExit(estimatorState.dbgModule,
                    state < sizeof(estimator11kStateStrs) /
                    sizeof(estimator11kStateStrs[0]));

    return estimator11kStateStrs[state];
}

// Help messages for estimator status command
static const char *estimatorMenuStatusHelp[] = {
    "s -- display status for all STAs",
    "Usage:",
    "\ts: dump status information",
    NULL
};

/**
 * @brief Parameters for dumping status when iterating over the station
 *        database.
 */
struct estimatorStatusCmdContext {
    struct cmdContext *context;
};

/**
 * @brief Dump the header for the STA status information.
 *
 * @param [in] context  the context handle to use for output
 */
static void estimatorStatusIterateCB(stadbEntry_handle_t entry, void *cookie) {
    struct estimatorStatusCmdContext *statusContext =
        (struct estimatorStatusCmdContext *) cookie;
    lbDbgAssertExit(estimatorState.dbgModule, statusContext);

    estimatorSTAState_t *state = stadbEntry_getEstimatorState(entry);
    if (state) {
        const struct ether_addr *addr = stadbEntry_getAddr(entry);
        lbDbgAssertExit(estimatorState.dbgModule, addr);

        u_int32_t remainingUsec = 0;

        // Only compute the 11k remaining time if it is actually running.
        if (estimator11kState_awaiting11kBeaconReport == state->dot11kState ||
            estimator11kState_awaiting11kProhibitExpiry == state->dot11kState) {
            struct timespec curTime;
            lbGetTimestamp(&curTime);

            remainingUsec =
                estimatorComputeTimeDiff(&curTime, &state->dot11kTimeout);
        }

        cmdf(statusContext->context, lbMACAddFmt(":") "  %-25s  %-25s  %u.%u\n",
             lbMACAddData(addr->ether_addr_octet),
             estimatorGetThroughputEstimationStateStr(state->throughputState),
             estimatorGet11kStateStr(state->dot11kState),
             remainingUsec / USECS_PER_SEC, remainingUsec % USECS_PER_SEC);
    }
}

#ifndef GMOCK_UNIT_TESTS
static
#endif
void estimatorMenuStatusHandler(struct cmdContext *context,
                                const char *cmd) {
    struct estimatorStatusCmdContext statusContext = {
        context
    };

    cmdf(context, "%-17s  %-25s  %-25s  %-12s\n",
         "MAC Address", "Throughput State", "802.11k State",
         "802.11k Expiry (s)");
    if (stadb_iterate(estimatorStatusIterateCB, &statusContext) != LBD_OK) {
        cmdf(context, "Iteration over station database failed\n");
    }

    cmdf(context, "\n");
}

// Help messages for estimator rate command
static const char *estimatorMenuRateHelp[] = {
    "rate -- estimate rate for a STA",
    "Usage:",
    "\trate <mac addr>: estimate for the specified STA",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void estimatorMenuRateHandler(struct cmdContext *context,
                              const char *cmd) {
    if (!cmd) {
        cmdf(context, "estimator 'rate' command must include MAC address\n");
        return;
    }

    const char *arg = cmdWordFirst(cmd);

    const struct ether_addr *staAddr = ether_aton(arg);
    if (!staAddr) {
        cmdf(context, "estimator 'rate' command invalid MAC address: %s\n",
             arg);
        return;
    }

    stadbEntry_handle_t entry = stadb_find(staAddr);
    if (!entry) {
        cmdf(context, "estimator 'rate' unknown MAC address: "
                      lbMACAddFmt(":") "\n",
             lbMACAddData(staAddr->ether_addr_octet));
        return;
    }

    if (estimator_estimateSTADataMetrics(entry) != LBD_OK) {
        cmdf(context, "estimator 'rate' " lbMACAddFmt(":")
                      " failed\n",
             lbMACAddData(staAddr->ether_addr_octet));
    }
}

// Help messages for estimator airtime command
static const char *estimatorMenuAirtimeHelp[] = {
    "airtime -- estimate airtime for all active STAs on a channel",
    "Usage:",
    "\tairtime <channel>: estimate for the specified channel",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void estimatorMenuAirtimeHandler(struct cmdContext *context,
                                 const char *cmd) {
    if (!cmd) {
        cmdf(context, "estimator 'airtime' command must include channel\n");
        return;
    }

    const char *arg = cmdWordFirst(cmd);
    if (!cmdWordDigits(arg)) {
        cmdf(context, "Channel must be a decimal number\n");
        return;
    }

    lbd_channelId_t channel = atoi(arg);
    if (estimator_estimatePerSTAAirtimeOnChannel(channel) != LBD_OK) {
        cmdf(context, "estimator 'airtime' %u failed\n", channel);
    }
}

// Sub-menus for the estimator debug CLI.
static const struct cmdMenuItem estimatorMenu[] = {
    CMD_MENU_STANDARD_STUFF(),
    { "s", estimatorMenuStatusHandler, NULL, estimatorMenuStatusHelp },
    { "rate", estimatorMenuRateHandler, NULL, estimatorMenuRateHelp },
    { "airtime", estimatorMenuAirtimeHandler, NULL, estimatorMenuAirtimeHelp },
    CMD_MENU_END()
};

// Top-level estimator help items
static const char *estimatorMenuHelp[] = {
    "estimator -- Rate estimator",
    NULL
};

// Top-level station monitor menu.
static const struct cmdMenuItem estimatorMenuItem = {
    "estimator",
    cmdMenu,
    (struct cmdMenuItem *) estimatorMenu,
    estimatorMenuHelp
};

#endif /* LBD_DBG_MENU */

/**
 * @brief Initialize the debug CLI hooks for this module (if necesary).
 */
static void estimatorMenuInit(void) {
#ifdef LBD_DBG_MENU
    cmdMainMenuAdd(&estimatorMenuItem);
#endif /* LBD_DBG_MENU */
}
