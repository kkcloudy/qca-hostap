// vim: set et sw=4 sts=4 cindent:
/*
 * @File: bandmon.c
 *
 * @Abstract: Implementation of band monitor public APIs
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

#include <stdlib.h>
#include <stdint.h>

#include <dbg.h>

#if LBD_DBG_MENU
#include <cmd.h>
#endif  /* LBD_DBG_MENU */

#include "internal.h"
#include "lbd_assert.h"
#include "module.h"
#include "profile.h"
#include "stadb.h"
#include "steerexec.h"
#include "diaglog.h"

#include "bandmon.h"
#include "bandmonDiaglogDefs.h"

// Forward decls
static void bandmonMenuInit(void);

static LBD_STATUS bandmonInitializeChannels(void);
static struct bandmonChannelUtilizationInfo_t *
    bandmonGetChannelUtilizationInfo(lbd_channelId_t channel);

static void bandmonReadConfig(void);

static void bandmonRSSIObserver(stadbEntry_handle_t entry,
                                stadb_rssiUpdateReason_e reason, void *cookie);
static void bandmonSteeringAllowedObserver(stadbEntry_handle_t entry, void *cookie);

static inline LBD_BOOL bandmonAreAllUtilizationsRecorded(void);
static u_int8_t bandmonDetermineOperatingRegion(void);

static void bandmonHandleChanUtilEvent(struct mdEventNode *event);
static void bandmonHandleVAPRestartEvent(struct mdEventNode *event);
static void bandmonHandleChanUtil(lbd_channelId_t channelId, u_int8_t utilization);
static void bandmonTransitionBlackoutState(void);

static LBD_STATUS bandmonUpdateOverload(void);
static void bandmonProcessOperatingRegion(void);

static LBD_BOOL bandmonUpdatePreAssocSteeringCallback(
    stadbEntry_handle_t entryHandle, stadbEntry_bssStatsHandle_t bssHandle,
    void *cookie);
static void bandmonUpdatePreAssocSteering(stadbEntry_handle_t entry,
                                          LBD_BOOL abortRequired);

static LBD_BOOL bandmonIsPreAssocSteeringPermitted(void);
static void bandmonStaDBIterateCB(stadbEntry_handle_t entry, void *cookie);

static lbd_airtime_t bandmonCanSupportClientImpl(
        const struct bandmonChannelUtilizationInfo_t *chanInfo,
        lbd_airtime_t airtime);

static void bandmonGenerateOverloadChangeEvent(void);
static void bandmonGenerateUtilizationUpdateEvent(void);

static void bandmonDiaglogOverloadChange(void);
static void bandmonDiaglogBlackoutChange(LBD_BOOL isBlackoutStart);

/**
 * @brief Internal state for the band monitor module.
 */
static struct {
    struct dbgModule *dbgModule;

#ifdef LBD_DBG_MENU
    /// When debug mode is enabled, all utilization events are ignored and
    /// changes have to come via the debug CLI.
    LBD_BOOL debugModeEnabled;
#endif /* LBD_DBG_MENU */

    /// Configuration data obtained at init time.
    struct {
        /// The per-band medium utilization overload thresholds for the
        /// overload condition.
        u_int8_t overloadThresholds[wlanif_band_invalid];

        /// The per-band medium utilization safety thresholds for active
        /// steering.
        u_int8_t safetyThresholds[wlanif_band_invalid];

        /// The maximum age an RSSI measurements can be before it is
        /// considered to old to be used when making a steering decision.
        time_t rssiMaxAge;

        /// The RSSI value above which pre-association steering to a
        /// non-overloaded channel may be done.
        u_int8_t rssiSafetyThreshold;

        /// Number of probes required when non-associted band RSSI is valid
        u_int8_t probeCountThreshold;
    } config;

    /// The number of currently active channels.
    u_int8_t numActiveChannels;

    /// Bitmask that is used to keep track of the updates for each band.
    /// The updates are complete on all channels when the bitmask is either
    /// all 0's or all 1's (up to the bit index for the number of active
    /// channels).
    u_int8_t utilizationsState;

    /// State capturing whether we are in a steering blackout window or
    /// one is coming up at the next utilization update.
    enum bandmon_blackoutState_e {
        /// No steering blackout is in effect.
        bandmon_blackoutState_idle,

        /// Next utilization update will be a steering blackout.
        bandmon_blackoutState_pending,

        /// Next utilization update should re-enter the steering blackout.
        /// This is used when there are projected utilization changes
        /// while already in a steering blackout (eg. due to downgrade
        /// steering).
        bandmon_blackoutState_activeWithPending,

        /// Currently in a steering blackout.
        bandmon_blackoutState_active
    } blackoutState;

    /// Whether a one shot event for utilization update was requested.
    LBD_BOOL oneShotUtilizationRequested;

    /// State information on a per active channel basis.
    struct bandmonChannelUtilizationInfo_t {
        /// The index of the bit in the utilizationsState value for this
        /// entry.
        size_t bitIndex;

        /// The channel index.
        lbd_channelId_t channelId;

        /// The last measured utilization (the percentage of time the channel
        /// was busy, between 0 and 100) during a period in which no active
        /// upgrade steering and no idle upgrade steerings were allowed.
        u_int8_t measuredUtilization;

        /// The amount the utilization (percentage of time the channel is
        /// busy) on this channel is projected to increase based on the active
        //steering attempts done since the last measurement.
        u_int8_t projectedUtilizationIncrease;

        /// Whether the overload value has changed since last reported.
        LBD_BOOL overloadChanged : 1;

        /// Whether the channel is currently considered overloaded (based on
        /// measured utilization only) or not.
        LBD_BOOL isOverloaded : 1;

        /// Whether on the last assessment, the channel was considered
        /// overloaded.
        LBD_BOOL wasOverloaded : 1;
    } channelUtilizations[WLANIF_MAX_RADIOS];

} bandmonState;

/**
 * @brief Parameters that are populated during iteration over the supported
 *        BSSes.
 *
 * Once the iteration completes, these parameters indicate whether each band has
 * candidate channels that meet RSSI threshold for pre-association steering for
 * a given STA.
 */
typedef struct bandmonUpdatePreAssocSteeringParams {
    /// The number of candidate channels that meet pre-assoc steering
    /// RSSI threshold (may not be final candidate due to overload).
    u_int8_t candidateChannelCount;

    /// Whether a band has sufficient RSSI for pre-assoc steering. It will
    /// be marked as sufficient if at least one channel on the band meets
    /// the RSSI criteria.
    LBD_BOOL bandHasSufficientRSSI[wlanif_band_invalid];
} bandmonUpdatePreAssocSteeringParams;


/**
 * @brief Default configuration values.
 *
 * These are used if the config file does not specify them.
 */
static struct profileElement bandmonElementDefaultTable[] = {
    { BANDMON_MU_OVERLOAD_THRESHOLD_W2_KEY, "70" },
    { BANDMON_MU_OVERLOAD_THRESHOLD_W5_KEY, "70" },
    { BANDMON_MU_SAFETY_THRESHOLD_W2_KEY,   "50" },
    { BANDMON_MU_SAFETY_THRESHOLD_W5_KEY,   "60" },
    { BANDMON_RSSI_SAFETY_THRESHOLD_KEY,    "20" },
    { BANDMON_RSSI_MAX_AGE_KEY,             "5"  },
    { BANDMON_PROBE_COUNT_THRESHOLD_KEY,    "1" },
    { NULL, NULL }
};

#define BANDMON_UTILIZATION_INVALID 255

// ====================================================================
// Public API
// ====================================================================

LBD_STATUS bandmon_init(void) {
    bandmonState.dbgModule = dbgModuleFind("bandmon");
    bandmonState.dbgModule->Level = DBGINFO;

    // Start with no reading on any channels.
    bandmonState.utilizationsState = 0;
    memset(bandmonState.channelUtilizations, 0,
           sizeof(bandmonState.channelUtilizations));

    bandmonState.blackoutState = bandmon_blackoutState_idle;
    bandmonState.oneShotUtilizationRequested = LBD_FALSE;

    if (stadb_registerRSSIObserver(bandmonRSSIObserver,
                                   &bandmonState) != LBD_OK) {
        return LBD_NOK;
    }

    // The same observer is used for steering prohibit changes as we need
    // the same behavior (assessing the RSSI and then possibly installing
    // the blacklists).
    if (steerexec_registerSteeringAllowedObserver(
                bandmonSteeringAllowedObserver, &bandmonState) != LBD_OK) {
        return LBD_NOK;
    }

    // Resolve the active channels.
    if (bandmonInitializeChannels() != LBD_OK) {
        return LBD_NOK;
    }

    bandmonReadConfig();

    mdEventTableRegister(mdModuleID_BandMon, bandmon_event_maxnum);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_chan_util,
                          bandmonHandleChanUtilEvent);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_vap_restart,
                          bandmonHandleVAPRestartEvent);

    bandmonMenuInit();
    return LBD_OK;
}

LBD_BOOL bandmon_areAllChannelsOverloaded(void) {
    size_t i;
    for (i = 0; i < bandmonState.numActiveChannels; ++i) {
        struct bandmonChannelUtilizationInfo_t *chanInfo =
            &bandmonState.channelUtilizations[i];
        if (!chanInfo->isOverloaded) {
            return LBD_FALSE;
        }
    }

    // If reach here, all channels have been checked and found to be
    // overloaded.
    return LBD_TRUE;
}

lbd_channelId_t bandmon_getLeastLoadedChannel(wlanif_band_e band) {
    lbd_channelId_t minLoadChannel = LBD_CHANNEL_INVALID;
    u_int8_t currentMinUtilization = UINT8_MAX;

    size_t i;
    for (i = 0; i < bandmonState.numActiveChannels; ++i) {
        struct bandmonChannelUtilizationInfo_t *chanInfo =
            &bandmonState.channelUtilizations[i];
        if (wlanif_resolveBandFromChannelNumber(chanInfo->channelId) == band &&
                !chanInfo->isOverloaded &&
                chanInfo->measuredUtilization < currentMinUtilization) {
            minLoadChannel = chanInfo->channelId;
            currentMinUtilization = chanInfo->measuredUtilization;
        }
    }

    return minLoadChannel;
}

LBD_STATUS bandmon_isChannelOverloaded(lbd_channelId_t channelId,
                                       LBD_BOOL *isOverloaded) {
    if (!isOverloaded) {
        return LBD_NOK;
    }

    const struct bandmonChannelUtilizationInfo_t *chanInfo =
        bandmonGetChannelUtilizationInfo(channelId);
    if (chanInfo) {
        *isOverloaded = chanInfo->isOverloaded;
        return LBD_OK;
    }

    return LBD_NOK;
}

lbd_airtime_t bandmon_getMeasuredUtilization(lbd_channelId_t channelId) {
    const struct bandmonChannelUtilizationInfo_t *chanInfo =
        bandmonGetChannelUtilizationInfo(channelId);
    if (chanInfo) {
        return chanInfo->measuredUtilization;
    }

    return LBD_INVALID_AIRTIME;
}

LBD_BOOL bandmon_isInSteeringBlackout(void) {
    return bandmonState.blackoutState == bandmon_blackoutState_activeWithPending ||
           bandmonState.blackoutState == bandmon_blackoutState_active;
}

lbd_airtime_t bandmon_canSupportClient(lbd_channelId_t channelId,
                                       lbd_airtime_t airtime) {
    const struct bandmonChannelUtilizationInfo_t *chanInfo =
        bandmonGetChannelUtilizationInfo(channelId);
    return bandmonCanSupportClientImpl(chanInfo, airtime);
}

LBD_BOOL bandmon_canOffloadClientFromBand(wlanif_band_e band) {
    if (band >= wlanif_band_invalid) {
        // Invalid band.
        return LBD_FALSE;
    }

    size_t i;
    for (i = 0; i < bandmonState.numActiveChannels; ++i) {
        struct bandmonChannelUtilizationInfo_t *chanInfo =
            &bandmonState.channelUtilizations[i];
        if (band ==
            wlanif_resolveBandFromChannelNumber(chanInfo->channelId)) {
            continue;
        }

        if (bandmonCanSupportClientImpl(chanInfo, 0) != LBD_INVALID_AIRTIME) {
            // This channel has at least some headroom.
            return LBD_TRUE;
        }
    }

    // No channels have any room.
    return LBD_FALSE;
}

LBD_STATUS bandmon_addProjectedAirtime(lbd_channelId_t channelId,
                                       lbd_airtime_t airtime,
                                       LBD_BOOL allowAboveSafety) {
    struct bandmonChannelUtilizationInfo_t *chanInfo =
        bandmonGetChannelUtilizationInfo(channelId);
    if (!chanInfo) { return LBD_NOK; }

    if (allowAboveSafety ||
        bandmonCanSupportClientImpl(chanInfo, airtime) != LBD_INVALID_AIRTIME) {
        chanInfo->projectedUtilizationIncrease += airtime;

        if (bandmonState.blackoutState == bandmon_blackoutState_idle) {
            bandmonState.blackoutState = bandmon_blackoutState_pending;
        } else if (bandmonState.blackoutState ==
                bandmon_blackoutState_active) {
            bandmonState.blackoutState =
                bandmon_blackoutState_activeWithPending;
        }

        return LBD_OK;
    }

    return LBD_NOK;
}

void bandmon_enableOneShotUtilizationEvent(void) {
    bandmonState.oneShotUtilizationRequested = LBD_TRUE;
}

LBD_STATUS bandmon_fini(void) {
    LBD_STATUS status =
        steerexec_unregisterSteeringAllowedObserver(
                bandmonSteeringAllowedObserver, &bandmonState);
    status |=
        stadb_unregisterRSSIObserver(bandmonRSSIObserver,
                                     &bandmonState);

    return status;
}

LBD_STATUS bandmon_isExpectedBelowSafety(lbd_channelId_t channelId,
                                         lbd_airtime_t totalOffloadedAirtime,
                                         LBD_BOOL *isBelow) {
    struct bandmonChannelUtilizationInfo_t *chanInfo =
        bandmonGetChannelUtilizationInfo(channelId);
    if (!chanInfo || !isBelow ||
        totalOffloadedAirtime == LBD_INVALID_AIRTIME) {
        return LBD_NOK;
    }
    *isBelow = LBD_FALSE;
    if (totalOffloadedAirtime >= chanInfo->measuredUtilization) {
        dbgf(bandmonState.dbgModule, DBGINFO,
             "%s: Offload more airtime than measured on Channel %u: "
             "offloaded [%u%%] vs measured [%u%%]",
             __func__, chanInfo->channelId, totalOffloadedAirtime,
             chanInfo->measuredUtilization);
        return LBD_NOK;
    }

    wlanif_band_e band =
        wlanif_resolveBandFromChannelNumber(chanInfo->channelId);
    if (bandmonState.config.safetyThresholds[band] > (chanInfo->measuredUtilization +
                                                      chanInfo->projectedUtilizationIncrease -
                                                      totalOffloadedAirtime)) {
        *isBelow = LBD_TRUE;
    }

    return LBD_OK;
}

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Determine whether the airtime can fit on the given channel
 *        without causing it to go above the safety threshold.
 *
 * This considers any projected airtime increase recorded via
 * bandmon_addProjectedAirtime() in addition to the measured utilization.
 *
 * @param [in] chanInfo  the channel to check
 * @param [in] airtime
 *
 * @return LBD_INVALID_AIRTIME if airtime can not fit on the
 *         given channel without causing it to go above the
 *         safety threshold.  Otherwise return the difference
 *         between the safety threshold and the (measured +
 *         projected) utilization (amount of headroom
 *         available).  Note the projected utilization does not
 *         include the airtime passed in.
 */
static lbd_airtime_t bandmonCanSupportClientImpl(
        const struct bandmonChannelUtilizationInfo_t *chanInfo,
        lbd_airtime_t airtime) {
    if (airtime <= 100 && chanInfo) {
        wlanif_band_e band =
            wlanif_resolveBandFromChannelNumber(chanInfo->channelId);
        if (chanInfo->measuredUtilization +
            chanInfo->projectedUtilizationIncrease + airtime <=
                bandmonState.config.safetyThresholds[band]) {
            return bandmonState.config.safetyThresholds[band] -
                (chanInfo->measuredUtilization +
                 chanInfo->projectedUtilizationIncrease);
        }
    }

    return LBD_INVALID_AIRTIME;
}

/**
 * @brief Count the number of channels that are currently marked as overloaded.
 *
 * @return the number of channels that are overloaded
 */
static u_int8_t bandmonGetNumOverloadedChannels(void) {
    u_int8_t numOverloaded = 0;
    size_t i;
    for (i = 0; i < bandmonState.numActiveChannels; ++i) {
        struct bandmonChannelUtilizationInfo_t *chanInfo =
            &bandmonState.channelUtilizations[i];
        if (chanInfo->isOverloaded) {
            ++numOverloaded;
        }
    }

    return numOverloaded;
}

/**
 * @brief Query the active channels and reset the overload state for them.
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
static LBD_STATUS bandmonInitializeChannels(void) {
    lbd_channelId_t channels[WLANIF_MAX_RADIOS];
    bandmonState.numActiveChannels =
        wlanif_getChannelList(channels, WLANIF_MAX_RADIOS);
    if (0 == bandmonState.numActiveChannels) {
        return LBD_NOK;
    }

    // Now reset all of the utilization information for the channels.
    size_t i;
    for (i = 0; i < bandmonState.numActiveChannels; ++i) {
        struct bandmonChannelUtilizationInfo_t *chanInfo =
            &bandmonState.channelUtilizations[i];
        chanInfo->bitIndex = i;
        chanInfo->channelId = channels[i];
        chanInfo->measuredUtilization = 0;
        chanInfo->projectedUtilizationIncrease = 0;

        // Note that isOverloaded and wasOverloaded are intentionally not
        // reset here. This allows us to determine whether there was an
        // overload change when we reset due to a channel change.
    }

    return LBD_OK;
}

/**
 * @brief Find the matching entry for the channel utilization by the channel
 *        number.
 *
 * @param [in] channelId  the channel number
 *
 * @return the handle to the entry, or NULL if no match was found
 */
static struct bandmonChannelUtilizationInfo_t *
    bandmonGetChannelUtilizationInfo(lbd_channelId_t channelId) {
    size_t i;
    for (i = 0; i < bandmonState.numActiveChannels; ++i) {
        struct bandmonChannelUtilizationInfo_t *chanInfo =
            &bandmonState.channelUtilizations[i];
        if (channelId == chanInfo->channelId) {
            return chanInfo;
        }
    }

    return NULL;
}

/**
 * @brief Read the configuration from the file.
 */
static void bandmonReadConfig(void) {
    bandmonState.config.overloadThresholds[wlanif_band_24g] =
        profileGetOptsInt(mdModuleID_BandMon,
                          BANDMON_MU_OVERLOAD_THRESHOLD_W2_KEY,
                          bandmonElementDefaultTable);
    bandmonState.config.overloadThresholds[wlanif_band_5g] =
        profileGetOptsInt(mdModuleID_BandMon,
                          BANDMON_MU_OVERLOAD_THRESHOLD_W5_KEY,
                          bandmonElementDefaultTable);

    bandmonState.config.safetyThresholds[wlanif_band_24g] =
        profileGetOptsInt(mdModuleID_BandMon,
                          BANDMON_MU_SAFETY_THRESHOLD_W2_KEY,
                          bandmonElementDefaultTable);
    bandmonState.config.safetyThresholds[wlanif_band_5g] =
        profileGetOptsInt(mdModuleID_BandMon,
                          BANDMON_MU_SAFETY_THRESHOLD_W5_KEY,
                          bandmonElementDefaultTable);

    bandmonState.config.rssiSafetyThreshold =
        profileGetOptsInt(mdModuleID_BandMon,
                          BANDMON_RSSI_SAFETY_THRESHOLD_KEY,
                          bandmonElementDefaultTable);

    bandmonState.config.rssiMaxAge =
        profileGetOptsInt(mdModuleID_BandMon,
                          BANDMON_RSSI_MAX_AGE_KEY,
                          bandmonElementDefaultTable);

    bandmonState.config.probeCountThreshold =
        profileGetOptsInt(mdModuleID_BandMon,
                          BANDMON_PROBE_COUNT_THRESHOLD_KEY,
                          bandmonElementDefaultTable);
}

/**
 * @brief Callback function invoked by the station database module when
 *        the RSSI for a specific STA has been updated.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] reason  the reason for the RSSI update
 * @param [in] cookie  the pointer to our internal state
 */
static void bandmonRSSIObserver(stadbEntry_handle_t entry,
                                stadb_rssiUpdateReason_e reason,
                                void *cookie) {
    if (bandmonIsPreAssocSteeringPermitted()) {
        // We ignore the cookie here, since our state is static anyways.
        // We also ignore the reason for the RSSI update as in all cases, we want
        // to do the same thing.
        bandmonUpdatePreAssocSteering(entry, LBD_FALSE /* abortRequired */);
    }
}

/**
 * @brief Callback function invoked by the steering executor when steering
 *        becomes possible again for a given STA.
 *
 * @param [in] entry  the entry that is now steerable
 * @param [in] cookie  the pointer to our internal state
 */
static void bandmonSteeringAllowedObserver(stadbEntry_handle_t entry, void *cookie) {
    if (bandmonIsPreAssocSteeringPermitted()) {
        // We ignore the cookie here, since our state is static anyways.
        bandmonUpdatePreAssocSteering(entry, LBD_FALSE /* abortRequired */);
    }
}

/**
 * @brief Update the overload state for the channel based on the utilization
 *        value stored.
 *
 * @param [in] chanInfo  the information for the channel to update
 *
 * @return LBD_TRUE if there was a change in the overload; otherwise LBD_FALSE
 */
static LBD_BOOL bandmonUpdateChannelOverload(
        struct bandmonChannelUtilizationInfo_t *chanInfo) {
    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(chanInfo->channelId);

    LBD_BOOL isOverloaded = LBD_FALSE;
    if (wlanif_band_24g == band) {
        if (chanInfo->measuredUtilization >
                bandmonState.config.overloadThresholds[wlanif_band_24g]) {
            isOverloaded = LBD_TRUE;
        }
    } else {  // must be 5 GHz
        if (chanInfo->measuredUtilization >
                bandmonState.config.overloadThresholds[wlanif_band_5g]) {
            isOverloaded = LBD_TRUE;
        }
    }

    if (chanInfo->isOverloaded != isOverloaded) {
        chanInfo->wasOverloaded = chanInfo->isOverloaded;
        chanInfo->isOverloaded = isOverloaded;
        return LBD_TRUE;
    } else {
        // If there was no change in the overload status for this channel,
        // we do not need to remember whether the previous utilization
        // update indicated the channel is no longer overloaded. Thus, we
        // can always clear this value. If we needed to react to the
        // 5 GHz overload going away, we will have done that on the first
        // transition to not being overloaded (and not this subsequent one
        // where we are still not overloaded).
        chanInfo->wasOverloaded = LBD_FALSE;
        return LBD_FALSE;
    }
}

/**
 * @brief Determine if we have a complete set of utilization information.
 *
 * @return LBD_TRUE if the complete set of info is available; otherwise
 *         LBD_FALSE
 */
static inline LBD_BOOL bandmonAreAllUtilizationsRecorded(void) {
    return bandmonState.utilizationsState == 0 ||
           bandmonState.utilizationsState ==
           (1 << bandmonState.numActiveChannels) - 1;
}

/**
 * @brief Update the overload state for all channels if all measurements are
 *        available.
 *
 * @return the number of channels which had their overload state change
 */
static u_int8_t bandmonDetermineOperatingRegion(void) {
    // All channels must have been updated before we can say there has been
    // a change in the overload state.
    if (bandmonAreAllUtilizationsRecorded()) {
        size_t numChanges = 0;
        size_t i;
        for (i = 0; i < bandmonState.numActiveChannels; ++i) {
            struct bandmonChannelUtilizationInfo_t *chanInfo =
                &bandmonState.channelUtilizations[i];
            dbgf(bandmonState.dbgModule, DBGINFO, "%s: Channel %u [%u%%]",
                 __func__, chanInfo->channelId, chanInfo->measuredUtilization);
            if (bandmonUpdateChannelOverload(chanInfo)) {
                chanInfo->overloadChanged = LBD_TRUE;
                numChanges++;
            }
        }

        return numChanges;
    }

    return 0;  // no assessment
}

/**
 * @brief React to an event providing updated channel utilization information
 *        for a single band.
 */
static void bandmonHandleChanUtilEvent(struct mdEventNode *event) {
    const wlanif_chanUtilEvent_t *utilEvent =
        (const wlanif_chanUtilEvent_t *) event->Data;

#ifdef LBD_DBG_MENU
    if (!bandmonState.debugModeEnabled)
#endif
    {
        bandmonHandleChanUtil(utilEvent->bss.channelId,
                              utilEvent->utilization);
    }
}

/**
 * @brief React to an event that one of the VAPs on a band was restarted.
 */
static void bandmonHandleVAPRestartEvent(struct mdEventNode *event) {
    const wlanif_vapRestartEvent_t *restartEvent =
        (const wlanif_vapRestartEvent_t *) event->Data;

    if (bandmonInitializeChannels() != LBD_OK) {
        dbgf(bandmonState.dbgModule, DBGERR,
             "%s: Failed to fetch active channels; aborting",
             __func__);
        exit(1);
    }

    dbgf(bandmonState.dbgModule, DBGINFO,
         "%s: Resetting utilization information due to VAP restart "
         "on band %u", __func__, restartEvent->band);

    // Reset our state for steering blackout and one shot utilization,
    // as the conditions that had dictated them are no longer relevant.
    bandmonState.blackoutState = bandmon_blackoutState_idle;
    bandmonState.oneShotUtilizationRequested = LBD_FALSE;

    // Start back with no samples and if we went from an overloaded state
    // to a non-overloaded one, perform the necessary aborts.
    bandmonState.utilizationsState = 0;
    if (bandmonDetermineOperatingRegion()) {
        bandmonProcessOperatingRegion();
    }
}

/**
 * @brief Determine whether a utilization update can be recorded based on
 *        the blackout state.
 */
static inline LBD_BOOL bandmonCanRecordUtilizationUpdate(void) {
    return bandmonState.blackoutState == bandmon_blackoutState_idle ||
           bandmonState.blackoutState == bandmon_blackoutState_active;
}

/**
 * @brief React to a utilization measurement on the provided band.
 *
 * @param [in] channel  the channel on which the utilization was measured
 * @param [in] utilization   the utilization value (0-100)
 */
static void bandmonHandleChanUtil(lbd_channelId_t channel, u_int8_t utilization) {
    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(channel);
    struct bandmonChannelUtilizationInfo_t *chanInfo =
        bandmonGetChannelUtilizationInfo(channel);

    // This should always be the case, but we are defensive anyways.
    if (band < wlanif_band_invalid && chanInfo) {
        // This is toggling a bit for the band so that only when the bit
        // values match across the bands is a new check done for
        // overload (see bandmonDetermineOperatingRegion for where this
        // occurs).
        bandmonState.utilizationsState ^= (1 << chanInfo->bitIndex);

        // Only record the utilization if we are not entering a blackout,
        // as in the blackout the value might be inaccurate.
        if (bandmonCanRecordUtilizationUpdate()) {
            chanInfo->measuredUtilization = utilization;
        }

        if (diaglog_startEntry(mdModuleID_BandMon,
                               bandmon_msgId_utilization,
                               diaglog_level_info)) {
            diaglog_write8(channel);
            diaglog_write8(utilization);
            diaglog_finishEntry();
        }

        u_int8_t numOverloadChanges = bandmonDetermineOperatingRegion();
        if (numOverloadChanges) {
            bandmonProcessOperatingRegion();
        }

        if (bandmonAreAllUtilizationsRecorded()) {
            bandmonTransitionBlackoutState();
        }
    }
}

/**
 * @brief Reset all projected utilization increases to 0.
 */
static void bandmonClearProjectedUtilizationIncreases(void) {
    size_t i;
    for (i = 0; i < bandmonState.numActiveChannels; ++i) {
        struct bandmonChannelUtilizationInfo_t *chanInfo =
            &bandmonState.channelUtilizations[i];
        chanInfo->projectedUtilizationIncrease = 0;
    }
}

/**
 * @brief Move the blackout state to the next state.
 *
 * @param [in] generateEvent  flag indicating whether to generate an event
 *                            if exiting the blackout state or a utilization
 *                            update was requested
 */
static void bandmonTransitionBlackoutState(void) {
    switch (bandmonState.blackoutState) {
        case bandmon_blackoutState_idle:
            if (bandmonState.oneShotUtilizationRequested) {
                bandmonGenerateUtilizationUpdateEvent();
            }
            bandmonState.oneShotUtilizationRequested = LBD_FALSE;
            break;

        case bandmon_blackoutState_pending:
            dbgf(bandmonState.dbgModule, DBGINFO,
                 "%s: Entering steering blackout state "
                 "(one shot util req=%u)",
                 __func__, bandmonState.oneShotUtilizationRequested);
            bandmonState.blackoutState = bandmon_blackoutState_active;
            bandmonDiaglogBlackoutChange(LBD_TRUE);

            // Carry over the one shot utilation flag into the active
            // blackout state (which will be entered on the next utilization
            // update).
            break;

        case bandmon_blackoutState_activeWithPending:
            dbgf(bandmonState.dbgModule, DBGINFO,
                 "%s: Re-entering steering blackout state "
                 "(one shot util req=%u)",
                 __func__, bandmonState.oneShotUtilizationRequested);
            bandmonState.blackoutState = bandmon_blackoutState_active;
            bandmonDiaglogBlackoutChange(LBD_TRUE);

            // Carry over the one shot utilation flag into the active
            // blackout state (which will be entered on the next utilization
            // update).
            break;

        case bandmon_blackoutState_active:
            dbgf(bandmonState.dbgModule, DBGINFO,
                 "%s: Exiting steering blackout state "
                 "(one shot util req=%u)",
                 __func__, bandmonState.oneShotUtilizationRequested);
            bandmonClearProjectedUtilizationIncreases();

            if (bandmonState.oneShotUtilizationRequested) {
                bandmonGenerateUtilizationUpdateEvent();
            }

            bandmonState.blackoutState = bandmon_blackoutState_idle;
            bandmonDiaglogBlackoutChange(LBD_FALSE);
            bandmonState.oneShotUtilizationRequested = LBD_FALSE;
            break;
    }

}

/**
 * @brief Emit the event indicating a change in which channels are overloaded.
 */
static void bandmonGenerateOverloadChangeEvent(void) {
    bandmon_overloadChangeEvent_t event;
    event.numOverloadedChannels = bandmonGetNumOverloadedChannels();

    mdCreateEvent(mdModuleID_BandMon, mdEventPriority_Low,
                  bandmon_event_overload_change, &event, sizeof(event));

}

/**
 * @brief Emit the event indicating updated utilization information is
 *        available.
 */
static void bandmonGenerateUtilizationUpdateEvent(void) {
    bandmon_utilizationUpdateEvent_t event;
    event.numOverloadedChannels = bandmonGetNumOverloadedChannels();

    mdCreateEvent(mdModuleID_BandMon, mdEventPriority_Low,
                  bandmon_event_utilization_update, &event, sizeof(event));
}

/**
 * @brief Generate a diagnostic log (if enabled) indicating which channels
 *        are now considered overloaded.
 */
static void bandmonDiaglogOverloadChange(void) {
    if (diaglog_startEntry(mdModuleID_BandMon,
                           bandmon_msgId_overloadChange,
                           diaglog_level_demo)) {
        diaglog_write8(bandmonGetNumOverloadedChannels());

        // Now dump the overloaded channels.
        size_t i;
        for (i = 0; i < bandmonState.numActiveChannels; ++i) {
            struct bandmonChannelUtilizationInfo_t *chanInfo =
                &bandmonState.channelUtilizations[i];
            if (chanInfo->isOverloaded) {
                diaglog_write8(chanInfo->channelId);
            }
        }

        diaglog_finishEntry();
    }
}

/**
 * @brief Generate a diagnostic log (if enabled) indicating the change in
 *        the blackout state.
 *
 * @param [in] isBlackoutStart  whether this is the starting point or ending
 *                              point for a steering blackout
 */
static void bandmonDiaglogBlackoutChange(LBD_BOOL isBlackoutStart) {
    if (diaglog_startEntry(mdModuleID_BandMon,
                           bandmon_msgId_blackoutChange,
                           diaglog_level_demo)) {
        diaglog_write8(isBlackoutStart);
        diaglog_finishEntry();
    }
}

/**
 * @brief Check whether the operating region has changed and if it has,
 *        do the necessary ACL operations.
 *
 * @param [in] overloadState  the current overload condition
 */
static void bandmonProcessOperatingRegion(void) {
    if (bandmonUpdateOverload() != LBD_OK) {
        return;
    }

    bandmonGenerateOverloadChangeEvent();
    bandmonDiaglogOverloadChange();

    // When moving from 5 GHz being overloaded to 2.4 GHz being
    // overloaded, any devices that do not meet the criteria for steering
    // to 5 GHz should have any steering that is currently installed
    // aborted.
    LBD_BOOL isOverloaded24g = LBD_FALSE;
    LBD_BOOL wasOverloaded5g = LBD_FALSE;

    u_int8_t i;
    for (i = 0; i < bandmonState.numActiveChannels; ++i) {
        struct bandmonChannelUtilizationInfo_t *chanInfo =
            &bandmonState.channelUtilizations[i];
        wlanif_band_e band =
            wlanif_resolveBandFromChannelNumber(chanInfo->channelId);
        if (wlanif_band_24g == band) {
            isOverloaded24g |= chanInfo->isOverloaded;
        } else { // must be 5 GHz, as we do should never have invalid channels
            lbDbgAssertExit(bandmonState.dbgModule, band == wlanif_band_5g);
            wasOverloaded5g |= chanInfo->wasOverloaded;
        }
    }

    LBD_BOOL abortRequired = isOverloaded24g && wasOverloaded5g;
    if (stadb_iterate(bandmonStaDBIterateCB, (void *) abortRequired) != LBD_OK) {
        dbgf(bandmonState.dbgModule, DBGERR,
             "%s: Failed to iterate over STA DB; will wait for RSSI "
             "updates", __func__);
        return;
    }
}

/**
 * @brief Inform the lower layers of a change in the overload state.
 *
 * @param [in] overloadState  the new overload state
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
static LBD_STATUS bandmonUpdateOverload(void) {
    size_t i;
    for (i = 0; i < bandmonState.numActiveChannels; ++i) {
        struct bandmonChannelUtilizationInfo_t *chanInfo =
            &bandmonState.channelUtilizations[i];
        if (chanInfo->overloadChanged) {
            if (wlanif_setOverload(chanInfo->channelId,
                                   chanInfo->isOverloaded) != LBD_OK) {
                dbgf(bandmonState.dbgModule, DBGERR,
                     "%s: Failed to set overload status for channel %u",
                     __func__, chanInfo->channelId);

                return LBD_NOK;
            } else {
                chanInfo->overloadChanged = LBD_FALSE;
            }
        }
    }

    return LBD_OK;
}

/**
 * @brief Add all non-overloaded channels to the list of pre-association steering
 *        candidate channels if any channel on the same band has sufficient RSSI
 *        (so long as there is still room).
 *
 * @param [in] params  the structure containing the information about which band
 *                     has sufficient RSSI for pre-assoc steering
 * @param [in] maxNumCandidate  maximum number of candidate
 * @param [out] candidateChannels  the list of pre-association candidate channels
 *
 * @return number of candidate channels selected
 */
static size_t bandmonAddCandidatesPreAssocChannel(
        bandmonUpdatePreAssocSteeringParams *params,
        size_t maxNumCandidate, lbd_channelId_t *candidateChannels) {
    size_t i, candidateCount = 0;
    for (i = 0; i < bandmonState.numActiveChannels; ++i) {
        struct bandmonChannelUtilizationInfo_t *chanInfo =
            &bandmonState.channelUtilizations[i];
        if (chanInfo->isOverloaded) { continue; }
        wlanif_band_e band = wlanif_resolveBandFromChannelNumber(chanInfo->channelId);
        lbDbgAssertExit(bandmonState.dbgModule, band < wlanif_band_invalid);
        if (params->bandHasSufficientRSSI[band]) {
            // Note that currently this condition will always be true since we
            // only allow for 2 candidates when there are three channels.
            if (candidateCount <= maxNumCandidate) {
                candidateChannels[candidateCount++] = chanInfo->channelId;
            }
        }
    }
    return candidateCount;
}

/**
 * @brief Callback for the BSS statistics for a specific STA.
 *
 * This callback is responsible for determining whether to steer the STA
 * to a non-overloaded channel or not.
 *
 * @param [in] entryHandle  the STA being processed
 * @param [in] bssHandle  the BSS for which to update the RSSI (if necesasry)
 * @param [in] cookie  the internal parameters for the iteration
 *
 * @return LBD_FALSE always (as it does not keep the BSSes around)
 */
static LBD_BOOL bandmonUpdatePreAssocSteeringCallback(
    stadbEntry_handle_t entryHandle, stadbEntry_bssStatsHandle_t bssHandle,
    void *cookie) {
    bandmonUpdatePreAssocSteeringParams *params =
        (bandmonUpdatePreAssocSteeringParams *) cookie;

    const lbd_bssInfo_t *bssInfo = stadbEntry_resolveBSSInfo(bssHandle);
    lbDbgAssertExit(bandmonState.dbgModule, bssInfo); // should never happen in practice

    time_t rssiAgeSecs = 0xFF;
    u_int8_t rssiCount = 0;
    u_int8_t rssi = stadbEntry_getUplinkRSSI(entryHandle, bssHandle,
                                             &rssiAgeSecs, &rssiCount);
    if (rssi != LBD_INVALID_RSSI &&
        rssiAgeSecs < bandmonState.config.rssiMaxAge &&
        rssiCount >= bandmonState.config.probeCountThreshold &&
        rssi > bandmonState.config.rssiSafetyThreshold) {
        params->candidateChannelCount++;
        // When there is a BSS meet pre-assoc steering requirement, mark the band
        // as valid, so all non-overloaded channels on the band can be selected.
        wlanif_band_e band = wlanif_resolveBandFromChannelNumber(bssInfo->channelId);
        lbDbgAssertExit(bandmonState.dbgModule, band < wlanif_band_invalid);
        params->bandHasSufficientRSSI[band] = LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Perform the necessary updates on the provided entry for
 *        pre-association steering based on the current overload state.
 *
 * @param [in] entry  the entry for whcih to update the steering decision
 * @param [in] abortRequired  LBD_TRUE if steering should be aborted if
 *                            the criteria for steering to the non-overloaded
 *                            band are not met; otherwise LBD_FALSE
 */
static void bandmonUpdatePreAssocSteering(stadbEntry_handle_t entry,
                                          LBD_BOOL abortRequired) {
    // We only care about entries that are dual band capable, are in network
    // (meaning they've previously associated), and that are not currently
    // associated.
    //
    // Furthermore, for simplicity, we do not pre-association steer clients
    // with reserved airtime as they should have a natural tendency to go
    // to the BSS on which they have a reservation.
    if (!stadbEntry_isDualBand(entry) || !stadbEntry_isInNetwork(entry) ||
        stadbEntry_hasReservedAirtime(entry) ||
        stadbEntry_getServingBSS(entry, NULL)) {
        return;
    }

    bandmonUpdatePreAssocSteeringParams params = {0};
    if (stadbEntry_iterateBSSStats(entry,
                                   bandmonUpdatePreAssocSteeringCallback,
                                   &params, NULL, NULL) != LBD_OK) {
        const struct ether_addr *addr = stadbEntry_getAddr(entry);
        dbgf(bandmonState.dbgModule, DBGERR,
             "%s: Failed to iterate over BSS stats for " lbMACAddFmt(":"),
             __func__, lbMACAddData(addr->ether_addr_octet));
    }

    // If there are any candidate channels, perform/update the steering.
    if (params.candidateChannelCount) {
        lbd_channelId_t candidateChannels[STEEREXEC_MAX_ALLOW_ASSOC];
        memset(candidateChannels, LBD_CHANNEL_INVALID, STEEREXEC_MAX_ALLOW_ASSOC);
        size_t numCandidates = bandmonAddCandidatesPreAssocChannel(
                                   &params, STEEREXEC_MAX_ALLOW_ASSOC,
                                   candidateChannels);
        LBD_BOOL ignored;
        if (numCandidates &&
            steerexec_allowAssoc(entry, numCandidates,
                                 candidateChannels,
                                 &ignored) == LBD_OK && !ignored) {
            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            dbgf(bandmonState.dbgModule, DBGINFO,
                 "%s: Pre-association steer " lbMACAddFmt(":")
                 " to channel(s) (%u, %u)", __func__,
                 lbMACAddData(addr->ether_addr_octet),
                 candidateChannels[0],
                 candidateChannels[1]);
        }
    } else if (abortRequired) {
        LBD_BOOL ignored;
        if (steerexec_abortAllowAssoc(entry, &ignored) == LBD_OK && !ignored) {
            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            dbgf(bandmonState.dbgModule, DBGINFO,
                 "%s: Cancelled pre-association steer " lbMACAddFmt(":"),
                 __func__, lbMACAddData(addr->ether_addr_octet));
        }
    }
}

/**
 * @brief Determine whether pre-association steering is permitted under the
 *        current overoad conditions or not.
 *
 *
 * @return LBD_TRUE if steering is permitted; otherwise LBD_FALSE
 */
static LBD_BOOL bandmonIsPreAssocSteeringPermitted(void) {
    // Pre-association steering is not permitted if all of the channels are
    // overloaded or none of the channels are overloaded.
    u_int8_t numOverloaded = bandmonGetNumOverloadedChannels();

    return !(numOverloaded == 0 || numOverloaded == bandmonState.numActiveChannels);
}

/**
 * @brief Handler for each entry in the station database.
 *
 * @param [in] entry  the current entry being examined
 * @param [in] cookie  the parameter provided in the stadb_iterate call
 */
static void bandmonStaDBIterateCB(stadbEntry_handle_t entry, void *cookie) {
    LBD_BOOL abortRequired = (LBD_BOOL) cookie;

    // If we are no longer overloaded or are overloaded on all channels, for
    // all unassociated STAs that are dual band capable and in network
    // (meaning they've been associated before) that do not have reserved
    // airtime, abort any steering that may be in progress.
    if (!bandmonIsPreAssocSteeringPermitted() &&
        stadbEntry_isDualBand(entry) && stadbEntry_isInNetwork(entry) &&
        !stadbEntry_hasReservedAirtime(entry) &&
        !stadbEntry_getServingBSS(entry, NULL)) {
        LBD_BOOL ignored;
        LBD_STATUS result = steerexec_abortAllowAssoc(entry, &ignored);
        if (result == LBD_NOK && !ignored) {
            const struct ether_addr *addr = stadbEntry_getAddr(entry);

            dbgf(bandmonState.dbgModule, DBGERR,
                 "%s: Failed to abort pre-association steering for "
                 lbMACAddFmt(":"), __func__,
                 lbMACAddData(addr->ether_addr_octet));
        } else if (!ignored) {
            const struct ether_addr *addr = stadbEntry_getAddr(entry);

            dbgf(bandmonState.dbgModule, DBGINFO,
                 "%s: Cancelled pre-association steering for "
                 lbMACAddFmt(":"), __func__,
                 lbMACAddData(addr->ether_addr_octet));
        }
    } else {
        bandmonUpdatePreAssocSteering(entry, abortRequired);
    }
}

#ifdef LBD_DBG_MENU

static const char *bandmonMenuStatusHelp[] = {
    "s -- print station database contents",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void bandmonMenuStatusHandler(struct cmdContext *context, const char *cmd) {
    size_t i;
    for (i = 0; i < bandmonState.numActiveChannels; ++i) {
        struct bandmonChannelUtilizationInfo_t *chanInfo =
            &bandmonState.channelUtilizations[i];
        cmdf(context, "Channel %-3u: Measured: %-3u%%%c%-14s "
                      "Projected Increase: %-3u%%\n",
             chanInfo->channelId, chanInfo->measuredUtilization,
             bandmonState.utilizationsState & (1 << i) ? '*' : ' ',
             chanInfo->isOverloaded ? " (overloaded)" : "",
             chanInfo->projectedUtilizationIncrease);
    }
}

static const char *bandmonMenuDebugHelp[] = {
    "d -- enable/disable band monitor debug mode",
    "Usage:",
    "\td on: enable debug mode (ignoring utilization measurements)",
    "\td off: disable debug mode (handling utilization measurements)",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void bandmonMenuDebugHandler(struct cmdContext *context, const char *cmd) {
    LBD_BOOL isOn = LBD_FALSE;
    const char *arg = cmdWordFirst(cmd);

    if (!arg) {
        cmdf(context, "bandmon 'd' command requires on/off argument\n");
        return;
    }

    if (cmdWordEq(arg, "on")) {
        isOn = LBD_TRUE;
    } else if (cmdWordEq(arg, "off")) {
        isOn = LBD_FALSE;
    } else {
        cmdf(context, "bandmon 'd' command: invalid arg '%s'\n", arg);
        return;
    }

    dbgf(bandmonState.dbgModule, DBGINFO, "%s: Setting debug mode to %u",
         __func__, isOn);
    bandmonState.debugModeEnabled = isOn;
}

static const char *bandmonMenuUtilHelp[] = {
    "util -- inject a utilization measurement",
    "Usage:",
    "\tutil <chan> <value>: inject utilization <value> on the channel",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void bandmonMenuUtilHandler(struct cmdContext *context, const char *cmd) {
    const char *arg = cmdWordFirst(cmd);

    if (!bandmonState.debugModeEnabled) {
        cmdf(context, "bandmon 'util' command not allowed unless debug mode "
                      "is enabled\n");
        return;
    }

    if (!arg) {
        cmdf(context, "bandmon 'util' command invalid channel\n");
        return;
    }

    int channel = atoi(arg);

    arg = cmdWordNext(arg);
    if (!cmdWordDigits(arg)) {
        cmdf(context, "bandmon 'util' command invalid utilization '%s'\n",
             arg);
        return;
    }

    // The cmdWordDigits above does not allow a negative number, so we only
    // need to check for too large of values here.
    int utilization = atoi(arg);
    if (utilization > 100) {
        cmdf(context, "bandmon 'util' command: utilization must be "
                      "percentage\n");
        return;
    }

    dbgf(bandmonState.dbgModule, DBGINFO, "%s: Spoofing utilization of [%u%%] "
                                          "on channel %u",
         __func__, utilization, channel);

    // Now inject the utilization event as if it came from wlanif.
    bandmonHandleChanUtil(channel, utilization);
}

static const struct cmdMenuItem bandmonMenu[] = {
    CMD_MENU_STANDARD_STUFF(),
    { "s", bandmonMenuStatusHandler, NULL, bandmonMenuStatusHelp },
    { "d", bandmonMenuDebugHandler, NULL, bandmonMenuDebugHelp },
    { "util", bandmonMenuUtilHandler, NULL, bandmonMenuUtilHelp },
    CMD_MENU_END()
};

static const char *bandmonMenuHelp[] = {
    "bandmon -- Band Monitor",
    NULL
};

static const struct cmdMenuItem bandmonMenuItem = {
    "bandmon",
    cmdMenu,
    (struct cmdMenuItem *) bandmonMenu,
    bandmonMenuHelp
};

#endif /* LBD_DBG_MENU */

static void bandmonMenuInit(void) {
#ifdef LBD_DBG_MENU
    cmdMainMenuAdd(&bandmonMenuItem);
#endif /* LBD_DBG_MENU */
}
