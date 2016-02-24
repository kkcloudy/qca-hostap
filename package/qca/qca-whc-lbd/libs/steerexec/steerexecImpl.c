// vim: set et sw=4 sts=4 cindent:
/*
 * @File: steerexecImpl.c
 *
 * @Abstract: Package-level implementation of the steering executor for
 *            802.11v BSS Transition Management compliant clients and
 *            legacy clients
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
#include <time.h>
#include <limits.h>
#include <math.h>

#include <dbg.h>
#include <evloop.h>

#ifdef LBD_DBG_MENU
#include <cmd.h>
#endif

#include "internal.h"
#include "lbd_assert.h"
#include "module.h"
#include "profile.h"

#include "steerexecImpl.h"
#include "steerexecDiaglogDefs.h"
#include "stadb.h"
#include "bandmon.h"
#include "diaglog.h"

// For now, we are only permitting 2 observers, as it is likely that the
// following will need to observe steering allowed changes:
//
// 1. Pre-association steering decision maker
// 2. Post-association steering decision maker
#define MAX_STEERING_ALLOWED_OBSERVERS 2

/**
 * @brief Structure used to define a steerexec common timer
 *        (shared between all STAs)
 */
typedef struct steerexecImplTimerStruct_t {
    /// Timer implementation.
    struct evloopTimeout timer;

    /// Count of entries waiting for timeout.
    size_t countEntries;

    /// Next expiry time.
    time_t nextExpiry;
} steerexecImplTimerStruct_t;

/**
 * @brief Internal state for the steering executor used for
 *        legacy steering.
 */
struct steerexecImplLegacyPriv_t {
    /// Timer used to age out devices marked as steering unfriendly.
    steerexecImplTimerStruct_t steeringUnfriendly;

    /// Timer used to age out devices blacklisted.
    struct evloopTimeout blacklistTimer;

    /// The number of entries which are blacklisted on one band.
    size_t numBlacklist;

    /// The time (in seconds) at which the clear blacklist timer should
    /// next expire.
    time_t nextBlacklistExpiry;
};

/**
 * @brief Internal state for the steering executor used for
 *        802.11v BTM steering.
 */
struct steerexecImplBTMPriv_t {
    /// Dialog token to send with the next BTM request
    u_int8_t dialogToken;

    /// Timer used to age out devices marked as BTM-steering unfriendly.
    steerexecImplTimerStruct_t unfriendlyTimer;

    /// Timer used to age out devices marked as Active-steering unfriendly.
    steerexecImplTimerStruct_t activeUnfriendlyTimer;
};

/**
 * @brief Internal state for the steering executor.
 */
struct steerexecImplPriv_t {
    steerexecImplConfig_t config;

    /// Observer for all changes in the steering allowed status.
    struct steerexecImplSteeringAllowedObserver {
        LBD_BOOL isValid;
        steerexec_steeringAllowedObserverCB callback;
        void *cookie;
    } steeringAllowedObservers[MAX_STEERING_ALLOWED_OBSERVERS];

    /// Transaction ID of the next steer attempt.
    u_int8_t transaction;

    /// Timer used to age out steering prohibitions.
    struct evloopTimeout prohibitTimer;

    /// Number of entries which are currently under a steering prohibition.
    size_t numSteeringProhibits;

    /// The time (in seconds) at which the steering prohibit timer should
    /// next expire.
    time_t nextProhibitExpiry;

    /// Internal state used for legacy steering
    struct steerexecImplLegacyPriv_t legacy;

    /// Internal state used for 802.11v BTM steering
    struct steerexecImplBTMPriv_t btm;

    struct dbgModule *dbgModule;
};

/**
 * @brief Legacy steering state information stored with each STA
 *        that has been steered.
 */
typedef struct steerexecImplSteeringStateLegacy_t {
    /// The time the last steering was attempted or completed (whichever is
    /// more recent).
    time_t lastSteeringTime;

    /// The number of consecutive authentication rejects seen so far
    /// for the current attempt at steering.
    u_int32_t numAuthRejects;

    /// Flag indicating if this device is steering unfriendly
    LBD_BOOL steeringUnfriendly;

    /// Consecutive failure count of legacy steering
    u_int32_t countConsecutiveFailure;

    /// Timer used to track T-steering period
    struct evloopTimeout tSteerTimer;

    /// Count of disabled channels (used for pre-association steering)
    u_int8_t disabledChannelCount;

    /// Set of disabled channels (used for pre-association steering)
    lbd_channelId_t disabledChannelList[WLANIF_MAX_RADIOS-1];
} steerexecImplSteeringStateLegacy_t;

/**
 * @brief Type that denotes current state of BTM steering.
 */
typedef enum steerexecImpl_btmState_e {
    /// No BTM transition in progress
    steerexecImpl_btmState_idle,

    /// BTM request sent, waiting on BTM response
    steerexecImpl_btmState_waiting_response,

    /// BTM response received, waiting on association on new band
    steerexecImpl_btmState_waiting_association,

    /// BTM transition was aborted
    steerexecImpl_btmState_aborted,

    /// Invalid state
    steerexecImpl_btmState_invalid,
} steerexecImpl_btmState_e;

static const char *steerexecImpl_btmStateString[] = {
    "Idle",
    "WaitResp",
    "WaitAssoc",
    "Aborted",
    "Invalid"
};

static const char *steerexecImpl_btmComplianceString[] = {
    "Idle",
    "ActiveUnfriendly",
    "Active",
    "Invalid"
};

/**
 * @brief 802.11v BSS Transition Management steering state
 *        information stored with each STA that has been
 *        steered.
 */
typedef struct steerexecImplSteeringStateBTM_t {
    /// Timer used to track when a BTM response or association should be received
    /// (which is expected depends on the state)
    struct evloopTimeout timer;

    /// The time the last steering was attempted or completed (whichever is
    /// more recent).
    time_t lastSteeringTime;

    /// The time the last active steering attempt failed.
    time_t lastActiveSteeringFailureTime;

    /// State tracking what is the next BTM event expected
    steerexecImpl_btmState_e state;

    /// Flag indicating if this device is BTM unfriendly
    LBD_BOOL btmUnfriendly;

    /// State tracking how we should attempt to steer this client
    steerexecImpl_btmComplianceState_e complianceState;

    /// Dialog token sent with most recent request
    u_int8_t dialogToken;

    /// Record the BSSID the STA has indicated it will transition to
    struct ether_addr bssid;

    /// BSS STA was associated on at the start of the steer
    lbd_bssInfo_t initialAssoc;

    /// Count how many times transition has failed due to no response received
    u_int32_t countNoResponseFailure;

    /// Count how many times transition has failed due to reject code received
    u_int32_t countRejectFailure;

    /// Count how many times transition has failed due to no / incorrect association received
    u_int32_t countAssociationFailure;

    /// Count how many times transition has succeeded
    u_int32_t countSuccess;

    /// Consecutive failure count as active (since the last success as active)
    u_int32_t countConsecutiveFailureActive;

    /// Consecutive failure count (since the last BTM success)
    /// This is used in the idle state, or after transitioning to the active state
    /// (since steerexecImpl_maxConsecutiveBTMFailuresAsActive consecutive failures
    /// are required before the active consecutive failure count is incremented)
    u_int32_t countConsecutiveFailure;

    /// Count how many times a BTM response is received with a different BSSID
    /// than the target BSS(es)
    u_int32_t countBSSIDMismatch;
} steerexecImplSteeringStateBTM_t;

static const char *steerexecImpl_SteeringTypeString[] = {
    "None",
    "Legacy",
    "BTM and Blacklist",
    "BTM",
    "BTM and Blacklist (Active)",
    "BTM (Active)",
    "Pre-Association",
    "BTM BE",
    "BTM BE (Active)",
    "BTM and Blacklist BE",
    "BTM and Blacklist BE (Active)",
    "Invalid"
};

static const char *steerexecImpl_SteeringProhibitTypeString[] = {
    "None",
    "Short",
    "Long",
    "Invalid"
};

/**
 * @brief Type of blacklist that is active for the STA
 */
typedef enum steerexecImplBlacklistType_e {
    /// Nothing is blacklisted.
    steerexecImplBlacklist_none,

    /// Channel(s) are blacklisted.
    steerexecImplBlacklist_channel,

    /// Candidate(s) are blacklisted.
    steerexecImplBlacklist_candidate,

    /// Invalid.
    steerexecImplBlacklist_invalid
} steerexecImplBlacklistType_e;


static const char *steerexecImpl_SteeringBlacklistTypeString[] = {
    "None",
    "Channel",
    "Candidate",
    "Invalid"
};

/**
 * @brief State information that the steering executor stores
 *        with each STA that has been steered.
 */
typedef struct steerexecImplSteeringState_t {
    /// Steering context.
    steerexecImplHandle_t context;

    /// The type of blacklisting for this STA.
    steerexecImplBlacklistType_e blacklistType;

    /// Candidate count.
    u_int8_t candidateCount;

    /// Candidate list.
    lbd_bssInfo_t candidateList[STEEREXEC_MAX_CANDIDATES];

    /// Type of steering used.
    steerexecImplSteeringType_e steerType;

    /// Transaction ID of the most recent steer attempt.
    u_int8_t transaction;

    /// Whether steering for this device is currently prohibited, and
    /// the length of the prohibition.
    steerexecImplSteeringProhibitType_e steeringProhibited;

    /// Legacy state information.
    steerexecImplSteeringStateLegacy_t legacy;

    /// BTM state information.
    /// Only allocated for STAs that indicate they support BTM.
    steerexecImplSteeringStateBTM_t *btm;
} steerexecImplSteeringState_t;

/**
 * @brief Structure used when iterating through channels to make
 *        sure there is at least one enabled channel with an OK
 *        RSSI.
 */
typedef struct steerexecImplCheckChannelRSSI_t {
    /// Current time
    struct timespec ts;

    /// Steering executor pointer
    struct steerexecImplPriv_t *exec;

    /// Steering state for STA
    steerexecImplSteeringState_t *state;

    /// Count of currently enabled channels
    u_int8_t enabledChannelCount;

    /// List of currently enabled channels
    lbd_channelId_t enabledChannelList[WLANIF_MAX_RADIOS];

    /// Set to LBD_TRUE if there exists a channel that is currently enabled
    /// with an OK RSSI
    LBD_BOOL isChannelRSSIOK;
} steerexecImplCheckChannelRSSI_t;

static const char *steerexec_SteeringReasonTypeString[] = {
    "UserRequest",
    "ActiveUpgrade",
    "ActiveDowngradeRate",
    "ActiveDowngradeRSSI",
    "IdleUpgrade",
    "IdleDowngrade",
    "ActiveOffload",
    "IdleOffload",
    "Invalid"
};

static const char *steerexec_SteerEligibilityString[] = {
    "None",
    "Idle",
    "Active",
    "Invalid"
};

// Maximum number of consecutive failures while active allowed before marking a STA
// as active steering unfriendly
static const u_int32_t steerexecImpl_maxConsecutiveBTMFailuresAsActive = 4;

// ====================================================================
// Forward decls for internal "private" functions
// ====================================================================

static steerexecImplSteeringState_t *steerexecImplGetOrCreateSteeringState(
        steerexecImplHandle_t exec, stadbEntry_handle_t entry);

static void steerexecImplDestroySteeringState(void *state);

static steerexecImplSteeringType_e steerexecImplDetermineSteeringType(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    stadbEntry_bssStatsHandle_t stats,
    LBD_BOOL eligibilityOnly,
    LBD_BOOL reportReasonNotEligible);

static u_int32_t steerexecImplGetSteeringProhibitTime(
    steerexecImplHandle_t exec,
    steerexecImplSteeringProhibitType_e prohibit);

static LBD_BOOL steerexecImplIsInSteeringQuietPeriod(
        steerexecImplHandle_t exec,
        stadbEntry_handle_t entry,
        steerexecImplSteeringState_t *state,
        LBD_BOOL notifyObservers);
static void steerexecImplStartSteeringProhibit(
        steerexecImplHandle_t exec, steerexecImplSteeringState_t *state,
        const struct ether_addr *staAddr,
        steerexecImplSteeringProhibitType_e prohibit);
static void steerexecImplProhibitTimeoutHandler(void *cookie);
static void steerexecImplProhibitIterateCB(stadbEntry_handle_t entry,
                                             void *cookie);

static void steerexecImplStartSteeringUnfriendly(
        steerexecImplHandle_t exec, steerexecImplSteeringState_t *state,
        const struct ether_addr *staAddr);
static void steerexecImplStartBTMUnfriendly(
        steerexecImplHandle_t exec,
        steerexecImplSteeringState_t *state,
        const struct ether_addr *staAddr,
        steerexecImplTimerStruct_t *timer,
        u_int32_t exponent,
        u_int32_t maxBackoff );
static void steerexecImplUnfriendlyTimeoutHandler(void *cookie);
static void steerexecImplBTMUnfriendlyTimeoutHandler(void *cookie);
static void steerexecImplBTMActiveUnfriendlyTimeoutHandler(void *cookie);
static void steerexecImplUnfriendlyIterateCB(stadbEntry_handle_t entry,
                                             void *cookie);
static void steerexecImplBTMUnfriendlyIterateCB(stadbEntry_handle_t entry,
                                                void *cookie);

static void steerexecImplBlacklistTimeoutHandler(void *cookie);
static void steerexecImplBlacklistIterateCB(stadbEntry_handle_t entry,
                                              void *cookie);
static void steerexecImplCleanupBlacklistBTM(steerexecImplSteeringState_t *state,
                                             stadbEntry_handle_t entry,
                                             const struct ether_addr *staAddr,
                                             steerexecImplSteeringStatusType_e status);

static void steerexecImplNotifySteeringAllowedObservers(
        steerexecImplHandle_t exec, stadbEntry_handle_t entry);

static LBD_STATUS steerexecImplAbortSteerImpl(
        steerexecImplHandle_t exec, stadbEntry_handle_t entry,
        steerexecImplSteeringState_t *state,
        steerexecImplSteeringStatusType_e status);

static void steerexecImplLowRSSIObserver(stadbEntry_handle_t entry, void *cookie);

static void steerexecImplTSteeringTimeoutHandler(void *cookie);

static void steerexecImplBTMTimeoutHandler(void *cookie);

static void steerexecImplRSSIObserver(stadbEntry_handle_t entry,
                                        stadb_rssiUpdateReason_e reason,
                                        void *cookie);

static void steerexecImplMarkBlacklist(
    steerexecImplHandle_t exec,
    steerexecImplSteeringState_t *state,
    steerexecImplBlacklistType_e blacklistType);

static void steerexecImplUpdateTransactionID(steerexecImplHandle_t exec,
                                             steerexecImplSteeringState_t *state);

static void steerexecImplDiagLogSteeringUnfriendly(
        const struct ether_addr *staAddr, LBD_BOOL isUnfriendly,
        u_int32_t consecutiveFailures);
static void steerexecImplDiagLogSteeringProhibited(
        const struct ether_addr *staAddr,
        steerexecImplSteeringProhibitType_e prohibit);
static void steerexecImplDiagLogBTMCompliance(
        const struct ether_addr *staAddr,
        LBD_BOOL btmUnfriendly,
        steerexecImpl_btmComplianceState_e complianceState,
        u_int32_t consecutiveFailures,
        u_int32_t consecutiveFailuresActive);
static void steerexecImplDiagLogSteerEnd(
        const struct ether_addr *staAddr,
        u_int8_t transaction,
        steerexecImplSteeringType_e steerType,
        steerexecImplSteeringStatusType_e status);

static LBD_STATUS steerexecImplPrepareAndSetBlacklist(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    LBD_BOOL *ignored,
    stadbEntry_bssStatsHandle_t stats,
    const lbd_bssInfo_t *bss,
    LBD_BOOL *okToSteer);

static LBD_STATUS steerexecImplSteerBTM(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS);

static LBD_STATUS steerexecImplSteerLegacy(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS);

static LBD_STATUS steerexecImplAbortBTM(steerexecImplHandle_t exec,
                                        steerexecImplSteeringState_t *state,
                                        stadbEntry_handle_t entry,
                                        const struct ether_addr *addr);

static LBD_STATUS steerexecImplAbortLegacy(steerexecImplHandle_t exec,
                                           steerexecImplSteeringState_t *state,
                                           stadbEntry_handle_t entry,
                                           steerexecImplSteeringStatusType_e status,
                                           const struct ether_addr *addr);

static LBD_BOOL steerexecImplHandleAssocUpdateBTM(
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS,
    const struct ether_addr *staAddr);

static LBD_BOOL steerexecImplHandleAssocUpdateLegacy(
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS,
    const struct ether_addr *staAddr);

static void steerexecImplHandleAssocPreAssoc(
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS);

static void steerexecImplAssocBlacklistClear(steerexecImplHandle_t exec,
                                             stadbEntry_handle_t entry,
                                             steerexecImplSteeringState_t *state,
                                             const lbd_bssInfo_t *assocBSS);

static void steerexecImplHandleBTMResponseEvent(struct mdEventNode *event);

static void steerexecImplSteerEnd(steerexecImplSteeringState_t *state,
                                  const struct ether_addr *staAddr,
                                  steerexecImplSteeringStatusType_e status);
static void steerexecImplSteerEndBTMFailure(
    stadbEntry_handle_t entry,
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr,
    steerexecImplSteeringStatusType_e status);

static LBD_STATUS steerexecImplGetAndValidateRadioChannelList(
    steerexecImplSteeringState_t *state,
    u_int8_t *channelCount,
    lbd_channelId_t *channelList);

static LBD_STATUS steerexecImplChannelDelta(
    steerexecImplSteeringState_t *state,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    u_int8_t *enabledChannelCount,
    lbd_channelId_t *enabledChannelList,
    u_int8_t *disabledChannelCount,
    lbd_channelId_t *disabledChannelList);

static u_int8_t steerexecImplCopyAllNotOnList(
    u_int8_t count1,
    const lbd_channelId_t *list1,
    u_int8_t count2,
    const lbd_channelId_t *list2,
     lbd_channelId_t *outList);

static void steerexecImplUpdateChannelSet(
    steerexecImplSteeringState_t *state,
    u_int8_t enabledChannelCount,
    const lbd_channelId_t *enabledChannelList,
    u_int8_t disabledChannelCount,
    const lbd_channelId_t *disabledChannelList);

static LBD_STATUS steerexecImplEnableAllDisabledChannels(
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr);

static LBD_STATUS steerexecImplEnableAllDisabledCandidates(
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr);

static LBD_BOOL steerexecImplIsOnCandidateList(steerexecImplSteeringState_t *state,
                                               u_int8_t candidateCount,
                                               const lbd_bssInfo_t *candidateList,
                                               const lbd_bssInfo_t *bss);

static LBD_BOOL steerexecImplIsOnChannelList(u_int8_t channelCount,
                                             const lbd_channelId_t *channelList,
                                             lbd_channelId_t channel);

static LBD_BOOL steerexecImplCleanupSteerDifferentType(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplSteeringType_e steerType);
static LBD_STATUS steerexecImplReconcileSteerCandidate(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplSteeringType_e steerType,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    LBD_BOOL *willSteer);
static LBD_STATUS steerexecImplReconcileSteerChannel(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplSteeringType_e steerType,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    LBD_BOOL *willSteer);

static LBD_STATUS steerexecImplRemoveAllBlacklists(
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr);
static void steerexecImplMarkAsNotBlacklisted(steerexecImplSteeringState_t *state);

static LBD_BOOL steerexecImplIsBTMSteer(steerexecImplSteeringType_e steerType);
static LBD_BOOL steerexecImplIsBTMOnlySteer(steerexecImplSteeringType_e steerType);
static LBD_BOOL steerexecImplIsActiveSteer(steerexecImplSteeringType_e steerType);
static void steerexecImplChanChangeObserver(lbd_vapHandle_t vap,
                                            lbd_channelId_t channelId,
                                            void *cookie);

static LBD_STATUS steerexecImplUpdateBTMCapability(
    steerexecImplSteeringState_t *state,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr);

static LBD_STATUS steerexecImplSetupBTMState(steerexecImplSteeringState_t *state,
                                             stadbEntry_handle_t entry);

static void steerexecImplSetLastSteeringTime(
    steerexecImplSteeringState_t *state);

// ====================================================================
// Public API
// ====================================================================

steerexecImplHandle_t steerexecImplCreate(const steerexecImplConfig_t *config,
                                          struct dbgModule *dbgModule) {
    steerexecImplHandle_t exec =
        calloc(1, sizeof(struct steerexecImplPriv_t));
    if (exec) {
        memcpy(&exec->config, config, sizeof(*config));

        exec->dbgModule = dbgModule;

        if (stadb_registerLowRSSIObserver(steerexecImplLowRSSIObserver, exec) != LBD_OK ||
            stadb_registerRSSIObserver(steerexecImplRSSIObserver, exec) != LBD_OK ||
            wlanif_registerChanChangeObserver(steerexecImplChanChangeObserver, exec) != LBD_OK) {
            free(exec);
            return NULL;
        }

        evloopTimeoutCreate(&exec->prohibitTimer,
                            "steerexecImplProhibitTimeout",
                            steerexecImplProhibitTimeoutHandler,
                            exec);

        evloopTimeoutCreate(&exec->legacy.steeringUnfriendly.timer,
                            "steerexecImplUnfriendlyTimeout",
                            steerexecImplUnfriendlyTimeoutHandler,
                            exec);

        evloopTimeoutCreate(&exec->legacy.blacklistTimer,
                            "steerexecImplClearBlacklistTimeout",
                            steerexecImplBlacklistTimeoutHandler,
                            exec);

        evloopTimeoutCreate(&exec->btm.unfriendlyTimer.timer,
                            "steerexecImplBTMUnfriendlyTimeout",
                            steerexecImplBTMUnfriendlyTimeoutHandler,
                            exec);

        evloopTimeoutCreate(&exec->btm.activeUnfriendlyTimer.timer,
                            "steerexecImplBTMActiveUnfriendlyTimeout",
                            steerexecImplBTMActiveUnfriendlyTimeoutHandler,
                            exec);

        mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_btm_response,
                              steerexecImplHandleBTMResponseEvent);
    }

    return exec;
}

LBD_STATUS steerexecImplAbort(steerexecImplHandle_t exec,
                              stadbEntry_handle_t entry,
                              steerexecImplSteeringStatusType_e abortReason,
                              LBD_BOOL *ignored) {
    if (!exec || !entry) {
        return LBD_NOK;
    }

    if (ignored) {
        *ignored = LBD_TRUE;
    }

    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // There must not be any steering operation in progress, so silently
        // succeed.
        return LBD_OK;
    }

    const struct ether_addr *addr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, addr);

    if (state->steerType == steerexecImplSteeringType_none) {
        // No Steering in progress.
        if (abortReason == steerexecImplSteeringStatusType_channel_change) {
            // When there is channel change, clear all blacklist
            return steerexecImplRemoveAllBlacklists(state, addr);
        } else {
            return LBD_NOK;
        }
    }

    LBD_STATUS status;

    if (steerexecImplIsBTMSteer(state->steerType)) {
        status = steerexecImplAbortBTM(exec, state, entry, addr);

        // Do we have blacklists installed too?
        if (steerexecImplIsBTMOnlySteer(state->steerType)) {
            steerexecImplSteerEnd(state, addr, abortReason);
            return status;
        }
    }

    if (ignored) {
        *ignored = LBD_FALSE;
    }

    // Do blacklist related abort
    return steerexecImplAbortLegacy(exec, state, entry, abortReason, addr);
}

LBD_STATUS steerexecImplAbortAllowAssoc(steerexecImplHandle_t exec,
                                        stadbEntry_handle_t entry,
                                        LBD_BOOL *ignored) {
    if (!exec || !entry) {
        return LBD_NOK;
    }

    if (ignored) {
        *ignored = LBD_TRUE;
    }

    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // There must not be any steering operation in progress, so silently
        // succeed.
        return LBD_OK;
    }

    if (state->steerType != steerexecImplSteeringType_preassociation) {
        // No preassociation steering in progress.
        return LBD_NOK;
    }

    if (ignored) {
        *ignored = LBD_FALSE;
    }

    // Do blacklist related abort
    const struct ether_addr *addr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, addr);
    return steerexecImplAbortLegacy(exec, state, entry,
                                    steerexecImplSteeringStatusType_abort_user,
                                    addr);
}


LBD_STATUS steerexecImplAllowAssoc(
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    LBD_BOOL *ignored) {

    if (!exec || !entry) {
        return LBD_NOK;
    }

    if (channelCount > STEEREXEC_MAX_ALLOW_ASSOC || !channelCount || !channelList) {
        return LBD_NOK;
    }

    steerexecImplSteeringState_t *state =
        steerexecImplGetOrCreateSteeringState(exec, entry);
    if (!state) {
        return LBD_NOK;
    }

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    stadbEntry_bssStatsHandle_t stats = stadbEntry_getServingBSS(entry, NULL);

    if (steerexecImplDetermineSteeringType(state, exec, entry, staAddr,
                                           stats, LBD_TRUE /* eligibiltyOnly */,
                                           LBD_TRUE /* reportReasonNotEligible */) !=
        steerexecImplSteeringType_preassociation) {
        return LBD_NOK;
    }

    // Update the blacklists / set of disabled VAPs based upon the new steer request
    LBD_BOOL willSteer;
    if (steerexecImplReconcileSteerChannel(
        state, exec, entry, staAddr, steerexecImplSteeringType_preassociation,
        channelCount, channelList, &willSteer) != LBD_OK) {
        return LBD_NOK;
    }

    // No error, but no action to take.
    if (!willSteer) {
        if (ignored) {
            *ignored = LBD_TRUE;
        }
        return LBD_OK;
    }

    state->steerType = steerexecImplSteeringType_preassociation;
    if (ignored) {
        *ignored = LBD_FALSE;
    }

    steerexecImplSetLastSteeringTime(state);

    // Update the transaction ID
    steerexecImplUpdateTransactionID(exec, state);

    dbgf(exec->dbgModule, DBGINFO,
         "%s: Starting new steer for " lbMACAddFmt(":") " of type %s (transaction %d)",
         __func__, lbMACAddData(staAddr->ether_addr_octet),
         steerexecImpl_SteeringTypeString[state->steerType], state->transaction);

    if (diaglog_startEntry(mdModuleID_SteerExec,
                           steerexec_msgId_preAssocSteerStart,
                           diaglog_level_demo)) {
        diaglog_writeMAC(staAddr);
        diaglog_write8(state->transaction);
        // Log the number of channels.
        diaglog_write8(channelCount);
        size_t i;
        // Log the channels.
        for (i = 0; i < channelCount; i++) {
            diaglog_write8(channelList[i]);
        }
        diaglog_finishEntry();
    }

    return LBD_OK;
}

LBD_STATUS steerexecImplSteer(steerexecImplHandle_t exec,
                              stadbEntry_handle_t entry,
                              u_int8_t candidateCount,
                              const lbd_bssInfo_t *candidateList,
                              steerexec_steerReason_e reason,
                              LBD_BOOL *ignored) {
    if (!exec || !entry || !candidateList ||
        (candidateCount == 0) || (candidateCount > STEEREXEC_MAX_CANDIDATES)) {
        return LBD_NOK;
    }

    // This function can only be used for locally associated STAs.
    // However, don't return here - this could be a call to change the target BSS.
    stadbEntry_bssStatsHandle_t stats = stadbEntry_getServingBSS(entry, NULL);

    // Get the BSS this STA is associated to
    const lbd_bssInfo_t *assocBSS = stadbEntry_resolveBSSInfo(stats);

    steerexecImplSteeringState_t *state =
        steerexecImplGetOrCreateSteeringState(exec, entry);
    if (!state) {
        return LBD_NOK;
    }

    // Common preparation, and blacklist installation, if needed
    LBD_BOOL okToSteer;
    if (steerexecImplPrepareAndSetBlacklist(state, exec, entry, candidateCount,
                                            candidateList,
                                            ignored, stats, assocBSS, &okToSteer) != LBD_OK) {
        return LBD_NOK;
    }

    if (!okToSteer) {
        // No errors occurred, but can't steer the STA now, return
        return LBD_OK;
    }

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    // How the device is steered is determined by whether or not the device supports
    // 802.11v BTM
    LBD_STATUS status;
    if (state->steerType == steerexecImplSteeringType_legacy) {
        status = steerexecImplSteerLegacy(state, exec, entry,
                                          candidateCount,
                                          candidateList, staAddr, assocBSS);
    } else {
        status = steerexecImplSteerBTM(state, exec, entry,
                                       candidateCount,
                                       candidateList, staAddr, assocBSS);
    }

    if (status == LBD_OK) {
        // Steering was successful, log and set target band
        if (ignored) {
            *ignored = LBD_FALSE;
        }

        // Copy over the candidates
        state->candidateCount = candidateCount;
        memcpy(&state->candidateList[0], candidateList,
               candidateCount * sizeof(lbd_bssInfo_t));

        // Update the transaction ID
        steerexecImplUpdateTransactionID(exec, state);

        // Make sure the reason code is not out of bounds
        if (reason > steerexec_steerReasonInvalid) {
            reason = steerexec_steerReasonInvalid;
        }
        dbgf(exec->dbgModule, DBGINFO,
             "%s: Starting new steer for " lbMACAddFmt(":") " of type %s "
             " for reason %s (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             steerexecImpl_SteeringTypeString[state->steerType],
             steerexec_SteeringReasonTypeString[reason],
             state->transaction);

        if (diaglog_startEntry(mdModuleID_SteerExec,
                               steerexec_msgId_postAssocSteerStart,
                               diaglog_level_demo)) {
            diaglog_writeMAC(staAddr);
            diaglog_write8(state->transaction);
            diaglog_write8(state->steerType);
            diaglog_write8(reason);
            // Log the currently associated BSS
            diaglog_writeBSSInfo(assocBSS);
            // Log the number of candidates
            diaglog_write8(candidateCount);
            // Log the candidates
            size_t i;
            for (i = 0; i < candidateCount; i++) {
                diaglog_writeBSSInfo(&candidateList[i]);
            }
            diaglog_finishEntry();
        }
    } else {
        state->steerType = steerexecImplSteeringType_none;
    }

    return status;
}

void steerexecImplHandleAssocUpdate(steerexecImplHandle_t exec,
                                    stadbEntry_handle_t entry) {
    if (!exec || !entry) {
        return;
    }

    // Ignore any devices that do not have a valid association state. They
    // must be brand new ones.
    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        return;
    }

    // Check if the STA is actually associated
    stadbEntry_bssStatsHandle_t stats = stadbEntry_getServingBSS(entry, NULL);
    if (!stats) {
        // Not actually associated
        return;
    }

    const lbd_bssInfo_t *assocBSS = stadbEntry_resolveBSSInfo(stats);
    lbDbgAssertExit(exec->dbgModule, assocBSS);

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    // We have a steering state and the STA is associated.  Check if the BTM
    // capabilities have changed.
    if (steerexecImplUpdateBTMCapability(state, entry, staAddr) != LBD_OK) {
        // Error occurred - can't change BTM capabilities, return here
        return;
    }

    // What to do on association is determined by whether or not the device supports
    // 802.11v BTM
    LBD_BOOL steeringComplete;
    if (steerexecImplIsBTMSteer(state->steerType)) {
        steeringComplete = steerexecImplHandleAssocUpdateBTM(exec, entry, state,
                                                             assocBSS, staAddr);
    } else if (state->steerType == steerexecImplSteeringType_preassociation) {
          return steerexecImplHandleAssocPreAssoc(exec, entry, state, assocBSS);
    } else if (state->steerType == steerexecImplSteeringType_legacy) {
        steeringComplete = steerexecImplHandleAssocUpdateLegacy(exec, entry, state,
                                                                assocBSS, staAddr);
    } else {
        // No steer in progress, cancel T-Steering timer (in case it was started)
        evloopTimeoutUnregister(&state->legacy.tSteerTimer);
        // If there was an aborted BTM steer in progress, return to the idle state now
        if (state->btm && state->btm->state == steerexecImpl_btmState_aborted) {
            state->btm->state = steerexecImpl_btmState_idle;
            evloopTimeoutUnregister(&state->btm->timer);
        }
        return;
    }

    // Do blacklist related cleanup if needed
    if (steeringComplete) {
        steerexecImplAssocBlacklistClear(exec, entry, state, assocBSS);
    }
}

steerexec_steerEligibility_e steerexecImplDetermineSteeringEligibility(
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    LBD_BOOL reportReasonNotEligible) {
    if (!exec || !entry) {
        return steerexec_steerEligibility_none;
    }

    // Check if the STA is actually associated
    stadbEntry_bssStatsHandle_t stats = stadbEntry_getServingBSS(entry, NULL);
    if (!stats) {
        // Not actually associated
        return steerexec_steerEligibility_none;
    }

    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // If there is no steering state, this STA hasn't been steered before,
        // therefore it can't be prohibited from steering.
        // It can only be steered while idle (regardless of whether it supports
        // BTM or not).
        return steerexec_steerEligibility_idle;
    }

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    steerexecImplSteeringType_e steerType = steerexecImplDetermineSteeringType(
        state, exec, entry, staAddr, stats,
        LBD_TRUE /* eligibilityOnly */,
        reportReasonNotEligible);

    if (steerType == steerexecImplSteeringType_legacy) {
        // Legacy STAs can only be steered while idle
        return steerexec_steerEligibility_idle;
    } else if (!steerexecImplIsBTMSteer(steerType)) {
        return steerexec_steerEligibility_none;
    } else {
        // For BTM STAs, determine if it can be steered while active or not.
        lbDbgAssertExit(exec->dbgModule, state->btm);

        if (state->btm->complianceState == steerexecImpl_btmComplianceState_active) {
            // Determine if the STA reports it supports RRM
            if (stadbEntry_isRRMSupported(entry)) {
                return steerexec_steerEligibility_active;
            } else {
                // Even though the STA could be steered while active according
                // to steerexec, it doesn't support RRM, so we can't get stats
                // on the non-serving channel.  Only attempt to steer while idle.
                return steerexec_steerEligibility_idle;
            }
        } else {
            return steerexec_steerEligibility_idle;
        }
    }
}

LBD_BOOL steerexecImplShouldAbortSteerForActive(steerexecImplHandle_t exec,
                                          stadbEntry_handle_t entry) {
    if (!exec || !entry) {
        return LBD_FALSE;
    }

    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // If there is no steering state, this STA hasn't been steered before,
        // therefore there is nothing to abort.
        return LBD_FALSE;
    }

    // If there is no steer in progresss, nothing to abort
    if (state->steerType == steerexecImplSteeringType_none) {
        return LBD_FALSE;
    }

    if (!stadbEntry_isBTMSupported(entry)) {
        // STA does not report it supports BSS Transition Management,
        // therefore should abort any steer if active.
        return LBD_TRUE;
    } else {
        // For BTM STAs, determine if it can be steered while active or not.
        lbDbgAssertExit(exec->dbgModule, state->btm);

        if (state->btm->complianceState == steerexecImpl_btmComplianceState_active) {
            return LBD_FALSE;
        } else {
            return LBD_TRUE;
        }
    }
}

LBD_STATUS steerexecImplRegisterSteeringAllowedObserver(
        steerexecImplHandle_t exec,
        steerexec_steeringAllowedObserverCB callback,
        void *cookie) {
    if (!exec || !callback) {
        return LBD_NOK;
    }

    struct steerexecImplSteeringAllowedObserver *freeSlot = NULL;
    size_t i;
    for (i = 0; i < MAX_STEERING_ALLOWED_OBSERVERS; ++i) {
        struct steerexecImplSteeringAllowedObserver *curSlot =
            &exec->steeringAllowedObservers[i];
        if (curSlot->isValid && curSlot->callback == callback &&
            curSlot->cookie == cookie) {
            dbgf(exec->dbgModule, DBGERR, "%s: Duplicate registration "
                                          "(func %p, cookie %p)",
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

LBD_STATUS steerexecImplUnregisterSteeringAllowedObserver(
        steerexecImplHandle_t exec,
        steerexec_steeringAllowedObserverCB callback,
        void *cookie) {
    if (!exec || !callback) {
        return LBD_NOK;
    }

    size_t i;
    for (i = 0; i < MAX_STEERING_ALLOWED_OBSERVERS; ++i) {
        struct steerexecImplSteeringAllowedObserver *curSlot =
            &exec->steeringAllowedObservers[i];
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

void steerexecImplDestroy(steerexecImplHandle_t exec) {
    if (exec) {
        stadb_unregisterLowRSSIObserver(steerexecImplLowRSSIObserver, exec);
        stadb_unregisterRSSIObserver(steerexecImplRSSIObserver, exec);
        wlanif_unregisterChanChangeObserver(steerexecImplChanChangeObserver, exec);
        evloopTimeoutUnregister(&exec->prohibitTimer);
        evloopTimeoutUnregister(&exec->legacy.steeringUnfriendly.timer);
        evloopTimeoutUnregister(&exec->legacy.blacklistTimer);
        evloopTimeoutUnregister(&exec->btm.unfriendlyTimer.timer);
        evloopTimeoutUnregister(&exec->btm.activeUnfriendlyTimer.timer);
        free(exec);
    }
}

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Return if the STA is being steered via BTM (either
 *        with or without blacklists)
 *
 * @param [in] steerType  steering type to check
 *
 * @return LBD_TRUE if this is a BTM steer type, LBD_FALSE
 *         otherwise
 */
static LBD_BOOL steerexecImplIsBTMSteer(steerexecImplSteeringType_e steerType) {
    if ((steerType == steerexecImplSteeringType_btm) ||
        (steerType == steerexecImplSteeringType_btm_and_blacklist) ||
        (steerType == steerexecImplSteeringType_btm_active) ||
        (steerType == steerexecImplSteeringType_btm_and_blacklist_active) ||
        (steerType == steerexecImplSteeringType_btm_be) ||
        (steerType == steerexecImplSteeringType_btm_be_active) ||
        (steerType == steerexecImplSteeringType_btm_blacklist_be) ||
        (steerType == steerexecImplSteeringType_btm_blacklist_be_active)) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Return if the STA is being steered via BTM without
 *        blacklists
 *
 * @param [in] steerType  steering type to check
 *
 * @return LBD_TRUE if this is a BTM only (no blacklist) steer
 *         type, LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplIsBTMOnlySteer(steerexecImplSteeringType_e steerType) {
    if ((steerType == steerexecImplSteeringType_btm) ||
        (steerType == steerexecImplSteeringType_btm_active) ||
        (steerType == steerexecImplSteeringType_btm_be) ||
        (steerType == steerexecImplSteeringType_btm_be_active)) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Return if the STA is being steered while active
 *
 * @param [in] steerType  steering type to check
 *
 * @return LBD_TRUE if this is an active steer type, LBD_FALSE
 *         otherwise
 */
static LBD_BOOL steerexecImplIsActiveSteer(steerexecImplSteeringType_e steerType) {
    if ((steerType == steerexecImplSteeringType_btm_active)||
        (steerType == steerexecImplSteeringType_btm_and_blacklist_active) ||
        (steerType == steerexecImplSteeringType_btm_be_active) ||
        (steerType == steerexecImplSteeringType_btm_blacklist_be_active)) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Return if the the steer is best effort
 *
 * @param [in] steerType  steering type to check
 *
 * @return LBD_TRUE if this is a best effort steer type,
 *         LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplIsBestEffortSteer(steerexecImplSteeringType_e steerType) {
    if ((steerType == steerexecImplSteeringType_btm_be) ||
        (steerType == steerexecImplSteeringType_btm_be_active) ||
        (steerType == steerexecImplSteeringType_btm_blacklist_be) ||
        (steerType == steerexecImplSteeringType_btm_blacklist_be_active)) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Mark a STA entry as no longer blacklisted.  Will
 *        unregister the blacklist timer if no other STAs are
 *        still blacklisted.
 *
 * @param [in] state  steering state for the STA
 */
static void steerexecImplMarkAsNotBlacklisted(steerexecImplSteeringState_t *state) {
    if (state->blacklistType != steerexecImplBlacklist_none) {
        state->blacklistType = steerexecImplBlacklist_none;
        state->context->legacy.numBlacklist--;
        if (!state->context->legacy.numBlacklist) {
            // No more STAs are blacklisted, clear the timer
            evloopTimeoutUnregister(&state->context->legacy.blacklistTimer);
        }
    }
}

/**
 * @brief Check if the STA is reporting a different BTM
 *        capability than previous association
 *
 * @param [in] state  steering state for the STA
 * @param [in] entry  stadb entry for the STA
 * @param [in] staAddr  MAC address of the STA
 *
 * @return LBD_OK if the state was updated successfully; LBD_NOK
 *         otherwise
 */
static LBD_STATUS steerexecImplUpdateBTMCapability(
    steerexecImplSteeringState_t *state,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr) {
    if (!state->btm && stadbEntry_isBTMSupported(entry)) {
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Device " lbMACAddFmt(":") " previously marked as not BTM "
             "capable, now supports BTM", __func__,
             lbMACAddData(staAddr->ether_addr_octet));

        if (steerexecImplSetupBTMState(state, entry) != LBD_OK) {
            dbgf(state->context->dbgModule, DBGERR,
             "%s: Unable to upgrade device " lbMACAddFmt(":") " from non-BTM "
             "capable, to BTM capable, deleted steering entry", __func__,
             lbMACAddData(staAddr->ether_addr_octet));

            // Destroy the steering state
            steerexecImplDestroySteeringState(state);

            // Clear the stadb record
            stadbEntry_setSteeringState(entry, NULL, NULL);
            return LBD_NOK;
        }
    } else if (state->btm && !stadbEntry_isBTMSupported(entry)) {
        // If device no longer reports it supports BTM just print
        // an informational mesage, no action to take
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Device " lbMACAddFmt(":") " previously marked as BTM "
             "capable, no longer supports BTM", __func__,
             lbMACAddData(staAddr->ether_addr_octet));
    }

    return LBD_OK;
}

/**
 * @brief Setup the BTM state in the steering state
 *
 * @param [in] state steering state for the STA
 * @param [in] entry stadb entry for the STA
 *
 * @return LBD_OK if the state was updated successfully; LBD_NOK
 *         otherwise
 */
static LBD_STATUS steerexecImplSetupBTMState(steerexecImplSteeringState_t *state,
                                             stadbEntry_handle_t entry) {
    state->btm = calloc(1, sizeof(steerexecImplSteeringStateBTM_t));
    if (!state->btm) {
        return LBD_NOK;
    }
    state->btm->state = steerexecImpl_btmState_idle;
    // Initially only attempt to use BTM steering while idle
    state->btm->complianceState = steerexecImpl_btmComplianceState_idle;
    evloopTimeoutCreate(&state->btm->timer,
                        "steerexecImplBTMTimer",
                        steerexecImplBTMTimeoutHandler,
                        entry);

    return LBD_OK;
}

/**
 * @brief Obtain the steering state entry for the STA, creating it if it does
 *        not exist.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the handle to the STA for which to get the state
 *
 * @return the state entry, or NULL if one could not be created
 */
static steerexecImplSteeringState_t *steerexecImplGetOrCreateSteeringState(
        steerexecImplHandle_t exec, stadbEntry_handle_t entry) {
    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        state = calloc(1, sizeof(steerexecImplSteeringState_t));
        if (!state) {
            return NULL;
        }

        state->context = exec;
        evloopTimeoutCreate(&state->legacy.tSteerTimer,
                            "steerexecImplTSteeringTimeout",
                            steerexecImplTSteeringTimeoutHandler,
                            entry);

        if (stadbEntry_isBTMSupported(entry)) {
            if (steerexecImplSetupBTMState(state, entry) != LBD_OK) {
                steerexecImplDestroySteeringState(state);
                return NULL;
            }
        }

        stadbEntry_setSteeringState(entry, state,
                                    steerexecImplDestroySteeringState);
    }

    return state;
}

/**
 * @brief Destructor function used to clean up the steering state for the
 *        steering executor.
 */
static void steerexecImplDestroySteeringState(void *state) {
    steerexecImplSteeringState_t *statePtr = (steerexecImplSteeringState_t *)state;
    evloopTimeoutUnregister(&statePtr->legacy.tSteerTimer);
    if (statePtr->btm) {
        evloopTimeoutUnregister(&statePtr->btm->timer);
        free(statePtr->btm);
    }
    free(state);
}

/**
 * @brief Determine the BTM steering type to use depending on if
 *        the STA is active, and whether blacklists are required
 *
 * @param [in] active LBD_TRUE if STA is active, LBD_FALSE
 *                    otherwise
 * @param [in] useBlacklist  LBD_TRUE if blacklists should be
 *                           used, LBD_FALSE otherwise
 *
 * @return Steering type to use
 */
static steerexecImplSteeringType_e steerexecImplDetermineBTMSteeringType(
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    stadbEntry_bssStatsHandle_t stats,
    LBD_BOOL active,
    LBD_BOOL useBlacklist) {

    // Even if we usually use a blacklist for BTM steering, if the RSSI
    // is sufficiently low, we can't be confident the transaction will
    // succeed due to poor channel conditions.  If we try and steer, it
    // is best effort (no blacklist, no marking as unfriendly on failure)
    LBD_BOOL useBestEffort = LBD_FALSE;
    lbd_rssi_t rssi = stadbEntry_getUplinkRSSI(entry, stats,
                                               NULL, NULL);

    if ((rssi == LBD_INVALID_RSSI) ||
        (rssi < exec->config.btm.minRSSIBestEffort)) {
        // Generally the RSSI should be both valid and recent here.  However, if
        // we can't get a valid RSSI, use best-effort steering.  Also use
        // best-effort steering if the RSSI indicates channel conditions are poor
        // (even if that RSSI is not recent).
        useBestEffort = LBD_TRUE;
    }

    if (active) {
        if (useBestEffort) {
            return steerexecImplSteeringType_btm_be_active;
        }
        if (useBlacklist) {
            return steerexecImplSteeringType_btm_and_blacklist_active;
        } else {
            return steerexecImplSteeringType_btm_active;
        }
    } else {
        if (useBestEffort) {
            return steerexecImplSteeringType_btm_be;
        }
        if (useBlacklist) {
            return steerexecImplSteeringType_btm_and_blacklist;
        } else {
            return steerexecImplSteeringType_btm;
        }
    }
}

/**
 * @brief Determine the type of steering to use for this STA
 *
 * @param [in] state steering state for the STA
 * @param [in] exec steering executor instance
 * @param [in] entry staDB entry for the STA
 * @param [in] staAddr MAC address of the STA
 * @param [in] isAssoc LBD_TRUE if the STA is associated,
 *                     LBD_FALSE otherwise
 * @param [in] eligibilityOnly LBD_TRUE if just checking whether
 *                             the STA is eligible to be steered
 *                             via BTM, LBD_FALSE if the type of
 *                             BTM steering also needs to be
 *                             determined
 * @param [in] reportReasonNotEligible  whether to report the
 *                                      reason why the STA is
 *                                      not eligible for
 *                                      steering
 *
 * @return Steering type to use
 */
static steerexecImplSteeringType_e steerexecImplDetermineSteeringType(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    stadbEntry_bssStatsHandle_t stats,
    LBD_BOOL eligibilityOnly,
    LBD_BOOL reportReasonNotEligible) {

    steerexecImplSteeringType_e steerType;

    // Steering unfriendly devices cannot be steered until a timer expires
    // that lets us try steering them again.
    if (state->legacy.steeringUnfriendly) {
        if (reportReasonNotEligible) {
            dbgf(exec->dbgModule, DBGDEBUG,
                 "%s: Cannot steer " lbMACAddFmt(":") " due "
                 "to being marked as steering unfriendly", __func__,
                 lbMACAddData(staAddr->ether_addr_octet));
        }
        return steerexecImplSteeringType_none;
    }

    // If the device was steered too recently, return.
    if (state->steeringProhibited != steerexecImplSteeringProhibitType_none) {
        if (reportReasonNotEligible) {
            dbgf(exec->dbgModule, DBGDEBUG,
                 "%s: Cannot steer "  lbMACAddFmt(":") " due "
                 "to quiet period", __func__,
                 lbMACAddData(staAddr->ether_addr_octet));
        }
        return steerexecImplSteeringType_none;
    }

    if (!stats) {
        steerType = steerexecImplSteeringType_preassociation;
    } else if (!stadbEntry_isBTMSupported(entry)) {
        // STA does not report it supports BSS Transition Management,
        // only use legacy steering
        steerType = steerexecImplSteeringType_legacy;
    } else {
        if (eligibilityOnly) {
            // Just checking steering eligibility, enough to say
            // it supports BTM
            return steerexecImplSteeringType_btm;
        }

        // STA reports it does support BTM, but is it eligible to use it?
        if (state->btm->btmUnfriendly) {
            // Using legacy steering
            steerType = steerexecImplSteeringType_legacy;
        } else if (state->btm->complianceState != steerexecImpl_btmComplianceState_active) {
            // Must be idle, can only be steered while idle
            steerType = steerexecImplDetermineBTMSteeringType(exec, entry, stats,
                                                              LBD_FALSE /* isActive */,
                                                              exec->config.btm.alsoBlacklist);
        } else {
            // This STA can be steered while active - check if it actually is active
            LBD_BOOL active = LBD_FALSE;
            if (stadbEntry_getActStatus(entry, &active, NULL) != LBD_OK) {
                dbgf(state->context->dbgModule, DBGERR,
                 "%s: BTM STA can be steered while active, but could not get activity status, "
                 "will assume is idle",
                 __func__);
            }

            steerType = steerexecImplDetermineBTMSteeringType(exec, entry, stats, active,
                                                              exec->config.btm.alsoBlacklist);
        }
    }

    return steerType;
}

/**
 * @brief Get the length of time (in seconds) to prohibit
 *        steering
 *
 * @param [in] exec steering executor instance
 * @param [in] prohibit type of steering prohibition
 *
 * @return u_int32_t length of time (in seconds) to prohibit
 *        steering
 */
static u_int32_t steerexecImplGetSteeringProhibitTime(
    steerexecImplHandle_t exec,
    steerexecImplSteeringProhibitType_e prohibit) {
    if (prohibit == steerexecImplSteeringProhibitType_short) {
        return exec->config.btm.steeringProhibitShortTime;
    } else if (prohibit == steerexecImplSteeringProhibitType_long) {
        return exec->config.legacy.steeringProhibitTime;
    } else if (prohibit == steerexecImplSteeringProhibitType_none) {
        return 0;
    } else {
        // Invalid duration
        lbDbgAssertExit(exec->dbgModule, 0);
        return 0;  // keep compiler happy
    }
}

/**
 * @brief Start the time period during which steering is prohibited for this
 *        entry.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] state  the object that captures the steering state
 * @param [in] staAddr  the address of the STA that is having its prohibited
 *                      time started/updated
 * @param [in] prohibit type of steering prohibition
 */
static void steerexecImplStartSteeringProhibit(
        steerexecImplHandle_t exec,
        steerexecImplSteeringState_t *state,
        const struct ether_addr *staAddr,
        steerexecImplSteeringProhibitType_e prohibit) {

    steerexecImplSetLastSteeringTime(state);

    // Get the correct time to prohibit steering for.
    u_int32_t prohibitTime =
        steerexecImplGetSteeringProhibitTime(exec, prohibit) + 1;

    // Special case: if the prohibit time is 0, don't set a timer here
    // (STA is never prohibited from steering)
    if (prohibitTime == 1) {
        return;
    }

    LBD_BOOL generateLog = LBD_FALSE;
    if (state->steeringProhibited == steerexecImplSteeringProhibitType_none) {
        // New entry being prohibited.
        exec->numSteeringProhibits++;
        generateLog = LBD_TRUE;
    } else if ((state->steeringProhibited == steerexecImplSteeringProhibitType_short) &&
               (prohibit == steerexecImplSteeringProhibitType_long)) {
        // Also log if the prohibit time is increased.
        generateLog = LBD_TRUE;
    }

    state->steeringProhibited = prohibit;
    
    // Determine if we need to set a new timer.  This will occur if this is
    // the first timer set, or if this new expiry is for an earlier time than the previous
    // earliest expiry.  This can occur if a short timer is started while
    // a long timer is the current next expiry.
    if ((exec->numSteeringProhibits == 1) ||
        (exec->nextProhibitExpiry > state->legacy.lastSteeringTime + prohibitTime)) {

        exec->nextProhibitExpiry = state->legacy.lastSteeringTime + prohibitTime;

        // Initial timer expiry we let be for the max time. It'll get
        // rescheduled based on the earliest expiry time (if necessary).
        evloopTimeoutRegister(&exec->prohibitTimer,
                              prohibitTime, 0);
    }

    if (generateLog) {
        steerexecImplDiagLogSteeringProhibited(staAddr,
                                               prohibit);
    }
}

/**
 * @brief Calculate the exponential backoff time
 *        min(maxBackoff, (baseTime * 2 ^ exponent))
 *
 * @param [in] baseTime  base time for the calculation
 * @param [in] exponent  exponent for the calculation
 * @param [in] maxBackoff   maximum value for the backoff
 *
 * @return Exponential backoff time
 */
static u_int32_t steerexecImplGetExpBackoffTime(u_int32_t baseTime,
                                                u_int32_t exponent,
                                                u_int32_t maxBackoff) {
    // We are limited to a 32-bit backoff time (around 68 years)
    if (exponent >= 31) {
        return maxBackoff;
    }
    // Handle rollover
    u_int32_t exponentialFactor = (1 << exponent);
    if (maxBackoff / baseTime <= exponentialFactor) {
        return maxBackoff;
    }
    return baseTime * exponentialFactor;
}

/**
 * @brief Start an exponential backoff for a STA.  Will start
 *        the timer running if this is the first STA using this
 *        timer, or the expiry time for this STA is less than
 *        the old timer expiry.
 *
 * @param [in] timer  timer structure to use
 * @param [in] baseTime  base time for the backoff
 * @param [in] exponent  exponent for the backoff
 * @param [in] maxBackoff   maximum value for the backoff
 */
static void steerexecImplStartExpBackoff(steerexecImplTimerStruct_t *timer,
                                         u_int32_t baseTime,
                                         u_int32_t exponent,
                                         u_int32_t maxBackoff) {
    if (!baseTime) {
        return;
    }

    timer->countEntries++;

    struct timespec ts;
    lbGetTimestamp(&ts);

    time_t incTime =
        steerexecImplGetExpBackoffTime(baseTime, exponent, maxBackoff) + 1;
    if ((timer->countEntries == 1) || (timer->nextExpiry > ts.tv_sec + incTime)) {
        timer->nextExpiry = ts.tv_sec + incTime;

        evloopTimeoutRegister(&timer->timer, incTime, 0);
    }
}

/**
 * @brief Start the time period during which this entry is marked as
 *        steering unfriendly.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] state  the object that captures the steering state
 * @param [in] staAddr address of the STA marked steering
 *                     unfriendly
 */
static void steerexecImplStartSteeringUnfriendly(
        steerexecImplHandle_t exec,
        steerexecImplSteeringState_t *state,
        const struct ether_addr *staAddr) {
    lbDbgAssertExit(exec->dbgModule, !state->legacy.steeringUnfriendly);
    state->legacy.steeringUnfriendly = LBD_TRUE;

    steerexecImplStartExpBackoff(&exec->legacy.steeringUnfriendly,
                                 exec->config.legacy.steeringUnfriendlyTime,
                                 state->legacy.countConsecutiveFailure,
                                 exec->config.legacy.maxSteeringUnfriendly);

    state->legacy.countConsecutiveFailure++;

    steerexecImplDiagLogSteeringUnfriendly(staAddr, LBD_TRUE,
                                           state->legacy.countConsecutiveFailure);
}

/**
 * @brief Start the time period during which this entry is
 *        marked as BTM steering unfriendly (can be either
 *        active steering unfriendly, or unfriendly for any kind
 *        of BTM steering).
 *
 * @param [in] exec  the executor instance to use
 * @param [in] state  the object that captures the steering state
 * @param [in] staAddr address of the STA marked BTM steering
 *                     unfriendly
 * @param [in] timer  timer to start
 * @param [in] exponent  exponent for backoff
 * @param [in] maxBackoff   maximum value for backoff
 */
static void steerexecImplStartBTMUnfriendly(
        steerexecImplHandle_t exec,
        steerexecImplSteeringState_t *state,
        const struct ether_addr *staAddr,
        steerexecImplTimerStruct_t *timer,
        u_int32_t exponent,
        u_int32_t maxBackoff) {
    // BTM unfriendly time of 0 means this station will always always
    // be treated as BTM friendly.
    if (!exec->config.btm.btmUnfriendlyTime) {
        return;
    }

    if (state->btm->complianceState == steerexecImpl_btmComplianceState_active) {
        // Was using active steering, mark as active unfriendly
        state->btm->complianceState =
            steerexecImpl_btmComplianceState_activeUnfriendly;
        struct timespec ts;
        lbGetTimestamp(&ts);
        state->btm->lastActiveSteeringFailureTime = ts.tv_sec;

        state->btm->countConsecutiveFailureActive++;
        // Reset the count of consecutive failures (to use for idle steering)
        state->btm->countConsecutiveFailure = 0;
    } else {
        // Was using idle steering, mark as BTM unfriendly
        state->btm->btmUnfriendly = LBD_TRUE;
        state->btm->countConsecutiveFailure++;
    }

    steerexecImplStartExpBackoff(timer,
                                 exec->config.btm.btmUnfriendlyTime,
                                 exponent, maxBackoff);

    steerexecImplDiagLogBTMCompliance(staAddr, state->btm->btmUnfriendly,
                                      state->btm->complianceState,
                                      state->btm->countConsecutiveFailure,
                                      state->btm->countConsecutiveFailureActive);
}

/**
 * @brief Update the BTM compliance state, based on the success
 *        or failure of the previous transaction.
 *
 * @param [in] entry  stadb entry
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of STA
 * @param [in] success  set to LBD_TRUE if the previous
 *                      transaction was a success, LBD_FALSE on
 *                      failure
 */
static void steerexecImplUpdateBTMCompliance(
    stadbEntry_handle_t entry,
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr,
    LBD_BOOL success) {

    if (success) {
        // Any successful BTM steer will reset the consecutive failure count.
        state->btm->countConsecutiveFailure = 0;

        if (state->btm->complianceState ==
            steerexecImpl_btmComplianceState_idle) {
            // Since the STA successfully obeyed the BTM request, allow it to
            // be steered while active
            state->btm->complianceState = steerexecImpl_btmComplianceState_active;
            steerexecImplDiagLogBTMCompliance(staAddr, state->btm->btmUnfriendly,
                                              state->btm->complianceState,
                                              state->btm->countConsecutiveFailure,
                                              state->btm->countConsecutiveFailureActive);
        } else if (state->btm->complianceState ==
                   steerexecImpl_btmComplianceState_active) {
            if (steerexecImplIsActiveSteer(state->steerType)) {
                // Only reset the consecutive failure while active count
                // if the STA was actually active at the time of the steer.
                state->btm->countConsecutiveFailureActive = 0;
            }
        }
    } else {
        if (steerexecImplIsBestEffortSteer(state->steerType)) {
            // Failures are OK in best-effort state, return
            return;
        }

        // While in the active allowed state, will not move to the active unfriendly
        // state until there are either steerexecImpl_maxConsecutiveBTMFailuresAsActive
        // consecutive failures while active, or the STA fails to transition while
        // idle.
        if (state->btm->complianceState == steerexecImpl_btmComplianceState_active) {
            if ((state->btm->countConsecutiveFailure ==
                 steerexecImpl_maxConsecutiveBTMFailuresAsActive - 1) ||
                (!steerexecImplIsActiveSteer(state->steerType))) {
                steerexecImplStartBTMUnfriendly(
                    state->context, state, staAddr,
                    &state->context->btm.activeUnfriendlyTimer,
                    state->btm->countConsecutiveFailureActive,
                    state->context->config.btm.maxBTMActiveUnfriendly);
                return;
            }
        } else {
            steerexecImplStartBTMUnfriendly(state->context, state, staAddr,
                                            &state->context->btm.unfriendlyTimer,
                                            state->btm->countConsecutiveFailure,
                                            state->context->config.btm.maxBTMUnfriendly);
            return;
        }
        state->btm->countConsecutiveFailure++;
    }
}

/**
 * @brief Store the transaction ID with the per-STA steering
 *        information, and increment the global transaction ID,
 *        handling overflow if needed.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] state  the object that captures the steering
 *                    state
 */
static void steerexecImplUpdateTransactionID(steerexecImplHandle_t exec,
                                             steerexecImplSteeringState_t *state) {
    state->transaction = exec->transaction;
    exec->transaction++;
}

/**
 * @brief Generate a diagnostic log indicating that the steering unfriendly
 *        state for a given client changed.
 *
 * @param [in] staAddr  the MAC address of the STA whose state changed
 * @param [in] isUnfriendly  flag indicating whether the STA is currently
 *                           considered steering unfriendly
 * @param [in] consecutiveFailures  number of consecutive legacy
 *                                  steering failures
 */
static void steerexecImplDiagLogSteeringUnfriendly(
        const struct ether_addr *staAddr, LBD_BOOL isUnfriendly,
        u_int32_t consecutiveFailures) {
    if (diaglog_startEntry(mdModuleID_SteerExec,
                           steerexec_msgId_steeringUnfriendly,
                           diaglog_level_info)) {
        diaglog_writeMAC(staAddr);
        diaglog_write8(isUnfriendly);
        diaglog_write32(consecutiveFailures);
        diaglog_finishEntry();
    }
}

/**
 * @brief Generate a diagnostic log indicating that the BTM
 *        compliance state for a given client changed.
 *
 * @param [in] staAddr  the MAC address of the STA whose state changed
 * @param [in] btmUnfriendly  flag indicating whether the STA is
 *                            currently considered BTM
 *                            unfriendly
 * @param [in] complianceState  current BTM compliance state
 * @param [in] consecutiveFailures  count of BTM failures since
 *                                  the last successful BTM
 *                                  transition
 * @param [in] consecutiveFailuresActive count of BTM failures
 *                                       in the active allowed
 *                                       state since the last
 *                                       successful BTM
 *                                       transition while active
 */
static void steerexecImplDiagLogBTMCompliance(
        const struct ether_addr *staAddr,
        LBD_BOOL btmUnfriendly,
        steerexecImpl_btmComplianceState_e complianceState,
        u_int32_t consecutiveFailures,
        u_int32_t consecutiveFailuresActive) {
    if (diaglog_startEntry(mdModuleID_SteerExec,
                           steerexec_msgId_btmCompliance,
                           diaglog_level_info)) {
        diaglog_writeMAC(staAddr);
        diaglog_write8(btmUnfriendly);
        diaglog_write8(complianceState);
        diaglog_write32(consecutiveFailures);
        diaglog_write32(consecutiveFailuresActive);
        diaglog_finishEntry();
    }
}

/**
 * @brief Generate a diagnostic log indicating that a steer
 *        attempt has ended.
 *
 * @param [in] staAddr  the MAC address of the STA whose state changed
 * @param [in] transaction completed transaction ID
 * @param [in] steerType  type of steer that was underway
 * @param [in] status  status of steer that has ended
 */
static void steerexecImplDiagLogSteerEnd(
        const struct ether_addr *staAddr,
        u_int8_t transaction,
        steerexecImplSteeringType_e steerType,
        steerexecImplSteeringStatusType_e status) {

    if (diaglog_startEntry(mdModuleID_SteerExec,
                           steerexec_msgId_steerEnd,
                           diaglog_level_info)) {

        diaglog_writeMAC(staAddr);
        diaglog_write8(transaction);
        diaglog_write8(steerType);
        diaglog_write8(status);
        diaglog_finishEntry();
    }
}

/**
 * @brief Generate a diagnostic log indicating that the steering prohibited
 *        state for a given client changed.
 *
 * @param [in] staAddr  the MAC address of the STA whose state changed
 * @param [in] prohibit type of steering prohibition
 */
static void steerexecImplDiagLogSteeringProhibited(
        const struct ether_addr *staAddr,
        steerexecImplSteeringProhibitType_e prohibit) {
    if (diaglog_startEntry(mdModuleID_SteerExec,
                           steerexec_msgId_steeringProhibited,
                           diaglog_level_info)) {
        diaglog_writeMAC(staAddr);
        diaglog_write8(prohibit);
        diaglog_finishEntry();
    }
}

/**
 * @brief Cleanup after a steer attempt has ended
 *
 * @param [in] state steering state
 * @param [in] staAddr the MAC address of the STA whose steer
 *                     attempt has ended
 * @param [in] status status of the steer attempt
 */
static void steerexecImplSteerEnd(steerexecImplSteeringState_t *state,
                                  const struct ether_addr *staAddr,
                                  steerexecImplSteeringStatusType_e status) {
    // Log if enabled
    steerexecImplDiagLogSteerEnd(staAddr, state->transaction,
                                 state->steerType, status);

    // Start the prohibit timer
    steerexecImplStartSteeringProhibit(state->context, state, staAddr,
                                       state->steeringProhibited);

    // No steer in progress
    state->steerType = steerexecImplSteeringType_none;
    if (state->btm) {
        // Special case: if the steer was aborted due to user request,
        // want to make sure that any error messages are suppressed
        // due to the potentially ongoing BTM transition.
        if (status == steerexecImplSteeringStatusType_abort_user) {
            state->btm->state = steerexecImpl_btmState_aborted;
        } else {
            state->btm->state = steerexecImpl_btmState_idle;
        }
    }
}

/**
 * @brief Common operations after a BTM steering failure
 *
 * @param [in] entry  stadb entry
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of STA
 * @param [in] status  status code for the failure
 */
static void steerexecImplSteerEndBTMFailure(
    stadbEntry_handle_t entry,
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr,
    steerexecImplSteeringStatusType_e status) {
    switch (status) {
        case steerexecImplSteeringStatusType_btm_response_timeout:
            dbgf(state->context->dbgModule, DBGINFO,
                 "%s: "lbMACAddFmt(":")" timeout waiting for BTM response (transaction %d)",
                 __func__, lbMACAddData(staAddr->ether_addr_octet), state->transaction);
            // Increment failure count
            state->btm->countNoResponseFailure++;
            break;
        case steerexecImplSteeringStatusType_assoc_timeout:
            dbgf(state->context->dbgModule, DBGINFO,
                 "%s: "lbMACAddFmt(":")" timeout waiting for association after BTM response "
                 "(transaction %d)",
                 __func__, lbMACAddData(staAddr->ether_addr_octet), state->transaction);
            // Increment failure count
            state->btm->countAssociationFailure++;
            break;
        case steerexecImplSteeringStatusType_btm_reject:
            // Report the failure in the calling function to avoid having to pass in
            // the reject code.
            // Increment failure count
            state->btm->countRejectFailure++;
            break;
        default:
            dbgf(state->context->dbgModule, DBGINFO,
                 "%s: "lbMACAddFmt(":")" invalid steering status %u",
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 status);
    }

    steerexecImplUpdateBTMCompliance(entry, state, staAddr,
                                     LBD_FALSE /* success */);

    // Clear the blacklist, if one exists
    steerexecImplCleanupBlacklistBTM(state, entry, staAddr, status);
}

/**
 * @brief Mark the STA being blacklisted.
 *
 * Start the blacklist timer when the first STA is blacklisted.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] state  the object that captures the steering state
 * @param [in] blacklistType  the type of blacklisting to
 *                            perform
 */
static void steerexecImplMarkBlacklist(steerexecImplHandle_t exec,
                                       steerexecImplSteeringState_t *state,
                                       steerexecImplBlacklistType_e blacklistType) {
    struct timespec ts;
    lbGetTimestamp(&ts);

    lbDbgAssertExit(exec->dbgModule, state->blacklistType == steerexecImplBlacklist_none);

    exec->legacy.numBlacklist++;
    state->blacklistType = blacklistType;

    if (exec->config.legacy.blacklistTime > 0 &&
        exec->legacy.numBlacklist == 1) {
        exec->legacy.nextBlacklistExpiry =
            ts.tv_sec + exec->config.legacy.blacklistTime + 1;

        // Initial timer expiry we let be for the max time. It'll get
        // rescheduled based on the earliest expiry time (if necessary).
        evloopTimeoutRegister(&exec->legacy.blacklistTimer,
                              exec->config.legacy.blacklistTime + 1, 0);
    }
}

/**
 * @brief Examine a single entry to see if its steering prohibition period
 *        has elapsed.
 *
 * @param [in] entry  the entry to examine
 * @param [in] cookie  the executor handle
 */
static void steerexecImplProhibitIterateCB(stadbEntry_handle_t entry,
                                             void *cookie) {
    if (!stadbEntry_isDualBand(entry) || !stadbEntry_isInNetwork(entry)) {
        return;
    }

    steerexecImplHandle_t exec = (steerexecImplHandle_t) cookie;
    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (state &&
        steerexecImplIsInSteeringQuietPeriod(exec, entry, state,
                                               LBD_TRUE /* notifyObservers */)) {
        // Determine if the next expiry time is sooner than the one currently
        // set. If so, update the time so that it is used when the timer is
        // next scheduled.
        time_t expiryTime = state->legacy.lastSteeringTime +
            steerexecImplGetSteeringProhibitTime(exec, state->steeringProhibited) + 1;
        if (expiryTime < exec->nextProhibitExpiry) {
            exec->nextProhibitExpiry = expiryTime;
        }
    }
}

/**
 * @brief Handle the periodic timer that signals we should check how many
 *        entries are still waiting for steering prohibition to complete.
 *
 * @param [in] cookie  the executor handle
 */
static void steerexecImplProhibitTimeoutHandler(void *cookie) {
    steerexecImplHandle_t exec = (steerexecImplHandle_t) cookie;

    struct timespec ts;
    lbGetTimestamp(&ts);

    // This is the worst case. The iteration will adjust this based on the
    // actual devices that are still under prohibition.
    exec->nextProhibitExpiry = ts.tv_sec + exec->config.legacy.steeringProhibitTime + 1;

    if (stadb_iterate(steerexecImplProhibitIterateCB, exec) != LBD_OK) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Failed to iterate over station database", __func__);

        // For now we are falling through to reschedule the timer.
    }

    if (exec->numSteeringProhibits != 0) {
        evloopTimeoutRegister(&exec->prohibitTimer,
                              exec->nextProhibitExpiry - ts.tv_sec, 0);
    }
}

/**
 * @brief Check if an exponential backoff timer has expired for
 *        a STA. If it has, decrement the number of entries
 *        pending expiry and return LBD_TRUE.  If not, check if
 *        this timer is the next to expire and update the next
 *        expiry if so, and return LBD_FALSE.
 *
 * @param [in] exec steering executor
 * @param [in] entry STA entry to check for expiry
 * @param [in] timer timer to check for expiry
 * @param [in] lastTime start time for timer for STA
 * @param [in] baseTime base expiry time for exponential backoff
 * @param [in] exponent exponent for exponential backoff
 * @param [in] maxBackoff  maximum value for exponential
 *                         backoff
 *
 * @return LBD_TRUE if this timer has expired, LBD_FALSE
 *         otherwise
 */
static LBD_BOOL steerexecImplTimerExpiryCheck(
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplTimerStruct_t *timer,
    time_t lastTime,
    u_int32_t baseTime,
    u_int32_t exponent,
    u_int32_t maxBackoff ) {

    struct timespec ts;
    lbGetTimestamp(&ts);

    u_int32_t backoffTime =
        steerexecImplGetExpBackoffTime(baseTime, exponent, maxBackoff);
    if (ts.tv_sec - lastTime > backoffTime) {
        timer->countEntries--;

        return LBD_TRUE;
    } else {
        time_t expiryTime = lastTime + backoffTime + 1;
        if (!timer->nextExpiry || (expiryTime < timer->nextExpiry)) {
            timer->nextExpiry = expiryTime;
        }

        return LBD_FALSE;
    }
}

/**
 * @brief Examine a single entry to see if its steering unfriendly period
 *        has elapsed.
 *
 * @param [in] entry  the entry to examine
 * @param [in] cookie  the executor handle
 */
static void steerexecImplUnfriendlyIterateCB(stadbEntry_handle_t entry,
                                             void *cookie) {
    if (!stadbEntry_isDualBand(entry) || !stadbEntry_isInNetwork(entry)) {
        return;
    }

    steerexecImplHandle_t exec = (steerexecImplHandle_t) cookie;
    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (state && state->legacy.steeringUnfriendly) {
        if (steerexecImplTimerExpiryCheck(exec, entry,
                                          &exec->legacy.steeringUnfriendly,
                                          state->legacy.lastSteeringTime,
                                          exec->config.legacy.steeringUnfriendlyTime,
                                          state->legacy.countConsecutiveFailure - 1,
                                          exec->config.legacy.maxSteeringUnfriendly)) {
            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(exec->dbgModule, addr);

            dbgf(exec->dbgModule, DBGINFO,
                 "%s: Cleared steering unfriendly flag for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(addr->ether_addr_octet));

            state->legacy.steeringUnfriendly = LBD_FALSE;

            steerexecImplDiagLogSteeringUnfriendly(addr, LBD_FALSE,
                                                   state->legacy.countConsecutiveFailure);

            steerexecImplNotifySteeringAllowedObservers(exec, entry);
        }
    }
}

/**
 * @brief Common function to start iterating through stadb
 *        entries, checking for timer expiry.
 *
 * @param [in] exec  steering executor
 * @param [in] timer  timer to check for expiry
 * @param [in] callback  callback function for iteration
 * @param [in] baseTime  basetime for timer expiry
 */
static void steerexecImplTimerStartIterate(steerexecImplHandle_t exec,
                                           steerexecImplTimerStruct_t *timer,
                                           stadb_iterFunc_t callback,
                                           u_int32_t baseTime) {
    struct timespec ts;
    lbGetTimestamp(&ts);

    timer->nextExpiry = 0;

    if (stadb_iterate(callback, exec) != LBD_OK) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Failed to iterate over station database", __func__);

        // For now we are falling through to reschedule the timer.
    }

    if (timer->countEntries != 0) {
        if (!timer->nextExpiry) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: There is at least 1 outstanding STA, but no nextExpiry", __func__);
            timer->nextExpiry = ts.tv_sec + baseTime + 1;
        }
        evloopTimeoutRegister(&timer->timer,
                              timer->nextExpiry - ts.tv_sec, 0);
    }
}

/**
 * @brief Handle the periodic timer that signals we should check how many
 *        entries are still waiting to have their steering unfriendly
 *        flag cleared.
 *
 * @param [in] cookie  the executor handle
 */
static void steerexecImplUnfriendlyTimeoutHandler(void *cookie) {
    steerexecImplHandle_t exec = (steerexecImplHandle_t) cookie;

    steerexecImplTimerStartIterate(exec, &exec->legacy.steeringUnfriendly,
                                   steerexecImplUnfriendlyIterateCB,
                                   exec->config.legacy.steeringUnfriendlyTime);
}

/**
 * @brief Examine a single entry to see if its BTM unfriendly
 *        period has elapsed.
 *
 * @param [in] entry  the entry to examine
 * @param [in] cookie  the executor handle
 */
static void steerexecImplBTMUnfriendlyIterateCB(stadbEntry_handle_t entry,
                                                void *cookie) {
    if (!stadbEntry_isDualBand(entry) || !stadbEntry_isInNetwork(entry)) {
        return;
    }

    steerexecImplHandle_t exec = (steerexecImplHandle_t) cookie;
    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (state && state->btm &&
        ((state->btm->btmUnfriendly))) {
        if (steerexecImplTimerExpiryCheck(exec, entry,
                                          &exec->btm.unfriendlyTimer,
                                          state->btm->lastSteeringTime,
                                          exec->config.btm.btmUnfriendlyTime,
                                          state->btm->countConsecutiveFailure - 1,
                                          exec->config.btm.maxBTMUnfriendly)) {

            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(exec->dbgModule, addr);

            dbgf(exec->dbgModule, DBGINFO,
                 "%s: Cleared BTM unfriendly flag for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(addr->ether_addr_octet));

            state->btm->btmUnfriendly = LBD_FALSE;

            steerexecImplDiagLogBTMCompliance(
                addr, state->btm->btmUnfriendly, state->btm->complianceState,
                state->btm->countConsecutiveFailure,
                state->btm->countConsecutiveFailureActive);

        }
    }
}

/**
 * @brief Examine a single entry to see if its BTM active
 *        unfriendly period has elapsed.
 *
 * @param [in] entry  the entry to examine
 * @param [in] cookie  the executor handle
 */
static void steerexecImplBTMActiveUnfriendlyIterateCB(stadbEntry_handle_t entry,
                                                      void *cookie) {
    if (!stadbEntry_isDualBand(entry) || !stadbEntry_isInNetwork(entry)) {
        return;
    }

    steerexecImplHandle_t exec = (steerexecImplHandle_t) cookie;
    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (state && state->btm &&
        (state->btm->complianceState == steerexecImpl_btmComplianceState_activeUnfriendly)) {
        if (steerexecImplTimerExpiryCheck(exec, entry,
                                          &exec->btm.activeUnfriendlyTimer,
                                          state->btm->lastActiveSteeringFailureTime,
                                          exec->config.btm.btmUnfriendlyTime,
                                          state->btm->countConsecutiveFailureActive - 1,
                                          exec->config.btm.maxBTMActiveUnfriendly)) {

            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(exec->dbgModule, addr);

            dbgf(exec->dbgModule, DBGINFO,
                 "%s: Cleared BTM active unfriendly flag for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(addr->ether_addr_octet));

            // Move to the next state
            state->btm->complianceState = steerexecImpl_btmComplianceState_idle;

            steerexecImplDiagLogBTMCompliance(
                addr, state->btm->btmUnfriendly,
                state->btm->complianceState,
                state->btm->countConsecutiveFailure,
                state->btm->countConsecutiveFailureActive);

        }
    }
}

/**
 * @brief Handle the periodic timer that signals we should check how many
 *        entries are still waiting to have their BTM unfriendly
 *        flag cleared.
 *
 * @param [in] cookie  the executor handle
 */
static void steerexecImplBTMUnfriendlyTimeoutHandler(void *cookie) {
    steerexecImplHandle_t exec = (steerexecImplHandle_t) cookie;

    steerexecImplTimerStartIterate(exec, &exec->btm.unfriendlyTimer,
                                   steerexecImplBTMUnfriendlyIterateCB,
                                   exec->config.btm.btmUnfriendlyTime);
}

/**
 * @brief Handle the periodic timer that signals we should check how many
 *        entries are still waiting to have their BTM unfriendly
 *        flag cleared.
 *
 * @param [in] cookie  the executor handle
 */
static void steerexecImplBTMActiveUnfriendlyTimeoutHandler(void *cookie) {
    steerexecImplHandle_t exec = (steerexecImplHandle_t) cookie;

    steerexecImplTimerStartIterate(exec, &exec->btm.activeUnfriendlyTimer,
                                   steerexecImplBTMActiveUnfriendlyIterateCB,
                                   exec->config.btm.btmUnfriendlyTime);
}

/**
 * @brief Handle timing out a set of blacklisted channels.  Will
 *        enable all channels that aren't overloaded, and update
 *        the disabledChannelCount and disabledChannelList.
 *
 * @param [in] exec  steering executor
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of the STA to manipulate
 *                      blacklist for
 *
 * @return LBD_OK if there were no errors; otherwise LBD_NOK
 */
static LBD_STATUS steerexecImplTimeoutBlacklistChannel(
    steerexecImplHandle_t exec,
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr) {
    // Check none of the channels are overloaded
    size_t channelsToChange = state->legacy.disabledChannelCount;
    int i;
    for (i = channelsToChange - 1; i >= 0 ; i--) {
        LBD_BOOL isOverloaded;
        if (bandmon_isChannelOverloaded(state->legacy.disabledChannelList[i],
                                        &isOverloaded) != LBD_OK) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Could not determine if channel %d is overloaded, "
                 "will remove entire blacklist for " lbMACAddFmt(":"),
                 __func__, state->legacy.disabledChannelList[i],
                 lbMACAddData(staAddr->ether_addr_octet));

            return LBD_NOK;
        }

        if (isOverloaded) {
            dbgf(exec->dbgModule, DBGDEBUG,
                 "%s: Will not remove blacklist for " lbMACAddFmt(":")
                 " on channel %d because it is overloaded",
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 state->legacy.disabledChannelList[i]);
            continue;
        }

        if (wlanif_setChannelStateForSTA(1,
                                         &state->legacy.disabledChannelList[i],
                                         staAddr,
                                         LBD_TRUE /* enable */) != LBD_OK) {
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: Failed to re-enable disabled channel %d, "
                 "will remove entire blacklist for " lbMACAddFmt(":"),
                 __func__, state->legacy.disabledChannelList[i],
                 lbMACAddData(staAddr->ether_addr_octet));
            return LBD_NOK;
        }

        dbgf(state->context->dbgModule, DBGDEBUG,
             "%s: Enable disabled channel %d for " lbMACAddFmt(":"),
             __func__, state->legacy.disabledChannelList[i],
             lbMACAddData(staAddr->ether_addr_octet));

        // Successfully disabled channel
        state->legacy.disabledChannelCount--;
        if (i != state->legacy.disabledChannelCount) {
            // Not the last element in the list, move other elements along
            memmove(&state->legacy.disabledChannelList[i],
                    &state->legacy.disabledChannelList[i+1],
                    (state->legacy.disabledChannelCount - i) *
                    sizeof(state->legacy.disabledChannelList[0]));
        }
    }

    return LBD_OK;
}

/**
 * @brief Handle timing out a set of blacklisted candidates.
 *
 *        Will enable all candidate that are not on overloaded
 *        channels, and update the candidateList and
 *        candidateCount.  Note that since candidateList and
 *        candidateCount reference the candidate BSSes that the
 *        STA is allowed to associate on, the number of
 *        candidates may increase in this function call.
 *        candidateCount will be reset to 0 and the blacklist
 *        removed if all blacklisted candidates can be enabled.
 *
 * @param [in] exec  steering executor
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of the STA to manipulate
 *                      blacklist for
 * @param [in] blacklistCount  count of candidates currently
 *                             blacklisted
 * @param [in] blacklist  list of candidates currently
 *                        blacklisted
 *
 * @return LBD_OK if there were no errors; otherwise LBD_NOK
 */
LBD_STATUS steerexecImplTimeoutBlacklistCandidate(
    steerexecImplHandle_t exec,
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr,
    u_int8_t blacklistCount,
    const lbd_bssInfo_t *blacklist) {
    size_t i;
    LBD_BOOL candidateStillBlacklisted = LBD_FALSE;
    for (i = 0; i < blacklistCount; i++) {
        LBD_BOOL isOverloaded;
        if (bandmon_isChannelOverloaded(blacklist[i].channelId,
                                        &isOverloaded) != LBD_OK) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Could not determine if channel %d is overloaded, "
                 "will remove entire blacklist for " lbMACAddFmt(":"),
                 __func__, state->legacy.disabledChannelList[i],
                 lbMACAddData(staAddr->ether_addr_octet));

            return LBD_NOK;
        }

        if (isOverloaded) {
            dbgf(exec->dbgModule, DBGDEBUG,
                 "%s: Will not remove blacklist on BSS " lbBSSInfoAddFmt()
                 " for " lbMACAddFmt(":") " because it is on an overloaded channel",
                 __func__, lbBSSInfoAddData(&blacklist[i]),
                 lbMACAddData(staAddr->ether_addr_octet));
            candidateStillBlacklisted = LBD_TRUE;
            continue;
        }

        // Channel is not overloaded, remove from blacklist
        if (wlanif_setCandidateStateForSTA(1,
                                           &blacklist[i],
                                           staAddr,
                                           LBD_TRUE /* enable */) != LBD_OK) {
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: Failed to remove blacklist on BSS " lbBSSInfoAddFmt()
                 " for " lbMACAddFmt(":") " will remove entire blacklist",
                 __func__, lbBSSInfoAddData(&blacklist[i]),
                 lbMACAddData(staAddr->ether_addr_octet));
            return LBD_NOK;
        }

        dbgf(state->context->dbgModule, DBGDEBUG,
             "%s: Removed blacklist on BSS " lbBSSInfoAddFmt() " for "
             lbMACAddFmt(":"),
             __func__, lbBSSInfoAddData(&blacklist[i]),
             lbMACAddData(staAddr->ether_addr_octet));

        // Successfully removed the blacklist
        // Add this BSS to the list that the STA can associate on
        // if there is still room.  If there isn't room, it means that all
        // candidates must have been enabled
        if (state->candidateCount == STEEREXEC_MAX_CANDIDATES) {
            // All channels enabled, mark as not blacklisted
            steerexecImplMarkAsNotBlacklisted(state);
            state->candidateCount = 0;
            return LBD_OK;
        } else {
            lbCopyBSSInfo(&blacklist[i],
                          &state->candidateList[state->candidateCount]);
            state->candidateCount++;
        }
    }

    if (!candidateStillBlacklisted) {
        // No candidates still blacklisted
        steerexecImplMarkAsNotBlacklisted(state);
        state->candidateCount = 0;
    }

    return LBD_OK;
}

/**
 * @brief Handle timing out either a candidate or channel based
 *        blacklist.  Will take appropriate action depending on
 *        the type of blacklist present.
 *
 * @param [in] exec  steering executor
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of the STA to manipulate
 *                      blacklist for
 *
 * @return LBD_OK if there were no errors; otherwise LBD_NOK
 */
static LBD_STATUS steerexecImplTimeoutBlacklist(
    steerexecImplHandle_t exec,
    steerexecImplSteeringState_t *state,
    const struct ether_addr *addr) {
    if (state->blacklistType == steerexecImplBlacklist_channel) {
        if (steerexecImplTimeoutBlacklistChannel(exec, state, addr) != LBD_OK) {
            return LBD_NOK;
        }

        if (!state->legacy.disabledChannelCount) {
            // All channels enabled, mark as not blacklisted
            steerexecImplMarkAsNotBlacklisted(state);
        }

        return LBD_OK;
    } else {
        // Candidate blacklist
        lbd_bssInfo_t candidateList[STEEREXEC_MAX_CANDIDATES];
        u_int8_t candidateCount;
        // Get the set of candidates not currently blacklisted
        candidateCount = wlanif_getNonCandidateStateForSTA(
            state->candidateCount,
            &state->candidateList[0],
            STEEREXEC_MAX_CANDIDATES,
            &candidateList[0]);
        if (!candidateCount) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Could not find any non-candidate VAPs, "
                 "will remove entire blacklist for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(addr->ether_addr_octet));

            return LBD_NOK;
        }

        if (candidateCount + state->candidateCount > WLANIF_MAX_RADIOS) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Total number of allowed candidates (%d) and "
                 "blacklisted candidates (%d) exceeds number of radios (%d), "
                 "will remove entire blacklist for " lbMACAddFmt(":"),
                 __func__, state->candidateCount, candidateCount,
                 WLANIF_MAX_RADIOS, lbMACAddData(addr->ether_addr_octet));

            return LBD_NOK;
        }

        return steerexecImplTimeoutBlacklistCandidate(exec, state, addr, candidateCount,
                                                      &candidateList[0]);
    }
}

/**
 * @brief Examine a single entry to see if its blacklist period
 *        has elapsed.
 *
 * @param [in] entry  the entry to examine
 * @param [in] cookie  the executor handle
 */
void steerexecImplBlacklistIterateCB(stadbEntry_handle_t entry,
                                     void *cookie) {

    steerexecImplHandle_t exec = (steerexecImplHandle_t) cookie;
    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (state && state->blacklistType != steerexecImplBlacklist_none) {
        struct timespec ts;
        lbGetTimestamp(&ts);

        if (ts.tv_sec - state->legacy.lastSteeringTime >
            exec->config.legacy.blacklistTime) {
            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(exec->dbgModule, addr);

            // Store for logging purposes.
            steerexecImplBlacklistType_e blacklistType = state->blacklistType;
            LBD_STATUS status = steerexecImplTimeoutBlacklist(exec, state, addr);
            if (status != LBD_OK) {
                // Selective blacklist didn't work, try disabling the
                // whole blacklist
                status = steerexecImplRemoveAllBlacklists(state, addr);
            }

            if ((LBD_OK == status) &&
                (state->blacklistType == steerexecImplBlacklist_none)) {
                dbgf(exec->dbgModule, DBGINFO,
                     "%s: Cleared blacklist of type %s for "lbMACAddFmt(":")" due to aging",
                     __func__, steerexecImpl_SteeringBlacklistTypeString[blacklistType],
                     lbMACAddData(addr->ether_addr_octet));
            }

            // If enable error, timer will be rescheduled and it will be retried
            // when timer expires next time.
        } else {
            time_t expiryTime = state->legacy.lastSteeringTime +
                exec->config.legacy.blacklistTime + 1;
            if (expiryTime < exec->legacy.nextBlacklistExpiry) {
                exec->legacy.nextBlacklistExpiry = expiryTime;
            }
        }
    }
}

/**
 * @brief Handle the periodic timer that signals we should check how many
 *        entries are still waiting to be removed from blacklist
 *
 * @param [in] cookie  the executor handle
 */
static void steerexecImplBlacklistTimeoutHandler(void *cookie) {
    steerexecImplHandle_t exec = (steerexecImplHandle_t) cookie;

    struct timespec ts;
    lbGetTimestamp(&ts);

    // This is the worst case. The iteration will adjust this based on the
    // actual devices that are still under prohibition.
    exec->legacy.nextBlacklistExpiry =
        ts.tv_sec + exec->config.legacy.blacklistTime + 1;

    if (stadb_iterate(steerexecImplBlacklistIterateCB, exec) != LBD_OK) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Failed to iterate over station database", __func__);

        // For now we are falling through to reschedule the timer.
    }

    if (exec->legacy.numBlacklist != 0) {
        evloopTimeoutRegister(&exec->legacy.blacklistTimer,
                              exec->legacy.nextBlacklistExpiry - ts.tv_sec, 0);
    }
}

/**
 * @brief Notify all registered oberservers that the provided entry can
 *        now be steered.
 *
 * @param [in] entry  the entry that was updated
 */
static void steerexecImplNotifySteeringAllowedObservers(
        steerexecImplHandle_t exec, stadbEntry_handle_t entry) {
    size_t i;
    for (i = 0; i < MAX_STEERING_ALLOWED_OBSERVERS; ++i) {
        struct steerexecImplSteeringAllowedObserver *curSlot =
            &exec->steeringAllowedObservers[i];
        if (curSlot->isValid) {
            curSlot->callback(entry, curSlot->cookie);
        }
    }
}

/**
 * @brief Determine if the state indicates the entry is eligible for steering
 *        or not.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the entry of the STA being examined
 * @param [in] state  the object to check for steering or not
 * @param [in] notifyObservers  LBD_TRUE if observers registered for the
 *                              steering prohibit callback should be notified
 *
 * @return LBD_TRUE if the entry is still not allowed to be steered (due to its
 *         last steering being too recently); LBD_FALSE if it is eligible to be
 *         steered
 */
static LBD_BOOL steerexecImplIsInSteeringQuietPeriod(
        steerexecImplHandle_t exec,
        stadbEntry_handle_t entry,
        steerexecImplSteeringState_t *state,
        LBD_BOOL notifyObservers) {
    if (state->steeringProhibited != steerexecImplSteeringProhibitType_none) {
        // Check if enough time has elapsed and if so, clear the flag.
        struct timespec ts;
        lbGetTimestamp(&ts);

        if (ts.tv_sec - state->legacy.lastSteeringTime >
            steerexecImplGetSteeringProhibitTime(exec, state->steeringProhibited)) {
            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(exec->dbgModule, addr);

            dbgf(exec->dbgModule, DBGINFO,
                 "%s: " lbMACAddFmt(":") " became eligible for steering",
                 __func__, lbMACAddData(addr->ether_addr_octet));

            state->steeringProhibited = steerexecImplSteeringProhibitType_none;
            exec->numSteeringProhibits--;

            if (notifyObservers && !state->legacy.steeringUnfriendly) {
                steerexecImplNotifySteeringAllowedObservers(exec, entry);
            }

            steerexecImplDiagLogSteeringProhibited(
                    addr, steerexecImplSteeringProhibitType_none);
        }
    }

    return (state->steeringProhibited != steerexecImplSteeringProhibitType_none);
}

/**
 * @brief Enable all channels that have been disabled as part of
 *        pre-association steering.  If attempting to enable the
 *        specific set of channels fails, it will attempt to
 *        enable all channels (to avoid the case where the
 *        channel may have changed while the steer is in
 *        progress).
 *
 * @param [in] state steering state for STA
 * @param [in] staAddr MAC address of STA to enable
 *
 * @return LBD_STATUS LBD_OK if the channels could be enabled,
 *                    LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplEnableAllDisabledChannels(
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr) {
    if (wlanif_setChannelStateForSTA(state->legacy.disabledChannelCount,
                                     &state->legacy.disabledChannelList[0],
                                     staAddr,
                                     LBD_TRUE /* enable */) != LBD_OK) {
        dbgf(state->context->dbgModule, DBGERR,
             "%s: Failed to re-enable disabled channel list for " lbMACAddFmt(":")
             ", will attempt to enable all channels",
             __func__, lbMACAddData(staAddr->ether_addr_octet));

        // This could be caused by a channel we had disabled having changed.
        // Try and enable on all channels.
        lbd_channelId_t newChannelList[WLANIF_MAX_RADIOS];
        u_int8_t newChannelCount = wlanif_getChannelList(&newChannelList[0],
                                                         WLANIF_MAX_RADIOS);
        if (wlanif_setChannelStateForSTA(newChannelCount,
                                         &newChannelList[0],
                                         staAddr,
                                         LBD_TRUE /* enable */) != LBD_OK) {
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: Failed to enable entire radio channel list for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(staAddr->ether_addr_octet));

            // Some sort of more serious error, but there's nothing we can do
            return LBD_NOK;
        }
    }

    // All channels should now be enabled
    state->legacy.disabledChannelCount = 0;

    return LBD_OK;
}


/**
 * @brief Enable all candidates that have been disabled as part
 *        of post-association steering.
 *
 * @param [in] state steering state for STA
 * @param [in] staAddr MAC address of STA to enable
 *
 * @return LBD_STATUS LBD_OK if the candidates could be enabled,
 *                    LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplEnableAllDisabledCandidates(
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr) {

    if (!steerexecImplIsBTMOnlySteer(state->steerType)) {
        if (wlanif_setNonCandidateStateForSTA(
            state->candidateCount,
            &state->candidateList[0],
            staAddr,
            LBD_TRUE /* enable */,
            LBD_FALSE /* probeOnly */) != LBD_OK) {
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: Failed to re-enable disabled candidate list for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(staAddr->ether_addr_octet));

            return LBD_NOK;
        }
    }

    // All candidates should now be enabled
    state->candidateCount = 0;

    return LBD_OK;
}

/**
 * @brief Enable all disabled candidates / channels, and remove
 *        blacklists (if installed).
 *
 * @param [in] state steering state for STA
 * @param [in] staAddr MAC address of STA to remove blacklists
 *                     for
 *
 * @return LBD_OK if successfully removed
 */
static LBD_STATUS steerexecImplRemoveAllBlacklists(
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr) {

    LBD_STATUS status;

    if (state->legacy.disabledChannelCount) {
        // Re-enable all disabled channels
        status = steerexecImplEnableAllDisabledChannels(state, staAddr);
    } else if (state->candidateCount) {
        // Re-enable all disabled candidates
        status = steerexecImplEnableAllDisabledCandidates(state, staAddr);
    } else {
        // No blacklist, return
        return LBD_OK;
    }

    if (status == LBD_OK) {
        steerexecImplMarkAsNotBlacklisted(state);
    }

    return status;
}

/**
 * @brief The core implementation of the package level
 *        steerexecImplAbortSteer() function.
 *
 * This allows the client to associate on the non-target band (where it was
 * previously disallowed).
 *
 * @pre exec, entry, and state are all valid
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the handle to the STA for which to abort
 * @param [in] state  the internal state used by the executor
 * @param [in] status reason for the abort
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
static LBD_STATUS steerexecImplAbortSteerImpl(
        steerexecImplHandle_t exec, stadbEntry_handle_t entry,
        steerexecImplSteeringState_t *state,
        steerexecImplSteeringStatusType_e status) {
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(state->context->dbgModule, staAddr);
    if (steerexecImplRemoveAllBlacklists(state,staAddr) != LBD_OK) {
        return LBD_NOK;
    }

    evloopTimeoutUnregister(&state->legacy.tSteerTimer);
    steerexecImplSteerEnd(state, staAddr, status);

    return LBD_OK;
}

/**
 * @brief Callback function invoked by the station database module when
 *        the RSSI for a specific STA went below the low RSSI threshold
 *
 * For a dual band STA, the blacklist installed on the other band will
 * be removed.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] cookie  the pointer to our internal state
 */
static void steerexecImplLowRSSIObserver(stadbEntry_handle_t entry, void *cookie) {
    const struct steerexecImplPriv_t *exec =
        (const struct steerexecImplPriv_t *) cookie;
    lbDbgAssertExit(NULL, exec);

    // We only care about entries that are dual band capable
    if (!stadbEntry_isDualBand(entry)) {
        return;
    }

    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // There must not be any steering operation in progress,
        // so no blacklist to remove.
        return;
    }

    stadbEntry_bssStatsHandle_t stats = stadbEntry_getServingBSS(entry, NULL);
    if (!stats) {
        // If not associated, nothing to do
        return;
    }

    wlanif_band_e band = stadbEntry_getAssociatedBand(entry, NULL);
    if (band == wlanif_band_invalid) {
        // Invalid band
        return;
    }

    // Be conservative here by double checking RSSI is below the low threshold
    u_int8_t rssi = stadbEntry_getUplinkRSSI(entry, stats, NULL, NULL);
    if (rssi != LBD_INVALID_RSSI &&
        rssi < exec->config.lowRSSIXingThreshold[band]) {
        const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
        lbDbgAssertExit(exec->dbgModule, staAddr);

        if (LBD_OK == steerexecImplRemoveAllBlacklists(state,
                                                       staAddr)) {
            dbgf(exec->dbgModule, DBGINFO,
                 "%s: Blacklist is cleared for "lbMACAddFmt(":")
                 " due to RSSI going below the low threshold (transaction %d).",
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 state->transaction);
        }
    }
}

/**
 * @brief Timeout handler for T-Steering timer
 *
 * It will abort current steering and mark the device as steering unfriendly
 *
 * @param [in] cookie  the steering state
 */
static void steerexecImplTSteeringTimeoutHandler(void *cookie) {
    stadbEntry_handle_t entry = (stadbEntry_handle_t) cookie;
    lbDbgAssertExit(NULL, entry);

    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    lbDbgAssertExit(NULL, state);

    if (steerexecImplIsBTMSteer(state->steerType) ||
        (state->steerType == steerexecImplSteeringType_none)) {
        // Take no action for BTM steering - separate timer used to evaluate.
        // If there is no steering in progress, also ignore.
        return;
    }

    steerexecImplAbortSteerImpl(state->context, entry, state,
                                steerexecImplSteeringStatusType_assoc_timeout);

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(state->context->dbgModule, staAddr);

    dbgf(state->context->dbgModule, DBGINFO,
         "%s: "lbMACAddFmt(":")" not associated within %u seconds; "
         "abort steering and mark the device as steering unfriendly (transaction %d).",
         __func__, lbMACAddData(staAddr->ether_addr_octet),
         state->context->config.legacy.tSteering,
         state->transaction);

    steerexecImplStartSteeringUnfriendly(state->context, state,
                                         staAddr);
}

/**
 * @brief Clear a blacklist (if one exists) and unregister the
 *        T_Steer timer (should be used for BTM clients only)
 *
 * @param state steering state
 * @param entry STA entry to clear blacklist for
 * @param staAddr STA address to clear blacklist for
 */
static void steerexecImplCleanupBlacklistBTM(steerexecImplSteeringState_t *state,
                                             stadbEntry_handle_t entry,
                                             const struct ether_addr *staAddr,
                                             steerexecImplSteeringStatusType_e status) {

    // Nothing to do for pure 802.11v based transitions
    if (steerexecImplIsBTMOnlySteer(state->steerType)) {
        // All candidates should now be enabled
        state->candidateCount = 0;

        steerexecImplSteerEnd(state, staAddr, status);
        return;
    }

    steerexecImplRemoveAllBlacklists(state, staAddr);

    // Clear the T_Steer timer
    evloopTimeoutUnregister(&state->legacy.tSteerTimer);

    steerexecImplSteerEnd(state, staAddr, status);
}

/**
 * @brief Timeout handler for BSS Transition Management timeouts
 *
 * Increments counters indicating cause of failure, and resets
 * BTM state.
 *
 * TBD: Add logic evaluating if this device is not BTM friendly
 *
 * @param cookie the steering state
 */
static void steerexecImplBTMTimeoutHandler(void *cookie) {
    stadbEntry_handle_t entry = (stadbEntry_handle_t) cookie;
    lbDbgAssertExit(NULL, entry);

    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    lbDbgAssertExit(NULL, state);

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(state->context->dbgModule, staAddr);

    // Get the current BTM state
    switch (state->btm->state) {
        case steerexecImpl_btmState_aborted:
            // The transition was already aborted, so ignore this timeout,
            // and reset back to the idle state
            state->btm->state = steerexecImpl_btmState_idle;
            break;
        case steerexecImpl_btmState_idle:
            dbgf(state->context->dbgModule, DBGINFO,
             "%s: "lbMACAddFmt(":")" timeout during BTM transition, but no BTM transition in progress",
             __func__, lbMACAddData(staAddr->ether_addr_octet));
            break;
        case steerexecImpl_btmState_waiting_response:
            steerexecImplSteerEndBTMFailure(
                entry, state, staAddr,
                steerexecImplSteeringStatusType_btm_response_timeout);
            break;
        case steerexecImpl_btmState_waiting_association:
            steerexecImplSteerEndBTMFailure(
                entry, state, staAddr,
                steerexecImplSteeringStatusType_assoc_timeout);
            break;
        default:
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: "lbMACAddFmt(":")" received timeout during BTM transition, but invalid BTM state %d",
                 __func__, lbMACAddData(staAddr->ether_addr_octet), state->btm->state);
            break;
    }
}

/**
 * @brief React to an authentication rejection that was sent, aborting
 *        steering if necessary.
 *
 * Also start the T-Steering timer if the STA has a steering in progress
 * and the timer has not started.
 *
 * If this is a BTM client, mark as steering prohibited now
 * (since this message indicates the client is attempting to
 * associate somewhere it wasn't steered to).
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the entry for which an auth reject was sent
 * @param [in] state  the internal state used by the executor
 *
 * @return LBD_TRUE if the steering was aborted; otherwise LBD_FALSE
 */
static LBD_BOOL steerexecImplHandleAuthRej(
        struct steerexecImplPriv_t *exec, stadbEntry_handle_t entry,
        steerexecImplSteeringState_t *state) {

    // If this is a BTM compliant station, and not marked as steering prohibited,
    // mark it now.  If the STA attempts to associate on a
    // blacklisted band, we will delay our next attempt to steer in case it
    // has temporarily blacklisted us.
    if (stadbEntry_isBTMSupported(entry)) {
        if (state->steeringProhibited != steerexecImplSteeringProhibitType_long) {
            const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(exec->dbgModule, staAddr);
            steerexecImplStartSteeringProhibit(exec, state, staAddr,
                                               steerexecImplSteeringProhibitType_long);
        }
    }

    // If TSteering timer is not running, start it
    unsigned secsRemaining, usecsRemaining;
    if(evloopTimeoutRemaining(&state->legacy.tSteerTimer, &secsRemaining,
                              &usecsRemaining)) {
        evloopTimeoutRegister(&state->legacy.tSteerTimer, exec->config.legacy.tSteering,
                              0 /* USec */);
        state->legacy.numAuthRejects = 1;
        return LBD_FALSE;
    } else {
        // Update the authentication reject count, but only if enough time
        // has elapsed from the first one.
        if (exec->config.legacy.tSteering - secsRemaining >
                exec->config.legacy.initialAuthRejCoalesceTime) {
            state->legacy.numAuthRejects++;
        }

        // If there have been too many auth rejects, abort the steering.
        if (state->legacy.numAuthRejects == exec->config.legacy.authRejMax) {
            const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(exec->dbgModule, staAddr);

            steerexecImplAbortSteerImpl(exec, entry, state,
                                        steerexecImplSteeringStatusType_abort_auth_reject);

            dbgf(exec->dbgModule, DBGINFO,
                 "%s: Aborting steer for " lbMACAddFmt(":")
                 " due to repeated auth rejects (transaction %d)",
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 state->transaction);

            steerexecImplStartSteeringUnfriendly(state->context, state,
                                                 staAddr);

            return LBD_TRUE;
        }

        // Have not hit the limit yet.
        return LBD_FALSE;
    }
}

/**
 * @brief Check if a channel has an RSSI below the low threshold
 *        for a STA
 *
 * @param [in] ts  current time
 * @param [in] exec  steering executor
 * @param [in] state  steering state for STA
 * @param [in] entry  staDB entry for STA
 * @param [in] stats  BSS stats handle to check RSSI for
 * @param [in] channel  channel to check RSSI for
 *
 * @return LBD_FALSE if the RSSI is too low; otherwise LBD_TRUE
 */
static LBD_BOOL steerexecImplIsTargetChannelRSSIOK(
    const struct timespec *ts,
    struct steerexecImplPriv_t *exec,
    steerexecImplSteeringState_t *state,
    stadbEntry_handle_t entry,
    stadbEntry_bssStatsHandle_t stats,
    lbd_channelId_t channel) {

    wlanif_band_e targetBand =
        wlanif_resolveBandFromChannelNumber(channel);
    lbDbgAssertExit(exec->dbgModule, targetBand != wlanif_band_invalid);

    time_t rssiAgeSecs = 0xFF;
    lbd_rssi_t rssi = stadbEntry_getUplinkRSSI(entry, stats,
                                               &rssiAgeSecs, NULL);

    // Note RSSI value is only checked if it is valid and has been updated
    // since the steer began.  This function is basically checking if conditions
    // have changed since the decision was made to begin steering.
    if (rssi == LBD_INVALID_RSSI ||
        rssiAgeSecs > (ts->tv_sec - state->legacy.lastSteeringTime) ||
        rssi >= exec->config.targetLowRSSIThreshold[targetBand]) {
        // Target RSSI is OK, or has not changed since the steer began
        return LBD_TRUE;
    }

    // Target RSSI is too low
    dbgf(exec->dbgModule, DBGDEBUG,
         "%s: RSSI (%u) on candidate channel %u is below threshold (%u)",
         __func__, rssi, channel, exec->config.targetLowRSSIThreshold[targetBand]);
    return LBD_FALSE;
}

/**
 * @brief Check if all candidate BSSes have a RSSI below the low
 *        threshold for a STA (post-association steering)
 *
 * @param [in] exec  steering executor
 * @param [in] state  steering state for STA
 * @param [in] entry  staDB entry for STA
 *
 * @return LBD_FALSE if all candidates have an RSSI below the
 *         low threshold; LBD_TRUE otherwise
 */
static LBD_BOOL steerexecImplIsTargetRSSIOKCandidate(
    struct steerexecImplPriv_t *exec,
    steerexecImplSteeringState_t *state,
    stadbEntry_handle_t entry) {

    struct timespec ts;
    lbGetTimestamp(&ts);

    size_t i;

    for (i = 0; i < state->candidateCount; i++) {
        stadbEntry_bssStatsHandle_t stats =
            stadbEntry_findMatchBSSStats(entry,
                                         &state->candidateList[i]);
        if (!stats) {
            // No stats for this target BSS
            continue;
        }

        if (steerexecImplIsTargetChannelRSSIOK(&ts, exec, state, entry, stats,
                                               state->candidateList[i].channelId)) {
            return LBD_TRUE;
        }
    }

    // No candidate has an OK target RSSI
    return LBD_FALSE;
}

/**
 * @brief Callback function used to check if a BSS has a RSSI
 *        below the low threshold for a STA (used for
 *        pre-association steering)
 *
 * @param [in] entry  staDB entry for STA
 * @param [in] bssHandle  BSS stats handle
 * @param [inout] cookie  contains
 *                        steerexecImplCheckChannelRSSI_t
 *                        pointer
 *
 * @return LBD_FALSE if the RSSI is below the low threshold;
 *         LBD_TRUE otherwise
 */
static LBD_BOOL steerexecImplIsTargetRSSIOKChannelCallback(
    stadbEntry_handle_t entry, stadbEntry_bssStatsHandle_t bssHandle,
    void *cookie) {
    steerexecImplCheckChannelRSSI_t *params =
        (steerexecImplCheckChannelRSSI_t *) cookie;

    const lbd_bssInfo_t *bssInfo = stadbEntry_resolveBSSInfo(bssHandle);
    lbDbgAssertExit(params->exec->dbgModule, bssInfo); // should never happen in practice

    // Is this BSS on one of the enabled channels?
    if (!steerexecImplIsOnChannelList(params->enabledChannelCount,
                                      params->enabledChannelList,
                                      bssInfo->channelId)) {
        return LBD_FALSE;
    }

    // Is the RSSI for this BSS OK?
    if (steerexecImplIsTargetChannelRSSIOK(&params->ts, params->exec, params->state,
                                           entry, bssHandle,
                                           bssInfo->channelId)) {
        params->isChannelRSSIOK = LBD_TRUE;
        return LBD_TRUE;
    }

    // RSSI is insufficient
    return LBD_FALSE;
}

/**
 * @brief Check if all enabled channels have a RSSI below the
 *        low threshold for a STA (pre-association steering)
 *
 * @param [in] exec  steering executor
 * @param [in] state  steering state for STA
 * @param [in] entry  staDB entry for STA
 *
 * @return LBD_FALSE if all channels have a RSSI below the low
 *         threshold; LBD_TRUE otherwise
 */
static LBD_BOOL steerexecImplIsTargetRSSIOKChannel(
    struct steerexecImplPriv_t *exec,
    steerexecImplSteeringState_t *state,
    stadbEntry_handle_t entry) {

    u_int8_t wlanifChannelCount;
    lbd_channelId_t wlanifChannelList[WLANIF_MAX_RADIOS];

    // Get the set of channels from the radio
    if (steerexecImplGetAndValidateRadioChannelList(state, &wlanifChannelCount,
                                                    &wlanifChannelList[0]) != LBD_OK) {
        return LBD_FALSE;
    }

    // Get the set of enabled channels
    steerexecImplCheckChannelRSSI_t params;
    lbGetTimestamp(&params.ts);
    params.exec = exec;
    params.state = state;
    params.isChannelRSSIOK = LBD_FALSE;
    params.enabledChannelCount = steerexecImplCopyAllNotOnList(
        wlanifChannelCount,
        &wlanifChannelList[0],
        state->legacy.disabledChannelCount,
        &state->legacy.disabledChannelList[0],
        &params.enabledChannelList[0]);

    // Determine if there are any BSSes that have an adequate RSSI
    if (stadbEntry_iterateBSSStats(entry,
                                   steerexecImplIsTargetRSSIOKChannelCallback,
                                   &params, NULL, NULL) != LBD_OK) {
        const struct ether_addr *addr = stadbEntry_getAddr(entry);
        dbgf(exec->dbgModule, DBGERR,
             "%s: Failed to iterate over BSS stats for " lbMACAddFmt(":"),
             __func__, lbMACAddData(addr->ether_addr_octet));

        return LBD_FALSE;
    }

    return params.isChannelRSSIOK;
}

/**
 * @brief Callback function invoked by the station database module when
 *        the RSSI for a specific STA got updates
 *
 * If a STA is in steering progress and the target band RSSI goes below
 * the threshold, the steering will be cancelled.
 *
 * In addition, the T_Steering timer will be started on the first auth
 * reject.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] reason  the reason the RSSI value was updated
 * @param [in] cookie  the pointer to our internal state
 */
static void steerexecImplRSSIObserver(stadbEntry_handle_t entry,
                                        stadb_rssiUpdateReason_e reason,
                                        void *cookie) {
    struct steerexecImplPriv_t *exec =
        (struct steerexecImplPriv_t *) cookie;
    lbDbgAssertExit(NULL, exec);
    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        return;
    }
    // Ignore entry that is not currently blacklisted, or being steered via 802.11v without
    // also requiring a blacklist to be installed.
    if (steerexecImplIsBTMOnlySteer(state->steerType) ||
        ((state->steerType == steerexecImplSteeringType_none) &&
         (state->blacklistType == steerexecImplBlacklist_none))) {
        return;
    }

    // If the auth reject handling indicates the abort already happened, we
    // do not even need to examine the RSSI.
    if (reason == stadb_rssiUpdateReason_authrej &&
        steerexecImplHandleAuthRej(exec, entry, state)) {
        return;
    }

    // If steering is still in progress, we need to check the RSSI to make
    // sure the target is not too low.  As long as at least one candidate
    // has an OK RSSI, we will continue steering.
    LBD_BOOL rssiSafe = LBD_FALSE;
    if (state->steerType == steerexecImplSteeringType_none) {
        return;
    } else if (state->steerType == steerexecImplSteeringType_preassociation) {
        rssiSafe = steerexecImplIsTargetRSSIOKChannel(exec, state, entry);
    } else {
        rssiSafe = steerexecImplIsTargetRSSIOKCandidate(exec, state, entry);
    }

    if (!rssiSafe) {
        const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
        lbDbgAssertExit(exec->dbgModule, staAddr);

        dbgf(exec->dbgModule, DBGINFO,
             "%s: Aborting steer for " lbMACAddFmt(":")
             " due to RSSI being too low for all candidate channels (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);

        steerexecImplAbortSteerImpl(exec, entry, state,
                                    steerexecImplSteeringStatusType_abort_low_rssi);
    }
}

/**
 * @brief Check if a candidate list matches the currently active
 *        steer
 *
 * @param [in] state steering state for the STA
 * @param [in] candidateCount number of candidates
 * @param [in] candidateList list of candidates
 *
 * @return LBD_TRUE if steer is to the same target BSS set
 */
LBD_BOOL steerexecImplIsSameTarget(steerexecImplSteeringState_t *state,
                                   u_int8_t candidateCount,
                                   const lbd_bssInfo_t *candidateList) {
    if ((state->candidateCount == candidateCount) &&
        (memcmp(&state->candidateList, candidateList,
                sizeof(lbd_bssInfo_t) * candidateCount) == 0)) {
        return LBD_TRUE;
    } else {
        return LBD_FALSE;
    }
}

/**
 * @brief Determine the change in blacklist due to a new
 *        candidate based steer
 *
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of STA
 * @param [in] candidateCount  number of candidates for steer
 * @param [in] candidateList  list of candidates for steer
 * @param [out] enableCount  count of candidate BSSes to enable
 * @param [out] enableList  list of candidate BSSes to enable
 * @param [out] disableCount  count of candidate BSSes to
 *                            disable
 * @param [out] disableList  list of candidate BSSes to disable
 *
 */
static void steerexecImplUpdateCandidateBlacklist(
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    u_int8_t *enableCount,
    lbd_bssInfo_t *enableList,
    u_int8_t *disableCount,
    lbd_bssInfo_t *disableList) {

    // Get the set of candidates to enable - any candidate on the new candidate list
    // that is not on the old candidate list.
    size_t i, j;
    *enableCount = 0;
    *disableCount = 0;
    for (i = 0; i < candidateCount; i++) {
        LBD_BOOL match = LBD_FALSE;
        for (j = 0; j < state->candidateCount; j++) {
            if (lbAreBSSesSame(&candidateList[i], &state->candidateList[j])) {
                match = LBD_TRUE;
                break;
            }
        }

        if (!match) {
            lbCopyBSSInfo(&candidateList[i], &enableList[*enableCount]);
            (*enableCount)++;
        }
    }

    // Get the set of channels to disable - any channel on the old candidate list
    // that is not on the new candidate list.
    for (i = 0; i < state->candidateCount; i++) {
        LBD_BOOL match = LBD_FALSE;
        for (j = 0; j < candidateCount; j++) {
            if (lbAreBSSesSame(&candidateList[j], &state->candidateList[i])) {
                match = LBD_TRUE;
                break;
            }
        }

        if (!match) {
            lbCopyBSSInfo(&state->candidateList[i], &disableList[*disableCount]);
            (*disableCount)++;
        }
    }
}

/**
 * @brief Set the lastSteeringTime (and the BTM last steering 
 *        time if needed) to the current time
 * 
 * @param [in] state  steering state
 */
static void steerexecImplSetLastSteeringTime(
    steerexecImplSteeringState_t *state) {
    struct timespec ts;
    lbGetTimestamp(&ts);

    state->legacy.lastSteeringTime = ts.tv_sec;

    if (steerexecImplIsBTMSteer(state->steerType)) {
        state->btm->lastSteeringTime = ts.tv_sec;
    }
}

/**
 * @brief Perform common pre-steering preparation (regardless of
 *        steering mechanism) and install blacklist if required
 *        (legacy clients and BTM clients when BTMAlsoBlacklist
 *        config parameter is set)
 *
 * @param [in] state the internal state used by the executor for
 *                   the entry
 * @param [in] exec steering executor
 * @param [in] entry staDB entry to prepare for steering
 * @param [in] candidateCount number of candidates for steer
 * @param [in] candidateList list of candidates for steer
 * @param [out] ignored set to LBD_TRUE if this request is
 *                      ignored
 * @param [in] bss BSS the STA is currently associated to
 * @param [out] okToSteer set to LBD_TRUE if preparation was
 *                        successful and STA can be steered to
 *                        targetBand
 *
 * @return LBD_STATUS LBD_OK on success, LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplPrepareAndSetBlacklist(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    LBD_BOOL *ignored,
    stadbEntry_bssStatsHandle_t stats,
    const lbd_bssInfo_t *bss,
    LBD_BOOL *okToSteer) {

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    *okToSteer = LBD_FALSE;
    if (ignored) {
        *ignored = LBD_TRUE;
    }

    // Determine what sort of steering to use
    steerexecImplSteeringType_e steerType =
        steerexecImplDetermineSteeringType(state, exec, entry, staAddr,
                                           stats,
                                           LBD_FALSE /* eligibilityOnly */,
                                           LBD_TRUE /* reportReasonNotEligible */);

    // Should only be here for post-association steering
    if ((steerType == steerexecImplSteeringType_none) ||
        (steerType == steerexecImplSteeringType_preassociation)) {
        return LBD_OK;
    }

    // Make sure we're not getting steering to the currently associated BSS
    if (steerexecImplIsOnCandidateList(state, candidateCount, candidateList, bss)) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Requested steer for " lbMACAddFmt(":")
             " to currently associated BSS " lbBSSInfoAddFmt() ", will not steer",
             __func__,
             lbMACAddData(staAddr->ether_addr_octet),
             lbBSSInfoAddData(bss));
        return LBD_NOK;
    }

    // Update the blacklist state / set of disabled VAPs based on the new
    // steer request.
    if (steerexecImplReconcileSteerCandidate(
        state, exec, entry, staAddr, steerType,
        candidateCount, candidateList, okToSteer) != LBD_OK) {
        return LBD_NOK;
    }

    if (!(*okToSteer)) {
        return LBD_OK;
    }

    state->steerType = steerType;

    // Set prohibit timer to an appropriate duration based on the steer type
    // (shorter prohibition for BTM STAs).
    if (steerType == steerexecImplSteeringType_legacy) {
        // Mark this entry as not allowing steering for the configured time.
        steerexecImplStartSteeringProhibit(exec, state, staAddr,
                                           steerexecImplSteeringProhibitType_long);
    } else {
       
        steerexecImplStartSteeringProhibit(exec, state, staAddr,
                                           steerexecImplSteeringProhibitType_short);

        // Store the current association
        lbCopyBSSInfo(bss, &state->btm->initialAssoc);
    }

    // Blacklisting process was OK, can continue on to steer the STA now
    if (ignored) {
        *ignored = LBD_FALSE;
    }
    *okToSteer = LBD_TRUE;

    return LBD_OK;
}

/**
 * @brief Perform steering via BSS Transition Management request
 *        frame
 *
 * @param [in] state the internal state used by the executor for
 *                   the entry
 * @param [in] exec steering executor
 * @param [in] entry staDB entry to steer
 * @param [in] candidateCount number of candidates for steer
 * @param [in] candidateList list of candidates for steer
 * @param [in] staAddr MAC address of STA to steer
 * @param [in] assocBSS BSS STA is currently associated on
 *
 * @return LBD_STATUS LBD_OK if steering was started
 *         successfully, LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplSteerBTM(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS) {

    if (wlanif_sendBTMRequest(assocBSS,
                              staAddr,
                              exec->btm.dialogToken,
                              candidateCount,
                              candidateList) != LBD_OK) {
        // Failed to send BTM request
        dbgf(exec->dbgModule, DBGERR,
             "%s: Can't steer for " lbMACAddFmt(":")
             " sendBTMRequest failed (transaction %d)",
             __func__,
             lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);
        return LBD_NOK;
    }

    // Increment dialogToken for the next BTM to send, and store current dialogToken
    // with the STA record
    state->btm->dialogToken = exec->btm.dialogToken;
    exec->btm.dialogToken++;

    // Steering is now in progress to the target band, waiting for a BTM response
    state->btm->state = steerexecImpl_btmState_waiting_response;

    // Start timer for BTM response timeout
    evloopTimeoutRegister(&state->btm->timer, exec->config.btm.responseTime,
                          0 /* USec */);

    return LBD_OK;
}

/**
 * @brief Perform steering via disassociation
 *
 * @param [in] state the internal state used by the executor for
 *                   the entry
 * @param [in] exec steering executor
 * @param [in] entry staDB entry to steer
 * @param [in] candidateCount number of candidates for steer
 * @param [in] candidateList list of candidates for steer
 * @param [in] staAddr MAC address of STA to steer
 * @param [in] assocBSS BSS STA is currently associated on
 *
 * @return LBD_STATUS LBD_OK if steering was started
 *         successfully, LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplSteerLegacy(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS) {

    // If the device is currently associated on the other band (the one being
    // disallowed), kick it out. If it is already associated on the target
    // band, we do not disassociate as this may be an attempt to lock the
    // client to the band.
    if (wlanif_disassociateSTA(assocBSS, staAddr) != LBD_OK) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Failed to force " lbMACAddFmt(":") " to disassociate "
             "on BSS " lbBSSInfoAddFmt() " (transaction %d)", __func__,
             lbMACAddData(staAddr->ether_addr_octet),
             lbBSSInfoAddData(assocBSS), state->transaction);

        // Should we remove the blacklist we installed above? For now,
        // we do not as the hope is if the client does disassociate, it
        // should go to the target band as desired.
        return LBD_NOK;
    }

    return LBD_OK;
}

/**
 * @brief Abort a steering attempt for a STA being steered via
 *        BTM.  Note this is currently a NOP since a BTM
 *        transition can not be cancelled.
 *
 * @param [in] exec steering executor
 * @param [in] state  steering state
 * @param [in] entry staDB entry to steer
 * @param [in] addr  MAC address of STA
 *
 * @return LBD_STATUS always returns LBD_OK
 */
static LBD_STATUS steerexecImplAbortBTM(steerexecImplHandle_t exec,
                                        steerexecImplSteeringState_t *state,
                                        stadbEntry_handle_t entry,
                                        const struct ether_addr *addr) {
    // Can't cancel an 802.11v BTM request.  No need to return an error, just log
    // that nothing was done.
    dbgf(exec->dbgModule, DBGDEBUG,
         "%s: Steer request to " lbMACAddFmt(":")
         " aborted, but it was steered via BTM, so transition may continue (transaction %d)",
         __func__, lbMACAddData(addr->ether_addr_octet),
         state->transaction);

    return LBD_OK;
}

/**
 * @brief Abort a steering attempt for a STA being steered via
 *        legacy mechanics
 *
 * @param [in] exec steering executor
 * @param [in] state steering state for STA
 * @param [in] entry staDB entry to steer
 * @param [in] status  abort reason
 * @param [in] addr  MAC address of STA
 *
 * @return LBD_STATUS LDB_OK if aborted successfully, LBD_NOK
 *                    otherwise
 */
static LBD_STATUS steerexecImplAbortLegacy(steerexecImplHandle_t exec,
                                           steerexecImplSteeringState_t *state,
                                           stadbEntry_handle_t entry,
                                           steerexecImplSteeringStatusType_e status,
                                           const struct ether_addr *addr) {
    dbgf(exec->dbgModule, DBGINFO,
         "%s: Aborting steer request for " lbMACAddFmt(":")
         " due to %s (transaction %d)",
         __func__, lbMACAddData(addr->ether_addr_octet),
         status == steerexecImplSteeringStatusType_channel_change ?
             "channel change" : "user abort",
         state->transaction);

    return steerexecImplAbortSteerImpl(exec, entry, state, status);
}

/**
 * @brief Check if a BSS is on a candidate list
 *
 * @param [in] state steering state
 * @param [in] candidateCount number of candidates for steer
 * @param [in] candidateList list of candidates for steer
 * @param [in] bss BSS to check for
 *
 * @return LBD_TRUE if found, LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplIsOnCandidateList(steerexecImplSteeringState_t *state,
                                               u_int8_t candidateCount,
                                               const lbd_bssInfo_t *candidateList,
                                               const lbd_bssInfo_t *bss) {
    size_t i;

    for (i = 0; i < candidateCount; i++) {
        if (lbAreBSSesSame(bss, &candidateList[i])) {
            return LBD_TRUE;
        }
    }

    // Not found in list
    return LBD_FALSE;
}

/**
 * @brief Check if a channel is on a channel list
 *
 * @param [in] channelCount  count of channels to check
 * @param [in] channelList  list of channels to check
 * @param [in] channel  channel to search for
 *
 * @return LBD_TRUE if channel is found; LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplIsOnChannelList(u_int8_t channelCount,
                                             const lbd_channelId_t *channelList,
                                             lbd_channelId_t channel) {
    size_t i;
    for (i = 0; i < channelCount; i++) {
        if (channelList[i] == channel) {
            return LBD_TRUE;
        }
    }

    return LBD_FALSE;
}

/**
 * @brief Received an association update message for a STA which
 *        is being steered via BTM
 *
 * @param [in] exec steering executor
 * @param [in] entry staDB entry for the STA whose association
 *                   status is updated
 * @param [in] state steering state for STA
 * @param [in] assocBSS BSS STA is associated on
 * @param [in] staAddr MAC address of STA
 *
 * @return LBD_BOOL LBD_TRUE if steering is completed
 *                  successfully, LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplHandleAssocUpdateBTM(
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS,
    const struct ether_addr *staAddr) {

    // Were we expecting a new association?
    if ((state->btm->state == steerexecImpl_btmState_idle) ||
        (state->btm->state == steerexecImpl_btmState_invalid)) {
        // This is not an error - association doesn't have to be due to BTM request
        return LBD_FALSE;
    } else if (state->btm->state == steerexecImpl_btmState_waiting_response) {
        // It's possible we didn't receive the BTM response for some reason, so continue, just print a warning
        dbgf(exec->dbgModule, DBGDEBUG,
             "%s: Received association update from " lbMACAddFmt(":")
             ", but no BTM response received yet (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);
    }

    // STA has associated somewhere valid - was it where we expected?
    if (steerexecImplIsOnCandidateList(state, state->candidateCount,
                                       &state->candidateList[0], assocBSS)) {
        // Success case
        dbgf(exec->dbgModule, DBGINFO,
             "%s: BTM steering " lbMACAddFmt(":") " is complete (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);

        // Unregister the timeout
        evloopTimeoutUnregister(&state->btm->timer);
        state->btm->countSuccess++;

        // Disassociate on the old interface as long as there is a blacklist in place
        if (!steerexecImplIsBTMOnlySteer(state->steerType)) {
            if (wlanif_disassociateSTA(&state->btm->initialAssoc,
                                       staAddr) != LBD_OK) {
                dbgf(exec->dbgModule, DBGDEBUG,
                     "%s: " lbMACAddFmt(":") " no longer associated on original "
                     "BSS " lbBSSInfoAddFmt() ", not disassociated at steer end "
                     "(transaction %d)",
                     __func__, lbMACAddData(staAddr->ether_addr_octet),
                     lbBSSInfoAddData(&state->btm->initialAssoc),
                     state->transaction);
            }
        }

        steerexecImplUpdateBTMCompliance(entry, state, staAddr,
                                         LBD_TRUE /* success */);
        return LBD_TRUE;
    } else {
        dbgf(exec->dbgModule, DBGINFO,
             "%s: Requested BTM steering " lbMACAddFmt(":")
             " but associated on an unexpected BSS " lbBSSInfoAddFmt()
             " (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             lbBSSInfoAddData(assocBSS),
             state->transaction);

        // Don't cancel the timeout or change the state, just keep waiting

        return LBD_FALSE;
    }
}

/**
 * @brief Received an association update message for a STA which
 *        is being steered via legacy mechanics
 *
 * @param [in] exec steering executor
 * @param [in] entry staDB entry for the STA whose association
 *                   status is updated
 * @param [in] state steering state for STA
 * @param [in] assocBSS BSS STA is associated on
 * @param [in] staAddr MAC address of STA
 *
 * @return LBD_BOOL LBD_TRUE if steering is completed
 *                  successfully, LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplHandleAssocUpdateLegacy(
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS,
    const struct ether_addr *staAddr) {

    // STA has associated somewhere valid - was it where we expected?
    if (steerexecImplIsOnCandidateList(state, state->candidateCount,
                                       &state->candidateList[0], assocBSS)) {
        // Steering completed.
        state->legacy.countConsecutiveFailure = 0;
        const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
        lbDbgAssertExit(exec->dbgModule, staAddr);

        dbgf(exec->dbgModule, DBGINFO,
             "%s: Steering " lbMACAddFmt(":") " is complete (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);

        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Received an association event for a STA which is being
 *        pre-association steered
 *
 * @param [in] exec steering executor
 * @param [in] entry staDB entry for the STA whose association
 *                   status is updated
 * @param [in] state steering state for STA
 * @param [in] assocBSS BSS STA is associated on
 *
 */
static void steerexecImplHandleAssocPreAssoc(
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS) {

    // Check there was a valid association
    wlanif_band_e assocBand = wlanif_resolveBandFromChannelNumber(assocBSS->channelId);
    if (assocBand == wlanif_band_invalid) {
        // Not associated, nothing to do
        return;
    }

    // If we had started T_Steering due to an auth reject and now the
    // STA has associated, we want to stop the timer.
    evloopTimeoutUnregister(&state->legacy.tSteerTimer);

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    // Special case for 5 GHz. We need to clear the blacklist immediately
    // as we want to make sure the client can associate to 2.4 GHz if
    // it wanders out of 5 GHz range (and we cannot react fast enough).
    if (assocBand == wlanif_band_5g) {
        if (steerexecImplEnableAllDisabledChannels(state, staAddr) != LBD_OK) {
            return;
        }

        state->legacy.disabledChannelCount = 0;
    } else {
        // Record this entry as blacklisted on the disabled channel set,
        // and keep it for the configured time
        steerexecImplMarkBlacklist(exec, state, steerexecImplBlacklist_channel);
    }

    steerexecImplSteerEnd(state, staAddr,
                          steerexecImplSteeringStatusType_success);
}

/**
 * @brief Clear blacklists / probe withholding for a STA steered
 *        via legacy mechanics
 *
 * @param [in] exec steering executor
 * @param [in] entry staDB entry for the STA whose association
 *                   status is updated
 * @param [in] state steering state for STA
 * @param [in] assocBSS BSS STA is associated on
 *  */
static void steerexecImplAssocBlacklistClear(steerexecImplHandle_t exec,
                                             stadbEntry_handle_t entry,
                                             steerexecImplSteeringState_t *state,
                                             const lbd_bssInfo_t *assocBSS) {

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    if (steerexecImplIsBTMOnlySteer(state->steerType)) {
        // Pure 802.11v BTM steering, nothing to do here
        steerexecImplSteerEnd(state, staAddr,
                              steerexecImplSteeringStatusType_success);
        state->candidateCount = 0;
        return;
    }

    evloopTimeoutUnregister(&state->legacy.tSteerTimer);

    wlanif_band_e assocBand = wlanif_resolveBandFromChannelNumber(assocBSS->channelId);
    // Special case for 5 GHz. We need to clear the blacklist immediately
    // as we want to make sure the client can associate to 2.4 GHz if
    // it wanders out of 5 GHz range (and we cannot react fast enough).
    if (assocBand == wlanif_band_5g) {
        steerexecImplEnableAllDisabledCandidates(state, staAddr);
    } else {
        // Record this entry as blacklisted on the disabled band,
        // and keep it for the configured time
        steerexecImplMarkBlacklist(exec, state, steerexecImplBlacklist_candidate);

        // To avoid confusing the user (if s/he happens to be looking
        // at a screen that might be affected by seeing beacons but not
        // probe responses, re-enable probe resposnes here. If the client
        // happens to try the 5 GHz band again, it will still get rejected.
        if (wlanif_setNonCandidateStateForSTA(state->candidateCount,
                                           &state->candidateList[0],
                                           staAddr,
                                           LBD_TRUE /* enable */,
                                           LBD_TRUE /* probeOnly */) != LBD_OK) {
            // This should not happen unless the blacklist entry was
            // removed out from under us, so we just log an error.
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Failed to enable probe responses for "
                 lbMACAddFmt(":"), __func__,
                 lbMACAddData(staAddr->ether_addr_octet));
        } else {
            dbgf(exec->dbgModule, DBGDEBUG,
                 "%s: Probe responses are enabled for "
                 lbMACAddFmt(":"), __func__,
                 lbMACAddData(staAddr->ether_addr_octet));
        }

    }

    steerexecImplSteerEnd(state, staAddr,
                          steerexecImplSteeringStatusType_success);
}

/**
 * @brief Change the currently in progress steer to a best 
 *        effort steer (will keep the status indicating if this
 *        is an active steer or a blacklist steer the same)
 * 
 * @param [in] state  steering state for STA
 */
static void steerexecImplUpdateSteerTypeBE(
    steerexecImplSteeringState_t *state) {

    // If this is already a BE steer - do nothing
    if (steerexecImplIsBestEffortSteer(state->steerType)) {
        return;
    }

    // Determine if the current steer has a blacklist and is active
    LBD_BOOL isActive = steerexecImplIsActiveSteer(state->steerType);
    LBD_BOOL isBTMOnly = steerexecImplIsBTMOnlySteer(state->steerType);

    if (isActive) {
        if (isBTMOnly) {
            state->steerType = steerexecImplSteeringType_btm_be_active;
        } else {
            state->steerType = steerexecImplSteeringType_btm_blacklist_be_active;
        }
    } else {
        if (isBTMOnly) {
            state->steerType = steerexecImplSteeringType_btm_be;
        } else {
            state->steerType = steerexecImplSteeringType_btm_blacklist_be;
        }
    }
}


/**
 * @brief Check if the BTM response BSSID matches one of the 
 *        target BSSes
 * 
 * @param [in] state  steering state for STA 
 * @param [in] staAddr  MAC address for STA 
 * @param [in] bssid  BSSID from BTM response
 */
static void steerexecImplHandleResponseBSSID(
    steerexecImplSteeringState_t *state,
    const struct ether_addr *staAddr,
    const struct ether_addr *bssid) {

    // Check if the BSSID in the response matches any of the target BSSIDs 
    // requested.
    if (wlanif_isBSSIDInList(state->candidateCount, &state->candidateList[0],
                             bssid)) {
        // Response BSSID matches one of the requested target BSSIDs
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Received successful BTM response from " lbMACAddFmt(":")
             " BSSID " lbMACAddFmt(":") " (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             lbMACAddData(bssid->ether_addr_octet),
             state->transaction);
    } else {
        // Response BSSID doesn't match one of the target BSSIDs

        // Update the type of the steer to be best-effort
        steerexecImplUpdateSteerTypeBE(state);

        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Received successful BTM response from " lbMACAddFmt(":")
             " but BSSID " lbMACAddFmt(":") " does not match any of the requested"
             " targets, will steer as best-effort (steer type %s) (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             lbMACAddData(bssid->ether_addr_octet),
             steerexecImpl_SteeringTypeString[state->steerType],
             state->transaction);

        // Increment count of the mismatch
        state->btm->countBSSIDMismatch++;
    }

    // Store the BSSID
    lbCopyMACAddr(bssid->ether_addr_octet, state->btm->bssid.ether_addr_octet);
}

/**
 * @brief React to an event that a BTM response was received.
 *
 * @param [in] event event received
 */
static void steerexecImplHandleBTMResponseEvent(struct mdEventNode *event) {
    const wlanif_btmResponseEvent_t *resp =
        (const wlanif_btmResponseEvent_t *)event->Data;

    lbDbgAssertExit(NULL, resp);

    stadbEntry_handle_t staHandle = stadb_find(&resp->sta_addr);
    if (!staHandle) {
        return;
    }

    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(staHandle);
    if (!state) {
        return;
    }

    // Were we expecting this response?
    if (state->btm->state == steerexecImpl_btmState_aborted) {
        // The steer was already cancelled, so ignore this response
        evloopTimeoutUnregister(&state->btm->timer);
        state->btm->state = steerexecImpl_btmState_idle;
        return;
    } else if (state->btm->state != steerexecImpl_btmState_waiting_response) {
        // This is not necessarily an error - BTM response could have been received due to a
        // request sent from the console, or just very delayed
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Received unexpected BTM response from " lbMACAddFmt(":")
             " (last transaction was %d)",
             __func__, lbMACAddData(resp->sta_addr.ether_addr_octet),
             state->transaction);
        return;
    }

    // Response was expected, cancel the timeout
    evloopTimeoutUnregister(&state->btm->timer);

    // Does the dialog token match?
    if (state->btm->dialogToken != resp->dialog_token) {
        // Some devices may not update the dialog token, so don't treat this as an error,
        // just print a warning
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Received BTM response from " lbMACAddFmt(":")
             " with unexpected dialog token (%d), expected (%d)",
             __func__, lbMACAddData(resp->sta_addr.ether_addr_octet), resp->dialog_token,
             state->btm->dialogToken);
    }

    // Is the BTM response a success?
    if (resp->status != IEEE80211_WNM_BSTM_RESP_SUCCESS) {
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Received BTM response from " lbMACAddFmt(":")
             " with non-success code (%d) (transaction %d)",
             __func__, lbMACAddData(resp->sta_addr.ether_addr_octet), resp->status,
             state->transaction);
        steerexecImplSteerEndBTMFailure(staHandle, state, &resp->sta_addr,
                                        steerexecImplSteeringStatusType_btm_reject);
        return;
    }

    // Does the BSSID match?
    steerexecImplHandleResponseBSSID(state, &resp->sta_addr, &resp->target_bssid);

    // STA indicated it would transition, update state
    state->btm->state = steerexecImpl_btmState_waiting_association;
    
    // Start timer for association
    evloopTimeoutRegister(&state->btm->timer, state->context->config.btm.associationTime,
                          0 /* USec */);

}

/**
 * @brief Get and check the set of channels provided from the
 *        radio are valid
 *
 * @param [in] state steering state
 * @param [out] channelCount number of channels provided from
 *                           the radio
 * @param [out] channelList list of channels provided from the
 *                          radio
 *
 * @return LBD_STATUS LBD_OK if the set of channels is valid,
 *                    LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplGetAndValidateRadioChannelList(
    steerexecImplSteeringState_t *state,
    u_int8_t *channelCount,
    lbd_channelId_t *channelList) {

    // Get the set of active channels from wlanif
    *channelCount = wlanif_getChannelList(channelList,
                                          WLANIF_MAX_RADIOS);

    // There must be at least 2 channels enabled (one per band), and not
    // more than 3 channels (max number of radios)
    if ((*channelCount < 2) ||
        (*channelCount > WLANIF_MAX_RADIOS)) {
        dbgf(state->context->dbgModule, DBGERR,
             "%s: Invalid number of channels: %d, should be in range 2 to %d",
             __func__, *channelCount, WLANIF_MAX_RADIOS);

        return LBD_NOK;
    }

    return LBD_OK;
}

/**
 * @brief Check the set of input channels (channels to enable
 *        STA association on) are valid.  The set of input
 *        channels is fixed if possible by removing invalid
 *        channels.  If there are no valid channels, an error is
 *        returned.
 *
 * @param [in] state steering state
 * @param [in] radioChannelCount count of channels provided by
 *                               the radio
 * @param [in] radioChannelList set of channels provided by the
 *                              radio
 * @param [inout] inChannelCount count of input channels
 *                               provided by the caller
 * @param [inout] inChannelList set of input channels provided
 *                              by the caller
 *
 * @return LBD_STATUS LBD_OK if inChannelList contains any valid
 *                    channels, LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplValidateInChannelList(
    steerexecImplSteeringState_t *state,
    u_int8_t radioChannelCount,
    const lbd_channelId_t *radioChannelList,
    u_int8_t *inChannelCount,
    lbd_channelId_t *inChannelList) {

    size_t i, j;
    u_int8_t updatedChannelCount = 0;
    lbd_channelId_t updatedChannelList[WLANIF_MAX_RADIOS];

    // Check at least one channel on the input list is present on a radio.
    for (i = 0; i < *inChannelCount; i++) {
        LBD_BOOL match = LBD_FALSE;
        for (j = 0; j < radioChannelCount; j++) {
            if (inChannelList[i] == radioChannelList[j]) {
                match = LBD_TRUE;

                // Copy this to the updated list
                updatedChannelList[updatedChannelCount] = inChannelList[i];
                updatedChannelCount++;
                break;
            }
        }

        if (!match) {
            dbgf(state->context->dbgModule, DBGINFO,
             "%s: Requested pre-association steering to channel %d, "
             "but it isn't present on any radio",
             __func__, inChannelList[i]);
        }
    }

    if (!updatedChannelCount) {
        dbgf(state->context->dbgModule, DBGERR,
             "%s: No requested pre-association channels are present on any radio, will not steer",
             __func__);
        return LBD_NOK;
    }

    // Copy over the new channel set
    *inChannelCount = updatedChannelCount;
    memcpy(inChannelList, &updatedChannelList[0],
           updatedChannelCount * sizeof(lbd_channelId_t));

    return LBD_OK;
}

/**
 * @brief Check the set of currently disabled channels is
 *        consistent with the set of channels provided by the
 *        radio.
 *
 * @param [in] state steering state
 * @param [in] radioChannelCount count of channels provided by
 *                               the radio
 * @param [in] radioChannelList set of channels provided by the
 *                              radio
 *
 * @return LBD_STATUS LBD_OK if the set of disabled channels is
 *                    consistent with the set of channels
 *                    provided by the radio, LBD_NOK otherwise.
 */
static LBD_STATUS steerexecImplValidateDisabledChannelList(
    steerexecImplSteeringState_t *state,
    u_int8_t radioChannelCount,
    const lbd_channelId_t *radioChannelList) {

    size_t j;

    for (j = 0; j < state->legacy.disabledChannelCount; j++) {
        if (!steerexecImplIsOnChannelList(radioChannelCount,
                                          &radioChannelList[0],
                                          state->legacy.disabledChannelList[j])) {
            // Not found - there must have been a channel change event since
            // this steering attempt started.
            // Reset the state - enable all channels on the updatedChannelList, and
            // disable all channels not on that list
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: Pre-association steer in progress, but disabled channel %d"
                 " is no longer active, will reset steer",
                 __func__, state->legacy.disabledChannelList[j]);

            return LBD_NOK;
        }
    }

    return LBD_OK;
}

/**
 * @brief Copy all channels present in list1 and not list2 to
 *        outList
 *
 * @param [in] count1 count of channels present on list1
 * @param [in] list1 set of channels in the first list
 * @param [in] count2 count of channels present on list2
 * @param [in] list2 set of channels in the second list
 * @param [out] outList set of channels present in list1 and not
 *                      list2
 *
 * @return u_int8_t number of channels copied to outList
 */
static u_int8_t steerexecImplCopyAllNotOnList(
    u_int8_t count1,
    const lbd_channelId_t *list1,
    u_int8_t count2,
    const lbd_channelId_t *list2,
     lbd_channelId_t *outList) {
    size_t i;
    u_int8_t outCount = 0;

    for (i = 0; i < count1; i++) {
        if (!steerexecImplIsOnChannelList(count2, list2, list1[i])) {
            // No match, so copy
            outList[outCount] = list1[i];
            outCount++;
        }
    }

    return outCount;
}

/**
 * @brief Copy all channels present in list1 and list2 to
 *        outList
 *
 * @param [in] count1 count of channels present on list1
 * @param [in] list1 set of channels in the first list
 * @param [in] count2 count of channels present on list2
 * @param [in] list2 set of channels in the second list
 * @param [out] outList set of channels present in list1 and
 *                      list2
 *
 * @return u_int8_t number of channels copied to outList
 */
static u_int8_t steerexecImplCopyAllOnList(
    u_int8_t count1,
    const lbd_channelId_t *list1,
    u_int8_t count2,
    const lbd_channelId_t *list2,
     lbd_channelId_t *outList) {
    size_t i, j;
    u_int8_t outCount = 0;

    for (i = 0; i < count1; i++) {
        for (j = 0; j < count2; j++) {
            if (list2[j] == list1[i]) {
                // Match, so copy
                outList[outCount] = list1[i];
                outCount++;

                break;
            }
        }
    }

    return outCount;
}

/**
 * @brief Reset the set of enabled and disabled channels to be
 *        consistent with the set of channels provided by the
 *        radio and the enabled channel set requested by the
 *        caller.
 *
 * @param [in] state steering state
 * @param [in] radioChannelCount count of channels provided by
 *                               the radio
 * @param [in] radioChannelList set of channels provided by the
 *                              radio
 * @param [in] updatedChannelCount count of channels provided by
 *                                 the caller
 * @param [in] updatedChannelList set of channels provided by
 *                                the caller
 * @param [out] enabledChannelCount count of channels to enable
 * @param [out] enabledChannelList set of channels to enable
 * @param [out] disabledChannelCount count of channels to
 *                                   disable
 * @param [out] disabledChannelList set of channels to disable
 */
static void steerexecImplResetChannelList(
    steerexecImplSteeringState_t *state,
    u_int8_t radioChannelCount,
    const lbd_channelId_t *radioChannelList,
    u_int8_t updatedChannelCount,
    const lbd_channelId_t *updatedChannelList,
    u_int8_t *enabledChannelCount,
    lbd_channelId_t *enabledChannelList,
    u_int8_t *disabledChannelCount,
    lbd_channelId_t *disabledChannelList) {

    state->legacy.disabledChannelCount = 0;

    // Enabled channels are all those on the list requested by the caller
    *enabledChannelCount = updatedChannelCount;
    memcpy(enabledChannelList, &updatedChannelList[0],
           updatedChannelCount * sizeof(lbd_channelId_t));

    // Disabled channels are all those on the radio channel list, and not on the
    // list requested by the caller
    *disabledChannelCount =
        steerexecImplCopyAllNotOnList(radioChannelCount, radioChannelList,
                                      updatedChannelCount, updatedChannelList,
                                      disabledChannelList);
}

/**
 * @brief Update the blacklist state / set of disabled VAPs
 *        based upon a new post-association (candidate
 *        based) steer request. Will:
 *            - Cancel existing steer if there is one in
 *              progress
 *            - Enable any VAPs disabled by channel
 *            - Update the set of VAPs disabled / enabled by
 *              candidate
 *            - Mark the entry as not blacklisted
 *
 * @param [in] state  steering state
 * @param [in] exec  steering executor
 * @param [in] entry  stadb entry
 * @param [in] staAddr  STA MAC address
 * @param [in] steerType type of steer requested
 * @param [in] candidateCount  count of steer candidates
 * @param [in] candidateList  list of steer candidates
 * @param [out] willSteer  fill in with LBD_TRUE if a new steer
 *                         should be started, LBD_FALSE
 *                         otherwise
 *
 * @return LBD_OK on success, LBD_NOK otherwise.
 */
static LBD_STATUS steerexecImplReconcileSteerCandidate(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplSteeringType_e steerType,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    LBD_BOOL *willSteer) {

    *willSteer = LBD_FALSE;

    // If there is any steering in progress, we need to handle that specially.
    if (state->steerType != steerexecImplSteeringType_none) {

        if (steerexecImplIsSameTarget(state, candidateCount, candidateList)) {
            // Nop. Already being steered to the target.
            return LBD_OK;
        } else {
            dbgf(exec->dbgModule, DBGINFO,
                 "%s: Aborting steer for " lbMACAddFmt(":")
                 " due to request to steer to different target (transaction %d)",
                 __func__,
                 lbMACAddData(staAddr->ether_addr_octet),
                 state->transaction);
            return steerexecImplAbortSteerImpl(exec, entry, state,
                                               steerexecImplSteeringStatusType_abort_change_target);
        }
    }

    LBD_BOOL updatedState = steerexecImplCleanupSteerDifferentType(
        state, exec, entry, staAddr, steerType);
    if (!steerexecImplIsBTMOnlySteer(steerType)) {
        if (updatedState) {
            // No previous blacklisted candidates - disable all VAPs that don't match
            // the candidate list
            if (wlanif_setNonCandidateStateForSTA(candidateCount, candidateList,
                                               staAddr, LBD_FALSE /* enable */,
                                               LBD_FALSE /* probeOnly */) != LBD_OK) {
                dbgf(exec->dbgModule, DBGERR,
                     "%s: Failed to update candidate based blacklists for "
                     lbMACAddFmt(":") ", will not steer", __func__,
                     lbMACAddData(staAddr->ether_addr_octet));
                return LBD_NOK;
            }
         } else {
             // Update the blacklist.
             u_int8_t enableCount, disableCount;
             lbd_bssInfo_t enableList[STEEREXEC_MAX_CANDIDATES], disableList[STEEREXEC_MAX_CANDIDATES];
             steerexecImplUpdateCandidateBlacklist(state, staAddr, candidateCount, candidateList,
                                                   &enableCount, &enableList[0],
                                                   &disableCount, &disableList[0]);

             // Update the blacklists + probe response witholding in wlanif
             // There were previously blacklisted candidates - enable and disable specific VAPs

             // Enable all candidates on the enable list
             if (wlanif_setCandidateStateForSTA(enableCount, &enableList[0],
                                                staAddr, LBD_TRUE /* enable */) != LBD_OK) {
                 dbgf(exec->dbgModule, DBGERR,
                      "%s: Failed to enable candidate(s) for "
                      lbMACAddFmt(":") ", will not steer", __func__,
                      lbMACAddData(staAddr->ether_addr_octet));
                 return LBD_NOK;
             }

             // Disable all candidates on the disable list
             if (wlanif_setCandidateStateForSTA(disableCount, &disableList[0],
                                                staAddr, LBD_FALSE /* enable */) != LBD_OK) {
                 dbgf(exec->dbgModule, DBGERR,
                      "%s: Failed to disable candidate(s) for "
                      lbMACAddFmt(":") ", will not steer", __func__,
                      lbMACAddData(staAddr->ether_addr_octet));
                 return LBD_NOK;
             }
         }
    }

    *willSteer = LBD_TRUE;

    // No longer blacklisted
    steerexecImplMarkAsNotBlacklisted(state);

    return LBD_OK;
}


/**
 * @brief Update the blacklist state / set of disabled VAPs
 *        based upon a new pre-association (channel based)
 *        steer request. Will:
 *            - Cancel a post-association steer if there is one
 *              in progress
 *            - Enable any VAPs disabled by candidate
 *            - Update the set of VAPs disabled / enabled by
 *              channel
 *            - Mark the entry as not blacklisted
 *
 * @param [in] state  steering state
 * @param [in] exec  steering executor
 * @param [in] entry  stadb entry
 * @param [in] staAddr  STA MAC address
 * @param [in] steerType type of steer requested
 * @param [in] channelCount  count of channels
 * @param [in] channelList  list of channels
 * @param [out] willSteer  fill in with LBD_TRUE if a new steer
 *                         should be started, LBD_FALSE
 *                         otherwise
 *
 * @return LBD_OK on success, LBD_NOK otherwise.
 */
static LBD_STATUS steerexecImplReconcileSteerChannel(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplSteeringType_e steerType,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    LBD_BOOL *willSteer) {

    *willSteer = LBD_FALSE;
    LBD_BOOL cleanupComplete = LBD_FALSE;

    // Do cleanup if there is another steer in progress
    cleanupComplete = steerexecImplCleanupSteerDifferentType(
        state, exec, entry, staAddr,
        steerexecImplSteeringType_preassociation);

    // Check if set of enabled channels has changed
    u_int8_t countEnable, countDisable;
    lbd_channelId_t listEnable[WLANIF_MAX_RADIOS], listDisable[WLANIF_MAX_RADIOS];

    if (steerexecImplChannelDelta(state, channelCount, channelList,
                                  &countEnable, &listEnable[0],
                                  &countDisable, &listDisable[0]) == LBD_NOK) {
        // Error occurred.
        return LBD_NOK;
    } else if (!countEnable && !countDisable) {
        // Nothing to do, set of channels has not changed
        return LBD_OK;
    }

    if (!cleanupComplete) {
        dbgf(exec->dbgModule, DBGINFO,
             "%s: Pre-association steer for " lbMACAddFmt(":")
             " aborted due to changed channel set (transaction %d)",
             __func__,
             lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);
    }

    if (countEnable) {
        // Change set of enabled channels via wlanif
        if (wlanif_setChannelStateForSTA(
            countEnable,
            &listEnable[0],
            staAddr,
            LBD_TRUE /* enable */) != LBD_OK) {

            // Failed to update the set of enabled channels
            return LBD_NOK;
        }
    }

    if (countDisable) {
        // Change set of disabled channels via wlanif
        if (wlanif_setChannelStateForSTA(
            countDisable,
            &listDisable[0],
            staAddr,
            LBD_FALSE /* enable */) != LBD_OK) {

            // Failed to update the set of disabled channels
            return LBD_NOK;
        }
    }

    // Set of enabled channels changed, update storage
    steerexecImplUpdateChannelSet(state,
                                  countEnable, &listEnable[0],
                                  countDisable, &listDisable[0]);

    *willSteer = LBD_TRUE;
    return LBD_OK;
}

/**
 * @brief Helper function to determine if the entire blacklist
 *        should be removed (as opposed to selective update)
 *
 * @param [in] state steering state
 * @param [in] steerType steer type
 *
 * @return LBD_TRUE if the entire blacklist should be removed,
 *         LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplShouldRemoveBlacklist(
    steerexecImplSteeringState_t *state,
    steerexecImplSteeringType_e steerType) {

    if ((state->blacklistType != steerexecImplBlacklist_none) &&
        (steerexecImplIsBTMOnlySteer(steerType))) {
        // Starting a BTM steer, and there was any kind of blacklist
        return LBD_TRUE;
    } else if ((state->blacklistType == steerexecImplBlacklist_candidate) &&
        (steerType == steerexecImplSteeringType_preassociation)) {
        // Had a candidate blacklist, and starting a channel steer
        return LBD_TRUE;
    } else if ((state->blacklistType == steerexecImplBlacklist_channel) &&
               ((steerType == steerexecImplSteeringType_legacy) ||
                steerexecImplIsBTMSteer(steerType))) {
        // Had a channel blacklist, and starting a candidate steer
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Cleanup old state when starting a new steer of a
 *        different type.
 *
 * @param [in] state  steering state
 * @param [in] exec  steering executor
 * @param [in] entry  stadb entry
 * @param [in] staAddr  STA MAC address
 * @param [in] steerType type of steer requested
 *
 * @return LBD_TRUE if all cleanup could be done here (due to
 *         the steer type changing), LBD_FALSE if the steer type
 *         has not changed, meaning cleanup could not be done
 *         here.
 */
static LBD_BOOL steerexecImplCleanupSteerDifferentType(
    steerexecImplSteeringState_t *state,
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplSteeringType_e steerType) {

    if (state->steerType == steerexecImplSteeringType_none) {
        if (state->blacklistType == steerexecImplBlacklist_none) {
            // No blacklist, fresh state.
            return LBD_TRUE;
        }
        // No steer in progress - is there a blacklist of the opposite type
        // still around?
        if (steerexecImplShouldRemoveBlacklist(state, steerType)) {
            // Blacklist type doesn't match current steer.
            // Re-enable everything that is disabled
            steerexecImplRemoveAllBlacklists(state, staAddr);
            return LBD_TRUE;
        }

        // There is already a blacklist of the same type as the new steer,
        // will need to selectively update the blacklist state.
        return LBD_FALSE;
    } else {
        // There is a steer in progress - is it a pre-association steer and
        // the new steer is a pre-association steer?
        if ((state->steerType == steerType) &&
            (steerType == steerexecImplSteeringType_preassociation)) {
            // Same type - will need to update the blacklist state.
            return LBD_FALSE;
        }

        // The new steer is of a different type, abort the previous steer.
        dbgf(exec->dbgModule, DBGINFO,
             "%s: Aborting steer for " lbMACAddFmt(":")
             " due to request for new steer (transaction %d)",
             __func__,
             lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);
        steerexecImplAbortSteerImpl(exec, entry, state,
                                    steerexecImplSteeringStatusType_abort_change_target);

        // Fresh state for steering.
        return LBD_TRUE;
    }
}

/**
 * @brief Check the set of requested channels for validity, and
 *        get the set of channels to enable and disable.
 *
 * @pre Set of input channels should contain unique channelIds
 *      (ie. no repeating channels)
 * @pre All channel sets are non-NULL
 *
 * @param [in] state steering state
 * @param [in] channelCount count of channels requested by
 *                          caller
 * @param [in] channelList set of channels requested by caller
 * @param [out] enabledChannelCount count of channels to enable
 * @param [out] enabledChannelList set of channels to enable
 * @param [out] disabledChannelCount count of channels to
 *                                   disable
 * @param [out] disabledChannelList set of channels to disable
 *
 * @return LBD_STATUS LBD_OK if the channels are valid, LBD_NOK
 *                    otherwise
 */
static LBD_STATUS steerexecImplChannelDelta(
    steerexecImplSteeringState_t *state,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    u_int8_t *enabledChannelCount,
    lbd_channelId_t *enabledChannelList,
    u_int8_t *disabledChannelCount,
    lbd_channelId_t *disabledChannelList) {

    size_t i, j;

    *enabledChannelCount = 0;
    *disabledChannelCount = 0;

    u_int8_t wlanifChannelCount;
    lbd_channelId_t wlanifChannelList[WLANIF_MAX_RADIOS];

    // Get the set of channels from the radio
    if (steerexecImplGetAndValidateRadioChannelList(state, &wlanifChannelCount,
                                                    &wlanifChannelList[0]) != LBD_OK) {
        return LBD_NOK;
    }

    // Validate the input set of channels
    u_int8_t updatedChannelCount = channelCount;
    lbd_channelId_t updatedChannelList[WLANIF_MAX_RADIOS];
    memcpy(&updatedChannelList[0], channelList,
           channelCount * sizeof(lbd_channelId_t));

    if (steerexecImplValidateInChannelList(state,
                                           wlanifChannelCount,
                                           &wlanifChannelList[0],
                                           &updatedChannelCount,
                                           &updatedChannelList[0]) != LBD_OK) {
        return LBD_NOK;
    }

    // Make sure all the currently disabled channels match ones on the wlanif list
    // Note: We don't track the enabled channels, if an enabled channel has changed, we don't care
    if (steerexecImplValidateDisabledChannelList(state, wlanifChannelCount,
                                                 &wlanifChannelList[0]) != LBD_OK) {
        // If the disabled channel list is no longer valid, we will still attempt to steer
        // This steer will bring the channel set back in sync with what is reported from wlanif
        steerexecImplResetChannelList(state,
                                      wlanifChannelCount,
                                      &wlanifChannelList[0],
                                      updatedChannelCount,
                                      &updatedChannelList[0],
                                      enabledChannelCount,
                                      enabledChannelList,
                                      disabledChannelCount,
                                      disabledChannelList);
        return LBD_OK;
    }

    // No channel state has changed, continue

    // Get the set of disabled channels
    // The disabled list will be all channels in the wlanif list that aren't in
    // the updated list or the disable list.
    for (i = 0; i < wlanifChannelCount; i++) {
        LBD_BOOL match = LBD_FALSE;
        for (j = 0; j < updatedChannelCount; j++) {
            if (updatedChannelList[j] == wlanifChannelList[i]) {
                match = LBD_TRUE;

                break;
            }
        }

        if (!match) {
            // Channel to disable - check if it's already disabled
            for (j = 0; j < state->legacy.disabledChannelCount; j++) {
                if (wlanifChannelList[i] == state->legacy.disabledChannelList[j]) {
                    // already disabled, nothing to do
                    match = LBD_TRUE;
                    break;
                }
            }

            if (!match) {
                // Not present on disabled, list, add it
                disabledChannelList[*disabledChannelCount] = wlanifChannelList[i];
                (*disabledChannelCount)++;
            }
        }
    }

    // Get the set of enabled channels
    // The enabled list will be all channels in the updated list that are currently disabled.
    *enabledChannelCount =
        steerexecImplCopyAllOnList(updatedChannelCount, &updatedChannelList[0],
                                   state->legacy.disabledChannelCount,
                                   &state->legacy.disabledChannelList[0],
                                   enabledChannelList);
    return LBD_OK;
}

/**
 * @brief Update the set of disabled channels to store with the
 *        STA
 *
 * @param [in] state steering state
 * @param [in] enabledChannelCount count of channels enabled
 * @param [in] enabledChannelList set of channels enabled
 * @param [in] disabledChannelCount count of channels disabled
 * @param [in] disabledChannelList set of channels disabled
 */
static void steerexecImplUpdateChannelSet(
    steerexecImplSteeringState_t *state,
    u_int8_t enabledChannelCount,
    const lbd_channelId_t *enabledChannelList,
    u_int8_t disabledChannelCount,
    const lbd_channelId_t *disabledChannelList) {

    // Copy over disabled channels
    lbd_channelId_t temp[WLANIF_MAX_RADIOS-1];
    // Still disabled channels are all those on the old disabled channel list, and not on the
    // new enabled list
    u_int8_t countDisabled =
        steerexecImplCopyAllNotOnList(state->legacy.disabledChannelCount,
                                      &state->legacy.disabledChannelList[0],
                                      enabledChannelCount,
                                      &enabledChannelList[0],
                                      &temp[0]);

    // Copy over the still disabled channels
    memcpy(&state->legacy.disabledChannelList, &temp,
           countDisabled * sizeof(lbd_channelId_t));

    // Copy over the newly disabled channels
    memcpy(&state->legacy.disabledChannelList[countDisabled], disabledChannelList,
           disabledChannelCount * sizeof(lbd_channelId_t));
    state->legacy.disabledChannelCount = countDisabled + disabledChannelCount;

    // Mark this entry as no longer blacklisted.
    steerexecImplMarkAsNotBlacklisted(state);
}

/**
 * @brief Callback function used to cancel active steering of a client, and
 *        clear blacklist if any
 *
 * @see stadb_iterFunc_t
 */
static void steerexecImplHandleChanChangeCB(stadbEntry_handle_t entry,
                                     void *cookie) {
    struct steerexecImplPriv_t *exec =
        (struct steerexecImplPriv_t *) cookie;
    lbDbgAssertExit(NULL, exec);

    steerexecImplAbort(exec, entry,
                       steerexecImplSteeringStatusType_channel_change,
                       NULL /* ignored */);
}

/**
 * @brief Callback function invoked by wlanif when channel change happens
 *
 * It will cancel any ongoing steering and clear blacklist if any
 *
 * @see wlanif_chanChangeObserverCB
 */
static void steerexecImplChanChangeObserver(lbd_vapHandle_t vap,
                                            lbd_channelId_t channelId,
                                            void *cookie) {
    struct steerexecImplPriv_t *exec =
        (struct steerexecImplPriv_t *) cookie;
    lbDbgAssertExit(NULL, exec);

    if (LBD_NOK == stadb_iterate(steerexecImplHandleChanChangeCB, exec)) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Failed to iterate station database for aborting steering",
             __func__);
    }
}

#ifdef GMOCK_UNIT_TESTS
LBD_BOOL steerexecImplIsSTASteeringUnfriendly(stadbEntry_handle_t entry) {
    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        return LBD_FALSE;
    }

    return state->legacy.steeringUnfriendly;
}
#endif

#ifdef LBD_DBG_MENU

void steerexecImplDumpLegacyHeader(struct cmdContext *context,
                                   steerexecImplHandle_t exec) {
    struct timespec ts;
    lbGetTimestamp(&ts);

    cmdf(context, "Legacy overall state:\n");
    cmdf(context, "  Current # STAs prohibited from steering: %u\n",
         exec->numSteeringProhibits);

    if (exec->numSteeringProhibits > 0) {
        cmdf(context, "    Next prohibit update: %u seconds\n",
             exec->nextProhibitExpiry - ts.tv_sec);
    }

    cmdf(context, "  Current # STAs marked as steering unfriendly: %u\n",
         exec->legacy.steeringUnfriendly.countEntries);

    if (exec->legacy.steeringUnfriendly.countEntries &&
        exec->config.legacy.steeringUnfriendlyTime > 0) {
        cmdf(context, "    Next unfriendly update: %u seconds\n",
             exec->legacy.steeringUnfriendly.nextExpiry - ts.tv_sec);
    }

    cmdf(context, "  Current # STAs blacklisted: %u\n",
         exec->legacy.numBlacklist);

    if (exec->legacy.numBlacklist > 0 && exec->config.legacy.blacklistTime > 0) {
        cmdf(context, "    Next blacklist update: %u seconds\n",
             exec->legacy.nextBlacklistExpiry - ts.tv_sec);
    }

    cmdf(context, "\nLegacy per STA information:\n");
    cmdf(context, "%-20s%-12s%-20s%-15s%-15s%-15s%-15s%-10s%-21s\n",
         "MAC", "Transaction", "Secs since steered", "# Auth Rej",
         "Prohibited", "Unfriendly", "T_Steer", "Blacklist", "Consecutive Failures");
}

void steerexecImplDumpBTMHeader(struct cmdContext *context,
                                steerexecImplHandle_t exec) {
    struct timespec ts;
    lbGetTimestamp(&ts);

    cmdf(context, "BTM overall state:\n");

    cmdf(context, "  Current # STAs marked as BTM unfriendly: %u\n",
         exec->btm.unfriendlyTimer.countEntries);

    if (exec->btm.unfriendlyTimer.countEntries > 0) {
        cmdf(context, "    Next BTM unfriendly update: %u seconds\n",
             exec->btm.unfriendlyTimer.nextExpiry - ts.tv_sec);
    }

    cmdf(context, "  Current # STAs marked as BTM active unfriendly: %u\n",
         exec->btm.activeUnfriendlyTimer.countEntries);

    if (exec->btm.activeUnfriendlyTimer.countEntries > 0) {
        cmdf(context, "    Next BTM active unfriendly update: %u seconds\n",
             exec->btm.activeUnfriendlyTimer.nextExpiry - ts.tv_sec);
    }

    cmdf(context, "\n802.11v BTM Compliant per STA information:\n");
    cmdf(context, "%-18s%-12s%-16s%-17s%-10s%-11s%-17s%-12s%-6s%-15s\n",
         "MAC", "Transaction", "Secs since steer", "(active failure)",
         "State", "Unfriendly", "Compliance", "Eligibility",
         "Token", "Timer");
}

void steerexecImplDumpBTMStatisticsHeader(struct cmdContext *context,
                                          steerexecImplHandle_t exec) {
    cmdf(context, "\n802.11v BTM Compliant per STA statistics:\n");
    cmdf(context, "%-18s%-7s%-7s%-8s%-8s%-21s%-9s%-14s\n",
         "MAC", "NoResp", "Reject", "NoAssoc", "Success", "Consecutive Failures",
         "(active)", "BSSIDMismatch");
}

static void steerexecImplDumpBTMEntryState(struct cmdContext *context,
                                           stadbEntry_handle_t entry,
                                           steerexecImplSteeringState_t *state) {
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(state->context->dbgModule, staAddr);

    cmdf(context, lbMACAddFmt(":") " ",
         lbMACAddData(staAddr->ether_addr_octet));

    cmdf(context, "%-12d", state->transaction);

    struct timespec ts;
    lbGetTimestamp(&ts);
    cmdf(context, "%-16d(%-14d) ", ts.tv_sec - state->btm->lastSteeringTime,
         state->btm->lastActiveSteeringFailureTime ?
         ts.tv_sec - state->btm->lastActiveSteeringFailureTime :
         0);

    cmdf(context, "%-10s", state->btm->state <= steerexecImpl_btmState_invalid ?
         steerexecImpl_btmStateString[state->btm->state] :
         steerexecImpl_btmStateString[steerexecImpl_btmState_invalid]);

    cmdf(context, "%-11s", state->btm->btmUnfriendly ? "yes" : "no");

    cmdf(context, "%-17s",
         state->btm->complianceState <= steerexecImpl_btmComplianceState_invalid ?
         steerexecImpl_btmComplianceString[state->btm->complianceState] :
         steerexecImpl_btmComplianceString[steerexecImpl_btmComplianceState_invalid]);

    steerexec_steerEligibility_e eligibility =
        steerexecImplDetermineSteeringEligibility(
            state->context, entry,
            LBD_FALSE /* reportReasonNotEligible */);
    cmdf(context, "%-12s",
         steerexec_SteerEligibilityString[eligibility]);

    cmdf(context, "%-6d", state->btm->dialogToken);

    unsigned timeoutRemaining;
    if (evloopTimeoutRemaining(&state->btm->timer, &timeoutRemaining,
                               NULL) == 0) {
        cmdf(context, "%-15u", timeoutRemaining);
    } else {
        cmdf(context, "%-15c", ' ');
    }

    cmdf(context, "\n");
}

static void steerexecImplDumpBTMEntryStatistics(
    struct cmdContext *context,
    stadbEntry_handle_t entry,
    steerexecImplSteeringState_t *state) {
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(state->context->dbgModule, staAddr);

    cmdf(context, lbMACAddFmt(":") " ",
         lbMACAddData(staAddr->ether_addr_octet));

    cmdf(context, "%-7d", state->btm->countNoResponseFailure);
    cmdf(context, "%-7d", state->btm->countRejectFailure);
    cmdf(context, "%-8d", state->btm->countAssociationFailure);
    cmdf(context, "%-8d", state->btm->countSuccess);
    cmdf(context, "%-21d", state->btm->countConsecutiveFailure);
    cmdf(context, "(%-6d) ", state->btm->countConsecutiveFailureActive);
    cmdf(context, "%-14d", state->btm->countBSSIDMismatch);

    cmdf(context, "\n");
}

static void steerexecImplDumpLegacyEntryState(struct cmdContext *context,
                                              stadbEntry_handle_t entry,
                                              steerexecImplSteeringState_t *state) {
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(state->context->dbgModule, staAddr);

    cmdf(context, lbMACAddFmt(":") "   ",
         lbMACAddData(staAddr->ether_addr_octet));

    cmdf(context, "%-12d", state->transaction);

    struct timespec ts;
    lbGetTimestamp(&ts);
    cmdf(context, "%-20d%-15u", ts.tv_sec - state->legacy.lastSteeringTime,
         state->legacy.numAuthRejects);

    cmdf(context, "%-15s%-15s",
         (state->steeringProhibited <= steerexecImplSteeringProhibitType_invalid ?
          steerexecImpl_SteeringProhibitTypeString[state->steeringProhibited] :
          steerexecImpl_SteeringProhibitTypeString[steerexecImplSteeringProhibitType_invalid]),
         state->legacy.steeringUnfriendly ? "yes" : "no");

    unsigned tSteeringRemaining;
    if (evloopTimeoutRemaining(&state->legacy.tSteerTimer, &tSteeringRemaining,
                               NULL) == 0) {
        cmdf(context, "%-15u", tSteeringRemaining);
    } else {
        cmdf(context, "%-15c", ' ');
    }

    cmdf(context, "%-10s", state->blacklistType <= steerexecImplBlacklist_invalid ?
         steerexecImpl_SteeringBlacklistTypeString[state->blacklistType] :
         steerexecImpl_SteeringBlacklistTypeString[steerexecImplBlacklist_invalid]);

    cmdf(context, "%-21d", state->legacy.countConsecutiveFailure);

    cmdf(context, "\n");
}

void steerexecImplDumpEntryState(struct cmdContext *context,
                                 steerexecImplHandle_t exec,
                                 stadbEntry_handle_t entry,
                                 LBD_BOOL inProgressOnly,
                                 LBD_BOOL dumpBTMClients,
                                 LBD_BOOL dumpStatistics) {
    steerexecImplSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (state &&
        (!inProgressOnly || state->steerType != steerexecImplSteeringType_none)) {

        if (dumpBTMClients && stadbEntry_isBTMSupported(entry)) {
            if (dumpStatistics) {
                steerexecImplDumpBTMEntryStatistics(context, entry, state);
            } else {
                steerexecImplDumpBTMEntryState(context, entry, state);
            }
        } else if (!dumpBTMClients) {
            // Need to dump legacy status for BTM clients as well since these
            // can be steered via legacy if they fail BTM transitions
            steerexecImplDumpLegacyEntryState(context, entry, state);
        }
    }
}

#endif /* LBD_DBG_MENU */
