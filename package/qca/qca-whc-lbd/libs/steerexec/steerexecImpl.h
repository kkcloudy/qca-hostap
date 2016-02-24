// vim: set et sw=4 sts=4 cindent:
/*
 * @File: steerexecImpl.h
 *
 * @Abstract: Package level interface to the steering executor for legacy
 *            clients
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
 */

#ifndef steerexecImpl__h
#define steerexecImpl__h

#include "lbd.h"  // for LBD_STATUS

#include "steerexec.h"
#include "stadbEntry.h"
#include "wlanif.h"

#if defined(__cplusplus)
extern "C" {
#endif


/**
 * @brief Config parameters used for legacy stations, and BTM
 *        compliant stations if config parameter
 *        BTMAlsoBlacklist = 1
 */
typedef struct steerexecImplLegacyConfig_t {
    /// Amount of time between successive steerings for the legacy
    /// steering mechanism.
    u_int32_t steeringProhibitTime;

    /// How long to allow for the STA to associate on the target band
    /// before aborting the steering.
    u_int32_t tSteering;

    /// The window during which repeated authentication rejects are counted
    /// as only a single one.
    u_int32_t initialAuthRejCoalesceTime;

    /// The point at which repeated authentications result in the blacklist
    /// being cleared and steering aborted.
    u_int32_t authRejMax;

    /// The base amount of time a device should be considered as steering
    /// unfriendly before being attempted again (s).
    u_int32_t steeringUnfriendlyTime;

    /// The maximum timeout used for backoff for steering unfriendly STAs.
    /// Total amount of backoff is calculated as
    /// min(maxSteeringUnfriendly, SteeringUnfriendlyTime * 2 ^ CountConsecutiveFailures)
    u_int32_t maxSteeringUnfriendly;

    /// The amount of time a device should be blacklisted on one band
    /// before being removed.
    u_int32_t blacklistTime;
} steerexecImplLegacyConfig_t;

/**
 * @brief Config parameters used for BTM compliant stations
 */
typedef struct steerexecImplBTMConfig_t {
    /// How long to wait for a BTM response after sending a BTM request.
    /// If no response is received in that time,
    /// mark the BTM transition as a failure
    u_int32_t responseTime;

    /// How long to wait for an association on the target band after receiving a BTM response.
    /// If no association is received in that time, mark the BTM transition as a failure
    u_int32_t associationTime;

    /// If set to 0, just attempt to move the client via 802.11v BTM, otherwise also blacklist
    /// when steering the client
    u_int32_t alsoBlacklist;

    /// The base time to mark a STA as BTM-unfriendly after failing to respond correctly
    /// to a BTM request (s)
    u_int32_t btmUnfriendlyTime;

    /// The maximum timeout used for backoff for BTM unfriendly STAs.
    /// Total amount of backoff is calculated as
    /// min(maxBTMUnfriendly, btmUnfriendlyTime * 2 ^ CountConsecutiveFailures)
    u_int32_t maxBTMUnfriendly;

    /// The maximum timeout used for backoff for active steering unfriendly STAs.
    /// Total amount of backoff is calculated as
    /// min(maxBTMActiveUnfriendly, btmUnfriendlyTime * 2 ^ CountConsecutiveFailuresActive)
    u_int32_t maxBTMActiveUnfriendly;

    /// Amount of time between successive steerings for the BTM
    /// steering mechanism unless there is an auth reject (in which
    /// case the long prohibit time is used).
    u_int32_t steeringProhibitShortTime;

    /// Number of seconds allowed for a RSSI measurement to
    /// be considered as recent
    u_int8_t freshnessLimit;

    /// Minimum RSSI allowed before STA will be steered as best-effort
    lbd_rssi_t minRSSIBestEffort;
} steerexecImplBTMConfig_t;

typedef struct steerexecImplConfig_t {
    /// Config parameters for legacy steering
    steerexecImplLegacyConfig_t legacy;

    /// Config parameters for 802.11v BTM steering
    steerexecImplBTMConfig_t btm;

    /// RSSI threshold indicating poor signal strength
    u_int8_t lowRSSIXingThreshold[wlanif_band_invalid];

    /// RSSI threshold indicating the target band is not strong enough
    /// for association
    u_int8_t targetLowRSSIThreshold[wlanif_band_invalid];
} steerexecImplConfig_t;

struct steerexecImplPriv_t;
typedef struct steerexecImplPriv_t *steerexecImplHandle_t;

/**
 * @brief Type of steering currently in progress for the STA
 */
typedef enum steerexecImplSteeringType_e {
    /// No steering in progress
    steerexecImplSteeringType_none,

    /// Legacy steering
    steerexecImplSteeringType_legacy,

    /// BTM steering with a blacklist
    steerexecImplSteeringType_btm_and_blacklist,

    /// BTM steering only (no blacklist)
    steerexecImplSteeringType_btm,

    /// BTM steering while active with a blacklist
    steerexecImplSteeringType_btm_and_blacklist_active,

    /// BTM steering only (no blacklist) while active
    steerexecImplSteeringType_btm_active,

    /// Pre-association
    steerexecImplSteeringType_preassociation,

    /// Best-effort BTM steering (no blacklist, failures do not mark
    /// STA as unfriendly / increase exponential backoff)
    steerexecImplSteeringType_btm_be,

    /// Best-effort BTM steering (no blacklist, failures do not mark
    /// STA as unfriendly / increase exponential backoff) while active
    steerexecImplSteeringType_btm_be_active,

    /// Best-effort BTM steering with blacklist (failures do not mark
    /// STA as unfriendly / increase exponential backoff)
    steerexecImplSteeringType_btm_blacklist_be,

    /// Best-effort BTM steering with blacklist (failures do not mark
    /// STA as unfriendly / increase exponential backoff) while active
    steerexecImplSteeringType_btm_blacklist_be_active,

    /// Invalid state
    steerexecImplSteeringType_invalid
} steerexecImplSteeringType_e;

/**
 * @brief Type that denotes the current state of BTM compliance
 */
typedef enum steerexecImpl_btmComplianceState_e {
    /// Will attempt to steer via BTM request, but only while idle
    steerexecImpl_btmComplianceState_idle,

    /// Will attempt to steer via BTM request, but only while idle
    /// and will not promote to active steering until the timer expires
    /// (STA has failed a BTM transition while in the active state)
    steerexecImpl_btmComplianceState_activeUnfriendly,

    /// Will attempt to steer via BTM request while idle or active
    steerexecImpl_btmComplianceState_active,

    /// Invalid state
    steerexecImpl_btmComplianceState_invalid,
} steerexecImpl_btmComplianceState_e;

/**
 * @brief Type of steering prohibition for the STA
 */
typedef enum steerexecImplSteeringProhibitType_e {
    /// No steering prohibition
    steerexecImplSteeringProhibitType_none,

    /// Short steering prohibition (used for clean BTM steering)
    steerexecImplSteeringProhibitType_short,

    /// Long steering prohibition (used for legacy and non-clean
    /// BTM steering)
    steerexecImplSteeringProhibitType_long,

    /// Invalid steering prohibition
    steerexecImplSteeringProhibitType_invalid
} steerexecImplSteeringProhibitType_e;

/**
 * @brief Status of attempted steer when complete
 */
typedef enum steerexecImplSteeringStatusType_e {
    /// Success.
    steerexecImplSteeringStatusType_success,

    /// Steer was aborted due to excessive auth rejects.
    steerexecImplSteeringStatusType_abort_auth_reject,

    /// Steer was aborted because target RSSI is too low
    steerexecImplSteeringStatusType_abort_low_rssi,

    /// Steer was aborted because steering was started to
    /// a different target
    steerexecImplSteeringStatusType_abort_change_target,

    /// Steer was aborted by user.
    steerexecImplSteeringStatusType_abort_user,

    /// BTM reject response.
    steerexecImplSteeringStatusType_btm_reject,

    /// BTM response timeout.
    steerexecImplSteeringStatusType_btm_response_timeout,

    /// Association timeout.
    steerexecImplSteeringStatusType_assoc_timeout,

    /// Steer was aborted due to channel change
    steerexecImplSteeringStatusType_channel_change,

    /// Invalid status.
    steerexecImplSteeringStatusType_invalid
} steerexecImplSteeringStatusType_e;

/**
 * @brief Create the steering executor.
 *
 * @param [in] config  the configuration parameters needed
 * @param [in] dbgModule  the area to use for log messages
 *
 * @return a handle to the executor instance, or NULL if creation failed
 */
steerexecImplHandle_t steerexecImplCreate(const steerexecImplConfig_t *config,
                                          struct dbgModule *dbgModule);

/**
 * @brief Abort any steering operation which may be in progress
 *        for the STA.
 *
 * Note that with BTM based steering only the blacklisting can be
 * aborted (if used). The BTM request will remain in progress and
 * can only be undone via sending another BTM request in the future.
 *
 * If the abort reason is channel change, will remove all blacklist
 * even if no steering is in progress.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the handle to the STA for which to abort
 * @param [in] status reason for the abort
 * @param [out] ignored  if the request was ignored by the executor, this
 *                       will be set to LBD_TRUE; otherwise it will be set
 *                       to LBD_FALSE indicating it was acted upon by the
 *                       executor; this parameter may be NULL if the caller
 *                       does not care to distinguish between ignored and
 *                       non-ignored requests
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexecImplAbort(steerexecImplHandle_t exec,
                              stadbEntry_handle_t entry,
                              steerexecImplSteeringStatusType_e status,
                              LBD_BOOL *ignored);

/**
 * @brief Abort any pre-association steering operation which may
 *        be in progress for the STA.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] handle  the handle to the STA for which to abort
 * @param [out] ignored  if the request was ignored by the executor, this
 *                       will be set to LBD_TRUE; otherwise it will be set
 *                       to LBD_FALSE indicating it was acted upon by the
 *                       executor; this parameter may be NULL if the caller
 *                       does not care to distinguish between ignored and
 *                       non-ignored requests
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexecImplAbortAllowAssoc(steerexecImplHandle_t exec,
                                        stadbEntry_handle_t handle,
                                        LBD_BOOL *ignored);

/**
 * @brief Allows the STA to associate on any channels in
 *        channelList (used for pre-association steering).
 *        The STA will be prohibited from associating on any
 *        channel not on channelList
 *
 * @param [in] exec  the executor instance to use
 * @param [in] handle the handle to the STA to allow
 * @param [in] channelCount count of channels in channelList
 * @param [in] channelList list of channels to allow the STA
 *                         to associate on
 * @param [out] ignored  if the request was ignored by the executor, this
 *                       will be set to LBD_TRUE; otherwise it will be set
 *                       to LBD_FALSE indicating it was acted upon by the
 *                       executor; this parameter may be NULL if the caller
 *                       does not care to distinguish between ignored and
 *                       non-ignored requests
 *
 * @return LBD_STATUS LBD_OK on success, LBD_NOK otherwse
 */
LBD_STATUS steerexecImplAllowAssoc(
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    LBD_BOOL *ignored);

/**
 * @brief Steer the STA to any of the BSSes listed in
 *        candidateList (used for post-association steering).
 *
 * @param [in] exec  the executor instance to use
 * @param [in] handle STA to be steered
 * @param [in] candidateCount count of BSSes in candidateList
 * @param [in] candidateList list of potential targets for
 *                           steering
 * @param [in] reason  reason for the steer
 * @param [out] ignored  if the request was ignored by the executor, this
 *                       will be set to LBD_TRUE; otherwise it will be set
 *                       to LBD_FALSE indicating it was acted upon by the
 *                       executor; this parameter may be NULL if the caller
 *                       does not care to distinguish between ignored and
 *                       non-ignored requests
 *
 * @return LBD_STATUS LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexecImplSteer(steerexecImplHandle_t exec,
                              stadbEntry_handle_t entry,
                              u_int8_t candidateCount,
                              const lbd_bssInfo_t *candidateList,
                              steerexec_steerReason_e reason,
                              LBD_BOOL *ignored);

/**
 * @brief Inform the steering executor of an update on the
 *        association for a given STA.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the handle to the STA which was updated
 */
void steerexecImplHandleAssocUpdate(steerexecImplHandle_t exec,
                                    stadbEntry_handle_t entry);

/**
 * @brief Returns the conditions under which entry can be
 *        steered at this time.
 *
 * @pre Should only be called for associated STAs
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry STA to determine steering eligibility for
 * @param [in] reportReasonNotEligible  whether to report the
 *                                      reason why the STA is
 *                                      not eligible for
 *                                      steering
 *
 * @return Eligibility for handle to be steered
 */
steerexec_steerEligibility_e steerexecImplDetermineSteeringEligibility(
    steerexecImplHandle_t exec,
    stadbEntry_handle_t entry,
    LBD_BOOL reportReasonNotEligible);

/**
 * @brief Determines if a steer should be aborted if the STA
 *        becomes active.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] handle STA to determine if the steer should be
 *                    aborted
 *
 * @return LBD_TRUE if steer should be aborted, LBD_FALSE
 *         otherwise
 */
LBD_BOOL steerexecImplShouldAbortSteerForActive(steerexecImplHandle_t exec,
                                                stadbEntry_handle_t handle);

/**
 * @brief Register a function to get called back when an entry can be
 *        steered again (after previously not being allowed).
 *
 * @param [in] exec  the executor instance to use
 * @param [in] callback  the callback function to invoke
 * @param [in] cookie  the parameter to pass to the callback function
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexecImplRegisterSteeringAllowedObserver(
        steerexecImplHandle_t exec,
        steerexec_steeringAllowedObserverCB callback,
        void *cookie);

/**
 * @brief Unregister the observer callback function.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] callback  the callback function to unregister
 * @param [in] cookie  the registered parameter to pass to the callback
 *                     function
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexecImplUnregisterSteeringAllowedObserver(
        steerexecImplHandle_t exec,
        steerexec_steeringAllowedObserverCB callback,
        void *cookie);

/**
 * @brief Destroy the steering executor.
 *
 * @param [in] exec  the steering executor instance to destroy
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
void steerexecImplDestroy(steerexecImplHandle_t exec);

#ifdef GMOCK_UNIT_TESTS
/**
 * @brief Check if a device is steering unfriendly
 */
LBD_BOOL steerexecImplIsSTASteeringUnfriendly(stadbEntry_handle_t entry);
#endif

#ifdef LBD_DBG_MENU
struct cmdContext;

/**
 * @brief Dump the overall executor information along with the
 *        header for the individual entries.  Information
 *        relevant to legacy devices and BTM devices steered via
 *        legacy mechanisms only.
 *
 * @param [in] context  the output context
 * @param [in] exec  the executor instance to use
 */
void steerexecImplDumpLegacyHeader(struct cmdContext *context,
                                   steerexecImplHandle_t exec);

/**
 * @brief Dump the overall executor information along with the
 *        header for the individual entries.  802.11v BSS
 *        Transition Management compatible devices only.
 *
 * @param [in] context  the output context
 * @param [in] exec  the executor instance to use
 */
void steerexecImplDumpBTMHeader(struct cmdContext *context,
                                steerexecImplHandle_t exec);

/**
 * @brief Dump the header for BTM-related statistics (per STA).
 *
 * @param [in] context  the output context
 * @param [in] exec  the executor instance to use
 */
void steerexecImplDumpBTMStatisticsHeader(struct cmdContext *context,
                                          steerexecImplHandle_t exec);

/**
 * @brief Dump the steering state for a single entry.
 *
 * @param [in] context  the output context
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the entry to dump
 * @param [in] inProgressOnly  flag indicating whether to only dump entries
 *                             that are currently being steered
 * @param [in] dumpBTMClients set to LBD_TRUE if dumping
 *                            information relevant to BTM
 *                            stations
 * @param [in] dumpStatistics set to LBD_TRUE if dumping
 *                            BTM statistics
 */
void steerexecImplDumpEntryState(struct cmdContext *context,
                                 steerexecImplHandle_t exec,
                                 stadbEntry_handle_t entry,
                                 LBD_BOOL inProgressOnly,
                                 LBD_BOOL dumpBTMClients,
                                 LBD_BOOL dumpStatistics);

#endif /* LBD_DBG_MENU */

#if defined(__cplusplus)
}
#endif

#endif
