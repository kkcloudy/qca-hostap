// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stadbEntryPrivate.h
 *
 * @Abstract: Definition for the STA database entry type. This file should not
 *            be used outside of the stadb module.
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

#ifndef stadbEntryPrivate__h
#define stadbEntryPrivate__h

#include <net/ethernet.h>

#include "list.h"

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief All of the stats that are stored for a BSS
 */
typedef struct stadbEntryPriv_bssStats_t {
    /// if this stat entry is valid or not
    LBD_BOOL valid : 1;

    /// last time this entry was updated
    time_t lastUpdateSecs;

    /// Basic information of this BSS
    lbd_bssInfo_t bss;

    /// PHY capability supported on this channel
    wlanif_phyCapInfo_t phyCapInfo;

    struct {
        /// if this RSSI value is estimated or measured
        /// This should only be used for debugging purpose.
        LBD_BOOL estimate : 1;

        /// The last uplink RSSI value, or LBD_INVALID_RSSI if nothing was
        /// obtained yet.
        lbd_rssi_t rssi;

        /// The time value corresponding to the last point at which the RSSI
        /// was updated.
        time_t lastUpdateSecs;

        /// For a probe RSSI, we want to do RSSI averaging and this field will
        /// be set to the number of probes being averaged; for other RSSI update,
        /// set this field to 0.
        u_int8_t probeCount;
    } uplinkInfo;

    struct {
        /// The estimated downlink full capacity on this channel,
        /// or LBD_INVALID_LINK_CAP if not estimated yet
        lbd_linkCapacity_t fullCapacity;

        /// The time value corresponding to the last point at which the data rate
        /// was updated.
        time_t lastUpdateSecs;

        /// The estimated airtime on this channel, LBD_INVALID_AIRTIME if not estimated yet
        lbd_airtime_t airtime;
    } downlinkInfo;

    /// The reserved airtime if any
    lbd_airtime_t reservedAirtime;
} stadbEntryPriv_bssStats_t;

/**
 * @brief All of the data that is stored for a specific station.
 */
typedef struct stadbEntryPriv_t {
    /// Doubly-linked list for use in a given hash table bucket.
    list_head_t hashChain;

    /// The MAC address of the station
    struct ether_addr addr;

    /// The bands on which the STA has been known to operate.
    u_int8_t operatingBands;

    /// Record of the RSSI values seen by the AP for this device on each of
    /// the supported bands.
    struct {
        /// The last RSSI value, or STADBENTRY_INVALID_RSSI if nothing was
        /// obtained yet.
        u_int8_t rssi;

        /// The time value corresponding to the last point at which the RSSI
        /// was updated.
        time_t lastUpdateSecs;
    } latestRSSI[wlanif_band_invalid];

    // Association state.
    struct {
        /// The time of the last association.
        struct timespec lastAssoc;

        /// Whether the device has been associated ever or not.
        LBD_BOOL hasAssoc;

        /// The channel on which the device is currently associated (if any).
        lbd_channelId_t channel;

        /// Last ESS the STA is associated on
        lbd_essId_t lastServingESS;

        /// The pointer to the associated BSS stats. It should be NULL
        /// when not associated
        stadbEntry_bssStatsHandle_t bssHandle;
    } assoc;

    /// State information related to steering. This should be considered
    /// opaque to all but the steering executor.
    void *steeringState;

    /// Function to invoke to destroy the steering state prior to destroying
    /// the overall entry.
    stadbEntry_steeringStateDestructor_t steeringStateDestructor;

    // Activity state
    struct {
        /// The time of last time activity status change
        time_t lastActUpdate;

        /// Whether the device is active or not
        LBD_BOOL isAct;
    } activity;

    /// Timestamp of the last time the entry was updated.
    time_t lastUpdateSecs;

    /// 802.11v BSS Transition Management support (as reported via Association Request)
    u_int8_t isBTMSupported : 1;

    /// 802.11k Radio Resource Management support (as reported via Association Request)
    u_int8_t isRRMSupported : 1;

    /// Whether it has Reserved airtime on any BSS
    LBD_BOOL hasReservedAirtime : 1;

    /// The best PHY mode supported across all bands (VHT, HT or basic)
    wlanif_phymode_e bestPHYMode : 2;

    /// State information related to estimating STA data rates and airtimes.
    /// This should be considered opaque to all but the estimator.
    void *estimatorState;

    /// Function to invoke to destroy the estimator state prior to
    /// destroying the overall entry.
    stadbEntry_estimatorStateDestructor_t estimatorStateDestructor;

    /*********************************************************
     * New fields, should replace old ones after refactoring *
     *********************************************************/
    struct {
        /// Whether the data rate info is valid
        LBD_BOOL valid : 1;

        /// The measured downlink data rate for this station
        lbd_linkCapacity_t downlinkRate;

        /// The measured uplink data rate for this station
        lbd_linkCapacity_t uplinkRate;

        /// The time value corresponding to the last point at which the data rate
        /// information was updated.
        time_t lastUpdateSecs;
    } dataRateInfo;

    stadbEntryPriv_bssStats_t bssStats[STADB_ENTRY_MAX_BSS_STATS];
} stadbEntryPriv_t;

/**
 * @brief Create a new station entry with the provided MAC address.
 *
 * @param [in] addr  the MAC address for the new entry
 *
 * @return  the handle to the new entry, or NULL if it could not be created
 */
stadbEntry_handle_t stadbEntryCreate(const struct ether_addr *addr);

/**
 * @brief Mark whether the STA of the provided entry is associated on the
 *        provided band or not.
 *
 * Also mark this device as being an in network device. If it is disassociated,
 * also mark it as inactive.
 *
 * Note that if the call is for a disassociation and the band does not
 * match what is currently thought to be the associated band, no update
 * is made to the currently associated band.
 *
 * If a disassociation occurs shortly after an association
 * (currently within 500ms), the association status is verified
 * in the driver (to make sure we haven't received the updates
 * in the wrong order).
 *
 * If the verifyAssociation parameter is set to LBD_TRUE, the
 * association status is only updated if the STA is currently
 * not marked as associated, and the association status is
 * verified from the driver.  This flag is used for when the
 * association status is inferred due to receiving a RSSI or
 * activity update.  It is possible to receive spurious events,
 * so we don't want to incorrectly update the association in
 * these cases.
 *
 * @param [in] handle  the handle of the entry to update
 * @param [in] bss  the bss on which the assoc/disassoc
 *                  occurred
 * @param [in] isAssociated  LBD_TRUE if the device is now associated;
 *                           LBD_FALSE if the device is now disassociated
 * @param [in] updateActive  flag indicating if the device should be
 *                           marked as active when it is associated
 * @param [in] verifyAssociation  set to LBD_TRUE if the
 *                                association needs to be
 *                                verified
 * @param [out] assocChanged set to LBD_TRUE if the association
 *                           state of the entry changed.  Will
 *                           be ignored if NULL
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntryMarkAssociated(stadbEntry_handle_t handle,
                                    const lbd_bssInfo_t *bss,
                                    LBD_BOOL isAssociated,
                                    LBD_BOOL updateActive,
                                    LBD_BOOL verifyAssociation,
                                    LBD_BOOL *assocChanged);

/**
 * @brief Update whether the STA of the provided entry supports
 *        BSS Transition Management (BTM).  Called after
 *        receiving an association request
 *
 * @param [in] entry  the handle of the entry to update
 * @param [in] isBTMSupported  LBD_TRUE if BTM is supported
 * @param [out]  changed  set to LBD_TRUE if the BTM support
 *                        status changed
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntryUpdateIsBTMSupported(stadbEntry_handle_t entry,
                                          LBD_BOOL isBTMSupported,
                                          LBD_BOOL *changed);

/**
 * @brief Update whether the STA of the provided entry supports
 *        802.11k Radio Resource Management (RRM). Called after
 *        receiving an association request
 *
 * @param [in] entry  the handle of the entry to update
 * @param [in] isRRMSupported  LBD_TRUE if RRM is supported
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntryUpdateIsRRMSupported(stadbEntry_handle_t entry,
                                          LBD_BOOL isRRMSupported);

/**
 * @brief Mark whether the STA is active or not
 *
 * If it is active, also mark the associated band.
 *
 * @param [in] handle  the handle of the entry to update
 * @param [in] bss  the bss on which the activity status change
 *                  occurred
 * @param [in] active  flag indicating if the STA is active or not
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntryMarkActive(stadbEntry_handle_t handle,
                                const lbd_bssInfo_t *bss,
                                LBD_BOOL active);

/**
 * @brief Record the latest RSSI value on the given BSS in the database
 *        entry.
 *
 * @param [in] handle  the handle to the entry to modify
 * @param [in] bss  the BSS on which the RSSI measurement occurred
 * @param [in] rssi  the RSSI measurement
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntryRecordRSSI(stadbEntry_handle_t entry,
                                const lbd_bssInfo_t *bss,
                                lbd_rssi_t rssi);
/**
 * @brief Record the latest probe request RSSI value on the given BSS
 *        in the database entry.
 *
 * @param [in] handle  the handle to the entry to modify
 * @param [in] bss  the BSS on which the RSSI measurement occurred
 * @param [in] rssi  the RSSI measurement
 * @param [in] maxInterval  the number of seconds allowed for this measurement
 *                          to be averaged with previous ones if any
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntryRecordProbeRSSI(stadbEntry_handle_t entry,
                                     const lbd_bssInfo_t *bss,
                                     lbd_rssi_t rssi, time_t maxInterval);

/**
 * @brief Destroy the provided entry.
 *
 * @param [in] handle  the handle to the entry to destroy
 */
void stadbEntryDestroy(stadbEntry_handle_t handle);

/**
 * @brief Compute the hash code for the entry.
 *
 * The hash code is derived from the STA's MAC address.
 *
 * @pre addr is valid
 *
 * @param [in] addr  the address for which to compute the hash code
 *
 * @return  the computed hash code
 */
u_int8_t stadbEntryComputeHashCode(const struct ether_addr *addr);

/**
 * @brief Update PHY capabilities information of a STA on a given BSS
 *
 * This will store the new capabilities in BSS stats entry if
 * the capability entry is valid; otherwise, do nothing.
 *
 * @param [in] entry  the handle of the entry to update
 * @param [in] bssHandle  the handle of BSS stats entry to store PHY capability info
 * @param [in] phyCapInfo  the new PHY capabilities
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntrySetPHYCapInfo(stadbEntry_handle_t entry,
                                   stadbEntry_bssStatsHandle_t bssHandle,
                                   const wlanif_phyCapInfo_t *phyCapInfo);

/**
 * @brief Find the BSS stats entry for the given BSS info
 *
 * If there is a matching BSS stats entry, return it;
 * otherwise, if not require matching BSS only, return
 * 1. an empty slot if any;
 * 2. oldest entry on the same band to overwrite if any
 * 3. oldest entry to overwrite
 *
 * @param [in] handle  the handle to the entry to find BSS stats
 * @param [in] bss  the BSS information to look for an entry
 * @param [in] matchOnly  if true, only find BSS stats entry that matching
 *                        the given BSS info
 *
 * @return the BSS stats handle found, or NULL on failure
 */
stadbEntry_bssStatsHandle_t stadbEntryFindBSSStats(stadbEntry_handle_t handle,
                                                   const lbd_bssInfo_t *bss,
                                                   LBD_BOOL matchOnly);

/**
 * @brief Add reserved airtime on a given BSS to the STA
 *
 * It will mark the BSS/band as supported and set top level
 * hasReservedAirtime flag.
 *
 * @param [in] handle  the handle to the entry to add reserved airtime
 * @param [in] bss  the BSS on which airtime is reserved
 * @param [in] airtime  the reserved airtime
 *
 * @return LBD_OK if the airtime
 */
LBD_STATUS stadbEntryAddReservedAirtime(stadbEntry_handle_t handle,
                                        const lbd_bssInfo_t *bss,
                                        lbd_airtime_t airtime);

/**
 * @brief Handle channel change on a specific VAP
 *
 * If the STA supports that VAP, the channel ID will be updated;
 * otherwise do nothing.
 *
 * @pre entry handle, VAP handle and channel ID are valid
 *
 * @param [in] handle  the handle to the entry
 * @param [in] vap  the VAP on which channel change occurs
 * @param [in] channel  new channel ID
 */
void stadbEntryHandleChannelChange(stadbEntry_handle_t handle,
                                   lbd_vapHandle_t vap,
                                   lbd_channelId_t channel);

/**
 * @brief Emit an association dialog log
 *
 * @param [in] handle  stadb entry to generate log for
 * @param [in] bss  associated BSS to generate log for
 */
void stadbEntryAssocDiagLog(stadbEntry_handle_t handle,
                            const lbd_bssInfo_t *bss);

/**
 * @brief Create BSS entries for BSSes on the same ESS as the
 *        serving BSS if they do not exist.
 *
 * For dual band capable clients, will create BSS entries for both bands;
 * for single band client, will create BSS entries on the same band as the
 * serving BSS.
 *
 * It will also assign PHY capability on the serving BSS to all same band BSSes
 * if it does not have valid PHY capability yet.
 *
 * @pre This should only happen at association time
 *
 * @param [in] handle  the handle to the entry
 * @param [in] servingBSS  the BSS the client entry associates on
 * @param [in] servingPHY  the PHY capability seen on the serving BSS
 */
void stadbEntryPopulateBSSesFromSameESS(stadbEntry_handle_t handle,
                                        const lbd_bssInfo_t *servingBSS,
                                        const wlanif_phyCapInfo_t *servingPHY);

/**
 * @brief Get the ESS ID the STA last associates on
 *
 * @param [in] handle  the handle to the STA entry
 *
 * @return the last associated ESS ID, or LBD_ESSID_INVALID if the STA has
 *         never associated before
 */
lbd_essId_t stadbEntryGetLastServingESS(stadbEntry_handle_t handle);

// --------------------------------------------------------------------
// Debug menu dump routines
// --------------------------------------------------------------------

// Optionally include functions for dumping out individual entries in the
// database.
#ifdef LBD_DBG_MENU
struct cmdContext;

/**
 * @brief Enumeration for different types of detailed information of a STA
 */
typedef enum stadbEntryDBGInfoType_e {
    stadbEntryDBGInfoType_phy,
    stadbEntryDBGInfoType_bss,

    stadbEntryDBGInfoType_rate_measured,
    stadbEntryDBGInfoType_rate_estimated,

    stadbEntryDBGInfoType_invalid,
} stadbEntryDBGInfoType_e;

/**
 * @brief Print the header corresponding to the entry summary information that
 *        will be included.
 *
 * @param [in] context  the output context
 * @param [in] inNetwork  flag indicating if the header is for in-network STAs
 */
void stadbEntryPrintSummaryHeader(struct cmdContext *context, LBD_BOOL inNetwork);

/**
 * @brief Print the summary information for this entry.
 *
 * @param [in] handle  the handle to the STA entry
 * @param [in] context  the output stream
 * @param [in] inNetwork  if set to LBD_TRUE, it should only print in-network entry;
 *                        otherwise, print only out-of-network entry
 */
void stadbEntryPrintSummary(const stadbEntry_handle_t handle,
                            struct cmdContext *context,
                            LBD_BOOL inNetwork);

/**
 * @brief Print the detailed information for this entry
 *
 * @param [in] context  the output stream
 * @param [in] handle  the handle to the STA entry
 * @param [in] infoType  the type of detailed info to print
 * @param [in] listAddr  whether to include MAC address in the output
 */
void stadbEntryPrintDetail(struct cmdContext *context,
                           const stadbEntry_handle_t handle,
                           stadbEntryDBGInfoType_e infoType,
                           LBD_BOOL listAddr);

/**
 * @brief Print the header corresponding to the entry detailed information that
 *        will be included.
 *
 * @param [in] context  the output stream
 * @param [in] infoType  the type of detailed info to print
 * @param [in] listAddr  whether to include MAC address in the output
 */
void stadbEntryPrintDetailHeader(struct cmdContext *context,
                                 stadbEntryDBGInfoType_e infoType,
                                 LBD_BOOL listAddr);
#endif /* LBD_DBG_MENU */


#if defined(__cplusplus)
}
#endif

#endif
