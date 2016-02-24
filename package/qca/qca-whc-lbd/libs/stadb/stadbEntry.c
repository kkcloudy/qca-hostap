// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stadbEntry.c
 *
 * @Abstract: Implementation of accessors and mutators for stadbEntry
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

#ifdef LBD_DBG_MENU
#include <cmd.h>
#endif

#include "stadbEntry.h"
#include "stadbEntryPrivate.h"
#include "stadbDiaglogDefs.h"

#include "internal.h"
#include "lbd_assert.h"
#include "diaglog.h"

// Forward decls
static void stadbEntryMarkBandSupported(stadbEntry_handle_t handle,
                                        const lbd_bssInfo_t *bss);

static time_t stadbEntryGetTimestamp(void);
static void stadbEntryUpdateTimestamp(stadbEntry_handle_t entry);
static void stadbEntryBSSStatsUpdateTimestamp(stadbEntry_bssStatsHandle_t bssHandle);
static void stadbEntryResetBSSStatsEntry(stadbEntry_bssStatsHandle_t bssHandle,
                                         const lbd_bssInfo_t *newBSS);
static void stadbEntryFindBestPHYMode(stadbEntry_handle_t entry);
static LBD_BOOL stadbEntryIsValidAssociation(const struct timespec *ts,
                                             const lbd_bssInfo_t *bss,
                                             stadbEntry_handle_t entry,
                                             LBD_BOOL checkAssociation);

// Minimum time since association occurred when disassociation message
// is received.  If disassociation is received before this time, verify
// if the STA is really disassociated.  500 ms.
static const struct timespec STADB_ENTRY_MIN_TIME_ASSOCIATION = {0, 500000000};

const struct ether_addr *stadbEntry_getAddr(const stadbEntry_handle_t handle) {
    if (handle) {
        return &handle->addr;
    }

    return NULL;
}

LBD_BOOL stadbEntry_isMatchingAddr(const stadbEntry_handle_t entry,
                                   const struct ether_addr *addr) {
    if (!entry || !addr) {
        return LBD_FALSE;
    }

    return lbAreEqualMACAddrs(entry->addr.ether_addr_octet,
                              addr->ether_addr_octet);
}

LBD_BOOL stadbEntry_isBandSupported(const stadbEntry_handle_t entry,
                                    wlanif_band_e band) {
    if (!entry || band >= wlanif_band_invalid) {
        return LBD_FALSE;
    }

    return (entry->operatingBands & 1 << band) != 0;
}

LBD_BOOL stadbEntry_isDualBand(const stadbEntry_handle_t entry) {
    if (!entry) {
        return LBD_FALSE;
    }

    u_int8_t mask = (1 << wlanif_band_24g | 1 << wlanif_band_5g);
    return (entry->operatingBands & mask) == mask;
}

wlanif_band_e stadbEntry_getAssociatedBand(const stadbEntry_handle_t entry,
                                           time_t *deltaSecs) {
    if (!entry) {
        return wlanif_band_invalid;
    }

    if (!entry->assoc.bssHandle) {
        return wlanif_band_invalid;
    }

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - entry->assoc.lastAssoc.tv_sec;
    }

    return wlanif_resolveBandFromChannelNumber(entry->assoc.bssHandle->bss.channelId);
}

LBD_BOOL stadbEntry_isInNetwork(const stadbEntry_handle_t entry) {
    if (!entry) {
        return LBD_FALSE;
    }

    return entry->assoc.hasAssoc;
}

LBD_STATUS stadbEntry_getAge(const stadbEntry_handle_t entry, time_t *ageSecs) {
    if (!entry || !ageSecs) {
        return LBD_NOK;
    }

    *ageSecs = stadbEntryGetTimestamp() - entry->lastUpdateSecs;
    return LBD_OK;
}

void *stadbEntry_getSteeringState(stadbEntry_handle_t entry) {
    if (entry) {
        return entry->steeringState;
    }

    return NULL;
}

LBD_STATUS stadbEntry_setSteeringState(
        stadbEntry_handle_t entry, void *state,
        stadbEntry_steeringStateDestructor_t destructor) {
    if (!entry || (state && !destructor)) {
        return LBD_NOK;
    }

    entry->steeringState = state;
    entry->steeringStateDestructor = destructor;
    return LBD_OK;
}

void *stadbEntry_getEstimatorState(stadbEntry_handle_t entry) {
    if (entry) {
        return entry->estimatorState;
    }

    return NULL;
}

LBD_STATUS stadbEntry_setEstimatorState(
        stadbEntry_handle_t entry, void *state,
        stadbEntry_estimatorStateDestructor_t destructor) {
    if (!entry || (state && !destructor)) {
        return LBD_NOK;
    }

    entry->estimatorState = state;
    entry->estimatorStateDestructor = destructor;
    return LBD_OK;
}

LBD_STATUS stadbEntry_getActStatus(const stadbEntry_handle_t entry, LBD_BOOL *active, time_t *deltaSecs) {
    if (!entry || !active) {
        return LBD_NOK;
    }

    if (!stadbEntry_getServingBSS(entry, NULL)) {
        // If an entry is not associated, there is no activity status
        return LBD_NOK;
    }

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - entry->activity.lastActUpdate;
    }

    *active = entry->activity.isAct;

    return LBD_OK;
}

// ====================================================================
// "Package" and private helper functions
// ====================================================================

stadbEntry_handle_t stadbEntryCreate(const struct ether_addr *addr) {
    if (!addr) {
        return NULL;
    }

    stadbEntry_handle_t entry = calloc(1, sizeof(stadbEntryPriv_t));
    if (entry) {
        lbCopyMACAddr(addr->ether_addr_octet, entry->addr.ether_addr_octet);
        entry->assoc.channel = LBD_CHANNEL_INVALID;
        entry->assoc.lastServingESS = LBD_ESSID_INVALID;
        stadbEntryUpdateTimestamp(entry);

        // All BSS stats entries should be invalid at this point. But before using
        // a BSS stats entry, need to make sure it is reset so that all fields have
        // invalid values. (Currently done in stadbEntryFindBSSStats)
    }

    return entry;
}

LBD_STATUS stadbEntryRecordRSSI(stadbEntry_handle_t entry,
                                const lbd_bssInfo_t *bss,
                                lbd_rssi_t rssi) {
    if (!entry || !bss) {
        return LBD_NOK;
    }

    time_t curTime = stadbEntryGetTimestamp();
    stadbEntryMarkBandSupported(entry, bss);

    stadbEntry_bssStatsHandle_t bssHandle =
        stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
    bssHandle->valid = LBD_TRUE;

    bssHandle->uplinkInfo.rssi = rssi;
    bssHandle->uplinkInfo.lastUpdateSecs = curTime;
    bssHandle->uplinkInfo.probeCount = 0;
    bssHandle->uplinkInfo.estimate = LBD_FALSE;

    stadbEntryBSSStatsUpdateTimestamp(bssHandle);

    // Since we get a lot of RSSI updates, we don't want to clutter the
    // diaglog stream for those nodes we may not even care about.
    if (stadbEntry_isInNetwork(entry) &&
        diaglog_startEntry(mdModuleID_StaDB,
                           stadb_msgId_rssiUpdate,
                           diaglog_level_demo)) {
        diaglog_writeMAC(&entry->addr);
        diaglog_writeBSSInfo(bss);
        diaglog_write8(rssi);
        diaglog_finishEntry();
    }

    return LBD_OK;
}

LBD_STATUS stadbEntryRecordProbeRSSI(stadbEntry_handle_t entry,
                                     const lbd_bssInfo_t *bss,
                                     lbd_rssi_t rssi, time_t maxInterval) {
    if (!entry || !bss ||
        (entry->assoc.bssHandle && lbAreBSSesSame(bss, &entry->assoc.bssHandle->bss))) {
        // Ignore probes on the associated band since they present an
        // instantaneous measurement and may not be as accurate as our
        // average RSSI report or triggered RSSI measurement which are
        // both taken over a series of measurements.
        return LBD_NOK;
    }

    time_t curTime = stadbEntryGetTimestamp();
    stadbEntryMarkBandSupported(entry, bss);

    stadbEntry_bssStatsHandle_t bssHandle =
        stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
    bssHandle->valid = LBD_TRUE;
    stadbEntryBSSStatsUpdateTimestamp(bssHandle);

    if (!bssHandle->uplinkInfo.probeCount ||
        (curTime - bssHandle->uplinkInfo.lastUpdateSecs) > maxInterval) {
        // Reset probe RSSI averaging
        bssHandle->uplinkInfo.rssi = rssi;
        bssHandle->uplinkInfo.lastUpdateSecs = curTime;
        bssHandle->uplinkInfo.probeCount = 1;
        bssHandle->uplinkInfo.estimate = LBD_FALSE;
    } else {
        // Average this one with previous measurements
        bssHandle->uplinkInfo.rssi =
            (bssHandle->uplinkInfo.rssi * bssHandle->uplinkInfo.probeCount + rssi) /
            (bssHandle->uplinkInfo.probeCount + 1);
        bssHandle->uplinkInfo.lastUpdateSecs = curTime;
        ++bssHandle->uplinkInfo.probeCount;
    }

    // Since we get a lot of RSSI updates, we don't want to clutter the
    // diaglog stream for those nodes we may not even care about.
    if (stadbEntry_isInNetwork(entry) &&
        diaglog_startEntry(mdModuleID_StaDB,
                           stadb_msgId_rssiUpdate,
                           diaglog_level_demo)) {
        diaglog_writeMAC(&entry->addr);
        diaglog_writeBSSInfo(bss);
        // Report averaged probe RSSI
        diaglog_write8(bssHandle->uplinkInfo.rssi);
        diaglog_finishEntry();
    }

    return LBD_OK;
}

LBD_STATUS stadbEntryMarkAssociated(stadbEntry_handle_t entry,
                                    const lbd_bssInfo_t *bss,
                                    LBD_BOOL isAssociated,
                                    LBD_BOOL updateActive,
                                    LBD_BOOL verifyAssociation,
                                    LBD_BOOL *assocChanged) {
    if (assocChanged) {
        *assocChanged = LBD_FALSE;
    }
    if (!entry || !bss) {
        return LBD_NOK;
    }

    // Did the association status change?
    LBD_BOOL assocSame = entry->assoc.bssHandle &&
                         lbAreBSSesSame(&entry->assoc.bssHandle->bss, bss);
    lbd_channelId_t oldAssocChannel = entry->assoc.channel;
    lbd_essId_t oldServingESS = entry->assoc.lastServingESS;

    struct timespec ts;
    lbGetTimestamp(&ts);
    stadbEntryMarkBandSupported(entry, bss);

    if (isAssociated) {
        if (verifyAssociation) {
            if (oldAssocChannel == LBD_CHANNEL_INVALID) {
                // This check should always return LBD_TRUE under normal
                // circumstances.  It is added to be overly cautious and ensure
                // that we only receive notifications on an interface
                // the STA is associated on.
                if (!stadbEntryIsValidAssociation(&ts, bss, entry,
                                                  LBD_TRUE /* checkAssociation */)) {
                    // STA is not actually associated even though we got an
                    // update, ignore.
                    return LBD_OK;
                }
            } else {
                // If we are verifying the association, ignore association
                // updates when we are already associated.  In this case
                // we can't disambiguate the associations (it's caused by
                // an unclean disassociation / spurious messages from firmware),
                // so ignore until one of the entries times out.
                return LBD_OK;
            }
        }

        // Only update the last association time if the VAP on which we
        // previously thought the STA was associated is out of date/wrong.
        if (!assocSame) {
            entry->assoc.lastAssoc = ts;
        }

        stadbEntry_bssStatsHandle_t bssHandle =
            stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
        bssHandle->valid = LBD_TRUE;
        entry->assoc.bssHandle = bssHandle;
        entry->assoc.channel = bss->channelId;
        entry->assoc.hasAssoc = LBD_TRUE;
        entry->assoc.lastServingESS = bss->essId;
        if (updateActive) {
            // Also mark entry as active
            entry->activity.isAct = LBD_TRUE;
            entry->activity.lastActUpdate = ts.tv_sec;
        }
    } else if ((assocSame &&
                stadbEntryIsValidAssociation(&ts, bss, entry,
                                             LBD_FALSE /* checkAssociation */)) ||
               !entry->assoc.bssHandle) {
        entry->assoc.bssHandle = NULL;
        entry->assoc.channel = LBD_CHANNEL_INVALID;

        // An entry that disassociates should be considered in network as it
        // was previously associated. This generally should not happen unless
        // we somehow miss an association event.
        entry->assoc.hasAssoc = LBD_TRUE;

        // Also mark entry as inactive
        entry->activity.isAct = LBD_FALSE;
        entry->activity.lastActUpdate = ts.tv_sec;
    }

    if (oldAssocChannel != entry->assoc.channel ||
        oldServingESS != entry->assoc.lastServingESS) {
        // Association status changed, including ESS change
        if (assocChanged) {
            *assocChanged = LBD_TRUE;
        }

        stadbEntryAssocDiagLog(entry, bss);
    }

    return LBD_OK;
}

LBD_STATUS stadbEntryUpdateIsBTMSupported(stadbEntry_handle_t entry,
                                          LBD_BOOL isBTMSupported,
                                          LBD_BOOL *changed) {
    if (!entry) {
        return LBD_NOK;
    }

    if (changed) {
        if (entry->isBTMSupported == isBTMSupported) {
            *changed = LBD_FALSE;
        } else {
            *changed = LBD_TRUE;
        }
    }

    // update if BTM is supported
    entry->isBTMSupported = isBTMSupported;

    return LBD_OK;
}

LBD_STATUS stadbEntryUpdateIsRRMSupported(stadbEntry_handle_t entry,
                                          LBD_BOOL isRRMSupported) {
    if (!entry) {
        return LBD_NOK;
    }

    // update if RRM is supported
    entry->isRRMSupported = isRRMSupported;

    return LBD_OK;
}

void stadbEntryDestroy(stadbEntry_handle_t entry) {
    if (entry) {
        if (entry->steeringState) {
            lbDbgAssertExit(NULL, entry->steeringStateDestructor);
            entry->steeringStateDestructor(entry->steeringState);
        }
        if (entry->estimatorState) {
            lbDbgAssertExit(NULL, entry->estimatorStateDestructor);
            entry->estimatorStateDestructor(entry->estimatorState);
        }
    }

    free(entry);
}

LBD_STATUS stadbEntryMarkActive(stadbEntry_handle_t entry,
                                const lbd_bssInfo_t *bss,
                                LBD_BOOL active) {
    if (!entry || !bss) {
        return LBD_NOK;
    }

    time_t curTime = stadbEntryGetTimestamp();

    // Only mark the entry as associated if it is being reported as active.
    // If we did it always, we might change the associated band due to the
    // STA having moved from one band to another without cleanly
    // disassociating.
    //
    // For example, if the STA is on 5 GHz and then moves to 2.4 GHz without
    // cleanly disassociating, the driver will still have an activity timer
    // running on 5 GHz. When that expires, if we mark it as associated, we
    // will clobber our current association state (of 2.4 GHz) with this 5 GHz
    // one. This will cause RSSI measurements and steering to be done with the
    // wrong band.
    //
    // Note that we do not update activity status, as it will be done
    // immediately below. We cannot let it mark the activity status as it
    // always sets the status to active for an associated device and inactive
    // for an unassociated device.
    if (active) {
        stadbEntryMarkAssociated(entry, bss, LBD_TRUE, /* isAssociated */
                                 LBD_FALSE /* updateActive */,
                                 LBD_TRUE /* verifyAssociation */,
                                 NULL /* assocChanged */);
    }

    // Only update the activity if the device is associated, as if it is not,
    // we do not know for sure that it is really a legitimate association
    // (see the note above for reasons).
    if (entry->assoc.bssHandle &&
        lbAreBSSesSame(&entry->assoc.bssHandle->bss, bss)) {
        entry->activity.isAct = active;
        entry->activity.lastActUpdate = curTime;

        if (diaglog_startEntry(mdModuleID_StaDB, stadb_msgId_activityUpdate,
                               diaglog_level_demo)) {
            diaglog_writeMAC(&entry->addr);
            diaglog_writeBSSInfo(bss);
            diaglog_write8(entry->activity.isAct);
            diaglog_finishEntry();
        }
    }

    return LBD_OK;
}

/**
 * @brief Mark the provided band as being supported by this entry.
 *
 * @param [in] handle  the handle to the entry to modify
 * @param [in] band  the band to enable for the entry
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
static void stadbEntryMarkBandSupported(stadbEntry_handle_t entry,
                                        const lbd_bssInfo_t *bss) {
    lbDbgAssertExit(NULL, entry && bss);
    LBD_BOOL wasDualBand = stadbEntry_isDualBand(entry);
    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(bss->channelId);
    entry->operatingBands |= 1 << band;
    stadbEntryUpdateTimestamp(entry);

    if (stadbEntry_isInNetwork(entry) &&
        !wasDualBand && stadbEntry_isDualBand(entry) &&
        diaglog_startEntry(mdModuleID_StaDB,
                           stadb_msgId_dualBandUpdate,
                           diaglog_level_demo)) {
        diaglog_writeMAC(&entry->addr);
        diaglog_write8(LBD_TRUE);
        diaglog_finishEntry();
    }
}

/**
 * @brief Determine if an association or disassociation is
 *        valid.
 *
 * On disassociation: Treated as valid if the association is
 * older than STADB_ENTRY_MIN_TIME_ASSOCIATION or the STA is
 * verified as disassociated via wlanif
 *
 * On association: Treated as valid if the STA is verified as
 * associated on bss via wlanif
 *
 * @param [in] ts  current time
 * @param [in] bss BSS to check for association on
 * @param [in] entry  stadb entry to check for association
 * @param [in] checkAssociation  if LBD_TRUE check if STA is
 *                               associated on bss; if LBD_FALSE
 *                               check if STA is disassociated
 *                               on bss
 *
 * @return LBD_TRUE if the association is valid; LBD_FALSE
 *         otherwise
 */
static LBD_BOOL stadbEntryIsValidAssociation(const struct timespec *ts,
                                             const lbd_bssInfo_t *bss,
                                             stadbEntry_handle_t entry,
                                             LBD_BOOL checkAssociation) {
    if (!checkAssociation) {
        // If this is disassociation, check the time relative to the last
        // association.
        struct timespec diff;
        lbTimeDiff(ts, &entry->assoc.lastAssoc, &diff);
        if (lbIsTimeAfter(&diff, &STADB_ENTRY_MIN_TIME_ASSOCIATION)) {
            // The association happened more than the min time ago, treat it as valid
            return LBD_TRUE;
        }
    }

    // Check if the STA is really associated
    LBD_BOOL isAssociation = wlanif_isSTAAssociated(bss, &entry->addr);

    // Check if the association state matches what we were checking for.
    return (isAssociation == checkAssociation);
}

LBD_BOOL stadbEntry_isBTMSupported(const stadbEntry_handle_t entry) {
    lbDbgAssertExit(NULL, entry);

    return entry->isBTMSupported;
}

LBD_BOOL stadbEntry_isRRMSupported(const stadbEntry_handle_t entry) {
    lbDbgAssertExit(NULL, entry);

    return entry->isRRMSupported;
}

/**
 * @brief Get a timestamp in seconds for use in delta computations.
 *
 * @return the current time in seconds
 */
static time_t stadbEntryGetTimestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec;
}

/**
 * @brief Update the timestamp in the entry that stores the last time it was
 *        updated.
 *
 * @param [in] entry   the handle to the entry to update
 */
static void stadbEntryUpdateTimestamp(stadbEntry_handle_t entry) {
    lbDbgAssertExit(NULL, entry);
    entry->lastUpdateSecs = stadbEntryGetTimestamp();
}

u_int8_t stadbEntryComputeHashCode(const struct ether_addr *addr) {
    return lbMACAddHash(addr->ether_addr_octet);
}

#ifdef LBD_DBG_MENU
static const char *stadbEntryChWidthString[] = {
    "20MHz",
    "40MHz",
    "80MHz",
    "NA"
};

static const char *stadbEntryPHYModeString[] = {
    "BASIC",
    "HT",
    "VHT",
    "NA"
};

// Definitions used to help format debug output,
#define MAC_ADDR_STR_LEN 25
#define BSS_INFO_STR_LEN 30
#define ASSOC_STR_LEN (BSS_INFO_STR_LEN + 10) // BSS (age)
#define ACTIVITY_STR_LEN 20
#define PHY_FIELD_LEN 15
#define RSSI_STR_LEN 25 // RSSI (age) (flag)
#define RATE_INFO_FIELD_LEN 15
#define RESERVED_AIRTIME_LEN 15

void stadbEntryPrintSummaryHeader(struct cmdContext *context, LBD_BOOL inNetwork) {
    cmdf(context, "%-*s%-10s%-10s", MAC_ADDR_STR_LEN, "MAC Address", "Age", "Bands");
    if (inNetwork) {
        cmdf(context, "%-*s%-*s%-10s\n",
             ASSOC_STR_LEN, "Assoc? (age)", ACTIVITY_STR_LEN, "Active? (age)", "Flags");
    } else {
        cmdf(context, "\n");
    }
}

void stadbEntryPrintSummary(const stadbEntry_handle_t entry,
                            struct cmdContext *context,
                            LBD_BOOL inNetwork) {
    if (!entry) {
        return;
    } else if (stadbEntry_isInNetwork(entry) ^ inNetwork) {
        return;
    }

    time_t curTime = stadbEntryGetTimestamp();
    cmdf(context, lbMACAddFmt(":") "        %-10u%c%c        ",
         lbMACAddData(entry->addr.ether_addr_octet),
         curTime - entry->lastUpdateSecs,
         stadbEntry_isBandSupported(entry, wlanif_band_24g) ? '2' : ' ',
         stadbEntry_isBandSupported(entry, wlanif_band_5g) ? '5' : ' ');

    if (!inNetwork) {
        cmdf(context, "\n");
        return;
    }

    char assocStr[ASSOC_STR_LEN + 1]; // Add one for null terminator
    if (!entry->assoc.bssHandle) {
        snprintf(assocStr, sizeof(assocStr), "       (%u)",
                 (unsigned int)(curTime - entry->assoc.lastAssoc.tv_sec));
    } else {
        snprintf(assocStr, sizeof(assocStr), lbBSSInfoAddFmt() " (%u)",
                 lbBSSInfoAddData(&entry->assoc.bssHandle->bss),
                 (unsigned int)(curTime - entry->assoc.lastAssoc.tv_sec));
    }
    cmdf(context, "%-*s", ASSOC_STR_LEN, assocStr);

    if (entry->assoc.bssHandle) {
        char activityStr[ACTIVITY_STR_LEN + 1]; // Add one for null terminator
        snprintf(activityStr, sizeof(activityStr), "%-3s (%u)",
                 entry->activity.isAct ? "yes" : "no",
                 (unsigned int)(curTime - entry->activity.lastActUpdate));
        cmdf(context, "%-*s", ACTIVITY_STR_LEN, activityStr);
    } else {
        cmdf(context, "%-*s", ACTIVITY_STR_LEN, " ");
    }

    cmdf(context, "%s%s%s",
         entry->isBTMSupported ? "BTM " : "",
         entry->isRRMSupported ? "RRM " : "",
         entry->hasReservedAirtime ? "RA " : "");

    cmdf(context, "\n");
}

void stadbEntryPrintDetailHeader(struct cmdContext *context,
                                 stadbEntryDBGInfoType_e infoType,
                                 LBD_BOOL listAddr) {
    if (listAddr) {
        cmdf(context, "%-*s", MAC_ADDR_STR_LEN, "MAC Address");
    }
    cmdf(context, "%-*s", BSS_INFO_STR_LEN, "BSS Info");
    switch (infoType) {
        case stadbEntryDBGInfoType_phy:
            cmdf(context, "%-*s%-*s%-*s%-*s%-*s",
                 PHY_FIELD_LEN, "MaxChWidth",
                 PHY_FIELD_LEN, "NumStreams",
                 PHY_FIELD_LEN, "PHYMode",
                 PHY_FIELD_LEN, "MaxMCS",
                 PHY_FIELD_LEN, "MaxTxPower");
            break;
        case stadbEntryDBGInfoType_bss:
            cmdf(context, "%-*s%-*s",
                 RSSI_STR_LEN, "RSSI (age) (flags)",
                 RESERVED_AIRTIME_LEN, "Reserved Airtime");
            break;
        case stadbEntryDBGInfoType_rate_measured:
            cmdf(context, "%-*s%-*s%-*s",
                 RATE_INFO_FIELD_LEN, "DLRate (Mbps)",
                 RATE_INFO_FIELD_LEN, "ULRate (Mbps)",
                 RATE_INFO_FIELD_LEN, "Age (seconds)");
            break;
        case stadbEntryDBGInfoType_rate_estimated:
            cmdf(context, "%-*s%-*s%-*s",
                 RATE_INFO_FIELD_LEN, "fullCap (Mbps)",
                 RATE_INFO_FIELD_LEN, "airtime (%)",
                 RATE_INFO_FIELD_LEN, "Age (seconds)");
            break;
        default:
            break;
    }

    cmdf(context, "\n");
}

/**
 * @brief Parameters used when iterating BSS stats to print
 *        detailed information
 */
typedef struct stadbEntryPrintDetailCBParams_t {
    /// The context to print details
    struct cmdContext *context;
    /// The type of the detailed info to print
    stadbEntryDBGInfoType_e infoType;
    /// Whether to print MAC address
    LBD_BOOL listAddr;
} stadbEntryPrintDetailCBParams_t;

/**
 * @brief Print common information for each detailed info entry of a given STA
 *
 * @param [in] entry  the handle to the STA
 * @param [in] bssHandle  the handle to the BSS stats
 * @param [in] context  the output stream to print
 * @param [in] listAddr  whether to print MAC address
 */
static void stadbEntryPrintDetailCommonInfo(stadbEntry_handle_t entry,
                                            stadbEntry_bssStatsHandle_t bssHandle,
                                            struct cmdContext *context,
                                            LBD_BOOL listAddr) {
    if (listAddr) {
        char macStr[MAC_ADDR_STR_LEN + 1];
        snprintf(macStr, sizeof(macStr), lbMACAddFmt(":"), lbMACAddData(entry->addr.ether_addr_octet));
        cmdf(context, "%-*s", MAC_ADDR_STR_LEN, macStr);
    }

    char bssStr[BSS_INFO_STR_LEN + 1];
    snprintf(bssStr, sizeof(bssStr), lbBSSInfoAddFmt(), lbBSSInfoAddData(&bssHandle->bss));
    cmdf(context, "%-*s", BSS_INFO_STR_LEN, bssStr);
}

/**
 * @brief Callback function to print PHY capability on a BSS of a given STA
 *
 * @param [in] entry  the handle to the STA
 * @param [in] bssHandle  the handle to the BSS
 * @param [in] cookie  the parameters provided to the iteration
 *
 * @return LBD_FALSE (not used)
 */
static LBD_BOOL stadbEntryPrintDetailCB(stadbEntry_handle_t entry,
                                        stadbEntry_bssStatsHandle_t bssHandle,
                                        void *cookie) {
    stadbEntryPrintDetailCBParams_t *params = (stadbEntryPrintDetailCBParams_t *) cookie;

    switch (params->infoType) {
        case stadbEntryDBGInfoType_phy:
            if (bssHandle->phyCapInfo.valid) {
                stadbEntryPrintDetailCommonInfo(entry, bssHandle, params->context, params->listAddr);
                cmdf(params->context, "%-*s%-*u%-*s%-*u%-*u\n",
                     PHY_FIELD_LEN, stadbEntryChWidthString[bssHandle->phyCapInfo.maxChWidth],
                     PHY_FIELD_LEN, bssHandle->phyCapInfo.numStreams,
                     PHY_FIELD_LEN, stadbEntryPHYModeString[bssHandle->phyCapInfo.phyMode],
                     PHY_FIELD_LEN, bssHandle->phyCapInfo.maxMCS,
                     PHY_FIELD_LEN, bssHandle->phyCapInfo.maxTxPower);
            }
            break;
        case stadbEntryDBGInfoType_bss:
            // Always show BSS entry regardless of whether RSSI is valid or not
            stadbEntryPrintDetailCommonInfo(entry, bssHandle, params->context, params->listAddr);
            if (bssHandle->uplinkInfo.rssi != LBD_INVALID_RSSI) {
                char rssiStr[RSSI_STR_LEN + 1];
                time_t curTime = stadbEntryGetTimestamp();
                snprintf(rssiStr, sizeof(rssiStr), "%u (%lu) (%c%c)",
                         bssHandle->uplinkInfo.rssi,
                         curTime - bssHandle->uplinkInfo.lastUpdateSecs,
                         bssHandle->uplinkInfo.probeCount ? 'P' : ' ',
                         bssHandle->uplinkInfo.estimate ? 'E' : ' ');
                cmdf(params->context, "%-*s", RSSI_STR_LEN, rssiStr);
            } else {
                cmdf(params->context, "%-*s", RSSI_STR_LEN, " ");
            }
            if (bssHandle->reservedAirtime != LBD_INVALID_AIRTIME) {
                char airtimeStr[RESERVED_AIRTIME_LEN + 1];
                snprintf(airtimeStr, sizeof(airtimeStr), "%u%%",
                         bssHandle->reservedAirtime);
                cmdf(params->context, "%-*s", RESERVED_AIRTIME_LEN, airtimeStr);
            } else {
                cmdf(params->context, "%-*s", RESERVED_AIRTIME_LEN, " ");
            }
            cmdf(params->context, "\n");
            break;
        case stadbEntryDBGInfoType_rate_estimated:
            if (bssHandle->downlinkInfo.fullCapacity != LBD_INVALID_LINK_CAP) {
                stadbEntryPrintDetailCommonInfo(entry, bssHandle, params->context, params->listAddr);
                time_t curTime = stadbEntryGetTimestamp();
                cmdf(params->context, "%-*u%-*u%-*lu\n",
                     RATE_INFO_FIELD_LEN, bssHandle->downlinkInfo.fullCapacity,
                     RATE_INFO_FIELD_LEN, bssHandle->downlinkInfo.airtime,
                     RATE_INFO_FIELD_LEN, curTime - bssHandle->downlinkInfo.lastUpdateSecs);
            }
            break;
        default:
            break;
    }

    return LBD_FALSE;
}

/**
 * @brief Print the measured rate info of a given STA
 *
 * @param [in] context  the output stream to print
 * @param [in] entry  the handle to the STA
 * @param [in] listAddr  whether to print MAC address
 */
static void stadbEntryPrintMeasuredRate(struct cmdContext *context,
                                        const stadbEntry_handle_t entry,
                                        LBD_BOOL listAddr) {
    if (!entry->assoc.bssHandle || !entry->dataRateInfo.valid) {
        // Ignore not associated STA or STA without measured rate
        return;
    }

    stadbEntryPrintDetailCommonInfo(entry, entry->assoc.bssHandle, context, listAddr);
    time_t curTime = stadbEntryGetTimestamp();
    cmdf(context, "%-*u%-*u%-*lu\n",
         RATE_INFO_FIELD_LEN, entry->dataRateInfo.downlinkRate,
         RATE_INFO_FIELD_LEN, entry->dataRateInfo.uplinkRate,
         RATE_INFO_FIELD_LEN, curTime - entry->dataRateInfo.lastUpdateSecs);

    cmdf(context, "\n");
}

void stadbEntryPrintDetail(struct cmdContext *context,
                           const stadbEntry_handle_t entry,
                           stadbEntryDBGInfoType_e infoType,
                           LBD_BOOL listAddr) {
    if (infoType == stadbEntryDBGInfoType_rate_measured) {
        // Only have one measured rate info per STA
        stadbEntryPrintMeasuredRate(context, entry, listAddr);
    } else {
        // Other info will be one per BSS entry
        stadbEntryPrintDetailCBParams_t params = {
            context, infoType, listAddr
        };
        stadbEntry_iterateBSSStats(entry, stadbEntryPrintDetailCB, &params, NULL, NULL);
    }
}

#undef MAC_ADDR_STR_LEN
#undef BSS_INFO_STR_LEN
#undef ASSOC_STR_LEN
#undef ACTIVITY_STR_LEN
#undef PHY_FIELD_LEN
#undef RSSI_STR_LEN
#undef RATE_INFO_FIELD_LEN

#endif /* LBD_DBG_MENU */

/*****************************************************
 *  New APIs
 ****************************************************/
/**
 * @brief Add BSS that meets requirement to the selected list
 *
 * The list is sorted, and this BSS will be inserted before the entries that
 * have a lower metric than it, or to the end if none. If there are already
 * enough better BSSes selected, do nothing
 *
 * @pre sortedMetrics must be initialized to all 0
 *
 * @param [inout] selectedBSSList  the list to insert BSS
 * @param [inout] sortedMetrics  the list to insert metric, the order must be
 *                               the same as selectedBSSList
 * @param [in] bssStats  the handle to the BSS
 * @param [in] metric  the metric returned from callback function for this BSS
 * @param [in] maxNumBSS  maximum number of BSS requested
 * @param [inout] numBSSSelected  number of BSS being added to the list
 */
static void stadbEntryAddBSSToSelectedList(lbd_bssInfo_t *selectedBSSList,
                                           u_int32_t *sortedMetrics,
                                           stadbEntryPriv_bssStats_t *bssStats,
                                           u_int32_t metric, size_t maxNumBSS,
                                           size_t *numBSSSelected) {
    size_t i;
    for (i = 0; i < maxNumBSS; ++i) {
        if (metric > sortedMetrics[i]) {
            // Need to move all entries from i to right by 1, last one will be discarded
            size_t numEntriesToMove = maxNumBSS - i - 1;
            if (numEntriesToMove) {
                memmove(&selectedBSSList[i + 1], &selectedBSSList[i],
                        sizeof(lbd_bssInfo_t) * numEntriesToMove);
                memmove(&sortedMetrics[i + 1], &sortedMetrics[i],
                        sizeof(u_int32_t) * numEntriesToMove);
            }
            lbCopyBSSInfo(&bssStats->bss, &selectedBSSList[i]);
            sortedMetrics[i] = metric;
            if (*numBSSSelected < maxNumBSS) {
                ++*numBSSSelected;
            }
            return;
        }
    }
}

LBD_STATUS stadbEntry_iterateBSSStats(stadbEntry_handle_t entry, stadbEntry_iterBSSFunc_t callback,
                                      void *cookie, size_t *maxNumBSS, lbd_bssInfo_t *bss) {
    // Sanity check
    if (!entry || !callback || (maxNumBSS && !bss) ||
        ((!maxNumBSS || !(*maxNumBSS)) && bss)) {
        return LBD_NOK;
    }

    size_t i, numBSSSelected = 0;
    stadbEntryPriv_bssStats_t *bssStats = NULL;
    u_int32_t sortedMetrics[STADB_ENTRY_MAX_BSS_STATS] = {0},
              metric = 0;

    for (i = 0; i < STADB_ENTRY_MAX_BSS_STATS; ++i) {
        bssStats = &entry->bssStats[i];
        if (bssStats->valid &&
            (entry->assoc.lastServingESS == LBD_ESSID_INVALID ||
             bssStats->bss.essId == entry->assoc.lastServingESS)) {
            metric = callback(entry, bssStats, cookie);
            if (bss && metric) {
                stadbEntryAddBSSToSelectedList(bss, sortedMetrics, bssStats,
                                               metric, *maxNumBSS, &numBSSSelected);
            }
        }
    }

    if (maxNumBSS) {
        *maxNumBSS = numBSSSelected;
    }

    return LBD_OK;
}

const wlanif_phyCapInfo_t * stadbEntry_getPHYCapInfo(
        const stadbEntry_handle_t entry, const stadbEntry_bssStatsHandle_t bssHandle) {
    if (!entry || !bssHandle || !bssHandle->valid || !bssHandle->phyCapInfo.valid) {
        return NULL;
    }

    return &bssHandle->phyCapInfo;
}

lbd_linkCapacity_t stadbEntry_getFullCapacity(const stadbEntry_handle_t entry,
                                              const stadbEntry_bssStatsHandle_t bssHandle,
                                              time_t *deltaSecs) {
    if (!entry || !bssHandle || !bssHandle->valid) {
        return LBD_INVALID_LINK_CAP;
    }

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - bssHandle->downlinkInfo.lastUpdateSecs;
    }

    return bssHandle->downlinkInfo.fullCapacity;
}

LBD_STATUS stadbEntry_setFullCapacity(stadbEntry_handle_t entry,
                                      stadbEntry_bssStatsHandle_t bssHandle,
                                      lbd_linkCapacity_t capacity) {
    if (!entry || !bssHandle || !bssHandle->valid) {
        return LBD_NOK;
    }

    bssHandle->downlinkInfo.fullCapacity = capacity;
    time_t curTime = stadbEntryGetTimestamp();
    bssHandle->downlinkInfo.lastUpdateSecs = curTime;

    return LBD_OK;
}

LBD_STATUS stadbEntry_setFullCapacityByBSSInfo(stadbEntry_handle_t entry,
                                               const lbd_bssInfo_t *bss,
                                               lbd_linkCapacity_t capacity) {
    if (!entry || !bss) {
        return LBD_NOK;
    }

    stadbEntry_bssStatsHandle_t bssHandle =
        stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
    bssHandle->valid = LBD_TRUE;
    bssHandle->downlinkInfo.fullCapacity = capacity;
    time_t curTime = stadbEntryGetTimestamp();
    bssHandle->downlinkInfo.lastUpdateSecs = curTime;

    stadbEntryBSSStatsUpdateTimestamp(bssHandle);
    return LBD_OK;
}

lbd_rssi_t stadbEntry_getUplinkRSSI(const stadbEntry_handle_t entry,
                                    const stadbEntry_bssStatsHandle_t bssHandle,
                                    time_t *ageSecs, u_int8_t *probeCount) {
    if (!entry || !bssHandle || !bssHandle->valid) {
        return LBD_INVALID_RSSI;
    }

    if (ageSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *ageSecs = curTime - bssHandle->uplinkInfo.lastUpdateSecs;
    }

    if (probeCount) {
        *probeCount = bssHandle->uplinkInfo.probeCount;
    }

    return bssHandle->uplinkInfo.rssi;
}

LBD_STATUS stadbEntry_setUplinkRSSI(stadbEntry_handle_t entry,
                                    stadbEntry_bssStatsHandle_t bssHandle,
                                    lbd_rssi_t rssi) {
    if (!entry || !bssHandle || !bssHandle->valid) {
        return LBD_NOK;
    }

    bssHandle->uplinkInfo.rssi = rssi;
    bssHandle->uplinkInfo.estimate = LBD_TRUE;
    bssHandle->uplinkInfo.lastUpdateSecs = stadbEntryGetTimestamp();
    bssHandle->uplinkInfo.probeCount = 0;

    return LBD_OK;
}

lbd_airtime_t stadbEntry_getAirtime(const stadbEntry_handle_t entry,
                                    const stadbEntry_bssStatsHandle_t bssHandle,
                                    time_t *deltaSecs) {
    if (!entry || !bssHandle || !bssHandle->valid) {
        return LBD_INVALID_AIRTIME;
    }

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - bssHandle->downlinkInfo.lastUpdateSecs;
    }

    return bssHandle->downlinkInfo.airtime;
}

LBD_STATUS stadbEntry_setAirtime(stadbEntry_handle_t entry,
                                 stadbEntry_bssStatsHandle_t bssHandle,
                                 lbd_airtime_t airtime) {
    if (!entry || !bssHandle || !bssHandle->valid) {
        return LBD_NOK;
    }

    bssHandle->downlinkInfo.airtime = airtime;

    return LBD_OK;
}

LBD_STATUS stadbEntry_setAirtimeByBSSInfo(stadbEntry_handle_t entry,
                                          const lbd_bssInfo_t *bss,
                                          lbd_airtime_t airtime) {
    if (!entry || !bss) {
        return LBD_NOK;
    }

    stadbEntry_bssStatsHandle_t bssHandle =
        stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
    bssHandle->valid = LBD_TRUE;
    bssHandle->downlinkInfo.airtime = airtime;

    stadbEntryBSSStatsUpdateTimestamp(bssHandle);
    return LBD_OK;
}

LBD_STATUS stadbEntry_getLastDataRate(const stadbEntry_handle_t entry,
                                      lbd_linkCapacity_t *dlRate,
                                      lbd_linkCapacity_t *ulRate,
                                      time_t *deltaSecs) {
    if (!entry || !dlRate || !ulRate || !entry->dataRateInfo.valid) {
        return LBD_NOK;
    }

    *dlRate = entry->dataRateInfo.downlinkRate;
    *ulRate = entry->dataRateInfo.uplinkRate;

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - entry->dataRateInfo.lastUpdateSecs;
    }

    return LBD_OK;
}

LBD_STATUS stadbEntry_setLastDataRate(stadbEntry_handle_t entry,
                                      lbd_linkCapacity_t dlRate,
                                      lbd_linkCapacity_t ulRate) {
    if (!entry) {
        return LBD_NOK;
    }

    entry->dataRateInfo.valid = LBD_TRUE;
    entry->dataRateInfo.downlinkRate = dlRate;
    entry->dataRateInfo.uplinkRate = ulRate;
    entry->dataRateInfo.lastUpdateSecs = stadbEntryGetTimestamp();

    stadbEntryUpdateTimestamp(entry);
    return LBD_OK;
}

LBD_BOOL stadbEntry_isChannelSupported(const stadbEntry_handle_t entry,
                                       lbd_channelId_t channel) {
    if (!entry) {
        return LBD_FALSE;
    }

    size_t i = 0;
    for (i = 0; i < STADB_ENTRY_MAX_BSS_STATS; ++i) {
        if (entry->bssStats[i].valid &&
            entry->bssStats[i].bss.channelId == channel) {
            return LBD_TRUE;
        }
    }

    return LBD_FALSE;
}

stadbEntry_bssStatsHandle_t stadbEntry_getServingBSS(
        const stadbEntry_handle_t entry, time_t *deltaSecs) {
    if (!entry || !entry->assoc.bssHandle) {
        return NULL;
    }

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - entry->assoc.lastAssoc.tv_sec;
    }
    return entry->assoc.bssHandle;
}

const lbd_bssInfo_t *stadbEntry_resolveBSSInfo(const stadbEntry_bssStatsHandle_t bssHandle) {
    if (!bssHandle) {
        return NULL;
    }

    return &bssHandle->bss;
}

stadbEntry_bssStatsHandle_t stadbEntry_findMatchBSSStats(stadbEntry_handle_t entry,
                                                         const lbd_bssInfo_t *bss) {
    return stadbEntryFindBSSStats(entry, bss, LBD_TRUE /* matchOnly */);
}

stadbEntry_bssStatsHandle_t stadbEntryFindBSSStats(stadbEntry_handle_t entry,
                                                   const lbd_bssInfo_t *bss,
                                                   LBD_BOOL matchOnly) {
    if (!entry || !bss) {
        return NULL;
    }

    stadbEntry_bssStatsHandle_t emptySlot = NULL;
    stadbEntry_bssStatsHandle_t oldestEntry = NULL, oldestSameBandEntry = NULL;

    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(bss->channelId);

    size_t i;
    time_t oldestTime = 0, oldestSameBandTime = 0;
    for (i = 0; i < STADB_ENTRY_MAX_BSS_STATS; ++i) {
        if (entry->bssStats[i].valid &&
            lbAreBSSesSame(bss, &entry->bssStats[i].bss)) {
            // When there is a match, return
            return &entry->bssStats[i];
        } else if (!matchOnly) {
            if (!entry->bssStats[i].valid && !emptySlot) {
                emptySlot = &entry->bssStats[i];
            } else if (wlanif_resolveBandFromChannelNumber(
                           entry->bssStats[i].bss.channelId) == band) {
                if (!oldestSameBandEntry ||
                    entry->bssStats[i].lastUpdateSecs < oldestSameBandTime) {
                    oldestSameBandEntry = &entry->bssStats[i];
                    oldestSameBandTime = entry->bssStats[i].lastUpdateSecs;
                }
            } else if (!oldestEntry ||
                       entry->bssStats[i].lastUpdateSecs < oldestTime) {
                 oldestEntry = &entry->bssStats[i];
                 oldestTime = entry->bssStats[i].lastUpdateSecs;
            }
        }
    }

    if (matchOnly) {
        return NULL;
    }

    if (emptySlot) {
        stadbEntryResetBSSStatsEntry(emptySlot, bss);
        return emptySlot;
    } else if (oldestSameBandEntry) {
        // For same band entry, PHY information is likely to be the same,
        // so keep it until next update while clearing all other info
        wlanif_phyCapInfo_t phyCapInfo = oldestSameBandEntry->phyCapInfo;
        stadbEntryResetBSSStatsEntry(oldestSameBandEntry, bss);
        memcpy(&oldestSameBandEntry->phyCapInfo, &phyCapInfo, sizeof(phyCapInfo));
        return oldestSameBandEntry;
    } else {
        lbDbgAssertExit(NULL, oldestEntry);
        stadbEntryResetBSSStatsEntry(oldestEntry, bss);
        return oldestEntry;
    }
}

LBD_STATUS stadbEntrySetPHYCapInfo(stadbEntry_handle_t entry,
                                   stadbEntry_bssStatsHandle_t bssHandle,
                                   const wlanif_phyCapInfo_t *phyCapInfo) {
    if (!entry || !bssHandle || !phyCapInfo || !phyCapInfo->valid) {
        return LBD_NOK;
    }

    bssHandle->valid = LBD_TRUE;
    stadbEntryBSSStatsUpdateTimestamp(bssHandle);

    if (memcmp(phyCapInfo, &bssHandle->phyCapInfo, sizeof(wlanif_phyCapInfo_t))) {
        memcpy(&bssHandle->phyCapInfo, phyCapInfo, sizeof(wlanif_phyCapInfo_t));
        // In case a client advertised 802.11ac support at one point gets downgraded
        // to 802.11n mode only on 5 GHz, we re-examine PHY modes across all BSSes
        // whenever there is a PHY capability info change on association
        stadbEntryFindBestPHYMode(entry);
    }

    return LBD_OK;
}

/**
 * @brief Find the best PHY mode supported by a STA across all BSSes
 *
 * @param [in] entry  the handle to the STA entry
 */
static void stadbEntryFindBestPHYMode(stadbEntry_handle_t entry) {
    entry->bestPHYMode = wlanif_phymode_basic;

    size_t i = 0;
    for (i = 0; i < STADB_ENTRY_MAX_BSS_STATS; ++i) {
        stadbEntryPriv_bssStats_t *bssStats = &entry->bssStats[i];

        if (bssStats->valid && bssStats->phyCapInfo.valid) {
            wlanif_phymode_e phyMode = bssStats->phyCapInfo.phyMode;
            if (phyMode != wlanif_phymode_invalid && phyMode > entry->bestPHYMode) {
                entry->bestPHYMode = phyMode;
            }
        }
    }
}

/**
 * @brief Update the timestamp of a BSS stats entry
 *
 * The caller should confirm the entry is valid
 *
 * @param [in] bssHandle  the handle to the BSS entry to be updated
 */
static void stadbEntryBSSStatsUpdateTimestamp(stadbEntry_bssStatsHandle_t bssHandle) {
    lbDbgAssertExit(NULL, bssHandle && bssHandle->valid);
    bssHandle->lastUpdateSecs = stadbEntryGetTimestamp();
}

LBD_STATUS stadbEntryAddReservedAirtime(stadbEntry_handle_t entry,
                                        const lbd_bssInfo_t *bss,
                                        lbd_airtime_t airtime) {
    if (!entry || !bss || airtime == LBD_INVALID_AIRTIME) {
        return LBD_NOK;
    }

    stadbEntry_bssStatsHandle_t bssHandle =
        stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
    lbDbgAssertExit(NULL, bssHandle);

    bssHandle->valid = LBD_TRUE;
    bssHandle->reservedAirtime = airtime;
    stadbEntryBSSStatsUpdateTimestamp(bssHandle);

    entry->hasReservedAirtime = LBD_TRUE;
    // Mark the STA as in-network device and mark band as supported
    entry->assoc.hasAssoc = LBD_TRUE;
    stadbEntryMarkBandSupported(entry, bss);

    return LBD_OK;
}

LBD_BOOL stadbEntry_hasReservedAirtime(stadbEntry_handle_t handle) {
    if (!handle) { return LBD_FALSE; }

    return handle->hasReservedAirtime;
}

lbd_airtime_t stadbEntry_getReservedAirtime(stadbEntry_handle_t handle,
                                            stadbEntry_bssStatsHandle_t bssHandle) {
    if (!handle || !bssHandle || !bssHandle->valid) {
        return LBD_INVALID_AIRTIME;
    }

    return bssHandle->reservedAirtime;
}

/**
 * @brief Reset a BSS stats entry with new BSS info
 *
 * All other fields should be set to invalid values.
 *
 * @param [in] bssStats  the entry to be reset
 * @param [in] newBSS  the new BSS info to be assigned to the entry
 */
static void stadbEntryResetBSSStatsEntry(stadbEntry_bssStatsHandle_t bssStats,
                                         const lbd_bssInfo_t *newBSS) {
    memset(bssStats, 0, sizeof(*bssStats));
    bssStats->reservedAirtime = LBD_INVALID_AIRTIME;
    lbCopyBSSInfo(newBSS, &bssStats->bss);
}

wlanif_phymode_e stadbEntry_getBestPHYMode(stadbEntry_handle_t entry) {
    if (!entry) { return wlanif_phymode_invalid; }

    // If there is no PHY cap info for this client yet, it will return
    // wlanif_phymode_basic since this field is 0 initialized at entry
    // creation time.
    return entry->bestPHYMode;
}

void stadbEntryHandleChannelChange(stadbEntry_handle_t entry,
                                   lbd_vapHandle_t vap,
                                   lbd_channelId_t channelId) {
    size_t i = 0;
    for (i = 0; i < STADB_ENTRY_MAX_BSS_STATS; ++i) {
        stadbEntryPriv_bssStats_t *bssStats = &entry->bssStats[i];
        if (bssStats->valid && bssStats->bss.vap == vap) {
            bssStats->bss.channelId = channelId;
            // The new channel may have a different TX power, so nuke RSSI
            // here to allow a new one filled in.
            memset(&bssStats->uplinkInfo, 0, sizeof(bssStats->uplinkInfo));
            bssStats->uplinkInfo.rssi = LBD_INVALID_RSSI;
            bssStats->uplinkInfo.lastUpdateSecs = 0xFFFFFFFF;
            break;
        }
    }
}

void stadbEntryAssocDiagLog(stadbEntry_handle_t entry,
                            const lbd_bssInfo_t *bss) {
    if (diaglog_startEntry(mdModuleID_StaDB,
                           stadb_msgId_associationUpdate,
                           diaglog_level_demo)) {
        diaglog_writeMAC(&entry->addr);
        diaglog_writeBSSInfo(bss);
        diaglog_write8(entry->assoc.bssHandle != NULL);
        diaglog_write8(entry->activity.isAct);
        diaglog_write8(stadbEntry_isDualBand(entry));
        diaglog_write8(entry->isBTMSupported);
        diaglog_write8(entry->isRRMSupported);
        diaglog_finishEntry();
    }
}

void stadbEntryPopulateBSSesFromSameESS(stadbEntry_handle_t entry,
                                        const lbd_bssInfo_t *servingBSS,
                                        const wlanif_phyCapInfo_t *servingPHY) {
    if (!entry || !servingBSS || !servingPHY) { return; }

    size_t maxNumBSSes = STADB_ENTRY_MAX_BSS_STATS - 1; // exclude serving BSS
    lbd_bssInfo_t bss[maxNumBSSes];

    if (LBD_NOK == wlanif_getBSSesSameESS(servingBSS,
                                          !stadbEntry_isDualBand(entry),
                                          &maxNumBSSes, bss) ||
        !maxNumBSSes) {
        // No other BSSes on the serving ESS
        return;
    }

    wlanif_band_e servingBand = wlanif_resolveBandFromChannelNumber(servingBSS->channelId);
    size_t i;
    for (i = 0; i < maxNumBSSes; ++i) {
        // Create a BSS entry for all same ESS BSSes if they do not exist
        stadbEntry_bssStatsHandle_t bssHandle =
            stadbEntryFindBSSStats(entry, &bss[i], LBD_FALSE /* matchOnly */);
        bssHandle->valid = LBD_TRUE;
        // Assign PHY capability to same band BSS if it does not have a valid one
        if ((wlanif_resolveBandFromChannelNumber(bss[i].channelId) == servingBand) &&
            !bssHandle->phyCapInfo.valid && servingPHY->valid) {
            memcpy(&bssHandle->phyCapInfo, servingPHY, sizeof(wlanif_phyCapInfo_t));
        }
        // It's not an update happening on this BSS entry, so no timestamp update
    }
}

lbd_essId_t stadbEntryGetLastServingESS(stadbEntry_handle_t entry) {
    lbDbgAssertExit(NULL, entry);

    return entry->assoc.lastServingESS;
}
