// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorSNRToPhyRate.c
 *
 * @Abstract: Private helper for conversion from an SNR to a PHY rate.
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

#include <dbg.h>

#include "internal.h"
#include "lbd_assert.h"
#include "estimatorRCPIToPhyRate.h"
#include "estimatorSNRToPhyRateTable.h"

// Constants

/**
 * @brief The expected total noise value (noise floor plus noise figure)
 *        based on the channel width.
 */
static const int8_t NOISE_OFFSET_BY_CH_WIDTH[wlanif_chwidth_invalid] = {
    -94,  // 20 MHz
    -91,  // 40 MHz
    -88,  // 80 MHz
};

// Forward decls
static void estimatorRCPIToPhyRateResolveMinPhyCap(
        const wlanif_phyCapInfo_t *bssCap, const wlanif_phyCapInfo_t *staCap,
        wlanif_phyCapInfo_t *minCap);
static lbd_snr_t estimatorRCPIToPhyRateEstimateSNR(struct dbgModule *dbgModule,
                                                   int8_t rcpi,
                                                   wlanif_chwidth_e chwidth);

// ====================================================================
// Package level APIs
// ====================================================================
lbd_linkCapacity_t estimatorEstimateFullCapacityFromRCPI(
        struct dbgModule *dbgModule,
        stadbEntry_handle_t entry, const lbd_bssInfo_t *targetBSSInfo,
        stadbEntry_bssStatsHandle_t measuredBSS, int8_t rcpi,
        u_int8_t measuredBSSTxPower) {
    // We need to get both the AP and STA capabilities on the target
    // BSS so we can take the lowest common denominator.
    const wlanif_phyCapInfo_t *bssCap = wlanif_getBSSPHYCapInfo(targetBSSInfo);
    if (!bssCap || !bssCap->valid) {
        dbgf(dbgModule, DBGERR, "%s: Failed to resolve BSS capabilities for "
                                lbBSSInfoAddFmt(),
             __func__, lbBSSInfoAddData(targetBSSInfo));
        return LBD_INVALID_LINK_CAP;
    }

    // Adjust RCPI value based on relative powers on the measured and target BSSes
    // if both are valid.
    if (measuredBSSTxPower) {
        rcpi += bssCap->maxTxPower - measuredBSSTxPower;
    }

    const struct ether_addr *addr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(dbgModule, addr);

    const wlanif_phyCapInfo_t *staCap =
        stadbEntry_getPHYCapInfo(entry, measuredBSS);
    if (!staCap || !staCap->valid) {
        dbgf(dbgModule, DBGERR,
             "%s: Failed to resolve STA capaiblities for " lbMACAddFmt(":")
             " on " lbBSSInfoAddFmt(), __func__,
             lbMACAddData(addr->ether_addr_octet),
             lbBSSInfoAddData(targetBSSInfo));
        return LBD_INVALID_LINK_CAP;
    }

    wlanif_phyCapInfo_t minPhyCap;
    estimatorRCPIToPhyRateResolveMinPhyCap(bssCap, staCap, &minPhyCap);

    lbd_snr_t snr = estimatorRCPIToPhyRateEstimateSNR(dbgModule, rcpi,
                                                      minPhyCap.maxChWidth);

    lbd_linkCapacity_t capacity =
        estimatorSNRToPhyRateTablePerformLookup(dbgModule, minPhyCap.phyMode,
                                                minPhyCap.maxChWidth,
                                                minPhyCap.numStreams,
                                                minPhyCap.maxMCS,
                                                snr);

    if (LBD_INVALID_LINK_CAP == capacity) {
        dbgf(dbgModule, DBGERR,
             "%s: No supported PHY rate for " lbMACAddFmt(":") " on "
             lbBSSInfoAddFmt() " using PhyMode [%u] ChWidth [%u] "
             "NumStreams [%u] MaxMCS [%u] SNR [%u]",
             __func__, lbMACAddData(addr->ether_addr_octet),
             lbBSSInfoAddData(targetBSSInfo),
             minPhyCap.phyMode, minPhyCap.maxChWidth, minPhyCap.numStreams,
             minPhyCap.maxMCS, snr);
    } else {
        dbgf(dbgModule, DBGDUMP,
             "%s: Estimated capacity for STA " lbMACAddFmt(":") " of %u Mbps "
             "using PhyMode [%u] ChWidth [%u] NumStreams [%u] MaxMCS [%u] "
             "SNR [%u]",
             __func__, lbMACAddData(addr->ether_addr_octet), capacity,
             minPhyCap.phyMode, minPhyCap.maxChWidth, minPhyCap.numStreams,
             minPhyCap.maxMCS, snr);
    }
    return capacity;
}

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Determine the minimum capability set of the two provided and
 *        store it in the output parameter.
 *
 * @param [in] bssCap  the resolved capabilities of the BSS
 * @param [in] staCap  the resolved capabilities of the STA
 * @param [out] minCapp  the minimum capability set
 */
static void estimatorRCPIToPhyRateResolveMinPhyCap(
        const wlanif_phyCapInfo_t *bssCap, const wlanif_phyCapInfo_t *staCap,
        wlanif_phyCapInfo_t *minCap) {
    // Assume the STA is less capable and then fix up as necessary.
    *minCap = *staCap;

    if (bssCap->phyMode < minCap->phyMode) {
        minCap->phyMode = bssCap->phyMode;
    }

    if (bssCap->maxChWidth < minCap->maxChWidth) {
        minCap->maxChWidth = bssCap->maxChWidth;
    }

    if (bssCap->numStreams < minCap->numStreams) {
        minCap->numStreams = bssCap->numStreams;
    }

    if (bssCap->maxMCS < minCap->maxMCS) {
        minCap->maxMCS = bssCap->maxMCS;
    }
}

/**
 * @brief Estimate the SNR from an RCPI value and the channel width.
 *
 * @param [in] dbgModule  the module to use for logging errors
 * @param [in] rcpi  the value reported by the STA
 * @param [in] chwidth  the channel width for which to estimate the SNR
 *
 * @return the estimated SNR
 */
static lbd_snr_t estimatorRCPIToPhyRateEstimateSNR(struct dbgModule *dbgModule,
                                                   int8_t rcpi,
                                                   wlanif_chwidth_e chwidth) {
    lbDbgAssertExit(dbgModule, chwidth < wlanif_chwidth_invalid);
    return rcpi - NOISE_OFFSET_BY_CH_WIDTH[chwidth];
}
