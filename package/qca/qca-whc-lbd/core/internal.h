/*
 * @File: internal.h
 *
 * @Abstract: Load balancing daemon internal header file.
 *
 * @Notes: Macros and functions used by the load balancing daemon
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2011,2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#ifndef internal__h /*once only*/
#define internal__h

#include "lbd.h"
#include <string.h>
#include <stddef.h>
#include <dbg.h>

// ====================================================================
// Helper functions for use across modules
// ====================================================================

/**
 * @brief Helper function to determine if two BSSes are owned by the same
 *        AP (same physical device).
 *
 * @param [in] bss1  the information for the first BSS
 * @param [in] bss2  the information for the second BSS
 *
 * @return LBD_TRUE if they are for the same AP; LBD_FALSE if they are not
 *         or one of more of the values is NULL
 */
static inline LBD_BOOL lbAreBSSInfoSameAP(const lbd_bssInfo_t *bss1,
                                          const lbd_bssInfo_t *bss2) {
    if (bss1 && bss2 && bss1->apId == bss2->apId) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Fills in the fields of a lbd_bssInfo_t structure to
 *        mark it as invalid.
 *
 * @param [in] bss structure to mark as invalid
 */
static inline void lbInvalidateBSSInfo(lbd_bssInfo_t *bss) {
    if (!bss) {
        return;
    }

    bss->apId = LBD_APID_SELF;
    bss->channelId = LBD_CHANNEL_INVALID;
    bss->essId = LBD_ESSID_INVALID;
    bss->vap = LBD_VAP_INVALID;
}

/**
 * @brief Checks if a lbd_bssInfo_t structure is valid.  Note
 *        currently only checks the channelId, since this is
 *        always required to have a valid value.
 *
 * @param [in] bss structure to check for validity
 *
 * @return LBD_BOOL returns LBD_TRUE if valid, LBD_FALSE
 *         otherwise
 */
static inline LBD_BOOL lbIsBSSValid(lbd_bssInfo_t *bss) {
    if (!bss) {
        return LBD_FALSE;
    }

    if (bss->channelId == LBD_CHANNEL_INVALID) {
        return LBD_FALSE;
    } else {
        return LBD_TRUE;
    }
}

/**
 * @brief Check if two lbd_bssInfo_t structures are describing
 *        the same BSS
 *
 * @param [in] bss1 the information for the first BSS
 * @param [in] bss2 the information for the second BSS
 *
 * @return LBD_BOOL returns LBD_TRUE if they are the same,
 *         LBD_FALSE otherwise
 */
static inline LBD_BOOL lbAreBSSesSame(const lbd_bssInfo_t *bss1, const lbd_bssInfo_t *bss2) {
    if (!bss1 || !bss2)  {
        return LBD_FALSE;
    }

    // Compare all fields except the VAP
    if ((bss1->apId == bss2->apId) &&
        (bss1->channelId == bss2->channelId) &&
        (bss1->essId == bss2->essId)) {
        return LBD_TRUE;
    } else {
        return LBD_FALSE;
    }
}

/*
 * lbCopyMACAddr - Copy MAC address variable
 */
#define lbCopyMACAddr(src, dst) memcpy( dst, src, HD_ETH_ADDR_LEN )

/*
 * lbCopyBSSInfo - Copy BSS info structure
 */
#define lbCopyBSSInfo(src, dst) memcpy( dst, src, sizeof(lbd_bssInfo_t) )

/*
 * lbAreEqualMACAddrs - Compare two MAC addresses (returns 1 if equal)
 */
#define lbAreEqualMACAddrs(arg1, arg2) (!memcmp(arg1, arg2, HD_ETH_ADDR_LEN))

/*
 * lbMACAddHash - Create a Hash out of a MAC address
 */
#define lbMACAddHash(_arg) (__lbMidx(_arg, 0) ^ __lbMidx(_arg, 1) ^ __lbMidx(_arg, 2) \
		^ __lbMidx(_arg, 3) ^ __lbMidx(_arg, 4) ^ __lbMidx(_arg, 5)) /* convert to use the HD_ETH_ADDR_LEN constant */

/*
 * lbMACAddFmt - Format a MAC address (use with (s)printf)
 */
#define lbMACAddFmt(_sep) "%02X" _sep "%02X" _sep "%02X" _sep "%02X" _sep "%02X" _sep "%02X"

/*
 * lbMACAddData - MAC Address data octets
 */
#define lbMACAddData(_arg) __lbMidx(_arg, 0), __lbMidx(_arg, 1), __lbMidx(_arg, 2), __lbMidx(_arg, 3), __lbMidx(_arg, 4), __lbMidx(_arg, 5)

#define __lbMidx(_arg, _i) (((u_int8_t *)_arg)[_i])

/**
 * @brief Add the format string for an lbd_bssInfo_t object.
 */
#define lbBSSInfoAddFmt() "APId %-3d ChanId %-3d ESSId %-3d"

/**
 * @brief Add the data members of lbd_bssInfo_t suitable for the format
 *        provided by lbBSSInfoAddFmt() above.
 *
 * @pre bssInfo is non-null
 */
#define lbBSSInfoAddData(bssInfo) \
        (bssInfo)->apId, (bssInfo)->channelId, (bssInfo)->essId

/**
 * @brief Log multiple BSS info
 *
 * @param [in] dbgModule  the module to log the info
 * @param [in] level  the log level
 * @param [in] func  the name of the caller function
 * @param [in] prefix  optional prefix string to log
 * @param [in] numBSSes  number of BSSes to log
 * @param [in] bssInfo  the BSS info to log
 */
static inline void lbLogBSSInfoCandidates(
        struct dbgModule *dbgModule, enum dbgLevel level, const char *func,
        const char *prefix, size_t numBSSes, const lbd_bssInfo_t *bssInfo) {
    if (!dbgModule || !func || !numBSSes || !bssInfo) {
        return;
    }
    dbgf(dbgModule, level, "%s: %s (no. of BSSes: %u):",
         func, prefix ? prefix : "", numBSSes);
    size_t i = 0;
    for (i = 0; i < numBSSes; ++i) {
        dbgf(dbgModule, level, lbBSSInfoAddFmt(), lbBSSInfoAddData((&bssInfo[i])));
    }
}

/**
 * @brief Obtain a timestamp.
 *
 * This is guaranteed to be monotonically increasing.
 *
 * @param [out]  the timestamp obtained
 */
void lbGetTimestamp(struct timespec *ts);

/**
 * @brief Determine if the first time is before the second one.
 *
 * @param [in] time1  the first time
 * @param [in] time2  the second time
 *
 * @return LBD_TRUE if time1 is before time2; otherwise LBD_FALSE
 */
LBD_BOOL lbIsTimeBefore(const struct timespec *time1,
                        const struct timespec *time2);

/**
 * @brief Determine if the first time is after the second one.
 *
 * @param [in] time1  the first time
 * @param [in] time2  the second time
 *
 * @return LBD_TRUE if time1 is after time2; otherwise LBD_FALSE
 */
static inline LBD_BOOL lbIsTimeAfter(const struct timespec *time1,
                                     const struct timespec *time2) {
    return lbIsTimeBefore(time2, time1);
}

/**
 * @brief Get the difference from time2 to time1
 *  
 * @pre time1 is later than or equal to time2 
 *  
 * @param [in] time1  the later time to get the difference to 
 * @param [in] time2  the earlier time to get the difference 
 *                    from
 * @param [out] diff  the difference from time2 to time1 
 */
void lbTimeDiff(const struct timespec *time1,
                const struct timespec *time2,
                struct timespec *diff);

/**
 * @brief Debug log the assertion (and related metadata) and then attempt
 *        clean termination of lbd with an exit status of 1.
 *
 * @param [in] dbg  the module handle to use for debug logging
 * @param [in] assertion  the assertion expression that failed
 * @param [in] filename  the file in which the assertion failed
 * @param [in] line  the line number on which the assertion failed
 * @param [in] function  the function in which the assertion failed
 */
void __lbDbgAssertExit(struct dbgModule *dbg, const char *assertion,
                       const char *filename, unsigned int line,
                       const char *function);

/**
 * @brief Attempt to shutdown lbd cleanly and then exit with a non-zero
 *        status.
 */
void lbdFatalShutdown(void);

#endif
