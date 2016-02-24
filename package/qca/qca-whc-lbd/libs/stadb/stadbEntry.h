// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stadbEntry.h
 *
 * @Abstract: A single entry in the station database, corresponding to a known
 *            Wi-Fi STA
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

#ifndef stadbEntry__h
#define stadbEntry__h

#include "lbd.h"  // for LBD_STATUS
#include "wlanif.h"  // for wlanif_band_e

#if defined(__cplusplus)
extern "C" {
#endif
// opaque forward declaration
struct stadbEntryPriv_t;
struct stadbEntryPriv_bssStats_t;
typedef struct stadbEntryPriv_t *stadbEntry_handle_t;
typedef struct stadbEntryPriv_bssStats_t *stadbEntry_bssStatsHandle_t;

// Maximum number of BSS stats per STA
#define STADB_ENTRY_MAX_BSS_STATS 3

/**
 * @brief Function to invoke to request that the steering state be destroyed
 *        prior to the destruction of the entry itself.
 *
 * @param [in] state  the steering state corresponding to the entry being
 *                    destroyed
 */
typedef void (*stadbEntry_steeringStateDestructor_t)(void *state);

/**
 * @brief Function to invoke to request that the station monitor state be
 *        destroyed prior to the destruction of the entry itself.
 *
 * @param [in] state  the station monitor state corresponding to the entry being
 *                    destroyed
 */
typedef void (*stadbEntry_estimatorStateDestructor_t)(void *state);

/**
 * @brief Obtain the MAC address for the provided station entry.
 *
 * @param [in] handle  the handle to the entry for which to obtain the address
 *
 * @return  the MAC address of the entry, or NULL if the entry is invalid
 */
const struct ether_addr *stadbEntry_getAddr(const stadbEntry_handle_t handle);

/**
 * @brief Determine if the provided entry matches the MAC address given.
 *
 * @param [in] handle  the handle to the entry to compare
 * @param [in] addr  the MAC address to compare to
 *
 * @return LBD_TRUE if the addresses match; otherwise LBD_FALSE
 */
LBD_BOOL stadbEntry_isMatchingAddr(const stadbEntry_handle_t handle,
                                   const struct ether_addr *addr);

/**
 * @brief Determine whether the band provided is supported or not for the
 *        given STA.
 *
 * @param [in] handle  the handle to the entry to check
 * @param [in] band  the band for which to check
 *
 * @return LBD_TRUE if the band is supported; otherwise LBD_FALSE
 */
LBD_BOOL stadbEntry_isBandSupported(const stadbEntry_handle_t handle,
                                    wlanif_band_e band);

/**
 * @brief Determine whether the entry provided supports both the 2.4 GHz
 *        and 5 GHz bands.
 *
 * @param [in] handle  the handle to the entry to check
 *
 * @return LBD_TRUE if both bands are supported; otherwise LBD_FALSE
 */
LBD_BOOL stadbEntry_isDualBand(const stadbEntry_handle_t handle);

/**
 * @brief Determine the band on which the device is associated, and
 *        optionally how long ago that occurred.
 *
 * @param [in] handle  the handle of the entry to query
 * @param [out] deltaSecs  the number of seconds that have elapsed since
 *                         the device last associated
 *
 * @return the band on which it is associated, or wlanif_band_invalid if the
 *         device is not currently associated or the handle is invalid
 */
wlanif_band_e stadbEntry_getAssociatedBand(const stadbEntry_handle_t handle,
                                           time_t *deltaSecs);

/**
 * @brief Determine if the device ever associated (and thus should be
 *        considered an in-network device).
 *
 * @param [in] handle  the handle of the entry to query
 *
 * @return LBD_TRUE if the device has been associated; otherwise LBD_FALSE
 */
LBD_BOOL stadbEntry_isInNetwork(const stadbEntry_handle_t handle);

/**
 * @brief Determine how old the entry is (where age is defined as the number
 *        of seconds since it was last updated).
 *
 * @param [in] handle  the handle for which to obtain the age
 * @param [out] ageSecs  the age of the entry, in seconds
 *
 * @return LBD_OK if the entry was found and the age is valid; otherwise
 *         LBD_NOK
 */
LBD_STATUS stadbEntry_getAge(const stadbEntry_handle_t handle, time_t *ageSecs);

/**
 * @brief Obtain the opaque handle stored previously as the steering state
 *        (if there was one).
 *
 * @param [in] handle  the handle of the entry for which to get the steering
 *                     state
 *
 * @return the steering state, or NULL if none has been stored (or the entry
 *         handle is invalid)
 */
void *stadbEntry_getSteeringState(stadbEntry_handle_t handle);

/**
 * @brief Store an opaque steering state pointer in the entry for later lookup.
 *
 * @param [in] handle  the handle of the entry for which to get the steering
 *                     state
 * @param [in] state  the state to store
 * @param [in] destructor  the destructor function to use when cleaning up
 *                         the entry
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntry_setSteeringState(
        stadbEntry_handle_t handle, void *state,
        stadbEntry_steeringStateDestructor_t destructor);

/**
 * @brief Obtain the opaque handle stored previously as the estimator
 *        state (if there was one).
 *
 * @param [in] handle  the handle of the entry for which to get the estimator
 *                     state
 *
 * @return the station monitor state, or NULL if none has been stored (or the entry
 *         handle is invalid)
 */
void *stadbEntry_getEstimatorState(stadbEntry_handle_t handle);

/**
 * @brief Store an opaque estimator state pointer in the entry for later lookup.
 *
 * @param [in] handle  the handle of the entry for which to get the estimator
 *                     state
 * @param [in] state  the state to store
 * @param [in] destructor  the destructor function to use when cleaning up
 *                         the entry
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntry_setEstimatorState(
        stadbEntry_handle_t handle, void *state,
        stadbEntry_estimatorStateDestructor_t destructor);

/**
 * @brief Get activity status of a STA
 *
 * @param [in] handle  the handle for which to check idle status
 * @param [out] active  on success this will contain the activity status of this STA
 * @param [out] deltaSecs  if non-NULL, on success this will contain the number
 *                         of seconds that have elapsed since the last time activity
 *                         status is recorded
 *
 * @return LBD_NOK if the parameters are invalid or the STA is not associated;
 *         otherwise LBD_OK
 */
LBD_STATUS stadbEntry_getActStatus(const stadbEntry_handle_t entry, LBD_BOOL *active, time_t *deltaSecs);

/**
 * @brief Return whether or not BTM is supported for the entry
 * 
 * @param [in] handle entry to check for BTM support
 * 
 * @return LBD_BOOL LBD_TRUE if BTM is supported, false 
 *                  otherwise
 */
LBD_BOOL stadbEntry_isBTMSupported(const stadbEntry_handle_t handle);

/**
 * @brief Return whether or not RRM is supported for the entry
 *
 * @param [in] handle entry to check for RRM support
 *
 * @return LBD_BOOL LBD_TRUE if RRM is supported, false
 *                  otherwise
 */
LBD_BOOL stadbEntry_isRRMSupported(const stadbEntry_handle_t handle);

/**
 * @brief Callback function type for iterating all BSSes supported of a STA to
 *        determine if the BSS info gets filled in the output parameter provided
 *        in the stadbEntry_iterateBSSStats function.
 *
 * For each BSS that should be filled in the output parameter, a non-zero metric
 * must be provided. This metric must be the larger the better.
 *
 * @param [in] entry  the STA entry that is currently examined
 * @param [in] bssHandle  the stats handle of the BSS
 * @param [in] cookie  the argument provided to stadbEntry_iterateBSSStats
 *
 * @return the metric if the BSS meets the requirement; otherwise return 0
 */
typedef u_int32_t (*stadbEntry_iterBSSFunc_t)(stadbEntry_handle_t entry,
                                              stadbEntry_bssStatsHandle_t bssHandle,
                                              void *cookie);
/**
 * @brief Iterate all BSSes of a STA entry, invoking callback function on each BSS
 *
 * @param [in] entry  the STA entry to check
 * @param [in] callback  the callback function to invoke
 * @param [in] cookie  opaque parameter to provide in the callback
 * @param [in|out] maxNumBSS  on input, it specifies maximum number of BSS info entries
 *                            expected; on output, it returns the number of BSS info
 *                            entries populated on success
 * @param [out] bssInfo  If not NULL, fill in the basic information of all BSSes
 *                       meets the requirement on success
 *
 * @return LBD_OK if the iteration succeeds; otherwise return LBD_NOK
 */
LBD_STATUS stadbEntry_iterateBSSStats(stadbEntry_handle_t entry, stadbEntry_iterBSSFunc_t callback,
                                      void *cookie, size_t *maxNumBSS, lbd_bssInfo_t *bssInfo);

/**
 * @brief Query PHY capability information of a STA on a BSS
 *
 * @param [in] entry  the STA to query PHY capability info
 * @param [in] bssHandle  the stats handle of the BSS
 *
 * @return the PHY capability info on success; otherwise return NULL
 */
const wlanif_phyCapInfo_t *
stadbEntry_getPHYCapInfo(const stadbEntry_handle_t entry, const stadbEntry_bssStatsHandle_t bssHandle);

/**
 * @brief Obtain the full capacity information (maximum data rate assuming
 *        STA can monopolize the channel) for a specific STA on a specific
 *        channel on the downlink.
 *
 * Optionally also get the number of seconds that have elapsed since the
 * estimate was updated.
 *
 * @param [in] handle  the handle of the entry from which to retrieve the
 *                     estimated full capacity
 * @param [in] bssHandle  the stats handle of the BSS
 * @param [out] deltaSecs  if non-NULL, on success this will contain the number
 *                         of seconds that have elapsed since the last capacity
 *                         update for this channel
 *
 * @return the last capacity estimate, in Mbps, or LBD_INVALID_LINK_CAP if no
 *         capacity information is available
 */
lbd_linkCapacity_t stadbEntry_getFullCapacity(const stadbEntry_handle_t handle,
                                              const stadbEntry_bssStatsHandle_t bssHandle,
                                              time_t *deltaSecs);

/**
 * @brief Obtain uplink RSSI information of a given entry on a specific BSS
 *
 * @param [in] handle  the handle of the entry from which to retrieve RSSI information
 * @param [in] bssHandle  the stats handle of the BSS
 * @param [out] ageSecs  if not NULL, set to the age of current RSSI value (in seconds) on success
 * @param [out] probeCount  if the RSSI is measured from probe requests, set to the number of
 *                          probe requests being averaged for this value; otherwise, set to 0
 *
 * @return the RSSI value on success; otherwise, return LBD_INVALID_RSSI
 */
lbd_rssi_t stadbEntry_getUplinkRSSI(const stadbEntry_handle_t handle,
                                    const stadbEntry_bssStatsHandle_t bssHandle,
                                    time_t *ageSecs, u_int8_t *probeCount);

/**
 * @brief Set estimated uplink RSSI value for a STA on a specific BSS
 *
 * @param [in] entry  the STA to set RSSI
 * @param [in] bssHandle  the stats handle of the BSS
 * @param [in] rssi  the estimated RSSI value
 *
 * @return LBD_OK on success; otherwise return LBD_NOK
 */
LBD_STATUS stadbEntry_setUplinkRSSI(stadbEntry_handle_t entry,
                                    stadbEntry_bssStatsHandle_t bssHandle,
                                    lbd_rssi_t rssi);

/**
 * @brief Store the estimated full capacity information (maximum data rate
 *        assuming STA can monopolize the channel) for a specific STA on a
 *        specific channel on the downlink.
 *
 * This API is used to update the value stored for a BSS for which stats
 * already exist.
 *
 * @param [in] handle  the handle of the entry from which to store the
 *                     estimated full capacity
 * @param [in] bssHandle  the stats handle of the BSS
 * @param [in] capacity  the estimated capacity, in Mbps
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntry_setFullCapacity(stadbEntry_handle_t handle,
                                      stadbEntry_bssStatsHandle_t bssHandle,
                                      lbd_linkCapacity_t capacity);

/**
 * @brief Store the estimated full capacity information (maximum data rate
 *        assuming STA can monopolize the channel) for a specific STA on a
 *        specific channel on the downlink.
 *
 * This API is used when only the identifying info is known for the BSS. If
 * no existing stats entry exists for the BSS, one will be created.
 *
 * @param [in] handle  the handle of the entry from which to store the
 *                     estimated full capacity
 * @param [in] bss  the BSS on which the measurement is received and full
 *                  capacity is estimated
 * @param [in] capacity  the estimated capacity, in Mbps
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntry_setFullCapacityByBSSInfo(stadbEntry_handle_t handle,
                                               const lbd_bssInfo_t *bss,
                                               lbd_linkCapacity_t capacity);

/**
 * @brief Obtain the current estimated airtime for the given STA on a specific BSS.
 *
 * @param [in] handle  the handle of the entry for which to get airtime
 * @param [in] bssHandle  the stats handle of the BSS
 * @param [out] deltaSecs  if non-NULL, on success this will contain the number
 *                         of seconds that have elapsed since last airtime estimation
 *
 * @return the estimated airtime on the BSS, or LBD_INVALID_AIRTIME
 */
lbd_airtime_t stadbEntry_getAirtime(const stadbEntry_handle_t handle,
                                    const stadbEntry_bssStatsHandle_t bssHandle,
                                    time_t *deltaSecs);

/**
 * @brief Store the estimated airtime for the STA on a specific BSS
 *
 * This API is used to update the value stored for a BSS for which stats
 * already exist.
 *
 * @param [in] handle  the handle of the entry for which to store airtime
 * @param [in] bssHandle  the stats handle of the BSS
 * @param [in] airtime  the estimated airtime
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntry_setAirtime(stadbEntry_handle_t handle,
                                 stadbEntry_bssStatsHandle_t bssHandle,
                                 lbd_airtime_t airtime);

/**
 * @brief Store the estimated airtime for the STA on a given BSS
 *
 * This API is used when only the identifying info is known for the BSS. If
 * no existing stats entry exists for the BSS, one will be created.
 *
 * @param [in] handle  the handle of the entry for which to store airtime
 * @param [in] bss  the BSS on which the measurement is received and airtime
 *                  is estimated
 * @param [in] airtime  the estimated airtime
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntry_setAirtimeByBSSInfo(stadbEntry_handle_t handle,
                                          const lbd_bssInfo_t *bss,
                                          lbd_airtime_t airtime);

/**
 * @brief Obtain the current measured data rate for the given STA.
 *
 * Optionally also get the number of seconds that have elapsed since the
 * estimate was updated.
 *
 * @param [in] handle  the handle of the entry for which to get the data rate
 * @param [out] dlRate  the downlink data rate in Mbps
 * @param [out] ulRate  the uplink data rate in Mbps
 * @param [out] deltaSecs  if non-NULL, on success this will contain the number
 *                         of seconds that have elapsed since the last capacity
 *                         update for this channel
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntry_getLastDataRate(const stadbEntry_handle_t handle,
                                      lbd_linkCapacity_t *dlRate,
                                      lbd_linkCapacity_t *ulRate,
                                      time_t *deltaSecs);

/**
 * @brief Store the current data rates for the STA as seen by its serving AP.
 *
 * @param [in] handle  the handle of the entry for which to store the
 *                     data rate
 * @param [in] txRate  the downlink data rate in Mbps
 * @param [in] rxRate  the uplink data rate in Mbps
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntry_setLastDataRate(stadbEntry_handle_t handle,
                                      lbd_linkCapacity_t dlRate,
                                      lbd_linkCapacity_t ulRate);

/**
 * @brief Determine whether the channel provided is supported or not for the
 *        given STA.
 *
 * @param [in] handle  the handle to the entry to check
 * @param [in] channel  the channel for which to check
 *
 * @return LBD_TRUE if the channel is supported; otherwise LBD_FALSE
 */

LBD_BOOL stadbEntry_isChannelSupported(const stadbEntry_handle_t handle,
                                       lbd_channelId_t channel);

/**
 * @brief Determine the BSS on which the device is associated, and
 *        optionally how long ago that occurred.
 *
 * @param [in] handle  the handle of the entry to query
 * @param [out] deltaSecs  the number of seconds that have elapsed since
 *                         the device last associated
 *
 * @return the BSS handle on which it is associated, or NULL if the device is not
 *         currently associated or the entry handle is invalid
 */
stadbEntry_bssStatsHandle_t stadbEntry_getServingBSS(
        const stadbEntry_handle_t handle, time_t *deltaSecs);

/**
 * @brief Look up BSS info from BSS stats handle
 *
 * @param [in] bssHandle  the BSS handle to check
 *
 * @return the BSS info on success, or NULL if the BSS handle is invalid
 */
const lbd_bssInfo_t *stadbEntry_resolveBSSInfo(const stadbEntry_bssStatsHandle_t bssHandle);

/**
 * @brief Find the BSS stats entry matching the given BSS info
 *
 * @param [in] handle  the handle to the entry to find BSS stats
 * @param [in] bss  the BSS information to look for an entry
 *
 * @return the mathcing BSS stats handle found, or NULL if not found
 */
stadbEntry_bssStatsHandle_t stadbEntry_findMatchBSSStats(stadbEntry_handle_t handle,
                                                         const lbd_bssInfo_t *bss);

/**
 * @brief Check if the given STA has reserved airtime on any BSS
 *
 * @param [in] handle  the handle to the entry to check reserved airtime
 *
 * @return LBD_TRUE if the STA has reserved airtime; otherwise return LBD_FALSE
 */
LBD_BOOL stadbEntry_hasReservedAirtime(stadbEntry_handle_t handle);

/**
 * @brief Obtain the reserved airtime for the STA on the given BSS
 *
 * @param [in] handle  the handle to the STA entry
 * @param [in] bssHandle  the handle to the BSS stats
 *
 * @return the reserved airtime if any; otherwise return LBD_INVALID_AIRTIME
 */
lbd_airtime_t stadbEntry_getReservedAirtime(stadbEntry_handle_t handle,
                                            stadbEntry_bssStatsHandle_t bssHandle);

/**
 * @brief Obtain the best PHY mode supported by the client across all bands
 *
 * @param [in] handle  the handle to the STA entry
 *
 * @return the best PHY mode supported by this STA; return wlanif_phymode_invalid
 *         if the STA is not valid
 */
wlanif_phymode_e stadbEntry_getBestPHYMode(stadbEntry_handle_t handle);

#if defined(__cplusplus)
}
#endif

#endif
