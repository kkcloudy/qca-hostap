// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanif.h
 *
 * @Abstract: Load balancing daemon WLAN interface
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

#ifndef wlanif__h
#define wlanif__h

#include <netinet/ether.h>

#include "lbd.h"
#include "ieee80211_external.h"

// ====================================================================
// Types exposed purely for logging purposes
// ====================================================================

/**
 * @brief The diagnostic logging message IDs generated by this module.
 */
typedef enum wlanif_msgId_e {
    /// Raw utilization measurement: 8-bit band + 8-bit utilization
    wlanif_msgId_rawChanUtilization,

    /// Raw RSSI measurement: MAC + 8-bit band + 8-bit RSSI
    wlanif_msgId_rawRSSI,

    /// Interface information
    wlanif_msgId_interface
} wlanif_msgId_e;

// ====================================================================
// Common types exported to other modules
// ====================================================================


#define WLANIF_MAX_RADIOS 3  // looking forward to tri-radio platforms

/**
 * @brief Type that denotes the Wi-Fi band.
 *
 * This type is only for use within the Load Balancing Daemon.
 */
typedef enum wlanif_band_e {
    wlanif_band_24g,   ///< 2.4 GHz
    wlanif_band_5g,    ///< 5 GHz
    wlanif_band_invalid,  ///< band is not known or is invalid
} wlanif_band_e;

/**
 * @brief IDs of events that are generated from this module.
 */
typedef enum wlanif_event_e {
    wlanif_event_probereq,    ///< RX'ed probe request
    wlanif_event_authrej,     ///< TX'ed authentication message with failure

    wlanif_event_act_change,  ///< RX'ed activity change

    wlanif_event_assoc,       ///< A client associated
    wlanif_event_disassoc,    ///< A client disassociated

    wlanif_event_chan_util,   ///< Channel utilization measurement
    wlanif_event_vap_restart, ///< VAP was restarted (eg. due to channel
                              ///< change or a down/up)

    wlanif_event_rssi_xing,   ///< RSSI crossing threshold

    wlanif_event_rssi_measurement, ///< RSSI measurement

    wlanif_event_band_steering_state,  ///< Band steering on/off change

    wlanif_event_btm_response, ///< RX'ed BSS Transition Management response frame

    wlanif_event_beacon_report,  ///< 802.11k beacon report received

    wlanif_event_tx_rate_xing,   ///< Tx rate crossing threshold

    wlanif_event_maxnum
} wlanif_event_e;

/**
 * @brief The format of the wlanif_event_probereq event.
 */
typedef struct wlanif_probeReqEvent_t {
    /// Address of the STA that sent the probe request.
    struct ether_addr sta_addr;

    /// The BSS on which the probe request was sent.
    lbd_bssInfo_t bss;

    /// The measured RSSI of the probe request.
    u_int8_t rssi;
} wlanif_probeReqEvent_t;

/**
 * @brief The format of the wlanif_event_authrej event.
 */
typedef struct wlanif_authRejEvent_t {
    /// Address of the STA that sent the authentication message and that
    /// is being refused admission due to an ACL.
    struct ether_addr sta_addr;

    /// The BSS on which the message was sent.
    lbd_bssInfo_t bss;

    /// The measured RSSI of the received authentication message.
    u_int8_t rssi;
} wlanif_authRejEvent_t;

/**
 * @brief The format of the wlanif_event_act_change event.
 */
typedef struct wlanif_actChangeEvent_t {
    /// Address of the STA whose activity status changed.
    struct ether_addr sta_addr;

    /// BSS on which the change occurred
    lbd_bssInfo_t bss;

    /// The activity status
    LBD_BOOL active;
} wlanif_actChangeEvent_t;

/**
 * @brief Type of update of STA capability state
 */
typedef enum wlanif_capStateUpdate_e {
    wlanif_cap_enabled = 0,
    wlanif_cap_disabled = 1,
    wlanif_cap_unchanged = 2,

    wlanif_cap_invalid
} wlanif_capStateUpdate_e;

/**
 * @brief Enumerations for bandwidth (MHz) supported by STA
 */
typedef enum wlanif_chwidth_e {
    wlanif_chwidth_20,
    wlanif_chwidth_40,
    wlanif_chwidth_80,
    wlanif_chwidth_160,

    wlanif_chwidth_invalid
} wlanif_chwidth_e;

/**
 * @brief Enumerations for IEEE802.11 PHY mode
 */
typedef enum wlanif_phymode_e {
    wlanif_phymode_basic,
    wlanif_phymode_ht,
    wlanif_phymode_vht,

    wlanif_phymode_invalid
} wlanif_phymode_e;

/**
 * @brief PHY capabilities supported by a VAP or client
 */
typedef struct wlanif_phyCapInfo_t {
    /// Flag indicating if this PHY capability entry is valid or not
    LBD_BOOL valid : 1;

    /// The maximum bandwidth supported by this STA
    wlanif_chwidth_e maxChWidth : 3;

    /// The spatial streams supported by this STA
    u_int8_t numStreams : 4;

    /// The PHY mode supported by this STA
    wlanif_phymode_e phyMode : 8;

    /// The maximum MCS supported by this STA
    u_int8_t maxMCS;

    /// The maximum TX power supporetd by this STA
    u_int8_t maxTxPower;
} wlanif_phyCapInfo_t;

/**
 * @brief The format of the wlanif_event_assoc and wlanif_event_disassoc
 *        events.
 *
 * These events carry the same payload and thus share the same event
 * structure.
 */
typedef struct wlanif_assocEvent_t {
    /// Address of the STA that associated/disassociated.
    struct ether_addr sta_addr;

    /// The BSS on which the change occurred
    lbd_bssInfo_t bss;

    /// Indicate if BTM is supported (set to wlanif_cap_unchanged if unknown at this time)
    wlanif_capStateUpdate_e btmStatus;

    /// Indicate if RRM is supported (set to wlanif_cap_unchanged if unknown at this time)
    wlanif_capStateUpdate_e rrmStatus;

    /// PHY capabilities supported
    wlanif_phyCapInfo_t phyCapInfo;
} wlanif_assocEvent_t;

/**
 * @brief The format of the wlanif_event_chan_util event.
 */
typedef struct wlanif_chanUtilEvent_t {
    /// The BSS on which the STA is associated.
    lbd_bssInfo_t bss;

    /// The channel utilization as a percentage.
    u_int8_t utilization;
} wlanif_chanUtilEvent_t;

/**
 * @brief The format of the wlanif_vap_restart event.
 */
typedef struct wlanif_vapRestartEvent_t {
    /// The band on which the VAP was restarted.
    wlanif_band_e band;
} wlanif_vapRestartEvent_t;

/**
 * @brief Enum types denote crossing direction
 */
typedef enum {
    wlanif_xing_unchanged = 0,
    wlanif_xing_up = 1,
    wlanif_xing_down = 2,

    wlanif_xing_invalid
} wlanif_xingDirection_e;

/**
 * @brief The format of the wlanif_event_rssi_xing event
 */
typedef struct wlanif_rssiXingEvent_t {
    /// Address of the STA whose RSSI is reported.
    struct ether_addr sta_addr;

    /// The BSS on which the STA is associated.
    lbd_bssInfo_t bss;

    /// The RSSI measurement
    u_int8_t rssi;

    /// Flag indicating if it crossed inactivity RSSI threshold
    wlanif_xingDirection_e inactRSSIXing;

    /// Flag indicating if it crossed low RSSI threshold
    wlanif_xingDirection_e lowRSSIXing;

    /// Flag indicating if it crossed the rate based RSSI threshold
    wlanif_xingDirection_e rateRSSIXing;
} wlanif_rssiXingEvent_t;

/**
 * @brief The format of the wlanif_event_tx_rate_xing event
 */
typedef struct wlanif_txRateXingEvent_t {
    /// Address of the STA whose Tx rate is reported.
    struct ether_addr sta_addr;

    /// The BSS on which the STA is associated.
    lbd_bssInfo_t bss;

    /// The Tx rate (Kbps).
    u_int32_t tx_rate;

    /// Flag indicating direction of the crossing.
    wlanif_xingDirection_e xing;
} wlanif_txRateXingEvent_t;

/**
 * @brief The format of the wlanif_event_rssi_measurement event
 */
typedef struct wlanif_rssiMeasurementEvent_t {
    /// Address of the STA whose RSSI is reported.
    struct ether_addr sta_addr;

    /// The BSS on which the STA is associated.
    lbd_bssInfo_t bss;

    /// The RSSI measurement
    u_int8_t rssi;
} wlanif_rssiMeasurementEvent_t;

/**
 * @brief The format of the wlanif_event_band_steering_state event.
 */
typedef struct wlanif_bandSteeringStateEvent_t {
    /// Whether band steering is enabled.
    LBD_BOOL enabled;
} wlanif_bandSteeringStateEvent_t;

/**
 * @brief The format of the wlanif_event_btm_response event.
 */
typedef struct wlanif_btmResponseEvent_t {
    /// Token for the corresponding request frame.
    u_int8_t dialog_token;

    /// MAC address of the sending station.
    struct ether_addr sta_addr;

    /// Status of the response to the request frame.
    enum IEEE80211_WNM_BSTM_RESP_STATUS status;

    /// Number of minutes that the STA requests the BSS to delay termination.
    u_int8_t termination_delay;

    /// BSSID of the BSS that the STA transitions to.
   struct ether_addr target_bssid;
} wlanif_btmResponseEvent_t;

/**
 * @brief Parameters for a BTM candidate list
 */
typedef struct wlanif_btmCandidate_t {
    /// Target BSSID
    struct ether_addr bssid;

    /// Channel the target BSSID is operating on
    u_int8_t channel;

    /// Preference for this target BSSID (higher number is higher preference)
    u_int8_t preference;
} wlanif_btmCandidate_t;

/**
 * @brief The format of the wlanif_event_beacon_report event.
 */
typedef struct wlanif_beaconReportEvent_t {
    /// Flag indicating if the beacon report is valid or not
    LBD_BOOL valid;

    /// MAC address of the STA where beacon report is received
    struct ether_addr sta_addr;

    /// The first BSS reported in the beacon report message.
    lbd_bssInfo_t reportedBss;

    /// The RCPI measurement reported
    int8_t rcpi;
} wlanif_beaconReportEvent_t;

/**
 * @brief Callback function when dumping the associated STAs.
 *
 * @param [in] addr  the MAC address of the associated STA
 * @param [in] bss  the bss the STA is associated to
 * @param [in] isBTMSupported set to LBD_TRUE if BTM is
 *                            supported, LBD_FALSE otherwise
 * @param [in] isRRMSupported set to LBD_TRUE if RRM is
 *                            supported, LBD_FALSE otherwise
 * @param [in] phyCapInfo  PHY capabilities supported by each STA
 * @param [in] cookie  the parameter provided in the dump call
 */
typedef void (*wlanif_associatedSTAsCB)(const struct ether_addr *addr,
                                        const lbd_bssInfo_t *bss,
                                        LBD_BOOL isBTMSupported,
                                        LBD_BOOL isRRMSupported,
                                        const wlanif_phyCapInfo_t *phyCapInfo,
                                        void *cookie);

/**
 * @brief Callback function when dumping Airtime Fairness table
 *
 * @param [in] addr  the MAC address of the STA listed in ATF table
 * @param [in] bss  the BSS on which the airtime is reserved for this STA
 * @param [in] airtime  the reserved airtime listed in ATF table
 * @param [in] cookie  the parameter provided in the dump call
 */
typedef void (*wlanif_reservedAirtimeCB)(const struct ether_addr *addr,
                                         const lbd_bssInfo_t *bss,
                                         lbd_airtime_t airtime,
                                         void *cookie);

/**
 * @brief Function callback type that other modules can register to observe
 *        channel changes.
 *
 * @param [in] vap  the VAP on which channel change happens
 * @param [in] channelId  new channel
 * @param [in] cookie  the value provided by the caller when the observer
 *                     callback function was registered
 */
typedef void (*wlanif_chanChangeObserverCB)(lbd_vapHandle_t vap,
                                            lbd_channelId_t channelId,
                                            void *cookie);

/**
 * @brief Snapshot of relevant per-STA statistics needed for load balancing.
 */
typedef struct wlanif_staStatsSnapshot_t {
    /// Number of bytes sent to the STA by this AP.
    u_int64_t txBytes;

    /// Number of bytes received from the STA by this AP.
    u_int64_t rxBytes;

    /// Last rate at which packets sent to the STA by this AP were sent.
    lbd_linkCapacity_t lastTxRate;

    /// Last rate at which the packets sent by the STA to this AP were sent.
    lbd_linkCapacity_t lastRxRate;
} wlanif_staStatsSnapshot_t;

// ====================================================================
// Public API
// ====================================================================

/**
 * @brief Initialize the library.
 *
 * Note that asynchronous events will not be enabled until the listen init
 * callbacks are invoked.
 *
 * @return LBD_OK on successful init; otherwise LBD_NOK
 */
LBD_STATUS wlanif_init(void);

/**
 * @brief Set overload status on a channel
 *
 * @param [in] channel  the channel on which to set overload status
 * @param [in] overload  LBD_TRUE for overload, LBD_FALSE for not overload
 *
 * @return LBD_OK on successfully set overload; otherwise LBD_NOK
 */
LBD_STATUS wlanif_setOverload(lbd_channelId_t channel, LBD_BOOL overload);

/**
 * @brief For each of the VAPs, dump the associated STAs and invoke the
 *        callback with each STA MAC address and the band on which it
 *        is associated.
 *
 * @param [in] callback  the callback to invoke with the associated STA
 *                       information
 * @param [in] cookie  the parameter to provide in the callback (in addition
 *                     to the STA information) for use by the caller of this
 *                     function
 *
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanif_dumpAssociatedSTAs(wlanif_associatedSTAsCB callback,
                                     void *cookie);

/**
 * @brief Request real-time RSSI measurement of a specific station
 *
 * The RSSI measurement will be reported back in wlanif_event_rssi_measurement.
 *
 * If the previous request has not completed in driver, this request will fail.
 *
 * @param [in] bss  the BSS that the client is associated with
 * @param [in] staAddr  the MAC address of the specific station
 * @param [in] numSamples  number of RSSI samples to average before reporting RSSI back
 *
 * @return  LBD_OK if the request is sent successfully; otherwise LBD_NOK
 */
LBD_STATUS wlanif_requestStaRSSI(const lbd_bssInfo_t *bss,
                                 const struct ether_addr * staAddr,
                                 u_int8_t numSamples);

/**
 * @brief Either enable or disable all VAPs on a channel in
 *        channelList for a STA.
 *
 * @param [in] channelCount number of channels in channelList
 * @param [in] channelList set of channels to enable or disable
 * @param [in] staAddr the MAC address of the STA
 * @param [in] enable set to LBD_TRUE to enable for all
 *             channels, LBD_FALSE to disable
 *
 * @return LBD_STATUS LBD_OK if the state could be set, LBD_NOK
 *                    otherwise
 */
LBD_STATUS wlanif_setChannelStateForSTA(
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable);

/**
 * @brief Will set the state of all VAPs on the same ESS not
 *        matching the candidate list.
 *
 * @param [in] candidateCount number of candidates in
 *                            candidateList
 * @param [in] candidateList set of candidate BSSes
 * @param [in] staAddr the MAC address of the STA
 * @param [in] enable if LBD_TRUE, will enable all VAPs not on
 *                    the candidate list, if LBD_FALSE will
 *                    disable.
 * @param [in] probeOnly if LBD_TRUE, will set the probe
 *                       response witholding state only
 *
 * @return LBD_STATUS LBD_OK if the state could be set, LBD_NOK
 *                    otherwise
 */
LBD_STATUS wlanif_setNonCandidateStateForSTA(
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable,
    LBD_BOOL probeOnly);

/**
 * @brief Get all candidate BSSes on the same ESS not matching 
 *        the candidate list
 * 
 * @param [in] candidateCount number of candidates in
 *                            candidateList
 * @param [in] candidateList set of candidate BSSes
 * @param [in] maxCandidateCount  maximum number of candidate 
 *                                BSSes that can be returned in
 *                                outCandidateList
 * @param [out] outCandidateList  set of candidate BSSes on the 
 *                                same ESS but not matching the
 *                                candidate list
 * 
 * @return Number of candidate BSSes added to outCandidateList 
 */
u_int8_t wlanif_getNonCandidateStateForSTA(
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    u_int8_t maxCandidateCount,
    lbd_bssInfo_t *outCandidateList);

/**
 * @brief Will update the state for all VAPs on the candidate
 *        list.
 *
 * @param [in] candidateCount number of candidates in
 *                            candidateList
 * @param [in] candidateList set of candidate BSSes
 * @param [in] staAddr the MAC address of the STA
 * @param [in] enable if LBD_TRUE, will enable all VAPs on
 *                    the candidate list, if LBD_FALSE will
 *                    disable.
 *
 * @return LBD_STATUS LBD_OK if the state could be set, LBD_NOK
 *                    otherwise
 */
LBD_STATUS wlanif_setCandidateStateForSTA(
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable);

/**
 * @brief Determine if a BSSID identifies one of the candidates 
 *        in a list.
 * 
 * @param [in] candidateCount number of candidates in
 *                            candidateList
 * @param [in] candidateList set of candidate BSSes
 * @param [in] bssid  BSSID to search for
 * 
 * @return LBD_TRUE if match is found; LBD_FALSE otherwise
 */
LBD_BOOL wlanif_isBSSIDInList(u_int8_t candidateCount,
                              const lbd_bssInfo_t *candidateList,
                              const struct ether_addr *bssid);

/**
 * @brief Get the set of channels that are active on this device
 *
 * @param [out] channelList set of active channels
 * @param [in] maxSize maximum number of channels that will be
 *                     returned
 *
 * @return u_int8_t count of active channels
 */
u_int8_t wlanif_getChannelList(lbd_channelId_t *channelList,
                               u_int8_t maxSize);

/**
 * @brief Kick the STA out of the provided band, forcing disassociation.
 *
 * @param [in] assocBSS  the BSS on which the STA should be
 *                       disassociated
 * @param [in] staAddr the MAC address of the STA to disassociate
 *
 * @return LBD_OK if the request to disassociate was successfully handled;
 *         otherwise LBD_NOK
 */
LBD_STATUS wlanif_disassociateSTA(const lbd_bssInfo_t *assocBSS,
                                  const struct ether_addr *staAddr);

/**
 * @brief Send a BSS Transition Management Request frame to a
 *        specific STA
 *
 * @param [in] assocBSS the BSS on which the STA is associated
 * @param [in] staAddr the MAC address of the STA to send the
 *                     request to
 * @param [in] dialogToken dialog token to send with the request
 * @param [in] candidateCount number of transition candidates to
 *                            include with the request
 * @param [in] candidates transition candidate list
 *
 * @return LBD_STATUS LBD_OK if the request was sent
 *                    successfully; otherwise LBD_NOK
 */
LBD_STATUS wlanif_sendBTMRequest(const lbd_bssInfo_t *assocBSS,
                                 const struct ether_addr *staAddr,
                                 u_int8_t dialogToken,
                                 u_int8_t candidateCount,
                                 const lbd_bssInfo_t *candidateList);

/**
 * @brief Request the real-time downlink RSSI measurement of a specific
 *        client. This could be the RSSI seen by client from beacon or probe
 *        response
 *
 * The RSSI measurement will be reported back in wlanif_event_rssi_measurement.
 *
 * @param [in] bss  the BSS on which the STA is associated on
 * @param [in] staAddr  the MAC address of the STA
 * @param [in] rrmCapable  flag indicating if the STA implements 802.11k feature
 * @param [in] numChannels  number of channels in channelList
 * @param [in] channelList  set of channels to measure downlink RSSI
 *
 * @return LBD_OK if the request has been sent successfully; otherwise
 *         return LBD_NOK
 */
LBD_STATUS wlanif_requestDownlinkRSSI(const lbd_bssInfo_t *bss,
                                      const struct ether_addr *staAddr,
                                      LBD_BOOL rrmCapable,
                                      size_t numChannels,
                                      const lbd_channelId_t *channelList);

/**
 * @brief Resolve band from channel number
 *
 * Only consider 2.4 GHz and 5 GHz band for now.
 *
 * @param [in] channum  the channel number
 *
 * @return the resolved band or wlanif_band_invalid
 */
wlanif_band_e wlanif_resolveBandFromChannelNumber(u_int8_t channum);

/**
 * @brief Enable the collection of byte and MCS statistics on the provided
 *        BSS.
 *
 * @param [in] bss  the BSS on which to enable the stats; this must be a
 *                  local BSS
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanif_enableSTAStats(const lbd_bssInfo_t *bss);

/**
 * @brief Take a snapshot of the STA statistics.
 *
 * @param [in] bss  the BSS that is serving the STA
 * @param [in] staAddr  the MAC address of the STA
 * @param [in] rateOnly will return only the rate data.  Does
 *                      not require stats to be enabled.
 * @param [out] staStats  the snapshot of the stats; only populated on success
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanif_sampleSTAStats(const lbd_bssInfo_t *bss,
                                 const struct ether_addr *staAddr,
                                 LBD_BOOL rateOnly,
                                 wlanif_staStatsSnapshot_t *staStats);

/**
 * @brief Disable the collection of byte and MCS statistics on the provided
 *        BSS.
 *
 * @param [in] bss  the BSS on which to disable the stats; this must be a
 *                  local BSS
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanif_disableSTAStats(const lbd_bssInfo_t *bss);

/**
 * @brief Obtain a copy of the PHY capabilities of a specific BSS.
 *
 * @param [in] bss  the BSS for which to obtain the capabilities
 *
 * @return the phy capabilities, or NULL on failure
 */
const wlanif_phyCapInfo_t *wlanif_getBSSPHYCapInfo(const lbd_bssInfo_t *bss);

/**
 * @brief Check if a given channel has the strongest Tx power on its band
 *
 * @param [in] channelId  the given channel
 * @param [out] isStrongest  set to LBD_TRUE if the channel has the highest Tx
 *                           power on its band on success
 *
 * @return LBD_OK on success; otherwise return LBD_NOK
 */
LBD_STATUS wlanif_isStrongestChannel(lbd_channelId_t channelId, LBD_BOOL *isStrongest);

/**
 * @brief Check if a given BSS is on the channel with the strongest Tx power
 *        on its band
 *
 * @param [in] bss  the given BSS
 * @param [out] isStrongest  set to LBD_TRUE if the channel has the highest Tx
 *                           power on its band on success
 *
 * @return LBD_OK on success; otherwise return LBD_NOK
 */
LBD_STATUS wlanif_isBSSOnStrongestChannel(const lbd_bssInfo_t *bss,
                                          LBD_BOOL *isStrongest);

/**
 * @brief For each of the VAPs, dump the Airtime Fainess (ATF) table and
 *        invoke the callback with each STA MAC address and the reserved
 *        airtime listed
 *
 * @param [in] callback  the callback to invoke with the reserved airtime
 *                       information
 * @param [in] cookie  the parameter to provide in the callback (in addition
 *                     to the airtime information) for use by the caller of this
 *                     function
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanif_dumpATFTable(wlanif_reservedAirtimeCB callback,
                               void *cookie);

/**
 * @brief Determine if STA is associated on a BSS
 * 
 * @param [in] bss  BSS to check for STA association
 * @param [in] staAddr  MAC address of STA to check for 
 *                      association
 * 
 * @return LBD_TRUE if STA is associated on BSS; LBD_FALSE 
 *         otherwise
 */
LBD_BOOL wlanif_isSTAAssociated(const lbd_bssInfo_t *bss,
                                const struct ether_addr *staAddr);

/**
 * @brief Register a callback function to observe channel changes
 *
 * Note that the pair of the callback and cookie must be unique.
 *
 * @param [in] callback  the function to invoke for channel changes
 * @param [in] cookie  the parameter to pass to the callback function
 *
 * @return LBD_OK if the observer was successfully registered; otherwise
 *         LBD_NOK (either due to no free slots or a duplicate registration)
 */
LBD_STATUS wlanif_registerChanChangeObserver(wlanif_chanChangeObserverCB callback,
                                             void *cookie);

/**
 * @brief Unregister a callback function so that it no longer will receive
 *        channel change notification.
 *
 * The parameters provided must match those given in the original
 * wlanif_registerChanChangeObserver() call.
 *
 * @param [in] callback  the function that was previously registered
 * @param [in] cookie  the parameter that was provided when the function was
 *                     registered
 *
 * @return LBD_OK if the observer was successfully unregistered; otherwise
 *         LBD_NOK
 */
LBD_STATUS wlanif_unregisterChanChangeObserver(wlanif_chanChangeObserverCB callback,
                                               void *cookie);

/**
 * @brief Find BSSes that are on the same band with the given BSS (except the given one)
 *
 * @param [in] bss  the given BSS
 * @param [in] sameBand  flag indicating if only same band BSSes should be returned
 * @param [inout] maxNumBSSes  on input, it is the maximum number of BSSes expected;
 *                             on output, return number of entries in the bssList
 * @param [out] bssList  the list of BSSes that are on the same band with given BSS
 *
 * @return LBD_OK on success, otherwise return LBD_NOK
 */
LBD_STATUS wlanif_getBSSesSameESS(const lbd_bssInfo_t *bss, LBD_BOOL sameBand,
                                  size_t* maxNumBSSes, lbd_bssInfo_t *bssList);

/**
 * @brief Terminate the library.
 *
 * @return LBD_OK on successful termination; otherwise LBD_NOK
 */
LBD_STATUS wlanif_fini(void);

#endif