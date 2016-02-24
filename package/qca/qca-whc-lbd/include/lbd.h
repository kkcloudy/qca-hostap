/*
 * @File: lbd.h
 *
 * @Abstract: Load balancing daemon main header file.
 *
 * @Notes: Type definitions used by load balancing daemon
 *
 * Copyright (c) 2011 Atheros Communications Inc.
 * All rights reserved.
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2012,2014 Qualcomm Atheros, Inc.
 * All rights reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#ifndef lbd__d
#define lbd__d

#include <sys/types.h>			/* Primitive types: u_int32_t, u_int8_t... */
#include <net/ethernet.h>		/* Ethernet structures */

/*
 * LBD_STATUS - Hybrid daemon API return values:
 *
 * LBD_OK: Function succeeded
 * LBD_NOK: Function failed
 *
 */
typedef enum
{
	LBD_OK = 0,
	LBD_NOK = -1

} LBD_STATUS;

/*
 * LBD_BOOL - Hybrid daemon boolean return values: FALSE & TRUE
 */
typedef enum
{
    LBD_FALSE = 0,
    LBD_TRUE = !LBD_FALSE

} LBD_BOOL;

/**
 * @brief An identifier that defines an AP.
 *
 * An AP is a collection of BSSes, operating on one or more channels.
 * For single AP load balancing, there is only one valid AP identifier,
 * namely LBD_APID_SELF. For multi-AP load balancing there will be
 * more identifiers allocated for remote devices.
 */
typedef u_int8_t lbd_apId_t;

// The identifier assigned for the local AP.
#define LBD_APID_SELF 0xFF

/**
 * @brief Type used to specify a single channel.
 *
 * This is defined in case future requirements require a more sophisticated
 * representation.
 */
typedef u_int8_t lbd_channelId_t;

// Value used to represent that the channel is not known/resolved.
#define LBD_CHANNEL_INVALID 0xFF

/**
 * @brief Type used to indicate that multiple BSSes are part of the same ESS.
 */
typedef u_int8_t lbd_essId_t;

// Value used to represent that the ESS is not known/resolved.
#define LBD_ESSID_INVALID 0xFF

/**
 * @brief Opaque handle that can be used for lower layer lookups of the
 *        underlying information for the VAP.
 */
typedef void * lbd_vapHandle_t;

// Value used to represent that the VAP is not known/resolved.
#define LBD_VAP_INVALID ((void *)0)

/**
 * @brief Representation of a specific BSS in the network.
 *
 * All upper layer entities should use this structure instead of operating
 * with BSSID or some other identifier. The lowest layer will map this to
 * BSSID or VAP as appropriate.
 */
typedef struct lbd_bssInfo_t {
    /// The identity AP that provides this BSS.
    lbd_apId_t apId;

    /// The channel on which the BSS is operating.
    lbd_channelId_t channelId;

    /// The ESS of which this BSS is a member.
    lbd_essId_t essId;

    /// Opaque handle to the VAP for this BSS.
    /// This is only expected to be valid when this object is being
    /// provided by the lowest layer that manages the VAPs.
    lbd_vapHandle_t vap;
} lbd_bssInfo_t;

/* MAC address utility functions */
#define HD_ETH_ADDR_LEN             ETH_ALEN

/**
 * @brief Type used to indicate RSSI value
 */
typedef u_int8_t lbd_rssi_t;
#define LBD_INVALID_RSSI 0x0

/**
 * @brief Type used to indicate SNR value
 *
 * @note This is equivalent to the RSSI type due to the terminology used
 *       for uplink measurements (which appear more like an SNR than an RSSI).
 */
typedef u_int8_t lbd_snr_t;
#define LBD_INVALID_SNR 0x0
#define LBD_MAX_SNR 0xFF

/**
 * @brief Type used to indicate airtime percentage value
 */
typedef u_int8_t lbd_airtime_t;
#define LBD_INVALID_AIRTIME 0xFF

/**
 * @brief Type used to indicate link capacity value
 */
typedef u_int16_t lbd_linkCapacity_t;
#define LBD_INVALID_LINK_CAP 0x0

/*
 * Ethernet address structure (from net/ethernet.h):
 *
 * struct ether_addr
 * {
 *   u_int8_t ether_addr_octet[ETH_ALEN];
 * } __attribute__ ((__packed__));
 *
 *
 * Ethernet header strucutre:
 *
 * struct ether_header
 * {
 *   u_int8_t  ether_dhost[ETH_ALEN];	// destination eth addr
 *   u_int8_t  ether_shost[ETH_ALEN];	// source ether addr
 *   u_int16_t ether_type;		        // packet type ID field
 * }
 */


#endif /* lbd__d */
