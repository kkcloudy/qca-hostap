// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanifBSteerEvents.h
 *
 * @Abstract: Load balancing daemon band steering events interface
 *
 * @Notes: This header should not be included directly by other components
 *         within the load balancing daemon. It should be considered
 *         private to the wlanif module.
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#ifndef wlanifBSteerEvents__h
#define wlanifBSteerEvents__h

#include "lbd.h"  // for LBD_STATUS
#include "wlanifBSteerControl.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Out of package forward decls.
struct dbgModule;

/* package API */

struct wlanifBSteerEventsPriv_t;  // opaque forward declaration
typedef struct wlanifBSteerEventsPriv_t * wlanifBSteerEventsHandle_t;

/**
 * @brief Initialize the band steering event interface but do not trigger
 *        the starting of the events.
 *
 * Triggering the events is done using wlanifBSteerEventsEnable().
 *
 * @param [in] dbgModule  the handle to use for logging
 *
 * @return a handle to the state for this instance, or NULL if it could
 *         not be created
 */
wlanifBSteerEventsHandle_t wlanifBSteerEventsCreate(struct dbgModule *dbgModule,
                                                    wlanifBSteerControlHandle_t controlHandle);

/**
 * @brief Turn on the event generation from the band steering module.
 *
 * This should be called after all interested entities have registered for the
 * events so that they do not miss any of them.
 *
 * @param [in] handle  the handle returned from wlanifBSteerEventsCreate() to
 *                     use to enable the events
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerEventsEnable(wlanifBSteerEventsHandle_t handle);

/**
 * @brief Destroy the band steering event interface.
 *
 * When this completes, no further events will be generated.
 *
 * @param [in] handle  the handle returned from wlanifBSteerEventsCreate() to
 *                     destroy
 *
 * @return LBD_OK if it was successfully destroyed; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerEventsDestroy(wlanifBSteerEventsHandle_t handle);

#if defined(__cplusplus)
}
#endif

#endif  // wlanifBSteerEvents__h
