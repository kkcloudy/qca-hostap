// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanifUtils.c
 *
 * @Abstract: Load balancing daemon - general wifi utilities
 *
 * @Notes: All functions placed in this file are stateless.
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


#include "wlanif.h"

wlanif_band_e wlanif_resolveBandFromChannelNumber(u_int8_t channum) {
    if (channum >=1 && channum <= 14) {
        return wlanif_band_24g;
    } else if (channum >= 36 && channum <= 169) {
        return wlanif_band_5g;
    }

    return wlanif_band_invalid;
}
