
#include <linux/netdevice.h>
#include <osdep.h>
#include <osif_private.h>
#include <ieee80211_var.h>
#include <if_athvar.h>
#include <ieee80211_defines.h>
#include <han_command.h>


#if ATOPT_BAND_STEERING
int32_t   bandsteering_enable = 1; //Prefer 5G default
EXPORT_SYMBOL(bandsteering_enable);
int32_t   bandsteering_rss_threshold = 20; //something is wrong 
EXPORT_SYMBOL(bandsteering_rss_threshold);
int32_t   bandsteering_access_load = 255;
EXPORT_SYMBOL(bandsteering_access_load);
int32_t   bandsteering_deny_count = 3;
EXPORT_SYMBOL(bandsteering_deny_count);
int32_t   bandsteering_debug = 0; 
EXPORT_SYMBOL(bandsteering_debug);
#endif
