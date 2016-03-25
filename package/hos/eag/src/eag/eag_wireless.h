/*******************************************************************************
Copyright (C) Autelan Technology


This software file is owned and distributed by Autelan Technology 
********************************************************************************


THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
********************************************************************************
* eag_wireless.h
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* eag_wireless
*
*
*******************************************************************************/
#if 0
#ifndef _EAG_WIRELESS_H
#define _EAG_WIRELESS_H
#include <dbus/dbus.h>

#include "wcpss/wid/WID.h"
#include "dbus/wcpss/dcli_wid_wtp.h"
#include "session.h"

int
eag_dcli_dl_init(void);

int
eag_dcli_dl_uninit(void);

int
eag_get_facl_tag_by_name(DBusConnection *conn,
					const char *facl_name);

int
eag_get_sta_info_by_mac_v2( eag_dbus_t *eag_dbus,
					int localid, int inst_id,
					uint8_t *sta_mac,
					struct appsession *session,
					unsigned int *security_type);

struct WtpStaInfo *
eag_show_sta_info_of_all_wtp(int ins_id,
					int local_id,
					DBusConnection *conn,
					int *iRet);

int
eag_free_wtp_sta_info_head(struct WtpStaInfo *StaHead);

int
eag_set_sta_up_traffic_limit(DBusConnection *conn,
					int localid, int ins_id,
					uint8_t sta_mac[6],
					uint32_t radio_id,
					uint8_t wlan_id,
					uint32_t value);

int
eag_set_sta_down_traffic_limit(DBusConnection *conn,
					int localid, int ins_id,
					uint8_t sta_mac[6],
					uint32_t radio_id,
					uint8_t wlan_id,
					uint32_t value);


#endif /*_EAG_WIRELESS_H*/
#endif

