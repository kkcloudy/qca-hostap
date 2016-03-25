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
* portal_ha.c
*
*
* CREATOR:
* autelan.software.xxx. team
*
* DESCRIPTION:
* xxx module main routine
*
*
*******************************************************************************/

#ifndef _EAG_CAPTIVE_H
#define _EAG_CAPTIVE_H

#include "limits2.h"
#include "session.h"
#include "eag_def.h"
#include "eag_interface.h"

typedef enum {
	CAP_STOP,
	CAP_START
} CAP_STATUS;

eag_captive_t *eag_captive_new( );
int
eag_captive_free(eag_captive_t * cap);
int
eag_captive_set_redir_srv(eag_captive_t * cap,
			  unsigned long srv_ip, unsigned short srv_port);

int
eag_captive_is_intf_in_list(eag_captive_t * cap, char *intf);
int
eag_captive_add_interface(eag_captive_t * cap, char *intf);
int
eag_captive_del_interface(eag_captive_t * cap, char *intfs);

int
eag_captive_add_tag(eag_captive_t *cap, uint32_t tag);

int
eag_captive_del_tag(eag_captive_t *cap, uint32_t tag);

int eag_captive_start(eag_captive_t * cap);
int eag_captive_stop(eag_captive_t * cap);

int eag_captive_authorize(eag_captive_t * cap, struct appsession *appsession);

int eag_captive_deauthorize(eag_captive_t * cap, struct appsession *appsession);

int eag_captive_eap_authorize(eag_captive_t * cap, unsigned int user_ip);

int eag_captive_del_eap_authorize(eag_captive_t * cap, unsigned int user_ip);

int eag_captive_macpre_authorize(eag_captive_t * cap, unsigned int user_ip);

int eag_captive_del_macpre_authorize(eag_captive_t * cap, unsigned int user_ip);

int eag_captive_update_session(eag_captive_t * cap,struct appsession *appsession);

int eag_captive_check_flux(eag_captive_t * cap, unsigned int check_interval);

int eag_captive_add_white_list(eag_captive_t * cap,
			       RULE_TYPE type,
			       unsigned long ipbegin, unsigned long ipend,
			       char *ports,
			       char *domain, char *intf, uint32_t tag);

int eag_captive_del_white_list(eag_captive_t * cap,
			       RULE_TYPE type,
			       unsigned long ipbegin, unsigned long ipend,
				   char *ports,
			       char *domain, char *intf, uint32_t tag);

int eag_captive_add_black_list(eag_captive_t * cap,
			       RULE_TYPE type,
			       unsigned long ipbegin, unsigned long ipend,
				   char *ports,
			       char *domain, char *intf, uint32_t tag);

int eag_captive_del_black_list(eag_captive_t * cap,
			       RULE_TYPE type,
			       unsigned long ipbegin, unsigned long ipend,
				   char *ports,
			       char *domain, char *intf, uint32_t tag);

#if 0
DBusMessage *
eag_dbus_method_conf_captive_list(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data );

DBusMessage *
eag_dbus_method_show_white_list(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data );

DBusMessage *
eag_dbus_method_show_black_list(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data );
DBusMessage *
eag_dbus_method_show_captive_intfs(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data );
DBusMessage *
eag_dbus_method_show_captive_tag(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data );
#endif

int eag_captive_get_capid( eag_captive_t * cap );
int eag_captive_get_hansitype( eag_captive_t * cap );
int eag_captive_get_ipset( eag_captive_t * cap );
int eag_captive_set_ipset(eag_captive_t * cap, int switch_t);
int eag_captive_set_macauth_ipset( eag_captive_t * cap, int switch_t);
int eag_captive_get_macauth_ipset( eag_captive_t *cap );
int
eag_captive_is_disable(eag_captive_t * cap);

#endif
