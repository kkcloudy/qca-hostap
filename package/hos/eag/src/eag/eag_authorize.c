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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include "limits2.h"
#include "eag_util.h"
#include "eag_errcode.h"
#include "eag_log.h"
#include "eag_conf.h"
#include "eag_interface.h"
#include "session.h"
#include "eag_wireless.h"
#include "eag_captive.h"
#include "eag_blkmem.h"
#include "hashtable.h"
#include "appconn.h"
//#include "eag_ipset.h"
#include "eag_iptables.h"
#include "eag_authorize.h"

struct wifi_nf_info
{
    unsigned char STAMAC[PKT_ETH_ALEN]; 
    unsigned int nfmark; 
};

#define WIFI_IOC_MAGIC 243
#define WIFI_IOC_SET_NFMASK _IOWR(WIFI_IOC_MAGIC, 15, struct wifi_nf_info)  
#define WIFI_IOC_GET_NFMASK _IOWR(WIFI_IOC_MAGIC, 16, struct wifi_nf_info)



struct eag_authorize{
	eag_captive_t *cap;
	int (*do_authorize)( eag_authorize_t *this, struct appsession *appsession );
	int (*de_authorize)( eag_authorize_t *this, struct appsession *appsession );
	#if 0
	int (*do_eap_authorize)( eag_authorize_t *this, unsigned int user_ip);
	int (*del_eap_authorize)( eag_authorize_t *this, unsigned int user_ip);
	#endif
	int (*do_macpre_authorize)( eag_authorize_t *this, unsigned int user_ip);
	int (*del_macpre_authorize)( eag_authorize_t *this, unsigned int user_ip);
	int (*do_flux)( eag_authorize_t *this, struct appsession *appsession );
	void *param;
};

static eag_authorize_t eag_authorize_ipset;
static eag_authorize_t eag_authorize_iptable;
static eag_authorize_t eag_authorize_tag;

int 
eag_authorize_do_authorize( eag_authorize_t *this, struct appsession *appsession )
{
	if( NULL != this && NULL != this->do_authorize ){
		return this->do_authorize(this, appsession );
	}

	eag_log_err("eag_authorize_do_authorize param error this=%p "\
				"this->do_authorize=%p", this, (this==NULL)?NULL:this->do_authorize);
	return EAG_ERR_INPUT_PARAM_ERR;
}

int 
eag_authorize_de_authorize( eag_authorize_t *this, struct appsession *appsession )
{
	if( NULL != this && NULL != this->de_authorize ){
		return this->de_authorize(this, appsession );
	}

	eag_log_err("eag_authorize_de_authorize param error this=%p "\
				"this->de_authorize=%p", this, (this==NULL)?NULL:this->de_authorize);
	return EAG_ERR_INPUT_PARAM_ERR;
}
#if 0
int 
eag_authorize_do_eap_authorize( eag_authorize_t *this, unsigned int user_ip )
{
	if( NULL != this && NULL != this->do_eap_authorize ){
		return this->do_eap_authorize(this, user_ip );
	}

	eag_log_err("eag_authorize_do_eap_authorize param error this=%p "\
				"this->do_eap_authorize=%p", this, (this==NULL)?NULL:this->do_eap_authorize);
	return EAG_ERR_INPUT_PARAM_ERR;
}

int 
eag_authorize_del_eap_authorize( eag_authorize_t *this, unsigned int user_ip )
{
	if( NULL != this && NULL != this->del_eap_authorize ){
		return this->del_eap_authorize(this, user_ip );
	}

	eag_log_err("eag_authorize_del_eap_authorize param error this=%p "\
				"this->del_eap_authorize=%p", this, (this==NULL)?NULL:this->del_eap_authorize);
	return EAG_ERR_INPUT_PARAM_ERR;
}
#endif
int 
eag_authorize_do_macpre_authorize( eag_authorize_t *this, unsigned int user_ip )
{
	if( NULL != this && NULL != this->do_macpre_authorize){
		return this->do_macpre_authorize(this, user_ip );
	}

	eag_log_err("eag_authorize_do_macpre_authorize param error this=%p "\
				"this->do_macpre_authorize=%p", this, (this==NULL)?NULL:this->do_macpre_authorize);
	return EAG_ERR_INPUT_PARAM_ERR;
}

int 
eag_authorize_del_macpre_authorize( eag_authorize_t *this, unsigned int user_ip )
{
	if( NULL != this && NULL != this->del_macpre_authorize){
		return this->del_macpre_authorize(this, user_ip );
	}

	eag_log_err("eag_authorize_del_macpre_authorize param error this=%p "\
				"this->del_macpre_authorize=%p", this, (this==NULL)?NULL:this->del_macpre_authorize);
	return EAG_ERR_INPUT_PARAM_ERR;
}

int 
eag_authorize_do_flux( eag_authorize_t *this, struct appsession *appsession )
{
	if( NULL != this && NULL != this->do_flux ){
		return this->do_flux(this, appsession );
	}

	eag_log_err("eag_authorize_do_flux param error this=%p "\
				"this->do_flux=%p", this, (this==NULL)?NULL:this->do_flux);
	return EAG_ERR_INPUT_PARAM_ERR;
}

eag_authorize_t *
eag_authorize_get_ipset_auth()
{
	return &eag_authorize_ipset;
}

eag_authorize_t *
eag_authorieze_get_iptables_auth()
{
	return &eag_authorize_iptable;
}
eag_authorize_t *
eag_authorieze_get_tag_auth()
{
	return &eag_authorize_tag;
}


#if 0
static int 
eag_authorize_ipset_do_authorize( eag_authorize_t *this, struct appsession *appsession )
{
	if( NULL == this ) {
        eag_log_err("eag_authorize_ipset_do_authorize this = %p", this);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( NULL == this->cap ){
		eag_log_err("eag_authorize_ipset_do_authorize this = %p this->cap =%p",
					this, this->cap);
		return EAG_ERR_INPUT_PARAM_ERR;	
	}
	if( NULL == appsession ){
		eag_log_err("eag_authorize_ipset_do_authorize appsession = NULL");
		return EAG_ERR_INPUT_PARAM_ERR;	
	}
	if( 0 == appsession->user_ip ){
		char ipstr[32];
		ip2str( appsession->user_ip, ipstr, sizeof(ipstr) );
		eag_log_err("eag_authorize_ipset_do_authorize appsession if=%s ip=%s",
					appsession->intf, ipstr );
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	return add_user_to_set( eag_captive_get_capid(this->cap),
							eag_captive_get_hansitype(this->cap),
							appsession->user_ip );
}

static int 
eag_authorize_ipset_de_authorize( eag_authorize_t *this, struct appsession *appsession )
{
    if( NULL == this ){
		eag_log_err( "eag_authorize_ipset_de_authorize this = %p", this);
		return EAG_ERR_INPUT_PARAM_ERR; 
	}
	if( NULL == this->cap ){
		eag_log_err( "eag_authorize_ipset_de_authorize this = %p  this->cap = %p",
					this, this->cap );
		return EAG_ERR_INPUT_PARAM_ERR;	
	}
	if( NULL == appsession ){
		eag_log_err( "eag_authorize_ipset_de_authorize appsession = NULL" );
		return EAG_ERR_INPUT_PARAM_ERR;	
	}
	if( strlen(appsession->intf)==0 || 0 == appsession->user_ip ){
		char ipstr[32];
		ip2str( appsession->user_ip, ipstr, sizeof(ipstr) );
		eag_log_err( "eag_authorize_ipset_de_authorize appsession if=%s ip=%s",
						appsession->intf, ipstr );
		return EAG_ERR_INPUT_PARAM_ERR;	
	}
	return del_user_from_set( eag_captive_get_capid(this->cap),
								eag_captive_get_hansitype(this->cap),
								appsession->user_ip );
}

static int 
eag_authorize_ipset_do_flux( eag_authorize_t *this, struct appsession *appsession )
{
	return EAG_RETURN_OK;
}
#if 0
static int 
eag_authorize_ipset_do_eap_authorize( eag_authorize_t *this, unsigned int user_ip )
{
	return EAG_RETURN_OK;
}

static int 
eag_authorize_ipset_del_eap_authorize( eag_authorize_t *this, unsigned int user_ip )
{
	return EAG_RETURN_OK;
}
#endif
static int 
eag_authorize_ipset_do_macpre_authorize( eag_authorize_t *this, unsigned int user_ip)
{
    if( NULL == this ){
		eag_log_err("eag_authorize_ipset_do_macpre_authorize this = %p", this);
		return EAG_ERR_INPUT_PARAM_ERR; 
	}
	if( NULL == this->cap ){
		eag_log_err("eag_authorize_ipset_do_macpre_authorize this = %p this->cap =%p",
					this, this->cap);
		return EAG_ERR_INPUT_PARAM_ERR;	
	}
	if( 0 == user_ip ){
		char ipstr[32];
		ip2str( user_ip, ipstr, sizeof(ipstr) );
		eag_log_err("eag_authorize_ipset_do_macpre_authorize ip=%s", ipstr );
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	return add_preauth_user_to_set( eag_captive_get_capid(this->cap),
							eag_captive_get_hansitype(this->cap),
							user_ip );
}

static int 
eag_authorize_ipset_del_macpre_authorize( eag_authorize_t *this, unsigned int user_ip )
{
    if( NULL == this ){
		eag_log_err( "eag_authorize_ipset_del_macpre_authorize this = %p", this);
		return EAG_ERR_INPUT_PARAM_ERR; 
	}
	if( NULL == this->cap ){
		eag_log_err( "eag_authorize_ipset_del_macpre_authorize this = %p  this->cap = %p",
					this, this->cap );
		return EAG_ERR_INPUT_PARAM_ERR;	
	}
	if( 0 == user_ip ){
		char ipstr[32];
		ip2str( user_ip, ipstr, sizeof(ipstr) );
		eag_log_err( "eag_authorize_ipset_del_macpre_authorize ip=%s", ipstr );
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	return del_preauth_user_from_set( eag_captive_get_capid(this->cap),
								eag_captive_get_hansitype(this->cap),
								user_ip );
}
#endif
static int 
eag_authorize_iptables_do_authorize( eag_authorize_t *this, struct appsession *appsession )
{
    if( NULL == this ){
		eag_log_err("eag_authorize_iptables_do_authorize this = %p", this);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( NULL == this->cap ){
		eag_log_err("eag_authorize_iptables_do_authorize this = %p  this->cap = %p",
					this, this->cap);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( NULL == appsession ){
		eag_log_err("eag_authorize_iptables_do_authorize appsession = NULL");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( strlen(appsession->bridge)==0 || 0 == appsession->user_ip ){
		char ipstr[32];
		ip2str(appsession->user_ip, ipstr, sizeof(ipstr) );
		eag_log_err("eag_authorize_iptables_do_authorize appsession if=%s ip=%s",
						appsession->bridge, ipstr );
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	return connect_up( appsession->bridge, appsession->user_ip);
}

static int 
eag_authorize_iptables_de_authorize( eag_authorize_t *this, struct appsession *appsession )
{
    if( NULL == this ){
		eag_log_err("eag_authorize_iptables_de_authorize this = %p", this);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( NULL == this->cap ){
		eag_log_err("eag_authorize_iptables_de_authorize this = %p  this->cap = %p",
					this, this->cap);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( NULL == appsession ){
		eag_log_err("eag_authorize_iptables_de_authorize appsession = NULL");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( strlen(appsession->bridge)==0 || 0 == appsession->user_ip ){
		char ipstr[32];
		ip2str( appsession->user_ip, ipstr, sizeof(ipstr) );
		
		eag_log_err("eag_authorize_iptables_de_authorize appsession if=%s ip=%s",
						appsession->bridge, ipstr );
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	return connect_down( appsession->bridge, appsession->user_ip);

}
#if 0
static int 
eag_authorize_iptables_do_eap_authorize( eag_authorize_t *this, unsigned int user_ip )
{
    if( NULL == this ){
		eag_log_err("eag_authorize_iptables_do_eap_authorize this = %p", this);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( NULL == this->cap ){
		eag_log_err("eag_authorize_iptables_do_eap_authorize this = %p  this->cap = %p",
					this, this->cap);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( 0 == user_ip ){
		eag_log_err("eag_authorize_iptables_do_eap_authorize user_ip = 0");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	return eap_connect_up(  eag_captive_get_capid(this->cap), 
						eag_captive_get_hansitype(this->cap), user_ip);
}

static int 
eag_authorize_iptables_del_eap_authorize( eag_authorize_t *this, unsigned int user_ip )
{
    if( NULL == this ){
		eag_log_err("eag_authorize_iptables_del_eap_authorize this = %p", this);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( NULL == this->cap ){
		eag_log_err("eag_authorize_iptables_del_eap_authorize this = %p  this->cap = %p",
					this, this->cap);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( 0 == user_ip ){
		eag_log_err("eag_authorize_iptables_del_eap_authorize  user_ip = 0");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	return eap_connect_down( eag_captive_get_capid(this->cap), 
						eag_captive_get_hansitype(this->cap), user_ip);

}
#endif
static int 
eag_authorize_iptables_do_macpre_authorize( eag_authorize_t *this, unsigned int user_ip )
{
    if( NULL == this ){
		eag_log_err("eag_authorize_iptables_do_macpre_authorize this = %p", this);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( NULL == this->cap ){
		eag_log_err("eag_authorize_iptables_do_macpre_authorize this = %p  this->cap = %p",
					this, this->cap);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( 0 == user_ip ){
		eag_log_err("eag_authorize_iptables_do_macpre_authorize user_ip = 0");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	eag_log_debug("eag_macauth", "macpre_connect_up BEGIN!user_ip:%#x", user_ip);
	return macpre_connect_up(user_ip);
}

static int 
eag_authorize_iptables_del_macpre_authorize( eag_authorize_t *this, unsigned int user_ip )
{
    if( NULL == this ){
		eag_log_err("eag_authorize_iptables_del_macpre_authorize this = %p", this);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( NULL == this->cap ){
		eag_log_err("eag_authorize_iptables_del_macpre_authorize this = %p  this->cap = %p",
					this, this->cap);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if( 0 == user_ip ){
		eag_log_err("eag_authorize_iptables_del_macpre_authorize  user_ip = 0");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	eag_log_debug("eag_macauth", "macpre_connect_down BEGIN!user_ip:%#x", user_ip);
	return macpre_connect_down(user_ip);

}

static int 
eag_authorize_iptables_do_flux( eag_authorize_t *this, struct appsession *appsession )
{
	return EAG_RETURN_OK;
}


int
eag_authorize_iptables_auth_init( eag_captive_t *cap,
						 void *param )
{
	memset( &eag_authorize_iptable, 0, sizeof(eag_authorize_iptable));
	eag_authorize_iptable.cap = cap;
	eag_authorize_iptable.do_authorize = eag_authorize_iptables_do_authorize;
	eag_authorize_iptable.de_authorize = eag_authorize_iptables_de_authorize;
	#if 0
	eag_authorize_iptable.do_eap_authorize = eag_authorize_iptables_do_eap_authorize;
	eag_authorize_iptable.del_eap_authorize = eag_authorize_iptables_del_eap_authorize;
	#endif
	eag_authorize_iptable.do_macpre_authorize = eag_authorize_iptables_do_macpre_authorize;
	eag_authorize_iptable.del_macpre_authorize = eag_authorize_iptables_del_macpre_authorize;
	eag_authorize_iptable.do_flux = eag_authorize_iptables_do_flux;	
	return EAG_RETURN_OK;
}

int
eag_authorize_iptables_auth_uninit( )
{
	return EAG_RETURN_OK;
}

int
eag_auth_set_tag(unsigned char *usermac, uint32_t tag)
{
	int fd = -1;
	int ret = 0;
	char macstr[32] = {0};
	struct wifi_nf_info wifi_nf_s;

	if (NULL == usermac) {
		eag_log_err("eag_auth_set_tag usermac = %p", usermac);
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	mac2str(usermac, macstr, sizeof(macstr), ':');
	fd = open("/dev/wifi0", O_RDWR);
	if (fd < 0) {
		eag_log_err("eag_auth_set_tag open /dev/wifi0 err, fd=%d", fd);
		return EAG_ERR_SOCKET_FAILED;
	}

	memset(&wifi_nf_s, 0, sizeof(struct wifi_nf_info));
	memcpy(wifi_nf_s.STAMAC, usermac, PKT_ETH_ALEN);
	wifi_nf_s.nfmark = tag;

	ret = ioctl(fd, WIFI_IOC_SET_NFMASK, &wifi_nf_s);	 
	if (ret < 0) {
		eag_log_err("eag_auth_set_tag ioctl err %d usermac=%s tag=%u", ret, macstr, tag);
        close(fd);
		return -1;
	}
	close(fd);
	
	return wifi_nf_s.nfmark;
}

#if 0
#include <stdlib.h>
#include <sys/wait.h>
#include "nmp_process.h"

extern nmp_mutex_t eag_iptables_lock;

int
eag_auth_set_tag(uint32_t ip, uint32_t tag)
{
	int ret = 0;
	char cmd[256] = {0};
	char ipstr[32] = {0};

	ip2str(ip, ipstr, sizeof(ipstr));

	snprintf(cmd, sizeof(cmd), "sudo /opt/bin/iptables -t mangle -I PREROUTING -s %s -j MARK --set-mark %u;"
				" sudo /opt/bin/iptables -t mangle -I PREROUTING -d %s -j MARK --set-mark %u",
				ipstr, tag, ipstr, tag);
	
	nmp_mutex_lock(&eag_iptables_lock);	
	ret = system(cmd);
	nmp_mutex_unlock(&eag_iptables_lock);
	
	ret = WEXITSTATUS(ret);

	eag_log_debug("eag_iptables", "eag_auth_set_tag cmd=%s, ret=%d\n", cmd, ret);

	return EAG_RETURN_OK;
}

int
eag_auth_del_tag(uint32_t ip, uint32_t tag)
{
	int ret = 0;
	char cmd[256] = {0};
	char ipstr[32] = {0};

	ip2str(ip, ipstr, sizeof(ipstr));

	snprintf(cmd, sizeof(cmd), "sudo /opt/bin/iptables -t mangle -D PREROUTING -s %s -j MARK --set-mark %u;"
				" sudo /opt/bin/iptables -t mangle -D PREROUTING -d %s -j MARK --set-mark %u",
				ipstr, tag, ipstr, tag);
	
	nmp_mutex_lock(&eag_iptables_lock);	
	ret = system(cmd);
	nmp_mutex_unlock(&eag_iptables_lock);
	
	ret = WEXITSTATUS(ret);

	eag_log_debug("eag_iptables", "eag_auth_set_tag cmd=%s, ret=%d\n", cmd, ret);

	return EAG_RETURN_OK;
}
#endif

int
eag_authorize_do_authorize_by_tag(eag_authorize_t *this, struct appsession *appsession)
{
	int last_tag = 0;
	if (NULL == this) {
		eag_log_err("eag_authorize_do_authorize_by_tag this = %p", this);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if (NULL == appsession) {
		eag_log_err("eag_authorize_do_authorize_by_tag appsession = NULL");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if (appsession->auth_tag > MAX_TAG_NUMBER) {
		eag_log_err("eag_authorize_do_authorize_by_tag auth_tag = %u", appsession->auth_tag);
		return EAG_ERR_INPUT_PARAM_ERR;
	}

    eag_log_info("eag_authorize_do_authorize_by_tag auth_tag=%d", appsession->auth_tag);

	last_tag = eag_auth_set_tag(appsession->usermac, appsession->auth_tag);
	if (last_tag < 0 || last_tag > MAX_TAG_NUMBER) {
		eag_log_err("eag_authorize_do_authorize_by_tag eag_auth_set_tag error last_tag=%d", last_tag);
		return -1;
	}

	if (0 == appsession->init_tag) {
        appsession->init_tag = (uint32_t )last_tag;
	}
    eag_log_info("eag_authorize_do_authorize_by_tag init_tag=%u, last_tag=%d",
    		appsession->init_tag, last_tag);

	return EAG_RETURN_OK;
}

int
eag_authorize_del_authorize_by_tag(eag_authorize_t *this, struct appsession *appsession)
{
	int last_tag = 0;
	if (NULL == this) {
		eag_log_err("eag_authorize_del_authorize_by_tag this = %p", this);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if (NULL == appsession) {
		eag_log_err("eag_authorize_del_authorize_by_tag appsession = NULL");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if (appsession->auth_tag > MAX_TAG_NUMBER) {
		eag_log_err("eag_authorize_del_authorize_by_tag auth_tag = %u", appsession->auth_tag);
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	//eag_auth_del_tag(appsession->user_ip, appsession->auth_tag);
	last_tag = eag_auth_set_tag(appsession->usermac, appsession->init_tag);
	if (last_tag < 0 || last_tag > MAX_TAG_NUMBER) {
		eag_log_err("eag_authorize_del_authorize_by_tag eag_auth_set_tag error last_tag=%d", last_tag);
		return -1;
	}
    eag_log_info("eag_authorize_del_authorize_by_tag init_tag=%u, last_tag=%d",
    		appsession->init_tag, last_tag);

	return EAG_RETURN_OK;
}

int
eag_authorize_tag_auth_init( eag_captive_t *cap,void *param )
{
	memset( &eag_authorize_tag, 0, sizeof(eag_authorize_tag));
	eag_authorize_tag.cap = cap;
	eag_authorize_tag.do_authorize = eag_authorize_do_authorize_by_tag;
	eag_authorize_tag.de_authorize = eag_authorize_del_authorize_by_tag;
	eag_authorize_tag.do_macpre_authorize = eag_authorize_iptables_do_macpre_authorize;
	eag_authorize_tag.del_macpre_authorize = eag_authorize_iptables_del_macpre_authorize;
	eag_authorize_tag.do_flux = eag_authorize_iptables_do_flux;	
	return EAG_RETURN_OK;
}

int
eag_authorize_tag_auth_uninit( )
{
	return EAG_RETURN_OK;
}


