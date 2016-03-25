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

#ifndef _EAG_AUTHORIZE_H
#define _EAG_AUTHORIZE_H

typedef struct eag_authorize eag_authorize_t;

eag_authorize_t *
eag_authorize_get_ipset_auth();
eag_authorize_t *
eag_authorieze_get_iptables_auth();
eag_authorize_t *
eag_authorieze_get_tag_auth();




int 
eag_authorize_do_authorize( eag_authorize_t *this, struct appsession *appsession );
int 
eag_authorize_de_authorize( eag_authorize_t *this, struct appsession *appsession );
#if 0
int 
eag_authorize_do_eap_authorize( eag_authorize_t *this, unsigned int user_ip );
int 
eag_authorize_del_eap_authorize( eag_authorize_t *this, unsigned int user_ip );
#endif
int 
eag_authorize_do_macpre_authorize( eag_authorize_t *this, unsigned int user_ip );
int 
eag_authorize_del_macpre_authorize( eag_authorize_t *this, unsigned int user_ip );

int 
eag_authorize_do_flux( eag_authorize_t *this, struct appsession *appsession );




int
eag_authorize_iptables_auth_init( eag_captive_t *cap,void *param );
int
eag_authorize_iptables_auth_uninit( );

/*int
eag_authorize_tag_auth_init(eag_captive_t *cap,
						DBusConnection *dbusconn, void *param);*/
int
eag_authorize_tag_auth_uninit();


#endif /*_EAG_AUTHORIZE_H*/




