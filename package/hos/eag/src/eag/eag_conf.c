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
* eag_conf.c
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "eag_errcode.h"
#include "eag_conf.h"


struct radius_srv_t *
radius_conf_and_domain(struct radius_conf *radiusconf,
								char *domain)
{
	struct radius_srv_t *srv = NULL;
	if( NULL == radiusconf || NULL == domain
			|| strlen(domain)==0 
			|| strlen(domain)>sizeof(radiusconf->radius_srv[0].domain)-1 ){
		return NULL;
	}

	if( radiusconf->current_num >= MAX_RADIUS_SRV_NUM ){
		return NULL;
	}
	srv = &(radiusconf->radius_srv[radiusconf->current_num]);
	strncpy(srv->domain, domain, sizeof(srv->domain)-1);

	srv->remove_domain_name = 0;
	
	radiusconf->current_num ++;

	return srv;
}


struct radius_srv_t *
radius_srv_get_by_domain( struct radius_conf *radiusconf, char *domain)
{
	int i;
	struct radius_srv_t *srv = NULL;

	if( NULL == radiusconf || NULL == domain
			|| strlen(domain)==0 
			|| strlen(domain)>sizeof(radiusconf->radius_srv[0].domain)-1 ){
		return NULL;
	}
	
	for( i=0; i<radiusconf->current_num; i++ ){
		srv = &(radiusconf->radius_srv[i]);
		if( 0 == strcmp(domain, srv->domain) ){
			return srv;
		}
	}

	return NULL;
}


int
radius_conf_del_domain( struct radius_conf *radiusconf,
								char *domain )
{
	struct radius_srv_t *srv = NULL;
	int i;
	
	if( NULL == radiusconf || NULL == domain
			|| strlen(domain)==0 
			|| strlen(domain)>sizeof(radiusconf->radius_srv[0].domain)-1 ){
		return -1;
	}

	if( radiusconf->current_num == 0 ){
		return -1;
	}

	for( i=0; i<radiusconf->current_num; i++ ){
		srv = &(radiusconf->radius_srv[i]);
		if( 0 == strcmp(domain, srv->domain) ){
			radiusconf->current_num--;
			memcpy( srv, srv+1, 
					sizeof(struct radius_srv_t)*(radiusconf->current_num-i));
			return 0;
		}
	}
	
	return -1;
}


int
radius_srv_set_auth(struct radius_srv_t *radius_srv,
		    uint32_t auth_ip,
		    uint16_t auth_port,
		    char *auth_secret, size_t auth_secretlen)
{
	if (auth_secretlen > sizeof (radius_srv->auth_secret)) {
		return -1;
	}
	radius_srv->auth_ip = auth_ip;
	radius_srv->auth_port = auth_port;
	memset(radius_srv->auth_secret, 0, RADIUS_SECRETSIZE);
	memcpy(radius_srv->auth_secret, auth_secret, auth_secretlen);
	radius_srv->auth_secretlen = auth_secretlen;

	return 0;
}

int
radius_srv_set_acct(struct radius_srv_t *radius_srv,
		    uint32_t acct_ip,
		    uint16_t acct_port,
		    char *acct_secret, size_t acct_secretlen)
{
	if (acct_secretlen > sizeof (radius_srv->acct_secret)) {
		return -1;
	}
	radius_srv->acct_ip = acct_ip;
	radius_srv->acct_port = acct_port;
	memset(radius_srv->acct_secret, 0, RADIUS_SECRETSIZE);
	memcpy(radius_srv->acct_secret, acct_secret, acct_secretlen);
	radius_srv->acct_secretlen = acct_secretlen;

	return 0;
}

int
radius_srv_set_backauth(struct radius_srv_t *radius_srv,
			uint32_t backup_auth_ip,
			uint16_t backup_auth_port,
			char *backup_auth_secret,
			size_t backup_auth_secretlen)
{
	if (backup_auth_secretlen > sizeof (radius_srv->backup_auth_secret)) {
		return -1;
	}
	radius_srv->backup_auth_ip = backup_auth_ip;
	radius_srv->backup_auth_port = backup_auth_port;
	memset(radius_srv->backup_auth_secret, 0, RADIUS_SECRETSIZE);
	memcpy(radius_srv->backup_auth_secret, backup_auth_secret,
	       backup_auth_secretlen);
	radius_srv->backup_auth_secretlen = backup_auth_secretlen;

	return 0;
}

int
radius_srv_set_backacct(struct radius_srv_t *radius_srv,
			uint32_t backup_acct_ip,
			uint16_t backup_acct_port,
			char *backup_acct_secret,
			size_t backup_acct_secretlen)
{
	if (backup_acct_secretlen > sizeof (radius_srv->backup_acct_secret)) {
		return -1;
	}

	radius_srv->backup_acct_ip = backup_acct_ip;
	radius_srv->backup_acct_port = backup_acct_port;
	memset(radius_srv->backup_acct_secret, 0, RADIUS_SECRETSIZE);
	memcpy(radius_srv->backup_acct_secret, backup_acct_secret,
	       backup_acct_secretlen);
	radius_srv->backup_acct_secretlen = backup_acct_secretlen;

	return 0;
}

/*portal srv */


int
portal_conf_add_srv( struct portal_conf *portalconf,
					PORTAL_KEY_TYPE key_type,
					void *key,
					char *portal_url, 
					uint16_t ntf_port,
					char *domain,
					uint32_t mac_server_ip,
					uint16_t mac_server_port)
{
	struct portal_srv_t *portal_srv = NULL;
	
	if( NULL == portalconf || NULL == key ){
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if( portalconf->current_num >= MAX_PORTAL_NUM ){
		return EAG_ERR_PORTAL_ADD_SRV_MAX_NUM;
	}
	
	if (strlen(portal_url) >= sizeof (portal_srv->portal_url)) {
		return EAG_ERR_PORTAL_ADD_SRV_URL_LEN_LIMITE;
	}

	
	portal_srv = &(portalconf->portal_srv[portalconf->current_num]);

	memset(portal_srv, 0, sizeof (struct portal_srv_t));
	portal_srv->key_type = key_type;
	switch (key_type) {
	case PORTAL_KEYTYPE_ESSID:
		strncpy(portal_srv->key.essid, key,
				sizeof (portal_srv->key.essid) - 1);
		break;
	case PORTAL_KEYTYPE_WLANID:
		portal_srv->key.wlanid = *((unsigned int *) key);
		break;
	case PORTAL_KEYTYPE_VLANID:
		portal_srv->key.vlanid = *((unsigned int *) key);
		break;
	case PORTAL_KEYTYPE_WTPID:
		portal_srv->key.wtpid = *((unsigned int *) key);
		break;
	case PORTAL_KEYTYPE_INTF:
		if(strlen(key) >= sizeof(portal_srv->key.intf)) {
			return EAG_ERR_PORTAL_ADD_SRV_INTF_LEN_LIMITE;
		}
		strncpy(portal_srv->key.intf, key,
				sizeof (portal_srv->key.intf) - 1);
		break;
	default:
		return EAG_ERR_PORTAL_ADD_SRV_ERR_TYPE;
	}

	strncpy(portal_srv->portal_url, portal_url,
		sizeof (portal_srv->portal_url) - 1);
	portal_srv->ntf_port = ntf_port;
	if( (NULL != domain) && (0 != strcmp(domain, "")) )
		strncpy(portal_srv->domain, domain, sizeof(portal_srv->domain)-1);
	portal_srv->mac_server_ip = mac_server_ip;
	portal_srv->mac_server_port = mac_server_port;
	portalconf->current_num++;

	return EAG_RETURN_OK;
}

struct portal_srv_t *
portal_srv_get_by_key(struct portal_conf *portalconf,
		      PORTAL_KEY_TYPE key_type, void *key)
{
	struct portal_srv_t *portal_srv;
	int i;

	for(i=0;i<portalconf->current_num;i++) {
		portal_srv = &(portalconf->portal_srv[i]);
		if (key_type == portal_srv->key_type) {
			switch (key_type) {
			case PORTAL_KEYTYPE_ESSID:
				if (0 == strcmp(portal_srv->key.essid, key)) {
					return portal_srv;
				}
				break;
			case PORTAL_KEYTYPE_WLANID:
				if (portal_srv->key.wlanid ==
				    	*((unsigned long *) key)) {
					return portal_srv;
				}
				break;
			case PORTAL_KEYTYPE_VLANID:
				if (portal_srv->key.vlanid ==
				    	*((unsigned long *) key)) {
					return portal_srv;
				}
				break;
			case PORTAL_KEYTYPE_WTPID:
				if (portal_srv->key.wtpid ==
				    	*((unsigned long *) key)) {
					return portal_srv;
				}
				break;
			case PORTAL_KEYTYPE_INTF:
				if (0 == strcmp(portal_srv->key.intf, key)) {
					return portal_srv;
				}
				break;
			default:
				return NULL;
			}
		}
	}

	return NULL;
}

int
portal_conf_del_srv(struct portal_conf *portalconf,
					PORTAL_KEY_TYPE key_type, void *key)
{
	struct portal_srv_t *portal_srv=NULL;
	int i;

	for(i=0;i<portalconf->current_num;i++) {
		portal_srv = &(portalconf->portal_srv[i]);
		if (key_type == portal_srv->key_type) {
			switch (key_type) {
			case PORTAL_KEYTYPE_ESSID:
				if (0 != strcmp(portal_srv->key.essid, key)) {
					continue;
				}
				break;
			case PORTAL_KEYTYPE_WLANID:
				if (portal_srv->key.wlanid !=
						*((unsigned long *) key)) {
					continue;
				}
				break;
			case PORTAL_KEYTYPE_VLANID:
				if (portal_srv->key.vlanid !=
						*((unsigned long *) key)) {
					continue;
				}
				break;
			case PORTAL_KEYTYPE_WTPID:
				if (portal_srv->key.wtpid !=
						*((unsigned long *) key)) {
					continue;
				}
				break;
			case PORTAL_KEYTYPE_INTF:
				if (0 != strcmp(portal_srv->key.intf, key)) {
					continue;
				}
				break;
			default:
				return -1;
			}

			portalconf->current_num--;
			memcpy( portal_srv, portal_srv+1, 
					sizeof(struct portal_srv_t)*(portalconf->current_num-i));
			
			return 0;
		}
	}

	return -1;
}

int
portal_conf_modify_srv( struct portal_conf *portalconf,
					PORTAL_KEY_TYPE key_type,
					void *key,
					char *portal_url, 
					uint16_t ntf_port,
					char *domain,
					uint32_t mac_server_ip,
					uint16_t mac_server_port )
{
	struct portal_srv_t *portal_srv=NULL;
	int i;

	for(i=0;i<portalconf->current_num;i++) {
		portal_srv = &(portalconf->portal_srv[i]);
		if (key_type == portal_srv->key_type) {
			switch (key_type) {
			case PORTAL_KEYTYPE_ESSID:
				if (0 != strcmp(portal_srv->key.essid, key)) {
					continue;
				}
				break;
			case PORTAL_KEYTYPE_WLANID:
				if (portal_srv->key.wlanid !=
						*((unsigned long *) key)) {
					continue;
				}
				break;
			case PORTAL_KEYTYPE_VLANID:
				if (portal_srv->key.vlanid !=
						*((unsigned long *) key)) {
					continue;
				}
				break;
			case PORTAL_KEYTYPE_WTPID:
				if (portal_srv->key.wtpid !=
						*((unsigned long *) key)) {
					continue;
				}
				break;
			case PORTAL_KEYTYPE_INTF:
				if (0 != strcmp(portal_srv->key.intf, key)) {
					continue;
				}
				break;
			default:
				return EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
			}

			portal_srv->ntf_port = ntf_port;
			if( (NULL!=portal_url) && (0!=strcmp(portal_url, "")) )
				strncpy(portal_srv->portal_url, portal_url, MAX_PORTAL_URL_LEN-1);
			
			if( (NULL!=domain) && (0!=strcmp(domain, "")) )
				strncpy(portal_srv->domain, domain, MAX_RADIUS_DOMAIN_LEN-1);
			else
				memset(portal_srv->domain, 0 ,MAX_RADIUS_DOMAIN_LEN);
			portal_srv->mac_server_ip = mac_server_ip;
			portal_srv->mac_server_port = mac_server_port;

			return 0;
		}
	}

	return -1;
}


/*nasid!!!*/
#if 0
int
nasid_conf_add_map(struct nasid_conf *nasidconf,
	       NASID_KEY_TYPE key_type, void *key, char *nasid, uint32_t conid)
{
	struct nasid_map_t *nasidmap = NULL;
	struct iprange_t *temp = NULL;
	int index=0;

	if (NULL==nasidconf
		||NULL==nasid){
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	
	if( nasidconf->current_num >= MAX_NASID_NUM ){
		return EAG_ERR_CONFIG_PARAM_OVER_MAX_VALUE;
	}

	index = nasid_conf_get_map_by_key(nasidconf, key_type, key);
	if( EAG_ERR_CONFIG_ITEM_NOT_FOUND != index){
		if ( index >= 0 ){
			return EAG_ERR_CONFIG_ITEM_PARAM_CONFLICT;
		}else{
			return index;
		}
	}
	
	nasidmap = &(nasidconf->nasid_map[nasidconf->current_num]);
	memset(nasidmap, 0, sizeof(struct nasid_map_t));

	nasidmap->key_type = key_type;
	switch (key_type) {
	case NASID_KEYTYPE_WLANID:
		nasidmap->key.wlanid = *((unsigned long *) key);
		break;
	case NASID_KEYTYPE_VLANID:
		nasidmap->key.vlanid = *((unsigned long *) key);
		break;
	case NASID_KEYTYPE_WTPID:
		nasidmap->key.wtpid = *((unsigned long *) key);
		break;
	case NASID_KEYTYPE_IPRANGE:
		temp = (struct iprange_t *) key;
		if (temp->ip_end<=0
			||temp->ip_begin > temp->ip_end){
			return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
		}
		nasidmap->key.iprange.ip_begin = temp->ip_begin;
		nasidmap->key.iprange.ip_end = temp->ip_end;
		break;
	case NASID_KEYTYPE_INTF:
		strncpy(nasidmap->key.intf, key,
			sizeof (nasidmap->key.intf) - 1);
		break;
	default:
		return EAG_ERR_UNKNOWN;

	}

	strncpy(nasidmap->nasid, nasid, sizeof (nasidmap->nasid) - 1);
	nasidmap->conid=conid;

	nasidconf->current_num++;

	return 0;
}

int
nasid_conf_get_map_by_key(struct nasid_conf *nasidconf,
		      NASID_KEY_TYPE key_type, void *key)	
{
	struct nasid_map_t *nasidmap=NULL;
	struct iprange_t *temp = NULL;
	int i;
	
	if (NULL==key){
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	for(i=0;i<nasidconf->current_num;i++) {
		nasidmap = &(nasidconf->nasid_map[i]);
		if (nasidmap->key_type == key_type) {
			switch (key_type) {
			case NASID_KEYTYPE_WLANID:
				if (nasidmap->key.wlanid !=
				    	*((unsigned long *) key)) {
					continue;
				}
				break;
			case NASID_KEYTYPE_VLANID:
				if (nasidmap->key.vlanid !=
				    	*((unsigned long *) key)) {
					continue;
				}

				break;
			case NASID_KEYTYPE_WTPID:
				if (nasidmap->key.wtpid !=
				   		*((unsigned long *) key)) {
					continue;
				}
				break;
			case NASID_KEYTYPE_IPRANGE:
				temp = (struct iprange_t*) key;
				if ( temp->ip_end < nasidmap->key.iprange.ip_begin	//need outside judge ip_end > ip_begin
					||temp->ip_begin > nasidmap->key.iprange.ip_end){
					continue;
				}
				break;
			case NASID_KEYTYPE_INTF:
				if (0 != strcmp(nasidmap->key.intf, key)) {
					continue;
				}
				break;
			default:
				return EAG_ERR_UNKNOWN;
			}

			return i;
		}
	}

	return EAG_ERR_CONFIG_ITEM_NOT_FOUND;
}

int
nasid_conf_totally_match_map_by_key(struct nasid_conf *nasidconf,
		      NASID_KEY_TYPE key_type, void *key)
{
	struct nasid_map_t *nasidmap=NULL;
	struct iprange_t *temp = NULL;
	int i=0;

	if (NULL==key){
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	for(i=0;i<nasidconf->current_num;i++) {
		nasidmap = &(nasidconf->nasid_map[i]);
		if (nasidmap->key_type == key_type) {
			switch (key_type) {
			case NASID_KEYTYPE_WLANID:
				if (nasidmap->key.wlanid !=
				    	*((unsigned long *) key)) {
					continue;
				}
				break;
			case NASID_KEYTYPE_VLANID:
				if (nasidmap->key.vlanid !=
				    	*((unsigned long *) key)) {
					continue;
				}

				break;
			case NASID_KEYTYPE_WTPID:
				if (nasidmap->key.wtpid !=
				   		*((unsigned long *) key)) {
					continue;
				}
				break;
			case NASID_KEYTYPE_IPRANGE:
				temp = (struct iprange_t*) key;
				if (nasidmap->key.iprange.ip_begin != temp->ip_begin
					||nasidmap->key.iprange.ip_end != temp->ip_end){
					continue;
				}
				break;
			case NASID_KEYTYPE_INTF:
				if (0 != strcmp(nasidmap->key.intf, key)) {
					continue;
				}
				break;
			default:
				return EAG_ERR_UNKNOWN;
			}

			return i;
		}
	}

	return EAG_ERR_CONFIG_ITEM_NOT_FOUND;
}


int
nasid_conf_del_map( struct nasid_conf *nasidconf,
				    NASID_KEY_TYPE key_type,
				    void *key )
{
	int i=0;
	int index=0;

	if (NULL==nasidconf){
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	index = nasid_conf_totally_match_map_by_key(nasidconf, key_type, key);
	
	if( index < 0){
		return index;
	}

	for( i=index;i < nasidconf->current_num; i++ ){
		memcpy( &(nasidconf->nasid_map[i]),
				&(nasidconf->nasid_map[i+1]),
				sizeof(struct nasid_map_t));
	}
	nasidconf->current_num --;
	
	return EAG_RETURN_OK;
}
#endif 

 /* nasid config for wlan range */
int
nasid_conf_add_map(struct nasid_conf *nasidconf,
	       NASID_KEY_TYPE key_type, void *key, char *nasid, uint32_t conid)
{
	struct nasid_map_t *nasidmap = NULL;
	struct iprange_t *temp = NULL;
	struct idrange_t *temp_1 = NULL;
	int index=0;

	if (NULL==nasidconf
		||NULL==nasid){
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	
	if( nasidconf->current_num >= MAX_NASID_NUM ){
		return EAG_ERR_CONFIG_PARAM_OVER_MAX_VALUE;
	}

	index = nasid_conf_get_map_by_key(nasidconf, key_type, key);
	if( EAG_ERR_CONFIG_ITEM_NOT_FOUND != index){
		if ( index >= 0 ){
			return EAG_ERR_CONFIG_ITEM_PARAM_CONFLICT;
		}else{
			return index;
		}
	}
	
	nasidmap = &(nasidconf->nasid_map[nasidconf->current_num]);
	memset(nasidmap, 0, sizeof(struct nasid_map_t));

	nasidmap->key_type = key_type;
	switch (key_type) {
		case NASID_KEYTYPE_WLANID:
			temp_1 = (struct idrange_t *) key;
			if (temp_1->id_end<=0
				||temp_1->id_begin > temp_1->id_end){
				return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
			}
			nasidmap->key.wlanidrange.id_begin = temp_1->id_begin;
			nasidmap->key.wlanidrange.id_end = temp_1->id_end;
			break;
		case NASID_KEYTYPE_VLANID:
			temp_1 = (struct idrange_t *) key;
			if (temp_1->id_end<=0
				||temp_1->id_begin > temp_1->id_end){
				return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
			}
			nasidmap->key.vlanidrange.id_begin = temp_1->id_begin;
			nasidmap->key.vlanidrange.id_end = temp_1->id_end;
			break;
		case NASID_KEYTYPE_WTPID:
			temp_1 = (struct idrange_t *) key;
			if (temp_1->id_end<=0
				||temp_1->id_begin > temp_1->id_end){
				return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
			}
			nasidmap->key.wtpidrange.id_begin = temp_1->id_begin;
			nasidmap->key.wtpidrange.id_end = temp_1->id_end;
			break;
		case NASID_KEYTYPE_IPRANGE:
			temp = (struct iprange_t *) key;
			if (temp->ip_end<=0
				||temp->ip_begin > temp->ip_end){
				return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
			}
			nasidmap->key.iprange.ip_begin = temp->ip_begin;
			nasidmap->key.iprange.ip_end = temp->ip_end;
			break;
		case NASID_KEYTYPE_INTF:
			strncpy(nasidmap->key.intf, key,
				sizeof (nasidmap->key.intf) - 1);
			break;
		default:
			return EAG_ERR_UNKNOWN;
	}

	strncpy(nasidmap->nasid, nasid, sizeof (nasidmap->nasid) - 1);
	nasidmap->conid=conid;

	nasidconf->current_num++;

	return 0;
}

int
nasid_conf_totally_match_map_by_key(struct nasid_conf *nasidconf,
		      NASID_KEY_TYPE key_type, void *key)
{
	struct nasid_map_t *nasidmap=NULL;
	struct iprange_t *temp = NULL;
	struct idrange_t *temp_1 = NULL;
	int i=0;

	if (NULL==key){
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	for(i=0;i<nasidconf->current_num;i++) {
		nasidmap = &(nasidconf->nasid_map[i]);
		if (nasidmap->key_type == key_type) {
			switch (key_type) {
			case NASID_KEYTYPE_WLANID:
				temp_1 = (struct idrange_t*) key;
				if (nasidmap->key.wlanidrange.id_begin != temp_1->id_begin
					||nasidmap->key.wlanidrange.id_end != temp_1->id_end){
					continue;
				}
				break;
			case NASID_KEYTYPE_VLANID:
				temp_1 = (struct idrange_t*) key;
				if (nasidmap->key.vlanidrange.id_begin != temp_1->id_begin
					||nasidmap->key.vlanidrange.id_end != temp_1->id_end){
					continue;
				}

				break;
			case NASID_KEYTYPE_WTPID:
				temp_1 = (struct idrange_t*) key;
				if (nasidmap->key.wtpidrange.id_begin != temp_1->id_begin
					||nasidmap->key.wtpidrange.id_end != temp_1->id_end){
					continue;
				}
				break;
			case NASID_KEYTYPE_IPRANGE:
				temp = (struct iprange_t*) key;
				if (nasidmap->key.iprange.ip_begin != temp->ip_begin
					||nasidmap->key.iprange.ip_end != temp->ip_end){
					continue;
				}
				break;
			case NASID_KEYTYPE_INTF:
				if (0 != strcmp(nasidmap->key.intf, key)) {
					continue;
				}
				break;
			default:
				return EAG_ERR_UNKNOWN;
			}

			return i;
		}
	}

	return EAG_ERR_CONFIG_ITEM_NOT_FOUND;
}

int
nasid_conf_modify_map(struct nasid_conf *nasidconf,
			NASID_KEY_TYPE key_type, void *key, char *nasid, uint32_t conid)
{
	struct nasid_map_t *nasidmap = NULL;
	struct iprange_t *temp = NULL;
	struct idrange_t *temp_1 = NULL;
	int index=0;

	if (NULL==nasidconf
		||NULL==nasid){
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if( nasidconf->current_num >= MAX_NASID_NUM ){
		return EAG_ERR_CONFIG_PARAM_OVER_MAX_VALUE;
	}

	index = nasid_conf_totally_match_map_by_key(nasidconf, key_type, key);

	if( index < 0){
		return index;
	}

	nasidmap = &(nasidconf->nasid_map[index]);
	memset(nasidmap, 0, sizeof(struct nasid_map_t));

	nasidmap->key_type = key_type;
	switch (key_type) {
		case NASID_KEYTYPE_WLANID:
			temp_1 = (struct idrange_t *) key;
			if (temp_1->id_end<=0
				||temp_1->id_begin > temp_1->id_end){
				return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
			}
			nasidmap->key.wlanidrange.id_begin = temp_1->id_begin;
			nasidmap->key.wlanidrange.id_end = temp_1->id_end;
			break;
		case NASID_KEYTYPE_VLANID:
			temp_1 = (struct idrange_t *) key;
			if (temp_1->id_end<=0
				||temp_1->id_begin > temp_1->id_end){
				return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
			}
			nasidmap->key.vlanidrange.id_begin = temp_1->id_begin;
			nasidmap->key.vlanidrange.id_end = temp_1->id_end;
			break;
		case NASID_KEYTYPE_WTPID:
			temp_1 = (struct idrange_t *) key;
			if (temp_1->id_end<=0
				||temp_1->id_begin > temp_1->id_end){
				return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
			}
			nasidmap->key.wtpidrange.id_begin = temp_1->id_begin;
			nasidmap->key.wtpidrange.id_end = temp_1->id_end;
			break;
		case NASID_KEYTYPE_IPRANGE:
			temp = (struct iprange_t *) key;
			if (temp->ip_end<=0
				||temp->ip_begin > temp->ip_end){
				return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
			}
			nasidmap->key.iprange.ip_begin = temp->ip_begin;
			nasidmap->key.iprange.ip_end = temp->ip_end;
			break;
		case NASID_KEYTYPE_INTF:
			strncpy(nasidmap->key.intf, key,
				sizeof (nasidmap->key.intf) - 1);
			break;
		default:
			return EAG_ERR_UNKNOWN;
	}

	strncpy(nasidmap->nasid, nasid, sizeof (nasidmap->nasid) - 1);
	nasidmap->conid=conid;

	return 0;
}

int
nasid_conf_get_map_by_key(struct nasid_conf *nasidconf,
		      NASID_KEY_TYPE key_type, void *key)	
{
	struct nasid_map_t *nasidmap=NULL;
	struct iprange_t *temp = NULL;
	struct idrange_t *temp_1 = NULL;
	int i;
	
	if (NULL==key){
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	for(i=0;i<nasidconf->current_num;i++) {
		nasidmap = &(nasidconf->nasid_map[i]);
		if (nasidmap->key_type == key_type) {
			switch (key_type) {
			case NASID_KEYTYPE_WLANID:
				temp_1 = (struct idrange_t*) key;
				if ( temp_1->id_end < nasidmap->key.wlanidrange.id_begin
					||temp_1->id_begin > nasidmap->key.wlanidrange.id_end){
					continue;
				}
				break;
			case NASID_KEYTYPE_VLANID:
				temp_1 = (struct idrange_t*) key;
				if ( temp_1->id_end < nasidmap->key.vlanidrange.id_begin
					||temp_1->id_begin > nasidmap->key.vlanidrange.id_end){
					continue;
				}
				break;
			case NASID_KEYTYPE_WTPID:
				temp_1 = (struct idrange_t*) key;
				if ( temp_1->id_end < nasidmap->key.wtpidrange.id_begin
					||temp_1->id_begin > nasidmap->key.wtpidrange.id_end){
					continue;
				}
				break;
			case NASID_KEYTYPE_IPRANGE:
				temp = (struct iprange_t*) key;
				if ( temp->ip_end < nasidmap->key.iprange.ip_begin	//need outside judge ip_end > ip_begin
					||temp->ip_begin > nasidmap->key.iprange.ip_end){
					continue;
				}
				break;
			case NASID_KEYTYPE_INTF:
				if (0 != strcmp(nasidmap->key.intf, key)) {
					continue;
				}
				break;
			default:
				return EAG_ERR_UNKNOWN;
			}

			return i;
		}
	}

	return EAG_ERR_CONFIG_ITEM_NOT_FOUND;
}

int
nasid_conf_del_map( struct nasid_conf *nasidconf,
				    NASID_KEY_TYPE key_type,
				    void *key )
{
	int i=0;
	int index=0;

	if (NULL==nasidconf){
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	index = nasid_conf_totally_match_map_by_key(nasidconf, key_type, key);
	
	if( index < 0){
		return index;
	}

	for( i=index;i < nasidconf->current_num; i++ ){
		memcpy( &(nasidconf->nasid_map[i]),
				&(nasidconf->nasid_map[i+1]),
				sizeof(struct nasid_map_t));
	}
	nasidconf->current_num --;
	
	return EAG_RETURN_OK;
}

//nas port id
#if 0
int
nasportid_conf_find_map( struct nasportid_conf *nasportidconf,
					uint32_t wlanid_begin, uint32_t wlanid_end,
					uint32_t wtpid_begin, uint32_t wtpid_end,
					uint32_t vlanid )
{
	int i;
	struct nasportid_map_t *map = NULL;

	for( i=0; i<nasportidconf->current_num; i++ ){
		map = &(nasportidconf->nasportid_map[i]);
		if ((wlanid_begin > map->wlanid_end	//make sure wlanid_begin < wlanid_end
			|| wlanid_end < map->wlanid_begin)
			&& (wtpid_begin > map->wtpid_end	//make sure wtpid_begin < wtpid_end
			|| wtpid_end < map->wtpid_begin)){	//vlanid no associate with wlanid wtpid
			continue;
		}else{
			return i;
		}
	}

	return EAG_ERR_CONFIG_ITEM_NOT_FOUND;
}
#endif
int
nasportid_conf_match_map_by_wlan( struct nasportid_conf *nasportidconf,
					uint32_t wlanid_begin, uint32_t wlanid_end,
					uint32_t wtpid_begin, uint32_t wtpid_end,
					uint32_t nasportid )
{
	int i;
	struct nasportid_map_t *map = NULL;

	for (i=0; i < nasportidconf->current_num; i++) {
		map = &(nasportidconf->nasportid_map[i]);
		if(wlanid_begin == map->key.wlan_wtp.wlanid_begin
			&& wlanid_end == map->key.wlan_wtp.wlanid_end
			&& wtpid_begin == map->key.wlan_wtp.wtpid_begin
			&& wtpid_end == map->key.wlan_wtp.wtpid_end 
			&& nasportid == map->nasportid) {
			return i;
		}
	}

	return EAG_ERR_CONFIG_ITEM_NOT_FOUND;
}

int
nasportid_conf_match_map_by_vlan( struct nasportid_conf *nasportidconf,
					uint32_t vlanid_begin, uint32_t vlanid_end,
					uint32_t nasportid )
{
	int i;
	struct nasportid_map_t *map = NULL;

	for (i=0; i < nasportidconf->current_num; i++) {
		map = &(nasportidconf->nasportid_map[i]);
		if(vlanid_begin == map->key.vlan.vlanid_begin
			&& vlanid_end == map->key.vlan.vlanid_end
			&& nasportid == map->nasportid) {
			return i;
		}
	}

	return EAG_ERR_CONFIG_ITEM_NOT_FOUND;
}


int
nasportid_conf_add_map_by_wlan( struct nasportid_conf *nasportidconf,
					uint32_t wlanid_begin, uint32_t wlanid_end,
					uint32_t wtpid_begin, uint32_t wtpid_end,
					uint32_t nasportid )
{
	struct nasportid_map_t *map = NULL;
	int ret;
	if( NULL == nasportidconf ){
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if( wlanid_begin <= 0
		|| wlanid_begin > MAX_WLANID_INPUT 
		|| wlanid_end <= 0
		|| wlanid_end > MAX_WLANID_INPUT
		|| wlanid_end < wlanid_begin
		|| wtpid_begin <= 0
		|| wtpid_begin > MAX_WTPID_INPUT
		|| wtpid_end <= 0
		|| wtpid_end > MAX_WTPID_INPUT
		|| wtpid_end < wtpid_begin 
		|| nasportid <= 0
		|| nasportid > MAX_MAPED_VLANID){
		return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
	}

	if( nasportidconf->current_num >= MAX_NASPORTID_NUM ){
		return EAG_ERR_CONFIG_PARAM_OVER_MAX_VALUE;
	}

	ret = nasportid_conf_match_map_by_wlan(nasportidconf,
						wlanid_begin, wlanid_end,
						wtpid_begin, wtpid_end,
						nasportid);
	
	if( EAG_ERR_CONFIG_ITEM_NOT_FOUND != ret ){
		if ( ret >=0 ){
			return EAG_ERR_CONFIG_ITEM_PARAM_CONFLICT;	
		}else {
			return ret;
		}
	}

	map = &(nasportidconf->nasportid_map[nasportidconf->current_num]);
	map->key.wlan_wtp.wlanid_begin = wlanid_begin;
	map->key.wlan_wtp.wlanid_end = wlanid_end;
	map->key.wlan_wtp.wtpid_begin = wtpid_begin;
	map->key.wlan_wtp.wtpid_end = wtpid_end;
	map->nasportid = nasportid;
	map->key_type = NASPORTID_KEYTYPE_WLAN_WTP;

	nasportidconf->current_num++;

	return EAG_RETURN_OK;
}

int
nasportid_conf_del_map_by_wlan(struct nasportid_conf *nasportidconf,
					uint32_t wlanid_begin, uint32_t wlanid_end,
					uint32_t wtpid_begin, uint32_t wtpid_end,
					uint32_t nasportid)
{
	int index;
	int i;
	if( NULL == nasportidconf ){
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if( wlanid_begin <= 0
		|| wlanid_begin > MAX_WLANID_INPUT 
		|| wlanid_end <= 0
		|| wlanid_end > MAX_WLANID_INPUT
		|| wlanid_end < wlanid_begin
		|| wtpid_begin <= 0
		|| wtpid_begin > MAX_WTPID_INPUT
		|| wtpid_end <= 0
		|| wtpid_end > MAX_WTPID_INPUT
		|| wtpid_end < wtpid_begin 
		|| nasportid <= 0
		|| nasportid > MAX_MAPED_VLANID){
		return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
	}

	index = nasportid_conf_match_map_by_wlan(nasportidconf,
						wlanid_begin, wlanid_end,
						wtpid_begin, wtpid_end, 
						nasportid);
	if( index < 0){
		return index;	//err
	}

	for (i = index;i < nasportidconf->current_num; i++){
		memcpy( &(nasportidconf->nasportid_map[i]),
				&(nasportidconf->nasportid_map[i+1]),
				sizeof(struct nasportid_map_t));
	}
	nasportidconf->current_num--;
	
	return 0;
}

int
nasportid_conf_add_map_by_vlan( struct nasportid_conf *nasportidconf,
					uint32_t vlanid_begin, uint32_t vlanid_end,
					uint32_t nasportid )
{
	struct nasportid_map_t *map = NULL;
	int ret;
	if( NULL == nasportidconf ){
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if(vlanid_begin <= 0
		|| vlanid_begin > MAX_VLANID_INPUT 
		|| vlanid_end <= 0
		|| vlanid_end > MAX_VLANID_INPUT
		|| vlanid_end < vlanid_begin
		|| nasportid <= 0
		|| nasportid > MAX_MAPED_VLANID){
		return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
	}

	if( nasportidconf->current_num >= MAX_NASPORTID_NUM ){
		return EAG_ERR_CONFIG_PARAM_OVER_MAX_VALUE;
	}

	ret = nasportid_conf_match_map_by_vlan(nasportidconf,
						vlanid_begin, vlanid_end,
						nasportid);
	
	if( EAG_ERR_CONFIG_ITEM_NOT_FOUND != ret ){
		if ( ret >=0 ){
			return EAG_ERR_CONFIG_ITEM_PARAM_CONFLICT;	
		}else {
			return ret;
		}
	}

	map = &(nasportidconf->nasportid_map[nasportidconf->current_num]);
	map->key.vlan.vlanid_begin = vlanid_begin;
	map->key.vlan.vlanid_end = vlanid_end;
	map->nasportid = nasportid;
	map->key_type = NASPORTID_KEYTYPE_VLAN;

	nasportidconf->current_num++;

	return EAG_RETURN_OK;
}

int
nasportid_conf_del_map_by_vlan( struct nasportid_conf *nasportidconf,
					uint32_t vlanid_begin, uint32_t vlanid_end,
					uint32_t nasportid )
{
	int index;
	int i;
	if( NULL == nasportidconf ){
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if(vlanid_begin <= 0
		|| vlanid_begin > MAX_VLANID_INPUT 
		|| vlanid_end <= 0
		|| vlanid_end > MAX_VLANID_INPUT
		|| vlanid_end < vlanid_begin
		|| nasportid > MAX_MAPED_VLANID){
		return EAG_ERR_CONFIG_PARAM_OUT_OF_RANGE;
	}

	index = nasportid_conf_match_map_by_vlan(nasportidconf,
						vlanid_begin, vlanid_end,
						nasportid);
	if( index < 0){
		return index;	//err
	}

	for (i = index; i < nasportidconf->current_num; i++) {
		memcpy( &(nasportidconf->nasportid_map[i]),
				&(nasportidconf->nasportid_map[i+1]),
				sizeof(struct nasportid_map_t));
	}
	nasportidconf->current_num--;
	
	return 0;
}


#if 0
uint32_t 
nasportid_conf_get_vlan_maped( struct nasportid_conf *nasportidconf,
					uint32_t wlanid, uint32_t wtpid )
{
	struct nasportid_map_t *map = NULL;
	int i;
	
	for( i=0; i<nasportidconf->current_num; i++ ){
		map = &(nasportidconf->nasportid_map[i]);
		if( wlanid >= map->wlanid_begin
			&& wlanid  <= map->wlanid_end
			&& wtpid >= map->wtpid_begin
			&& wtpid <= map->wtpid_end ){
			return map->vlanid;
		}
	}

	return 0;
}
#endif
#ifdef eag_conf_test


int
main()
{
	return 0;
}

#endif

