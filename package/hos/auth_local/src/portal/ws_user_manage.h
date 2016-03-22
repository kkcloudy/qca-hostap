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
* ws_user_manage.h
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
*
*
*
*******************************************************************************/

#ifndef _WS_USER_MANAGE_H
#define _WS_USER_MANAGE_H
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define EAGINS_ID_BEGIN	1
#define MAX_EAGINS_NUM	16
#define EAGINS_UNIXSOCK_PREFIX	"/var/run/eagins_user"

#define CAPTIVE_IP_CHECK_SUCCESS		0
#define CAPTIVE_IP_CHECK_FAILURE		1

#define INTERFACES_CHECK_SUCCESS		0
#define INTERFACES_CHECK_FAILURE		1

#define log_dbg(fmt,args...) fprintf( stderr, fmt, ## args)
#define log_err(e,fmt,args...)  fprintf(stderr, fmt,## args)

#include "user_manage.h"
#if 1 
struct cp_interface_t{
	int captive_portal_id;
	char *if_name;
	struct cp_interface_t *next;
};
typedef struct cp_interface_t* cp_interface_link;

#endif
/*这个将来可能被snmp调用到*/
STUserManagePkg *createRequirePkg( USER_MNG_TYPE req_type, void *param1, void *param2 );

int doRequire( STUserManagePkg *pkg, int ip, int port, int wait, STUserManagePkg **p_pkg_get );

int snmp_get_userstate_bymac(char * mac);

STUserManagePkg * show_auth_users_info(int * start, int * end);
int  add_interface_to_captive_portal(int captive_portal_id,char  *input_interface);
int  delete_interface_of_captive_portal(int captive_portal_id,char  *input_interface);
int   get_captive_portal_info( cp_interface_link captive_portal_info ,int * captive_num);
void  interface_list_destroy(cp_interface_link head);     
#endif
