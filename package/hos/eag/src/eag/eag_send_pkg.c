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
#include <string.h>
#include <stdio.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <syslog.h>

#include "limits2.h"
#include "nm_list.h"
#include "eag_errcode.h"
#include "eag_log.h"
#include "eag_util.h"
#include "eag_mem.h"
#include "eag_blkmem.h"
#include "eag_thread.h"
#include "eag_portal.h"
#include "md5.h"


#include "eag_mem.c"
#include "eag_log.c"

#include "eag_blkmem.c"
#include "eag_thread.c"

#include "eag_portal.c"
#include "eag_radius.c"
#include "eag_util.c"
#include "md5.c"
#include "eag_errcode.c"






eag_thread_master_t eag_thread_master;

eag_portal_t *portal = NULL;
unsigned int listen_ip = 0;	//192.168.1.16;
unsigned short listen_port = 0;
struct in_addr addr;

struct portal_pkg_t pkgsend;

int load_conf_line( struct portal_pkg_t *pkg, char *line )
{
	char *temp;
	int i;
	struct in_addr addr;
	unsigned long time;

#if 0
userip=192.168.1.1
errcode=0
pkgtype=0x36
username=aaaa
password=bbbb
challenge=0x00112233445566778899aabbccddeeff
chappasswd=0x00112233445566778899aabbccddeeff
usermac=00:11:22:33:44:55
ua=ieee
basip=1.2.3.4
starttime=123456789
stoptime=1234569411
nasid=99887666555

#endif
	if(line[0]=='#'){
		return 0;
	}
	temp = strchr(line,'=');
	if( NULL == temp ){
		return 0;
	}
	*temp = 0;
	temp++;

	for( i=0; temp[i]!=0; i++ ){
		if( 0x0a == temp[i] || 0x0b == temp[i] ){
			temp[i] = 0;
		}
	}
	
	if( 0 == strcmp("userip",line) ){		
		inet_aton(temp, &addr );
		pkg->user_ip = ntohl(addr.s_addr);
	}else if( 0 == strcmp("errcode",line) ){
		pkg->err_code = atol(temp);
	}else if( 0 == strcmp("pkgtype",line) ){
		pkg->pkg_type = strtol(temp,NULL,16);
	}else if( 0 == strcmp("username",line) ){
		eag_portal_pkg_add_attr(pkg, ATTR_USERNAME,temp,strlen(temp));
	}else if( 0 == strcmp("password",line) ){
		eag_portal_pkg_add_attr(pkg, ATTR_PASSWORD,temp,strlen(temp));
	}else if( 0 == strcmp("challenge",line) ){

	}else if( 0 == strcmp("chappasswd",line) ){

	}else if( 0 == strcmp("usermac",line) ){
		unsigned char mac[6];
		str2mac(mac, 6, temp);
		eag_portal_pkg_add_attr(pkg,ATTR_USERMAC,mac,6);
	}else if( 0 == strcmp("ua",line) ){
		eag_portal_pkg_add_attr(pkg,ATTR_USER_AGENT,temp,strlen(temp));
	}else if( 0 == strcmp("basip",line) ){
		unsigned long ip;
		inet_aton(temp, &addr );
		ip = ntohl(addr.s_addr);
		eag_portal_pkg_add_attr( pkg,ATTR_BASIP,&ip,4);
	}else if( 0 == strcmp("starttime",line) ){
		time = atol(temp);
		eag_portal_pkg_add_attr( pkg, ATTR_SESS_START, &time, 4);
	}else if( 0 == strcmp("stoptime",line) ){
		time = atol(temp);
		eag_portal_pkg_add_attr( pkg, ATTR_SESS_STOP, &time, 4);
	}
	else if( 0 == strcmp("sesstime",line) ){
		time = atol(temp);
		eag_portal_pkg_add_attr( pkg, ATTR_SESS_TIME, &time, 4);
	}
	else if( 0 == strcmp("nasid",line) ){
		eag_portal_pkg_add_attr( pkg, ATTR_NASID, temp, strlen(temp));
	}
	

	
}

int load_pkg( struct portal_pkg_t *pkg, char *filepath )
{
	FILE *file;
	char line[256];

	pkg->version = 0x01;
	file = fopen( filepath, "r" );
	if( NULL == file ){
		printf("config file open error!");
		return -1;
	}

	
	fgets(line, sizeof(line), file);
	while(!feof(file)){
		load_conf_line(pkg,line);
		fgets(line, sizeof(line), file );
	}

	fclose( file );

	return 0;
}

int
main(int argc, char *argv[])
{
	int iret = 0;
	struct sockaddr_in sockaddr;

	if (argc != 4) {
		printf("usage:%s ip port configfile", argv[0]);
		return 0;
	}

	eag_log_init(1);

	iret = eag_log_add_filter("eag_portal:macauth:portal_pkg");


	if (EAG_RETURN_OK != eag_thread_master_init(&eag_thread_master)) {
		return -1;
	}

	
	listen_ip = 0;//ntohl(addr.s_addr);
	listen_port = 0;//atoi(argv[2]);

	memset(	&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	inet_aton(argv[1], &addr);
	sockaddr.sin_addr = addr;
	sockaddr.sin_port = htons(atoi(argv[2]));
	

	portal = eag_portal_create();
	if (NULL == portal) {
		return -1;
	}
	eag_portal_set_params(portal, listen_ip, listen_port);
	eag_portal_set_thread_master(portal, &eag_thread_master);
	eag_portal_set_resend_params(portal, 3, 3);

	eag_portal_start(portal);
	//eag_portal_set_decaps_cb(portal, eag_macauth_portal_decaps_cb);

	/*init package*/
	memset( &pkgsend, 0, sizeof(pkgsend));
	load_pkg( &pkgsend, argv[3] );
	eag_portal_send_pkg( portal, &pkgsend, &sockaddr );
	
	int i=5;
	while (i>0) {
		struct timeval timer_wait;
		timer_wait.tv_sec = 1;
		timer_wait.tv_usec = 0;

		//eag_portal_timeout(portal);
		eag_thread_dispatch(&eag_thread_master, &timer_wait);
		i--;
	}

	return 0;

}


