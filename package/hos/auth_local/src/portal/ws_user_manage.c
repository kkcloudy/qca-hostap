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
* ws_user_manage.c
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
*
* DESCRIPTION: 
*
*
*******************************************************************************/
#include "ws_user_manage.h"

/*************************
*创建一个请求的数据包
*在不同的req_type下，param1和param2有不同的意义。
*REQ_GET_ONLINE_NUM:参数无用
REQ_GET_USR_BY_INDEX_RANG:param1 -> begin index, param2 end index; becareful it pointer.
REQ_LOGOUT_BY_INFO:param1 -> pointer of STOnlineUserInfo
REQ_GET_BY_INDEX:param1 -> the index whitch to find
REQ_GET_BY_NAME:param1 -> user name
REQ_GET_BY_MAC:param1 -> user mac
REQ_GET_BY_IP:param1 -> user ip
***************************/
STUserManagePkg *createRequirePkg( USER_MNG_TYPE req_type, void *param1, void *param2 )
{
	STUserManagePkg *pstPkgRet;
	
	pstPkgRet = (STUserManagePkg *)malloc(sizeof(STUserManagePkg));
	if( NULL == pstPkgRet )
	{
		return NULL;	
	}
	memset( pstPkgRet, 0, sizeof(STUserManagePkg) );           
	
	pstPkgRet->len = sizeof(STUserManagePkg);
	pstPkgRet->pkg_type = req_type;
	
	switch( req_type )
	{
		case REQ_GET_ONLINE_NUM:
			break;
		case REQ_GET_USR_BY_INDEX_RANG:
			pstPkgRet->data.req.reqinfo.idx.idx_begin = *((int*)param1);
			pstPkgRet->data.req.reqinfo.idx.idx_end = *((int*)param2);
			break;
		case REQ_LOGOUT_BY_INFO:
			//memcpy( &(pstPkgRet->data.req.reqinfo.user_info), param1, sizeof(STOnlineUserInfo) );
			pstPkgRet->data.req.reqinfo.user_ip = *((unsigned int*)param1);
			break;
		case REQ_GET_BY_INDEX:
			pstPkgRet->data.req.reqinfo.idx_get = *((int*)param1);
			break;
		case REQ_GET_BY_NAME:
			memcpy( pstPkgRet->data.req.reqinfo.username, param1, sizeof(pstPkgRet->data.req.reqinfo.username) );
			break;
		case REQ_GET_BY_MAC:
			memcpy( pstPkgRet->data.req.reqinfo.user_mac, param1, sizeof(pstPkgRet->data.req.reqinfo.user_mac) );
			break;
		case REQ_GET_BY_IP:
			pstPkgRet->data.req.reqinfo.user_ip = *((unsigned int*)param1);
			break;
		case ACK_GET_ONLINE_NUM:
		case ACK_GET_USR_BY_INDEX_RANG:
		case ACK_LOGOUT_BY_INFO:
		case ACK_GET_BY_INDEX:
		case ACK_GET_BY_NAME:
		case ACK_GET_BY_MAC:
		case ACK_GET_BY_IP:
		default:
			free( pstPkgRet );
			return NULL;
			break;
	}
	
	return pstPkgRet;
}


/*发送请求，等待相应。函数的返回可能根据网络状况有一定的延时，但最长不超过wait指定的秒数，
如果wait<=0,则默认延迟3秒，最长不超过15s*/
int doRequire( STUserManagePkg *pkg, int ip, int port, int wait, STUserManagePkg **p_pkg_get )
{
	int fd;
	int len,ret;
	int data_len;
	struct sockaddr_in remoteaddr;
	int begintime;
	
	char data[1024];

	int delay = 0;
	
	fprintf(stderr, "doRequire  \n");
	if( wait <= 0 )
	{
		delay = 3;	
	}
	else if( wait >15 )
	{
		delay = 15;	
	}
	else
	{
		delay = wait;	
	}
		
	/*创建连接*/
	fd = socket(AF_INET, SOCK_STREAM, 0);
	remoteaddr.sin_family = AF_INET;
	remoteaddr.sin_addr.s_addr = htonl(ip);/*连接到自己*/
	remoteaddr.sin_port = htons(port);
	len = sizeof(remoteaddr);
	fprintf(stderr, "before connect!!  \n");
	ret = connect(fd, (struct sockaddr *)&remoteaddr, len);
	if(ret == -1) 
	{
		fprintf(stderr, "connect() error\n");
		return -1;
	}
	fprintf(stderr, "after connect() ret=%d\n", ret );
	/*发送请求*/
	begintime = time(0);
	fprintf(stderr, "after connect() begintime=%d\n", begintime );	
	if( 0 != sendpkg( fd, delay, pkg ) )
	{
		fprintf( stderr, "sendpkg error!" );
		return -1;
	}
	fprintf(stderr, "after send() time(0)=%d\n", time(0) );		
	/*接收响应*/
	if( time(0) - begintime >= delay )
	{
		fprintf( stderr, "time out!!!" );
		return -1;	
	}
	
	fprintf(stderr, "before getpkg!!  time(0) = %d\n", time(0));
	ret = getpkg( fd, delay - (time(0) - begintime), p_pkg_get );
	fprintf( stderr, "after getpkg ret = %d\n", ret );
	close( fd );
	return ret;
}


/*return  0 为认证用户
		-1为非认证用户
*/
int snmp_get_userstate_bymac(char * mac)
{
	STUserManagePkg * req = NULL;
	STUserManagePkg * rsv = NULL;
	
	req = createRequirePkg( REQ_GET_BY_MAC, mac, NULL );
	if( req == NULL )
	{
		printf(  "create req pkg failed !!");
		return -1;
	}
	int ret = doRequire( req, ntohl(inet_addr("127.0.0.1")), 2001, 5, &rsv );
	if( rsv == NULL )
	{
		printf( "get respones failed!\n" );
		return -1;
	}
	printf( "rsv->all_user_num=%d!\n", rsv->all_user_num );

/*判断用户是否认证*/
	if( rsv->all_user_num == 0 )
		return -1;  /*no authed*/
	else
		return 0; /*authed*/
	
}




STUserManagePkg * show_auth_users_info(int * start, int * end)
{
	STUserManagePkg * req = NULL;
	STUserManagePkg * rsv = NULL;


	req = createRequirePkg( REQ_GET_USR_BY_INDEX_RANG, start, end );

	if( req == NULL )
	{
		fprintf( stderr, "create req pkg failed !!");
		return NULL;
	}

	int ret = doRequire( req, ntohl(inet_addr("127.0.0.1")), 2001, 5, &rsv );

	if( rsv == NULL )
	{
		fprintf( stderr, "get respones failed!\n" );
		return NULL;
	}
	
	return rsv;
}


