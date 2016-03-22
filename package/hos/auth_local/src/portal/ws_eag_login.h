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
* ws_eag_login.h
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

#ifndef WS_EAG_LOGIN
#define WS_EAG_LOGIN
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "ws_user_manage.h"





/*************************************
定义基本的数据类型
************************************/
#define INT8	char
#define UINT8	unsigned char
#define INT16	short
#define UINT16	unsigned short
#define INT32	int
#define UINT32	unsigned int
#define INT64	long long
#define UINT64	unsigned long long

/***********************************************
申明与移动portal 协议相关的数据类型，
参考《中国移动WEB接入流程测试规范》
	《中国移动WLAN接入系统设备功能和性能测试规范v5.3.1》
	
************************************************/

typedef struct {
	UINT8	version;
	UINT8	pkg_type;
	UINT8	auth_type;/*pap or chap*/
	UINT8	rsv;/*保留字段*/
	UINT16	serial_no;/*SerialNo字段为报文的序列号，长度为 2 字节，由Portal Server随机生成，Portal Server必须尽量保证不同认证流程的SerialNo在一定时间内不得重复，在同一个认证流程中所有报文的SerialNo相同*/
	UINT16	req_id;/*ReqID字段长度为 2 个字节，由AC设备随机生成，尽量使得在一定时间内ReqID不重复。*//*这里的想法是添加一个id池*/
	UINT32	user_ip;
	UINT16	user_port;
	UINT8	err_code;
	UINT8	attr_num;
	UINT8	attr[0];/*占位符号。根据实际的需要设置该部分的长度。*/
}STPortalPkg;

/*等于数据包的类型*/
typedef enum {
	REQ_CHALLENGE=0x01,/*Portal Server 向AC设备发送的请求Challenge报文*/
	ACK_CHALLENGE,/*0x02AC设备对Portal Server请求Challenge报文的响应报文*/
	REQ_AUTH,/*0x03Portal Server向AC设备发送的请求认证报文*/
	ACK_AUTH,/*0x04AC设备对Portal Server请求认证报文的响应报文*/
	REQ_LOGOUT,/*0x05若ErrCode字段值为0x00，表示此报文是Portal Server向AC设备发送的请求用户下线报文；若ErrCode字段值为0x01，表示该报文是Portal Server发送的超时报文，其原因是Portal Server发出的各种请求在规定时间内没有收到响应报文。*/
	ACK_LOGOUT,/*0x06AC设备对Portal Server请求下线报文的响应报文*/
	AFF_ACK_AUTH,/*0x07Portal Server对收到的认证成功响应报文的确认报文*/
	NTF_LOGOUT,/*0x08用户被强制下线通知报文*/
	REQ_INFO,/*0x09信息询问报文*/
	ACK_INFO,/*0x0A信息询问的应答报文*/
	REQ_MACINFO=0x30,
	ACK_MACINFO=0x31,
	NTF_MACLOGON=0x32,
	NTF_MACLOGOFF=0x34		
}PKG_TYPE;

/*定义认证的协议*/
typedef enum{
	AUTH_CHAP=0x00,
	AUTH_PAP=0x01
}AUTH_TYPE;


/*定义属性字段的类型*/
typedef enum{
	ATTR_USERNAME=1, 
	ATTR_PASSWORD,
	ATTR_CHALLENGE,/*chap方式的魔术字。*/
	ATTR_CHAPPASSWORD,/*经过chap方式加密后的密码。*/
	ATTR_PORT_ID=0x08,
	ATTR_BASIP=0x0a,
	ATTR_USERMAC=0x0b,
	ATTR_NASID=0x30,
	ATTR_SESS_START=0x31,
	ATTR_SESS_STOP=0x32,
	ATTR_SESS_TIME=0x33,
	ATTR_USER_IPV6 = 0xf1, /* add by houyongtao for ipv6 */
}ATTR_TYPE;


typedef struct{
	UINT8 attr_type;/*这里没有直接用 ATTR_TYPE做为数据类型，是因为在不同的编译器上　enum的大小可能不一样。而移动文档中规定attr_type占用1个byte;*/
	UINT8 attr_len;
	UINT8 attr_value[1];/*实际大小由attr_len来决定。*/
}STPkgAttr;

/*error code*/
/*ack challeng报文(ac回复给portal server的challenge请求的报文)的errcode 定义　　pkg_type=2(ACK_CHALLENGE)*/
typedef enum{
	CHALLENGE_SUCCESS=0,
	CHALLENGE_REJECT,/*challenge 被拒绝*/
	CHALLENGE_CONNECTED,/*此连接已经建立*/
	CHALLENGE_ONAUTH,/*当前portal server该用户正在认证过程中，请稍候再试*/
	CHALLENGE_FAILED/*用户的challenge请求失败*/
}ACK_CHALLENGE_ERRCODE;

/*ack auth报文(ac回复portal server的认证请求的报文)pkg_type = 4(ACK_AUTH)*/
typedef enum{
	PORTAL_AUTH_SUCCESS=0,
	PORTAL_AUTH_REJECT,
	PORTAL_AUTH_CONNECTED,
	PORTAL_AUTH_ONAUTH,/*当前portal server该用户正在认证过程中，请稍候再试*/
	PORTAL_AUTH_FAILED/*用户的challenge请求失败*/
}ACK_AUTH_ERRCODE;

/*pkg_type = 6(ACK_LOGOUT)*/
typedef enum{
	EC_ACK_LOGOUT_SUCCESS,
	EC_ACK_LOGOUT_REJECT,
	EC_ACK_LOGOUT_FAILED
}ACK_LOGOUT_ERRCODE;



/*pkg_type 5 req logout    portal---AC 请求用户下线*/
typedef enum{
	EC_REQ_LOGOUT, 			/*此报文是Portal Server发给AC设备的请求下线报文*/
	EC_REV_TIME_OUT			/*Portal Server没有收到AC设备发来的对各种请求的响应报文，而定时器时间到（即超时）时由Portal Server发给AC设备的报文*/
}REQ_LOGOUT_ERRCODE;



#define MAX_EAG_LOGIN_NAME_LEN 256
#define MAX_EAG_LOGIN_PASS_LEN 16

#define STATUS_NOTAUTH	0
#define STATUS_AUTHED	1
#define STATUS_FAILED	2
	


typedef struct {
	char	 	usrName[MAX_EAG_LOGIN_NAME_LEN];
	char 		usrPass[MAX_EAG_LOGIN_PASS_LEN];
	int 		usrOperation;/*1 --login,2--logout*/
	UINT32		usrStatus;
}STUserInfo;


typedef struct {
	int fd;
	UINT32 protocal;
	STPortalPkg *pSendPkg;
	STPortalPkg *pRevPkg;
	
}STAuthProcess;

#define MAX_ATTR_VALUE_LEN 253


typedef struct MD5Context {
  UINT32 buf[4];
  UINT32 bits[2];
  unsigned char in[64];
}MD5_CTX;

#define MD5LEN 16
#define EAGINS_ID_BEGIN	1
#define MAX_EAGINS_NUM	16
#define EAGINS_UNIXSOCK_PREFIX	"/var/run/eagins_user"



/****************************************************/
int cgi_auth_init(STAuthProcess * stAuProc, int port);
int  init_auth_socket(STAuthProcess * stAuProc, int port );
int suc_connect_unix_sock();
int get_authType_from_eag(STUserManagePkg *pkg, int fd,int wait, STUserManagePkg **pprsp);

int setPkgUserIP(STPortalPkg * pkg, UINT32 ip_addr);
int send_pkg(int sock,STPortalPkg * pkg);
STPortalPkg *createPortalPkg(PKG_TYPE pkg_type);
unsigned int  destroyPortalPkg(STPortalPkg *pstPortalPkg);
int getPortalPkg( int fd, int wait, STPortalPkg **pp_portal_pkg );
int sendPortalPkg( int fd, int wait, int port, char * addr, STPortalPkg *pkg );
static unsigned int getAttrNum(STPortalPkg *pstPortalPkg);
int addAttr(STPortalPkg **pp_stPortalPkg, ATTR_TYPE attr_type, void *attr_value, unsigned int attr_value_len );
STPkgAttr *getAttrByAttrType(STPortalPkg *pstPortalPkg, ATTR_TYPE attr_type);

int setRequireID(STPortalPkg *pstPortalPkg, unsigned short req_id);
unsigned short getRequireID(STPortalPkg *pstPortalPkg);

unsigned int getPkgSize(STPortalPkg *pstPortalPkg);
int setAuthType(STPortalPkg *pstPortalPkg, AUTH_TYPE auth_type);
int closePkgSock(STAuthProcess * stAuProc);
unsigned char getErrCode(STPortalPkg *pstPortalPkg);



/*MD5 function*/
void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf, size_t len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);
void MD5Transform(UINT32 buf[4], UINT32 const in[16]);







#endif
