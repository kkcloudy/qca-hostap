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
* portal_packet.c
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* portal_packet
*
*
*******************************************************************************/

#ifndef _PORTAL_PACKET_H
#define _PORTAL_PACKET_H

#include <stdint.h>

#define PORTAL_PACKET_MOBILE_HEADSIZE		16
#define PORTAL_PACKET_TELECOM_HEADSIZE		32
#define PORTAL_PACKET_SIZE			1024

#define PORTAL_AUTHLEN				16

#define MAX_ATTR_VALUE_LEN	253

#define PORTAL_PROTOCOL_MOBILE		0
#define PORTAL_PROTOCOL_TELECOM		1

#define PORTAL_TELECOM_USERNAME_LEN		32
#define PORTAL_MOBILE_ERRID_LEN			5

#define ERRID_AC101		"AC101"		/*IP地址是本AC所述的地址池中的有效地址，但这个地址目前已经通过认证在线*/
#define ERRID_AC102		"AC102"		/*AC发现用户请求认证的IP地址不是本AC所述的地址池中的有效地址*/
#define ERRID_AC103		"AC103"		/*AC发现用户请求认证的IP地址是本AC所述的地址池中的有效地址，但这个地址目前还未分配给用户*/
#define ERRID_AC999		"AC999"		/*其他错误信息*/
#define ERRID_AC201		"AC201"		/*AC与radius通讯超时或者通讯网络问题*/

struct portal_packet_t {
	uint8_t version;
	uint8_t type;
	uint8_t auth_type;	/* pap or chap */
	uint8_t rsv;
	uint16_t serial_no;
	uint16_t req_id;
	uint32_t user_ip;
	uint16_t user_port;
	uint8_t err_code;
	uint8_t attr_num;
	union {
		uint8_t m_attr[PORTAL_PACKET_SIZE-PORTAL_PACKET_MOBILE_HEADSIZE];
		struct {
			uint8_t authenticator[PORTAL_AUTHLEN];
			uint8_t attr[PORTAL_PACKET_SIZE-PORTAL_PACKET_TELECOM_HEADSIZE];
		} t;
	} payload;
};
/* } __attribute__((packed)); */

struct portal_packet_attr {
	uint8_t type;
	uint8_t len;
	uint8_t value[0];
};

typedef enum {
	REQ_CHALLENGE = 0x01,
	ACK_CHALLENGE,
	REQ_AUTH,
	ACK_AUTH,
	REQ_LOGOUT,
	ACK_LOGOUT,
	AFF_ACK_AUTH,
	NTF_LOGOUT,
	REQ_INFO,
	ACK_INFO,
	REQ_MACBINDING_INFO = 0x30,
	ACK_MACBINDING_INFO = 0x31,
	NTF_USER_LOGON = 0x32,
	NTF_USER_LOGOUT = 0x34,
	REQ_USER_OFFLINE = 0x36
} PORTAL_PACKET_TYPE;

typedef enum {
	AUTH_CHAP = 0x00,
	AUTH_PAP = 0x01
} AUTH_TYPE;

typedef enum {
	CHALLENGE_SUCCESS = 0,
	CHALLENGE_REJECT,
	CHALLENGE_CONNECTED,
	CHALLENGE_ONAUTH,
	CHALLENGE_FAILED
} ACK_CHALLENGE_ERRCODE;

typedef enum {
	PORTAL_AUTH_SUCCESS = 0,
	PORTAL_AUTH_REJECT,
	PORTAL_AUTH_CONNECTED,
	PORTAL_AUTH_ONAUTH,
	PORTAL_AUTH_FAILED
} ACK_AUTH_ERRCODE;

typedef enum {
	EC_REQ_LOGOUT = 0,
	EC_REQ_TIMEOUT
} REQ_LOGOUT_ERRCODE;

typedef enum {
	EC_ACK_LOGOUT_SUCCESS = 0,
	EC_ACK_LOGOUT_REJECT,
	EC_ACK_LOGOUT_FAILED
} ACK_LOGOUT_ERRCODE;

typedef enum {
	EC_ACK_INFO_SUCCESS = 0,
	EC_ACK_INFO_NOTSUPPORT,
	EC_ACK_INFO_FAILED
} ACK_INFO_ERRCODE;

typedef enum {
	ATTR_USERNAME = 0x01,
	ATTR_PASSWORD,
	ATTR_CHALLENGE,
	ATTR_CHAPPASSWORD,
	ATTR_ERRID = 0x05,
	ATTR_UPLINKFLUX = 0x06,
	ATTR_DOWNLINKFLUX = 0x07,
	ATTR_PORT_ID = 0x08, /* ATTR_PORT for China Telecom */
	ATTR_BASIP = 0x0a,
	ATTR_USERMAC = 0x0b,
	ATTR_NASID = 0x30,
	ATTR_SESS_START = 0x31,
	ATTR_SESS_STOP = 0x32,
	ATTR_SESS_TIME = 0x33,
	ATTR_USER_AGENT = 0x34,
	ATTR_INPUT_OCTETS = 0x35,
	ATTR_OUTPUT_OCTETS,
	ATTR_INPUT_PACKETS,
	ATTR_OUTPUT_PACKETS,
	ATTR_INPUT_GIGAWORDS,
	ATTR_OUTPUT_GIGAWORDS   
} ATTR_TYPE;

/*
void
portal_packet_ntoh(struct portal_packet_t *packet);

void
portal_packet_hton(struct portal_packet_t *packet);
*/

int
portal_packet_get_length(const struct portal_packet_t *packet);

int
portal_packet_add_attr(struct portal_packet_t *packet,
				ATTR_TYPE type, const void *value, size_t len);

struct portal_packet_attr *
portal_packet_get_attr(const struct portal_packet_t *packet,
				ATTR_TYPE type);

struct portal_packet_attr *
portal_packet_get_next_attr(const struct portal_packet_t *packet,
				struct portal_packet_attr *attr);

void
portal_packet_log_packet(struct portal_packet_t *packet);


int
portal_packet_init(struct portal_packet_t *packet,
				uint8_t type, uint32_t userip);

int
portal_set_protocol_type(int protocol_type);

int
portal_get_protocol_type(void);

int
portal_packet_minsize(void);

int
portal_request_check(struct portal_packet_t *pack,
		char *secret, size_t secretlen);

int
portal_response_check(struct portal_packet_t *pack,
		struct portal_packet_t *req_pack,
		char *secret, size_t secretlen);

int
portal_resp_authenticator(struct portal_packet_t *pack,
		struct portal_packet_t *req_pack,
		char *secret,
		size_t secretlen);

int
portal_req_authenticator(struct portal_packet_t *pack,
		char *secret,
		size_t secretlen);

#endif /* _PORTAL_PACKET_H */

