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

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>

#include "nm_list.h"
#include "hashtable.h"
#include "eag_log.h"
#include "eag_util.h"
#include "eag_errcode.h"
#include "md5.h"

#include "portal_packet.h"

static int eag_portal_protocol_type = PORTAL_PROTOCOL_MOBILE;

#if 0
void
portal_packet_ntoh(struct portal_packet_t *packet)
{
	packet->serial_no = ntohs(packet->serial_no);
	packet->req_id = ntohs(packet->req_id);
	packet->user_ip = ntohl(packet->user_ip);
	packet->user_port = ntohs(packet->user_port);
	return;
}

void
portal_packet_hton(struct portal_packet_t *packet)
{
	packet->serial_no = htons(packet->serial_no);
	packet->req_id = htons(packet->req_id);
	packet->user_ip = htonl(packet->user_ip);
	packet->user_port = htons(packet->user_port);
	return;
}
#endif

int
portal_packet_get_length(const struct portal_packet_t *packet)
{
	int i = 0;
	int length = 0;
	struct portal_packet_attr *attr = NULL;

	if (NULL == packet) {
		eag_log_err("portal_packet_get_length input error");
		return 0;
	}

	eag_log_debug("portal_packet", "portal_packet_get_length attr_num=%u",
			packet->attr_num);
	if (PORTAL_PROTOCOL_MOBILE == eag_portal_protocol_type) {
		length = PORTAL_PACKET_MOBILE_HEADSIZE;
		attr = (struct portal_packet_attr *)(packet->payload.m_attr);
	} else {
		length = PORTAL_PACKET_TELECOM_HEADSIZE;
		attr = (struct portal_packet_attr *)(packet->payload.t.attr);
	}
	
	for (i = 0; i < packet->attr_num; i++) {
		length += attr->len;
		if (length > PORTAL_PACKET_SIZE) {
			eag_log_warning("portal_packet_get_length length %d > max %d",
				length, PORTAL_PACKET_SIZE);
			return 0;
		}
		attr = (struct portal_packet_attr *) ((uint8_t *)attr + attr->len);
	}

	eag_log_debug("portal_packet", "portal_packet_get_length length=%d",
			length);

	return length;
}

int
portal_packet_add_attr(struct portal_packet_t *packet,
				ATTR_TYPE type, const void *value, size_t len)
{
	struct portal_packet_attr *attr = NULL;
	size_t packet_len = 0;

	if (NULL == packet || NULL == value
		|| len > MAX_ATTR_VALUE_LEN)
	{
		eag_log_err("portal_packet_add_attr failed, "
			"packet=%p, type=%d, value=%p, len=%d",
			packet, type, value, len);
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	packet_len = portal_packet_get_length(packet);
	attr = (struct portal_packet_attr *) ((uint8_t *)packet + packet_len);
	
	packet_len = packet_len + len + 2;
	if (packet_len > PORTAL_PACKET_SIZE) {
		eag_log_err("portal_packet_add_attr failed, "
			"packet_len %u > max %u",
			packet_len, PORTAL_PACKET_SIZE);
		return EAG_ERR_PORTAL_INVALID_PKGSIZE;
	}
	
	attr->type = type;
	attr->len = len + 2;
	memcpy(attr->value, value, len);

	packet->attr_num++;

	return 0;
}

struct portal_packet_attr *
portal_packet_get_attr(const struct portal_packet_t *packet,
				ATTR_TYPE type)
{
	struct portal_packet_attr *attr = NULL;
	size_t i = 0;

	if (NULL == packet) {
		eag_log_err("portal_packet_get_attr input error");
		return NULL;
	}

	if (PORTAL_PROTOCOL_MOBILE == eag_portal_protocol_type) {
		attr = (struct portal_packet_attr *)(packet->payload.m_attr);
	} else {
		attr = (struct portal_packet_attr *)(packet->payload.t.attr);
	}
	
	for (i = 0; i < packet->attr_num; i++) {
		if (type == attr->type) {
			return attr;
		}
		attr = (struct portal_packet_attr *)((uint8_t *)attr + attr->len);
	}

	return NULL;
}

struct portal_packet_attr *
portal_packet_get_next_attr(const struct portal_packet_t *packet,
				struct portal_packet_attr *attr)
{
	size_t packet_len = 0;
	
	if (NULL == packet) {
		eag_log_err("portal_packet_get_next_attr input error");
		return NULL;
	}

	if (0 == packet->attr_num) {
		return NULL;
	}

	if (NULL == attr) {
		if (PORTAL_PROTOCOL_MOBILE == eag_portal_protocol_type) {
			attr = (struct portal_packet_attr *)(packet->payload.m_attr);
		} else {
			attr = (struct portal_packet_attr *)(packet->payload.t.attr);
		}
	} else {
		packet_len = portal_packet_get_length(packet);
		attr = (struct portal_packet_attr *)((uint8_t *)attr + attr->len);
		if ((uint8_t *)attr - (uint8_t *)packet >= packet_len) {
			return NULL;
		}
	}

	return attr;
}

/* Convert 16 octet unsigned char to 32+1 octet ASCII hex string */
int
portal_char2hex(uint8_t *src, size_t srclen,
				char *dst, size_t dstlen)
{
	int i = 0;

	memset(dst, 0, dstlen);
	for (i = 0; (i < srclen) && (dstlen > (i + 1) * 2); i++) {
		snprintf(dst + i * 2, 3, "%2x", src[i]);
	}

	dst[i * 2] = '\0';
	
	return 0;
}

void
portal_packet_log_packet(struct portal_packet_t *packet)
{
	struct portal_packet_attr *attr = NULL;
	char tmp_buf[256] = "";
	
	if (NULL == packet) {
		eag_log_err("portal_packet_log_packet input error");
		return;
	}
	if (EAG_TRUE != eag_log_is_filter_register("portalpacket")) {
		/*在没有注册portal_pkg的情况下，
		减少后续判断的次数*/
		return;
	}
	eag_log_debug("portalpacket", "-----portal_packet_log_packet-----");
	eag_log_debug("portalpacket", "version = %u", packet->version);
	eag_log_debug("portalpacket", "type = %u", packet->type);
	eag_log_debug("portalpacket", "auth_type = %u", packet->auth_type);
	eag_log_debug("portalpacket", "rsv = %u", packet->rsv);
	eag_log_debug("portalpacket", "serial_no = %u", ntohs(packet->serial_no));
	eag_log_debug("portalpacket", "req_id = %u", ntohs(packet->req_id));
	ip2str(ntohl(packet->user_ip), tmp_buf, sizeof (tmp_buf));
	eag_log_debug("portalpacket", "user_ip = %x:%s", packet->user_ip, tmp_buf);
	eag_log_debug("portalpacket", "user_port = %u", ntohs(packet->user_port));
	eag_log_debug("portalpacket", "err_code = %u", packet->err_code);

	eag_log_debug("portalpacket", "attr_num = %u", packet->attr_num);

	for (attr = portal_packet_get_next_attr(packet, attr);
		NULL != attr; attr = portal_packet_get_next_attr(packet, attr)) {
		memset(tmp_buf, 0, sizeof(tmp_buf));
		memcpy(tmp_buf, attr->value, attr->len - 2);
		switch (attr->type) {
		case ATTR_USERNAME:
			eag_log_debug("portalpacket", "ATTR_USERNAME(%#x)=%s",
					ATTR_USERNAME, tmp_buf);
			break;
		case ATTR_PASSWORD:
			eag_log_debug("portalpacket", "ATTR_PASSWORD(%#x)=%s",
					ATTR_PASSWORD, tmp_buf);
			break;
		case ATTR_CHALLENGE:
			portal_char2hex((uint8_t *)attr->value,
					attr->len - 2, tmp_buf, sizeof(tmp_buf));
			eag_log_debug("portalpacket", "ATTR_CHALLENGE(%#x)=%s",
					ATTR_CHALLENGE, tmp_buf);
			break;
		case ATTR_CHAPPASSWORD:
			portal_char2hex((uint8_t *)attr->value,
					attr->len - 2, tmp_buf, sizeof(tmp_buf));
			eag_log_debug("portalpacket", "ATTR_CHAPPASSWORD(%#x)=%s",
					ATTR_CHAPPASSWORD, tmp_buf);
			break;
		case ATTR_PORT_ID:
			eag_log_debug("portalpacket", "ATTR_PORT_ID(%#x)=%s",
					ATTR_PORT_ID, tmp_buf);
			break;
		case ATTR_BASIP:
		{
			uint32_t ip = 0;

			if (4 != attr->len - 2) {
				eag_log_debug("portalpacket",
						"ATTR_BASIP(%#x)=%s, len=%u != 4",
						ATTR_PORT_ID, "error",
						attr->len - 2);
				break;
			}
			memcpy(&ip, attr->value, 4);
			ip2str(ntohl(ip), tmp_buf, sizeof (tmp_buf));
			eag_log_debug("portalpacket",
					"ATTR_BASIP(%#x)=%s", ATTR_BASIP,
					tmp_buf);
		}
			break;
		case ATTR_USERMAC:
			if (6 != attr->len - 2) {
				eag_log_debug("portalpacket",
						"ATTR_USERMAC(%#x)=%s, len=%u != 6",
						ATTR_USERMAC, "error",
						attr->len - 2);
				break;
			}
			mac2str((uint8_t *)attr->value, tmp_buf, sizeof(tmp_buf), '-');
			eag_log_debug("portalpacket", "ATTR_USERMAC(%#x)=%s",
				      ATTR_USERMAC, tmp_buf);
			break;
		case ATTR_NASID:
			eag_log_debug("portalpacket", "ATTR_NASID(%#x)=%s",
				      ATTR_NASID, tmp_buf);
			break;
		case ATTR_SESS_START:
		{
			time_t time = 0;

			if (4 != attr->len - 2) {
				eag_log_debug("portalpacket",
						"ATTR_SESS_START(%#x)=%s, len=%u != 4",
						ATTR_SESS_START, "error",
						attr->len - 2);
				break;
			}
			memcpy(&time, attr->value, 4);
			time = ntohl(time);
			eag_log_debug("portalpacket",
					"ATTR_SESS_START(%#x)=%lu:%s",
					ATTR_SESS_START,
					time,
					ctime(&time));
		}
			break;
		case ATTR_SESS_STOP:
		{
			time_t time = 0;

			if (4 != attr->len - 2) {
				eag_log_debug("portalpacket",
						"ATTR_SESS_STOP(%#x)=%s, len=%d != 4",
						ATTR_SESS_STOP, "error",
						attr->len - 2);
				break;
			}
			memcpy(&time, attr->value, 4);
			time = ntohl(time);
			eag_log_debug("portalpacket",
					"ATTR_SESS_STOP(%#x)=%lu:%s",
					ATTR_SESS_STOP,
					time,
					ctime(&time));
		}
			break;
		case ATTR_SESS_TIME:
		{
			time_t time = 0;

			if (4 != attr->len - 2) {
				eag_log_debug("portalpacket",
						"ATTR_SESS_TIME(%#x)=%s, len=%d != 4",
						ATTR_SESS_TIME, "error",
						attr->len - 2);
				break;
			}
			memcpy(&time, attr->value, 4);
			time = ntohl(time);
			eag_log_debug("portalpacket",
					"ATTR_SESS_TIME(%#x)=%lu",
					ATTR_SESS_TIME, time);
		}
			break;
		default:
			eag_log_debug("portalpacket",
					"unknow attr type=%#x, error packet",
					attr->type);
			break;
		}
	}
}


int
portal_packet_init(struct portal_packet_t *packet,
				uint8_t type, uint32_t userip)
{
	memset(packet, 0, sizeof(struct portal_packet_t));

	if (PORTAL_PROTOCOL_MOBILE == eag_portal_protocol_type) {
		packet->version = 0x1;
	} else {
		packet->version = 0x2;
	}

	packet->type = type;
	packet->user_ip = htonl(userip);

	return 0;
}

int
portal_set_protocol_type(int protocol_type)
{
	eag_portal_protocol_type = protocol_type;

	return 0;
}

int
portal_get_protocol_type(void)
{
	return eag_portal_protocol_type;
}

int
portal_packet_minsize(void)
{
	if (PORTAL_PROTOCOL_MOBILE == eag_portal_protocol_type)
		return PORTAL_PACKET_MOBILE_HEADSIZE;

	return PORTAL_PACKET_TELECOM_HEADSIZE;
}

int
portal_request_check(struct portal_packet_t *pack,
		char *secret, size_t secretlen)
{
	uint8_t auth[PORTAL_AUTHLEN] = {0};
	uint8_t padd[PORTAL_AUTHLEN] = {0};
	MD5_CTX context;
	int packet_len = 0;
	
	if (PORTAL_PROTOCOL_MOBILE == eag_portal_protocol_type) {
		return 0;
	}
	
	memset(padd, 0, sizeof(padd));
	MD5Init(&context);
	MD5Update(&context, (uint8_t *)pack,
			PORTAL_PACKET_TELECOM_HEADSIZE - PORTAL_AUTHLEN);
	MD5Update(&context, (uint8_t *)padd, PORTAL_AUTHLEN);
	packet_len = portal_packet_get_length(pack);
	MD5Update(&context, (uint8_t *)pack + PORTAL_PACKET_TELECOM_HEADSIZE,
			packet_len - PORTAL_PACKET_TELECOM_HEADSIZE);
	MD5Update(&context, (uint8_t *)secret, secretlen);
	MD5Final(auth, &context);

	return memcmp(pack->payload.t.authenticator, auth, PORTAL_AUTHLEN);
}

int
portal_response_check(struct portal_packet_t *pack,
		struct portal_packet_t *req_pack,
		char *secret, size_t secretlen)
{
	uint8_t auth[PORTAL_AUTHLEN] = {0};
	MD5_CTX context;
	int packet_len = 0;
	
	if (PORTAL_PROTOCOL_MOBILE == eag_portal_protocol_type) {
		return 0;
	}
	
	MD5Init(&context);
	MD5Update(&context, (uint8_t *)pack,
			PORTAL_PACKET_TELECOM_HEADSIZE - PORTAL_AUTHLEN);
	MD5Update(&context, req_pack->payload.t.authenticator, PORTAL_AUTHLEN);
	packet_len = portal_packet_get_length(pack);
	MD5Update(&context, (uint8_t *)pack + PORTAL_PACKET_TELECOM_HEADSIZE,
			packet_len - PORTAL_PACKET_TELECOM_HEADSIZE);
	MD5Update(&context, (uint8_t *)secret, secretlen);
	MD5Final(auth, &context);

	return memcmp(pack->payload.t.authenticator, auth, PORTAL_AUTHLEN);
}

int
portal_resp_authenticator(struct portal_packet_t *pack,
		struct portal_packet_t *req_pack,
		char *secret,
		size_t secretlen)
{
	MD5_CTX context;
	int packet_len = 0;

	if (PORTAL_PROTOCOL_MOBILE == eag_portal_protocol_type) {
		return 0;
	}
	
	memcpy(pack->payload.t.authenticator, 
		req_pack->payload.t.authenticator, PORTAL_AUTHLEN);

	MD5Init(&context);
	packet_len = portal_packet_get_length(pack);
	MD5Update(&context, (void *)pack, packet_len);
	MD5Update(&context, (uint8_t *)secret, secretlen);
	MD5Final(pack->payload.t.authenticator, &context);

	return 0;
}

int
portal_req_authenticator(struct portal_packet_t *pack,
		char *secret,
		size_t secretlen)
{
	MD5_CTX context;
	int packet_len = 0;

	if (PORTAL_PROTOCOL_MOBILE == eag_portal_protocol_type) {
		return 0;
	}

	memset(pack->payload.t.authenticator, 0, PORTAL_AUTHLEN);

	MD5Init(&context);
	packet_len = portal_packet_get_length(pack);
	MD5Update(&context, (void *)pack, packet_len);
	MD5Update(&context, (uint8_t *)secret, secretlen);
	MD5Final(pack->payload.t.authenticator, &context);

	return 0;
}

