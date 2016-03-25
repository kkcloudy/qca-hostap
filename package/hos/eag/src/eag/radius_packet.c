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
* radius_packet.c
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* radius_packet
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

#include "radius_packet.h"

int
radius_packet_init(struct radius_packet_t *packet,
		uint8_t code)
{
	if (NULL == packet) {
		eag_log_err("radius_packet_init input error");
		return -1;
	}

	memset(packet, 0, RADIUS_PACKET_HEADSIZE);
	packet->code = code;
	packet->id = 0;
	packet->length = htons(RADIUS_PACKET_HEADSIZE);

	if (RADIUS_CODE_ACCESS_REQUEST == packet->code) {
		rand_buff(packet->authenticator, RADIUS_AUTHLEN);
	}

	return 0;
}

/* 
 * radius_addattr()
 * Add an attribute to a packet. The packet length is modified 
 * accordingly.
 * If data==NULL and dlen!=0 insert null attribute.
 */
int
radius_addattr(struct radius_packet_t *pack,
		uint8_t type, uint32_t vendor_id, uint8_t vendor_type,
		uint32_t value, uint8_t *data, uint16_t dlen)
{
	struct radius_attr_t *a = NULL;
	uint16_t length = ntohs(pack->length);
	uint16_t vlen = 0;

	a = (struct radius_attr_t *) ((uint8_t *)pack + length);

	if (type != RADIUS_ATTR_VENDOR_SPECIFIC) {
		if (dlen) {	/* If dlen != 0 it is a text/string attribute */
			vlen = dlen;
		} else {
			vlen = 4;	/* address, integer or time */
		}

		if (vlen > RADIUS_ATTR_VLEN) {
			eag_log_warning("radius_addattr truncating RADIUS attribute "
				"type %d vendor(%d,%d) from %d to %d bytes [%s]",
			     type, vendor_id, vendor_type, vlen,
			     RADIUS_ATTR_VLEN, data);
			vlen = RADIUS_ATTR_VLEN;
		}

		if ((length + vlen + 2) > RADIUS_PACKET_SIZE) {
			eag_log_err("radius_addattr "
				"radius packet size %d too large, no more space",
				(length + vlen + 2));
			return EAG_ERR_RADIUS_PKG_OUTOFF_SIZE;
		}

		length += vlen + 2;

		pack->length = htons(length);

		a->t = type;
		a->l = vlen + 2;

		if (data) {
			memcpy(a->v.t, data, vlen);
		} else if (dlen) {
			memset(a->v.t, 0, vlen);
		} else {
			a->v.i = htonl(value);
		}
	} else {		/* Vendor specific */
		if (dlen) {	/* If dlen != 0 it is a text/string attribute */
			vlen = dlen;
		} else {
			vlen = 4;	/* address, integer or time */
		}

		if (vlen > RADIUS_ATTR_VLEN - 8) {
			eag_log_warning("radius_addattr truncating RADIUS attribute "
				"type %d vendor(%d,%d) from %d to %d bytes [%s]",
			     type, vendor_id, vendor_type, vlen,
			     RADIUS_ATTR_VLEN - 8, data);
			vlen = RADIUS_ATTR_VLEN - 8;
		}

		if ((length + vlen + 2) > RADIUS_PACKET_SIZE) {
			eag_log_err("radius_addattr "
				"radius packet size %d too large, no more space!",
				(length + vlen + 2));
			return EAG_ERR_RADIUS_PKG_OUTOFF_SIZE;
		}

		length += vlen + 8;

		pack->length = htons(length);

		a->t = type;
		a->l = vlen + 8;

		a->v.vv.i = htonl(vendor_id);
		a->v.vv.t = vendor_type;
		a->v.vv.l = vlen + 2;

		if (data) {
			memcpy((uint8_t *)a + 8, data, dlen);
		} else if (dlen) {
			memset((uint8_t *)a + 8, 0, dlen);
		} else {
			a->v.vv.v.i = htonl(value);
		}
	}

	return EAG_RETURN_OK;
}

int
radius_getnextattr(struct radius_packet_t *pack, struct radius_attr_t **attr,
		uint8_t type, uint32_t vendor_id, uint8_t vendor_type,
		int instance, size_t *roffset)
{
	struct radius_attr_t *t = NULL;
	size_t len = 0;
	size_t offset = *roffset;
	int count = 0;

	if (NULL == pack) {
		eag_log_err("radius_getnextattr input error");
		return -1;
	}
	
    len = ntohs(pack->length) - RADIUS_PACKET_HEADSIZE;

	if (0) {
		printf("radius_getattr payload(len=%u,off=%u) %.2x %.2x %.2x %.2x\n",
			(unsigned int) len, (unsigned int) offset,
			pack->payload[0], pack->payload[1], pack->payload[2],
			pack->payload[3]);
	}

	while (offset < len) {
		t = (struct radius_attr_t *) (&pack->payload[offset]);

		if (0) {
			printf("radius_getattr %d %d %d %.2x %.2x\n", 
				t->t, t->l, ntohl(t->v.vv.i), (int) t->v.vv.t,
				(int) t->v.vv.l);
		}

		offset += t->l;

		if (t->t != type)
			continue;

		if (RADIUS_ATTR_VENDOR_SPECIFIC == t->t &&
			(ntohl(t->v.vv.i) != vendor_id || t->v.vv.t != vendor_type))
			continue;

		if (count == instance) {

			if (type == RADIUS_ATTR_VENDOR_SPECIFIC)
				*attr = (struct radius_attr_t *) &t->v.vv.t;
			else
				*attr = t;

			if (0)
				printf("Found\n");

			*roffset = offset;
			return 0;
		} else {
			count++;
		}
	}

	return -1;		/* Not found */
}

/* 
 * radius_getattr()
 * Search for an attribute in a packet. Returns -1 if attribute is not found.
 * The first instance matching attributes will be skipped
 */
int
radius_getattr(struct radius_packet_t *pack, struct radius_attr_t **attr,
		uint8_t type, uint32_t vendor_id, uint8_t vendor_type,
		int instance)
{
	size_t offset = 0;

	return radius_getnextattr(pack, attr, type, vendor_id, vendor_type,
				  instance, &offset);
}

/* 
 * radius_pwencode()
 * Encode a password using MD5.
 */
static int
radius_pwencode(uint8_t *dst, size_t dstsize, size_t *dstlen,
		uint8_t *src, size_t srclen,
		uint8_t *authenticator, char *secret, size_t secretlen)
{
	uint8_t output[RADIUS_MD5LEN] = {0};
	MD5_CTX context;
	size_t i = 0;
	size_t n = 0;

	memset(dst, 0, dstsize);

	/* Make dstlen multiple of 16 */
	if (srclen & 0x0f) {
		*dstlen = (srclen & 0xf0) + 0x10;	/* Padding 1 to 15 zeros */
	} else {
 		*dstlen = srclen;	/* No padding */
	}
	eag_log_info("radius_pwencode dstlen = %u", *dstlen);
	/* Is dstsize too small ? */
	if (dstsize <= *dstlen) {
		eag_log_err("radius_pwencode dstsize %u < dstlen %u",
				dstsize, *dstlen);
		*dstlen = 0;
		return -1;
	}

	/* Copy first 128 octets of src into dst */
	if (srclen > 128) {
		memcpy(dst, src, 128);
	} else {
		memcpy(dst, src, srclen);
	}

	/* Get MD5 hash on secret + authenticator */
	MD5Init(&context);
	MD5Update(&context, (uint8_t *)secret, secretlen);
	MD5Update(&context, authenticator, RADIUS_AUTHLEN);
	MD5Final(output, &context);

	/* XOR first 16 octets of dst with MD5 hash */
	for (i = 0; i < RADIUS_MD5LEN; i++) {
		dst[i] ^= output[i];
	}

	/* Continue with the remaining octets of dst if any */
	for (n = 0;
	     n < 128 && n < (*dstlen - RADIUS_AUTHLEN); n += RADIUS_AUTHLEN)
	{
		MD5Init(&context);
		MD5Update(&context, (uint8_t *)secret, secretlen);
		MD5Update(&context, dst + n, RADIUS_AUTHLEN);
		MD5Final(output, &context);
		for (i = 0; i < RADIUS_AUTHLEN; i++)
			dst[i + n + RADIUS_AUTHLEN] ^= output[i];
	}

	return 0;
}

int
radius_add_userpasswd(struct radius_packet_t *pack,
		uint8_t *pwd, uint16_t pwdlen,
		char *secret, size_t secretlen)
{
	int iret = 0;
	char passwd[RADIUS_PWSIZE] = {0};
	size_t pwlen = 0;

	radius_pwencode((uint8_t *)passwd, RADIUS_PWSIZE, &pwlen,
			pwd, pwdlen, pack->authenticator, secret, secretlen);
	pwd = (uint8_t *)passwd;
	pwdlen = (uint16_t)pwlen;

	iret = radius_addattr(pack, RADIUS_ATTR_USER_PASSWORD, 0, 0, 0,
				pwd, pwdlen);

	return iret;
}

/* 
 * radius_hmac_md5()
 * Calculate HMAC MD5 on a radius packet.
 */
int
radius_hmac_md5(struct radius_packet_t *pack,
		char *secret, size_t secretlen, uint8_t *dst)
{
	uint8_t digest[RADIUS_MD5LEN] = {0};
	size_t length = 0;
	MD5_CTX context;
	uint8_t *key = NULL;
	size_t key_len = 0;
	uint8_t k_ipad[65] = {0};
	uint8_t k_opad[65] = {0};
	uint8_t tk[RADIUS_MD5LEN] = {0};
	int i = 0;

	if (secretlen > 64) {	/* TODO: If Microsoft truncate to 64 instead */
		MD5Init(&context);
		MD5Update(&context, (uint8_t *)secret, secretlen);
		MD5Final(tk, &context);
		key = tk;
		key_len = 16;
	} else {
		key = (uint8_t *)secret;
		key_len = secretlen;
	}

	length = ntohs(pack->length);

	memset(k_ipad, 0x36, sizeof(k_ipad));
	memset(k_opad, 0x5c, sizeof(k_opad));

	for (i = 0; i < key_len; i++) {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
	}

	/* Perform inner MD5 */
	MD5Init(&context);
	MD5Update(&context, k_ipad, 64);
	MD5Update(&context, (uint8_t *) pack, length);
	MD5Final(digest, &context);

	/* Perform outer MD5 */
	MD5Init(&context);
	MD5Update(&context, k_opad, 64);
	MD5Update(&context, digest, 16);
	MD5Final(digest, &context);

	memcpy(dst, digest, RADIUS_MD5LEN);

	return 0;
}

/* 
 * radius_acctreq_authenticator()
 * Update a packet with an accounting request authenticator
 */
int
radius_acctreq_authenticator(struct radius_packet_t *pack,
		char *secret,
		size_t secretlen)
{
	/* From RFC 2866: Authenticator is the MD5 hash of:
	    Code + Identifier + Length + 16 zero octets + request attributes +
	    shared secret */
	MD5_CTX context;

	memset(pack->authenticator, 0, RADIUS_AUTHLEN);

	/* Get MD5 hash on secret + authenticator */
	MD5Init(&context);
	MD5Update(&context, (void *)pack, ntohs(pack->length));
	MD5Update(&context, (uint8_t *)secret, secretlen);
	MD5Final(pack->authenticator, &context);

	return 0;
}

/* 
 * radius_authresp_authenticator()
 * Update a packet with an authentication response authenticator
 */
int
radius_authresp_authenticator(struct radius_packet_t *pack,
		uint8_t *req_auth,
		char *secret,
		size_t secretlen)
{
	/* From RFC 2865: Authenticator is the MD5 hash of:
	    Code + Identifier + Length + request authenticator + request attributes +
	    shared secret */
	MD5_CTX context;

	memcpy(pack->authenticator, req_auth, RADIUS_AUTHLEN);

	/* Get MD5 hash on secret + authenticator */
	MD5Init(&context);
	MD5Update(&context, (void *)pack, ntohs(pack->length));
	MD5Update(&context, (uint8_t *)secret, secretlen);
	MD5Final(pack->authenticator, &context);

	return 0;
}

/*
 * radius_reply_check()
 * Check that the authenticator on a reply is correct.
 */
int
radius_reply_check(struct radius_packet_t *pack,
		struct radius_packet_t *pack_req,
		char *secret, size_t secretlen)
{
	uint8_t auth[RADIUS_AUTHLEN] = {0};
	MD5_CTX context;

	MD5Init(&context);
	MD5Update(&context, (uint8_t *)pack,
				RADIUS_PACKET_HEADSIZE - RADIUS_AUTHLEN);
	MD5Update(&context, pack_req->authenticator, RADIUS_AUTHLEN);
	MD5Update(&context, (uint8_t *)pack + RADIUS_PACKET_HEADSIZE,
		ntohs(pack->length) - RADIUS_PACKET_HEADSIZE);
	MD5Update(&context, (uint8_t *)secret, secretlen);
	MD5Final(auth, &context);

	return memcmp(pack->authenticator, auth, RADIUS_AUTHLEN);
}

/*
 * radius_request_check()
 * Check that the authenticator on an accounting , DM, COA request is correct.
 */
int
radius_request_check(struct radius_packet_t *pack,
		char *secret, size_t secretlen)
{
	uint8_t auth[RADIUS_AUTHLEN] = {0};
	uint8_t padd[RADIUS_AUTHLEN] = {0};
	MD5_CTX context;

	memset(padd, 0, sizeof(padd));
	MD5Init(&context);
	MD5Update(&context, (uint8_t *)pack,
			RADIUS_PACKET_HEADSIZE - RADIUS_AUTHLEN);
	MD5Update(&context, (uint8_t *)padd, RADIUS_AUTHLEN);
	MD5Update(&context, (uint8_t *)pack + RADIUS_PACKET_HEADSIZE,
			ntohs(pack->length) - RADIUS_PACKET_HEADSIZE);
	MD5Update(&context, (uint8_t *)secret, secretlen);
	MD5Final(auth, &context);

	return memcmp(pack->authenticator, auth, RADIUS_AUTHLEN);
}

const char *
radius_terminate_cause_int2str(int int_reason)
{
	switch (int_reason) {
	case RADIUS_TERMINATE_CAUSE_USER_REQUEST:
		return "UserRequest";
	case RADIUS_TERMINATE_CAUSE_LOST_CARRIER:
		return "LostCarrier";
	case RADIUS_TERMINATE_CAUSE_LOST_SERVICE:
		return "LostService";
	case RADIUS_TERMINATE_CAUSE_IDLE_TIMEOUT:
		return "IdleTimeout";
	case RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT:
		return "SessionTimeout";
	case RADIUS_TERMINATE_CAUSE_ADMIN_RESET:
		return "AdminReset";
	case RADIUS_TERMINATE_CAUSE_ADMIN_REBOOT:
		return "AdminReboot";
	case RADIUS_TERMINATE_CAUSE_PORT_ERROR:
		return "PortError";
	case RADIUS_TERMINATE_CAUSE_NAS_ERROR:
		return "NasError";
	case RADIUS_TERMINATE_CAUSE_NAS_REQUEST:
		return "NasRequest";
	case RADIUS_TERMINATE_CAUSE_NAS_REBOOT:
		return "NasReboot";
	case RADIUS_TERMINATE_CAUSE_PORT_UNNEEDED:
		return "PortUnneeded";
	case RADIUS_TERMINATE_CAUSE_PORT_PREEMPTED:
		return "PortPreempted";
	case RADIUS_TERMINATE_CAUSE_PORT_SUSPEND:
		return "PortSuspend";
	case RADIUS_TERMINATE_CAUSE_SERVICE_UNAVAILABLE:
		return "ServiceUnavailable";
	case RADIUS_TERMINATE_CAUSE_CALLBACK:
		return "CallBack";
	case RADIUS_TERMINATE_CAUSE_USER_ERROR:
		return "UserError";
	case RADIUS_TERMINATE_CAUSE_HOST_REQUEST:
		return "HostRequest";
	default:
		return "Unknow Reason";
	}
}

