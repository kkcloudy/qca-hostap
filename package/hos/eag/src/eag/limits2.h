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
* limits2.h
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
#ifndef _LIMITS_H
#define _LIMITS_H

/*
 * extracted from various .h files, needs some cleanup.
 */

#define LEAKY_BUCKET 0
/* If the constants below are defined packets which have been dropped
   by the traffic shaper will be counted towards accounting and
   volume limitation */
/* #define COUNT_DOWNLINK_DROP 1 */
/* #define COUNT_UPLINK_DROP 1 */

/*#define BUCKET_SIZE                   300000 -* Size of leaky bucket (~200 packets) */
/* Time length of leaky bucket in milliseconds */
/* Bucket size = BUCKET_TIME * Bandwidth-Max radius attribute */
/* Not used if BUCKET_SIZE is defined */
#define BUCKET_TIME                     5000	/* 5 seconds */
#define BUCKET_SIZE_MIN                15000	/* Minimum size of leaky bucket (~10 packets) */
#define CHECK_INTERVAL                     1	/* Time between checking connections */

/* options */
#define OPT_IPADDRLEN                    256
#define OPT_IDLETIME                      10	/* Options idletime between each select */
#define MAX_PASS_THROUGHS                128	/* Max number of allowed UAM pass-throughs */
#define UAMSERVER_MAX                      8
#define MACOK_MAX                         16

/* redir */
#define REDIR_MAXLISTEN                   32
#define REDIR_MAXTIME                    100	/* Seconds */
#define REDIR_HTTP_MAX_TIME               3/*10*/ /* Seconds */	/*modify to 3 second 20100524 . old is 10 */
#define REDIR_HTTP_SELECT_TIME        500000	/*  microseconds = 0.5 seconds   change to 2.5s by shaojunwu 20090904 */
#define REDIR_RADIUS_MAX_TIME             3	/* Seconds */
#define REDIR_RADIUS_SELECT_TIME      500000	/* microseconds = 0.5 seconds */
#define REDIR_CHALLEN                     16
#define REDIR_MD5LEN                      16
#define REDIR_MACSTRLEN                   17
#define REDIR_MAXCHAR                     64	/* 1024 */
#define REDIR_MAXBUFFER                 5125

#define REDIR_USERNAMESIZE               256	/* Max length of username */
//#define REDIR_MAXQUERYSTRING            2048
#define REDIR_USERURLSIZE               256	/* Max length of URL requested by user */
#define REDIR_USERAGENTSIZE              256
#define REDIR_ADVERTISING_URL_SIZE		256	/*advertisingURL size */
#define REDIR_LANGSIZE                    16
#define REDIR_IDENTSIZE                   16

#define REDIR_MAXCONN                     16

//#define REDIR_CHALLENGETIMEOUT1          300 /* Seconds */
//#define REDIR_CHALLENGETIMEOUT2          600 /* Seconds */

#define REDIR_URL_LEN                   2048
#define REDIR_SESSIONID_LEN               17

#define APP_NUM_CONN                    1024
#define EAP_LEN                         256	/* TODO: Rather large */
#define MESSAGE_LEN						256
#define MACSTRLEN                         17
#define MS2SUCCSIZE                       40	/* MS-CHAPv2 authenticator response as ASCII */
#define DATA_LEN                        1500	/* Max we allow */
#define USERNAMESIZE                     256	/* Max length of username */
#define CHALLENGESIZE                     16	/* From chap.h MAX_CHALLENGE_LENGTH */

/* radius */
#define RADIUS_MD5LEN                     16	/* Length of MD5 hash */
#define RADIUS_AUTHLEN                    16	/* RFC 2865: Length of authenticator */
#define RADIUS_PWSIZE                    128	/* RFC 2865: Max 128 octets in password */
#define RADIUS_QUEUESIZE                 256	/* Same size as id address space */
#define RADIUS_ATTR_VLEN                 253
#define RADIUS_PACKSIZE                 4096
#define RADIUS_HDRSIZE                    20
#define RADIUS_PASSWORD_LEN               16
#define RADIUS_MPPEKEYSSIZE               32	/* Length of MS_CHAP_MPPE_KEYS attribute */
#define RADIUS_DEFINTERVAL_TIME			300	/*default radius  account update interval time interval */
#define RADIUS_MAX_NASID_LEN			64



/*portal*/
//#define MAX_RADIUS_DOMAIN_LEN			32
#define MAX_PORTAL_DOMAIN_LEN			MAX_RADIUS_DOMAIN_LEN
#define PORTAL_CHALLEN					16

#define MAX_SESSION_ID_LEN				32


/*system :  wireless*/
#define  MAX_APNAME_LENGTH		256
#define  MAX_ESSID_LENGTH		64
#define  MAX_IF_NAME_LEN			16
#define  MAX_NASPORTID_LEN		32
#define  PKT_ETH_ALEN			6

#endif

