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
* eag_util.c
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* eag_util
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
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <endian.h>

#include "nm_list.h"
#include "hashtable.h"
#include "eag_log.h"
#include "eag_util.h"
#include "eag_errcode.h"

#include "openssl/evp.h"
#include "openssl/bio.h"
#include "eag_util.h"

/* macro definition */
#define EAG_URANDOM_FILE_PATH "/dev/urandom"

int
sockopt_reuseaddr(int sock)
{
	int ret;
	int on = 1;

	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			 (void *) &on, sizeof (on));
	if (ret < 0) {
		eag_log_warning("can't set sockopt SO_REUSEADDR to socket %d",
				sock);
		return -1;
	}
	return 0;
}

int 
set_nonblocking(int fd)
{
	int flags = 0;

	if ((flags = fcntl(fd, F_GETFL)) < 0)
	{
		eag_log_err("fcntl(F_GETFL) failed for fd %d: %s",
			fd, safe_strerror(errno));
		return -1;
	}
	if (fcntl(fd, F_SETFL, (flags | O_NONBLOCK)) < 0)
	{
		eag_log_err("fcntl failed setting fd %d non-blocking: %s",
			fd, safe_strerror(errno));
		return -1;
	}
	return 0;
}

int
clear_nonblocking(int fd)
{
	int flags = 0;

	if ((flags = fcntl(fd, F_GETFL)) < 0)
	{
		eag_log_err("fcntl(F_GETFL) failed for fd %d: %s",
			fd, safe_strerror(errno));
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags & (~O_NONBLOCK)) < 0)
	{
		eag_log_err("fcntl failed clear fd %d non-blocking: %s",
			fd, safe_strerror(errno));
		return -1;
	}

	return 0;
}

void
rand_buff(uint8_t *buff, size_t size)
{
	static FILE *fp = NULL;

	if (NULL == fp) {
		fp = fopen(EAG_URANDOM_FILE_PATH, "r");
	}

	if (NULL != fp) {
		fread(buff, 1, size, fp);
	}
}

char *
ip2str(uint32_t ip, char *str, size_t size)
{
	if (NULL == str) {
		return NULL;
	}

	memset(str, 0, size);
	snprintf(str, size-1, "%u.%u.%u.%u",
		(ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff);

	return str;
}

char *
mac2str(const uint8_t mac[6], char *str, size_t size, char separator)
{
	if (NULL == mac || NULL == str || size <= 0) {
		return NULL;
	}
	if (':' != separator && '-' != separator && '_' != separator) {
		separator = ':';
	}

	memset(str, 0, size);
	snprintf(str, size-1, "%02X%c%02X%c%02X%c%02X%c%02X%c%02X",
		mac[0], separator, mac[1], separator, mac[2], separator,
		mac[3], separator, mac[4], separator, mac[5]);

	return str;
}

int
str2mac(const char *str, uint8_t mac[6])
{
	char separator = ':';
	int num = 0;
	
	if (NULL == str || NULL == mac || strlen(str) < 17) {
		return -1;
	}

	separator = str[2];
	switch (separator) {
	case ':':
		num = sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
		break;
	case '-':
		num = sscanf(str, "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
		break;
	case '_':
		num = sscanf(str, "%hhx_%hhx_%hhx_%hhx_%hhx_%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
		break;
	default:
		break;
	}
	
	return (6 == num) ? 0 : -1;
}

int
delete_0d0a(char *buff)
{
	if (NULL == buff) {
		return -1;
	}
	
	for (; *buff != '\0' && *buff != '\r' && *buff != '\n'; buff++) {;
	}
	*buff = '\0';

	return 0;
}

int
create_tcp_server(uint32_t ip, uint16_t port)
{
	int ret = 0;
	int fd = 0;
	int optval = 1;
	int tcpflag = 1;
	struct sockaddr_in addr;
	char ipstr[32] = "";

	ip2str(ip, ipstr, sizeof(ipstr));
	
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		eag_log_err("create_tcp_server @%s:%u failed: %s",
				ipstr, port, safe_strerror(errno));
		fd = -1;
		return fd;
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (0 != ret) {
		eag_log_err("create_tcp_server @%s:%u "
			"setsockopt SO_REUSEADDR failed: fd(%d), %s",
			ipstr, port, fd, safe_strerror(errno));
		close(fd);
		fd = -1;
		return fd;
	}

	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &tcpflag, sizeof(tcpflag));
	if (ret < 0) {
		eag_log_err("create_tcp_server @%s:%u "
			"setsockopt TCP_NODELAY failed: fd(%d), %s",
			ipstr, port, fd, safe_strerror(errno));
		close(fd);
		fd = -1;
		return fd;
	}
	
	set_nonblocking(fd);

	memset(&addr, 0, sizeof (struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(ip);
	addr.sin_port = htons(port);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin_len = sizeof (struct sockaddr_in);
#endif

	ret = bind(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		eag_log_err("create_tcp_server @%s:%u bind failed: fd(%d), %s",
			ipstr, port, fd, safe_strerror(errno));
		close(fd);
		fd = -1;
		return fd;
	}

	ret = listen(fd, 32);
	if (ret < 0) {
		eag_log_err("create_tcp_server @%s:%u listen failed: fd(%d), %s",
			ipstr, port, fd, safe_strerror(errno));
		close(fd);
		fd = -1;
		return fd;
	}

    return fd;
}

int
conn_to_server(uint32_t ip, uint16_t port)
{
	int fd = 0;
	int ret = 0;
	struct sockaddr_in addr;
	char ipstr[32] = "";

	ip2str(ip, ipstr, sizeof(ipstr));

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		eag_log_err("conn_to_server @%s:%u failed, %s",
			ipstr, port, safe_strerror(errno));
		fd = -1;
		return fd;
	}
	
	set_nonblocking(fd);

	memset(&addr, 0, sizeof (struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(ip);
	addr.sin_port = htons(port);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin_len = sizeof (struct sockaddr_in);
#endif

	ret = connect(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		struct timeval tv = {1, 5000};
		fd_set writable;

        if (errno != EINPROGRESS) {
            eag_log_err("conn_to_server @%s:%u connect failed: fd(%d) %s",
				ipstr, port, fd, safe_strerror(errno));
			goto failed;
        }
		
		eag_log_warning("TODO:conn_to_server you should rewrite conn_to_server at here!");
		FD_ZERO(&writable);
        FD_SET(fd, &writable);
        ret = select(fd+1, NULL, &writable, NULL, &tv);
        if (ret < 0) {
			eag_log_err("conn_to_server @%s:%u select failed: %s",
				ipstr, port, safe_strerror(errno));
			goto failed;
        } else if (0 == ret) {
        	eag_log_err("conn_to_server @%s:%u select timeout", ipstr, port);
			goto failed;
        } else {
			int error = 0;
            socklen_t len = sizeof(int);

			ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
			if (ret < 0) {
				eag_log_err("conn_to_server @%s:%u "
					"getsockopt SO_ERROR failed, fd(%d) %s",
					ipstr, port, fd, safe_strerror(errno));
				goto failed;
			}
			
            if (0 != error) {
				eag_log_err("conn_to_server @%s:%u failed: fd(%d) SO_ERROR=%d",
					ipstr, port, fd, error);
				goto failed;;
            }
        }
	}

	return fd;

failed:
	close(fd);
	fd = -1;
	return fd;
}

int
is_mask(uint32_t mask)
{
	int i = 0;
	
	for (i = 0; i < 32; i++) {
		if ((mask>>i) & 0X1) {
			break;
		}
	}
	for (; i < 32; i++) {
		if (!((mask>>i) & 0X1)) {
			return 0;
		}
	}

	return 1;
}

int
is_net_overlap(uint32_t ip1, uint32_t mask1,
				uint32_t ip2, uint32_t mask2)
{
	uint32_t minmask;
	
	if( !is_mask(mask1) || !is_mask(mask2)) {
		return 0;
	}
	
	minmask = MIN(mask1, mask2);
	return (ip1 & minmask) == (ip2 & minmask);
}

int
read_file(const char *file, char *buf, int size)
{
	FILE *fp = NULL;

	if (NULL == file || NULL == buf) {
		eag_log_err("read_file input error");
		return -1;
	}

	memset(buf, 0, size);
	if ( (fp = fopen(file, "r")) == NULL) {
		eag_log_err("read_file %s open failed, %s", 
			file, safe_strerror(errno));
		return -1;
	}

	if (fgets(buf, size-1, fp) == NULL) {
		eag_log_err("read_file %s get failed, %s", 
			file, safe_strerror(errno));
		fclose(fp);
		memset(buf, 0, size);
		return -1;
	}
	fclose(fp);
	
	if ('\n' == buf[strlen(buf)-1]) {
		buf[strlen(buf)-1] = '\0';
	}
	
	return 0;
}

int
get_product_serial(void)
{
#define PRODUCT_SERIAL "/dbm/product/product_serial"
	int serial=-1;
	char buff[32];

	if( 0 != read_file(PRODUCT_SERIAL, buff, sizeof(buff)) ){
		return -2;
	}

	serial = atoi(buff);
#if 0
	if( serial != 7 /*7605i*/
		|| serial != 8 )/*8610*/
	{
		return serial;
	}
#endif
	return serial;
}
	
int
get_internal_if_name(int slotid, char *ifname, size_t len)
{
	int serial = 0;

	serial = get_product_serial();

	switch(serial){
		case 7:
			strncpy( ifname, "obc0", len-1 );
			break;
		case 8:
			snprintf( ifname, len-1, "ve%d", slotid );
			break;
		default:
			break;
	}

	return serial;
}

int
add_internal_if_ip(char *ifname, uint32_t ip, size_t mask)
{
#define IP_ADDR_ADD_DEV	"ip addr add dev %s %s/%u"
	char ipstr[32]="";
	char cmd[128]="";
	int ret = 0;

	if( NULL == ifname 
		|| strlen(ifname)==0 
		|| 0 == ip )
	{
		return -1;
	}
	
	ip2str( ip, ipstr, sizeof(ipstr) );
	snprintf( cmd, sizeof(cmd)-1, IP_ADDR_ADD_DEV, 
					ifname, ipstr, mask );
	
	ret = system( cmd );
	eag_log_info("add_internal_if_ip cmd = %s  ret=%d", cmd, ret);

	return 0;
	
}

int
del_internal_if_ip(char *ifname, uint32_t ip, size_t mask)
{
#define IP_ADDR_DEL_DEV	" ip addr del dev %s %s/%u"
	char ipstr[32]="";
	char cmd[128]="";
	int ret = 0;

	if( NULL == ifname 
		|| strlen(ifname)==0 
		|| 0 == ip )
	{
		return -1;
	}
	
	ip2str( ip, ipstr, sizeof(ipstr) );
	snprintf( cmd, sizeof(cmd)-1, IP_ADDR_DEL_DEV, 
					ifname, ipstr, mask );
	system( cmd );
	eag_log_info("del_internal_if_ip cmd = %s  ret=%d", cmd, ret);
	
	return 0;
	
}



int 
BIO_des_encrypt( unsigned char * inbuf , unsigned char ** outbuf , int inlen , unsigned char * key )
{
    BIO *bio, *mbio, *cbio;
    unsigned char *dst;
    int outlen;

    mbio = BIO_new( BIO_s_mem( ) );
    cbio = BIO_new( BIO_f_cipher( ) );
    BIO_set_cipher( cbio , EVP_des_ecb( ) , key , NULL , 1 );

    bio = BIO_push( cbio , mbio );
    BIO_write( bio , inbuf , inlen );
	BIO_ctrl(bio,BIO_CTRL_FLUSH,0,NULL);

    outlen = BIO_get_mem_data( mbio , (unsigned char **) & dst );
    * outbuf = ( unsigned char * ) malloc( outlen );
	if (NULL == * outbuf) {
		BIO_free_all( bio );
		return 0;
	}
    memcpy( * outbuf , dst , outlen );
    BIO_free_all( bio );

    return outlen;
}


int 
hex2str( unsigned char *hex, unsigned int hex_len, 
			unsigned char *output, unsigned int outputlen )
{
	int i;
	if (NULL==hex || NULL==output) {
		return -1;
	}

	int proc_hex_len=0;
	proc_hex_len = MIN(hex_len,(outputlen-1)/2);
	for (i=0; i<proc_hex_len; i++) {
		sprintf((char *)output+i*2,"%02x",(unsigned int)hex[i]);
	}

	return 0;
}

int
str2hex( unsigned char *str, unsigned char *output, unsigned int outputlen )
{
	int i;
	unsigned int str_len = strlen((char *)str);
	unsigned int proc_strlen = 0;

	if( str_len%2 !=0 ){
		return -1;
	} 

	proc_strlen = MIN(outputlen*2,str_len);
	for (i=0; i<proc_strlen; i+=2) {
		unsigned int temp;
		sscanf((char*)str+i,"%02x", &temp );
		output[i/2] = temp;
	}

	return 0;
}

uint64_t ntohl64(uint64_t arg64)
{
	uint64_t res64;

#if __BYTE_ORDER==__LITTLE_ENDIAN
	uint32_t low = (uint32_t) (arg64 & 0x00000000FFFFFFFFLL);
	uint32_t high = (uint32_t) ((arg64 & 0xFFFFFFFF00000000LL) >> 32);

	low = ntohl(low);
	high = ntohl(high);

	res64 = (uint64_t) high + (((uint64_t) low) << 32);
#else
	res64 = arg64;
#endif

	return res64;
}


uint64_t htonl64(uint64_t arg64)
{
	uint64_t res64;

#if __BYTE_ORDER==__LITTLE_ENDIAN
	uint32_t low = (uint32_t) (arg64 & 0x00000000FFFFFFFFLL);
	uint32_t high = (uint32_t) ((arg64 & 0xFFFFFFFF00000000LL) >> 32);

	low = htonl(low);
	high = htonl(high);

	res64 = (uint64_t) high + (((uint64_t) low) << 32);
#else
	res64 = arg64;
#endif

	return res64;
}

#ifdef eag_util_test
#include "eag_mem.c"
#include "eag_blkmem.c"
#include "eag_errcode.c"
#include "eag_log.c"

int
main()
{
	printf("is_mask(255) = %d\n",is_mask(255) );
	printf("is_mask(254) = %d\n",is_mask(254) );
	printf("is_mask(0xfffffe00) = %d\n",is_mask(0xfffffe00) );
	printf("is_mask(0xfffffa00) = %d\n",is_mask(0xfffffa00) );
	printf("is_mask(0xfffffb00) = %d\n",is_mask(0xfffffb00) );
	printf("is_mask(0xfffffc00) = %d\n",is_mask(0xfffffc00) );
	printf("is_mask(0xffffe000) = %d\n",is_mask(0xffffe000) );
	printf("is_mask(0xff400000) = %d\n",is_mask(0xff400000) );	
	printf("is_mask(0xff800000) = %d\n",is_mask(0xff800000) );
	printf("is_mask(0xffffc000) = %d\n",is_mask(0xffffc000) );
	printf("is_mask(0xffffef00) = %d\n",is_mask(0xffffef00) );
	printf("is_mask(0xffff) = %d\n",is_mask(0xffff) );
	printf("is_mask(0xeffffe00) = %d\n",is_mask(0xeffffe00) );

	struct in_addr addr;
	unsigned long ip1,mask1;
	unsigned long ip2,mask2;
	
	inet_aton("192.168.1.1", &addr);
	ip1 = ntohl(addr.s_addr);
	inet_aton("255.255.0.0", &addr);
	mask1 = ntohl(addr.s_addr);
	inet_aton("192.168.1.1", &addr);
	ip2 = ntohl(addr.s_addr);
	inet_aton("255.255.255.0", &addr);
	mask2 = ntohl(addr.s_addr);
	printf("192.168.1.1 255.255.0.0 192.168.1.1 255.255.255.0 = %d\n",
				is_net_overlap(ip1,mask1,ip2,mask2) );

	inet_aton("192.168.1.1", &addr);
	ip1 = ntohl(addr.s_addr);
	inet_aton("255.255.0.0", &addr);
	mask1 = ntohl(addr.s_addr);
	inet_aton("192.167.1.1", &addr);
	ip2 = ntohl(addr.s_addr);
	inet_aton("255.255.255.0", &addr);
	mask2 = ntohl(addr.s_addr);
	printf("192.168.1.1 255.255.0.0 192.168.1.1 255.255.255.0 = %d\n",
				is_net_overlap(ip1,mask1,ip2,mask2) );

	inet_aton("192.168.2.1", &addr);
	ip1 = ntohl(addr.s_addr);
	inet_aton("255.255.0.0", &addr);
	mask1 = ntohl(addr.s_addr);
	inet_aton("192.168.1.1", &addr);
	ip2 = ntohl(addr.s_addr);
	inet_aton("255.255.255.0", &addr);
	mask2 = ntohl(addr.s_addr);
	printf("192.168.2.1 255.255.0.0 192.168.1.1 255.255.255.0 = %d\n",
				is_net_overlap(ip1,mask1,ip2,mask2) );		
	return 0;
}
#endif

