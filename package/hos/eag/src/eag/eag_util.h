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
* eag_util.h
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

#ifndef _EAG_UTIL_H
#define _EAG_UTIL_H

#include <stdint.h>

#define MIN(a,b) ((a)>(b))?(b):(a)
#define MAX(a,b) ((a)>(b))?(a):(b)

int
sockopt_reuseaddr(int sock);

int 
set_nonblocking(int fd);

int
clear_nonblocking(int fd);

void
rand_buff(uint8_t *buff, size_t size);

char *
ip2str(uint32_t ip, char *str, size_t size);

char *
mac2str(const uint8_t mac[6], char *str, size_t size, char separator);

int
str2mac(const char *str, uint8_t mac[6]);

int
delete_0d0a(char *buff);

int
create_tcp_server(uint32_t ip, uint16_t port);

int
conn_to_server(uint32_t ip, uint16_t port);

int
is_mask(uint32_t mask);

int
is_net_overlap(uint32_t ip1, uint32_t mask1,
				uint32_t ip2, uint32_t mask2);

int
read_file(const char *file, char *buf, int size);

int
get_product_serial(void);

int
get_internal_if_name(int slotid, char *ifname, size_t len);

int
add_internal_if_ip(char *ifname, uint32_t ip, size_t mask);

int
del_internal_if_ip(char *ifname, uint32_t ip, size_t mask);



int 
BIO_des_encrypt( unsigned char * inbuf , unsigned char ** outbuf , 
					int inlen , unsigned char * key );// u should free outbuf after use.
int 
hex2str( unsigned char *hex, unsigned int hex_len, 
			unsigned char *output, unsigned int outputlen );
int
str2hex( unsigned char *str, unsigned char *output, unsigned int outputlen );

uint64_t ntohl64(uint64_t arg64);

uint64_t htonl64(uint64_t arg64);

#endif		/* _EAG_UTIL_H */

