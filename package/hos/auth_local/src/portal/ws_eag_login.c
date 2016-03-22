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
* ws_eag_login.c
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

#include "ws_eag_login.h"
//#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <fcntl.h>
//#include <unistd.h>

extern FILE *out;

int cgi_auth_init(STAuthProcess * stAuProc, int port)
{	
	
	init_auth_socket(stAuProc,port);
	
	
	return 0;
}


int  init_auth_socket(STAuthProcess * stAuProc, int port )
{
	stAuProc->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if( stAuProc->fd < 0 )
	{
		fprintf(stderr,"create socket error!");
		return -1;
	}
/*
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(inet_addr("192.168.9.237"));
	address.sin_port = htonl(port);

	if( connect(stAuProc->fd,(struct sockaddr *)&address, sizeof(address) )<0 )
	{
		fprintf(stderr,"socket connect error!");
		return -1;
	}
		*/
	
	return 0;
}

static int conn_to_unix_socket( char *sockpath )/*this func is defined in ws_user_manage.c!  should it be......*/
{
	struct sockaddr_un remote;
	int len;
	int fd=-1;

/*	chmod_file( sockpath );*/
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if ( fd == -1) {
		fprintf(stderr,"create_unix_socket create unix socket failed");
		return fd;
	}

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, sockpath);/*how len of sun_path??*/
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(fd, (struct sockaddr *)&remote, len) == -1) {
		fprintf(stderr, "conn_to_unix_socket socket fd %d	 %s\n", fd, strerror(errno));
		close(fd);
		fd = -1; 
		return fd;
	}

	return fd;
}

/**/
int suc_connect_unix_sock()
{
	int ret=-1,i;
	char path[100]="";
	for( i=EAGINS_ID_BEGIN ; i<=MAX_EAGINS_NUM; i++)
	{
		sprintf(path,EAGINS_UNIXSOCK_PREFIX"%d",i);
		if( !access(path,0))
			ret = conn_to_unix_socket(path);
		
		if( ret >= 0 )
		{
			fprintf(stderr,"findfd=%d",ret);
			break;
		}		
	}

	if ( i == (MAX_EAGINS_NUM+1) )/*都连接不上*/
		ret = -1;
	
	return ret;
}

int get_authType_from_eag( STUserManagePkg *pkg, int fd,int wait, STUserManagePkg **pprsp )
{
	int authType = 0, delay=0, begintime,ret;

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

	begintime = time(0);
	fprintf(stderr,"start to sendpkg");
	if( 0 != sendpkg( fd, delay, pkg ) )
	{
		fprintf( stderr, "sendpkg error!" );
		return -1;
	}
	
	/*接收响应*/
	if( time(0) - begintime >= delay )
	{
		fprintf( stderr, "time out!!!" );
		return -1;	
	}
	

	ret = getpkg( fd, delay - (time(0) - begintime), pprsp );
	fprintf( stderr, "after getpkg ret = %d\n", ret );


	fprintf( stderr, "*pprsp->auth_type = %d\n", (*pprsp)->auth_type );
	authType = (*pprsp)->auth_type;
	return authType;
}






/*auth_type属性*/
int setAuthType(STPortalPkg *pstPortalPkg, AUTH_TYPE auth_type)
{
	if (NULL == pstPortalPkg) {
		return -1;
	}
	
	pstPortalPkg->auth_type = auth_type;
	
	return 0;
}


int setPkgUserIP(STPortalPkg * pkg, UINT32 ip_addr)
{
	pkg->user_ip = ip_addr;
	return 0;
}

static unsigned int getAttrNum(STPortalPkg *pstPortalPkg)
{
	if (NULL == pstPortalPkg) {
		return -1;
	}

	return pstPortalPkg->attr_num;
}

/*添加属性*/
int addAttr
(
	STPortalPkg **pp_stPortalPkg,
	ATTR_TYPE attr_type,
	void *attr_value,
	unsigned int attr_value_len
)
{
	STPortalPkg *pstPortalPkg = NULL;
	STPkgAttr *pstPkgAttr = NULL;
	unsigned int new_pkg_size = 0;
	unsigned int pkg_size = 0;
	unsigned int old_pkg_size = 0;
	
	if (NULL == pp_stPortalPkg || 
		NULL == *pp_stPortalPkg || 
		NULL == attr_value ||
		0 == attr_value_len ||
		attr_value_len > MAX_ATTR_VALUE_LEN) 
	{
		return -1;
	} 
	
	
	pstPortalPkg = *pp_stPortalPkg;
	
	pkg_size = getPkgSize( pstPortalPkg ) ;
	new_pkg_size = attr_value_len + pkg_size + 2;/*加2是因为STPkgAttr中有两个字节来标识attr的类型和attr的长度。*/
	pstPortalPkg = (STPortalPkg *)realloc( pstPortalPkg, new_pkg_size );/*扩展buff的空间*/
	
	pstPkgAttr = (STPkgAttr *)( (UINT32)pstPortalPkg + pkg_size );
   
	pstPkgAttr->attr_type = attr_type;
	pstPkgAttr->attr_len = attr_value_len+2;
	memcpy( pstPkgAttr->attr_value, attr_value, attr_value_len );
	
	pstPortalPkg->attr_num++;
	
	*pp_stPortalPkg = pstPortalPkg;
	
	return 0;
}

/*根据attr_type获得属性*/
STPkgAttr *getAttrByAttrType
(
	STPortalPkg *pstPortalPkg,
	ATTR_TYPE attr_type
)
{
	STPkgAttr *pstPkgAttrRet = NULL;
	unsigned int attr_num = 0;
	unsigned int i = 0;
	
	if (NULL == pstPortalPkg) {
		return NULL;
	}

	attr_num = getAttrNum(pstPortalPkg);
	
	pstPkgAttrRet=(STPkgAttr *)pstPortalPkg->attr;
	for( i=0; i<attr_num; i++)
	{
		if( attr_type == pstPkgAttrRet->attr_type )
		{
			break;	
		}
		pstPkgAttrRet = (STPkgAttr *)((UINT32)pstPkgAttrRet + pstPkgAttrRet->attr_len);	
	}
	
	if( attr_num == i )
	{
		pstPkgAttrRet = NULL;
	}
	
	return pstPkgAttrRet;
}


/*设置req_id*/
int setRequireID
(
	STPortalPkg *pstPortalPkg,
	unsigned short req_id
)
{
	if (NULL == pstPortalPkg) {
		return -1;
	}

	pstPortalPkg->req_id = req_id;
	
	return 0;		
}

unsigned short getRequireID
(
	STPortalPkg *pstPortalPkg
)
{
	if (NULL == pstPortalPkg) {
		return -1;
	}

	return pstPortalPkg->req_id;			
}




unsigned int getPkgSize(STPortalPkg *pstPortalPkg)
{
	unsigned int i = 0;
	unsigned int pkg_size = 0;
	unsigned int attr_num = 0;
	STPkgAttr *pstPkgAttr = NULL;
	
	if (NULL == pstPortalPkg) {
		return -1;
	}
	
	pkg_size = sizeof(STPortalPkg);
	attr_num = getAttrNum(pstPortalPkg);
	fprintf(stderr,"attr_num=%d\n",attr_num);
	
	pstPkgAttr = (STPkgAttr *)pstPortalPkg->attr;

	for( i=0; i<attr_num; i++)
	{
		pkg_size += pstPkgAttr->attr_len;
		pstPkgAttr = (STPkgAttr *)((UINT32)pstPkgAttr + pstPkgAttr->attr_len);	
	}
	fprintf(stderr,"pkg_size=%d\n",pkg_size);
	return pkg_size;
}



STPortalPkg *createPortalPkg(PKG_TYPE pkg_type)/*version 默认设置为 0x1*/
{
	STPortalPkg *pRet = NULL;
	
	pRet = (STPortalPkg *)malloc(sizeof(STPortalPkg));
	if (!pRet) {
		fprintf(stderr, "createPortalPkg malloc failed!\n");
		return NULL;
	}

	memset( pRet, 0, sizeof(STPortalPkg) );
	pRet->version = 0x01;
	pRet->pkg_type = pkg_type;
	
	return pRet;
}

/*销毁一个数据包*/
unsigned int  destroyPortalPkg(STPortalPkg *pstPortalPkg)
{
	if( NULL != pstPortalPkg )
	{
		free( pstPortalPkg );
	}
	 
	return 0;
}

int closePkgSock(STAuthProcess * stAuProc)
{
	if( stAuProc == NULL )
		return -1;
	
	if( stAuProc->fd > 0)
		close(stAuProc->fd);
	
	return 0;
}

unsigned char getErrCode(STPortalPkg *pstPortalPkg)
{
	if (NULL == pstPortalPkg) {
		return -1;
	}
		
	return pstPortalPkg->err_code;	
}


int getPortalPkg( int fd, int wait, STPortalPkg **pp_portal_pkg )
{

	ssize_t recvlen = 0;
	size_t buflen = 0;
	char buffer[5125];


	int done=0;

	memset(buffer, 0, sizeof(buffer));

	struct sockaddr_in address;

	unsigned int addr_len = sizeof(address);


	/* read whatever the client send to us */ 
	{
	
		fd_set fdset;
		struct timeval tv;
		int status;
		FD_ZERO(&fdset);
		FD_SET(fd,&fdset);
		
		tv.tv_sec = wait;
		tv.tv_usec = 500000;
		fprintf(stderr,"getPortalPkg wait = %d\n",wait);
		fprintf(out,"getPortalPkg wait = %d\n",wait);
		int startTime=0, endTime=0;
		startTime =	time(0);

		
			status = select(fd + 1, &fdset, (fd_set *) 0,(fd_set *) 0,&tv);
			fprintf(stderr,"getPortalPkg status = %d\n", status );
			fprintf(out,"getPortalPkg status = %d\n", status );

			if( (status > 0) && FD_ISSET(fd, &fdset))
			{

					if (buflen + 2 >= sizeof(buffer)) {
						fprintf(stderr,"getPortalPkg select error2222 !!!!\n");
						fprintf(out,"getPortalPkg select error2222 !!!!\n");
						return -1;
					}
		
					if ((recvlen = recvfrom(fd, buffer + buflen,  sizeof(buffer) - 1 - buflen, 0 ,(struct sockaddr *)&address, (unsigned int*)&(addr_len) )) < 0) {
						fprintf(stderr, "getPortalPkg errno == %d  %s ECONNRESET = %d\n ", errno, strerror(errno),ECONNRESET );
						fprintf(out, "getPortalPkg errno == %d  %s ECONNRESET = %d\n ", errno, strerror(errno),ECONNRESET );
						if (errno != ECONNRESET)
							return -1;
					}
		
					if (recvlen == 0) done=1;
					
					buflen += recvlen;
					buffer[buflen] = 0;
					endTime = time(0);
			}
			else
			{
				//超时或出错
				*pp_portal_pkg = (STPortalPkg *)calloc( 1, buflen ); 
				if( NULL == *pp_portal_pkg )
				{ 
					return -1;
				}
				(*pp_portal_pkg)->err_code = PORTAL_AUTH_REJECT;
				fprintf(stderr, "getPortalPkg error time out\n");
				fprintf(out, "getPortalPkg error time out\n");
				return -1;
			}


		
	}
    fprintf(stderr, "getPortalPkg recvfrom length buflen=%d---rev form address=%s\n",buflen, inet_ntoa(address.sin_addr) );
    fprintf(out, "getPortalPkg recvfrom length buflen=%d---rev form address=%s\n",buflen, inet_ntoa(address.sin_addr) );
	
	if( buflen <= 0 )
	{
		fprintf(stderr, "getPortalPkg xxxxxxxx\n" );
		fprintf(out, "getPortalPkg xxxxxxxx\n" );
		return -1;
	}
	
	*pp_portal_pkg = (STPortalPkg *)calloc( 1, buflen );
 
	if( NULL == *pp_portal_pkg )
	{ 
		return -1;
	}
   
	memcpy( *pp_portal_pkg, buffer, buflen );
	

	return 0;
}




int sendPortalPkg( int fd, int wait, int port, char * addr, STPortalPkg *pkg )
{
	ssize_t c;
	size_t r = 0;
	ssize_t len = getPkgSize(pkg);
	char *buf = pkg;
	int starttime;

	
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(inet_addr(addr));
	address.sin_port = htonl(port);
	
	if( NULL == pkg )
		return -1;
	
	starttime = time(0);
	
	fprintf(out,"sendPortalPkg before send data  len = %d\n", len);
	fprintf(stderr,"sendPortalPkg before send data  len = %d\n", len);
	while( r < len && (time(0)<starttime+wait) ) 
	{
		fd_set fdset;
		struct timeval tv;
		
		FD_ZERO(&fdset);
		FD_SET(fd,&fdset);
		
		tv.tv_sec = 0;
		tv.tv_usec = 500000;
		
		if (select(fd + 1,(fd_set *) 0,&fdset,(fd_set *) 0,&tv) == -1)
		{
			fprintf(stderr,"sendPortalPkg sellect err!\n");
			fprintf(out,"sendPortalPkg sellect err!\n");
			break;
		}
		
		if (FD_ISSET(fd, &fdset))
			c = sendto(fd,buf+r,len-r,0, (struct sockaddr *)&address, sizeof(address) );
		
		if (c <= 0) break;
		r += (size_t)c;
		
	}
	fprintf(stderr,"sendPortalPkg after send data r = %d  len = %d\n", r, len);
	fprintf(out,"sendPortalPkg after send data r = %d  len = %d\n", r, len);
	if( len > r )
	{
		return -1;
	}
	fprintf(stderr,"sendPortalPkg send ok!!!\n");
	fprintf(out,"sendPortalPkg send ok!!!\n");
	return 0;
}

/*MD5加密可能用到的函数--------------*/

void byteReverse(unsigned char *buf, size_t longs)
{
    uint32_t t;
    do {
      t = (uint32_t)((uint16_t)(buf[3] << 8 | buf[2])) << 16 |
	            ((uint16_t)(buf[1] << 8 | buf[0]));
      *(uint32_t *) buf = t;
      buf += 4;
    } while (--longs);
}

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void MD5Init(struct MD5Context *ctx)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;

    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void MD5Update(struct MD5Context *ctx, unsigned char const *buf, size_t len)
{
    uint32_t t;

    /* Update bitcount */

    t = ctx->bits[0];
    if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t)
	ctx->bits[1]++;		/* Carry from low to high */
    ctx->bits[1] += len >> 29;

    t = (t >> 3) & 0x3f;	/* Bytes already in shsInfo->data */

    /* Handle any leading odd-sized chunks */

    if (t) {
	unsigned char *p = (unsigned char *) ctx->in + t;

	t = 64 - t;
	if (len < t) {
	    memcpy(p, buf, len);
	    return;
	}
	memcpy(p, buf, t);
	byteReverse(ctx->in, 16);
	MD5Transform(ctx->buf, (uint32_t *) ctx->in);
	buf += t;
	len -= t;
    }
    /* Process data in 64-byte chunks */

    while (len >= 64) {
	memcpy(ctx->in, buf, 64);
	byteReverse(ctx->in, 16);
	MD5Transform(ctx->buf, (uint32_t *) ctx->in);
	buf += 64;
	len -= 64;
    }

    /* Handle any remaining bytes of data. */

    memcpy(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void MD5Final(unsigned char digest[16], struct MD5Context *ctx)
{
    size_t count;
    unsigned char *p;

    /* Compute number of bytes mod 64 */
    count = (ctx->bits[0] >> 3) & 0x3F;

    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    p = ctx->in + count;
    *p++ = 0x80;
    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - count;

    /* Pad out to 56 mod 64 */
    if (count < 8) {
	/* Two lots of padding:  Pad the first block to 64 bytes */
	memset(p, 0, count);
	byteReverse(ctx->in, 16);
	MD5Transform(ctx->buf, (uint32_t *) ctx->in);

	/* Now fill the next block with 56 bytes */
	memset(ctx->in, 0, 56);
    } else {
	/* Pad block to 56 bytes */
	memset(p, 0, count - 8);
    }
    byteReverse(ctx->in, 14);

    /* Append length in bits and transform */
    ((uint32_t *) ctx->in)[14] = ctx->bits[0];
    ((uint32_t *) ctx->in)[15] = ctx->bits[1];

    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    byteReverse((unsigned char *) ctx->buf, 4);
    memcpy(digest, ctx->buf, 16);
    memset(ctx, 0, sizeof(ctx));	/* In case it's sensitive */
}

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
	( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
void MD5Transform(uint32_t buf[4], uint32_t const in[16])
{
    register uint32_t a, b, c, d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}




