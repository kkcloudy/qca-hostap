#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/in_route.h>
//#include <linux/ip_mp_alg.h>
#include <asm/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <resolv.h>
#include <netdb.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_bridge.h>
#include <dirent.h>

#include <errno.h>
//#include <linux/if_arp.h>

#include "limits2.h"
#include "eag_errcode.h"
#include "eag_log.h"
#include "eag_ipinfo.h"	

#define SIOCIARP	0x8956		/* get ARP table entry and intf name */

static int ipinfo_sockfd = -1;

#if 0
//#define RTM_GETROUTE	26
//#define AF_UNSPEC	0
#define PREFIXLEN_SPECIFIED 1
//#define RTA_ALIGNTO	4


static int print_neigh(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg,
							char *const inf, size_t if_len, unsigned char *const mac, const char *ip);

static int ll_remember_index(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);



#define NLMSG_LENGTH(len) ((len)+NLMSG_ALIGN(NLMSG_HDRLEN))
#define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len <= (len))
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
					  (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
#define RTA_DATA(rta)   ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_PAYLOAD(rta) ((int)((rta)->rta_len) - RTA_LENGTH(0))
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define SPRINT_BUF(x)	char x[64]
#define RTA_ALIGN(len) ( ((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1) )
#define RTA_LENGTH(len)	(RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
	
typedef int (*rtnl_filter_route_t)(const struct sockaddr_nl *, struct nlmsghdr *n, void *);
typedef int (*rtnl_filter_neigh_t)(const struct sockaddr_nl *, 
			    					struct nlmsghdr *n, void *,char *const,size_t len,unsigned char *const ,const char * );

struct rtnl_handle
{
	int 		fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	unsigned  int			seq;
	unsigned  int			dump;
};
struct dn_naddr 
{
		unsigned short a_len;
		unsigned char a_addr[20];
};
struct ipx_addr {
	unsigned int ipx_net;
	unsigned char ipx_node[6];
};
typedef struct
{
	unsigned char family;
	unsigned char bytelen;
	unsigned char bitlen;
	unsigned char flags;
	unsigned char data[4];
} inet_prefix;
struct namerec
{
	struct namerec *next;
	inet_prefix addr;
	char	    *name;
};
struct filter
{
	int family;
	int index;
	int state;
	int unused_only;
	inet_prefix pfx;
	int flushed;
	char *flushb;
	int flushp;
	int flushe;
} ;
struct idxmap
{
	struct idxmap * next;
	unsigned	index;
	int		type;
	int		alen;
	unsigned	flags;
	unsigned char	addr[8];
	char		name[16];
};

static struct
{
	int tb;
	int cloned;
	int flushed;
	char *flushb;
	int flushp;
	int flushe;
	int protocol, protocolmask;
	int scope, scopemask;
	int type, typemask;
	int tos, tosmask;
	int iif, iifmask;
	int oif, oifmask;
	int realm, realmmask;
	inet_prefix rprefsrc;
	inet_prefix rvia;
	inet_prefix rdst;
	inet_prefix mdst;
	inet_prefix rsrc;
	inet_prefix msrc;
} filter;
struct rtnl_handle rth_iproute;
static struct idxmap *g_idxmap[16];
//static struct namerec *nht[256];
struct filter filter_ip;
struct rtnl_handle rth;
int show_stats = 0;
int preferred_family = AF_UNSPEC;
int __iproute2_hz_internal;


static int rtnl_open_byproto (struct rtnl_handle *rth, unsigned subscriptions, int protocol)
{
	socklen_t addr_len;
	int sndbuf = 32768;
	int rcvbuf = 32768;

	memset(rth, 0, sizeof(rth));
	
	rth->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (rth->fd < 0) {
		eag_log_err("ip neigh Cannot open netlink socket\n");
		return -1;
	}

	if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0) {
		eag_log_err("ip neigh SO_SNDBUF");
		return -1;
	}

	if (setsockopt(rth->fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf)) < 0) {
		eag_log_err("ip neigh SO_RCVBUF");
		return -1;
	}

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
		eag_log_err("ip neigh Cannot bind netlink socket");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
		 eag_log_err("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		eag_log_err("Wrong address length %d\n", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		eag_log_err("Wrong address family %d\n", rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);

	eag_log_info("rtnl_open_byproto fd=%d", rth->fd);
	return 0;
}

static int rtnl_open (struct rtnl_handle *rth, unsigned subscriptions)
{
	return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}

void rtnl_close(struct rtnl_handle *rth)
{
	eag_log_info("rtnl_close fd=%d", rth->fd);
	if (rth->fd >= 0) {
		close(rth->fd);
		rth->fd = -1;
	}
}

static int rtnl_send(struct rtnl_handle *rth, const char *buf, int len)
{
	struct sockaddr_nl nladdr;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	return sendto(rth->fd, buf, len, 0, (struct sockaddr*)&nladdr, sizeof(nladdr));
}

static int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer, 
					unsigned groups, struct nlmsghdr *answer, rtnl_filter_route_t junk, void *jarg)
{
	int status;
	unsigned seq;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	struct iovec iov = {
		.iov_base = (void*) n,
		.iov_len = n->nlmsg_len
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char   buf[16384];

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = peer;
	nladdr.nl_groups = groups;

	n->nlmsg_seq = seq = ++rtnl->seq;

	if (answer == NULL)
		n->nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(rtnl->fd, &msg, 0);

	if (status < 0) {
		eag_log_err("Cannot talk to rtnetlink");
		return -1;
	}

	memset(buf,0,sizeof(buf));

	iov.iov_base = buf;

	while (1) {
		iov.iov_len = sizeof(buf);
		status = recvmsg(rtnl->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR)
				continue;
			eag_log_err("OVERRUN");
			continue;
		}
		if (status == 0) {
			eag_log_err("EOF on netlink\n");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			eag_log_err("sender address length == %d\n", msg.msg_namelen);
			return -1;
		}
		for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
			int err;
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l<0 || len>status) {
				if (msg.msg_flags & MSG_TRUNC) {
					eag_log_err("Truncated message\n");
					return -1;
				}
				eag_log_err("!!!malformed message: len=%d\n", len);
				return -1;
			}

			if (nladdr.nl_pid != peer ||
			    h->nlmsg_pid != rtnl->local.nl_pid ||
			    h->nlmsg_seq != seq) {
				if (junk) {
					err = junk(&nladdr, h, jarg);
					if (err < 0)
						return err;
				}
				/* Don't forget to skip that message. */
				status -= NLMSG_ALIGN(len);
				h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
				continue;
			}

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
				if (l < sizeof(struct nlmsgerr)) {
					eag_log_err("eag ERROR truncated\n");
				} else {
					errno = -err->error;
					if (errno == 0) {
						if (answer)
							memcpy(answer, h, h->nlmsg_len);
						return 0;
					}
					eag_log_err("RTNETLINK answers");
				}
				return -1;
			}
			if (answer) {
				memcpy(answer, h, h->nlmsg_len);
				return 0;
			}

			eag_log_err("Unexpected reply!!!\n");

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			eag_log_err("Message truncated\n");
			continue;
		}
		if (status) {
			eag_log_err("!!!Remnant of size %d\n", status);
			return -1;
		}
	}
}

#if 0
static char *resolve_address(const char *addr, int len, int af)
{
	struct namerec *n;
	struct hostent *h_ent;
	unsigned hash;
	static int notfirst;


	if (af == AF_INET6 && ((__u32*)addr)[0] == 0 &&
	    ((__u32*)addr)[1] == 0 && ((__u32*)addr)[2] == htonl(0xffff)) {
		af = AF_INET;
		addr += 12;
		len = 4;
	}

	hash = addr[len-1] ^ addr[len-2] ^ addr[len-3] ^ addr[len-4];

	for (n = nht[hash]; n; n = n->next) {
		if (n->addr.family == af &&
		    n->addr.bytelen == len &&
		    memcmp(n->addr.data, addr, len) == 0)
			return n->name;
	}
	if ((n = malloc(sizeof(*n))) == NULL)
		return NULL;
	n->addr.family = af;
	n->addr.bytelen = len;
	n->name = NULL;
	memcpy(n->addr.data, addr, len);
	n->next = nht[hash];
	nht[hash] = n;
	if (++notfirst == 1)
		sethostent(1);
	fflush(stdout);
	
	if ((h_ent = gethostbyaddr((const void *)addr, len, af)) != NULL)
	{
	//	n->name = (char *)malloc(strlen(h_ent->h_name));
	//	memset(n->name,0,strlen(h_ent->h_name));
	//	strcpy(n->name,h_ent->h_name);
		//n->name = char*(,h_ent->h_name);
	}
	/* Even if we fail, "negative" entry is remembered. */
	return n->name;
}
#endif

static int do_digit_t(char *str, unsigned int addr,  unsigned int scale, size_t *pos, size_t len)
{
	unsigned int tmp = addr >> (scale * 4);

	if (*pos == len)
		return 1;

	tmp &= 0x0f;
	if (tmp > 9)
		*str = tmp + 'A' - 10;
	else
		*str = tmp + '0';
	(*pos)++;

	return 0;
}

static const char *ipx_ntop1(const struct ipx_addr *addr, char *str, size_t len)
{
	 int i;
	 size_t pos = 0;
 
	 if (len == 0)
		 return str;
 
	 for(i = 7; i >= 0; i--)
		 if (do_digit_t(str + pos, ntohl(addr->ipx_net), i, &pos, len))
			 return str;
 
	 if (pos == len)
		 return str;
 
	 *(str + pos) = '.';
	 pos++;
	 
	 for(i = 0; i < 6; i++) {
		 if (do_digit_t(str + pos, addr->ipx_node[i], 1, &pos, len))
			 return str;
		 if (do_digit_t(str + pos, addr->ipx_node[i], 0, &pos, len))
			 return str;
	 }

	 if (pos == len)
		 return str;

	 *(str + pos) = 0;
 
	 return str;
}

static const char *ipx_ntop(int af, const void *addr, char *str, size_t len)
{
	switch(af) {
		case AF_IPX:
			errno = 0;
			return ipx_ntop1((struct ipx_addr *)addr, str, len);
		default:
			errno = EAFNOSUPPORT;
	}

	return NULL;
}

static __inline__ u_int16_t dn_ntohs(u_int16_t addr)
{
	 union {
		 u_int8_t byte[2];
		 u_int16_t word;
	 } u;
 
	 u.word = addr;
	 return ((unsigned short)u.byte[0]) | (((unsigned short)u.byte[1]) << 8);
 }

static int do_digit(char *str,  unsigned short *addr, unsigned short scale, size_t *pos, size_t len, int *started)
{
	unsigned short tmp = *addr / scale;

	if (*pos == len)
		return 1;

	if (((tmp) > 0) || *started || (scale == 1)) {
		*str = tmp + '0';
		*started = 1;
		(*pos)++;
		*addr -= (tmp * scale);
	}

	return 0;
}

static char *dnet_ntop1(const struct dn_naddr *dna, char *str, size_t len)
{
	u_int16_t addr = dn_ntohs(*(u_int16_t *)dna->a_addr);
	u_int16_t area = addr >> 10;
	size_t pos = 0;
	int started = 0;

	if (dna->a_len != 2)
		return NULL;

	addr &= 0x03ff;

	if (len == 0)
		return str;

	if (do_digit(str + pos, &area, 10, &pos, len, &started))
		return str;

	if (do_digit(str + pos, &area, 1, &pos, len, &started))
		return str;

	if (pos == len)
		return str;

	*(str + pos) = '.';
	pos++;
	started = 0;

	if (do_digit(str + pos, &addr, 1000, &pos, len, &started))
		return str;

	if (do_digit(str + pos, &addr, 100, &pos, len, &started))
		return str;

	if (do_digit(str + pos, &addr, 10, &pos, len, &started))
		return str;

	if (do_digit(str + pos, &addr, 1, &pos, len, &started))
		return str;

	if (pos == len)
		return str;

	*(str + pos) = 0;

	return str;
}

static const char *dnet_ntop(int af, const void *addr, char *str, size_t len)
{
	switch(af) {
		case AF_DECnet:
			errno = 0;
			return dnet_ntop1((struct dn_naddr *)addr, str, len);
		default:
			errno = EAFNOSUPPORT;
	}

	return NULL;
}

static const char *rt_addr_n2a(int af, int len, const void *addr, char *buf, int buflen)
{
	switch (af) {
	case AF_INET:
	case AF_INET6:
		return inet_ntop(af, addr, buf, buflen);
	case AF_IPX:
		return ipx_ntop(af, addr, buf, buflen);
	case AF_DECnet:
	{
		struct dn_naddr dna = { 2, { 0, 0, }};
		memcpy(dna.a_addr, addr, 2);
		return dnet_ntop(af, &dna, buf, buflen);
	}
	default:
		return "???";
	}
}

static const char *format_host(int af, int len, const void *addr, char *buf, int buflen)
{

#ifdef RESOLVE_HOSTNAMES
	int resolve_hosts = 0;
	if (resolve_hosts) {
		char *n;
		if (len <= 0) {
			switch (af) {
			case AF_INET:
				len = 4;
				break;
			case AF_INET6:
				len = 16;
				break;
			case AF_IPX:
				len = 10;
				break;
#ifdef AF_DECnet
			/* I see no reasons why gethostbyname
			   may not work for DECnet */
			case AF_DECnet:
				len = 2;
				break;
#endif
			default: ;
			}
		}
		if (len > 0 &&
		    (n = resolve_address(addr, len, af)) != NULL)
			return n;
	}
#endif
	return rt_addr_n2a(af, len, addr, buf, buflen);
}

static int __get_hz(void)
{
	char name[1024];
	int hz = 0;
	FILE *fp;

	if (getenv("HZ"))
		return atoi(getenv("HZ")) ? : HZ;

	if (getenv("PROC_NET_PSCHED")) {
		snprintf(name, sizeof(name)-1, "%s", getenv("PROC_NET_PSCHED"));
	} else if (getenv("PROC_ROOT")) {
		snprintf(name, sizeof(name)-1, "%s/net/psched", getenv("PROC_ROOT"));
	} else {
		strcpy(name, "/proc/net/psched");
	}
	fp = fopen(name, "r");

	if (fp) {
		unsigned nom, denom;
		if (fscanf(fp, "%*08x%*08x%08x%08x", &nom, &denom) == 2)
			if (nom == 1000000)
				hz = denom;
		fclose(fp);
	}
	if (hz)
		return hz;
	return HZ;
}

static int get_hz(void)
{
	if (__iproute2_hz_internal == 0)
		__iproute2_hz_internal = __get_hz();
	return __iproute2_hz_internal;
}

static int dnet_num(const char *src, u_int16_t * dst)
{
	int rv = 0;
	int tmp;
	*dst = 0;

	while ((tmp = *src++) != 0) {
		tmp -= '0';
		if ((tmp < 0) || (tmp > 9))
			return rv;

		rv++;
		(*dst) *= 10;
		(*dst) += tmp;
	}

	return rv;
}

static __inline__ u_int16_t dn_htons(u_int16_t addr)
{
        union {
                u_int8_t byte[2];
                u_int16_t word;
        } u;

        u.word = addr;
        return ((u_int16_t)u.byte[0]) | (((u_int16_t)u.byte[1]) << 8);
}

static int dnet_pton1(const char *src, struct dn_naddr *dna)
{
	u_int16_t area = 0;
	u_int16_t node = 0;
	int pos;

	pos = dnet_num(src, &area);
	if ((pos == 0) || (area > 63) || (*(src + pos) != '.'))
		return 0;
	pos = dnet_num(src + pos + 1, &node);
	if ((pos == 0) || (node > 1023))
		return 0;
	dna->a_len = 2;
	*(u_int16_t *)dna->a_addr = dn_htons((area << 10) | node);

	return 1;
}

static int dnet_pton(int af, const char *src, void *addr)
{
	int err;

	switch (af) {
	case AF_DECnet:
		errno = 0;
		err = dnet_pton1(src, (struct dn_naddr *)addr);
		break;
	default:
		errno = EAFNOSUPPORT;
		err = -1;
	}

	return err;
}

static int get_addr_1(inet_prefix *addr, const char *name, int family)
{
	const char *cp;
	unsigned char *ap = (unsigned char*)addr->data;
	int i;

	memset(addr, 0, sizeof(*addr));

	if (strcmp(name, "default") == 0 ||
		strcmp(name, "all") == 0 ||
		strcmp(name, "any") == 0) {
		if (family == AF_DECnet)
			return -1;
		addr->family = family;
		addr->bytelen = (family == AF_INET6 ? 16 : 4);
		addr->bitlen = -1;
		return 0;
	}

	if (strchr(name, ':')) {
		addr->family = AF_INET6;
		if (family != AF_UNSPEC && family != AF_INET6)
			return -1;
		if (inet_pton(AF_INET6, name, addr->data) <= 0)
			return -1;
		addr->bytelen = 16;
		addr->bitlen = -1;
		return 0;
	}

	if (family == AF_DECnet) {
		struct dn_naddr dna;
		addr->family = AF_DECnet;
		if (dnet_pton(AF_DECnet, name, &dna) <= 0)
			return -1;
		memcpy(addr->data, dna.a_addr, 2);
		addr->bytelen = 2;
		addr->bitlen = -1;
		return 0;
	}

	addr->family = AF_INET;
	if (family != AF_UNSPEC && family != AF_INET)
		return -1;
	addr->bytelen = 4;
	addr->bitlen = -1;
	for (cp=name, i=0; *cp; cp++) {
		if (*cp <= '9' && *cp >= '0') {
			ap[i] = 10*ap[i] + (*cp-'0');
			continue;
		}
		if (*cp == '.' && ++i <= 3)
			continue;
		return -1;
	}
	return 0;
}

static int get_unsigned(unsigned *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > UINT_MAX)
		return -1;
	*val = res;
	return 0;
}


int get_prefix_1(inet_prefix *dst, char *arg, int family)
{
	int err;
	unsigned plen;
	char *slash;

	memset(dst, 0, sizeof(*dst));

	if (strcmp(arg, "default") == 0 ||
	    strcmp(arg, "any") == 0 ||
	    strcmp(arg, "all") == 0) {
		if (family == AF_DECnet)
			return -1;
		dst->family = family;
		dst->bytelen = 0;
		dst->bitlen = 0;
		return 0;
	}

	slash = strchr(arg, '/');
	if (slash)
		*slash = 0;

	err = get_addr_1(dst, arg, family);
	if (err == 0) {
		switch(dst->family) {
			case AF_INET6:
				dst->bitlen = 128;
				break;
			case AF_DECnet:
				dst->bitlen = 16;
				break;
			default:
			case AF_INET:
				dst->bitlen = 32;
		}
		if (slash) {
			if (get_unsigned(&plen, slash+1, 0) || plen > dst->bitlen) {
				err = -1;
				goto done;
			}
			dst->flags |= PREFIXLEN_SPECIFIED;
			dst->bitlen = plen;
		}
	}
done:
	if (slash)
		*slash = '/';
	return err;
}

static int get_prefix(inet_prefix *dst, char *arg, int family)
{
	if (family == AF_PACKET) {
		eag_log_err("Error: \"%s\" may be inet prefix, but it is not allowed in this context.\n", arg);
		return -1;
	}
	if (get_prefix_1(dst, arg, family)) {
		eag_log_err("Error: an inet prefix is expected rather than \"%s\".\n", arg);
		return -1;
	}
	return 0;
}

static int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		eag_log_err("addattr_l ERROR: message exceeded bound of %d\n",maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

static int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
	if (len){
		eag_log_err("!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	}
	return 0;
}

static int flush_update(void)
{
	if (rtnl_send(&rth, filter_ip.flushb, filter_ip.flushp) < 0) {
		eag_log_err("Failed to send flush request\n");
		return -1;
	}
	filter_ip.flushp = 0;
	return 0;
}

static int inet_addr_match(const inet_prefix *a, const inet_prefix *b, int bits)
{
	unsigned int *a1 = (unsigned int *)a->data;
	unsigned int *a2 = (unsigned int *)b->data;
	int words = bits >> 0x05;

	bits &= 0x1f;

	if (words)
		if (memcmp(a1, a2, words << 2))
			return -1;

	if (bits) {
		unsigned int w1, w2;
		unsigned int mask;

		w1 = a1[words];
		w2 = a2[words];

		mask = htonl((0xffffffff) << (0x20 - bits));

		if ((w1 ^ w2) & mask)
			return 1;
	}

	return 0;
}

static int ll_remember_index(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	int h;
	struct ifinfomsg *ifi = NLMSG_DATA(n);
	struct idxmap *im, **imp;
	struct rtattr *tb[IFLA_MAX+1];

	if (n->nlmsg_type != RTM_NEWLINK)
		return 0;

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(ifi)))
		return -1;


	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(n));
	if (tb[IFLA_IFNAME] == NULL)
		return 0;

	h = ifi->ifi_index&0xF;

	for (imp=&g_idxmap[h]; (im=*imp)!=NULL; imp = &im->next){
		if (im->index == ifi->ifi_index)
			break;
	}

	if (im == NULL) {
		im = malloc(sizeof(*im));
		if (im == NULL)
			return 0;
		im->next = *imp;
		im->index = ifi->ifi_index;
		*imp = im;
	}

	im->type = ifi->ifi_type;
	im->flags = ifi->ifi_flags;
	if (tb[IFLA_ADDRESS]) {
		int alen;
		im->alen = alen = RTA_PAYLOAD(tb[IFLA_ADDRESS]);
		if (alen > sizeof(im->addr))
			alen = sizeof(im->addr);
		memcpy(im->addr, RTA_DATA(tb[IFLA_ADDRESS]), alen);
	} else {
		im->alen = 0;
		memset(im->addr, 0, sizeof(im->addr));
	}
	strcpy(im->name, RTA_DATA(tb[IFLA_IFNAME]));
	return 0;
}

static int rtnl_wilddump_request(struct rtnl_handle *rth, int family, int type)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;
	struct sockaddr_nl nladdr;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = rth->dump = ++rth->seq;
	req.g.rtgen_family = family;
	return sendto(rth->fd, (void*)&req, sizeof(req), 0,
			  (struct sockaddr*)&nladdr, sizeof(nladdr));
}

static int rtnl_dump_filter(struct rtnl_handle *rth, rtnl_filter_neigh_t filter, void *arg1,
						 char *const inf, size_t n, unsigned char *const mac, const char *ip)
{
			
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[16384];

	iov.iov_base = buf;

	while (1) {
		int status;
		struct nlmsghdr *h = NULL;

		iov.iov_len = sizeof(buf);
		status = recvmsg(rth->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR)
				continue;
			eag_log_err("OVERRUN");
			continue;
		}

		if (status == 0) {
			eag_log_err("EOF on netlink\n");
			return -1;
		}
		
		h = (struct nlmsghdr*)buf;


		#if 1
		while (NLMSG_OK(h, status)) {
			int err;
			 
			#if 0
			if (nladdr.nl_pid != 0 ||
				h->nlmsg_pid != rth->local.nl_pid ||
				h->nlmsg_seq != rth->dump) {
				if (junk) {
					eag_log_err("err==%d\n",err);
					err = junk(&nladdr, h, arg2);
					if (err < 0)
						return err;
				}
				goto skip_it;
			}
			#endif
			
			if (h->nlmsg_type == NLMSG_DONE)
				return 0;
			#if 0
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
				eag_log_err("err==%x\n",err);
				if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
					fprintf(stderr, "ERROR truncated\n");
				} else     {
					errno = -err->error;
					perror("RTNETLINK answers");
				}
				return -1;
			}
			#endif
			
			err = filter(&nladdr, h, arg1, inf, n, mac, ip);
			if (err < 0)
				return err;

				h = NLMSG_NEXT(h, status);
		}
		
		#endif
	
		if (msg.msg_flags & MSG_TRUNC) {
			eag_log_err("Message truncated\n");
			continue;
		}
		if (status) {
			eag_log_err(" ip neigh Remnant of size %d\n", status);
			return 1;
		}
	}

}


static int ll_init_map(struct rtnl_handle *rth)
{

	if (rtnl_wilddump_request(rth, 0, RTM_GETLINK) < 0) {
		eag_log_err("ip neigh Cannot send dump request");
		return -1;
	}

	if (rtnl_dump_filter(rth, (rtnl_filter_neigh_t)ll_remember_index, NULL, NULL, 0, NULL,NULL) < 0) {
		eag_log_err("ip neigh Dump terminated\n");
		return -1;
	}

	return 0;
}

static const char *ll_idx_n2a(unsigned idx, char *buf)
{
	struct idxmap *im;

	if (idx == 0)
		return "*";
	for (im = g_idxmap[idx&0xF]; im; im = im->next)
	{
		if (im->index == idx)
		{
			return im->name;
		}
	}
	snprintf(buf, 16, "if%d", idx);
	return buf;
}

static const char *ll_index_to_name(unsigned idx)
{
	static char nbuf[16];

	return ll_idx_n2a(idx, nbuf);
}

#if 0
static int ll_index_to_type(unsigned idx)
{
	struct idxmap *im;

	if (idx == 0)
		return -1;
	for (im = g_idxmap[idx&0xF]; im; im = im->next)
	{
		if (im->index == idx)
		{
			return im->type;
		}
	}
	return -1;
}
#endif

#if 0
static const unsigned char *ll_addr_n2a(unsigned char *addr, int alen, int type, unsigned char *buf, int blen)
{
	int i;
	int l;

	if (alen == 4 &&
	    (type == ARPHRD_TUNNEL || type == ARPHRD_SIT || type == ARPHRD_IPGRE)) {
		return inet_ntop(AF_INET, addr, buf, blen);
	}
	
	
	l = 0;
	for (i=0; i<alen; i++) {
		
		if (i==0) {
			snprintf(buf+l, blen, "%02x", addr[i]);
			
			blen -= 2;
			l += 2;
		} else {
			snprintf(buf+l, blen, ":%02x", addr[i]);
			blen -= 3;
			l += 3;
		}
	}
	
	return buf;
}
#endif

static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
	__u32 table = r->rtm_table;
	if (tb[15])
		table = *(__u32*) RTA_DATA(tb[15]);
	return table;
}

/*ip neighbor functions*/
static void ipneigh_reset_filter()
{
	memset(&filter_ip, 0, sizeof(struct filter));
	filter_ip.state = ~0;
}

int eag_ipneigh_init()
{
	if (rtnl_open(&rth, RTMGRP_NEIGH) < 0) {
		eag_log_err("rtnl_open error!");
		return -1;
	}
	
	ipneigh_reset_filter();
	if (!filter_ip.family)
			filter_ip.family = preferred_family;
	
	filter_ip.state = 0xFF & ~NUD_NOARP;
	
	return 0;
}

int eag_ipneigh_uninit()
{
	int h;
	struct idxmap *im, *imp;
	for (h=0;h<16;h++)
	{
		im=g_idxmap[h];
		
		while (im!=NULL)
		{
			imp=im;
			im=im->next;
			free(imp);
		}
		g_idxmap[h]=NULL;
	}
	
	rtnl_close(&rth);
	return 0;
}

static int print_neigh(const struct sockaddr_nl *who, 
							struct nlmsghdr *n, 
							void *arg,
							char *const inf,
							size_t if_len,
							unsigned char *const mac,
							const char *ip)
{
	//unsigned char b1[6];
	struct ndmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr * tb[NDA_MAX+1];
	char abuf[256];
	
	if (n->nlmsg_type != RTM_NEWNEIGH && n->nlmsg_type != RTM_DELNEIGH) {
		//eag_log_err("Not RTM_NEWNEIGH: %08x %08x %08x\n",
			//n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		
		return 0;
	}
	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		eag_log_err("BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (filter_ip.flushb && n->nlmsg_type != RTM_NEWNEIGH)
		return 0;

	if (filter_ip.family && filter_ip.family != r->ndm_family)
		return 0;
	if (filter_ip.index && filter_ip.index != r->ndm_ifindex)
		return 0;
	if (!(filter_ip.state&r->ndm_state) &&
		(r->ndm_state || !(filter_ip.state&0x100)) &&
			 (r->ndm_family != AF_DECnet))
		return 0;

	parse_rtattr(tb, NDA_MAX, NDA_RTA(r), n->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	if (tb[NDA_DST]) {
		if (filter_ip.pfx.family) {
			inet_prefix dst;
			memset(&dst, 0, sizeof(dst));
			dst.family = r->ndm_family;
			memcpy(&dst.data, RTA_DATA(tb[NDA_DST]), RTA_PAYLOAD(tb[NDA_DST]));
			if (inet_addr_match(&dst, &filter_ip.pfx, filter_ip.pfx.bitlen))
				return 0;
		}
	}
	if (filter_ip.unused_only && tb[NDA_CACHEINFO]) {
		struct nda_cacheinfo *ci = RTA_DATA(tb[NDA_CACHEINFO]);
		if (ci->ndm_refcnt)
			return 0;
	}

	if (filter_ip.flushb) {
		struct nlmsghdr *fn;
		if (NLMSG_ALIGN(filter_ip.flushp) + n->nlmsg_len > filter_ip.flushe) {
			if (flush_update())
				return -1;
		}
		fn = (struct nlmsghdr*)(filter_ip.flushb + NLMSG_ALIGN(filter_ip.flushp));
		memcpy(fn, n, n->nlmsg_len);
		fn->nlmsg_type = RTM_DELNEIGH;
		fn->nlmsg_flags = NLM_F_REQUEST;
		fn->nlmsg_seq = ++rth.seq;
		filter_ip.flushp = (((char*)fn) + n->nlmsg_len) - filter_ip.flushb;
		filter_ip.flushed++;
		if (show_stats < 2)
			return 0;
	}
	
	if (tb[NDA_DST]) {
		/*
		eag_log_err("ip neigh ip :%s ", 
			format_host(r->ndm_family,
					RTA_PAYLOAD(tb[NDA_DST]),
					RTA_DATA(tb[NDA_DST]),
					abuf, sizeof(abuf)));*/
		if(strcmp(ip,format_host(r->ndm_family,
					RTA_PAYLOAD(tb[NDA_DST]),
					RTA_DATA(tb[NDA_DST]),
					abuf, sizeof(abuf)))!= 0)
		{
			return 0;
		}
	}
	if (!filter_ip.index && r->ndm_ifindex)
	{
		//eag_log_err("ip neigh dev :%s ", ll_index_to_name(r->ndm_ifindex));	//debug
		strncpy(inf,ll_index_to_name(r->ndm_ifindex),if_len);
	}
	if (tb[NDA_LLADDR]) {
		//SPRINT_BUF(b1);
		//eag_log_err("ip neigh lladdr :%s", ll_addr_n2a(RTA_DATA(tb[NDA_LLADDR]),
						 // RTA_PAYLOAD(tb[NDA_LLADDR]),
						 //ll_index_to_type(r->ndm_ifindex),
						 //b1, sizeof(b1)));	//debug
		/*
		strncpy(mac,ll_addr_n2a(RTA_DATA(tb[NDA_LLADDR]),
						  RTA_PAYLOAD(tb[NDA_LLADDR]),
						  ll_index_to_type(r->ndm_ifindex),
						  b1, sizeof(b1)),MAX_MACADDR_LEN);
		*/
		
		int i=0;
		unsigned char *lladdr;
		lladdr=RTA_DATA(tb[NDA_LLADDR]);

		/*ll_addr_n2a(RTA_DATA(tb[NDA_LLADDR]),
						  RTA_PAYLOAD(tb[NDA_LLADDR]),
						  ll_index_to_type(r->ndm_ifindex),
						  b1, sizeof(b1));*/
		
		for (i=0;i<MAX_MACADDR_LEN;i++)
		{
			mac[i]=lladdr[i];
		}
						  
	}
	if (r->ndm_flags & NTF_ROUTER) {
		eag_log_err("ip neigh router");
	}
	if (tb[NDA_CACHEINFO] && show_stats) {
		static int hz;
		struct nda_cacheinfo *ci = RTA_DATA(tb[NDA_CACHEINFO]);
		if (!hz) {
			hz = get_hz();
		}
		if (ci->ndm_refcnt) {
			eag_log_err("ip neigh ref %d", ci->ndm_refcnt);
		}
		eag_log_err("ip neigh used %d/%d/%d", ci->ndm_used/hz,
			   ci->ndm_confirmed/hz, ci->ndm_updated/hz);
	}
	
	return 0;
}

int arp_ipneigh(char *const interface, size_t n, unsigned char *const mac, const unsigned long ip)
{
	char ip_string[MAX_IPADDR_LEN];
	memset(ip_string,0,MAX_IPADDR_LEN);
	
	ll_init_map(&rth);
	if (rtnl_wilddump_request(&rth, filter_ip.family, 30) < 0)
	{
			eag_log_err("ip neigh Cannot send dump request");
			return -1;
	}	
	snprintf(ip_string,MAX_IPADDR_LEN,"%d.%d.%d.%d",(int)((ip & 0xff000000) >> 24),(int)((ip & 0xff0000) >> 16), \
					(int)((ip& 0xff00) >> 8),(int)(ip & 0xff));
	
	if (rtnl_dump_filter(&rth, (rtnl_filter_neigh_t)print_neigh, NULL, interface, n, mac, ip_string) < 0)
	{
			eag_log_err("ip neigh Dump terminated\n");
			return -1;
	}
	return 0;
}

/*ip route functions*/
int eag_iproute_init()
{
	if (rtnl_open(&rth_iproute, 0) < 0)
		return -1;
	
	return 0;
}

int eag_iproute_uninit()
{
	int h;
	struct idxmap *im, *imp;
	for (h=0;h<16;h++){

		im=g_idxmap[h];

		while (im!=NULL)
		{
			imp=im;
			im=im->next;
			free(imp);
		}
		g_idxmap[h]=NULL;
	}

	rtnl_close(&rth_iproute);
	return 0;
}

static void iproute_reset_filter()
{
	memset(&filter, 0, sizeof(filter));
	filter.mdst.bitlen = -1;
	filter.msrc.bitlen = -1;
}

static int print_route(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg, char *const interf, size_t if_len)
{
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr * tb[RTA_MAX+1];
	//char abuf[256];
	inet_prefix dst;
	inet_prefix src;
	inet_prefix prefsrc;
	inet_prefix via;
	int host_len = -1;
	static int ip6_multiple_tables;
	__u32 table;
	//SPRINT_BUF(b1);
	

	if (n->nlmsg_type != RTM_NEWROUTE && n->nlmsg_type != RTM_DELROUTE)
	{
		//eag_log_err("Not a route: %08x %08x %08x\n",
			//n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return 0;
	}
	if (filter.flushb && n->nlmsg_type != RTM_NEWROUTE)
		return 0;
	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		eag_log_err("BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (r->rtm_family == AF_INET6)
		host_len = 128;
	else if (r->rtm_family == AF_INET)
		host_len = 32;
	else if (r->rtm_family == AF_DECnet)
		host_len = 16;
	else if (r->rtm_family == AF_IPX)
		host_len = 80;

	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
	table = rtm_get_table(r, tb);

	if (r->rtm_family == AF_INET6 && table != RT_TABLE_MAIN)
		ip6_multiple_tables = 1;

	if (r->rtm_family == AF_INET6 && !ip6_multiple_tables) {
		if (filter.cloned) {
			if (!(r->rtm_flags&RTM_F_CLONED))
				return 0;
		}
		if (filter.tb) {
			if (r->rtm_flags&RTM_F_CLONED)
				return 0;
			if (filter.tb == RT_TABLE_LOCAL) {
				if (r->rtm_type != RTN_LOCAL)
					return 0;
			} else if (filter.tb == RT_TABLE_MAIN) {
				if (r->rtm_type == RTN_LOCAL)
					return 0;
			} else {
				return 0;
			}
		}
	} else {
		if (filter.tb > 0 && filter.tb != table)
			return 0;
	}
	if ((filter.protocol^r->rtm_protocol)&filter.protocolmask)
		return 0;
	if ((filter.scope^r->rtm_scope)&filter.scopemask)
		return 0;
	if ((filter.type^r->rtm_type)&filter.typemask)
		return 0;
	if ((filter.tos^r->rtm_tos)&filter.tosmask)
		return 0;
	if (filter.rdst.family &&
	    (r->rtm_family != filter.rdst.family || filter.rdst.bitlen > r->rtm_dst_len))
		return 0;
	if (filter.mdst.family &&
	    (r->rtm_family != filter.mdst.family ||
	     (filter.mdst.bitlen < r->rtm_dst_len)))
		return 0;
	if (filter.rsrc.family &&
	    (r->rtm_family != filter.rsrc.family || filter.rsrc.bitlen > r->rtm_src_len))
		return 0;
	if (filter.msrc.family &&
	    (r->rtm_family != filter.msrc.family ||
	     (filter.msrc.bitlen < r->rtm_src_len)))
		return 0;
	if (filter.rvia.family && r->rtm_family != filter.rvia.family)
		return 0;
	if (filter.rprefsrc.family && r->rtm_family != filter.rprefsrc.family)
		return 0;

	memset(&dst, 0, sizeof(dst));
	dst.family = r->rtm_family;
	if (tb[RTA_DST])
		memcpy(&dst.data, RTA_DATA(tb[RTA_DST]), (r->rtm_dst_len+7)/8);
	if (filter.rsrc.family || filter.msrc.family) {
		memset(&src, 0, sizeof(src));
		src.family = r->rtm_family;
		if (tb[RTA_SRC])
			memcpy(&src.data, RTA_DATA(tb[RTA_SRC]), (r->rtm_src_len+7)/8);
	}
	if (filter.rvia.bitlen>0) {
		memset(&via, 0, sizeof(via));
		via.family = r->rtm_family;
		if (tb[RTA_GATEWAY])
			memcpy(&via.data, RTA_DATA(tb[RTA_GATEWAY]), host_len/8);
	}
	if (filter.rprefsrc.bitlen>0) {
		memset(&prefsrc, 0, sizeof(prefsrc));
		prefsrc.family = r->rtm_family;
		if (tb[RTA_PREFSRC])
			memcpy(&prefsrc.data, RTA_DATA(tb[RTA_PREFSRC]), host_len/8);
	}

	if (filter.rdst.family && inet_addr_match(&dst, &filter.rdst, filter.rdst.bitlen))
		return 0;
	if (filter.mdst.family && inet_addr_match(&dst, &filter.mdst, r->rtm_dst_len))
		return 0;

	if (filter.rsrc.family && inet_addr_match(&src, &filter.rsrc, filter.rsrc.bitlen))
		return 0;
	if (filter.msrc.family && inet_addr_match(&src, &filter.msrc, r->rtm_src_len))
		return 0;

	if (filter.rvia.family && inet_addr_match(&via, &filter.rvia, filter.rvia.bitlen))
		return 0;
	if (filter.rprefsrc.family && inet_addr_match(&prefsrc, &filter.rprefsrc, filter.rprefsrc.bitlen))
		return 0;
	if (filter.realmmask) {
		__u32 realms = 0;
		if (tb[RTA_FLOW])
			realms = *(__u32*)RTA_DATA(tb[RTA_FLOW]);
		if ((realms^filter.realm)&filter.realmmask)
			return 0;
	}
	if (filter.iifmask) {
		int iif = 0;
		if (tb[RTA_IIF])
			iif = *(int*)RTA_DATA(tb[RTA_IIF]);
		if ((iif^filter.iif)&filter.iifmask)
			return 0;
	}
	if (filter.oifmask) {
		int oif = 0;
		if (tb[RTA_OIF])
			oif = *(int*)RTA_DATA(tb[RTA_OIF]);
		if ((oif^filter.oif)&filter.oifmask)
			return 0;
	}
	if (filter.flushb && 
	    r->rtm_family == AF_INET6 &&
	    r->rtm_dst_len == 0 &&
	    r->rtm_type == RTN_UNREACHABLE &&
	    tb[RTA_PRIORITY] &&
	    *(int*)RTA_DATA(tb[RTA_PRIORITY]) == -1)
		return 0;

	if (filter.flushb) {
		struct nlmsghdr *fn;
		if (NLMSG_ALIGN(filter.flushp) + n->nlmsg_len > filter.flushe) {
			if (flush_update())
				return -1;
		}
		fn = (struct nlmsghdr*)(filter.flushb + NLMSG_ALIGN(filter.flushp));
		memcpy(fn, n, n->nlmsg_len);
		fn->nlmsg_type = RTM_DELROUTE;
		fn->nlmsg_flags = NLM_F_REQUEST;
		fn->nlmsg_seq = ++rth_iproute.seq;
		filter.flushp = (((char*)fn) + n->nlmsg_len) - filter.flushb;
		filter.flushed++;
		if (show_stats < 2)
			return 0;
	}

	if (tb[RTA_OIF] && filter.oifmask != -1)
	{
		strncpy(interf,ll_index_to_name(*(int*)RTA_DATA(tb[RTA_OIF])),if_len);
	}

	return 0;
}

int ip_interface(const unsigned long ip, char *const interface, size_t n)
{
	struct {
		struct nlmsghdr 	n;
		struct rtmsg 		r;
		char   			buf[1024];
	}req;
	
	//char  *idev = NULL;
	//char  *odev = NULL;
	//int connected = 0;
	//int from_ok = 0;
	char ip_string[MAX_IPADDR_LEN];
	memset(ip_string,0,MAX_IPADDR_LEN);
	
	snprintf(ip_string,MAX_IPADDR_LEN,"%d.%d.%d.%d",(int)((ip & 0xff000000) >> 24),(int)((ip & 0xff0000) >> 16), \
					(int)((ip& 0xff00) >> 8),(int)(ip & 0xff));
	
	memset(&req, 0, sizeof(req));

	iproute_reset_filter();
	int preferred_family = AF_UNSPEC;

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = preferred_family;
	req.r.rtm_table = 0;
	req.r.rtm_protocol = 0;
	req.r.rtm_scope = 0;
	req.r.rtm_type = 0;
	req.r.rtm_src_len = 0;
	req.r.rtm_dst_len = 0;
	req.r.rtm_tos = 0;

	inet_prefix addr;
	get_prefix(&addr, ip_string, req.r.rtm_family);
	if (req.r.rtm_family == AF_UNSPEC)
		req.r.rtm_family = addr.family;
	if (addr.bytelen)
		addattr_l(&req.n, sizeof(req), RTA_DST, &addr.data, addr.bytelen);
	req.r.rtm_dst_len = addr.bitlen;

	if (req.r.rtm_dst_len == 0) {
		eag_log_err("need at least destination address\n");
		return -1;
	}

	ll_init_map(&rth_iproute);
	
	if (req.r.rtm_family == AF_UNSPEC)
		req.r.rtm_family = AF_INET;

	if (rtnl_talk(&rth_iproute, &req.n, 0, 0, &req.n, NULL, NULL) < 0)
		return -1;
	
	if (print_route(NULL, &req.n, NULL,interface,n) < 0) {
		eag_log_err("An error :-)\n");
		return -1;
	}

	return 0;
}
#endif
#define SYSFS_PATH_MAX	256
#define SYSFS_CLASS_NET "/sys/class/net/"
static int first;
#define MAX_BRIDGES	1024
#define MAX_PORTS	1024
int br_socket_fd = -1;

int br_init(void)
{
	if ((br_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return errno;
	return 0;
}

void br_shutdown(void)
{
	close(br_socket_fd);
	br_socket_fd = -1;
}

inline void __jiffies_to_tv(struct timeval *tv, unsigned long jiffies)
{
	unsigned long long tvusec;

	tvusec = 10000ULL*jiffies;
	tv->tv_sec = tvusec/1000000;
	tv->tv_usec = tvusec - 1000000 * tv->tv_sec;
}

inline void __copy_fdb(struct fdb_entry *ent, 
			      const struct __fdb_entry *f)
{
	memcpy(ent->mac_addr, f->mac_addr, 6);
	ent->port_no = f->port_no;
	ent->is_local = f->is_local;
	__jiffies_to_tv(&ent->ageing_timer_value, f->ageing_timer_value);
}

int br_read_fdb(const char *bridge, struct fdb_entry *fdbs, 
		unsigned long offset, int num)
{
	FILE *f;
	int i, n;
	struct __fdb_entry fe[num];
	char path[SYSFS_PATH_MAX];
	
	/* open /sys/class/net/brXXX/brforward */
	snprintf(path, SYSFS_PATH_MAX, SYSFS_CLASS_NET "%s/brforward", bridge);
	f = fopen(path, "r");
	if (f) {
		fseek(f, offset*sizeof(struct __fdb_entry), SEEK_SET);
		n = fread(fe, sizeof(struct __fdb_entry), num, f);
		fclose(f);
	} else {
		/* old kernel, use ioctl */
		unsigned long args[4] = { BRCTL_GET_FDB_ENTRIES,
					  (unsigned long) fe,
					  num, offset };
		struct ifreq ifr;
		int retries = 0;

		strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
		ifr.ifr_data = (char *) args;

	retry:
		n = ioctl(br_socket_fd, SIOCDEVPRIVATE, &ifr);

		/* table can change during ioctl processing */
		if (n < 0 && errno == EAGAIN && ++retries < 10) {
			sleep(0);
			goto retry;
		}
	}

	for (i = 0; i < n; i++) 
		__copy_fdb(fdbs+i, fe+i);

	return n;
}

 int compare_fdbs(const void *_f0, const void *_f1)
{
	const struct fdb_entry *f0 = _f0;
	const struct fdb_entry *f1 = _f1;

	return memcmp(f0->mac_addr, f1->mac_addr, 6);
}

int old_foreach_port(const char *brname,
				int (*iterator)(const char *br, const char *port, 
						void *arg),
				void *arg)
{
	int i, err, count;
	struct ifreq ifr;
	char ifname[IFNAMSIZ];
	int ifindices[MAX_PORTS];
	unsigned long args[4] = { BRCTL_GET_PORT_LIST,
				  (unsigned long)ifindices, MAX_PORTS, 0 };

	memset(ifindices, 0, sizeof(ifindices));
	strncpy(ifr.ifr_name, brname, IFNAMSIZ);
	ifr.ifr_data = (char *) &args;

	err = ioctl(br_socket_fd, SIOCDEVPRIVATE, &ifr);
	if (err < 0) {
	   // dprintf("list ports for bridge:'%s' failed: %s\n",
	   //	brname, strerror(errno));
		return -errno;
	}

	count = 0;
	for (i = 0; i < MAX_PORTS; i++) {
		if (!ifindices[i])
			continue;

		if (!if_indextoname(ifindices[i], ifname)) {
	   //	dprintf("can't find name for ifindex:%d\n",
	   //		ifindices[i]);
			continue;
		}

		++count;
		if (iterator(brname, ifname, arg))
			break;
	}

	return count;
}

int br_foreach_port(const char *brname,
		    int (*iterator)(const char *br, const char *port, void *arg,int pt,char *intf),
		    void *arg,int port_no,char *intf)
{
	int i, count;
	struct dirent **namelist;
	char path[SYSFS_PATH_MAX];

	snprintf(path, SYSFS_PATH_MAX, SYSFS_CLASS_NET "%s/brif", brname);
	count = scandir(path, &namelist, 0, alphasort);
	if (count < 0)
		return old_foreach_port(brname, (int (*)(const char *br, const char *port, void *arg))iterator, arg);

	for (i = 0; i < count; i++) {
		if (iterator(brname, namelist[i]->d_name, arg,port_no,intf))
			break;
	}
	for (i = 0; i < count; i++)
		free(namelist[i]);
	free(namelist);

	return count;
}

int dump_interface(const char *b, const char *p, void *arg,int port_no,char *intf)
{
	char path[SYSFS_PATH_MAX];
	FILE *fd;
	char buf[20];
	int port;
	if (p[0] == '.') return 0;

	if (first) 
		first = 0;
	snprintf(path, SYSFS_PATH_MAX, SYSFS_CLASS_NET "%s/brif/%s/port_no", b,p);
	fd = fopen(path,"r");
	if(fd == NULL)
			return -1;
	else
		{
			//printf("%s", p);
			fgets(buf,20,fd);
			//printf("buf==%s\n",buf);
			//printf("=============\n");
			port = strtol(buf,NULL,16);
			//printf("port_no===%x\n",port);
			if(port==port_no)
				{
					//printf("***interfacename=%s\n***",p);
				
					strcpy(intf,p);
				}
		}

	fclose(fd);
	return 0;
}

int brctl_show(char *mac,char *br,char *intf)
{
	int ret = 0;

	ret = br_init();
	if (ret){
		eag_log_err("brctl_show: br_init socket err %s",safe_strerror(ret));
		return EAG_ERR_SOCKET_FAILED;
	}
	const char *brname = br;
#define CHUNK 128
	int i, n;
	struct fdb_entry *fdb = NULL;
	int offset = 0;

	for(;;) {
		fdb = realloc(fdb, (offset + CHUNK) * sizeof(struct fdb_entry));
		if (!fdb) {
			eag_log_err("realloc failed : Out of memory\n");
			return EAG_ERR_MALLOC_FAILED;
		}
			
		n = br_read_fdb(brname, fdb+offset, offset, CHUNK);
		if (n == 0)
			break;

		if (n < 0) {
			//fprintf(stderr, "read of forward table failed: %s\n",
			//	strerror(errno));
			free(fdb);
			eag_log_err("brctl_show read fdb error!");
			return EAG_ERR_UNKNOWN;
		}

		offset += n;
	}

	qsort(fdb, offset, sizeof(struct fdb_entry), compare_fdbs);

	eag_log_debug("eag_ipinfo","port no\tmac addr\t\tis local?\tageing timer\n");
	char mac_br[24];
	for (i = 0; i < offset; i++) {
		const struct fdb_entry *f = fdb + i;
		eag_log_debug("eag_ipinfo","%3i\t", f->port_no);
		eag_log_debug("eag_ipinfo","%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\t",
		       f->mac_addr[0], f->mac_addr[1], f->mac_addr[2],
		       f->mac_addr[3], f->mac_addr[4], f->mac_addr[5]);
		eag_log_debug("eag_ipinfo","%s\t\t", f->is_local?"yes":"no");
		//br_show_timer(&f->ageing_timer_value);

		sprintf(mac_br,"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\t",
					   f->mac_addr[0], f->mac_addr[1], f->mac_addr[2],
					   f->mac_addr[3], f->mac_addr[4], f->mac_addr[5]);

		if( strncasecmp(mac_br,mac,17)==0)
		{
			int err;
			err = br_foreach_port(brname, dump_interface, NULL,f->port_no,intf);
	
		}
		
	}
	free(fdb);
	br_shutdown();
	return 0;
}


int 
eag_ipinfo_get(char * const intf, size_t n, unsigned char *const mac, uint32_t ip)
{
	struct arpreq req;
	struct sockaddr_in *sin = NULL;
        struct in_addr ip_addr;
	unsigned char *ptr = NULL;
	int ret = -1;

	memset(&ip_addr, 0, sizeof(struct in_addr));
	ip_addr.s_addr = ip;

	memset(&req, 0, sizeof(req));
	sin = (struct sockaddr_in *) &req.arp_pa;
	sin->sin_family = AF_INET;
	memcpy(&(sin->sin_addr), &ip_addr, sizeof(struct in_addr));
          strcpy( req.arp_dev,"br-wan");
	ret = ioctl(ipinfo_sockfd, SIOCGARP, &req);
	if (ret < 0) {
		eag_log_err("000SIOCGARP : %s", safe_strerror(errno));
	}
	strncpy(intf, req.arp_dev, n);
	ptr = (unsigned char *)&req.arp_ha.sa_data[0];
	memcpy(mac, ptr, PKT_ETH_ALEN);
	
	eag_log_info( "intf: %s, mac: %02x:%02x:%02x:%02x:%02x:%02x", intf, *ptr,
		*(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));

	return EAG_RETURN_OK;
}

int
eag_ipinfo_init()
{
	if (ipinfo_sockfd >= 0) {
		eag_log_err("eag_ipinfo_init already start fd(%d)", 
			ipinfo_sockfd);
		return EAG_RETURN_OK;
	}
	
	ipinfo_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ipinfo_sockfd < 0) {
		eag_log_err("Can't create ipinfo dgram socket: %s",
				safe_strerror(errno));
		ipinfo_sockfd = -1;
		return EAG_ERR_SOCKET_FAILED;
	}
	return EAG_RETURN_OK;
}

int
eag_ipinfo_exit()
{
	close(ipinfo_sockfd);
	ipinfo_sockfd = -1;

	return EAG_RETURN_OK;
}

#ifdef eag_ipinfo_test		/*for unit test */
#include "eag_mem.c"
#include "eag_log.c"
#include "eag_blkmem.c"
#include "eag_errcode.c"


int main(int argc, char**argv)
{
	int ret = 0;
	int vlanid = -1;
	char *sub_interface = NULL;
	unsigned char sta_mac_str[6];
	memset (sta_mac_str,0,6);
	char interface[32];
	memset (interface,0,6);
	
	printf ("ip_1 %s \n",argv[1]);

	unsigned long uint_ip_1,uint_ip_2;
	uint_ip_1=(unsigned long)inet_addr(argv[1]);
	uint_ip_2=(unsigned long)inet_addr(argv[2]);
	
	eag_ipneigh_init();
	eag_iproute_init();
	
	arp_ipneigh( interface, 32, sta_mac_str, uint_ip_1);
	printf ("ip %s: arp_ipneigh interface %s mac %02X:%02X:%02X:%02X:%02X:%02X\n",argv[1], interface , sta_mac_str[0],sta_mac_str[1],sta_mac_str[2],sta_mac_str[3],sta_mac_str[4],sta_mac_str[5]);
	memset (sta_mac_str,0,6);
	memset (interface,0,6);
	
	ip_interface( uint_ip_1, interface,32);
	printf ("ip %s: ip_interface interface %s\n",argv[1], interface );
	memset (interface,0,6);

	arp_ipneigh( interface, 32, sta_mac_str, uint_ip_2);
	printf ("ip %s: arp_ipneigh interface %s mac %02X:%02X:%02X:%02X:%02X:%02X\n",argv[2], interface , sta_mac_str[0],sta_mac_str[1],sta_mac_str[2],sta_mac_str[3],sta_mac_str[4],sta_mac_str[5]);
	memset (sta_mac_str,0,6);
	memset (interface,0,6);
	
	ip_interface( uint_ip_2, interface,32);
	printf ("ip %s: ip_interface interface %s\n",argv[2], interface );
	memset (interface,0,6);

	eag_ipneigh_uninit();
	eag_iproute_uninit();
	return 0;
}

#endif


