#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>   
#include <linux/rtnetlink.h>
#include <stdbool.h>   
#include <fcntl.h>
#include <stdint.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
//#include <mcheck.h>

#define IFI_NAME 16
#define	IFI_HADDR 8
#define MAX_IF_IFNAME_LEN		32

#define FREE_OBJECT(a) do { if(NULL!=a){free(a);a=NULL;} } while (0)

typedef struct ifi_info
{
  char ifi_name[IFI_NAME];
  u_char ifi_haddr[IFI_HADDR];
  u_short ifi_hlen;
  short ifi_flags;
  short ifi_myflags;
  struct sockaddr *ifi_addr;
  struct sockaddr *ifi_brdaddr;
  struct sockaddr *ifi_dstaddr;
  struct sockaddr *ifi_mask;
  struct ifi_info *ifi_next;
}ifi_info;

typedef struct inf
{
	char if_addr[32];
	char if_name[32];
	char if_stat[32];
	char if_mask[32];
	int  upflag;
	struct inf *next;
}infi;


typedef struct if_t {
	char ifname[MAX_IF_IFNAME_LEN];
	char ipaddr[32];
	unsigned long ip;
	unsigned int mask;
	struct if_t *next;
} if3;

typedef struct if_list_t{
	int if_num;
	if3 *if_head;
} if_list_p;

struct nlsock {  
    int sock;  
    int seq;  
    struct sockaddr_nl snl;  
    char *name;  
}net_cmd = { -1, 0, {0}, "netlink-cmd" };  

struct nl_if_info {   
    uint32_t addr;   
    char *name;   
};



static int nl_socket ( struct nlsock *nl, unsigned long groups )  
{  
    int ret = 0;  
    struct sockaddr_nl snl;  
    int sock;  
    socklen_t namelen;
  
    sock = socket ( AF_NETLINK, SOCK_RAW, NETLINK_ROUTE );  
    if ( sock < 0 ) {  
        fprintf ( stderr,  "Can't open %s socket: %s", nl->name,  
                strerror ( errno ) );  
        return -1;  
    }  
  
    ret = fcntl ( sock, F_SETFL, O_NONBLOCK );  
    if ( ret < 0 ) {  
        fprintf ( stderr,  "Can't set %s socket flags: %s", nl->name,  
                strerror ( errno ) );  
        close ( sock );  
        return -1;  
    }  
  
    memset ( &snl, 0, sizeof snl );  
    snl.nl_family = AF_NETLINK;  
    snl.nl_groups = groups;  
  
    /* Bind the socket to the netlink structure for anything. */  
    ret = bind ( sock, ( struct sockaddr * ) &snl, sizeof snl );  
    if ( ret < 0 ) {  
        fprintf ( stderr,  "Can't bind %s socket to group 0x%x: %s",  
                nl->name, snl.nl_groups, strerror ( errno ) );  
        close ( sock );  
        return -1;  
    }  
  
    /* multiple netlink sockets will have different nl_pid */  
    namelen = sizeof snl;  
    ret = getsockname ( sock, ( struct sockaddr * ) &snl, &namelen );  
    if ( ret < 0 || namelen != sizeof snl ) {  
        fprintf ( stderr,  "Can't get %s socket name: %s", nl->name,  
                strerror ( errno ) );  
        close ( sock );  
        return -1;  
    }  
  
    nl->snl = snl;  
    nl->sock = sock;  
    return ret;  
}  



static int nl_request ( int family, int type, struct nlsock *nl )  
{  
    int ret;  
    struct sockaddr_nl snl;  
  
    struct {  
        struct nlmsghdr nlh;  
        struct rtgenmsg g;  
    } req;  
  
  
    /* Check netlink socket. */  
    if ( nl->sock < 0 ) {  
        fprintf ( stderr, "%s socket isn't active.", nl->name );  
        return -1;  
    }  
  
    memset ( &snl, 0, sizeof snl );  
    snl.nl_family = AF_NETLINK;  
  
    req.nlh.nlmsg_len = sizeof req;  
    req.nlh.nlmsg_type = type;  
    req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;  
    req.nlh.nlmsg_pid = 0;  
    req.nlh.nlmsg_seq = ++nl->seq;  
    req.g.rtgen_family = family;  
  
    ret = sendto ( nl->sock, ( void* ) &req, sizeof req, 0,  
            ( struct sockaddr* ) &snl, sizeof snl );  
    if ( ret < 0 ) {  
        fprintf ( stderr, "%s sendto failed: %s", nl->name, strerror ( errno ) );  
        return -1;  
    }  
    return 0;  
}  

static void nl_parse_rtattr ( struct rtattr **tb, int max, struct rtattr *rta, int len )  
{  
    while ( RTA_OK ( rta, len ) ) {  
        if ( rta->rta_type <= max )  
            tb[rta->rta_type] = rta;  
        rta = RTA_NEXT ( rta,len );  
    }  
} 
static int nl_get_if_addr ( struct sockaddr_nl *snl, struct nlmsghdr *h, void *arg, if3 *if_node )  
{  
    int len;  
    struct ifaddrmsg *ifa;  
    struct rtattr *tb [IFA_MAX + 1];  
    //void *addr = NULL;  
    //void *broad = NULL;  
    //u_char flags = 0;  
    //char *label = NULL;  
    uint32_t ifa_addr = 0;
	uint32_t ifa_local = 0;  
    char ifa_label[MAX_IF_IFNAME_LEN + 1];  
   
    ifa = NLMSG_DATA ( h );  
    if ( ifa->ifa_family != AF_INET ){  
		 FREE_OBJECT(if_node);
    	 return -1;  
    }
    if ( h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR ){  
		FREE_OBJECT(if_node);
        return -1;  
    }
    len = h->nlmsg_len - NLMSG_LENGTH ( sizeof ( struct ifaddrmsg ) );  
    if ( len < 0 ){  
		FREE_OBJECT(if_node);
        return -1;  
    }
    memset ( tb, 0, sizeof tb );  
  
    nl_parse_rtattr ( tb, IFA_MAX, IFA_RTA ( ifa ), len );  
      
    if (tb[IFA_ADDRESS] == NULL){  
    	tb[IFA_ADDRESS] = tb[IFA_LOCAL];  
    }
    if ( tb[IFA_ADDRESS] ){  
    	 ifa_addr = *(uint32_t *) RTA_DATA ( tb[IFA_ADDRESS] );  
    }
    if ( tb[IFA_LOCAL] ){  
    	 ifa_local = *(uint32_t *) RTA_DATA ( tb[IFA_LOCAL] );  
    }
    if ( tb[IFA_LABEL] ){  
     	strncpy( ifa_label, RTA_DATA ( tb[IFA_LABEL] ), MAX_IF_IFNAME_LEN );   
    }
  
    // 储存所有地址信息   
    struct in_addr if_addr;
    struct in_addr if_mask;
     
    memcpy(&if_addr, &ifa_addr, 4);
    memcpy(&if_mask, &ifa_local, 4);
     
	if(if_node)
	{
		memset(if_node->ifname,0,sizeof(if_node->ifname));
		strncpy(if_node->ifname,ifa_label,sizeof(if_node->ifname)-1);
		memset(if_node->ipaddr,0,sizeof(if_node->ipaddr));
		strncpy(if_node->ipaddr,inet_ntoa(if_addr),sizeof(if_node->ipaddr)-1);
		if_node->ip = ntohl(if_addr.s_addr);
		if_node->mask = ifa->ifa_prefixlen;
	    
	}
	return 0;  
}  

/* Receive message from netlink interface and pass those information 
   to the given function. */  
static int nl_parse_info ( int ( *filter ) ( struct sockaddr_nl *, struct nlmsghdr *, void *, if3 * ),  
        struct nlsock *nl, void *arg, if_list_p *iflist_t)  
{  
    int status;  
    int ret = 0;  
    int error;  
  	if3 *p = NULL,*tail = NULL;
	if(iflist_t)
	{
		iflist_t->if_num = 0;
		iflist_t->if_head = (if3 *)malloc(sizeof(if3));			
		if(iflist_t->if_head)
		{
			memset(iflist_t->if_head,0,sizeof(if3));
			tail = iflist_t->if_head;
		}
	}
    while ( 1 ) {  
        char buf[4096];  
        struct iovec iov = { buf, sizeof buf };  
        struct sockaddr_nl snl;  
        struct msghdr msg = { ( void* ) &snl, sizeof snl, &iov, 1, NULL, 0, 0};  
        struct nlmsghdr *h;  
  
        status = recvmsg ( nl->sock, &msg, 0 );  
  
        if ( status < 0 ) {  
            if ( errno == EINTR )  
                continue;  
            if ( errno == EWOULDBLOCK || errno == EAGAIN )  
                break;  
            fprintf ( stderr, "%s recvmsg overrun", nl->name );  
            continue;  
        }  
  
        if ( snl.nl_pid != 0 ) {  
            fprintf ( stderr, "Ignoring non kernel message from pid %u",  
                    snl.nl_pid );  
            continue;  
        }  
  
        if ( status == 0 ) {  
            fprintf ( stderr, "%s EOF", nl->name );  
            return -1;  
        }  
  
        if ( msg.msg_namelen != sizeof snl ) {  
            fprintf ( stderr, "%s sender address length error: length %d",  
                    nl->name, msg.msg_namelen );  
            return -1;  
        }  
  
        for ( h = ( struct nlmsghdr * ) buf; NLMSG_OK ( h, status );  
                h = NLMSG_NEXT ( h, status ) ) {  
            /* Finish of reading. */  
            if ( h->nlmsg_type == NLMSG_DONE )  
                return ret;  
  
            /* Error handling. */  
            if ( h->nlmsg_type == NLMSG_ERROR ) {  
                struct nlmsgerr *err = ( struct nlmsgerr * ) NLMSG_DATA ( h );  
  
                /* If the error field is zero, then this is an ACK */  
                if ( err->error == 0 ) {  
                    /* return if not a multipart message, otherwise continue */  
                    if ( ! ( h->nlmsg_flags & NLM_F_MULTI ) ) {  
                        return 0;  
                    }  
                    continue;  
                }  
  
                if ( h->nlmsg_len < NLMSG_LENGTH ( sizeof ( struct nlmsgerr ) ) ) {  
                    fprintf ( stderr, "%s error: message truncated",  
                            nl->name );  
                    return -1;  
                }  
                fprintf ( stderr, "%s error: %s, type=%u, seq=%u, pid=%d",  
                        nl->name, strerror ( -err->error ),  
                        err->msg.nlmsg_type, err->msg.nlmsg_seq,  
                        err->msg.nlmsg_pid );  
                /* 
                ret = -1; 
                continue; 
                */  
                return -1;  
            }  
  
  
            /* skip unsolicited messages originating from command socket */  
            if ( nl != &net_cmd && h->nlmsg_pid == net_cmd.snl.nl_pid ) {  
                continue;  
            }  

  			p = (if3 *)malloc(sizeof(if3));			
			memset(p,0,sizeof(if3));
            error = ( *filter ) ( &snl, h, arg, p);  
            if ( error < 0 ) {  
                fprintf ( stderr, "%s filter function error/n", nl->name );  
                ret = error;  
            }  
			else if( error == 0 )
			{
				if(p)
				{
					p->next = NULL;
					if(tail)
					{
						tail->next = p;
						tail = p;					
						if(iflist_t)
						{
							iflist_t->if_num++;
						}
					}
					else
					{
						FREE_OBJECT(p);	
					}
				}
			}
			
        }  
  
        /* After error care. */  
        if ( msg.msg_flags & MSG_TRUNC ) {  
            fprintf ( stderr, "%s error: message truncated", nl->name );  
            continue;  
        }  
        if ( status ) {  
            fprintf ( stderr, "%s error: data remnant size %d", nl->name,  
                    status );  
            return -1;  
        }  
    }  
    return ret;  
}   

void Free_get_all_if_info(if_list_p *iflist_t)
{
	int i = 0;
	if3 *f1 = NULL,*f2 = NULL;
	if(iflist_t)
	{
		f1 = iflist_t->if_head;
		if(f1)
		{			
			for(i = 0,f2 = f1->next; ((i < iflist_t->if_num)&&(NULL != f2)); i++,f2 = f2->next)
			{
				FREE_OBJECT(f1);
				f1 = f2;
			}
			FREE_OBJECT(f1);
		}
	}
}

/*获取所有三层接口的列表*/
/*返回0时，调用Free_get_all_if_info释放空间*/
int get_all_if_info( if_list_p *iflist_t )
{
	int ret = 0;  
	//char if_name[256] = { 0 };  
	//char *p = NULL;  
	struct nl_if_info if_info = { -1, " " };  

	ret = nl_socket ( &net_cmd, 0 );
	if ( ret < 0 ) 
	{  
		goto end;
	}  
	ret = nl_request ( AF_INET, RTM_GETADDR, &net_cmd );  
	if ( ret < 0 )
	{  
		goto end;
	}
	ret = nl_parse_info ( nl_get_if_addr, &net_cmd, &if_info, iflist_t); 
	if ( ret < 0 )
	{  
		goto end;
	}
	ret = 0;
	
end:
	if (net_cmd.sock >= 0) {
		close(net_cmd.sock);
		net_cmd.sock = -1;
	}
	return ret;
}

int 
if_has_ipaddr( unsigned long ipaddr )
{
    if_list_p list;
    if3 *p = NULL;
    int ret = 0;
    ret = get_all_if_info( &list );
    
    if( 0 != ret ){
        return 0;    
    }
    for(p=list.if_head;p!=NULL;p=p->next){
        if( p->ip == ipaddr ){
            ret = 1;
            break;
        }   
    }
    
    Free_get_all_if_info( &list );      
    
    return ret;
}


#if 0
int main()
{
    setenv("MALLOC_TRACE","mymemory.log",1);
    mtrace();
    if_list_p list;
    get_all_if_info( &list );
         
    Free_get_all_if_info( &list );
    
    printf("%x:%d\n", 123,if_has_ipaddr(123));
    printf("%x:%d\n", 0x7f000001,if_has_ipaddr(0x7f000001));    
    printf("%x:%d\n", 0x640101fe,if_has_ipaddr(0x640101fe));    
    printf("%x:%d\n", 0xc0a807af,if_has_ipaddr(0xc0a807af));   
    
    muntrace();
    return 0;
}
#endif
