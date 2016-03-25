/*******************************************************************************
			Copyright(c), 2009, Autelan Technology Co.,Ltd.
						All Rights Reserved

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
*	RCSfile   :  eag_iptables.c
*
*	Author   :  wangke
*
*	Revision :  1.00
*
*	Date      :  2010-1-5
********************************************************************************/
#ifdef __cplusplus
extern "C"
{
#endif
/*********************************************************
*	head files														*
**********************************************************/
#include <getopt.h>
#include <sys/errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <iptables.h>
#include <arpa/inet.h>
#include <linux/netfilter/nf_nat.h>
#include <pthread.h>
#include <syslog.h>
#include <netdb.h>
#include <linux/netfilter/xt_iprange.h> 	/* -m iprange */
#include <linux/netfilter/xt_multiport.h>	/* -m multiport */
#include <linux/netfilter/xt_string.h>	/* -m string */
#include <linux/netfilter/xt_comment.h>	/* -m comment */
//#include "eag_ipset.h"	/* -m set */
#include <linux/netfilter/x_tables.h>	/* -m comment */

#include "eag_errcode.h"

#include "eag_log.h"
#include "eag_util.h"
#include "eag_time.h"
#include "eag_mem.h"
#include "nm_list.h"

#include "eag_blkmem.h"
#include "hashtable.h"
#include "session.h"
#include "appconn.h"

#include "eag_interface.h"
#include "eag_iptables.h"

#include "nmp_process.h"

#define MAX_CAPTIVE_ID		16
#define USE_THREAD_LOCK		0
#define EAG_IPTABLE_SRC		1
#define EAG_IPTABLE_DST		2
#define EAG_IPTABLE_STRING	0x1
#define EAG_IPTABLE_ALGO	0x2
#define EAG_IPTABLE_FROM	0x4
#define EAG_IPTABLE_TO		0x8
#define IPT_MULTI_PORTS             15
#define CP_FILTER 		"CP_FILTER"
#define CP_DNAT 		"CP_DNAT"


struct eag_ipt_matches {
	struct list_head node;
	struct ipt_entry_match *match;
};

struct eag_ipt_entries {
	struct list_head node;
	struct ipt_entry *entry;
};
#if 0
union nf_inet_addr {
	__u32		all[4];
	__be32		ip;
	__be32		ip6[4];
	struct in_addr	in;
	struct in6_addr	in6;
};
struct xt_iprange_mtinfo {
	union nf_inet_addr src_min, src_max;
	union nf_inet_addr dst_min, dst_max;
	u_int8_t flags;
};
#endif
/*********************************************************
*	global variable define									  *
**********************************************************/
#if USE_THREAD_LOCK
static pthread_mutex_t eag_iptables_glock;
#endif

nmp_mutex_t eag_iptables_lock = {-1, ""};



static int 
get_index_of_entry(	const char * table_name,const char * chain_name,
							const unsigned int ip_addr,const int type );
static int 
add_and_del_entry	(const char *table_name,const char *chain_name,
							const int source_ip,const int dest_ip,
							const char *target_name,const int type);
static int 
check_is_chain(const char * table_name,const char * chain_name);


/*********************************************************
*	extern variable												*
**********************************************************/

/*********************************************************
*	functions define												*
**********************************************************/

/*******************************************************************
 *	get_ip_counter_info
 * 
 *	DESCRIPTION:
 *		This function get counter info of one user by ip
 *
 *	INPUT:
 *		ip_addr - the ip address
 *	
 *	OUTPUT:
 *		the_info - the counter info
 *
 *	RETURN:
 *		EAG_ERR_UNKNOWN	- get the counter failed
 *		EAG_RETURN_OK 	- get the counter successfully
 *
 *********************************************************************/
int 
get_ip_counter_info (unsigned int ip_addr,ip_counter_info * the_info)
{
	const char* table_name = "filter";
	const char* chain_name = NULL;
	const struct ipt_entry* p_entry = NULL;	
	const struct ipt_counters* my_counter = NULL;//ipt_counters defined in ip_tables.h
	struct iptc_handle *handle = NULL;
	char ip_str[32] = "";
	int return_ret = EAG_ERR_UNKNOWN;
	int is_get_source = 0;//flag
	int is_get_destination = 0;//flag
	unsigned int counter_num = 1;
	
	ip2str(ip_addr, ip_str, sizeof(ip_str));
	
	/* check input */
	if (0 == ip_addr>>24)
	{
		eag_log_err("ip range error! ip_addr == %s",ip_str);	
		goto return_error;
	}
	if (NULL == the_info)
	{
		eag_log_err("input counter_info is NULL");
		goto return_error;
	}

	/* set the ip address */
	the_info->ip_addr = ip_addr;

	/* init */
	nmp_mutex_lock(&eag_iptables_lock);
	handle = iptc_init(table_name);
	nmp_mutex_unlock(&eag_iptables_lock);
	if (NULL == handle)
	{
		eag_log_err("function get_ip_counter_info  error,"\
					"can't init iptc handle,table name:%s",table_name);
		goto return_error;
	}
	
	for	(chain_name = iptc_first_chain(handle);
		chain_name && ( !is_get_source || !is_get_destination);
		chain_name = iptc_next_chain(handle))
	{		
		counter_num = 1;//rule start from 1		
		/* get rules */
		for (p_entry = iptc_first_rule(chain_name, handle); 
  			p_entry && (!is_get_source || !is_get_destination); 
  			p_entry = iptc_next_rule(p_entry, handle))
		{
			my_counter = iptc_read_counter(chain_name, counter_num, handle);
			if (ip_addr == p_entry->ip.src.s_addr && !is_get_source){
				the_info->source_byte = my_counter->bcnt;
				the_info->source_pkt = my_counter->pcnt;
				is_get_source = 1;
			}else if (ip_addr == p_entry->ip.dst.s_addr && !is_get_destination){
				the_info->destination_byte= my_counter->bcnt;
				the_info->destination_pkt= my_counter->pcnt;
				is_get_destination = 1;
			}
			counter_num++;
		}
	}

	if (is_get_source==0 && is_get_destination==0)
	{	
		eag_log_err("can't find counter in the iptable");
		goto return_error;
	}

//return_success:
	return_ret = EAG_RETURN_OK;
	goto return_line;
	
return_error:
	return_ret = EAG_ERR_UNKNOWN;
	goto return_line;
	
return_line:
	if (NULL != handle)
	{
		iptc_free(handle);
		handle = NULL;
	}
	return return_ret;

}//get_ip_counter_info

/*******************************************************************
 *	connect_up
 * 
 *	DESCRIPTION:
 *		Add the ip to the iptables
 *
 *	INPUT:
 *		user_id 		- user captive portal id
 *		user_interface	- interface name
 *		user_ip		- user ip
 *
 *	OUTPUT:
 *		NULL
 *
 *	RETURN:
 *		EAG_ERR_UNKNOWN		- error
 *		EAG_RETURN_OK 		- success
 *
 *********************************************************************/
int 
connect_up(const char *user_interface,const unsigned int user_ip)
{
	int entry_num = 0;
//	int return_ret = EAG_ERR_UNKNOWN;
	char chain_name[256];
	char chain_name_in[256];
	char chain_name_nat[256];	
	char target_name[256];
	char target_name_nat[256];
	char ip_str[32] = "";

	//char *cpid_prefix = NULL;

		
	//cpid_prefix = (HANSI_LOCAL==hansitype)?"L":"R";
	ip2str(user_ip, ip_str, sizeof(ip_str));
	
	
	memset(chain_name,0,sizeof(chain_name));
	memset(chain_name_in,0,sizeof(chain_name_in));
	memset(chain_name_nat,0,sizeof(chain_name_nat));
	memset(target_name,0,sizeof(target_name));
	memset(target_name_nat,0,sizeof(target_name_nat));
	
	snprintf(chain_name,sizeof(chain_name),"CP_F_%s",user_interface);
	snprintf(chain_name_in,sizeof(chain_name_in),"CP_F_%s_IN", user_interface);
	snprintf(chain_name_nat,sizeof(chain_name_nat),"CP_N_DEFAULT");
	snprintf(target_name,sizeof(target_name),"CP_F_AUTH_DEFAULT");
	snprintf(target_name_nat,sizeof(target_name_nat),"ACCEPT");

	/* search if the chain is exist */
	if (EAG_RETURN_OK!= check_is_chain("filter",chain_name) 
		|| EAG_RETURN_OK != check_is_chain("filter",chain_name_in) 
		|| EAG_RETURN_OK != check_is_chain("nat",chain_name_nat))
	{
		eag_log_err("connect_up error,one or more chain is not exist,chain:%s,%s,%s",
						chain_name,chain_name_in,chain_name_nat);
		return EAG_ERR_UNKNOWN;
	}

	/* serch if the entry is exist */
	entry_num = get_index_of_entry("filter",chain_name,user_ip,EAG_IPTABLES_SOURCE);
	if ( entry_num < 0 ){
		eag_log_err("connect_up  error. input param might error!");
		return EAG_ERR_UNKNOWN;
	}else if( entry_num > 0 )
	{
		eag_log_err("connect_up error,entry is exist in the chain of table "\
					"\"filter\":user_ip==%s,chain_name==%s",ip_str,chain_name);
		return EAG_ERR_UNKNOWN;
	}
	
	/* add the entry */
	if	(EAG_RETURN_OK != add_and_del_entry("filter",chain_name,
							user_ip,0,target_name,EAG_IPTABLES_ADD)
		|| EAG_RETURN_OK !=  add_and_del_entry("filter",chain_name_in,0,
							user_ip,target_name,EAG_IPTABLES_ADD)
		|| EAG_RETURN_OK !=  add_and_del_entry("nat",chain_name_nat,
							user_ip,0,target_name_nat,EAG_IPTABLES_ADD))
	{
		eag_log_err("connect_up error, add entry error");
		return EAG_ERR_UNKNOWN;
	}

	return EAG_RETURN_OK;
}

/*******************************************************************
 *	connect_down
 * 
 *	DESCRIPTION:
 *		Delete the ip from the iptables
 *
 *	INPUT:
 *		user_id 		- user captive portal id
 *		user_interface	- interface name
 *		user_ip		- user ip
 *
 *	OUTPUT:
 *		NULL
 *
 *	RETURN:
 *		EAG_ERR_UNKNOWN		- error
 *		EAG_RETURN_OK 		- success
 *
 *********************************************************************/
int 
connect_down(const char *user_interface,const unsigned int user_ip)
{
//	int entry_num = 0;
//	int return_ret = EAG_ERR_UNKNOWN;
	char chain_name[256];
	char chain_name_in[256];
	char chain_name_nat[256];	
	char target_name[256];
	char target_name_nat[256];
	char ip_str[32] = "";
	
	
	ip2str(user_ip, ip_str, sizeof(ip_str));
	
	/* check input */
	if (NULL == user_interface)
	{
		eag_log_err("connect_down error. no user_interface input");		
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if (0 == user_ip>>24)
	{
		eag_log_err("connect_down error. ip range error! ip_addr == %s",ip_str);	
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	
	memset(chain_name,0,sizeof(chain_name));
	memset(chain_name_in,0,sizeof(chain_name_in));
	memset(chain_name_nat,0,sizeof(chain_name_nat));
	memset(target_name,0,sizeof(target_name));
	memset(target_name_nat,0,sizeof(target_name_nat));
	
	snprintf(chain_name,sizeof(chain_name),"CP_F_%s",user_interface);
	snprintf(chain_name_in,sizeof(chain_name_in),"CP_F_%s_IN",user_interface);
	snprintf(chain_name_nat,sizeof(chain_name_nat),"CP_N_DEFAULT");
	snprintf(target_name,sizeof(target_name),"CP_F_AUTH_DEFAULT");
	snprintf(target_name_nat,sizeof(target_name_nat),"ACCEPT");
	
	/* search if the chain is exist */
	if (EAG_RETURN_OK != check_is_chain("filter",chain_name) 
		|| EAG_RETURN_OK != check_is_chain("filter",chain_name_in) 
		|| EAG_RETURN_OK != check_is_chain("nat",chain_name_nat))
	{
		eag_log_err("connect_down error,one or more chain is not exist,chain:%s,%s,%s",chain_name,chain_name_in,chain_name_nat);
		return EAG_ERR_UNKNOWN;
	}
	
	/* del the entry */
	if	(EAG_RETURN_OK != add_and_del_entry("filter",chain_name,
								user_ip,0,target_name,EAG_IPTABLES_DELTE)
		|| EAG_RETURN_OK !=  add_and_del_entry("filter",chain_name_in,0,
								user_ip,target_name,EAG_IPTABLES_DELTE)
		|| EAG_RETURN_OK !=  add_and_del_entry("nat",chain_name_nat,
								user_ip,0,target_name_nat,EAG_IPTABLES_DELTE) )
	{
		eag_log_err("connect_down error,delete entry error");
		return EAG_ERR_UNKNOWN;
	}

	return EAG_RETURN_OK;
}

/*******************************************************************
 *	check_is_chain
 * 
 *	DESCRIPTION:
 *		Check the chain is exist in the table
 *
 *	INPUT:
 *		table_name - table name
 *		chain_name - chain name
 *	
 *	OUTPUT:
 *		NULL
 *
 *	RETURN:
 *		EAG_ERR_UNKNOWN	- error or not chain
 *		EAG_RETURN_OK 	- is chain
 *
 *********************************************************************/
static int 
check_is_chain(const char * table_name,const char * chain_name)
{
	int ret = EAG_RETURN_OK;
	struct iptc_handle *handle = NULL;
	if (NULL == table_name || NULL == chain_name)
	{
		eag_log_err("function check_is_chain  error,input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	nmp_mutex_lock(&eag_iptables_lock);
	handle = iptc_init(table_name);
	nmp_mutex_unlock(&eag_iptables_lock);
	if (NULL == handle)
	{
		eag_log_err("function check_is_chain  error,can't init iptc handle,"\
					"table name:%s",table_name);
		ret = EAG_ERR_UNKNOWN;
	}
	else if (!iptc_is_chain(chain_name, handle))/*check chain exist*/
	{
		eag_log_err("chain is not exist in the table,chain name:%s,"\
					"table name:%s",chain_name,table_name);
		ret = EAG_ERR_UNKNOWN;
	}
	
	if (NULL != handle)
	{
		iptc_free(handle);
		handle = NULL;
	}
	return ret;
}

/*******************************************************************
 *	get_index_of_entry
 * 
 *	DESCRIPTION:
 *		Serch is the entry exist
 *
 *	INPUT:
 *		table_name 	- table name
 *		chain_name 	- chain name
 *		ip_addr		- ip address
 *		type			- the input ip is source or destination
 *	
 *	OUTPUT:
 *		num_of_entry - the num of the entry
 *
 *	RETURN:
 *		EAG_ERR_UNKNOWN		- error
 *		EAG_RETURN_CODE_NOT_FOUND - not exist
 *		EAG_RETURN_OK 		- success ,entry is exist
 *
 *********************************************************************/
static int 
get_index_of_entry(	const char * table_name,const char * chain_name,
							const unsigned int ip_addr,const int type )
{	
	const struct ipt_entry *p_entry = NULL;
	const struct ipt_counters *my_counter = NULL;
	struct iptc_handle *handle = NULL;
	unsigned int index = 1;
	char ip_str[32] = "";
	
	ip2str( ip_addr, ip_str, sizeof(ip_str) );
	
	/* check input */
	if (EAG_IPTABLES_SOURCE != type && EAG_IPTABLES_DESTINATION != type)
	{
		eag_log_err("input error,input:%d",type);
		return -1;
	}
	
	if (0 == ip_addr>>24)
	{
		eag_log_err("ip range error! ip_addr == %s",ip_str);	
		return -1;
	}
	
	if (NULL == table_name || NULL == chain_name)
	{
		eag_log_err("input counter_info is NULL");
		return -1;
	}
	
	/* iptc handle */
	nmp_mutex_lock(&eag_iptables_lock);
	handle = iptc_init(table_name);
	nmp_mutex_unlock(&eag_iptables_lock);
	if (NULL == handle)
	{
		eag_log_err("can't init iptc handle,table name:%s",table_name);
		return -1;
	}

	/* get rules */
	if (EAG_IPTABLES_SOURCE == type)
	{
		for	(p_entry = iptc_first_rule((const char *)chain_name, handle);
			p_entry;
			p_entry = iptc_next_rule(p_entry, handle))
		{
			my_counter = iptc_read_counter(chain_name,index, handle);
			//eag_log_dbg("chain_name=%s,ip_addr=%#X,p_entry->ip.src.s_addr=%#X",chain_name,ip_addr,p_entry->ip.src.s_addr);
			if (ip_addr == p_entry->ip.src.s_addr)
			{				
				//return index;
				goto find;
			}
			index++;
		}
	}
	else if (EAG_IPTABLES_DESTINATION == type)
	{
		for	(p_entry = iptc_first_rule(chain_name, handle);
			p_entry;
			p_entry = iptc_next_rule(p_entry, handle))
		{
			my_counter = iptc_read_counter(chain_name,index, handle);
			//eag_log_dbg("ip_addr=%#X,p_entry->ip.dst.s_addr=%#X",ip_addr,p_entry->ip.dst.s_addr);			
			if (ip_addr == p_entry->ip.dst.s_addr)
			{
				//return index;
				goto find;
			}
			index++;
		}
	}
	
	iptc_free(handle);
	handle = NULL;

	return 0;

find:
	iptc_free(handle);
	handle = NULL;

	return index;
}

/*******************************************************************
 *	add_and_del_entry
 * 
 *	DESCRIPTION:
 *		Add or delete the enty
 *
 *	INPUT:
 *		table_name 	- table name
 *		chain_name 	- chain name
 *		dest_ip		- destination ip address
 *		source_ip		- source ip address
 *		target_name	- target name
 *		type			- the input ip is source or destination
 *	
 *	OUTPUT:
 *		NULL
 *
 *	RETURN:
 *		EAG_ERR_UNKNOWN		- error
 *		EAG_RETURN_OK 		- success
 *
 *********************************************************************/
static int 
add_and_del_entry	(const char *table_name,const char *chain_name,
							const int source_ip,const int dest_ip,
							const char *target_name,const int type)
{
	struct ipt_entry *p_entry = NULL;
	struct ipt_entry_target *p_target  = NULL;
//	struct ipt_entry_match *p_match = NULL;
//	struct ipt_tcp *ptcp = NULL;
	struct iptc_handle *handle = NULL;
	size_t entry_size = 0;
	size_t target_size = 0;
	size_t match_size = 0;
	size_t all_size = 0;
//	int i = 0;
	int return_ret = EAG_RETURN_OK;
	char dest_ip_str[32] = "";
	char source_ip_str[32] = "";

#if USE_THREAD_LOCK	
	eag_log_debug("iptables","add_and_del_entry lock");
	pthread_mutex_lock( &eag_iptables_glock );
#endif
/*use iptables lock*/

	eag_log_debug("iptables","add_and_del_entry lock ");
	nmp_mutex_lock(&eag_iptables_lock);
	
	ip2str( dest_ip, dest_ip_str, sizeof(dest_ip_str) );
	ip2str( source_ip, source_ip_str, sizeof(source_ip_str) );
	
	/* check input */
	if (EAG_IPTABLES_ADD != type && EAG_IPTABLES_DELTE != type)
	{
		eag_log_err("input error,input:%d",type);
		goto return_error;
	}
	if ((0 == dest_ip>>24) && (0 == source_ip>>24))
	{
		eag_log_err("ip range error! dest_ip == %s,source_ip == %s",dest_ip_str,source_ip_str);	
		goto return_error;
	}
	if (NULL == table_name || NULL == chain_name || NULL == target_name)
	{
		eag_log_err("input counter_info is NULL");
		goto return_error;
	}
	
	#if 0//if need NAT,use this
	int is_nat;
	if(!strcmp(table_name,"nat"))
	{
		is_nat = 1;
	}else if(!strcmp(table_name,"filter"))
	{
		is_nat = 0;
	}else
	{
		return 0;
	}
	#endif
	
	handle = iptc_init(table_name);
	if ( NULL == handle)
	{
		eag_log_debug("iptables","can't init iptc handle,table name:%s",table_name);
		goto return_error;
	}

	entry_size = XT_ALIGN(sizeof(struct ipt_entry));

	match_size = 0;
	#if 0//if match port ,use this
	match_size = IPT_ALIGN(sizeof(struct ipt_entry_match)) + IPT_ALIGN(sizeof(struct ipt_tcp));
	#endif
	#if 0//if NAT,use this
	target_size = IPT_ALIGN(sizeof(struct ipt_entry_target));
	if(is_nat)
	{
		target_size += IPT_ALIGN(sizeof(struct ip_nat_multi_range));//nat		
	}else
	{
		target_size += IPT_ALIGN(sizeof(int));
	}
	#endif
	target_size = XT_ALIGN(sizeof(struct ipt_entry_target))+XT_ALIGN(sizeof(int));
	all_size = target_size + match_size + entry_size;

	p_entry = eag_malloc(all_size);
	memset(p_entry, 0, all_size);

	/* Set tha Entry part of the entry */
	/* Set source and destination IP address */
	p_entry->ip.src.s_addr = source_ip;	
	p_entry->ip.dst.s_addr = dest_ip;	
	if (0 == source_ip)
	{
		p_entry->ip.smsk.s_addr = 0x0;
	}
	else
	{
		p_entry->ip.smsk.s_addr = -1;
		//e->ip.smsk.s_addr = 0xffffffff;
	}
	if(0 == dest_ip)
	{
		p_entry->ip.dmsk.s_addr = 0x0;
	}
	else
	{
		p_entry->ip.dmsk.s_addr = -1;
		//e->ip.smsk.s_addr = 0xffffffff;
	}	
	/* Set the interface */
	#if 0
	if(strcmp(interface_name,"0"))
	{
		strcpy (p_entry->ip.iniface,interface_name);
		//for(i=strlen(interface_name);i>-1;i--)
		for(i=0;i<strlen(interface_name)+1;i++)
		{
			p_entry->ip.iniface_mask[i] = 0xff;
		}
	}
	#endif	
	/* Set the portol num(tcp 6,udp 17,icmp 1,IPv6 41,ALL 0) */
	#if 0
	if(!strcmp(portol_name,"tcp"))
	{
		p_entry->ip.proto = 6;
	}else if(!strcmp(portol_name,"udp"))
	{
		p_entry->ip.proto = 17;
	}else if(!strcmp(portol_name,"icmp"))
	{
		p_entry->ip.proto = 1;
	}else if(!strcmp(portol_name,"ipv6"))
	{
		p_entry->ip.proto = 41;
	}else
	{
		p_entry->ip.proto = 0;
	}
	#endif
	/* Set the proto (it's ALL here) */
	p_entry->ip.proto = 0;
	/* Set the size */
	p_entry->target_offset = entry_size + match_size;
	p_entry->next_offset = all_size;

	/* Set the ipt_entry_match part of the entry */
	#if 0//if match port,use it
	//Get address
	p_match = (struct ipt_entry_match*)p_entry->elems;
	p_match->u.user.match_size = match_size;
	//Set the portol name
	//strcpy(p_match->u.user.name,portol_name);
	//Set the Match Data of Match part----------------
	//Get address
	ptcp = (struct ipt_tcp*)p_match->data;
	//Set the port 	(All the port is match)
	ptcp->spts[0]=0;ptcp->spts[1]=0xffff;
	ptcp->dpts[0]=0;ptcp->dpts[1]=0xffff;
	#endif

	/* Set the ipt_entry_target part of the entry */
	/* Get address */
	p_target = (struct ipt_entry_target*)(p_entry->elems+match_size);
	p_target->u.user.target_size = target_size;
	/* Set the target */
	strcpy(p_target->u.user.name,target_name);
	//strcpy(pt->u.user.name,"SNAT");
	#if 0//if NAT
	struct ip_nat_multi_range *p_nat;
	p_nat = (struct ip_nat_multi_range *) p_target->data;
	p_nat->rangesize = 1;// 该nat不做随机的选择 ,>1为多NAT	
	p_nat->range[0].flags = IP_NAT_RANGE_PROTO_SPECIFIED |
		IP_NAT_RANGE_MAP_IPS;	
	p_nat->range[0].min.tcp.port = p_nat->range[0].max.tcp.port = 0;
	p_nat->range[0].min_ip = p_nat->range[0].max_ip = inet_addr("4.4.4.4");
	#endif
	
	/* add or del */
	if (EAG_IPTABLES_ADD == type)
	{
		//iptc_append_entry(chain_name,e,&h);//---append is insert in to the last
		if (!iptc_insert_entry(chain_name,p_entry,0,handle))
		{
			eag_log_err("add iptables error: %d,%s. table==%s,chain==%s,s_ip==%s,"\
						"d_ip==%s,target==%s,handle=%p",
						errno, iptc_strerror(errno), table_name, chain_name,
						source_ip_str, dest_ip_str, target_name, handle);
			goto return_error;
		}
	}
	else if (EAG_IPTABLES_DELTE == type)
	{
		if (!iptc_delete_entry(chain_name,p_entry,NULL,handle))
		{
			eag_log_err("del iptables error: %d,%s table==%s,chain==%s,s_ip==%s,"\
						"d_ip==%s,target==%s,handle=%p",
						errno, iptc_strerror(errno), table_name, chain_name,
						source_ip_str, dest_ip_str, target_name, handle);
			goto return_error;
		}
	}
	
	if (!iptc_commit(handle))
	{
		eag_log_err("commit iptables error: %d,%s.\n table==%s,chain==%s,s_ip==%s,d_ip==%s,target==%s,handle=%p",
						errno, iptc_strerror(errno), table_name, chain_name,
						source_ip_str, dest_ip_str, target_name, handle);
		goto return_error;
	}
//return_success:
	return_ret = EAG_RETURN_OK;
	goto return_line;
	
return_error:
	return_ret = EAG_ERR_UNKNOWN;
	goto return_line;

return_line:
	
	if (NULL != p_entry)
	{
		eag_free(p_entry);
		p_entry = NULL;
	}		
	
	if (NULL != handle)
	{
		iptc_free(handle);
		handle = NULL;
	}
	
	//log_dbg("add_and_del_entry will unlock");
#if USE_THREAD_LOCK	
	pthread_mutex_unlock( &eag_iptables_glock );
	eag_log_debug("iptables","add_and_del_entry unlock");
#endif

/*use iptable unlock*/
	nmp_mutex_unlock(&eag_iptables_lock);
	eag_log_debug("iptables","add_and_del_entry unlock");
	
	return return_ret;
}

#if 0
/*******************************************************************
 *	eap_connect_up
 * 
 *	DESCRIPTION:
 *		Add the ip to the iptables
 *
 *	INPUT:
 *		user_id 		- user captive portal id
 *		user_interface	- interface name
 *		user_ip		- user ip
 *
 *	OUTPUT:
 *		NULL
 *
 *	RETURN:
 *		EAG_ERR_UNKNOWN		- error
 *		EAG_RETURN_OK 		- success
 *
 *********************************************************************/
int 
eap_connect_up(const int user_id, const int hansitype,
		/*const char *user_interface,*/const unsigned int user_ip)
{
	int entry_num = 0;
//	int return_ret = EAG_ERR_UNKNOWN;
	char chain_name[256];
	char chain_name_nat[256];	
	char target_name[256];
	char target_name_nat[256];
	char ip_str[32] = "";

	char *cpid_prefix = NULL;

	if( (user_id<0 || user_id>MAX_CAPTIVE_ID)
		|| (hansitype != 0 && hansitype != 1)
		/*|| (NULL == user_interface || strlen(user_interface)==0)*/
		|| (0 == user_ip>>24) ){
		eag_log_err("eap connect_up error. user_id=%d hansitype=%d   user_ip=%x",
						user_id, hansitype, user_ip );
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	
	cpid_prefix = (HANSI_LOCAL==hansitype)?"L":"R";
	ip2str(user_ip, ip_str, sizeof(ip_str));
	
	
	memset(chain_name,0,sizeof(chain_name));
	memset(chain_name_nat,0,sizeof(chain_name_nat));
	memset(target_name,0,sizeof(target_name));
	memset(target_name_nat,0,sizeof(target_name_nat));
	/*EAP_PRE_AUTH_L1_F   EAP_PRE_AUTH_L1_N */ 
	snprintf(chain_name,sizeof(chain_name),"EAP_PRE_AUTH_%s%d_F",
					cpid_prefix, user_id);
	snprintf(chain_name_nat,sizeof(chain_name_nat),"EAP_PRE_AUTH_%s%d_N",
					cpid_prefix, user_id);
	snprintf(target_name,sizeof(target_name),"FW_FILTER");
	snprintf(target_name_nat,sizeof(target_name_nat),"FW_DNAT");

	/* search if the chain is exist */
	if (EAG_RETURN_OK!= check_is_chain("filter",chain_name) 
		|| EAG_RETURN_OK != check_is_chain("nat",chain_name_nat))
	{
		eag_log_err("eap connect_up error,one or more chain is not exist,chain:%s,%s",
						chain_name,chain_name_nat);
		return EAG_ERR_UNKNOWN;
	}

	/* serch if the entry is exist */
	entry_num = get_index_of_entry("filter",chain_name,user_ip,EAG_IPTABLES_SOURCE);
	if ( entry_num < 0 ){
		eag_log_err("eap connect_up  error. input param might error!");
		return EAG_ERR_UNKNOWN;
	}else if( entry_num > 0 )
	{
		eag_log_err("eap connect_up error,entry is exist in the chain of table "\
					"\"filter\":user_ip==%s,chain_name==%s",ip_str,chain_name);
		return EAG_ERR_UNKNOWN;
	}
	
	/* add the entry */
	if	(EAG_RETURN_OK != add_and_del_entry("filter",chain_name,
							user_ip,0,target_name,EAG_IPTABLES_ADD)
		|| EAG_RETURN_OK !=  add_and_del_entry("filter",chain_name,0,
							user_ip,target_name,EAG_IPTABLES_ADD)
		|| EAG_RETURN_OK !=  add_and_del_entry("nat",chain_name_nat,
							user_ip,0,target_name_nat,EAG_IPTABLES_ADD))
	{
		eag_log_err("eap connect_up error, add entry error");
		return EAG_ERR_UNKNOWN;
	}

	return EAG_RETURN_OK;
}

/*******************************************************************
 *	eap_connect_down
 * 
 *	DESCRIPTION:
 *		Delete the ip from the iptables
 *
 *	INPUT:
 *		user_id 		- user captive portal id
 *		user_interface	- interface name
 *		user_ip		- user ip
 *
 *	OUTPUT:
 *		NULL
 *
 *	RETURN:
 *		EAG_ERR_UNKNOWN		- error
 *		EAG_RETURN_OK 		- success
 *
 *********************************************************************/
int 
eap_connect_down(const int user_id, const int hansitype,
				/*const char *user_interface,*/const unsigned int user_ip)
{
	char chain_name[256];
	char chain_name_nat[256];	
	char target_name[256];
	char target_name_nat[256];
	char ip_str[32] = "";
	
	char *cpid_prefix = NULL;
	cpid_prefix = (HANSI_LOCAL==hansitype)?"L":"R";
	
	ip2str(user_ip, ip_str, sizeof(ip_str));
	
	/* check input */
	if( (user_id<0 || user_id>MAX_CAPTIVE_ID)
		|| (hansitype != 0 && hansitype != 1)
		/*|| (NULL == user_interface || strlen(user_interface)==0)*/
		|| (0 == user_ip>>24) ){
		eag_log_err("eap connect_down error. user_id=%d hansitype=%d   user_ip=%x",
						user_id, hansitype, user_ip );
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	memset(chain_name,0,sizeof(chain_name));
	memset(chain_name_nat,0,sizeof(chain_name_nat));
	memset(target_name,0,sizeof(target_name));
	memset(target_name_nat,0,sizeof(target_name_nat));
	/*EAP_PRE_AUTH_L1_F   EAP_PRE_AUTH_L1_N */ 
	snprintf(chain_name,sizeof(chain_name),"EAP_PRE_AUTH_%s%d_F",
					cpid_prefix, user_id);
	snprintf(chain_name_nat,sizeof(chain_name_nat),"EAP_PRE_AUTH_%s%d_N",
					cpid_prefix, user_id);
	snprintf(target_name,sizeof(target_name),"FW_FILTER");
	snprintf(target_name_nat,sizeof(target_name_nat),"FW_DNAT");

	
	/* search if the chain is exist */
	if (EAG_RETURN_OK != check_is_chain("filter",chain_name)  
		|| EAG_RETURN_OK != check_is_chain("nat",chain_name_nat))
	{
		eag_log_err("eap connect_down error,one or more chain is not exist,chain:%s,%s",chain_name,chain_name_nat);
		return EAG_ERR_UNKNOWN;
	}
	
	/* del the entry */
	if	(EAG_RETURN_OK != add_and_del_entry("filter",chain_name,
								user_ip,0,target_name,EAG_IPTABLES_DELTE)
		|| EAG_RETURN_OK !=  add_and_del_entry("filter",chain_name,0,
								user_ip,target_name,EAG_IPTABLES_DELTE)
		|| EAG_RETURN_OK !=  add_and_del_entry("nat",chain_name_nat,
								user_ip,0,target_name_nat,EAG_IPTABLES_DELTE) )
	{
		eag_log_err("eap connect_down error,delete entry error");
		return EAG_ERR_UNKNOWN;
	}

	return EAG_RETURN_OK;
}
#endif
int
macpre_connect_up(unsigned int user_ip)
{
	int entry_num = 0;
	char chain_name[256] = "";
	char chain_name_nat[256] = "";	
	char target_name[256] = "";
	char target_name_nat[256] = "";
	char ip_str[32] = "";
	//char *cpid_prefix = "";

	
	ip2str(user_ip, ip_str, sizeof(ip_str));
	
	/*MAC_PRE_AUTH_R3_F   MAC_PRE_AUTH_R3_N */
	snprintf(chain_name,sizeof(chain_name),"MAC_PRE_AUTH_F");
	snprintf(chain_name_nat,sizeof(chain_name_nat),"MAC_PRE_AUTH_N");
	snprintf(target_name,sizeof(target_name),"FW_FILTER");
	snprintf(target_name_nat,sizeof(target_name_nat),"FW_DNAT");

	/* search if the chain is exist */
	if (EAG_RETURN_OK!= check_is_chain("filter", chain_name)
		|| EAG_RETURN_OK != check_is_chain("nat", chain_name_nat))
	{
		eag_log_err("macpre_connect_up error, one or more chain is not exist, chain:%s,%s",
			chain_name,chain_name_nat);
		return EAG_ERR_UNKNOWN;
	}

	/* serch if the entry is exist */
	entry_num = get_index_of_entry("filter", chain_name, user_ip, EAG_IPTABLES_SOURCE);
	if (entry_num < 0) {
		eag_log_err("macpre_connect_up error, input param might error!");
		return EAG_ERR_UNKNOWN;
	} else if (entry_num > 0)
	{
		eag_log_err("macpre_connect_up error, entry is exist in the chain of table "
					"\"filter\":user_ip=%s,chain_name=%s",ip_str, chain_name);
		return EAG_ERR_UNKNOWN;
	}

	/* add the entry */
	if	(EAG_RETURN_OK != add_and_del_entry("filter", chain_name,
							user_ip, 0, target_name, EAG_IPTABLES_ADD)
		|| EAG_RETURN_OK !=  add_and_del_entry("filter",chain_name,
							0, user_ip, target_name, EAG_IPTABLES_ADD)
		|| EAG_RETURN_OK !=  add_and_del_entry("nat",chain_name_nat,
							user_ip, 0, target_name_nat, EAG_IPTABLES_ADD))
	{
		eag_log_err("macpre_connect_up error, add entry error");
		return EAG_ERR_UNKNOWN;
	}

	return EAG_RETURN_OK;
}

int
macpre_connect_down(unsigned int user_ip)
{
	char chain_name[256] = "";
	char chain_name_nat[256] = "";
	char target_name[256] = "";
	char target_name_nat[256] = "";
	char ip_str[32] = "";
	//char *cpid_prefix = "";
	
	ip2str(user_ip, ip_str, sizeof(ip_str));
	


	/*MAC_PRE_AUTH_R3_F   MAC_PRE_AUTH_R3_N */
	snprintf(chain_name,sizeof(chain_name),"MAC_PRE_AUTH_F");
	snprintf(chain_name_nat,sizeof(chain_name_nat),"MAC_PRE_AUTH_N");
	snprintf(target_name,sizeof(target_name),"FW_FILTER");
	snprintf(target_name_nat,sizeof(target_name_nat),"FW_DNAT");

	/* search if the chain is exist */
	if (EAG_RETURN_OK != check_is_chain("filter", chain_name)
		|| EAG_RETURN_OK != check_is_chain("nat", chain_name_nat))
	{
		eag_log_err("macpre_connect_down error, one or more chain is not exist, chain:%s,%s",
			chain_name, chain_name_nat);
		return EAG_ERR_UNKNOWN;
	}

	/* del the entry */
	if	(EAG_RETURN_OK != add_and_del_entry("filter", chain_name,
								user_ip, 0, target_name, EAG_IPTABLES_DELTE)
		|| EAG_RETURN_OK != add_and_del_entry("filter", chain_name,
								0, user_ip, target_name, EAG_IPTABLES_DELTE)
		|| EAG_RETURN_OK != add_and_del_entry("nat", chain_name_nat,
								user_ip, 0, target_name_nat, EAG_IPTABLES_DELTE))
	{
		eag_log_err("macpre_connect_down error, delete entry error");
		return EAG_ERR_UNKNOWN;
	}

	return EAG_RETURN_OK;
}

static inline void
set_revision(char *name, u_int8_t revision)
{
	/* Old kernel sources don't have ".revision" field,
	   but we stole a byte from name. */
	name[IPT_FUNCTION_MAXNAMELEN - 2] = '\0';
	name[IPT_FUNCTION_MAXNAMELEN - 1] = revision;
}

int
string_to_number_ll(const char *s, unsigned long long min, unsigned long long max,
		 unsigned long long *ret)
{
	unsigned long long number;
	char *end;

	/* Handle hex, octal, etc. */
	errno = 0;
	number = strtoull(s, &end, 0);
	if (*end == '\0' && end != s) {
		/* we parsed a number, let's see if we want this */
		if (errno != ERANGE && min <= number && (!max || number <= max)) {
			*ret = number;
			return 0;
		}
	}
	return -1;
}

int
string_to_number_l(const char *s, unsigned long min, unsigned long max,
		 unsigned long *ret)
{
	int result;
	unsigned long long number;

	result = string_to_number_ll(s, min, max, &number);
	*ret = (unsigned long)number;

	return result;
}

int 
string_to_number(const char *s, unsigned int min, unsigned int max,
		unsigned int *ret)
{
	int result;
	unsigned long number;

	result = string_to_number_l(s, min, max, &number);
	*ret = (unsigned int)number;

	return result;
}

int
service_to_port(const char *name, const char *proto)
{
	struct servent *service;

	if ((service = getservbyname(name, proto)) != NULL)
		return ntohs((unsigned short) service->s_port);

	return -1;
}


/*static inline void
parse_iprange(unsigned long ipbegin, unsigned long ipend,
				struct ipt_iprange *range)
{
	range->min_ip = ipbegin;
	range->max_ip = ipend;
}
*/
u_int16_t
parse_port(const char *port, const char *proto)
{
	unsigned int portnum;

	if ((string_to_number(port, 0, 65535, &portnum)) != -1 ||
	    (portnum = service_to_port(port, proto)) != -1)
		return (u_int16_t)portnum;

	eag_log_err("invalid port/service `%s' specified", port);
	return 0;
}

static void
parse_multi_ports(const char *portstring, 
		     struct xt_multiport_v1 *multiinfo,
		     const char *proto)
{
	char *buffer, *cp, *next, *range;
	unsigned int i;

	buffer = strdup(portstring);
	if (!buffer) {
		eag_log_err("strdup failed");
		return;
	}

	for (i=0; i<IPT_MULTI_PORTS; i++)
		multiinfo->pflags[i] = 0;
 
	for (cp=buffer, i=0; cp && i<IPT_MULTI_PORTS; cp=next, i++) {
		next=strchr(cp, ',');
 		if (next) *next++ = '\0';
		range = strchr(cp, ':');
		if (range) {
			if (i == IPT_MULTI_PORTS-1) {
				eag_log_err("too many ports specified");
				return;
			}
			*range++ = '\0';
		}
		multiinfo->ports[i] = parse_port(cp, proto);
		if (range) {
			multiinfo->pflags[i] = 1;
			multiinfo->ports[++i] = parse_port(range, proto);
			if (multiinfo->ports[i-1] >= multiinfo->ports[i]) {
				eag_log_err("invalid portrange specified");
				return;
			}
		}
 	}
	multiinfo->count = i;
 	if (cp) {
		eag_log_err("too many ports specified");
 	}
 	free(buffer);
}

static void
parse_algo(const char *s, struct xt_string_info *info)
{
	if (strlen(s) <= XT_STRING_MAX_ALGO_NAME_SIZE) {
		strncpy(info->algo, s, XT_STRING_MAX_ALGO_NAME_SIZE);
		return;
	}
	eag_log_err("ALGO too long `%s'", s);
}

static void
parse_comment(const char *s, struct xt_comment_info *info)
{	
	int slen = strlen(s);

	if (slen >= XT_MAX_COMMENT_LEN) {
		eag_log_err("COMMENT must be shorter than %i characters", XT_MAX_COMMENT_LEN);
		return;
	}
	strcpy((char *)info->comment, s);
}

void
parse_iniface(const char *str, struct ipt_entry *fw)
{
	int i = 0;
	strcpy (fw->ip.iniface, str);
	for(i = 0; i < strlen(str) + 1; i++) {
		fw->ip.iniface_mask[i] = 0xff;
	}
}

void
parse_outiface(const char *str, struct ipt_entry *fw)
{
	int i = 0;
	strcpy (fw->ip.outiface, str);
	for(i = 0; i < strlen(str) + 1; i++) {
		fw->ip.outiface_mask[i] = 0xff;
	}
}
/* Set the portol num(tcp 6, udp 17, icmp 1, IPv6 41, ALL 0) */
u_int16_t
parse_protocol(const char *str)
{
	if (!strcmp(str, "tcp")) {
		return 6;
	}
	if (!strcmp(str, "udp")) {
		return 17;
	}
	if (!strcmp(str, "icmp")) {
		return 1;
	}
	if (!strcmp(str, "IPv6")) {
		return 41;
	}
	return 0;
}

static void
parse_string(const char *str, struct xt_string_info *info)
{	
	if (strlen(str) <= XT_STRING_MAX_PATTERN_SIZE) {
		strncpy(info->pattern, str, XT_STRING_MAX_PATTERN_SIZE);
		info->patlen = strlen(str);
		return;
	}
}

/*static void
parse_bindings(const char *str, struct ipt_set_info *info)
{
	int i = 0;
	char *ptr = NULL;
	char *tmp = NULL;
	char *saved = NULL;

	saved = eag_calloc(1, strlen(str) + 1);
	strncpy(saved, str, strlen(str));
	tmp = saved;
	
	while (i < (EAG_SET_MAX_BINDINGS - 1) && tmp != NULL) {
		ptr = strsep(&tmp, ",");
		if (strncmp(ptr, "src", 3) == 0)
			info->flags[i++] |= EAG_IPSET_SRC;
		else if (strncmp(ptr, "dst", 3) == 0)
			info->flags[i++] |= EAG_IPSET_DST;
		else
			eag_log_err("You must spefify (the comma separated list of) 'src' or 'dst'.");
	}

	if (tmp) {
		eag_log_err("Can't follow bindings deeper than %i.", 
					   EAG_SET_MAX_BINDINGS - 1);
	}
	eag_free(saved);
}*/


static void
string_init(struct xt_entry_match *m, unsigned int *nfcache)
{
	struct xt_string_info *i = (struct xt_string_info *) m->data;

	if (i->to_offset == 0)
		i->to_offset = (u_int16_t) ~0UL;
}

static unsigned char *
iptable_mask(size_t all_size)
{

	unsigned char *mask;
	mask = eag_calloc(1, all_size);
	if (NULL == mask) {
		eag_log_err("calloc error:mask = NULL");
		return NULL;
	}
	memset(mask, 0xFF, all_size);
	return mask;
}

static unsigned char *
string_mask(size_t all_size)
{
	unsigned char *mask, *mptr;
	mask = eag_calloc(1, all_size);
	if (NULL == mask) {
		eag_log_err("calloc error:mask = NULL");
		return NULL;
	}
	memset(mask, 0xFF, XT_ALIGN(sizeof(struct ipt_entry)));
	mptr = mask + XT_ALIGN(sizeof(struct ipt_entry));
	memset(mptr, 0xFF,
		       XT_ALIGN(sizeof(struct xt_entry_match))
		       + offsetof(struct xt_string_info, config));
	mptr += XT_ALIGN(sizeof(struct xt_entry_match))
 	 	+ XT_ALIGN(sizeof(struct xt_string_info));
	memset(mptr, 0xFF,
	       XT_ALIGN(sizeof(struct xt_entry_target))
	       + XT_ALIGN(sizeof(int)));
	return mask;
		
}

struct ipt_entry *
eag_iptable_entry_new(const struct ipt_entry *fw,
		struct list_head *ipt_match_node,
		struct ipt_entry_target *target)
{
	struct ipt_entry *p_entry;
	struct eag_ipt_matches *matchp;
	size_t size = 0;
	int i = 0;
	
	size = XT_ALIGN(sizeof(struct ipt_entry));
	list_for_each_entry(matchp, ipt_match_node, node) {
		size += matchp->match->u.match_size;
	}

	p_entry = eag_malloc(size + target->u.target_size);
	if (NULL == p_entry) {
		eag_log_err("malloc error:p_entry = NULL");
		return p_entry;
	}

	*p_entry = *fw;	
	p_entry->target_offset = size;
	p_entry->next_offset = size + target->u.target_size;
	p_entry->ip.src.s_addr = 0x0;	
	p_entry->ip.dst.s_addr = 0x0;	
	p_entry->ip.smsk.s_addr = 0x0;
	p_entry->ip.dmsk.s_addr = 0x0;
	
	size = 0;
	if (0 == list_empty_careful(ipt_match_node)) {
		list_for_each_entry(matchp, ipt_match_node, node) {
			memcpy(p_entry->elems + size, matchp->match,
				matchp->match->u.match_size);
			size += matchp->match->u.match_size;
			i++;
		}
	}
	eag_log_info( "match count:%d", i);		
	memcpy(p_entry->elems + size, target, target->u.target_size);

	return p_entry;
	
}

/* 使用前分配内存
 * size = IPT_ALIGN(sizeof(struct ipt_entry_match))
 * 	+ IPT_ALIGN(sizeof(struct xt_iprange_mtinfo))
 */
static int
eag_match_iprange(int flag, unsigned long ipbegin, unsigned long ipend, 
		struct ipt_entry_match *match, size_t size)
{
	match = (struct ipt_entry_match *)match;
	match->u.match_size = size;
	strcpy(match->u.user.name, "iprange");
	set_revision(match->u.user.name, 1);

	struct xt_iprange_mtinfo *info = (struct xt_iprange_mtinfo *)match->data;

	switch (flag) {
	case EAG_IPTABLE_SRC:
		info->flags |= IPRANGE_SRC;
		info->src_min.ip = ipbegin;
		info->src_max.ip = ipend;
		eag_log_debug("eag_iptables", "src_iprange:%u-%u, flag:%u",
			info->src_min.ip, info->src_max.ip, info->flags);
		break;
	case EAG_IPTABLE_DST:
		info->flags |= IPRANGE_DST;
		info->dst_min.ip = ipbegin;
		info->dst_max.ip = ipend;
		eag_log_debug("eag_iptables", "dst_iprange:%u-%u, flag:%u",
			info->dst_min.ip, info->dst_max.ip, info->flags);
		break;
	default	:
		return -1;
	}
	return 0;
}

/* 使用前分配内存
 * size = IPT_ALIGN(sizeof(struct ipt_entry_match))
 * 	+ IPT_ALIGN(sizeof(struct ipt_multiport_v1))
 */
static int
eag_match_multiport(int flag, const char *portstring, const char *proto,
		struct xt_entry_match *match, size_t size)
{
	match = (struct ipt_entry_match *)match;
	match->u.match_size = size;
	strcpy(match->u.user.name, "multiport");
	set_revision(match->u.user.name, 1);
	struct xt_multiport_v1 *multiinfo = (struct xt_multiport_v1 *)match->data;

	switch (flag) {
	case EAG_IPTABLE_SRC:
		parse_multi_ports(portstring, multiinfo, proto);
		multiinfo->flags = XT_MULTIPORT_SOURCE;
		eag_log_debug("eag_iptables", "count:%u, flag:%u",
			multiinfo->count, multiinfo->flags);
		break;
	case EAG_IPTABLE_DST:
		parse_multi_ports(portstring, multiinfo, proto);
		multiinfo->flags = XT_MULTIPORT_DESTINATION;
		eag_log_debug("eag_iptables", "count:%u, flag:%u", 
			multiinfo->count, multiinfo->flags);
		break;
	default:
		return 0;
	}
	
	return 0;
}

/* 使用前分配内存
 * size = IPT_ALIGN(sizeof(struct ipt_entry_match))
 * 	+ IPT_ALIGN(sizeof(struct ipt_string_info))
 */
static int
eag_match_string(int flag, const char *str, const char *algo_str, u_int16_t to_offset,
		struct xt_entry_match *match, size_t size)
{
	match = (struct xt_entry_match *)match;
	match->u.match_size = size;
	strcpy(match->u.user.name, "string");
	struct xt_string_info *stringinfo = (struct xt_string_info *)match->data;

	if (flag & EAG_IPTABLE_STRING) {
		parse_string(str, stringinfo);
		stringinfo->patlen=strlen((char *)&stringinfo->pattern);
	}
	if (flag & EAG_IPTABLE_TO) {
		stringinfo->to_offset = to_offset;
	}
	if (flag & EAG_IPTABLE_ALGO) {
		parse_algo(algo_str, stringinfo);
	}
	
	return 0;	
}

/* 使用前分配内存
 * size = IPT_ALIGN(sizeof(struct ipt_entry_match))
 * 	+ IPT_ALIGN(sizeof(struct ipt_comment_info))
 */
static int
eag_match_comment(const char *comment_str,
		struct xt_entry_match *match, size_t size)
{
	match = (struct xt_entry_match *)match;
	match->u.match_size = size;
	strcpy(match->u.user.name, "comment");
	struct xt_comment_info *commentinfo = (struct xt_comment_info *)match->data;

	eag_log_debug("eag_iptables", "comment size:%u, str:%s",
		XT_ALIGN(sizeof(struct xt_comment_info)), comment_str);

	parse_comment(comment_str, commentinfo);

	return 0;
	
}

/* 使用前分配内存
 * size = IPT_ALIGN(sizeof(struct ipt_entry_match))
 * 	+ IPT_ALIGN(sizeof(struct ipt_set_info_match))
 */
static int
eag_match_set(const char *setname, const char *setflag,
		struct xt_entry_match *match, size_t size)
{
	match = (struct xt_entry_match *)match;
	match->u.match_size = size;
	strcpy(match->u.user.name, "set");
	//struct ipt_set_info_match *myinfo = (struct ipt_set_info_match *)match->data;
	//struct ipt_set_info *info = &myinfo->match_set;

	//info->index = eag_get_set_byname(setname);
	//parse_bindings(setflag, info);

	return 0;
	
}

int
eag_iptable_commit(char *table_name, char *chain_name,
//		struct eag_ipt_entries *entries,
		struct list_head *ipt_entry_node,
		int flag)
{
#if USE_THREAD_LOCK	
	eag_log_debug("eag_iptables","eag_iptable_glock lock");
	pthread_mutex_lock( &eag_iptables_glock );
#endif
	/*use iptables lock*/
	eag_log_debug("eag_iptables","iptable_lock lock ");
	nmp_mutex_lock(&eag_iptables_lock);
	
	struct eag_ipt_entries *p_entries = NULL;
	struct iptc_handle *handle = NULL;
	unsigned char *mask = NULL;
	int ret = 0;
	size_t size = 0;
		
	handle = iptc_init(table_name);
	if ( NULL == handle)
	{
		eag_log_warning("can't init iptc handle,table name:%s", table_name);
		goto return_error;
	}
	if (flag == EAG_IPTABLES_ADD) {
		list_for_each_entry(p_entries, ipt_entry_node, node)
		{
			if (!iptc_insert_entry(chain_name, 
				p_entries->entry, 0, handle)) 
			{
				eag_log_err("iptc_insert_entry failed chain_name=%s", chain_name);
				goto return_error;
			}
			eag_log_debug("eag_iptables", "ipt_insert_entry success");
		}
	} else if (flag == EAG_IPTABLES_DELTE) {
		list_for_each_entry(p_entries, ipt_entry_node, node)
		{
			size = p_entries->entry->next_offset;
			mask = iptable_mask(size);
			if (!iptc_delete_entry(chain_name, 
				p_entries->entry, mask, handle)) 
			{
				eag_log_err("iptc_delete_entry failed chain_name=%s", chain_name);
				goto return_error;
			}
			eag_log_debug("eag_iptables", "ipt_delete_entry success");
			free(mask);
			mask = NULL;
		}
		
	}
	eag_log_debug("eag_iptables", "chain:%s, table:%s", chain_name, table_name);

	if (!iptc_commit(handle)) {
		eag_log_warning("commit iptables error,iptc_commit  %s", iptc_strerror(errno));
		goto return_error;
	}
	eag_log_debug("eag_iptables", "iptc_commit success");

	ret = 0;
	goto return_line;
return_error:
	ret = 1;
	goto return_line;
return_line:
	if (NULL != handle) {
		iptc_free(handle);
		handle = NULL;
	}
	if (NULL != mask) {
		eag_free(mask);
		mask = NULL;
	}

#if USE_THREAD_LOCK	
	pthread_mutex_unlock( &eag_iptables_glock );
	eag_log_debug("eag_iptables","eag_iptable_glock unlock");
#endif
	/*use iptable unlock*/
	nmp_mutex_unlock(&eag_iptables_lock);
	eag_log_debug("eag_iptables","iptable_lock unlock");

	return ret;
}


struct ipt_entry *
eag_iprange_entry(int range_flag, char *proto,
		struct white_black_iprange *input_info, char *target_name)
{
	struct ipt_entry fw, *p_entry = NULL;
	//struct eag_ipt_matches *matches = NULL;
	struct list_head ipt_match_node;
	struct eag_ipt_matches *matchp, *tmp;
	struct ipt_entry_target *target = NULL;
	size_t size;

	memset(&fw, 0, sizeof(fw));
	INIT_LIST_HEAD(&ipt_match_node);
		
/* match */
	fw.ip.proto = parse_protocol(proto);
	if (input_info->iniface[0] != '\0') {
		parse_iniface(input_info->iniface, &fw);
		eag_log_debug("eag_iptables", "match:iniface");
	}
	if (strcmp(input_info->portstring, "all")) {
		matchp = eag_calloc(1, sizeof(struct eag_ipt_matches));
		if (NULL == matchp) {
			eag_log_err("calloc error:matchp = NULL");
			goto return_error;
		}
		size = XT_ALIGN(sizeof(struct xt_entry_match))
			+ XT_ALIGN(sizeof(struct xt_multiport_v1));
		matchp->match = eag_calloc(1, size);
		if (NULL == matchp->match) {
			eag_log_err("calloc error:matchp->match = NULL");
			eag_free(matchp);
			goto return_error;
		}
		eag_match_multiport(range_flag, input_info->portstring,
			proto, matchp->match, size);
		eag_log_debug("eag_iptables", "match:multiport, size:%u", size);

		list_add(&(matchp->node), &ipt_match_node);
	}
	if (input_info->comment_str[0] != '\0') {
		matchp = eag_calloc(1, sizeof(struct eag_ipt_matches));
		if (NULL == matchp) {
			eag_log_err("calloc error:matchp = NULL");
			goto return_error;
		}
		size = XT_ALIGN(sizeof(struct xt_entry_match))
 			+ XT_ALIGN(sizeof(struct xt_comment_info));
		matchp->match = eag_calloc(1, size);
		if (NULL == matchp->match) {
			eag_log_err("calloc error:matchp->match = NULL");
			eag_free(matchp);
			goto return_error;
		}
		eag_match_comment(input_info->comment_str, matchp->match, size);
		eag_log_debug("eag_iptables", "match:comment, size:%u", size);

		list_add(&(matchp->node), &ipt_match_node);
	}

	if (input_info->ipend >= input_info->ipbegin) {
		matchp = eag_calloc(1, sizeof(struct eag_ipt_matches));
		if (NULL == matchp) {
			eag_log_err("calloc error:matchp = NULL");
			goto return_error;
		}
		size = XT_ALIGN(sizeof(struct xt_entry_match))
			+ XT_ALIGN(sizeof(struct xt_iprange_mtinfo));
		matchp->match = eag_calloc(1, size);
		if (NULL == matchp->match) {
			eag_log_err("calloc error:matchp->match = NULL");
			eag_free(matchp);
			goto return_error;
		}
		eag_match_iprange(range_flag, input_info->ipbegin, input_info->ipend,
			matchp->match, size);
		eag_log_debug("eag_iptables", "match:iprange, size:%u", size);

		list_add(&(matchp->node), &ipt_match_node);
	} else if (input_info->ipbegin != 0) {
		eag_log_err("input error:ipbegin = %lu and ipend = %lu", 
			input_info->ipbegin, input_info->ipend);
		goto return_error;
	}

/* target */
	size= XT_ALIGN(sizeof(struct ipt_entry_target))+XT_ALIGN(sizeof(int));
	target = eag_calloc(1, size);
	if (NULL == target) {
		eag_log_err("calloc error:target = NULL");
		goto return_error;
	}

	target->u.target_size = size;
	strcpy(target->u.user.name, target_name);
	eag_log_debug("eag_iptables", "target_name:%s, target_size:%u", 
		target->u.user.name, target->u.target_size);
	

/* entry */
	p_entry = eag_iptable_entry_new(&fw, &ipt_match_node, target);
	goto return_line;
	
return_error:
	p_entry = NULL;
	goto return_line;

return_line:
	list_for_each_entry_safe(matchp, tmp, &ipt_match_node, node)
	{
		if (NULL != matchp->match) {
			eag_free(matchp->match);
			matchp->match = NULL;	
		}
		eag_free(matchp);
		matchp = NULL;
	}

	if (NULL != target) {
		eag_free(target);
		target = NULL;
	}
	return p_entry;
}

struct ipt_entry *
eag_add_del_intf_entry(struct eag_intf_entry_info *info)
{
	struct ipt_entry fw, *p_entry = NULL;
	struct list_head ipt_match_node = {0};
	struct eag_ipt_matches *matchp = NULL;
	struct eag_ipt_matches *tmp = NULL;
	struct ipt_entry_target *target = NULL;
	size_t size;

	memset(&fw, 0, sizeof(fw));
	INIT_LIST_HEAD(&ipt_match_node);
		
/* match */
	fw.ip.proto = 0;
	if (info->intf_flag == EAG_INTERFACE_IN && info->intf != NULL) {
		parse_iniface(info->intf, &fw);
		eag_log_info( "match:iniface");
	}
	if (info->intf_flag == EAG_INTERFACE_OUT && info->intf != NULL) {
		parse_outiface(info->intf, &fw);
		eag_log_info("match:outiface");
	}
	
	if (info->setname != NULL && info->setflag != NULL && strcmp(info->setname, "")) {
		matchp = eag_calloc(1, sizeof(struct eag_ipt_matches));
		if (NULL == matchp) {
			eag_log_err("eag_add_del_intf_entry calloc set error");
			goto return_error;
		}
		size = XT_ALIGN(sizeof(struct ipt_entry_match));
		matchp->match = eag_calloc(1, size);
		if (NULL == matchp->match) {
			eag_log_err("eag_add_del_intf_entry calloc set error");
			eag_free(matchp);
			goto return_error;
		}
		eag_log_info( "match:set, name:%s, flag:%s, size:%u", 
					info->setname, info->setflag, size);
		eag_match_set(info->setname, info->setflag, matchp->match, size);
		list_add(&(matchp->node), &ipt_match_node);
	}

/* target */
	size= XT_ALIGN(sizeof(struct ipt_entry_target))+XT_ALIGN(sizeof(int));
	target = eag_calloc(1, size);
	if (NULL == target) {
		eag_log_err("calloc error:target = NULL");
		goto return_error;
	}

	target->u.target_size = size;
	strcpy(target->u.user.name, info->target);
	eag_log_info( "target_name:%s, target_size:%u", 
		target->u.user.name, target->u.target_size);

/* entry */
	p_entry = eag_iptable_entry_new(&fw, &ipt_match_node, target);
	goto return_line;
	
return_error:
	p_entry = NULL;
return_line:
	list_for_each_entry_safe(matchp, tmp, &ipt_match_node, node)
	{
		if (NULL != matchp->match) {
			eag_free(matchp->match);
			matchp->match = NULL;	
		}		
		eag_free(matchp);
		matchp = NULL;
	}

	if (NULL != target) {
		eag_free(target);
		target = NULL;
	}
	return p_entry;
}


int
eag_noport_iprange (struct white_black_iprange *input_info)
{
	struct eag_ipt_entries *p_entries = NULL;
	struct eag_ipt_entries *tmp;
	struct list_head ipt_entry_node;

	if(strcmp(input_info->portstring, "all")) {
		eag_log_err("eag_noport_iprang input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	INIT_LIST_HEAD(&ipt_entry_node);
/* filter */
	p_entries = eag_malloc(sizeof(struct eag_ipt_entries));
	if (NULL == p_entries) {
		eag_log_err("malloc error:p_entry == NULL");
		return EAG_ERR_MALLOC_FAILED;
	}
	p_entries->entry = eag_iprange_entry(EAG_IPTABLE_SRC, "all",
		input_info, input_info->target_name);
       /*    p_entries->entry->ip.src.s_addr = input_info->ipbegin;	
           p_entries->entry->ip.smsk.s_addr = -1;*/
	list_add(&(p_entries->node), &ipt_entry_node);
	
	p_entries = eag_malloc(sizeof(struct eag_ipt_entries));
	if (NULL == p_entries) {
		eag_log_err("malloc error:p_entry == NULL");
		return EAG_ERR_MALLOC_FAILED;
	}
	p_entries->entry = eag_iprange_entry(EAG_IPTABLE_DST, "all", 
		input_info, input_info->target_name);
        /*	p_entries->entry->ip.dst.s_addr = input_info->ipbegin;
	 p_entries->entry->ip.dmsk.s_addr = -1;*/

	list_add(&(p_entries->node), &ipt_entry_node);
        printf("chain: %s,target : %s\n", input_info->chain_name,input_info->target_name);
	eag_iptable_commit("filter", input_info->chain_name,
		&ipt_entry_node, input_info->flag);

	
/* free p_entry */
	if (0 == strcmp(input_info->nat_chain_name, "") 
		|| 0 == strcmp(input_info->nat_target_name, "")) {
		eag_log_debug("eag_iptables", "nat_chain_name or nat_target_name is null");
		goto return_line;
	}

	list_for_each_entry_safe(p_entries, tmp, &ipt_entry_node, node) {
		if (NULL != p_entries->entry) {
			eag_free(p_entries->entry);
			p_entries->entry = NULL;
		}
	}

	
/* nat */
	p_entries = list_entry(p_entries->node.next, struct eag_ipt_entries, node);
	p_entries->entry = eag_iprange_entry(EAG_IPTABLE_DST, "all",
		input_info, input_info->nat_target_name);
	//p_entry = p_entry->next;
           /*p_entries->entry->ip.dst.s_addr = input_info->ipbegin;	
	 p_entries->entry->ip.dmsk.s_addr = -1;*/
	p_entries = list_entry(p_entries->node.next, struct eag_ipt_entries, node);

	p_entries->entry = eag_iprange_entry(EAG_IPTABLE_SRC, "all",
		input_info, input_info->nat_target_name);
         /* p_entries->entry->ip.src.s_addr = input_info->ipbegin;
        	 p_entries->entry->ip.smsk.s_addr = -1;*/


	eag_iptable_commit("nat", input_info->nat_chain_name,
		&ipt_entry_node, input_info->flag);

/* free p_entry */
return_line:
	list_for_each_entry_safe(p_entries, tmp, &ipt_entry_node, node) {
		if (NULL != p_entries->entry) {
			eag_free(p_entries->entry);
			p_entries->entry = NULL;
		}
		eag_free(p_entries);
		p_entries = NULL;
	}


	
	return 0;
}

int 
eag_port_iprange(struct white_black_iprange *input_info)
{
	struct eag_ipt_entries *p_entries = NULL;
	struct eag_ipt_entries *tmp;
	struct list_head ipt_entry_node;
	//struct eag_ipt_entries *entries = NULL;

	INIT_LIST_HEAD(&ipt_entry_node);
/* filter */
	p_entries = eag_malloc(sizeof(struct eag_ipt_entries));
	if (NULL == p_entries) {
		eag_log_err("malloc error:p_entry == NULL");
		return EAG_ERR_MALLOC_FAILED;
	}
	p_entries->entry = eag_iprange_entry(EAG_IPTABLE_SRC, "udp",
		input_info, input_info->target_name);

	list_add(&(p_entries->node), &ipt_entry_node);

	p_entries = eag_malloc(sizeof(struct eag_ipt_entries));
	if (NULL == p_entries) {
		eag_log_err("malloc error:p_entry == NULL");
		return EAG_ERR_MALLOC_FAILED;
	}
	p_entries->entry = eag_iprange_entry(EAG_IPTABLE_DST, "udp", 
		input_info, input_info->target_name);

	list_add(&(p_entries->node), &ipt_entry_node);

	p_entries = eag_malloc(sizeof(struct eag_ipt_entries));
	if (NULL == p_entries) {
		eag_log_err("malloc error:p_entry == NULL");
		return EAG_ERR_MALLOC_FAILED;
	}
	p_entries->entry = eag_iprange_entry(EAG_IPTABLE_SRC, "tcp",
		input_info, input_info->target_name);

	list_add(&(p_entries->node), &ipt_entry_node);

	p_entries = eag_malloc(sizeof(struct eag_ipt_entries));
	if (NULL == p_entries) {
		eag_log_err("malloc error:p_entry == NULL");
		return EAG_ERR_MALLOC_FAILED;
	}
	p_entries->entry = eag_iprange_entry(EAG_IPTABLE_DST, "tcp", 
		input_info, input_info->target_name);

	list_add(&(p_entries->node), &ipt_entry_node);

	eag_iptable_commit("filter", input_info->chain_name,
		&ipt_entry_node, input_info->flag);
/* free p_entry */
	list_for_each_entry_safe(p_entries, tmp, &ipt_entry_node, node)
	{
		if (NULL != p_entries->entry) {
			eag_free(p_entries->entry);
			p_entries->entry = NULL;
		}
	}
	
#if 1
/* nat */
	p_entries = list_entry(p_entries->node.next, struct eag_ipt_entries, node);
	p_entries->entry = eag_iprange_entry(EAG_IPTABLE_DST, "tcp",
		input_info, input_info->nat_target_name);
	p_entries = list_entry(p_entries->node.next, struct eag_ipt_entries, node);

	p_entries->entry = eag_iprange_entry(EAG_IPTABLE_SRC, "tcp",
		input_info, input_info->nat_target_name);
	p_entries = list_entry(p_entries->node.next, struct eag_ipt_entries, node);

	p_entries->entry = eag_iprange_entry(EAG_IPTABLE_DST, "udp",
		input_info, input_info->nat_target_name);
	p_entries = list_entry(p_entries->node.next, struct eag_ipt_entries, node);

	p_entries->entry = eag_iprange_entry(EAG_IPTABLE_SRC, "udp",
		input_info, input_info->nat_target_name);

	eag_iptable_commit("nat", input_info->nat_chain_name,
		&ipt_entry_node, input_info->flag);
#endif
/* free p_entry */
	list_for_each_entry_safe(p_entries, tmp, &ipt_entry_node, node)
	{
		if (NULL != p_entries->entry) {
			eag_free(p_entries->entry);
			p_entries->entry = NULL;
		}
		eag_free(p_entries);
		p_entries = NULL;
	}
	
	return 0;
}

int 
eag_iptable_iprange(struct white_black_iprange *input_info)
{	
	if (strcmp(input_info->portstring, "all")) {
		eag_log_debug("eag_iptables", "***********port*************");
		eag_port_iprange(input_info);
	} else {
		eag_log_debug("eag_iptables", "***********no port***********");
		eag_noport_iprange(input_info);			
	}
	return 0;
}

int
eag_iptable_white_domain(struct white_black_iprange *input_info)
{
	if (input_info->comment_str[0] != '\0') {
		eag_noport_iprange(input_info);	
	} else {
		eag_log_warning("input error");
		return -1;
	}
	return 0;
}

int
eag_iptable_black_domain(struct white_black_iprange *input_info)
{
	if (input_info->comment_str[0] != '\0') {
		eag_noport_iprange(input_info);	
	} else {
		eag_log_warning("input error");
		return -1;
	}
	return 0;
}

int
eag_iptable_add_interface_filter_commit( char *intf, char *setname)
{	
	char cap_filter_default_chain[EAG_IPTABLES_MAXNAMESIZE] = {0};	//CP_FILTER_DEFAULT
	char cap_auth_default_chain[EAG_IPTABLES_MAXNAMESIZE] = {0};	//CP_FILTER_AUTHORIZED_DEFAULT
	char cap_auth_intf_chain[EAG_IPTABLES_MAXNAMESIZE] = {0};	//CP_FILTER_AUTH_IF
	char cap_auth_intf_in_chain[EAG_IPTABLES_MAXNAMESIZE] = {0};	//CP_FILTER_AUTH_IF_IN

	snprintf(cap_filter_default_chain, EAG_IPTABLES_MAXNAMELEN, "CP_F_DEFAULT");
	snprintf(cap_auth_default_chain, EAG_IPTABLES_MAXNAMELEN, "CP_F_AUTH_DEFAULT");
	snprintf(cap_auth_intf_chain, EAG_IPTABLES_MAXNAMELEN, "CP_F_%s", intf);
	snprintf(cap_auth_intf_in_chain, EAG_IPTABLES_MAXNAMELEN, "CP_F_%s_IN", intf);

	struct iptc_handle *handle = NULL;
	struct ipt_entry *entry = NULL;
	struct eag_intf_entry_info intf_info = {0};
	int ret = 0;

#if USE_THREAD_LOCK	
	eag_log_debug("eag_iptables","eag_iptable_glock lock");
	pthread_mutex_lock( &eag_iptables_glock );
#endif
	/*use iptables lock*/
	eag_log_debug("eag_iptables","iptable_lock lock ");
	nmp_mutex_lock(&eag_iptables_lock);
	
	handle = iptc_init("filter");
	if (!handle) {
		eag_log_err("eag_iptable_add_interface_filter_commit iptc_init error:%s", iptc_strerror(errno));
		goto return_line;
	}

/* iptables -N $CP_FILTER_AUTH_IF */
	ret = iptc_create_chain(cap_auth_intf_chain, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_filter_commit iptc_create_chain %s error:%s", 
								cap_auth_intf_chain, iptc_strerror(errno));
		goto return_line;
	}

/* iptables -I $CP_FILTER_AUTH_IF -j RETURN */
	memset(&intf_info, 0, sizeof(struct eag_intf_entry_info));
	intf_info.chain = cap_auth_intf_chain;
	intf_info.target = "RETURN";
	entry = eag_add_del_intf_entry(&intf_info);

	ret = iptc_insert_entry(intf_info.chain, entry,0, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_filter_commit iptc_insert_entry %s error:%s", 
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;

/* iptables -I $CP_FILTER_AUTH_IF -m set --set ${CP_IPHASH_SET} src -j ${CP_FILTER_AUTHORIZED_DEFAULT} */
	/*memset(&intf_info, 0, sizeof(struct eag_intf_entry_info));
	intf_info.chain = cap_auth_intf_chain;
	intf_info.setname = setname;
	intf_info.setflag = "src";
	intf_info.target = cap_auth_default_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	ret = iptc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_filter_commit iptc_insert_entry %s error:%s", 
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;*/

/* iptables -N $CP_FILTER_AUTH_IF_IN */
	ret = iptc_create_chain(cap_auth_intf_in_chain, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_filter_commit iptc_create_chain %s error:%s", 
								cap_auth_intf_in_chain, iptc_strerror(errno));
		goto return_line;
	}

/* iptables -I $CP_FILTER_AUTH_IF_IN -j RETURN */
	memset(&intf_info, 0, sizeof(struct eag_intf_entry_info));
	intf_info.chain = cap_auth_intf_in_chain;
	intf_info.target = "RETURN";
	entry = eag_add_del_intf_entry(&intf_info);

	ret = iptc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_filter_commit iptc_insert_entry %s error:%s",
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;
	
/* iptables -I $CP_FILTER_AUTH_IF_IN -m set --set ${CP_IPHASH_SET} dst -j ${CP_FILTER_AUTHORIZED_DEFAULT}*/
	/*memset(&intf_info, 0, sizeof(struct eag_intf_entry_info));
	intf_info.chain = cap_auth_intf_in_chain;
	intf_info.setname = setname;
	intf_info.setflag = "dst";
	intf_info.target = cap_auth_default_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	ret = iptc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_filter_commit iptc_insert_entry %s error:%s", 
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;*/

/* iptables -I $CP_FILTER -i ${CP_IF} -j ${CP_FILTER_DEFAULT} */
	memset(&intf_info, 0, sizeof(struct eag_intf_entry_info));
	intf_info.chain = CP_FILTER;
	intf_info.intf = intf;
	intf_info.intf_flag = EAG_INTERFACE_IN;
	intf_info.target = cap_filter_default_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	ret = iptc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_filter_commit iptc_insert_entry %s error:%s",
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;

/* iptables -I $CP_FILTER -i ${CP_IF} -j ${CP_FILTER_AUTH_IF} */
	memset(&intf_info, 0, sizeof(struct eag_intf_entry_info));
	intf_info.chain = CP_FILTER;
	intf_info.intf = intf;
	intf_info.intf_flag = EAG_INTERFACE_IN;
	intf_info.target = cap_auth_intf_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	ret = iptc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_filter_commit iptc_insert_entry %s error:%s",
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;
	
/* iptables -I $CP_FILTER -o ${CP_IF} -j ${CP_FILTER_AUTH_IF_IN} */
	memset(&intf_info, 0, sizeof(struct eag_intf_entry_info));
	intf_info.chain = CP_FILTER;
	intf_info.intf = intf;
	intf_info.intf_flag = EAG_INTERFACE_OUT;
	intf_info.target = cap_auth_intf_in_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	ret = iptc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_filter_commit iptc_insert_entry %s error:%s", 
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;

	ret = iptc_commit(handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_filter_commit iptc_commit:%s", iptc_strerror(errno));
	}
	

return_line:
	if (NULL != entry) {
		eag_free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		iptc_free(handle);
		handle = NULL;
	}

#if USE_THREAD_LOCK	
	pthread_mutex_unlock( &eag_iptables_glock );
	eag_log_debug("eag_iptables","eag_iptable_glock unlock");
#endif
	/*use iptable unlock*/
	nmp_mutex_unlock(&eag_iptables_lock);
	eag_log_debug("eag_iptables","iptable_lock unlock");

	return ret;
}

int
eag_iptable_add_interface_nat_commit(char *intf, char *setname)
{
	char cap_nat_default_chain[EAG_IPTABLES_MAXNAMESIZE] = {0};		//CP_NAT_DEFAULT
	char cap_nat_auth_default_chain[EAG_IPTABLES_MAXNAMESIZE] = {0};	//CP_NAT_AUTHORIZED_DEFAULT
	char cap_nat_auth_intf_chain[EAG_IPTABLES_MAXNAMESIZE] = {0};		//CP_NAT_AUTH_IF

	snprintf(cap_nat_default_chain, EAG_IPTABLES_MAXNAMELEN, "CP_N_DEFAULT");
	snprintf(cap_nat_auth_default_chain, EAG_IPTABLES_MAXNAMELEN, "CP_N_AUTH_DEFAULT");
	snprintf(cap_nat_auth_intf_chain, EAG_IPTABLES_MAXNAMELEN, "CP_N_%s",intf);

	struct iptc_handle *handle = NULL;
	struct ipt_entry *entry = NULL;
	struct eag_intf_entry_info intf_info = {0};
	int ret = 0;

#if USE_THREAD_LOCK	
	eag_log_debug("eag_iptables","eag_iptable_glock lock");
	pthread_mutex_lock( &eag_iptables_glock );
#endif
	/*use iptables lock*/
	eag_log_debug("eag_iptables","iptable_lock lock ");
	nmp_mutex_lock(&eag_iptables_lock);
	
	handle = iptc_init("nat");
	if (!handle) {
		eag_log_err("eag_iptable_add_interface_nat_commit iptc_init error:%s", iptc_strerror(errno));
		goto return_line;
	}

/* iptables -t nat -N $CP_NAT_AUTH_IF*/
	/*ret = iptc_create_chain(cap_nat_auth_intf_chain, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_nat_commit iptc_create_chain %s error:%s", 
								cap_nat_auth_intf_chain, iptc_strerror(errno));
		goto return_line;
	}*/

/* iptables -t nat -I $CP_NAT_AUTH_IF -j RETURN */
	/*memset(&intf_info, 0, sizeof(struct eag_intf_entry_info));
	intf_info.chain = cap_nat_auth_intf_chain;
	intf_info.target = "RETURN";
	entry = eag_add_del_intf_entry(&intf_info);

	ret = iptc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_nat_commit iptc_insert_entry %s error:%s",
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;*/
	
/* iptables -t nat -I $CP_NAT_AUTH_IF -m set --set ${CP_IPHASH_SET} src -j ${CP_NAT_AUTHORIZED_DEFAULT} */
	/*memset(&intf_info, 0, sizeof(struct eag_intf_entry_info));
	intf_info.chain = cap_nat_auth_intf_chain;
	intf_info.setname = setname;
	intf_info.setflag = "src";
	intf_info.target = cap_nat_auth_default_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	ret = iptc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_nat_commit iptc_insert_entry %s error:%s", 
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;

/* iptables -t nat -I CP_DNAT -i ${CP_IF} -j $CP_NAT_DEFAULT */
	memset(&intf_info, 0, sizeof(struct eag_intf_entry_info));
	intf_info.chain = CP_DNAT;
	intf_info.intf = intf;
	intf_info.intf_flag = EAG_INTERFACE_IN;
	intf_info.target = cap_nat_default_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	ret = iptc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_nat_commit iptc_insert_entry %s error:%s",
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;

/* iptables -t nat -I CP_DNAT -i ${CP_IF} -j $CP_NAT_AUTH_IF */
	/*memset(&intf_info, 0, sizeof(struct eag_intf_entry_info));
	intf_info.chain = CP_DNAT;
	intf_info.intf = intf;
	intf_info.intf_flag = EAG_INTERFACE_IN;
	intf_info.target = cap_nat_auth_intf_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	ret = iptc_insert_entry(intf_info.chain, entry, 0, handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_nat_commit iptc_insert_entry %s error:%s",
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;*/

	ret = iptc_commit(handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_nat_commit iptc_commit:%s", iptc_strerror(errno));
	}
	
return_line:
	if (NULL != entry) {
		eag_free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		iptc_free(handle);
		handle = NULL;
	}

#if USE_THREAD_LOCK	
	pthread_mutex_unlock( &eag_iptables_glock );
	eag_log_debug("eag_iptables","eag_iptable_glock unlock");
#endif
	/*use iptable unlock*/
	nmp_mutex_unlock(&eag_iptables_lock);
	eag_log_debug("eag_iptables","iptable_lock unlock");

	return ret;
}

int
eag_iptable_add_interface(char *intf)
{
	int ret = 0;
	char cap_iphash_set[EAG_IPTABLES_MAXNAMESIZE] = {0};

	//snprintf(cap_iphash_set, EAG_IPTABLES_MAXNAMELEN, "CP_AUTHORIZED_SET");

	ret = eag_iptable_add_interface_filter_commit(intf, cap_iphash_set);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_filter_commit error:ret=%d", ret);
		return EAG_ERR_UNKNOWN;
	}
	ret = eag_iptable_add_interface_nat_commit(intf, cap_iphash_set);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_nat_commit error:ret=%d", ret);
		return EAG_ERR_UNKNOWN;
	}
	
	return EAG_RETURN_OK;
}

int
eag_iptable_del_interface_filter_commit( char * intf)
{
	char cap_filter_default_chain[EAG_IPTABLES_MAXNAMESIZE] = {0};	//CP_FILTER_DEFAULT
	char cap_auth_intf_chain[EAG_IPTABLES_MAXNAMESIZE] = {0};	//CP_FILTER_AUTH_IF
	char cap_auth_intf_in_chain[EAG_IPTABLES_MAXNAMESIZE] = {0};	//CP_FILTER_AUTH_IF_IN

	snprintf(cap_filter_default_chain, EAG_IPTABLES_MAXNAMELEN, "CP_F_DEFAULT");
	snprintf(cap_auth_intf_chain, EAG_IPTABLES_MAXNAMELEN, "CP_F_%s", intf);
	snprintf(cap_auth_intf_in_chain, EAG_IPTABLES_MAXNAMELEN, "CP_F_%s_IN", intf);

	struct iptc_handle *handle = NULL;
	struct ipt_entry *entry = NULL;
	struct eag_intf_entry_info intf_info = {0};
	unsigned char *mask = NULL;
	int ret = 0;

#if USE_THREAD_LOCK	
	eag_log_debug("eag_iptables","eag_iptable_glock lock");
	pthread_mutex_lock( &eag_iptables_glock );
#endif
	/*use iptables lock*/
	eag_log_debug("eag_iptables","iptable_lock lock ");
	nmp_mutex_lock(&eag_iptables_lock);
	
	handle = iptc_init("filter");
	if (!handle) {
		eag_log_err("eag_iptable_del_interface_filter_commit iptc_init error:%s", iptc_strerror(errno));
		goto return_line;
	}
	
/* iptables -D $CP_FILTER -o ${CP_IF} -j ${CP_FILTER_AUTH_IF_IN} */
	intf_info.chain = CP_FILTER;
	intf_info.intf_flag = EAG_INTERFACE_OUT;
	intf_info.intf = intf;
	intf_info.target = cap_auth_intf_in_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	mask = iptable_mask(entry->next_offset);
	ret = iptc_delete_entry(intf_info.chain, entry, mask, handle);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_filter_commit iptc_delete_entry %s error:%s", 
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;
	eag_free(mask);
	mask = NULL;
	
/* iptables -D $CP_FILTER -i ${CP_IF} -j ${CP_FILTER_AUTH_IF} */
	intf_info.chain = CP_FILTER;
	intf_info.intf_flag= EAG_INTERFACE_IN;
	intf_info.intf = intf;
	intf_info.target = cap_auth_intf_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	mask = iptable_mask(entry->next_offset);
	ret = iptc_delete_entry(intf_info.chain, entry, mask, handle);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_filter_commit iptc_delete_entry %s error:%s", 
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;
	eag_free(mask);
	mask = NULL;
	
/* iptables -D $CP_FILTER -i ${CP_IF} -j ${CP_FILTER_DEFAULT} */
	intf_info.chain = CP_FILTER;
	intf_info.intf_flag = EAG_INTERFACE_IN;
	intf_info.intf = intf;
	intf_info.target = cap_filter_default_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	mask = iptable_mask(entry->next_offset);
	ret = iptc_delete_entry(intf_info.chain, entry, mask, handle);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_filter_commit iptc_delete_entry %s error:%s", 
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;
	eag_free(mask);
	mask = NULL;

/* iptables -F ${CP_FILTER_AUTH_IF} */
	ret = iptc_flush_entries(cap_auth_intf_chain, handle);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_filter_commit iptc_flush_entries %s error:%s", 
								cap_auth_intf_chain, iptc_strerror(errno));
		goto return_line;
	}
	
/* iptables -X ${CP_FILTER_AUTH_IF} */
	ret = iptc_delete_chain(cap_auth_intf_chain, handle);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_filter_commit iptc_delete_chain %s error:%s", 
								cap_auth_intf_chain, iptc_strerror(errno));
		goto return_line;
	}

/* iptables -F ${CP_FILTER_AUTH_IF_IN} */
	ret = iptc_flush_entries(cap_auth_intf_in_chain, handle);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_filter_commit iptc_flush_entries %s error:%s", 
								cap_auth_intf_in_chain, iptc_strerror(errno));
		goto return_line;
	}
	
/* iptables -X ${CP_FILTER_AUTH_IF_IN} */
	ret = iptc_delete_chain(cap_auth_intf_in_chain, handle);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_filter_commit iptc_delete_chain %s error:%s", 
								cap_auth_intf_in_chain, iptc_strerror(errno));
		goto return_line;
	}
	
	ret = iptc_commit(handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_filter_commit iptc_commit:%s", iptc_strerror(errno));
	}
	
return_line:
	if (NULL != entry) {
		eag_free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		iptc_free(handle);
		handle = NULL;
	}
	if (NULL != mask) {
		eag_free(mask);
		mask = NULL;
	}
	
#if USE_THREAD_LOCK	
	pthread_mutex_unlock( &eag_iptables_glock );
	eag_log_debug("eag_iptables","eag_iptable_glock unlock");
#endif
	/*use iptable unlock*/
	nmp_mutex_unlock(&eag_iptables_lock);
	eag_log_debug("eag_iptables","iptable_lock unlock");
	
	return ret;
}

int
eag_iptable_del_interface_nat_commit(char * intf)
{
	char cap_nat_default_chain[EAG_IPTABLES_MAXNAMESIZE] = {0};		//CP_NAT_DEFAULT
	char cap_nat_auth_intf_chain[EAG_IPTABLES_MAXNAMESIZE] = {0};		//CP_NAT_AUTH_IF

	snprintf(cap_nat_default_chain, EAG_IPTABLES_MAXNAMELEN, "CP_N_DEFAULT");
	snprintf(cap_nat_auth_intf_chain, EAG_IPTABLES_MAXNAMELEN, "CP_N_%s", intf);

	struct iptc_handle *handle = NULL;
	struct ipt_entry *entry = NULL;
	struct eag_intf_entry_info intf_info = {0};
	unsigned char *mask = NULL;
	int ret = 0;

#if USE_THREAD_LOCK	
	eag_log_debug("eag_iptables","eag_iptable_glock lock");
	pthread_mutex_lock( &eag_iptables_glock );
#endif
	/*use iptables lock*/
	eag_log_debug("eag_iptables","iptable_lock lock ");
	nmp_mutex_lock(&eag_iptables_lock);
	
	handle = iptc_init("nat");
	if (!handle) {
		eag_log_err("eag_iptable_del_interface_filter_commit iptc_init error:%s", iptc_strerror(errno));
		goto return_line;
	}
	
/* iptables -t nat -D CP_DNAT -i ${CP_IF} -j ${CP_NAT_AUTH_IF} */
	/*intf_info.chain = CP_DNAT;
	intf_info.intf_flag = EAG_INTERFACE_IN;
	intf_info.intf = intf;
	intf_info.target = cap_nat_auth_intf_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	mask = iptable_mask(entry->next_offset);
	ret = iptc_delete_entry(intf_info.chain, entry, mask, handle);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_filter_commit iptc_delete_entry %s error:%s", 
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;
	eag_free(mask);
	mask = NULL;*/

/* iptables -t nat -D CP_DNAT -i ${CP_IF} -j $CP_NAT_DEFAULT */
	intf_info.chain = CP_DNAT;
	intf_info.intf_flag = EAG_INTERFACE_IN;
	intf_info.intf = intf;
	intf_info.target = cap_nat_default_chain;
	entry = eag_add_del_intf_entry(&intf_info);
	mask = iptable_mask(entry->next_offset);
	ret = iptc_delete_entry(intf_info.chain, entry, mask, handle);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_nat_commit iptc_delete_entry %s error:%s", 
								intf_info.chain, iptc_strerror(errno));
		goto return_line;
	}
	eag_free(entry);
	entry = NULL;
	eag_free(mask);
	mask = NULL;

/* iptables -t nat -F ${CP_NAT_AUTH_IF} */
	/*ret = iptc_flush_entries(cap_nat_auth_intf_chain, handle);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_filter_commit iptc_flush_entries %s error:%s", 
								cap_nat_auth_intf_chain, iptc_strerror(errno));
		goto return_line;
	}*/

/* iptables -t nat -X ${CP_NAT_AUTH_IF} */
	/*ret = iptc_delete_chain(cap_nat_auth_intf_chain, handle);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_filter_commit iptc_delete_chain %s error:%s", 
								cap_nat_auth_intf_chain, iptc_strerror(errno));
		goto return_line;
	}*/

	ret = iptc_commit(handle);
	if (!ret) {
		eag_log_err("eag_iptable_add_interface_nat_commit iptc_commit:%s", iptc_strerror(errno));
	}
	
return_line:
	if (NULL != entry) {
		eag_free(entry);
		entry = NULL;
	}
	if (NULL != handle) {
		iptc_free(handle);
		handle = NULL;
	}
	if (NULL != mask) {
		eag_free(mask);
		mask = NULL;
	}
	
#if USE_THREAD_LOCK	
	pthread_mutex_unlock( &eag_iptables_glock );
	eag_log_debug("eag_iptables","eag_iptable_glock unlock");
#endif
	/*use iptable unlock*/
	nmp_mutex_unlock(&eag_iptables_lock);
	eag_log_debug("eag_iptables","iptable_lock unlock");
	
	return ret;
}



int
eag_iptable_del_interface(char *intf)
{
	int ret = 0;

	ret = eag_iptable_del_interface_filter_commit( intf);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_filter_commit error:ret=%d", ret);
		return EAG_ERR_UNKNOWN;
	}
	ret = eag_iptable_del_interface_nat_commit( intf);
	if (!ret) {
		eag_log_err("eag_iptable_del_interface_nat_commit error:ret=%d", ret);
		return EAG_ERR_UNKNOWN;
	}
	
	return EAG_RETURN_OK;
}

#if 0
int
eag_iptable_black_domain(char *chain_name,
		char *iniface, char *str, int flag)
{
	struct iptc_handle *handle = NULL;
	struct ipt_entry *p_entry = NULL;
	struct ipt_entry_match *p_match = NULL;
	struct ipt_entry_target *p_target = NULL;
	unsigned char *mask = NULL;
	size_t entry_size = 0;
	size_t match_size = 0;
	size_t target_size = 0;
	size_t all_size = 0;
	int ret;
	int string_flag = EAG_IPTABLE_ALGO ^ EAG_IPTABLE_TO ^ EAG_IPTABLE_STRING;

	entry_size = IPT_ALIGN(sizeof(struct ipt_entry));
	match_size = IPT_ALIGN(sizeof(struct ipt_entry_match))
 	 	+ IPT_ALIGN(sizeof(struct ipt_string_info));
	target_size = IPT_ALIGN(sizeof(struct ipt_entry_target))
		+ IPT_ALIGN(sizeof(int));
	all_size = entry_size + match_size + target_size;
/* p_entry */
	p_entry = eag_malloc(all_size);
	if (NULL == p_entry) {
		eag_log_err("malloc error:p_entry = NULL");
		goto return_error;
	}
	memset(p_entry, 0, all_size);
	p_entry->ip.proto = 0;
	if (iniface[0] != '\0') {
		parse_iniface(iniface, p_entry);
		eag_log_debug("eag_iptables", "iniface:%s, mask:%s", 
			p_entry->ip.iniface, p_entry->ip.iniface_mask);
	}
	p_entry->target_offset = entry_size + match_size;
	p_entry->next_offset = all_size;
	p_entry->ip.src.s_addr = 0x0;	
	p_entry->ip.dst.s_addr = 0x0;	
	p_entry->ip.smsk.s_addr = 0x0;
	p_entry->ip.dmsk.s_addr = 0x0;
/* match */	
	p_match  = (struct ipt_entry_match *)p_entry->elems;
	string_init(p_match, &(p_entry->nfcache));
	eag_match_string(string_flag, str, "bm", 65535, p_match, match_size);
	eag_log_debug("eag_iptables", "name:%s, size:%u",
		p_match->u.user.name, p_match->u.match_size);
	struct ipt_string_info *stringinfo = (struct ipt_string_info *)p_match->data;
	eag_log_debug("eag_iptables", "to_offset:%u, algo:%s, string:%s, len:%u", 
		stringinfo->to_offset, stringinfo->algo, stringinfo->pattern, stringinfo->patlen);
	
/* target */
	p_target = (struct ipt_entry_target *)(p_entry->elems + match_size);
	p_target->u.target_size = target_size;
	strcpy(p_target->u.user.name, "DROP");	
/* commit */
#if USE_THREAD_LOCK	
	eag_log_debug("eag_iptables","black_domain lock");
	pthread_mutex_lock( &eag_iptables_glock );
#endif
	/*use iptables lock*/
	eag_log_debug("eag_iptables","black_domain lock ");
	nmp_mutex_lock(&eag_iptables_lock);
	
	handle = iptc_init("filter");
	if ( NULL == handle)
	{
		eag_log_warning("can't init iptc handle,table name:filter");
		goto return_error;
	}
	if (flag == EAG_IPTABLES_ADD) {
		if (!iptc_insert_entry(chain_name, p_entry, 0, handle)) {
			eag_log_err("iptc_insert_entry");
			goto return_error;
		}
	} else if (flag == EAG_IPTABLES_DELTE) {
		mask = string_mask(all_size);
		if (!iptc_delete_entry(chain_name, p_entry, mask, handle)) {
			eag_log_err("iptc_delete_entry");
			goto return_error;
		}
	}
	if (!iptc_commit(handle)) {
		eag_log_warning("black_domain commit iptables error");
		goto return_error;
	}
	eag_log_debug("eag_iptables", "iptc_commit success");
	ret = 0;
	goto return_line;
return_error:
	ret = -1;
	goto return_line;
return_line:
	if (NULL != p_entry) {
		free(p_entry);
		p_entry = NULL;
	}
	if (NULL != handle) {
		iptc_free(handle);
		handle = NULL;
	}
	if (NULL != mask) {
		free(mask);
		mask = NULL;
	}

#if USE_THREAD_LOCK	
	pthread_mutex_unlock( &eag_iptables_glock );
	eag_log_debug("eag_iptables","black_domain unlock");
#endif
	/*use iptable unlock*/
	nmp_mutex_unlock(&eag_iptables_lock);
	eag_log_debug("eag_iptables","black_domain unlock");
	return ret;
}
#endif
#if 0
#include <arpa/inet.h>

void parse_ip(const char *str, unsigned long *ip)
{
	struct in_addr addr;
	
	if (inet_aton(str, &addr) != 0) {
		*ip = ntohl(addr.s_addr);
		return;
	}
	eag_log_err("network '%s' not found", str);
}
int main(int argc, char *argv[])
{
	mtrace();

	struct white_black_iprange input_info;
	unsigned long ipbegin, ipend;
	parse_ip("15.16.32.0", &ipbegin);
	parse_ip("15.16.32.90", &ipend);

	memset(&input_info, 0, sizeof(struct white_black_iprange));

	strcpy(input_info.chain_name, argv[1]);
	strcpy(input_info.target_name, argv[2]);
	strcpy(input_info.nat_target_name, "FW_DNAT");

	input_info.ipbegin = ipbegin;
	input_info.ipend = ipend;
	if (!strcmp(argv[4], "add")) {
		input_info.flag = EAG_IPTABLES_ADD;
	} else {
		input_info.flag = EAG_IPTABLES_DELTE;
	}
	strcpy(input_info.portstring, argv[3]);
	strcpy(input_info.nat_chain_name, argv[1]);
	eag_iptable_iprange(&input_info);
	strcpy(input_info.comment_str, "www.123.com");
	eag_iptable_white_domain(&input_info);

	eag_iptable_black_domain(input_info.chain_name, 
		input_info.iniface, "www.169.com", input_info.flag);

	return 0;
}
#endif
/**************************************************************************************/

/*******************************************************************
 *	flush_all_appconn_flux
 * 
 *	DESCRIPTION:
 *		flush all appconn flux
 *
 *	INPUT:
 *		time_interval 	- time interval
 *	
 *	OUTPUT:
 *		flux of appconn
 *
 *	RETURN:
 *		EAG_RETURN_CODE_NOT_TIME_YET	- not time yet
 *		EAG_ERR_UNKNOWN			- error
 *		EAG_RETURN_OK 			- success
 *
 *********************************************************************/
#if 0
int flush_all_appconn_flux (int time_interval)
{
	static int last_time = 0;
	int time_now = time(0);
	//log_dbg("flush_all_appconn_flux time now=%d,last_time=%d,time_interval=%d",time_now,last_time,time_interval);
	if( time_now - last_time < time_interval)
	{	
		log_dbg("flush_all_appconn_flux not time yet.time gap=%d < time interval=%d",time_now - last_time , time_interval);
		return EAG_RETURN_CODE_NOT_TIME_YET;
	}
	last_time = time_now;
		
	struct iptc_handle *h;//iptc handle
	const char table_name[] = "filter";//table
	const char *chain_name = NULL;//chain
	const struct ipt_entry *p_entry = NULL;//struct of ipt_entry
	struct ipt_counters *my_counter = NULL;//ipt_counters defined in ip_tables.h
	
	h = iptc_init(table_name);
	if (!h)
	{
		eag_log_err("ERROR!flush_all_appconn_flux can't init iptc handle,table name:%s\n",table_name);
		return EAG_ERR_UNKNOWN;
	}

	int chain_name_cpid = -1, sscanf_ret = -1;
	char chain_name_ifname [64];//interface name	
	char chain_name_in [4];//the last "IN"
	
	unsigned int rule_num = 0;//rule num
	for (chain_name = iptc_first_chain(&h); chain_name; chain_name = iptc_next_chain(&h))
	{
		/* check chain_name , such as CP_0_GP_F_AUTH_eth0-4_IN is correct */
		chain_name_cpid = -1;
		memset(chain_name_ifname, 0, sizeof(chain_name_ifname));
		memset(chain_name_in, 0, sizeof(chain_name_in));
		sscanf_ret = sscanf(chain_name,"CP_%d_GP_F_AUTH_%63[^_]_%3s", &chain_name_cpid, chain_name_ifname, chain_name_in);
		//log_dbg("flush_all_appconn_flux chain_name=%s, sscanf_ret=%d,cpid=%d,interface_name=%s,chain_name_in=%s",
		//							chain_name,sscanf_ret,chain_name_cpid,chain_name_ifname,chain_name_in);
		if (sscanf_ret == 3)/* ret=3 means has "IN" in the last chain,this is the downflux chain */
		{
			if (chain_name_cpid < 0
				|| chain_name_cpid > MAX_CAPTIVE_ID
				|| strlen(chain_name_ifname) == 0 
				|| strcmp(chain_name_in,"IN") != 0)
			{
				//log_dbg("chain_name is illage,continue");
				continue;
			}
			//log_dbg("chain_name is correct");
			/* reset rule num */
			rule_num=0;
			
			/* get entry */
			for (p_entry = iptc_first_rule(chain_name, &h); 
				 p_entry; 
				 p_entry = iptc_next_rule(p_entry, &h))
			{
				rule_num++;//rule start at 1 !!!  
				//log_dbg("rule_num=%d,dip=%#X,sip=%#X",rule_num,p_entry->ip.dst.s_addr,p_entry->ip.src.s_addr);
				if (p_entry->ip.dst.s_addr == 0)
				{
 					//log_dbg("ip==0,continue");
					continue;
				}
				my_counter = iptc_read_counter(chain_name,rule_num, &h);
				//log_dbg("p_entry->ip.src.s_addr=%#X",p_entry->ip.src.s_addr);
				set_flux_of_appconn_by_ip(p_entry->ip.dst.s_addr, FLAG_SET_IN_FLUX_OF_APPCONN_BY_IP,
												my_counter->bcnt, my_counter->pcnt);						  
			}//for rule
		}
		else if(sscanf_ret == 2)/* ret=2 means doesn't have "IN" in the last chain,this is the upflux chain */
		{
			if (chain_name_cpid < 0
				|| chain_name_cpid > MAX_CAPTIVE_ID
				|| strlen(chain_name_ifname) == 0 )
			{
				//log_dbg("chain_name is illage,continue");
				continue;
			}
			
			/* reset rule num */
			rule_num=0;
			
			/* get entry */
			for (p_entry = iptc_first_rule(chain_name, &h);
			     p_entry;
				 p_entry = iptc_next_rule(p_entry, &h))
			{
				rule_num++;//rule start at 1 !!!				
				if (p_entry->ip.src.s_addr == 0)
				{
 					continue;
				}
				my_counter = iptc_read_counter(chain_name,rule_num, &h);
				set_flux_of_appconn_by_ip(p_entry->ip.src.s_addr, FLAG_SET_OUT_FLUX_OF_APPCONN_BY_IP,
												my_counter->bcnt, my_counter->pcnt);	
			}//for rule
		}
	}//for chain

	if(h)iptc_free(&h);
	//log_dbg("end of flux");
	return EAG_RETURN_OK;
}
#endif
#ifdef __cplusplus
}
#endif

