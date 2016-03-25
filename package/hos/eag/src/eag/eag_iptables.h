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
*	RCSfile   :  eag_iptables.h
*
*	Author   :  wangke
*
*	Revision :  1.00
*
*	Date      :  2010-1-5
********************************************************************************/
#ifndef _EAG_IPTABLES_H
#define _EAG_IPTABLES_H

/*********************************************************
*	head files														*
**********************************************************/

/*********************************************************
*	macro define													*
**********************************************************/
#define EAG_IPTABLES_SOURCE 						1
#define EAG_IPTABLES_DESTINATION 				2
#define EAG_IPTABLES_SOURCE_AND_DESTINATION 	3
#define EAG_IPTABLES_ADD							4
#define EAG_IPTABLES_DELTE				 		5

#define FLUSH_ALL_APPCONN_FLUX_TIME_INTERVAL_FOR_USER_MANAGE 5 /* flush all appcon flux time interval for user mamage,but the usemanage is in the fork...*/
#define FLUSH_ALL_APPCONN_FLUX_TIME_INTERVAL_FOR_RADIUS_IDLETIME 60 /* flush all appcon flux time interval for check radius idletime*/
#define FLUSH_ALL_APPCONN_FLUX_TIME_INTERVAL_FOR_RADIUS_PACK 60 /* flush all appcon flux time interval for radius pack */

#define FLAG_SET_OUT_FLUX_OF_APPCONN_BY_IP 1
#define FLAG_SET_IN_FLUX_OF_APPCONN_BY_IP 2

#define EAG_IPTABLES_MAXNAMELEN		30
#define EAG_IPTABLES_MAXNAMESIZE	32

#define EAG_INTERFACE_IN	1
#define EAG_INTERFACE_OUT	2

/*********************************************************
*	struct define													*
**********************************************************/
typedef struct _struct_ip_data_counter_
{
	char ip_addr[17];
	unsigned long long data_counter;
	struct _struct_ip_data_counter_ * next;
}ip_data_counter;

typedef struct _struct_ip_counter_info_
{
	unsigned int ip_addr;
	unsigned long long source_pkt;
	unsigned long long source_byte;               
	unsigned long long destination_pkt;
	unsigned long long destination_byte;
}ip_counter_info;

struct white_black_iprange {
	char chain_name[EAG_IPTABLES_MAXNAMESIZE];
	char nat_chain_name[EAG_IPTABLES_MAXNAMESIZE];
	char iniface[MAX_IF_NAME_LEN];
	unsigned long tag;
	char portstring[64]; 
	char target_name[EAG_IPTABLES_MAXNAMESIZE];
	char nat_target_name[EAG_IPTABLES_MAXNAMESIZE];
	char comment_str[256];
	unsigned long ipbegin;
	unsigned long ipend;
	int flag;
};

struct eag_intf_entry_info {
	char *chain;
	char *intf;
	char *setname;
	char *setflag;
	char *target;
	int intf_flag;
};
/********************************************************************
*	function declare															 *
********************************************************************/

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
 *		EAG_RETURN_CODE_ERROR	- get the counter failed
 *		EAG_RETURN_CODE_OK 	- get the counter successfully
 *
 *********************************************************************/
int 
get_ip_counter_info (unsigned int ip_addr,ip_counter_info * the_info);

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
 *		EAG_RETURN_CODE_ERROR		- error
 *		EAG_RETURN_CODE_OK 		- success
 *
 *********************************************************************/
int 
connect_up(const char *user_interface,const unsigned int user_ip);


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
 *		EAG_RETURN_CODE_ERROR		- error
 *		EAG_RETURN_CODE_OK 		- success
 *
 *********************************************************************/
int 
connect_down(const char *user_interface,const unsigned int user_ip);

int 
eag_iptable_iprange(struct white_black_iprange *input_info);

int
eag_iptable_white_domain(struct white_black_iprange *input_info);

int
eag_iptable_black_domain(struct white_black_iprange *input_info);

int
eag_iptable_add_interface(char *intf);

int
eag_iptable_del_interface(char *intf);


#if 0
int
eag_iptable_black_domain(char *chain_name, char *iniface, char *str, int flag);
#endif
#if 0
int 
eap_connect_up(const int user_id, const int hansitype,
		/*const char *user_interface,*/const unsigned int user_ip);

/*delete rule for authorize eap user*/
int 
eap_connect_down(const int user_id, const int hansitype,
				/*const char *user_interface,*/const unsigned int user_ip);
#endif
int
macpre_connect_up(unsigned int user_ip);

int
macpre_connect_down(unsigned int user_ip);

#if 0

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
 *		EAG_RETURN_CODE_ERROR		- error
 *		EAG_RETURN_CODE_OK 		- success
 *
 *********************************************************************/						
int add_and_del_entry	(const char *table_name,const char *chain_name,
							const int dest_ip,const int source_ip,
							const char *target_name,const int type);


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
 *		EAG_RETURN_CODE_ERROR	- error or not chain
 *		EAG_RETURN_CODE_OK 	- is chain
 *
 *********************************************************************/
int check_is_chain(const char * table_name,const char * chain_name);


/*******************************************************************
 *	get_num_of_entry
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
 *		EAG_RETURN_CODE_ERROR		- error
 *		EAG_RETURN_CODE_NOT_FOUND - not exist
 *		EAG_RETURN_CODE_OK 		- success ,entry is exist
 *
 *********************************************************************/
int get_num_of_entry(	const char *table_name, const char * chain_name,
							unsigned int ip_addr, const int type, int * num_of_entry);



#endif
#endif

