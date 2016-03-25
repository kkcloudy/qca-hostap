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
* portal_ha.c
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

/* eag_log.c */
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
//#include <dbus/dbus.h>
#include "nm_list.h"
#include "eag_log.h"
#include "eag_errcode.h"
#include "eag_blkmem.h"
//#include "eag_conf.h"

#define EAG_AUTELAN_LOG		0
#define EAG_HENAN_LOG		1
int autelan_log_switch = 1;		/* 0 is close, 1 is open */
int henan_log_switch = 0;		/* 0 is close, 1 is open */
int user_log_switch = 0;		/* 0 is close, 1 is open */
int log_forward = 1;
unsigned int eag_log_level = 0xFF;		/* all */
unsigned int eag_daemon_log_open = EAG_DAEMON_LOG_CLOSE;   /* close */
char STR_EAG[32] = {0}; 				/* syslog string eag	*/

#define EAG_LOG_BLEMEM_MAX_ITEM_NUM		64
#define EAG_LOG_BLEMEM_MAX_NUM			16

#define MAX_FILTER_LEN	120

struct LogFilterItem {
	struct list_head node;
	char filter[MAX_FILTER_LEN];
};

struct list_head filter_head = LIST_HEAD_INIT(filter_head);
static eag_blk_mem_t *filter_blkmem = NULL;

const char *
safe_strerror(int errnum)
{
	const char *s = strerror(errnum);
	return (s != NULL) ? s : "Unknown error";
}

#if 0
int
eag_log_init(int hansitype, int insid)
#else
int
eag_log_init( char *daemon )
#endif
{
	
	int iret = 0;
	if( NULL == daemon ){
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	static char prefix[32];/*it must be static. because openlog not copy the str but save the pointer!!!*/
	strncpy( prefix, daemon, sizeof(prefix)-1 );
	
	eag_log_get_openlog_name(daemon);/* the name will be used for openlog func next time!!!*/
	if (EAG_DAEMON_LOG_OPEN != eag_daemon_log_open) {
		openlog(prefix, LOG_ODELAY, LOG_DAEMON);
		setlogmask(LOG_AT_LEAST_DEBUG);
		iret = eag_blkmem_create(&filter_blkmem,
					 "eag_log_filter_blkmem",
					 sizeof (struct LogFilterItem),
					 EAG_LOG_BLEMEM_MAX_ITEM_NUM,
					 EAG_LOG_BLEMEM_MAX_NUM);
		if (EAG_RETURN_OK != iret) {
			syslog(LOG_ERR,
			       "eag_log_init create eag_log_filter_blkmem failed case %s",
			       eag_errcode_content(iret));
			return EAG_LOG_ERR_INIT_BLKMEM_FAILED;
		}
		eag_daemon_log_open = EAG_DAEMON_LOG_OPEN;
	}
	syslog(LOG_INFO, "%s log inited!", daemon);

	return EAG_RETURN_OK;
}

int
eag_log_uninit()
{
	struct LogFilterItem *pos = NULL;
	struct LogFilterItem *n = NULL;
	log_forward = 0;
	eag_daemon_log_open = EAG_DAEMON_LOG_CLOSE;
	/*release list */
	list_for_each_entry_safe(pos, n, &filter_head, node) {
		list_del(&(pos->node));
		eag_blkmem_free_item(filter_blkmem, pos);
	}

	/*release filter_blkmem */
	eag_blkmem_destroy(&filter_blkmem);

	return EAG_RETURN_OK;
}

void
eag_log_set_level(int level)
{
	setlogmask(level);
	return;
}

static int
eag_log_add_filter_single(char *filter)
{
	int iret = EAG_ERR_UNKNOWN;

	struct LogFilterItem *pfilteritem = NULL;
	struct LogFilterItem *pos = NULL;

	if (NULL == filter || strlen(filter)==0) {
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if (strlen(filter) > sizeof (pfilteritem->filter) - 1) {
		return EAG_LOG_ERR_ADD_FILTER_OVER_LENGTH;
	}
	/*find the same filter */
	list_for_each_entry(pos, &filter_head, node) {
		int cmp = strcmp(filter, pos->filter);
		if (0 == cmp) {
			return EAG_LOG_ERR_ADD_FILTER_ALREADY_HAVE;
		}
		if ( cmp < 0 ){
			break;
		}
	}

	pfilteritem = eag_blkmem_malloc_item(filter_blkmem);
	if (NULL != pfilteritem) {
		memset(pfilteritem, 0, sizeof (struct LogFilterItem));
		if( NULL == pos ){
			list_add_tail(&(pfilteritem->node), &filter_head);
		}else{
			list_add(&(pfilteritem->node), &(pos->node));/*add to first! the filter is be sorted!*/
		}
		strncpy(pfilteritem->filter, filter,
				sizeof (pfilteritem->filter) - 1);
		iret = EAG_RETURN_OK;
	} else {
		iret = EAG_LOG_ERR_ADD_FILTER_BLK_MALLOC_FAILED;
	}

	return iret;
}

int
eag_log_add_filter(char *filter_mult)
{				/*返回成功添加的filter的个数 */
	char *filter = NULL;
	int num = 0;
	int iret_temp = EAG_ERR_UNKNOWN;
	char *filter_mult_temp;

	if (NULL == filter_mult) {
		return 0;
	}

	filter_mult_temp = strdup(filter_mult);
	if (NULL == filter_mult_temp) {
		return 0;
	}

	for (filter = strtok(filter_mult_temp, ":");
	     NULL != filter; filter = strtok(NULL, ":")) {
		iret_temp = eag_log_add_filter_single(filter);
		if (EAG_RETURN_OK == iret_temp) {
			num++;
		}
	}

	free(filter_mult_temp);

	return num;
}

static int
eag_log_del_filter_single(char *filter)
{
	struct LogFilterItem *pos, *n;
	int iret = EAG_LOG_ERR_FILER_NOT_FIND;

	list_for_each_entry_safe(pos, n, &filter_head, node) {
		if (0 == strcmp(filter, pos->filter)) {
			list_del(&(pos->node));
			iret = eag_blkmem_free_item(filter_blkmem, pos);
			break;
		}
	}

	return iret;
}

int
eag_log_del_filter(char *filter_mult)
{
	char *filter = NULL;
	int num = 0;
	int iret = EAG_ERR_UNKNOWN;

	char *filter_mult_temp = NULL;

	if (NULL == filter_mult) {
		return 0;
	}

	filter_mult_temp = strdup(filter_mult);
	if (NULL == filter_mult_temp) {
		return 0;
	}

	for (filter = strtok(filter_mult_temp, ":");
	     NULL != filter; filter = strtok(NULL, ":")) {
		iret = eag_log_del_filter_single(filter);
		if (EAG_RETURN_OK == iret) {
			num++;
		}

	}
	free(filter_mult_temp);
	filter_mult_temp = NULL;
	
	return num;
}

static int
eag_log_if_match(const char *match, const char *filter)
{				/*when filter is substr of match */
	char *pmatch = NULL;
	unsigned int filter_len = 0;

	filter_len = strlen(filter);
	pmatch = strstr(match, filter);
	
	if (NULL == pmatch) {
		return EAG_FALSE;
	}

	if (':' == pmatch[filter_len] || '\0' == pmatch[filter_len]) {
//		printf("eag_log_if_match match=%s  filter=%s\n",match,filter);
//		printf("eag_log_if_match EAG_TRUE\n");
		return EAG_TRUE;
	}
	return EAG_FALSE;
}

int
eag_log_is_filter_register(const char *match)
{
	
	struct LogFilterItem *pos;
	int iret = EAG_FALSE;

	list_for_each_entry(pos, &filter_head, node) {
		iret = eag_log_if_match(match, pos->filter);
		if (EAG_TRUE == iret) {
			break;
		}
	}

	return iret;
}

int
eag_set_user_log(int status)
{
	if (1 != status && 0 != status) {
		return EAG_LOG_ERR_ALREADY_SET;
	}

	user_log_switch = status;

	return EAG_RETURN_OK;
}

int
eag_set_log_format(int key, int status)
{	
	if (1 != status && 0 != status) {
		return EAG_LOG_ERR_ALREADY_SET;
	}

	if (EAG_AUTELAN_LOG == key) {
		autelan_log_switch = status;
	} else if (EAG_HENAN_LOG == key) {
		henan_log_switch = status;
	} else {
		return EAG_LOG_ERR_ALREADY_SET;
	}

	return EAG_RETURN_OK;
}

int 
eag_log_set_debug_value(unsigned int val_mask)
{	
	if (eag_log_level & val_mask) {
		return EAG_LOG_ERR_ALREADY_SET;
	}
	
	eag_log_level |= val_mask;

	return EAG_RETURN_OK;
}

int 
eag_log_set_no_debug_value(unsigned int val_mask)
{	
	if (eag_log_level & val_mask) {
		eag_log_level &= ~val_mask;
		return EAG_RETURN_OK;
	}
	else 
		return EAG_LOG_ERR_ALREADY_SET;
}

void eag_log_get_openlog_name(char *daemon)
{
	strncpy( STR_EAG, daemon, sizeof(STR_EAG)-1 );
	syslog(LOG_INFO,"eag_log_get_openlog_name STR_EAG = %s", STR_EAG);
	
	return;
}
int is_print_log(int level)
{
	return EAG_RETURN_OK;
	#if 0
	if (!(eag_log_level & (LOG_MASK(level)))) {
		return EAG_LOG_ERR_LEVEL_NOT_MATCH;	
	}
	
	if (EAG_DAEMON_LOG_OPEN != eag_daemon_log_open) {
		openlog(STR_EAG, LOG_ODELAY, LOG_DAEMON);
		eag_daemon_log_open = EAG_DAEMON_LOG_OPEN;
	}

	return EAG_RETURN_OK;
	#endif
}

#if eag_log_test
#include <stdio.h>
#include <string.h>
#include "eag_mem.c"
#include "eag_blkmem.c"
#include "eag_errcode.c"

int
main()
{
	int iret = EAG_RETURN_OK;
	iret = eag_log_init(1);
	if (EAG_RETURN_OK != iret) {
		printf("eag_log_init failed :%s\n", eag_errcode_content(iret));
		return 0;
	}

	iret = eag_log_add_filter("test1");
	if (0 == iret) {
		printf("eag_log_add_filter failed test1\n");
	}

	iret = eag_log_add_filter("test1");
	if (0 == iret) {
		printf("eag_log_add_filter failed test1  xxxx\n");
	}

	iret = eag_log_add_filter("test3");
	if (0 == iret) {
		printf("eag_log_add_filter failed test3\n");
	}

	eag_log_syslog(LOG_DEBUG, "test1", "test1");
	eag_log_syslog(LOG_DEBUG, "test", "test");
	eag_log_syslog(LOG_DEBUG, "test2", "test2");
	eag_log_syslog(LOG_DEBUG, "test4", "test4");

	eag_log_debug("test3", "test3");

	eag_log_set_level(LOG_AT_LEAST_NOTICE);

	eag_log_debug("test1", "eag_log_debug  test1");
	eag_log_info("eag_log_info  test1");
	eag_log_notice("eag_log_notice  test1");
	eag_log_warning("eag_log_warning  test1");
	eag_log_err("eag_log_err  test1");

	eag_log_debug("test", "eag_log_debug  test");
	eag_log_info("eag_log_info  test");
	eag_log_notice("eag_log_notice  test");
	eag_log_warning("eag_log_warning  test");
	eag_log_err("eag_log_err  test");

	eag_log_debug("test:test1", "eag_log_debug  test:test1");
	eag_log_info("eag_log_info  test:test1");
	eag_log_notice("eag_log_notice  test:test1");
	eag_log_warning("eag_log_warning  test:test1");
	eag_log_err("eag_log_err  test:test1");

	iret = eag_log_add_filter("test3:test7:test8:test9");
	if (0 == iret) {
		printf("eag_log_init failed\n");
		return 0;
	}

	{
		struct LogFilterItem *pos;
		list_for_each_entry(pos, &filter_head, node) {
			printf("filter : %s\n", pos->filter);
		}
	}

	iret = eag_log_del_filter("test3:test7:test8:test9");
	if (iret != 4) {
		printf("eag_log_del_filter failed iret =%d\n", iret);
	}

	printf("after del!!!!!\n");
	{
		struct LogFilterItem *pos;
		list_for_each_entry(pos, &filter_head, node) {
			printf("filter : %s\n", pos->filter);
		}
	}

	eag_log_debug("test:test1", "after   dell");
	eag_log_debug("test:test1", "eag_log_err  test:test1");
	eag_log_debug("test:test2", "eag_log_err  test:test2");
	eag_log_debug("test:test3", "eag_log_err  test:test3");
	eag_log_debug("test1:test3", "eag_log_err  test1:test3");

	eag_log_uninit();

	return 0;
}

#endif
