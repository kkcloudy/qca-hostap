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
*	RCSfile:	hashtable.c
*
*	Author: 	shaojunwu
*
*	Revision:	1.00
*
*	Date:	2009-10-22 19:58:07
*
*******************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "nm_list.h"
#include "eag_errcode.h"
#include "hashtable.h"
#include "eag_log.h"
#include "eag_mem.h"

extern unsigned int
hash_value_count(const char *buff, unsigned int len, unsigned int hash_size)
{
	if (NULL == buff || 0 == len || 0 == hash_size) {
		eag_log_err("create_hash_table  error input!\n");
		return 0;
	}

	unsigned int uint32_hash_value = 0;

	while (4 <= len) {
		uint32_hash_value += *((unsigned int *) buff);
		buff += 4;
		len -= 4;
	}

	while (0 < len) {
		uint32_hash_value += (*buff) << ((len - 1) * 8);
		buff++;
		len--;
	}

	return uint32_hash_value % hash_size;
}

extern int
hashtable_create_table(hashtable ** ht, unsigned int hash_num)
{
	hashtable *table = NULL;
	unsigned int size = 0;
	unsigned int i = 0;

	if (0 == hash_num || NULL == ht) {
		eag_log_err("create_hash_table  error input!\n");
		return ERR_HASH_PARAM_ERR;
	}

	size = sizeof (hashtable) + sizeof (struct hlist_head) * hash_num;

	table = (hashtable *) eag_malloc(size);
	if (NULL == table) {
		eag_log_err("appconn_db_create malloc error!\n");
		return ERR_HASH_MALLOC_FAILED;
	}

	memset(table, 0, sizeof (hashtable));

	table->hash_num = hash_num;

	for (i = 0; i < hash_num; i++) {
		INIT_HLIST_HEAD(&(table->head_nodes[i]));
	}

	*ht = table;
	return HASH_RETURN_OK;
}

extern int
hashtable_destroy_table(hashtable ** ht)
{
	if (NULL == ht || NULL == *ht) {
		eag_log_err("hashtable_destroy_table input error!\n");
		return ERR_HASH_PARAM_ERR;
	}

	/* just free the table!!! the nodes are still there!!! */
	eag_free(*ht);

	*ht = NULL;

	return HASH_RETURN_OK;
}

extern int
hashtable_add_node(hashtable * ht, const void *key, unsigned int len,
		   struct hlist_node *node)
{
	if (NULL == ht || NULL == key || 0 == len || NULL == node) {
		eag_log_err("hashtable_add_node input error!\n");
		return ERR_HASH_PARAM_ERR;
	}

	unsigned int hash_value = 0;

	hash_value = hash_value_count(key, len, ht->hash_num);

	hlist_add_head(node, &(ht->head_nodes[hash_value]));

	return HASH_RETURN_OK;
}

extern int
hashtable_check_add_node(hashtable * ht, const void *key, unsigned int len,
			 struct hlist_node *node)
{
	if (NULL == ht || NULL == key || 0 == len || NULL == node) {
		eag_log_err("hashtable_add_obj input error!\n");
		return ERR_HASH_PARAM_ERR;
	}

	unsigned int hash_value = 0;
	int ret = 0;

	hash_value = hash_value_count(key, len, ht->hash_num);

	/* check is it in the list */
	ret = is_entry_in_hlist(node, &(ht->head_nodes[hash_value]));
	if (1 == ret) {
		eag_log_err("hashtable_add_obj error! node allready in it\n");
		return ERR_HASH_NODE_DUPLICATE;
	}
	hlist_add_head(node, &(ht->head_nodes[hash_value]));

	return HASH_RETURN_OK;
}

extern int
hashtable_del_node(struct hlist_node *node)
{
	if (NULL == node) {
		eag_log_err("hashtable_del_node input error!\n");
		return ERR_HASH_PARAM_ERR;
	}
//      unsigned int hash_value = 0;

	hlist_del(node);

	return HASH_RETURN_OK;
}

extern struct hlist_head *
hashtable_get_hash_list(hashtable * ht, const void *key, unsigned int len)
{
	if (NULL == ht || NULL == key || 0 == len) {
		eag_log_err("hashtable_get_hash_list input error!\n");
		return NULL;
	}

	unsigned int hash_value = 0;

	hash_value = hash_value_count(key, len, ht->hash_num);

	return &(ht->head_nodes[hash_value]);
}

/********************************************************
*method:   main 
*usage:    gcc hashtable.c dblnklst.c -o hashtest
*param:    
*return:   
*author:   shaojunwu
*create time:   	2009-10-23 9:44:26
*last changed:(include change contant, author, time!!!!)
*
*********************************************************/

#ifdef hashtable_test
#include <mcheck.h>

#include "eag_blkmem.c"
#include "eag_log.c"
#include "eag_mem.c"
#include "eag_errcode.c"

struct element_tst_t {
	struct hlist_node node;
	int i;
	char buff[128];
};

#define ELE_NUM 	512

int
main()
{
	hashtable *ht = NULL;
	int i;
	struct element_tst_t eles[ELE_NUM];

	struct element_tst_t *ele_get = NULL;
	struct hlist_head *hl_head;

	mtrace();

	memset(eles, 0, sizeof (eles));

	if (0 != hashtable_create_table(&ht, ELE_NUM)) {
		printf("create hash_table_err! table1\n");
		return -1;
	}

	/*add element */
	for (i = 0; i < ELE_NUM; i++) {
		memset(&(eles[i]), 0, sizeof (struct element_tst_t));
		eles[i].i = i;
		memset(eles[i].buff, 0, sizeof (eles[i].buff));
		memset(eles[i].buff, i % 7 + '0', i % 7 + 3);
		hashtable_add_node(ht, eles[i].buff, strlen(eles[i].buff),
				   &(eles[i].node));
	}

	/*find element */
	struct hlist_node *pos, *n;

	hl_head =
	    hashtable_get_hash_list(ht, eles[64].buff, strlen(eles[63].buff));
	hlist_for_each_entry_safe(ele_get, pos, n, hl_head, node) {
		printf("i=%d  buff=%s\n", ele_get->i, ele_get->buff);
	}

	printf("xxxxxxxxxxxxxxxxxxxxxxx\n");
	hashtable_del_node(&eles[64].node);
	hashtable_del_node(&eles[8].node);
	hashtable_del_node(&eles[22].node);
	hl_head =
	    hashtable_get_hash_list(ht, eles[64].buff, strlen(eles[63].buff));
	hlist_for_each_entry_safe(ele_get, pos, n, hl_head, node) {
		printf("i=%d  buff=%s\n", ele_get->i, ele_get->buff);
	}

	muntrace();
	return 0;
}

#endif
