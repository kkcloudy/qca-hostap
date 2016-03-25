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
*	RCSfile:	hashtable.h
*
*	Author: 	shaojunwu
*
*	Revision:	1.00
*
*	Date:	2009-10-22 19:58:07
*
*******************************************************************************/
#ifndef _HASHTABLE_H
#define _HASHTABLE_H

#include "eag_errcode.h"

#define HASH_RETURN_OK				EAG_RETURN_OK
#define ERR_HASH_BASE				EAG_HASH_ERR_BASE
#define ERR_HASH_PARAM_ERR			(EAG_HASH_ERR_BASE-1)
#define ERR_HASH_MALLOC_FAILED		(EAG_HASH_ERR_BASE-2)
#define ERR_HASH_NODE_DUPLICATE		(EAG_HASH_ERR_BASE-3)

typedef struct hash_table_t {
	unsigned int hash_num;
	struct hlist_head head_nodes[0];
} hashtable;

extern int hashtable_create_table(hashtable ** ht, unsigned int hash_num);
extern unsigned int hash_value_count(const char *buff, unsigned int len,
				     unsigned int hash_size);
extern int hashtable_destroy_table(hashtable ** ht);
extern int hashtable_add_node(hashtable * ht, const void *key, unsigned int len,
			      struct hlist_node *node);
extern int hashtable_check_add_node(hashtable * ht, const void *key,
				    unsigned int len, struct hlist_node *node);
extern int hashtable_del_node(struct hlist_node *node);
extern struct hlist_head *hashtable_get_hash_list(hashtable * ht,
						  const void *key,
						  unsigned int len);

#endif
