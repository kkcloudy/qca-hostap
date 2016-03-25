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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>

#include "eag_errcode.h"
#include "eag_mem.h"
#include "eag_log.h"
#include "nm_list.h"
#include "eag_blkmem.h"

#define MAX_BLK_ITEM_NUM	1024

#define MAX_EAG_BLK_MEM_NAME_LEN	32

struct list_head blkmem_head = LIST_HEAD_INIT(blkmem_head);


struct eag_blk {
	unsigned int item_size;
	unsigned int item_num;

	unsigned int free_num;
	unsigned char blk_item_flag[(MAX_BLK_ITEM_NUM+7) / 8];	/*each bit flag this item is in use or not */
	char *itemdata;
	char data[0];
};

struct eag_blk_mem {
	struct list_head node;
	char name[MAX_EAG_BLK_MEM_NAME_LEN];
	unsigned int blk_item_size;
	unsigned int blk_item_num;
	unsigned int max_blk_num;

	unsigned int blk_num;

	struct eag_blk *blk[MAX_BLK_NUM];
};

static int
eag_blk_create(struct eag_blk **blk, unsigned int item_size,
	       unsigned int item_num)
{
	struct eag_blk *pret = NULL;
	unsigned int blk_mem_size;

	if (NULL == blk || 0 == item_size || 0 == item_num) {
		eag_log_err("eag_blk_create input error!\n");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if (item_num > MAX_BLK_ITEM_NUM) {
		eag_log_err("eag_blk_create item_num over limite!\n");
		return EAG_BLKMEM_ERR_ITEM_NUM_OVER_LIMIT;
	}

	blk_mem_size = sizeof (struct eag_blk) + item_size * (item_num + 1);	/*+1 是因为可能在结构体对齐的时候有消耗 */

	pret = (struct eag_blk *) eag_malloc(blk_mem_size);
	if (NULL == pret) {
		eag_log_err("eag_blk_create eag_malloc failed!\n");
		return EAG_ERR_MALLOC_FAILED;
	}

	memset(pret, 0, sizeof (struct eag_blk));

	pret->item_num = item_num;
	pret->free_num = item_num;
	pret->item_size = item_size;
	pret->itemdata = pret->data - 
			((unsigned long) (&(pret->data))) % item_size + item_size;	/*结构体对齐 */

	*blk = pret;

	eag_log_debug("eag_blkmem",
		      "eag_blk_create success item_num=%d item_size=%d!\n",
		      item_num, item_size);
	return EAG_RETURN_OK;
}

static int
eag_blk_destroy(struct eag_blk **blk)
{
	int iret = EAG_RETURN_OK;

	if (NULL == blk || NULL == *blk) {
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if ((*blk)->free_num < (*blk)->item_num) {
		eag_log_warning("eag_destroy_blk has item not free!! ");
		iret = EAG_BLKMEM_ERR_HAS_ITEM_NOT_FREE;
	}

	eag_free(*blk);
	*blk = NULL;
	return iret;
}

inline static int
eag_blk_if_has_free_item(struct eag_blk *blk)
{
	return (blk->free_num > 0) ? 1 : 0;
}

static void *
eag_blk_malloc_item(struct eag_blk *blk)
{
	int i;
	unsigned char flag;
	int free_item_offset;
	int j;
	void *pret = NULL;

	if (NULL == blk) {
		eag_log_err("eag_blk_malloc_item blk is nul pointer!\n");
		return NULL;
	}

	if (0 == blk->free_num) {
		eag_log_err("eag_blk_malloc_item blk has no free item!\n");
		return NULL;
	}

	/*get a char not echo 0xff   mean the item is free */
	for (i = 0; i < sizeof (blk->blk_item_flag); i++) {
		if (blk->blk_item_flag[i] != 0xff) {
			break;
		}
	}

	if (i == sizeof (blk->blk_item_flag)) {
		blk->free_num = 0;
		eag_log_err("eag_blk_malloc_item blk has no free item!\n");
		return NULL;
    }

	flag = ~(blk->blk_item_flag[i]);

	for (j = 0; (j < 8) && (flag > 0); j++, flag >>= 1) {;
	}			/*find the leftest bit which is 1 */
	free_item_offset = i * 8 + 8 - j;

	flag = 1;
	flag <<= (j - 1);
	blk->blk_item_flag[i] |= flag;	/*set the flag of this item to 1 */

	blk->free_num--;

	pret = blk->itemdata + free_item_offset * (blk->item_size);
	return pret;
}

/**********************
*function:
*param:
*return:  ret >= 0    offset of item in blk. 
		EAG_BLKMEM_ERR_ITEM_NOT_IN_BLK, item is not in this blk;
		EAG_BLKMEM_ERR_ILLEGAL_ITEM_POINTER,  param item is not an item pointer.  some bad error happen!!!
*
**********************/
static int
eag_blk_get_item_offset_in_blk(struct eag_blk *blk, char *item)
{
	int offset = -1;

	if (NULL == blk || NULL == item) {
		eag_log_err("eag_blk_get_item_offset_in_blk input error!\n");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if ((item < blk->itemdata)
	    || (item > blk->itemdata + blk->item_size * blk->item_num)) {
//              syslog(LOG_WARNING, "eag_blk_get_item_offset_in_blk  item not in this blk!");
		return EAG_BLKMEM_ERR_ITEM_NOT_IN_BLK;
	}
	if ((((unsigned int) (item - blk->itemdata)) % (blk->item_size)) != 0) {
		eag_log_err
		    ("eag_blk_get_item_offset_in_blk %p is not an item pointer!\n",
		     item);
		return EAG_BLKMEM_ERR_ILLEGAL_ITEM_POINTER;
	}
	offset = (item - blk->itemdata) / (blk->item_size);
	return offset;
}

static int
eag_blk_if_all_free(struct eag_blk *blk)
{
	return (blk->free_num == blk->item_num) ? 1 : 0;
}

static void
eag_blk_free_item(struct eag_blk *blk, int offset)
{
	unsigned char flag;
	int i;
	int j;

	i = offset / 8;
	j = offset % 8;
	flag = 0x80;

	flag >>= j;

	if ((blk->blk_item_flag[i] & flag) == 0) {
		eag_log_warning
		    ("eag_blk_free_item offset %d is not in use! double free?\n",
		     i);
	} else {
		blk->blk_item_flag[i] ^= flag;
		memset(blk->itemdata + offset * blk->item_size, 0,
		       blk->item_size);
		blk->free_num++;
	}

	return;
}

int
eag_blkmem_create(eag_blk_mem_t ** eag_blk_mem,
		  char *name,
		  unsigned int blk_item_size, unsigned int blk_item_num, 
		  unsigned int max_blk_num)
{
	eag_blk_mem_t *pret = NULL;

	eag_log_info("eag_blkmem_create name=%s item_size=%u item_num=%u",
						(NULL==name)?"null":name,blk_item_size, blk_item_num);
	if (NULL==eag_blk_mem || 0==blk_item_size || 0==blk_item_num ) {
		eag_log_err("eag_blkmem_create input error!\n");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if (blk_item_num > MAX_BLK_ITEM_NUM) {
		eag_log_err("eag_blkmem_create blk_item_num over limit! blk_item_num=%d\n",
		     blk_item_num);
		return EAG_BLKMEM_ERR_ITEM_NUM_OVER_LIMIT;
	}

	if (NULL==name || strlen(name)==0) {
		eag_log_err("eag_blkmem_create input name error! name=%s",
						(NULL==name)?"null":name);
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	pret = (eag_blk_mem_t *) eag_malloc(sizeof (eag_blk_mem_t));
	if (NULL == pret) {
		eag_log_err("eag_blkmem_create eag_malloc failed!\n");
		return EAG_ERR_MALLOC_FAILED;
	}

	memset(pret, 0, sizeof (eag_blk_mem_t));

	if (NULL != name) {
		strncpy(pret->name, name, sizeof (pret->name) - 1);
	}
	pret->blk_item_size = blk_item_size;
	pret->blk_item_num = blk_item_num;
	pret->max_blk_num = max_blk_num;

	*eag_blk_mem = pret;

	list_add(&(pret->node), &blkmem_head);
	return EAG_RETURN_OK;
}

int
eag_blkmem_destroy(eag_blk_mem_t ** eag_blk_mem)
{
	int i;

	if (NULL == eag_blk_mem || NULL == *eag_blk_mem) {
		eag_log_err("eag_blkmem_destroy input error!\n");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	for (i = 0; i < MAX_BLK_NUM; i++) {
		if (NULL != (*eag_blk_mem)->blk[i]) {
			if (EAG_BLKMEM_ERR_HAS_ITEM_NOT_FREE
			    	== eag_blk_destroy(&((*eag_blk_mem)->blk[i]))) {
				eag_log_err("blk has item not free!  blkmem name=%s",
						     (*eag_blk_mem)->name);
			}
		}
	}
	list_del( &((*eag_blk_mem)->node));
	
	eag_free((*eag_blk_mem));
	(*eag_blk_mem) = NULL;

	return EAG_RETURN_OK;
}

static struct eag_blk *
eag_blkmem_get_blk_has_free(eag_blk_mem_t * eag_blk_mem)
{
	struct eag_blk *blk = NULL;
	int i;

	if (NULL == eag_blk_mem) {
		eag_log_err("eag_blkmem_get_blk_has_free input error!\n");
		return NULL;
	}

	for (i = 0; i < MAX_BLK_NUM; i++) {
		blk = eag_blk_mem->blk[i];
		if ((NULL != blk) && (1 == eag_blk_if_has_free_item(blk))) {
			break;
		}
		blk = NULL;
	}

	return blk;
}

inline static int
eag_blkmem_if_has_max_blk(eag_blk_mem_t * eag_blk_mem)
{
//      eag_log_debug(LOG_DEBUG, "eag_blk_mem->blk_num=%d\n", eag_blk_mem->blk_num );
	//return (eag_blk_mem->blk_num >= MAX_BLK_NUM) ? 1 : 0;
	return (eag_blk_mem->blk_num >= eag_blk_mem->max_blk_num) ? 1 : 0;
}

static int
eag_blkmem_add_blk(eag_blk_mem_t * eag_blk_mem, struct eag_blk *blk)
{
	int i;
	if (NULL == eag_blk_mem || NULL == blk) {
		eag_log_err("eag_blkmem_add_blk input error!\n");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	for (i = 0; i < MAX_BLK_NUM; i++) {
		if (NULL == eag_blk_mem->blk[i]) {
			eag_blk_mem->blk[i] = blk;
			eag_blk_mem->blk_num++;
			break;
		}
	}

	if (i != MAX_BLK_NUM) {
		return EAG_RETURN_OK;
	}

	return EAG_BLKMEM_ERR_HAS_MAX_BLK_NUM;
}

void *
eag_blkmem_malloc_item(eag_blk_mem_t * eag_blk_mem)
{
	void *pitem = NULL;
	struct eag_blk *blk = NULL;
	int iret = 0;

	if (NULL == eag_blk_mem) {
		eag_log_warning
		    ("eag_blkmem_malloc_item input error! eag_blk_mem=%p\n",
		     eag_blk_mem);
		return NULL;
	}

	blk = eag_blkmem_get_blk_has_free(eag_blk_mem);
	if (NULL == blk) {
		if (1 == eag_blkmem_if_has_max_blk(eag_blk_mem)) {
			eag_log_warning
			    ("eag_blkmem_malloc_item blkmem %s has it's blk limit %d!\n",
			     eag_blk_mem->name, eag_blk_mem->max_blk_num);
		} else {
			iret =
			    eag_blk_create(&blk, eag_blk_mem->blk_item_size,
					   eag_blk_mem->blk_item_num);
			if (EAG_RETURN_OK == iret && NULL != blk) {
				eag_blkmem_add_blk(eag_blk_mem, blk);
			}
//                      blkmem_syslog(LOG_WARNING, "eag_blkmem_malloc_item iret = %d!\n", iret );               
		}
	}

	if (NULL != blk) {
		pitem = eag_blk_malloc_item(blk);
		eag_log_debug("eag_blkmem","eag_blkmem_malloc_item blk is %p pitem is %p .\n",blk ,pitem);
	} else {
		eag_log_warning("eag_blkmem_malloc_item blk is null !\n");
	}

	return pitem;
}

int
eag_blkmem_free_item(eag_blk_mem_t * eag_blk_mem, void *buff)
{
	int i = 0;
	int offset = -1;
	struct eag_blk *blk = NULL;

	if (NULL == eag_blk_mem || NULL == buff) {
		eag_log_warning("eag_blkmem_free_item input error !\n");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	for (i = 0; i < MAX_BLK_NUM; i++) {
		blk = eag_blk_mem->blk[i];
		if (NULL != blk) {
			offset = eag_blk_get_item_offset_in_blk(blk, buff);
			if (offset >= 0) {
				break;
			}
		}
	}

	if (offset >= 0) {
		eag_blk_free_item(blk, offset);
		eag_log_debug("eag_blkmem","eag_blkmem_free_item blk is %p offset is %d .", blk , offset);
		if (1 == eag_blk_if_all_free(blk)) {
			eag_blk_destroy(&(eag_blk_mem->blk[i]));
			eag_blk_mem->blk_num--;
		}
	} else {
		eag_log_err
		    ("eag_blkmem_free_item buff %p not find in blkmem!\n",
		     buff);
		return EAG_ERR_UNKNOWN;
	}

	return EAG_RETURN_OK;
}



void
eag_blkmem_log_all_blkmem( char *blkmem_name )
{
	struct eag_blk_mem *blkmem;
	struct eag_blk *blk;
	int i;

	list_for_each_entry(blkmem, &blkmem_head, node){
		if( NULL == blkmem_name 
			|| strlen(blkmem_name) == 0 
			|| strcmp(blkmem_name,blkmem->name) == 0 ){
			unsigned int total_used = 0;
			eag_log_info("---------blkmem for %s----------",blkmem->name);
			eag_log_info("blkmem->blk_item_size=%u",blkmem->blk_item_size);
			eag_log_info("blkmem->blk_item_num=%u",blkmem->blk_item_num);
			eag_log_info("blkmem->max_blk_num=%u",blkmem->max_blk_num);
			eag_log_info("blkmem->blk_num = %u", blkmem->blk_num);
			for(i=0;i<MAX_BLK_NUM;i++){
				if( NULL != blkmem->blk[i] ){
					blk = blkmem->blk[i];
					eag_log_info("blkmem blk = %p free item num=%u", blk, blk->free_num );
					total_used += (blk->item_num - blk->free_num);
				}
			}
			eag_log_info("blkmem total used item = %u",total_used);			
		}
	}

	return;
}

#ifdef eag_blkmem_test		/*for unit test */

#include "nm_list.h"
#include "eag_log.c"
#include "eag_mem.c"
#include "eag_errcode.c"
struct test {
	struct list_head node;
	unsigned long long a;
	char b[12];
};

#define TEST_BLK_ITEM_NUM	10

int
main()
{

	int iret = 0;
	int i = 0;
	eag_blk_mem_t *pblkmem = NULL;

	struct test *test = NULL;
	struct test *next = NULL;

	struct list_head testhead = LIST_HEAD_INIT(testhead);

	eag_blkmem_create(&pblkmem, "test", sizeof (struct test), 2046, MAX_BLK_NUM);

	if (NULL != pblkmem) {
		return 0;
	}

	iret = eag_blkmem_create(&pblkmem,
				 "test",
				 sizeof (struct test), TEST_BLK_ITEM_NUM, MAX_BLK_NUM);

	if (NULL == pblkmem) {
		return 0;
	}

	printf("pblkmem = %p\n", pblkmem);
	for (i = 0; i < TEST_BLK_ITEM_NUM * MAX_BLK_NUM + 10; i++) {
		test = (struct test *) eag_blkmem_malloc_item(pblkmem);
		if (NULL == test) {
			printf("i=%d\n", i);
			break;
		}

		test->a = i;
		snprintf(test->b, sizeof (test->b) - 1, "%d", i);
		printf("test =%p test->b = %s\n", test, test->b);
		if (i % 2 == 0) {
			list_add(&(test->node), &testhead);
		} else {
			list_add_tail(&(test->node), &testhead);
		}
	}

	printf("before   list_for_each_entry_safe\n\n\n");
	list_for_each_entry_safe(test, next, &testhead, node) {
		list_del(&(test->node));
		printf("test->b = %s\n", test->b);
		eag_blkmem_free_item(pblkmem, test);
		printf("after eag_blkmem_free_item test\n\n\n");
	}

	iret = eag_blkmem_destroy(&pblkmem);
	printf("eag_blkmem_destroy  iret = %d\n", iret);

	return 0;
}

#endif
