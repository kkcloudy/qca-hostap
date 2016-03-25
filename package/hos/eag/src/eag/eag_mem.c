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

#include <stdio.h>
#include <stdlib.h>
//#include <pthread.h>
#include <string.h>
#include <syslog.h>
#include "eag_errcode.h"
#include "eag_log.h"

#define MEM_CHECK_MAX_NUM 10000
#define MEM_CHECK_MAX_STRINT_LEN 256

void *mem_check_recode_point[MEM_CHECK_MAX_NUM];
unsigned int mem_check_recode_size[MEM_CHECK_MAX_NUM];
char mem_check_recode_string[MEM_CHECK_MAX_NUM][MEM_CHECK_MAX_STRINT_LEN];
int mem_check_current_num = 0;
int mem_check_state_change_flag = 0;
int mem_check_flag = 0;
//static pthread_mutex_t eag_mem_glock;

void *
mem_check_malloc(unsigned int mem_check_malloc_size,
		 const char *mem_check_malloc_file_name,
		 const char *mem_check_malloc_func_name,
		 int mem_check_malloc_line_num)
{
//      pthread_mutex_lock( &eag_mem_glock );
	void *get_point;
	get_point = malloc(mem_check_malloc_size);
	if (mem_check_flag) {
		if (mem_check_current_num < MEM_CHECK_MAX_NUM) {
			mem_check_recode_point[mem_check_current_num] =
			    get_point;
			mem_check_recode_size[mem_check_current_num] =
			    mem_check_malloc_size;
			if (get_point) {
				snprintf(mem_check_recode_string
					 [mem_check_current_num],
					 MEM_CHECK_MAX_STRINT_LEN,
					 "%s:%s:[%d]:size:%d",
					 mem_check_malloc_file_name,
					 mem_check_malloc_func_name,
					 mem_check_malloc_line_num,
					 mem_check_malloc_size);
				mem_check_current_num++;
				mem_check_state_change_flag = 1;
			} else {
				eag_log_debug("eag_mem",
					      "MEM_CHECK:get a NULL point.");
			}
		} else {
			eag_log_debug("eag_mem",
				      "MEM_CHECK:counter full!,%s:%s:[%d]:size:%d(malloc)",
				      mem_check_malloc_file_name,
				      mem_check_malloc_func_name,
				      mem_check_malloc_line_num,
				      mem_check_malloc_size);
		}
	}
//      pthread_mutex_unlock( &eag_mem_glock );
	return get_point;
}

void *
mem_check_calloc(size_t num,
		 size_t size,
		 const char *mem_check_malloc_file_name,
		 const char *mem_check_malloc_func_name,
		 int mem_check_malloc_line_num)
{
//      pthread_mutex_lock( &eag_mem_glock );
	void *get_point;
	get_point = calloc(num, size);
	if (mem_check_flag) {
		if (mem_check_current_num < MEM_CHECK_MAX_NUM) {
			if (get_point) {
				mem_check_recode_point[mem_check_current_num] =
				    get_point;
				mem_check_recode_size[mem_check_current_num] =
				    num * size;
				snprintf(mem_check_recode_string
					 [mem_check_current_num],
					 MEM_CHECK_MAX_STRINT_LEN,
					 "%s:%s:[%d]:size:%u*%u=%u(calloc)",
					 mem_check_malloc_file_name,
					 mem_check_malloc_func_name,
					 mem_check_malloc_line_num,
					 (unsigned int) num,
					 (unsigned int) size,
					 (unsigned int) (num * size));
				mem_check_current_num++;
				mem_check_state_change_flag = 1;
			} else {
				eag_log_debug("eag_mem",
					      "MEM_CHECK:get a NULL point");
			}
		} else {
			eag_log_debug("eag_mem",
				      "MEM_CHECK:counter full!,%s:%s:[%d]:size:%u*%u=%u(calloc)",
				      mem_check_malloc_file_name,
				      mem_check_malloc_func_name,
				      mem_check_malloc_line_num,
				      (unsigned int) num, (unsigned int) size,
				      (unsigned int) (num * size));
		}
	}
//      pthread_mutex_unlock( &eag_mem_glock );
	return get_point;
}

void *
mem_check_realloc(void *mem_check_realloc_point,
		  unsigned int newsize,
		  const char *mem_check_malloc_file_name,
		  const char *mem_check_malloc_func_name,
		  int mem_check_malloc_line_num)
{
//      pthread_mutex_lock( &eag_mem_glock );
	void *get_point;
	get_point = realloc(mem_check_realloc_point, newsize);

	if (mem_check_flag) {
		int i;
		int get_point_flag = 0;
		if (newsize == 0 && mem_check_realloc_point) {
			//this is free
			eag_log_debug("eag_mem",
				      "MEM_CHECK:newsize=0,realloc free");
			for (i = mem_check_current_num - 1; i > -1; i--) {
				if (mem_check_recode_point[i] ==
				    mem_check_realloc_point) {
					get_point_flag = 1;
					mem_check_current_num--;
					mem_check_state_change_flag = 1;
					if (i != mem_check_current_num) {
						//not last one
						//copy the last one to the place, where is this well be free
						mem_check_recode_point[i] =
						    mem_check_recode_point
						    [mem_check_current_num];
						strncpy(mem_check_recode_string[i],
						       mem_check_recode_string
						       [mem_check_current_num],
						       sizeof(mem_check_recode_string[i])-1);
					}
					mem_check_recode_point
					    [mem_check_current_num] = 0;
					memset(mem_check_recode_string
					       [mem_check_current_num], 0,
					       MEM_CHECK_MAX_STRINT_LEN);
					break;
				}
			}
			if (!get_point_flag) {
				eag_log_debug("eag_mem",
					      "MEM_CHECK:newsize=0,realloc free some pointer unkonw");
			}
		} else if (get_point) {
			for (i = mem_check_current_num - 1; i > -1; i--) {
				if (mem_check_recode_point[i] ==
				    mem_check_realloc_point) {
					//already got it,replace the string
					get_point_flag = 1;
					snprintf(mem_check_recode_string[i],
						 MEM_CHECK_MAX_STRINT_LEN,
						 "%s:%s:[%d]:size:%d(it be realloced!!)",
						 mem_check_malloc_file_name,
						 mem_check_malloc_func_name,
						 mem_check_malloc_line_num,
						 newsize);
					mem_check_recode_size[i] = newsize;
					mem_check_recode_point[i] = get_point;
					//mem_check_state_change_flag = 0;
					//didn't to print if out;
					break;
				}
			}

			if (!get_point_flag) {
				//didn't get it,it a new one add it
				if (mem_check_current_num < MEM_CHECK_MAX_NUM) {
					mem_check_recode_point
					    [mem_check_current_num] = get_point;
					mem_check_recode_size[i] = newsize;
					mem_check_state_change_flag = 1;
					if (mem_check_realloc_point) {
						// alloc some where unknow
						snprintf(mem_check_recode_string
							 [mem_check_current_num],
							 MEM_CHECK_MAX_STRINT_LEN,
							 "%s:%s:[%d]:size:%d(realloc some point unkonw where has been malloced)",
							 mem_check_malloc_file_name,
							 mem_check_malloc_func_name,
							 mem_check_malloc_line_num,
							 newsize);
					} else {
						// didn't alloc before
						snprintf(mem_check_recode_string
							 [mem_check_current_num],
							 MEM_CHECK_MAX_STRINT_LEN,
							 "%s:%s:[%d]:size:%d(malloc by realloc)",
							 mem_check_malloc_file_name,
							 mem_check_malloc_func_name,
							 mem_check_malloc_line_num,
							 newsize);
					}
					mem_check_current_num++;
				} else {
					//counter full
					if (mem_check_realloc_point) {
						eag_log_debug("eag_mem",
							      "MEM_CHECK:counter full,%s:%s:[%d]:size:%d(realloc some point unkonw where has been malloced)",
							      mem_check_malloc_file_name,
							      mem_check_malloc_func_name,
							      mem_check_malloc_line_num,
							      newsize);
					} else {
						eag_log_debug("eag_mem",
							      "MEM_CHECK:counter full,%s:%s:[%d]:size:%d(malloc by realloc)",
							      mem_check_malloc_file_name,
							      mem_check_malloc_func_name,
							      mem_check_malloc_line_num,
							      newsize);
					}
				}
			}
		} else {
			eag_log_debug("eag_mem",
				      "MEM_CHECK:realloc error,return is null");
		}
	}
//      pthread_mutex_unlock( &eag_mem_glock );
	return get_point;
}

void
mem_check_free(void *mem_check_free_point,
	       const char *mem_check_malloc_file_name,
	       const char *mem_check_malloc_func_name,
	       int mem_check_malloc_line_num)
{
//      pthread_mutex_lock( &eag_mem_glock );
	if (mem_check_free_point) {
		if (mem_check_flag) {
			int i;
			int get_point_flag = 0;
			for (i = mem_check_current_num - 1; i > -1; i--) {
				if (mem_check_recode_point[i] ==
				    mem_check_free_point) {
					get_point_flag = 1;
					mem_check_current_num--;
					mem_check_state_change_flag = 1;
					if (i != mem_check_current_num) {
						//not last one
						//copy the last one to the place, where is this well be free
						mem_check_recode_point[i] =
						    mem_check_recode_point
						    [mem_check_current_num];
						mem_check_recode_size[i] =
						    mem_check_recode_size
						    [mem_check_current_num];
						strncpy(mem_check_recode_string[i],
						       mem_check_recode_string
						       [mem_check_current_num],
						       sizeof(mem_check_recode_string[i])-1);
					}
					//clean last one.what ever
					mem_check_recode_point
					    [mem_check_current_num] = 0;
					mem_check_recode_size
					    [mem_check_current_num] = 0;
					memset(mem_check_recode_string
					       [mem_check_current_num], 0,
					       MEM_CHECK_MAX_STRINT_LEN);
					break;
				}
			}
			if (!get_point_flag) {
				eag_log_debug("eag_mem",
					      "MEM_CHECK:free free some pointer unkonw,%s[%d],%s().",
					      mem_check_malloc_file_name,
					      mem_check_malloc_line_num,
					      mem_check_malloc_func_name);
			}
		}
		free(mem_check_free_point);
	} else {
		eag_log_debug("eag_mem",
			      "MEM_CHECK:free a NULL!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		eag_log_debug("eag_mem", "MEM_CHECK:free place,%s,%s[%d]",
			      mem_check_malloc_file_name,
			      mem_check_malloc_func_name,
			      mem_check_malloc_line_num);
	}
//      pthread_mutex_unlock( &eag_mem_glock );
}

int
mem_check_state(const char *mem_check_state_name)
{
//      pthread_mutex_lock( &eag_mem_glock );
	if (mem_check_flag) {
		if (mem_check_current_num && mem_check_state_change_flag) {
			int i;
			int total_mem = 0;
			eag_log_debug("eag_mem",
				      "MEM_CHECK:-------mem_check_state,%s,mem leak!-----------",
				      mem_check_state_name);
			eag_log_debug("eag_mem",
				      "MEM_CHECK:mem leak,check at:%s,",
				      mem_check_state_name);
			for (i = 0; i < mem_check_current_num; i++) {
				if (mem_check_recode_point[i])	//usual neetn't it
				{
					eag_log_debug("eag_mem",
						      "MEM_CHECK:mem leak:%s,point:%p",
						      mem_check_recode_string
						      [i],
						      mem_check_recode_point
						      [i]);
					total_mem += mem_check_recode_size[i];
				} else {
					eag_log_debug("eag_mem",
						      "MEM_CHECK:mem_check_state find error");
				}
			}
			eag_log_debug("eag_mem", "MEM_CHECK:mem leak,total:%d",
				      total_mem);
			eag_log_debug("eag_mem",
				      "MEM_CHECK:-----------end of mem_check_state------------------------");
			mem_check_state_change_flag = 0;
		}
	}
//      pthread_mutex_unlock( &eag_mem_glock );
	return 1;
}

int
mem_check_state_less(const char *mem_check_state_name)
{
//      pthread_mutex_lock( &eag_mem_glock );
	if (mem_check_flag) {
		if (mem_check_current_num && mem_check_state_change_flag) {
			int i, j;
			int total_mem = 0;
			int printf_plag[MEM_CHECK_MAX_NUM];
			int count = 1;
			memset(printf_plag, 1, MEM_CHECK_MAX_NUM);

			eag_log_debug("eag_mem",
				      "MEM_CHECK:------------start of mem_check_state---------------------");
			eag_log_debug("eag_mem",
				      "MEM_CHECK:find mem leak,check at:%s,",
				      mem_check_state_name);
			for (i = 0; i < mem_check_current_num; i++) {
				if (mem_check_recode_point[i] && printf_plag[i])	//usual neetn't it
				{
					count = 1;
					for (j = i + 1;
					     j < mem_check_current_num; j++) {
						if (printf_plag[j]
						    &&
						    !strcmp
						    (mem_check_recode_string[i],
						     mem_check_recode_string
						     [j])) {
							printf_plag[j] = 0;
							count++;
							total_mem +=
							    mem_check_recode_size
							    [i];
						}
					}
					eag_log_debug("eag_mem",
						      "MEM_CHECK:mem leak,time:%d,%s",
						      count,
						      mem_check_recode_string
						      [i]);
					total_mem += mem_check_recode_size[i];
				} else {
					//eag_log_debug("eag_mem","MEM_CHECK:mem_check_state find error");
				}
			}
			eag_log_debug("eag_mem", "MEM_CHECK:mem leak,total:%d",
				      total_mem);
			eag_log_debug("eag_mem",
				      "MEM_CHECK:-----------end of mem_check_state------------------------");
			mem_check_state_change_flag = 0;
		}
	}
//      pthread_mutex_unlock( &eag_mem_glock );
	return 1;
}

void
mem_check_clean(void)
{
//      pthread_mutex_lock( &eag_mem_glock );
	memset(mem_check_recode_point, 0, MEM_CHECK_MAX_NUM);
	memset(mem_check_recode_string, 0,
	       MEM_CHECK_MAX_NUM * MEM_CHECK_MAX_STRINT_LEN);
	memset(mem_check_recode_size, 0, MEM_CHECK_MAX_NUM);
	mem_check_current_num = 0;
	mem_check_state_change_flag = 0;
//      pthread_mutex_unlock( &eag_mem_glock );
	//eag_log_debug("eag_mem","MEM_CHECK:mem_check_clean done");
}

void
mem_check_start(void)
{
//      pthread_mutex_lock( &eag_mem_glock );
	mem_check_flag = 1;
	eag_log_debug("eag_mem", "MEM_CHECK:---START---");
//      pthread_mutex_unlock( &eag_mem_glock );
}

void
mem_check_stop(void)
{
//      pthread_mutex_lock( &eag_mem_glock );
	mem_check_flag = 0;
	eag_log_debug("eag_mem", "MEM_CHECK:---STOP---");
//      pthread_mutex_unlock( &eag_mem_glock );
}

#ifdef eag_mem_test
#include "eag_log.c"
#include "eag_errcode.c"
#include "eag_blkmem.c"

int
main()
{
	return 0;
}

#endif
