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

#ifndef _MEM_CHECK_EAG_C_

#define _MEM_CHECK_EAG_C_

extern void *mem_check_malloc(unsigned mem_check_malloc_size,
			      const char *mem_check_malloc_file_name,
			      const char *mem_check_malloc_func_name,
			      int mem_check_malloc_line_num);

extern void *mem_check_calloc(size_t num,
			      size_t size,
			      const char *mem_check_malloc_file_name,
			      const char *mem_check_malloc_func_name,
			      int mem_check_malloc_line_num);

extern void *mem_check_realloc(void *mem_check_realloc_point,
			       unsigned int newsize,
			       const char *mem_check_malloc_file_name,
			       const char *mem_check_malloc_func_name,
			       int mem_check_malloc_line_num);

extern void mem_check_free(void *mem_check_free_point,
			   const char *mem_check_malloc_file_name,
			   const char *mem_check_malloc_func_name,
			   int mem_check_malloc_line_num);

extern int mem_check_state(const char *mem_check_state_name);
extern int mem_check_state_less(const char *mem_check_state_name);

extern void mem_check_clean(void);
extern void mem_check_start(void);
extern void mem_check_stop(void);

#if 0
#define malloc(size) mem_check_malloc(size,__FILE__,__FUNCTION__,__LINE__)

#define calloc(num,size) mem_check_calloc(num,size,__FILE__,__FUNCTION__,__LINE__)

#define realloc(point,newsize) mem_check_realloc(point,newsize,__FILE__,__FUNCTION__,__LINE__)

#define free(point) mem_check_free(point,__FILE__,__FUNCTION__,__LINE__)
#endif
#if 0
#define eag_malloc(size) mem_check_malloc(size,__FILE__,__FUNCTION__,__LINE__)

#define eag_calloc(num,size) mem_check_calloc(num,size,__FILE__,__FUNCTION__,__LINE__)

#define eag_realloc(point,newsize) mem_check_realloc(point,newsize,__FILE__,__FUNCTION__,__LINE__)

#define eag_free(point) mem_check_free(point,__FILE__,__FUNCTION__,__LINE__)
#else
#include <stdlib.h>
#define eag_malloc 	malloc
#define eag_calloc 	calloc
#define eag_realloc realloc
#define eag_free    free
#endif
#endif
