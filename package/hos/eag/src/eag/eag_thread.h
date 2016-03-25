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

/* eag_thread.h */
#ifndef _EAG_THREAD_H
#define _EAG_THREAD_H

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct eag_thread eag_thread_t;
typedef struct eag_thread_master eag_thread_master_t;

/* Thread types. */
typedef enum {
	THREAD_READ = 0,
	THREAD_WRITE,
	THREAD_TIMER,
	THREAD_EVENT
} EagThreadType;

typedef int (*EagThreadRunFunc) (eag_thread_t * thread);

#define eag_thread_add_read(m,func,arg,fd) 	\
				eag_funcname_thread_add_read(m,func,arg,fd,#func)

#define eag_thread_add_write(m,func,arg,fd) 	\
				eag_funcname_thread_add_write(m,func,arg,fd,#func)

#define eag_thread_add_timer(m,func,arg,timeout_sec)    \
				eag_funcname_thread_add_timer(m,func,arg,timeout_sec,#func)

#define eag_thread_add_timer_msec(m,func,arg,timeout_msec) \
				eag_funcname_thread_add_timer_msec(m,func,arg,timeout_msec,#func)

#define eag_thread_add_event(m,func,arg,val) \
				eag_funcname_thread_add_event(m,func,arg,val,#func)

eag_thread_master_t *
eag_thread_master_new();

void 
eag_thread_master_free(eag_thread_master_t * m);
int 
eag_thread_master_update_time(eag_thread_master_t * m);
struct timeval *
eag_thread_master_get_timeval(eag_thread_master_t * m);

eag_thread_t *
eag_funcname_thread_add_read(eag_thread_master_t * m,
					   EagThreadRunFunc func,
					   void *arg,
					   int fd,
					   const char *funcname);

eag_thread_t *
eag_funcname_thread_add_write(eag_thread_master_t * m,
					    EagThreadRunFunc func,
					    void *arg,
					    int fd,
					    const char *funcname);

eag_thread_t *
eag_funcname_thread_add_timer(eag_thread_master_t *
					    master,
					    EagThreadRunFunc func,
					    void *arg, long timer,
					    const char *funcname);

eag_thread_t *
eag_funcname_thread_add_timer_msec(eag_thread_master_t *
						 m,
						 EagThreadRunFunc func,
						 void *arg, long timer,
						 const char *funcname);

eag_thread_t *
eag_funcname_thread_add_event(eag_thread_master_t * m,
					    EagThreadRunFunc func,
					    void *arg,
					    int val,
					    const char *funcname);

void *
eag_thread_get_arg(eag_thread_t * thread);

void 
eag_thread_cancel(eag_thread_t * thread);


int
eag_thread_dispatch(eag_thread_master_t * m, struct timeval *timer_wait);


void
eag_thread_log_all_thread( eag_thread_master_t * m );

#if 0

int eag_thread_get_fd(eag_thread_t * thread);

#endif
#ifdef  __cplusplus
}
#endif
#endif				/* _EAG_THREAD_H */
