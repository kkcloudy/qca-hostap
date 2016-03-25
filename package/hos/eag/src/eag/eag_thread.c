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

/* eag_thread.c */

#include <sys/select.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/time.h>
#include <stdio.h>
#include "nm_list.h"
#include "eag_errcode.h"
#include "eag_log.h"
#include "eag_util.h"

#include "eag_mem.h"
#include "eag_blkmem.h"
#include "eag_time.h"

#include "eag_thread.h"


#define MAX_FUNC_NAME_LEN	64
/* Thread itself. */
struct eag_thread {
	EagThreadType type;	/* thread type */
	struct list_head node;	/* previous/next pointer of the thread */
	eag_thread_master_t *master;	/* pointer to the struct thread_master. */
	EagThreadRunFunc func;	/* event function */
	void *arg;		/* event argument */
	union {
		int val;	/* second argument of the event. */
		int fd;		/* file descriptor in case of read/write. */
		struct timeval sands;	/* rest of time sands value. */
	} u;			/* Indepth usage info.  */
	char funcname[MAX_FUNC_NAME_LEN];
};

/* Master of the theads. */
struct eag_thread_master {
	struct list_head read;
	struct list_head write;
	struct list_head timer;
	struct list_head event;

	fd_set readfds;
	fd_set writefds;
	fd_set exceptfds;
	struct timeval time_now;
//      unsigned long alloc;
	eag_blk_mem_t *eag_thread_blkmem;
};

#define EAG_THREAD_BLKMEN_NAME		"eag_thread_blkmem"
#define EAG_THREAD_BLKMEM_BLKNUM	512
#define EAG_THREAD_BLKMEM_MAXNUM	128

/********************
*func:create an eagthread instance.
*params:
*author:
*date:20100106
**********************/
static eag_thread_t *
eag_thread_create(eag_thread_master_t * m,
		  EagThreadType type,
		  EagThreadRunFunc func, void *arg, const char *funcname)
{
	eag_thread_t *p_eag_thread = NULL;
	if( NULL == m || NULL == funcname){
		eag_log_err("eag_thread_create m=%p funcname=%s", m, 
					(NULL==funcname)?"NULL":funcname);
		return NULL;
	}
	p_eag_thread = eag_blkmem_malloc_item(m->eag_thread_blkmem);
	if (NULL != p_eag_thread) {
		memset(p_eag_thread, 0, sizeof (struct eag_thread));
		p_eag_thread->type = type;
		p_eag_thread->func = func;
		p_eag_thread->arg = arg;
		p_eag_thread->master = m;
		strncpy(p_eag_thread->funcname, funcname,
			sizeof (p_eag_thread->funcname) - 1);

		eag_log_debug("eag_thread:create",
			      "eag_thread_create type:%d funcname:%s  arg:%p\n",
			      p_eag_thread->type,
			      p_eag_thread->funcname, p_eag_thread->arg);
		return p_eag_thread;
	}

	return NULL;
}

static int
eag_thread_destroy(eag_thread_master_t * m, eag_thread_t * thread)
{
	if (NULL == thread ) {
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	eag_blkmem_free_item(m->eag_thread_blkmem, thread);

	return EAG_RETURN_OK;
}

void *
eag_thread_get_arg(eag_thread_t * thread)
{
	if (NULL != thread) {
		return thread->arg;
	}

	return NULL;
}

int
eag_thread_master_init(eag_thread_master_t * m)
{
	if (NULL == m) {
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	memset(m, 0, sizeof (*m));
	INIT_LIST_HEAD(&(m->read));
	INIT_LIST_HEAD(&(m->write));
	INIT_LIST_HEAD(&(m->timer));
	INIT_LIST_HEAD(&(m->event));

	FD_ZERO(&m->readfds);
	FD_ZERO(&m->writefds);
	FD_ZERO(&m->exceptfds);

//      m->alloc = 0;

	return eag_blkmem_create(&(m->eag_thread_blkmem),
				 EAG_THREAD_BLKMEN_NAME,
				 sizeof (eag_thread_t),
				 EAG_THREAD_BLKMEM_BLKNUM,
				 EAG_THREAD_BLKMEM_MAXNUM);
}

eag_thread_master_t *
eag_thread_master_new()
{
	eag_thread_master_t *m = NULL;

	m = (eag_thread_master_t *) eag_malloc(sizeof (eag_thread_master_t));
	if (NULL == m) {
		eag_log_err("eag_thread_master_new  malloc faile!");
		return NULL;
	}
	memset(m, 0, sizeof (eag_thread_master_t));

	INIT_LIST_HEAD(&(m->read));
	INIT_LIST_HEAD(&(m->write));
	INIT_LIST_HEAD(&(m->timer));
	INIT_LIST_HEAD(&(m->event));

	FD_ZERO(&m->readfds);
	FD_ZERO(&m->writefds);
	FD_ZERO(&m->exceptfds);

//      m->alloc = 0;

	if (EAG_RETURN_OK != eag_blkmem_create(&(m->eag_thread_blkmem),
					       EAG_THREAD_BLKMEN_NAME,
					       sizeof (eag_thread_t),
					       EAG_THREAD_BLKMEM_BLKNUM,
					       EAG_THREAD_BLKMEM_MAXNUM)) {
		eag_free(m);
		m = NULL;
		eag_log_err
		    ("eag_thread_master_new failed because blkmem create faile!");
	}

	return m;
}

int
eag_thread_master_update_time(eag_thread_master_t * m)
{
	return eag_time_gettimeofday(&m->time_now, NULL);
}

#if 0
struct timeval *
eag_thread_master_get_timeval(eag_thread_master_t * m)
{
	return &m->time_now;
}
#endif
static void
release_thread_list(eag_thread_master_t * m, struct list_head *head)
{
	eag_thread_t *pos, *n;

	list_for_each_entry_safe(pos, n, head, node) {
		list_del(&(pos->node));
		eag_thread_destroy(m, pos);
	}

	return;
}

void
eag_thread_master_free(eag_thread_master_t * m)
{

	if (NULL == m){
		eag_log_err("eag_thread_master_free input m is NULL!");
		return;
	}
	FD_ZERO(&(m->readfds));
	FD_ZERO(&(m->writefds));
	FD_ZERO(&(m->exceptfds));

	release_thread_list(m, &(m->read));
	release_thread_list(m, &(m->write));
	release_thread_list(m, &(m->timer));
	release_thread_list(m, &(m->event));

	eag_blkmem_destroy(&(m->eag_thread_blkmem));
	eag_free(m);
	
	return;
}

eag_thread_t *
eag_funcname_thread_add_read(eag_thread_master_t * m,
			     EagThreadRunFunc func,
			     void *arg, int fd, const char *funcname)
{
	eag_thread_t *thread = NULL;

	if (FD_ISSET(fd, &(m->readfds))) {
		eag_log_warning
		    ("eag_funcname_thread_add_read fd = %d is already in set!\n",
		     fd);
		return NULL;
	}

	thread = eag_thread_create(m, THREAD_READ, func, arg, funcname);

	if (NULL != thread) {
		thread->u.fd = fd;
		FD_SET(fd, &(m->readfds));
		list_add(&(thread->node), &(m->read));
	}
	eag_log_debug("eag_thread",
		      "add read fd = %d, funcname=%s  eag_thread=%p\n", fd,
		      funcname, thread);
	return thread;
}

eag_thread_t *
eag_funcname_thread_add_write(eag_thread_master_t * m,
			      EagThreadRunFunc func,
			      void *arg, int fd, const char *funcname)
{
	eag_thread_t *thread = NULL;

	if (FD_ISSET(fd, &(m->writefds))) {
		eag_log_warning
		    ("eag_funcname_thread_add_write fd = %d is already in set!\n",
		     fd);
		return NULL;
	}

	thread = eag_thread_create(m, THREAD_WRITE, func, arg, funcname);

	if (NULL != thread) {
		thread->u.fd = fd;
		FD_SET(fd, &(m->writefds));
		list_add(&(thread->node), &(m->write));
	}
	eag_log_debug("eag_thread",
		      "add write fd = %d, funcname=%s  eag_thread=%p\n", fd,
		      funcname, thread);
	return thread;
}

static eag_thread_t *
funcname_thread_add_timer_timeval(eag_thread_master_t * m,
				  EagThreadRunFunc func,
				  void *arg,
				  struct timeval *time_relative,
				  const char *funcname)
{
	eag_thread_t *thread = NULL;
	eag_thread_t *et = NULL;
	struct timeval alarm_time;

	thread = eag_thread_create(m, THREAD_TIMER, func, arg, funcname);
	if (NULL == thread) {
		eag_log_err
		    ("funcname_thread_add_timer_timeval  eag_thread_create failed!");
		return NULL;
	}

	/* Do we need jitter here? */
//      eag_thread_update_time (m);
	alarm_time.tv_sec = m->time_now.tv_sec + time_relative->tv_sec;
	alarm_time.tv_usec = m->time_now.tv_usec + time_relative->tv_usec;
	thread->u.sands = timeval_adjust(alarm_time);

	/* Sort by timeval. */
	list_for_each_entry(et, &(m->timer), node) {
		if (timeval_cmp(thread->u.sands, et->u.sands) <= 0) {
			list_add(&(thread->node), et->node.prev);
			return thread;
		}
	}

	list_add_tail(&(thread->node), &(m->timer));

	return thread;
}

eag_thread_t *
eag_funcname_thread_add_timer(eag_thread_master_t * m,
			      EagThreadRunFunc func,
			      void *arg, long timer, const char *funcname)
{
	struct timeval trel;

	trel.tv_sec = timer;
	trel.tv_usec = 0;

	return funcname_thread_add_timer_timeval(m, func, arg, &trel, funcname);
}

eag_thread_t *
eag_funcname_thread_add_timer_msec(eag_thread_master_t * m,
				   EagThreadRunFunc func,
				   void *arg, long timer, const char *funcname)
{
	struct timeval trel;

	trel.tv_sec = timer / 1000;
	trel.tv_usec = 1000 * (timer % 1000);

	return funcname_thread_add_timer_timeval(m, func, arg, &trel, funcname);
}

eag_thread_t *
eag_funcname_thread_add_event(eag_thread_master_t * m,
			      EagThreadRunFunc func,
			      void *arg, int val, const char *funcname)
{
	eag_thread_t *thread = NULL;

	thread = eag_thread_create(m, THREAD_EVENT, func, arg, funcname);

	if (NULL != thread) {
		thread->u.val = val;
		list_add(&(thread->node), &(m->event));
	}
	eag_log_debug("eag_thread",
		      "add event val = %d, funcname=%s  eag_thread=%p\n", val,
		      funcname, thread);
	return thread;
}

static void
eag_thread_run(eag_thread_t * thread)
{
	eag_log_debug("eag_thread",
		      "eag_thread_run  name=%s    eag_thread->func=%p",
		      thread->funcname, thread->func);
	if (NULL != thread->func) {
		thread->func(thread);
	}

	return;
}

void
eag_thread_cancel(eag_thread_t * thread)
{
	if( NULL == thread ){
		eag_log_err( "eag_thread_cancel input thread is NULL!" );
		return;
	}
	eag_log_debug("eag_thread",
		      "eag_thread_cancel func=%s fd=%d  eag_thread->type=%d\n",
		      thread->funcname, thread->u.fd, thread->type);
	switch (thread->type) {
	case THREAD_READ:
		FD_CLR(thread->u.fd, &(thread->master->readfds));
		list_del(&(thread->node));
		break;
	case THREAD_WRITE:
		FD_CLR(thread->u.fd, &(thread->master->writefds));
		list_del(&(thread->node));
		break;
	case THREAD_EVENT:
		list_del(&(thread->node));
		break;
	case THREAD_TIMER:
		list_del(&(thread->node));
		break;
	default:
		eag_log_err("eag_thread_cancel  eag_thread unknow type=%d!\n",
			    thread->type);
		list_del(&(thread->node));
		break;
	}

	eag_thread_destroy(thread->master, thread);
	return;
}

static void
eag_thread_process_fd(struct list_head *head, fd_set * fdset)
{
	eag_thread_t *pos, *n;
	DEBUG_FUNCTION_BEGIN();

	list_for_each_entry_safe(pos, n, head, node) {
		if (FD_ISSET(pos->u.fd, fdset)) {
			eag_log_debug("eag_thread", "fd %d is set!",
				      pos->u.fd);
			eag_log_debug("eag_thread",
				      "thread_process_fd pos type=%d fd=%d func=%s\n",
				      pos->type, pos->u.fd, pos->funcname);
			eag_thread_run(pos);
		}
	}

	DEBUG_FUNCTION_END();

	return;
}

static int
eag_thread_dispatch_event(eag_thread_master_t * m)
{
	return 0;
}

static int
eag_thread_dispatch_timer(eag_thread_master_t * m)
{
	eag_thread_t *pos, *n;
	
	list_for_each_entry_safe(pos, n, &(m->timer), node) {
		if (timeval_cmp(m->time_now, pos->u.sands) >= 0) {
			eag_log_debug("eag_thread", "eag_thread_dispatch_timer funcname=%s",
				      pos->funcname);
			eag_thread_run(pos);
		}
	}
	return 0;
}

static int
eag_thread_dispatch_sock(eag_thread_master_t * m, struct timeval *timer_wait)
{
	int num = 0;
	fd_set readfds;
	fd_set writefds;
	fd_set exceptfds;
	
	#if 0
	if (list_empty(&(m->read)) && list_empty(&(m->write))) {
		return EAG_RETURN_OK;
	}
	#endif
	readfds = m->readfds;
	writefds = m->writefds;
	exceptfds = m->writefds;

	num = select(FD_SETSIZE, &readfds, &writefds, &exceptfds, timer_wait);

	eag_log_debug("eag_thread_mainsock", "eag_thread_dispatch select num=%d\n",
		      num);
	
	if (num < 0) {
		eag_log_err("eag_thread_dispatch select error!\n");
	}
	else if(num == 0){
		eag_log_debug("eag_thread_mainsock",
			      "eag_thread_dispatch in idle\n");
	}
	else if (num > 0) {
		eag_log_debug("eag_thread_mainsock",
			      "before eag_thread_dispatch  read\n");
		eag_thread_process_fd(&(m->read), &readfds);
		eag_log_debug("eag_thread_mainsock",
			      "before eag_thread_dispatch  write\n");
		eag_thread_process_fd(&(m->write), &writefds);
	}

	return EAG_RETURN_OK;
}

int
eag_thread_dispatch(eag_thread_master_t * m, struct timeval *timer_wait)
{
	eag_thread_master_update_time(m);
	eag_thread_dispatch_event(m);
	eag_thread_dispatch_timer(m);
	eag_thread_dispatch_sock(m, timer_wait);
	return EAG_RETURN_OK;
}

void
eag_thread_log_all_thread( eag_thread_master_t * m )
{
	eag_thread_t *thread = NULL;
	eag_log_info("eag_log_all_thread begin");
	if( NULL != m && NULL != m->eag_thread_blkmem ){
		eag_log_info("eag_log_all_thread master = %p time_now=%ld:%ld", 
					m, (long)m->time_now.tv_sec, (long)m->time_now.tv_usec );
		
		eag_log_info("eag_log_all_thread log read:");
		list_for_each_entry(thread,&(m->read),node){
			eag_log_info("fd=%d funcname=%s  func=%p master=%p",
					thread->u.fd, thread->funcname, thread->func, thread->master );
		}
		
		eag_log_info("eag_log_all_thread log write:");
		list_for_each_entry(thread,&(m->write),node){
			eag_log_info("fd=%d funcname=%s  func=%p master=%p",
					thread->u.fd, thread->funcname, thread->func, thread->master );
		}
		
		eag_log_info("eag_log_all_thread log timer:");
		list_for_each_entry(thread,&(m->timer),node){
			eag_log_info("timer=%ld:%ld funcname=%s  func=%p master=%p",
					(long)thread->u.sands.tv_sec,(long) thread->u.sands.tv_usec,
					thread->funcname, thread->func, thread->master );
		}		
	}else{
		eag_log_info("eag_log_all_thread m = %p", m);
	}
	eag_log_info("eag_log_all_thread end");	
}



#ifdef eag_thread_test

#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>

#include "eag_errcode.c"
#include "eag_log.c"
#include "eag_mem.c"
#include "eag_blkmem.c"
#include "eag_util.c"

#define TEST_PORT	4567

eag_thread_master_t eag_thread_master;

struct sockaddr_in address;

struct test {
	struct sockaddr_in *address;
	size_t addr_len;
	int data_size;
	char buff[1024];
};

#define WRITE_BUFF "test!!!!!!!"
struct test test_read = { &address, sizeof (address), 0, "" };
struct test test_write =
    { &address, sizeof (address), sizeof (WRITE_BUFF), WRITE_BUFF };

int
eag_thread_test_write(eag_thread_t * thread)
{
	struct test *test = thread->arg;
	int write_len = 0;

	eag_log_debug("eag_thread",
		      "eag_thread_test_write test = %p   pid=%d\n", test,
		      getpid());
	eag_log_debug("eag_thread",
		      "eag_thread_test_write eag_thread->u.fd = %d  \n",
		      thread->u.fd);

	eag_log_debug("eag_thread",
		      "test->address = %p  test->addr_len=%u  test->buff=%s\n",
		      test->address, (unsigned int) test->addr_len, test->buff);
#if 0
	eag_log_debug("eag_thread_t",
		      "addr = %x  port=%x  len=%d  sizeof(addr)=%d\n",
		      test->address->sin_addr.s_addr, test->address->sin_port,
		      test->addr_len, sizeof (struct sockaddr_in));
#endif
	write_len = sendto(thread->u.fd, test->buff, strlen(test->buff), 0,
			   (struct sockaddr *) (test->address), test->addr_len);

	eag_log_debug("eag_thread", "eag_thread_test_write write_len=%d\n",
		      write_len);

	eag_thread_cancel(thread);

	return 0;
}

int
eag_thread_test_read(eag_thread_t * thread)
{
	struct test *test = thread->arg;

	test = thread->arg;

	eag_log_debug("eag_thread", "eag_thread_test_read test = %p\n", test);
	eag_log_debug("eag_thread",
		      "eag_thread_test_read eag_thread->u.fd = %d\n",
		      thread->u.fd);
	memset(test->buff, 0, sizeof (test->buff));
	test->data_size =
	    recv(thread->u.fd, test->buff, sizeof (test->buff) - 1, 0);

	eag_log_debug("eag_thread", "get buff = %s\n", test->buff);
	eag_thread_add_write(thread->master, eag_thread_test_write,
			     &test, thread->u.fd);

	return 0;
}

int
main(int argc, char *argv[])
{
	int pid;
	int sock;
	eag_log_init(1);
	eag_log_add_filter("eag_thread");

	eag_thread_master_init(&eag_thread_master);

//      test_read.address = &address;
//      test_read.addr_len = sizeof(struct sockaddr_in);
	eag_log_debug("eag_thread", "test_read = %p  test_read.address=%p\n",
		      &test_read, test_read.address);

//      test_write.address = &address;
//      test_write.addr_len = sizeof(struct sockaddr_in);
	eag_log_debug("eag_thread",
		      "test_write = %p  test_write.address=%p\n", &test_write,
		      test_write.address);

	pid = argc;		// fork();

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	eag_log_debug("eag_thread",
		      "!!!!!!!!!!!!!!!!!!!!!!!!after create socket argc=%d!\n",
		      argc);
	if (pid > 1) {		/*master */
#if 0
		int optval = 1;
		if (setsockopt
		    (sock, SOL_SOCKET, SO_REUSEADDR, &optval,
		     sizeof (optval))) {
			eag_log_debug("eag_thread",
				      "master	setsockopt failed");
			close(sock);
			sock = -1;
			return -1;
		}
#endif
		memset(&address, 0, sizeof (address));
		address.sin_family = AF_INET;	/* host byte order */
		address.sin_port = htons(TEST_PORT);	/* short, network byte order */
		address.sin_addr.s_addr = INADDR_ANY;	/* auto-fill with my IP */
		bzero(&(address.sin_zero), 8);	/* zero the rest of the struct */

		if (0 !=
		    bind(sock, (struct sockaddr *) &address,
			 sizeof (address))) {
			eag_log_debug("eag_thread", "master  bind failed");
			close(sock);
			sock = -1;
			return -1;
		}

		eag_thread_add_read(&eag_thread_master, eag_thread_test_read,
				    &test_read, sock);

	} else			//if( 0 == pid )/*child*/
	{
		memset(&address, 0, sizeof (address));
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(0xC0A80265);	//127.0.0.1
		address.sin_port = htons(TEST_PORT);
		bzero(&(address.sin_zero), 8);	/* zero the rest of the struct */
		sleep(2);
		eag_thread_add_write(&eag_thread_master,
				     eag_thread_test_write, &test_write, sock);
	}

	eag_log_debug("eag_thread", "before dispactch!!!!  pid=%d\n",
		      getpid());

	while (1) {
		struct timeval timer_wait;
		timer_wait.tv_sec = 1;
		timer_wait.tv_usec = 0;

		eag_thread_dispatch(&eag_thread_master, &timer_wait);
	}

	eag_thread_master_free(&eag_thread_master);
}

#endif
