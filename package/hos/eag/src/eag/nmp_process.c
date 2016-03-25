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
* nmp_process.c
*
*
* CREATOR:
* autelan.software.Network Dep. team
* zhangwl@autelan.com
*
* DESCRIPTION:
* Function for Process Synchronization
*
*
***************************************************************************/
#include <stdio.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include "eag_log.h"
#include "eag_errcode.h"
#include "nmp_process.h"

#define LOCK_FILE_MODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)

int
nmp_mutex_init(nmp_mutex_t *mutex, const char *file)
{
	mode_t old_mask = 0;
	
	if (NULL == mutex || NULL == file) {
		eag_log_err("nmp_mutex_init input error");
		return -1;
	}
	strncpy(mutex->filename, file, sizeof(mutex->filename));

	old_mask = umask(0111);
	if ( (mutex->fd = open(mutex->filename, O_CREAT|O_RDWR|O_TRUNC, 
						LOCK_FILE_MODE)) < 0) {
		eag_log_err("nmp_mutex_init open file failed: %s", 
				safe_strerror(errno));
		umask(old_mask);
		return -1;
	}
	umask(old_mask);
	
	eag_log_info("nmp_mutex_init mutex->fd = %d", mutex->fd);
	
    return 0;
}

int
nmp_mutex_destroy(nmp_mutex_t *mutex)
{
	if (NULL == mutex)  {
		eag_log_err("nmp_mutex_destroy input error");
		return -1;
	}

	if (mutex->fd >= 0) {
		close(mutex->fd);
		mutex->fd = -1;
		return 0;
	}
	eag_log_info("nmp_mutex_destroy ok");
	
	return 0;
}

int
nmp_mutex_lock(nmp_mutex_t *mutex)
{
	struct flock lock;
	char buf[32] = {0};

	if (NULL == mutex) {
		eag_log_err("nmp_mutex_lock, mutex is null");
		return -1;
	}

	lock.l_type = F_WRLCK;
	lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;
    	
	if (fcntl(mutex->fd, F_SETLKW, &lock) < 0) {
		eag_log_err("nmp_mutex_lock lock failed: fd(%d) %s",
			mutex->fd, safe_strerror(errno));
		return -1;
	}

	ftruncate(mutex->fd, 0);
	snprintf(buf, sizeof(buf), "%ld", (long)getpid());
	write(mutex->fd, buf, strlen(buf)+1);

	eag_log_debug("nmp_process", "nmp_mutex_lock %d,%s ok",
		mutex->fd, mutex->filename);
	
	return 0;
}

int
nmp_mutex_unlock(nmp_mutex_t *mutex)
{
	struct flock lock;

	if (NULL == mutex) {
		eag_log_err("nmp_mutex_unlock, mutex is null");
		return -1;
	}

	lock.l_type = F_UNLCK;
	lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;
    	
	ftruncate(mutex->fd, 0);
	if (fcntl(mutex->fd, F_SETLK, &lock) < 0) {
		eag_log_err("nmp_mutex_lock unlock failed: fd(%d) %s",
			mutex->fd, safe_strerror(errno));
		return -1;
	}

	eag_log_debug("nmp_process", "nmp_mutex_unlock %d,%s ok",
		mutex->fd, mutex->filename);
	
	return 0;
}

