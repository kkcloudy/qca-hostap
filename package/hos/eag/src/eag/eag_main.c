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
* eag_main.c
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* eag main
*
*
*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#define _GNU_SOURCE 			/* See feature_test_macros(7) */
#include <sched.h>

#include "eag_conf.h"
//#include "eag_interface.h"
#include "eag_time.h"
#include "eag_log.h"
#include "eag_ipinfo.h"
#include "nmp_process.h"
#include "eag_ins.h"
#include "eag_wireless.h"
#include "eag_util.h"

#define MAX_HANSI_ID					16
#define IPTABLES_LOCK_FILE				"/var/run/eag_iptables_lock"
#define SLOT_ID_FILE					"/dbm/local_board/slot_id"

extern nmp_mutex_t eag_iptables_lock;

static int keep_going = 1;
eag_ins_t *eagins = NULL;

static void
print_usage(const char *file)
{
	fprintf(stderr, "usage: %s [<type> <id>]\n", file);
	fprintf(stderr, "type=0, remote hansi, id 1-16\n");
	fprintf(stderr, "type=1, none or local hansi, id 0-16\n");
	exit(1);
}

static void
log_pid(const char *pidfile) 
{
	FILE *file = NULL;
	mode_t oldmask;

	oldmask = umask(022);
	file = fopen(pidfile, "w");
	umask(oldmask);
	if(NULL == file) return;
	fprintf(file, "%d\n", getpid());
	fclose(file);
}

static void signal_handler(int sig) 
{
	switch (sig) {
		case SIGTERM:
		case SIGINT:
		case SIGUSR2:
			eag_log_info("Received terminate signal %d\n", sig);
			keep_going = 0;
			break;
		default:
			break;
	}
}

static int set_eag_core(void)
{
	unsigned int sys_core_mask = 1;
	unsigned long core_mask = 0;
	int corenum = 0;
	unsigned int set_core_mask = 1;
	unsigned long mask_tmp = 0; /* let eag proc active on every core at random.  previous:1 */
	int num = 0;
	FILE *fp = NULL;
	
	fp = fopen( "/proc/coremask", "r" );
	if ( NULL == fp )
	{
		eag_log_err("set_eag_core open coremask file failed: %s", 
			safe_strerror(errno));
		return -1;
	}
	
	num = fscanf( fp, "%x", &sys_core_mask );
	if (num < 0) {
		eag_log_err("set_eag_core fscanf  failed: %s", 
			safe_strerror(errno));
		fclose( fp );
		return -1;
	}
	if (num != 1) {
		eag_log_err("set_eag_core fscanf  failed num = %d", num );
		fclose( fp );
		return -1;
	}
	fclose( fp );
	
	eag_log_info("set_eag_core sys_core_mask=%x", sys_core_mask);
	core_mask = sys_core_mask;
	
	while( core_mask>0 )
	{
		corenum++;
		core_mask>>=1;
	}
	
	if (corenum > 1)
	{
		set_core_mask = sys_core_mask & (~mask_tmp);
		if (sched_setaffinity(getpid(), sizeof(set_core_mask),  &set_core_mask) < 0)
		{	
			eag_log_err("set_eag_core set_core_mask=%x, corenum=%d, sys_core_mask=%x :%s ",
				set_core_mask, corenum, sys_core_mask, safe_strerror(errno));
			return -1;
		}
	}
	
	return 0;
}

int main(int argc, char *argv[])
{
	char buf[64] = "";
	char pidfile[128] = "";
	char daemon_name[32] = "eag";
	struct sigaction act;
	printf("eag  start .......11111\n");

#if 0
	if (1 == argc) {
		hansitype = HANSI_LOCAL;
		insid = 0;
	}
	else if (argc >= 3) {
		hansitype = atoi(argv[1]);
		insid = atoi(argv[2]);
		if (HANSI_REMOTE == hansitype) {
			if (insid < 1 || insid > MAX_HANSI_ID) {
				print_usage(argv[0]);
			}
		}
		else if (HANSI_LOCAL == hansitype) {
			if (insid < 0 || insid > MAX_HANSI_ID) {
				print_usage(argv[0]);
			}
		}
		else {
			print_usage(argv[0]);
		}
	}
	else {
		print_usage(argv[0]);
	}
	#endif
	eag_time_init();
	snprintf(pidfile, sizeof(pidfile)-1,
			"/var/run/eag.pid");
	log_pid(pidfile);
	eag_log_init(daemon_name);
	//set_eag_core();
	
	act.sa_handler = signal_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGUSR2, &act, NULL);
	eag_log_info("11111 eag_start");
	eagins = eag_ins_new();
	if (NULL == eagins) {
		eag_log_err("eag_ins_new failed");
		exit(1);
	}
	#if 0
	eag_ipneigh_init();
	eag_iproute_init();
	#endif
	eag_ipinfo_init();
	//eag_dcli_dl_init();
	nmp_mutex_init(&eag_iptables_lock, IPTABLES_LOCK_FILE);
        	printf("eag  start 33333.......\n");

	while (keep_going) {
		eag_ins_dispatch(eagins);
	}

	if (eag_ins_is_running(eagins)) {
		eag_ins_stop(eagins);
	}
	eag_ins_free(eagins);
	
	eag_log_uninit();
	eag_ipinfo_exit();
	#if 0
	eag_ipneigh_uninit();
	eag_iproute_uninit();
	#endif
	//eag_dcli_dl_uninit();
	nmp_mutex_destroy(&eag_iptables_lock);
	printf("eag  end .......\n");
	return 0;
}

