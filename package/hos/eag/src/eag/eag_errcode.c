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

#include "eag_errcode.h"

struct errcode_map_t {
	int errorcode;
	char *errcontent;
};

const struct errcode_map_t errcode_map[] = {
/*public error!*/
	{EAG_ERR_UNKNOWN, "unknown error!"},
	{EAG_ERR_INPUT_PARAM_ERR, "input param error!"},
	{EAG_ERR_MALLOC_FAILED, "malloc failed!"},
	{EAG_ERR_NULL_POINTER, "null pointer!"},

/*eag thread error!*/
	{EAG_ERR_THREAD_CREATE_FAILED, "thread create failed"},

};

#define ERROR_CODE_NUM	sizeof(errcode_map)/sizeof(errcode_map[0])

const char *
eag_errcode_content(int errcode)
{
	int i;
	for (i = 0; i < ERROR_CODE_NUM; i++) {
		if (errcode_map[i].errorcode == errcode) {
			return errcode_map[i].errcontent;
		}
	}

	return "unknown error!";
}

#ifdef eag_errcode_test
#include <stdio.h>
int
main()
{
	printf("eag_errcode.c test ok!\n");
	return 0;
}
#endif
