#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
//#include "../../../qca/qca-hostap/src/utils/common.h"

#define USER_DATABASE_PATH	"/var/run/userdb/" 
#define GUEST_DATABASE_PATH	"/var/run/userdb/guest" 
#define GUEST_DATABASE_TMP_PATH	"/var/run/userdb/guest.tmp" 
#define EMPLOYEE_DATABASE_PATH	"/var/run/userdb/employee" 
#define EMPLOYEE_DATABASE_TMP_PATH	"/var/run/userdb/employee.tmp" 

#define USER_GROUP_NAME_0 "guest"
#define USER_GROUP_NAME_1 "employee"
#define TMP_BUF_SIZE 128
#define USER_ADD_PARAMETER_NUM 5
#define USER_DEL_PARAMETER_NUM 3
#define USER_SHOW_PARAMETER_NUM 2
#define USER_GROUP_SHOW_PARAMETER_NUM 3

#ifndef os_malloc
#define os_malloc(s) malloc((s))
#endif
#ifndef os_free
#define os_free(p) free((p))
#endif

#ifndef os_memset
#define os_memset(s, c, n) memset(s, c, n)
#endif
#ifndef os_memcmp
#define os_memcmp(s1, s2, n) memcmp((s1), (s2), (n))
#endif

#ifndef os_strlen
#define os_strlen(s) strlen(s)
#endif
#ifndef os_strchr
#define os_strchr(s, c) strchr((s), (c))
#endif

#ifndef os_strcat
#define os_strcat(s, c) strcat((s), (c))
#endif
#ifndef os_strcpy
#define os_strcpy(s1, s2) strcpy((s1), (s2))
#endif
#ifndef os_strcmp
#define os_strcmp(s1, s2) strcmp((s1), (s2))
#endif


char *user_optarg;
int user_optind = 1;
int user_optopt;

static int user_cli_cmd_add(int argc, char *argv[])
{
	char buf[TMP_BUF_SIZE];
	char user_path[TMP_BUF_SIZE];
	FILE *userdb;
	char *filename;
	int guest_flag = 1;
	int employee_flag = 1;

	printf("Get ADD parameter information: %s %s %s\r\n",user_optarg,argv[0],argv[1]);
	if((0 == os_strcmp(argv[1],USER_GROUP_NAME_0)) || (0 == os_strcmp(argv[1],USER_GROUP_NAME_1))){
    	userdb= fopen(GUEST_DATABASE_PATH, "r");
    	if (!userdb){
			guest_flag = 0;
			if (mkdir(USER_DATABASE_PATH, 666) < 0) {
		        printf("Build file path: %s fail. %s\n", USER_DATABASE_PATH,strerror(errno));
		        return -1;
	        }
    		printf("%s file does not exis. \n",GUEST_DATABASE_PATH);
    	}
        if(guest_flag){
    		os_memset(buf,0,sizeof(buf));
        	while(fgets(buf,TMP_BUF_SIZE,userdb) != NULL){
        		if( 0 == strncmp(buf,user_optarg,os_strlen(user_optarg)) ){
        			printf("The user has been added, please check !\n");
    				fclose(userdb);
                    return -1;
        		}
        		os_memset(buf,0,sizeof(buf));
        	}
        	fclose(userdb);
	    }
    	userdb= fopen(EMPLOYEE_DATABASE_PATH, "r");
    	if (!userdb){
			employee_flag = 0;
    		printf("%s file does not exis.\n",EMPLOYEE_DATABASE_PATH);
    	}
		if(employee_flag){
        	os_memset(buf,0,sizeof(buf));
        	while(fgets(buf,TMP_BUF_SIZE,userdb) != NULL){
        		if( 0 == strncmp(buf,user_optarg,os_strlen(user_optarg)) ){
        			printf("The user has been added, please check !\n");
    				fclose(userdb);
                    return -1;
        		}
        		os_memset(buf,0,sizeof(buf));
        	}
        	fclose(userdb);
		}
		filename =(char*)os_malloc(TMP_BUF_SIZE);
    	if(filename == NULL){            
    		printf("malloc fail.\n");
    		return -1;
    	}        
    	memset(filename,0,os_strlen(filename));
    	memset(user_path,0,os_strlen(user_path));
    	os_strcpy(user_path, USER_DATABASE_PATH);
    	filename = os_strcat(user_path,argv[1]);
    	userdb = fopen(filename, "a+" );    	
    	if (!userdb){    		
    		printf("file %s not writeable.\n",filename);
    		return -1;    	
    	}		
    	snprintf(buf, sizeof(buf), "%s %s %s",user_optarg,argv[0],argv[1]);
    	fprintf( userdb, "%s\n", buf );	    
    	printf("user information addition success!\n");
    	fclose(userdb);	
    	return 0;

	}
	else{
		printf("Invalid group name: group name must be 'guest' or 'employee'\n");
		return -1;
	}

}

static char *format_str(char *dst, char *src)
{
	int i=0,j=0;
	if(!dst || !src)
		return NULL;
	while(src[i] != '\0' ){
		if( src[i] != ' ' )
			dst[j] = src[i];
		else{
			dst[j++] = '\t';
			dst[j++]= '\t';
			dst[j++] = '\t';
			dst[j] = '\t';
		}
		i++;
		j++;
	}
	return dst;
}

static int user_group_cli_cmd_show(char *groupname)
{
	FILE *userdb;
	char guest_buf[TMP_BUF_SIZE] = "guest";
	char employee_buf[TMP_BUF_SIZE] = "employee";
	char tmp[TMP_BUF_SIZE + 6];  /*add six \t*/

    if( 0 == strncmp(guest_buf,groupname,os_strlen(groupname)) ){
    	userdb = fopen(GUEST_DATABASE_PATH, "r" );
    	if (!userdb){
    		printf("open %s failed.\n",GUEST_DATABASE_PATH);
    		return -1;
    	}
    	printf("=========================================================================================\n");
    	printf("user name\t\t\tpassword\t\t\tgroup name\n");
    	os_memset(guest_buf,0,sizeof(guest_buf));
    	os_memset(tmp,0,sizeof(tmp));
    	while(fgets(guest_buf,TMP_BUF_SIZE,userdb) != NULL){
    		printf("%s\r\n",format_str(tmp, guest_buf));
    		os_memset(guest_buf,0,sizeof(guest_buf));
    		os_memset(tmp,0,sizeof(tmp));
    	}
    	fclose(userdb);
    	printf("=========================================================================================\n");

	}
	else if(0 == strncmp(employee_buf,groupname,os_strlen(groupname))){
    	userdb = fopen(EMPLOYEE_DATABASE_PATH, "r" );
    	if (!userdb){
    		printf("open %s failed.\n",EMPLOYEE_DATABASE_PATH);
    		return -1;
    	}
    	printf("=========================================================================================\n");
    	printf("user name\t\t\tpassword\t\t\tgroup name\n");
    	os_memset(employee_buf,0,sizeof(employee_buf));
    	os_memset(tmp,0,sizeof(tmp));
    	while(fgets(employee_buf,TMP_BUF_SIZE,userdb) != NULL){
    		printf("%s\r\n",format_str(tmp, employee_buf));
    		os_memset(employee_buf,0,sizeof(employee_buf));
    		os_memset(tmp,0,sizeof(tmp));
    	}
    	fclose(userdb);
    	printf("=========================================================================================\n");
	} 
	return 0;
}

static int user_cli_cmd_del(char *username)
{
	char buf[TMP_BUF_SIZE];
	char tmp[TMP_BUF_SIZE + 6];  /*add six \t*/
	FILE *userdb;
	FILE *userdb_tmp;
	int del_flag = 0;
	
	userdb= fopen(GUEST_DATABASE_PATH, "a+");
	if (!userdb){
		printf("open %s failed.\n",GUEST_DATABASE_PATH);
		return -1;
	}
	userdb_tmp= fopen(GUEST_DATABASE_TMP_PATH, "a+");
	if (!userdb_tmp){
		printf("open %s failed.\n",GUEST_DATABASE_TMP_PATH);
		return -1;
	}
	os_memset(buf,0,sizeof(buf));
	os_memset(tmp,0,sizeof(tmp));
	while(fgets(buf,TMP_BUF_SIZE,userdb) != NULL){
		if( 0 == strncmp(buf,username,os_strlen(username)) ){
			del_flag = 1;
			printf("find record, delete it\r\n");
			continue;
		}
		fputs(buf,userdb_tmp);
		os_memset(buf,0,sizeof(buf));
		os_memset(tmp,0,sizeof(tmp));
	}
	fclose(userdb);
    fclose(userdb_tmp);
	if( unlink(GUEST_DATABASE_PATH) != 0 ){
		printf("delete %s failed.\n",GUEST_DATABASE_PATH);
		return -1;
	}
	
	if( rename(GUEST_DATABASE_TMP_PATH, GUEST_DATABASE_PATH) != 0 ){
		printf("rename %s failed.\n",GUEST_DATABASE_PATH);
		return -1;
	}
		
	if(0 == del_flag){
    	userdb= fopen(EMPLOYEE_DATABASE_PATH, "a+");
    	if (!userdb){
    		printf("open %s failed.\n",EMPLOYEE_DATABASE_PATH);
    		return -1;
    	}
    	userdb_tmp= fopen(EMPLOYEE_DATABASE_TMP_PATH, "a+");
    	if (!userdb_tmp){
    		printf("open %s failed.\n",EMPLOYEE_DATABASE_TMP_PATH);
    		return -1;
    	}
    	os_memset(buf,0,sizeof(buf));
    	os_memset(tmp,0,sizeof(tmp));
    	while(fgets(buf,TMP_BUF_SIZE,userdb) != NULL){
    		if( 0 == strncmp(buf,username,os_strlen(username)) ){
    			printf("find record, delete it\r\n");
    			continue;
    		}
    		fputs(buf,userdb_tmp);
    		os_memset(buf,0,sizeof(buf));
    		os_memset(tmp,0,sizeof(tmp));
    	}
    	fclose(userdb);
        fclose(userdb_tmp);
    	if( unlink(EMPLOYEE_DATABASE_PATH) != 0 ){
    		printf("delete %s failed.\n",EMPLOYEE_DATABASE_PATH);
    		return -1;
    	}
    	
    	if( rename(EMPLOYEE_DATABASE_TMP_PATH, EMPLOYEE_DATABASE_PATH) != 0 ){
    		printf("rename %s failed.\n",EMPLOYEE_DATABASE_PATH);
    		return -1;
	}
	return 0;
    }
}
static int user_cli_cmd_show()
{
	FILE *userdb;
	char buf[TMP_BUF_SIZE];
	char tmp[TMP_BUF_SIZE + 6];  /*add six \t*/
	int guest_flag = 1;
	int employee_flag = 1;
	
	userdb = fopen(GUEST_DATABASE_PATH, "r" );
	
	if (!userdb){
		printf("open %s failed.\n",GUEST_DATABASE_PATH);
		guest_flag = 0;
	}
	printf("=========================================================================================\n");
	printf("user name\t\t\tpassword\t\t\tgroup name\n");
    if(guest_flag){
    	os_memset(buf,0,sizeof(buf));
    	os_memset(tmp,0,sizeof(tmp));
    	while(fgets(buf,TMP_BUF_SIZE,userdb) != NULL){
    		printf("%s",format_str(tmp, buf));
    		os_memset(buf,0,sizeof(buf));
    		os_memset(tmp,0,sizeof(tmp));
    	}
    	fclose(userdb);
    }

	userdb = fopen(EMPLOYEE_DATABASE_PATH, "r" );
	if (!userdb){
		printf("open %s failed.\n",EMPLOYEE_DATABASE_PATH);
    	employee_flag = 0;
	}
	if(employee_flag){
		os_memset(buf,0,sizeof(buf));
    	os_memset(tmp,0,sizeof(tmp));
    	while(fgets(buf,TMP_BUF_SIZE,userdb) != NULL){
    		printf("%s",format_str(tmp, buf));
    		os_memset(buf,0,sizeof(buf));
    		os_memset(tmp,0,sizeof(tmp));
    	}
    	fclose(userdb);
	}
	printf("=========================================================================================\n");
	return 0;
}

int user_info_getopt(int argc, char *const argv[], const char *optstring)
{
	static int optchr = 1;
	char *cp;

	if (optchr == 1) {
		if (user_optind >= argc) {
			/* all arguments processed */
			return EOF;
		}

		if (argv[user_optind][0] != '-' || argv[user_optind][1] == '\0') {
			/* no option characters */
			return EOF;
		}
	}

	if (os_strcmp(argv[user_optind], "--") == 0) {
		/* no more options */
		user_optind++;
		return EOF;
	}

	user_optopt = argv[user_optind][optchr];
	cp = os_strchr(optstring, user_optopt);
	if (cp == NULL || user_optopt == ':') {
		if (argv[user_optind][++optchr] == '\0') {
			optchr = 1;
			user_optind++;
		}
		return '?';
	}

	if (cp[1] == ':') {
		/* Argument required */
		optchr = 1;
		if (argv[user_optind][optchr + 1]) {
			/* No space between option and argument */
			user_optarg = &argv[user_optind++][optchr + 1];
		} else if (++user_optind >= argc) {
			/* option requires an argument */
			return '?';
		} else {
			/* Argument in the next argv */
			user_optarg = argv[user_optind++];
		}
	} else {
		/* No argument */
		if (argv[user_optind][++optchr] == '\0') {
			optchr = 1;
			user_optind++;
		}
		user_optarg = NULL;
	}
	return *cp;
}
static void usage(void)
{
	printf(
		"\n"
		"usage: user_cli [-a <user passwd group>] [-d <user>] [-s] [-g <group>] [-h]\n"
		"-a <user passwd group>\t\tcreate new user to database\n"
		"-d <user>\t\t\tdelete user from database\n"
		"-s\t\t\t\tshow user information\n"
		"-g <group>\t\t\tshow group information\n"
		"-h \t\t\t\thelp(show this usage text)\n");
}


int main(int argc, char *argv[])
{
	char ch;

	while((ch = user_info_getopt(argc, argv, "a:d:shg:")) != -1){
		switch(ch){
			case 'a':
				if(USER_ADD_PARAMETER_NUM == argc){
    				user_cli_cmd_add(argc-user_optind, &argv[user_optind]);
				}
				else
    				usage();
				break;
			case 'd':
				if(USER_DEL_PARAMETER_NUM == argc){
    				user_cli_cmd_del(user_optarg);
				}
				else
					usage();
				break;
			case 's':
				if(USER_SHOW_PARAMETER_NUM == argc){
    				user_cli_cmd_show();
		        }
				else
					usage();
				break;
			case 'g':
				if(USER_GROUP_SHOW_PARAMETER_NUM == argc){
				    user_group_cli_cmd_show(user_optarg);
				}
				else
					usage();
				break;
			default:
				usage();
				return -1;
		}	
	}
    return 0;
}



