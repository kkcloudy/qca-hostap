#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include "limits2.h"


#define CLI_PATH  "/var/run/cli"
#define EAG_PATH  "/var/run/eag"
typedef unsigned char 		uint8_t;
typedef unsigned short 		uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long long  uint64_t;

char *
ip2str(uint32_t ip, char *str, size_t size)
{
	if (NULL == str) {
		return NULL;
	}

	memset(str, 0, size);
	snprintf(str, size-1, "%u.%u.%u.%u",
		(ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff);

	return str;
}

char *
mac2str(const uint8_t mac[6], char *str, size_t size, char separator)
{
	if (NULL == mac || NULL == str || size <= 0) {
		return NULL;
	}
	if (':' != separator && '-' != separator && '_' != separator) {
		separator = ':';
	}

	memset(str, 0, size);
	snprintf(str, size-1, "%02X%c%02X%c%02X%c%02X%c%02X%c%02X",
		mac[0], separator, mac[1], separator, mac[2], separator,
		mac[3], separator, mac[4], separator, mac[5]);

	return str;
}

char *set_cmd_string(int argc,char*argv[])
{
        char*cmd;
	int i=0;
	cmd =(char*)malloc(512);
	if(cmd == NULL)
	{
		printf("malloc fail.\n");
		return NULL;
	}
	memset(cmd,0,256);
	strcpy(cmd,argv[0]);
	for(i = 1;i < argc;i++)
	{
                strcat(cmd," ");
	      strcat(cmd,argv[i]);
	}
	//printf("cmd:%s\n",cmd);
	return cmd;
}
char *wpa_ctrl_command(int sockfd, char*cmd)
{
	   char *buf;
	   int res;
	   fd_set rfds;
	   struct timeval tv;
	   struct sockaddr_un sock_address;
	 struct sockaddr_un from={0};

	    int address_len=0;
	    int from_len=0;
	   
	   buf = (char*)malloc(40960);
	   if(buf == NULL)
	   {
                       printf("malloc fail.\n");     
		    return NULL;
	   }
	   sock_address.sun_family=AF_UNIX;
	strcpy(sock_address.sun_path,EAG_PATH);
	address_len = sizeof(struct sockaddr_un );
	from_len = sizeof(struct sockaddr_un );
	   if (sendto(sockfd, cmd, strlen(cmd), 0,(struct sockaddr *) &sock_address, address_len) < 0) {
		free(buf);
		printf("%s,%d\n",__func__,__LINE__);
		return NULL;
	}

	  while(1) {
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);
		res = select(sockfd+1, &rfds, NULL, NULL, &tv);
		
		if (res < 0){
			printf("%s,%d\n",__func__,__LINE__);
			return NULL;}
		if (FD_ISSET(sockfd, &rfds)) {
			   memset(buf,0,4096);
			res = recvfrom(sockfd, buf, 4095, 0,(struct sockaddr *) &from,&from_len);
			if (res < 0){
		  		printf("%s,%d,%s\n",__func__,__LINE__,strerror(errno));
				return NULL;}
			else
				return buf;
	        }
		else{

			printf("%s,%d\n",__func__,__LINE__);
			return NULL;}
	 }

}

static int eag_cli_cmd_send(int sockfd, char* cmd)
{
	   char *buf;
	if (cmd == NULL) {
		printf(" the cmd is NULL.\n");
		return -1;
	}
	buf = wpa_ctrl_command(sockfd, cmd);
	if(buf != NULL)
	        printf("%s\n",buf);
	free(buf);
	return 0;
}
#if 0
static int eag_cli_cmd_add_captive_interface(int sockfd, char* cmd)
{
	char *buf;
	if (cmd == NULL) {
		printf("  the cmd is NULL.\n");
		return -1;
	}
	buf = wpa_ctrl_command(sockfd, cmd);
	if(buf != NULL)
	        printf("%s\n",buf);
	return 0;
}

static int eag_cli_cmd_set_nasip(int sockfd, char* cmd)
{
	char *buf;
	if (cmd == NULL) {
		printf("  the cmd is NULL.\n");
		return -1;
	}
	buf = wpa_ctrl_command(sockfd, cmd);
	if(buf != NULL)
	        printf("%s\n",buf);
	return 0;
}

static int eag_cli_cmd_service_status(int sockfd, char* cmd)
{
	char *buf;
	if (cmd == NULL) {
		printf("  the cmd is NULL.\n");
		return -1;
	}
	buf = wpa_ctrl_command(sockfd, cmd);
	if(buf != NULL)
	        printf("%s\n",buf);
	return 0;
}
#endif


struct user_list
{
 
        uint32_t index;
	uint32_t user_ip;
	uint8_t usermac[PKT_ETH_ALEN];
	//char essid[MAX_ESSID_LENGTH];
	char username[USERNAMESIZE];
	uint32_t session_time;
	uint64_t input_octets;
	//uint32_t input_packets;
	uint64_t output_octets;
	//uint32_t output_packets;
};

void show_user_list(int sockfd,char *buf)
{ 

	unsigned int num =0; 
	int i =0;
	char ipstr[32] = "";
	char macstr[36] = "";
	char ap_macstr[36] = "";
	uint32_t hour = 0;
	uint32_t minute = 0;
	uint32_t second = 0;
	char timestr[32] = "";
	struct user_list user;
	struct sockaddr_un from={0};
            int from_len=0;
	
	
           //num = atoi(buf);
           sscanf(buf,"%d",&num);
     	printf ("user num : %d\n",num);
	printf( "%-7s %-18s %-18s %-20s %-12s %-18s %-18s \n",
				"ID", "UserName", "UserIP", "UserMAC", "SessionTime", "OutputFlow", "InputFlow");
	int res =0;
	for (i = 0 ; i < num; i++)
	{
            memset(&user,0,sizeof(user));
	    res = recvfrom(sockfd, &user, sizeof(user), 0,(struct sockaddr *) &from,&from_len);
	    ip2str(user.user_ip, ipstr, sizeof(ipstr));
              mac2str(user.usermac, macstr, sizeof(macstr), ':');
	    hour = user.session_time/3600;
	    minute = (user.session_time%3600)/60;
	    second = user.session_time%60;
	    snprintf(timestr, sizeof(timestr), "%u:%02u:%02u",hour, minute, second);
               printf("%-7d %-18s %-18s %-20s %-12s %-18llu %-18llu \n",
				i+1, user.username, ipstr, macstr,timestr, user.output_octets, user.input_octets);
  	    
	}

            return NULL;	

}

static int eag_cli_cmd_show(int sockfd,  char *cmd)
{
	char *buf;
	char argv[3][64] = {0};
	
			
	if (cmd == NULL) {
		printf("  the cmd is NULL.\n");
		return -1;
	}
	sscanf(cmd,"%s %s %s",argv[0],argv[1],argv[2]);
	buf = wpa_ctrl_command(sockfd, cmd);
	if((0 == strcmp(argv[2],"list")) || (0 == strcmp(argv[2],"list")))
	{
		show_user_list(sockfd,buf);
	}
	else if(0 == strcmp(argv[2],"ip"))
	{
	}
	else if (0 == strcmp(argv[2],"index"))
	{
	}
	else if (0 == strcmp(argv[2],"mac"))
	{
	}
	else if(0 == strcmp(argv[2],"username"))
	{
	}
	free(buf);
	return 0;
}


struct eag_cli_cmd {
	const char *cmd;
	int (*handler)(int sockfd, char *cmd);
};

static struct eag_cli_cmd eag_cli_commands[] = {
		{ "add portal_server", eag_cli_cmd_send},
		{ "del portal_server", eag_cli_cmd_send},
		{ "modify portal_server", eag_cli_cmd_send},
		{ "add captive_interface", eag_cli_cmd_send },
		{ "del captive_interface", eag_cli_cmd_send },
		{"set nasip",eag_cli_cmd_send},
		{"set local_database",eag_cli_cmd_send},
		{"add white-list ip",eag_cli_cmd_send},
		{"del white-list ip",eag_cli_cmd_send},
		{ "service", eag_cli_cmd_send},
		{ "show user", eag_cli_cmd_show },
		{NULL,NULL}

};



int main(int argc, char *argv[])
{
	int sockfd= -1;
	struct sockaddr_un sock_address;
	int address_len=0;
	char *cmd;
	struct eag_cli_cmd *match;
	int count =0;

	if(argc == 1)
		return 0;
	sockfd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
                printf("create socket fail.\n");
	      return -1;
	}

	sock_address.sun_family=AF_UNIX;
	strcpy(sock_address.sun_path, CLI_PATH);
	address_len = sizeof(sock_address);
	//printf("%d,%s\n",argc,argv[0]);
	set_cmd_string( argc-1, &argv[1]);

	
	unlink(sock_address.sun_path);
	if(bind(sockfd,(struct sockaddr *)&sock_address,address_len) < 0)
	{
                   close(sockfd);
	        unlink(sock_address.sun_path);
	        printf("socket bind fail.\n");
	        return -1; 
	}
	#if 0
	if (connect(sockfd, (struct sockaddr *) &sock_address, address_len) < 0) {
		close(sockfd);
		unlink(sock_address.sun_path);
		printf("socket connect fail\n");
		return -1;
	}
	#endif
	cmd = set_cmd_string( argc-1, &argv[1]);
	match = eag_cli_commands;
	while(match->cmd)
	{
               if(0 == strncmp(cmd,match->cmd,strlen(match->cmd)))
                {
                        match->handler(sockfd,cmd);
		    count++;
		    break;
	       }
	        match++;
	}
           if(count == 0)
		printf("Unknown command '%s'\n", cmd);
            close(sockfd);
	  unlink(CLI_PATH);
    return 0;
}



