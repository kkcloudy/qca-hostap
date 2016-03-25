#ifndef _EAG_IPINFO_H_
#define _EAG_IPINFO_H_

#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#define MAX_MACADDR_LEN		6
#define MAX_IPADDR_LEN		32

struct fdb_entry
{
	uint8_t mac_addr[6];
	uint16_t port_no;
	unsigned char is_local;
	struct timeval ageing_timer_value;
};
#if 0
int eag_ipneigh_init();
int eag_ipneigh_uninit();
int eag_iproute_init();
int eag_iproute_uninit();
int arp_ipneigh(char *const interface, size_t n, unsigned char *const mac, const unsigned long ip);
int ip_interface(const unsigned long ip, char *const interface, size_t n);
#endif
int brctl_show(char * mac,char * brname,char *intf);

int get_vlanid_by_intf(const char *intf );


int 
eag_ipinfo_get(char * const intf, size_t n, unsigned char * const mac, uint32_t ip);

int
eag_ipinfo_init();

int
eag_ipinfo_exit();


#endif

