#ifndef __AT_CONNECT_CTL_H__
#define __AT_CONNECT_CTL_H__
#include <at_user_mgmt.h> 

extern int connect_to_best_swith;
extern int connect_to_best_debug;
extern int inactive_time;
void set_connect_to_best(int value);
int  get_connect_to_best(void);
void set_connect_balance(int value);
int get_connect_balance(void);
void set_connect_to_best_debug(int value);
int  get_connect_to_best_debug(void);
void set_max_dv(int value);
int  get_max_dv(void);
void set_inactive_time(int value);
int get_inactive_time(void);
void set_wating_time(int value);
int get_wating_time(void);
int  join5g(struct ieee80211com *ic, struct ieee80211vap *vap,struct ieee80211_node * ni, wbuf_t wbuf, struct userinfo_table * user);
void check_slow_connect(wbuf_t wbuf,struct userinfo_table * user);
int  connect_to_best(wbuf_t wbuf,struct ieee80211vap *vap,struct ieee80211_node * ni,struct userinfo_table * user);
int get_sta_mgmt_behavior(wbuf_t wbuf,struct ieee80211com *ic,struct userinfo_table *user);
int check_probe(struct ieee80211_node *ni, wbuf_t wbuf, int subtype);
#endif
