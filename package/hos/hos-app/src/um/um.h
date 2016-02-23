#ifndef __UM_H_CC431B9A6A7A07C3356E10656BDA3BDD__
#define __UM_H_CC431B9A6A7A07C3356E10656BDA3BDD__
/******************************************************************************/
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <uci_blob.h>
#include <libubus.h>
#include <syslog.h>

#ifndef SPRINT_MAX_LEN
#define SPRINT_MAX_LEN  2048
#endif

#ifndef UM_MAX_DELAYTIME   
#define UM_MAX_DELAYTIME 9999999
#endif

#ifndef UM_HASHSIZE
#define UM_HASHSIZE         64
#endif

#define UM_HASHMASK         (UM_HASHSIZE-1)

#ifndef UM_USERCACHE
#define UM_USERCACHE        1024
#endif

#ifndef UM_TIMERMS_WIFI
#define UM_TIMERMS_WIFI     5000
#endif

#ifndef UM_TIMERMS_PORTAL
#define UM_TIMERMS_PORTAL   5000
#endif

#ifndef UM_TIMERMS_AGING
#define UM_TIMERMS_AGING    5000
#endif

#ifndef UM_TIMERMS_REPORT
#define UM_TIMERMS_REPORT   5000
#endif

#ifndef UM_AGING_TIMES
#define UM_AGING_TIMES      2
#endif

struct wifiinfo {
    uint32_t uptime;
    uint32_t livetime;
    int      signal;
    
    struct {
        uint32_t rate;
        uint64_t bytes;
        uint32_t packets;
        
        uint32_t wifirate;
    } rx;
    
    struct {
        uint32_t rate;
        uint64_t bytes;
        uint32_t packets;
        
        uint32_t retries;   /* just keep */
        uint32_t failed;    /* just keep */
        uint32_t wifirate;
    } tx;
    
    struct {
        // wpa/wpa2 info
    } sec;
};

struct portalinfo {
    uint32_t uptime;
    uint32_t livetime;
    int type;
    int state;
    int enable;
    
    struct {
        uint32_t rate;
        uint64_t bytes;
        uint32_t packets;
    } rx;
    
    struct {
        uint32_t rate;
        uint64_t bytes;
        uint32_t packets;
    } tx;
};

struct apuser {
    bool local;
    byte mac[OS_MACSIZE];
    byte ap[OS_MACSIZE];
    byte vap[OS_MACSIZE];
    
    char ifname[1+OS_IFNAMELEN]; /* wlan ifname */
    int radioid;
    int wlanid;
    uint32_t ip;

    struct devinfo stdevinfo;
    struct wifiinfo wifi;
    struct portalinfo portal;
    
    struct {
        struct hlist_node mac; /* hash node in umc.hash */
        struct hlist_node ip; /* hash node in umc.hash */
        struct list_head  list; /* list node in umc.list */
    } node;

    int aging;
    uint32_t delaytime;
    unsigned char packetloss;
    unsigned char tx_retr;
    unsigned char rx_retr;
};

static inline void
um_user_init(struct apuser *user, bool local)
{
    os_objzero(user);

    user->delaytime = UM_MAX_DELAYTIME;
    user->packetloss = 100;
    user->local = local;
    
    INIT_HLIST_NODE(&user->node.mac);
    INIT_HLIST_NODE(&user->node.ip);
    INIT_LIST_HEAD(&user->node.list);
}

typedef multi_value_t um_foreach_f(struct apuser *user, void *data);
typedef multi_value_t um_get_f(struct apuser *user, void *data);

#define UM_POLICY_INITER(_id, _name, _type) \
        [_id] = { .name = _name, .type = BLOBMSG_TYPE_##_type }
#define UM_PARAM_INITER(_policy) \
        { .params = _policy, .n_params = os_count_of(_policy) }

enum {
	UM_USER_AP,
	UM_USER_VAP,
	UM_USER_WLANID,
	UM_USER_RADIOID,
	UM_USER_MAC,
	UM_USER_IP,
	UM_USER_UPTIME,
	UM_USER_LIVETIME,
	UM_USER_SIGNAL,
	UM_USER_RX_RATE,
	UM_USER_RX_WIFIRATE,
	UM_USER_RX_BYTES,
	UM_USER_TX_RATE,
	UM_USER_TX_WIFIRATE,
	UM_USER_TX_BYTES,
	UM_USER_PORTAL_ENABLE,
	UM_USER_PORTAL_TYPE,
	UM_USER_PORTAL_STATE,
	UM_USER_DEVTYPE,
	UM_USER_HOSTNAME,
	UM_USER_OSTYPE,
	UM_USER_DEVMODEL,
	UM_USER_CPUTYPE,
	UM_USER_DELAYTIME,
	UM_USER_PACKETLOSS,
	UM_USER_RX_RETR,
    UM_USER_TX_RETR,
    UM_USER_UP_PACKET,
    UM_USER_DOWN_PACKET,
	
	UM_USER_END,
};

#define UM_USER_POLICY_INITER  { \
    UM_POLICY_INITER(UM_USER_AP,            "ap",           STRING), /* "XX:XX:XX:XX:XX:XX" */ \
    UM_POLICY_INITER(UM_USER_VAP,           "vap",          STRING), /* "XX:XX:XX:XX:XX:XX" */ \
    UM_POLICY_INITER(UM_USER_WLANID,        "wlanid",       INT32), \
    UM_POLICY_INITER(UM_USER_RADIOID,       "radioid",      INT32), \
    UM_POLICY_INITER(UM_USER_MAC,           "mac",          STRING), /* "XX:XX:XX:XX:XX:XX" */ \
    UM_POLICY_INITER(UM_USER_IP,            "ip",           STRING), /* "xxx.xxx.xxx.xxx" */ \
    UM_POLICY_INITER(UM_USER_UPTIME,        "uptime",       INT32), \
    UM_POLICY_INITER(UM_USER_LIVETIME,      "livetime",     INT32), \
    UM_POLICY_INITER(UM_USER_SIGNAL,        "signal",       INT32), \
    UM_POLICY_INITER(UM_USER_RX_RATE,       "rx_rate",      INT32), \
    UM_POLICY_INITER(UM_USER_RX_WIFIRATE,   "rx_wifirate",  INT32), \
    UM_POLICY_INITER(UM_USER_RX_BYTES,      "rx_bytes",     INT64), \
    UM_POLICY_INITER(UM_USER_TX_RATE,       "tx_rate",      INT32), \
    UM_POLICY_INITER(UM_USER_TX_WIFIRATE,   "tx_wifirate",  INT32), \
    UM_POLICY_INITER(UM_USER_TX_BYTES,      "tx_bytes",     INT64), \
    UM_POLICY_INITER(UM_USER_PORTAL_ENABLE, "portal_enable",BOOL),  \
    UM_POLICY_INITER(UM_USER_PORTAL_TYPE,   "portal_type",  STRING), /* "wifidog" */ \
    UM_POLICY_INITER(UM_USER_PORTAL_STATE,  "portal_state", STRING), /* "unknow/probation/know" */ \
    UM_POLICY_INITER(UM_USER_DEVTYPE,       "devtype",      STRING),\
    UM_POLICY_INITER(UM_USER_HOSTNAME,      "hostname",     STRING),\
    UM_POLICY_INITER(UM_USER_OSTYPE,        "ostype",       STRING),\
    UM_POLICY_INITER(UM_USER_DEVMODEL,      "devmodel",     STRING),\
    UM_POLICY_INITER(UM_USER_CPUTYPE,       "cputype",      STRING),\
    UM_POLICY_INITER(UM_USER_DELAYTIME,     "delaytime",    INT32),\
    UM_POLICY_INITER(UM_USER_PACKETLOSS,    "packetloss",   INT32),\
    UM_POLICY_INITER(UM_USER_RX_RETR,       "rx_retr",      INT32),\
    UM_POLICY_INITER(UM_USER_TX_RETR,       "tx_retr",      INT32),\
    UM_POLICY_INITER(UM_USER_UP_PACKET,     "up_package",   INT32),\
    UM_POLICY_INITER(UM_USER_DOWN_PACKET,   "down_package", INT32),\
}

enum {
    UM_PORTAL_TYPE_WIFIDOG,
    
    UM_PORTAL_TYPE_END
};

enum {
    UM_WIFIDOG_STATE_UNKNOW,
    UM_WIFIDOG_STATE_PROBATION,
    UM_WIFIDOG_STATE_KNOW,

    UM_WIFIDOG_STATE_END
};

enum {
    UM_GETUSER_LOCAL,
    
    UM_GETUSER_AP,
    UM_GETUSER_APMASK,
    
    UM_GETUSER_MAC,
    UM_GETUSER_MACMASK,
    
    UM_GETUSER_IP,
    UM_GETUSER_IPMASK,
    
    UM_GETUSER_RADIO,
    UM_GETUSER_WLAN,

    UM_GETUSER_END,
};

#define UM_GETUSER_POLICY_INITER    { \
	UM_POLICY_INITER(UM_GETUSER_LOCAL,  "local",     BOOL),    \
	UM_POLICY_INITER(UM_GETUSER_AP,     "ap",        STRING),  \
	UM_POLICY_INITER(UM_GETUSER_APMASK, "apmask",    STRING),  \
	UM_POLICY_INITER(UM_GETUSER_MAC,    "mac",       STRING),  \
	UM_POLICY_INITER(UM_GETUSER_MACMASK,"macmask",   STRING),  \
	UM_POLICY_INITER(UM_GETUSER_IP,     "ip",        STRING),  \
	UM_POLICY_INITER(UM_GETUSER_IPMASK, "ipmask",    STRING),  \
	UM_POLICY_INITER(UM_GETUSER_RADIO,  "radio",     INT32),   \
	UM_POLICY_INITER(UM_GETUSER_WLAN,   "wlan",      STRING),  \
}

#define UM_INTFPOLICY_DISABLE   0

enum {
    UM_RADIOPOLICY_DISABLE  = UM_INTFPOLICY_DISABLE,

    UM_RADIOPOLICY_END
};

#define UM_RADIOPOLICY_INITER    { \
	UM_POLICY_INITER(UM_RADIOPOLICY_DISABLE, "disable", BOOL),  \
}

enum {
    UM_WLANPOLICY_DISABLE = UM_INTFPOLICY_DISABLE,
    UM_WLANPOLICY_IFNAME,

    UM_WLANPOLICY_END
};

#define UM_WLANPOLICY_INITER    { \
	UM_POLICY_INITER(UM_WLANPOLICY_DISABLE, "disable",  BOOL), \
	UM_POLICY_INITER(UM_WLANPOLICY_IFNAME, "ifname",    STRING), \
}

struct um_timer {
    struct uloop_timeout tm;
    appkey_t akid;
    unsigned int deft;
};

#define UM_TIMER_INITER(_deft, _cb) { \
    .tm = {                         \
        .cb = _cb,                  \
    },                              \
    .deft = _deft,                  \
}

enum {
    UM_INTF_RADIO,
    UM_INTF_WLAN,

    UM_INTF_END
};

#define UM_UCI_INTF_RADIO   "wifi-device"
#define UM_UCI_INTF_WLAN    "wifi-iface"

struct um_intf {
    /*
    * uci ifname
    */
    int type;
    char ifname[1+OS_IFNAMELEN];
    int radioid;
    int wlanid;
    
    struct list_head node;
};

struct um_uci {
    struct uci_blob_param_list param;
    struct list_head cfg;
    struct list_head tmp;
    char *uci_type;
};

struct um_control {
    byte basemac[OS_MACSIZE]; /* local ap's base mac */

    struct {
        struct hlist_head mac[UM_HASHSIZE];
        struct hlist_head ip[UM_HASHSIZE];
        struct list_head list;
        uint32_t count;
    } head;

    struct ubus_context *ctx;
    char *path;
    
    struct {
        struct um_timer wifi;
        struct um_timer portal;
        struct um_timer aging;
        struct um_timer report;
        appkey_t agtimes;
    } timer;
    
    struct {
        char *wifidog[UM_WIFIDOG_STATE_END];
        
        char *type[UM_PORTAL_TYPE_END];
        char **state[UM_PORTAL_TYPE_END];
    } portal;
    
    struct {
        struct {
            appkey_t akid;
            unsigned int deft;
        } new, delete, update, report, devinfo;
    } ev;
    
    struct {
        struct blobmsg_policy getuser[UM_GETUSER_END];
        struct blobmsg_policy user[UM_USER_END];

        struct blobmsg_policy radio[UM_RADIOPOLICY_END];
        struct blobmsg_policy wlan[UM_WLANPOLICY_END];
    } policy;

    struct {
        struct uci_context *ctx;

        struct um_uci radio;
        struct um_uci wlan;
    } uci;
    
    struct {
        struct ubus_object object;
        struct ubus_object_type type;
        struct ubus_method *methods;
        struct ubus_subscriber subscriber;
    } obj;

    struct {
        appkey_t main;
        appkey_t uci;
        appkey_t tid;
        appkey_t ubus;
        appkey_t user;
        appkey_t l2timer;
        appkey_t error;
        appkey_t warning;
        appkey_t trace;
    } debug;
};

struct user_filter {
    /*
    * true: just match local user
    * false: match all user
    */
    bool local;
    
    byte ap[OS_MACSIZE];
    byte apmask[OS_MACSIZE];  /* zero, not use ap as filter */
    
    byte mac[OS_MACSIZE];
    byte macmask[OS_MACSIZE]; /* zero, not use mac as filter */
    
    uint32_t ip;
    uint32_t ipmask;/* zero, not use ip as filter */
    
    int radioid;    /* <0, not use radioid as filter */
    int wlanid;     /* <0, not use wlanid as filter */
};

#define USER_FILTER_INITER(_local)  { \
    .local  = _local,   \
    .radioid= -1,       \
    .wlanid = -1,       \
}
/******************************************************************************/
extern int
um_uci_load(void);
/******************************************************************************/
extern int
um_ubus_handle_restart(
    struct ubus_context *ctx, 
    struct ubus_object *obj,
    struct ubus_request_data *req, 
    const char *method,
    struct blob_attr *msg
);

extern int
um_ubus_handle_reload(
    struct ubus_context *ctx, 
    struct ubus_object *obj,
    struct ubus_request_data *req, 
    const char *method,
    struct blob_attr *msg
);

extern int
um_ubus_handle_getuser(
    struct ubus_context *ctx, 
    struct ubus_object *obj,
    struct ubus_request_data *req, 
    const char *method,
    struct blob_attr *msg
);

extern int
um_ubus_report(void);

extern void
um_ubus_insert_cb(struct apuser *user);

extern void
um_ubus_remove_cb(struct apuser *user);

extern void
um_ubus_devinfo_cb(struct apuser *user);

extern void
um_ubus_update_cb(struct apuser *old, struct apuser *new);

typedef void um_user_update_f(bool created, struct apuser *dst, struct apuser *src);

extern int 
um_ubus_init(char *path);

extern void
um_ubus_fini(void);
/******************************************************************************/
extern void
__um_user_dump(struct apuser *user, char *action);

#define um_user_dump(user, action)  do{ \
    if (appkey_get(umc.debug.user, 0)) {   \
        __um_user_dump(user, action);   \
    }                                   \
}while(0)

extern struct apuser *
um_user_update(struct apuser *info, um_user_update_f *update);

extern int
um_user_foreach(um_foreach_f *foreach, void *data);

extern struct apuser *
um_user_getbymac(byte mac[]);

extern struct apuser *
um_user_getbyip(uint32_t ip);

extern int
um_user_getby(struct user_filter *filter, um_get_f *get, void *data);

extern int
um_user_del(struct apuser *user);

extern int
um_user_delby(struct user_filter *filter);

extern int
um_create_stabuf(void);
/******************************************************************************/
extern int
um_l2user_timer(void);

extern int
um_l3user_timer(void);

extern struct um_control umc;
extern struct blob_buf b;

static inline void
um_blob_buf_init(void)
{
    blob_buf_init(&b, 0);
}

static inline int
um_agtimes(void)
{
    return (int)appkey_get(umc.timer.agtimes, UM_AGING_TIMES);
}

void *delay_pthreadhandle(void *data);
void delay_update_stadelay(struct apuser *user);
void delay_aging_delaylist(void);
void delay_insert_ip(char *ipaddr);
int um_rwlock_rdlock(void);
int um_rwlock_wrlock(void);
int um_rwlock_unlock(void);

/*
* just for single thread(multi-thread unsafed)
*/
extern char *
um_macstring(byte mac[]);

#define um_is_ev_enable(_var)       appkey_get(umc.ev._var.akid, umc.ev._var.deft)
#define um_user_policy_name(id)     umc.policy.user[id].name

#define um_open_table(name)         blobmsg_open_table(&b, name)
#define um_open_array(name)         blobmsg_open_array(&b, name)
#define um_close_table(handle)      blobmsg_close_table(&b, handle)
#define um_close_array(handle)      blobmsg_close_array(&b, handle)

#define um_add_bool(name, val)      blobmsg_add_u8(&b, name, val)
#define um_add_string(name, val)    blobmsg_add_string(&b, name, val)
#define um_add_u32(name, val)       blobmsg_add_u32(&b, name, val)
#define um_add_u64(name, val)       blobmsg_add_u64(&b, name, val)

#define um_user_add_bool(id, val)   um_add_bool(um_user_policy_name(id), val)
#define um_user_add_string(id, val) um_add_string(um_user_policy_name(id), val)
#define um_user_add_u32(id, val)    um_add_u32(um_user_policy_name(id), val)
#define um_user_add_u64(id, val)    um_add_u64(um_user_policy_name(id), val)
#define um_user_add_macstring(id, mac)  um_user_add_string(id, um_macstring(mac))

#define um_portal_type(_type)           umc.portal.type[_type]
#define um_portal_state(_type, _state)  umc.portal.state[_type][_state]

#define um_user_portal_type(_user)      um_portal_type((_user)->portal.type)
#define um_user_portal_state(_user)     um_portal_state((_user)->portal.type, (_user)->portal.state)

#define um_ubus_send_reply(ctx, req)    ubus_send_reply(ctx, req, b.head)

/******************************************************************************/
#define um_debug_waring(var, fmt, args...)      do{ \
    if ((appkey_get(umc.debug.var, 0)) && (appkey_get(umc.debug.trace, 0) || appkey_get(umc.debug.warning, 0))) {         \
        printf(fmt, ##args);                    \
        printf("\r\n");                         \
        openlog("um", 0, LOG_DAEMON);          \
        syslog(LOG_WARNING, fmt, ##args);         \
        closelog();                            \
    }                                           \
}while(0)

#define um_debug_error(var, fmt, args...)   do{ \
    if (appkey_get(umc.debug.var, 0) && (appkey_get(umc.debug.error, 0) || appkey_get(umc.debug.warning, 0) || appkey_get(umc.debug.trace, 0))) {         \
        printf(fmt, ##args);                    \
        printf("\r\n");                         \
        openlog("um", 0, LOG_DAEMON);          \
        syslog(LOG_ERR, fmt, ##args);           \
        closelog();                             \
    }                                           \
}while(0)

#define um_debug_trace(var, fmt, args...)   do{ \
    if (appkey_get(umc.debug.var, 0) && appkey_get(umc.debug.trace, 0)) {         \
        printf(fmt, ##args);                    \
        printf("\r\n");                         \
   	    openlog("um", 0, LOG_DAEMON);          \
        syslog(LOG_DEBUG, fmt, ##args);         \
        closelog();                             \
    }                                           \
}while(0)

#define debug_main_waring(fmt, args...)          um_debug_ok(main, fmt, ##args)
#define debug_main_error(fmt, args...)       um_debug_error(main, fmt, ##args)
#define debug_main_trace(fmt, args...)       um_debug_trace(main, fmt, ##args)

#define debug_uci_waring(fmt, args...)          um_debug_waring(uci, fmt, ##args)
#define debug_uci_error(fmt, args...)       um_debug_error(uci, fmt, ##args)
#define debug_uci_trace(fmt, args...)       um_debug_trace(uci, fmt, ##args)

#define debug_tid_waring(fmt, args...)          um_debug_waring(tid, fmt, ##args)
#define debug_tid_error(fmt, args...)       um_debug_error(tid, fmt, ##args)
#define debug_tid_trace(fmt, args...)       um_debug_trace(tid, fmt, ##args)

#define debug_ubus_waring(fmt, args...)         um_debug_waring(ubus, fmt, ##args)
#define debug_ubus_error(fmt, args...)      um_debug_error(ubus, fmt, ##args)
#define debug_ubus_trace(fmt, args...)      um_debug_trace(ubus, fmt, ##args)

#define debug_user_waring(fmt, args...)         um_debug_waring(user, fmt, ##args)
#define debug_user_error(fmt, args...)      um_debug_error(user, fmt, ##args)
#define debug_user_trace(fmt, args...)      um_debug_trace(user, fmt, ##args)

#define debug_l2timer_waring(fmt, args...)      um_debug_waring(l2timer, fmt, ##args)
#define debug_l2timer_error(fmt, args...)   um_debug_error(l2timer, fmt, ##args)
#define debug_l2timer_trace(fmt, args...)   um_debug_trace(l2timer, fmt, ##args)
/******************************************************************************/
#endif /* __UM_H_CC431B9A6A7A07C3356E10656BDA3BDD__ */
