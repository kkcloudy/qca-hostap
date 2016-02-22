#include "utils.h"
#include "tid.h"
#include "um.h"

static inline int
hashbuf(byte *buf, int len, int mask)
{
    int i;
    int sum = 0;
    
    for (i=0; i<len; i++) {
        sum += (int)buf[i];
    }

    return sum & mask;
}

static inline int
hashmac(byte mac[])
{
    return hashbuf(mac, OS_MACSIZE, UM_HASHMASK);
}

static inline int
haship(uint32_t ip)
{
    return hashbuf((byte *)&ip, sizeof(ip), UM_HASHMASK);
}

static inline bool
in_list(struct list_head *node)
{
    return  (node->next && node->prev) && false==list_empty(node);
}

static inline int
__remove(struct apuser *user, void (*cb)(struct apuser *user))
{
    if (NULL==user) {
        return -EKEYNULL;
    }
    /*
    * not in list
    */
    else if (false==in_list(&user->node.list)) {
        debug_user_trace("[um]:__remove nothing(not in list)");
        
        return 0;
    }
    
    list_del(&user->node.list);
    if (is_good_mac(user->mac)) {
        hlist_del_init(&user->node.mac);
    }
    if (user->ip) {
        hlist_del_init(&user->node.ip);
    }
    umc.head.count--;

    if (cb) {
        cb(user);
    }

    return 0;
}

static inline int
__insert(struct apuser *user, void (*cb)(struct apuser *user))
{
    char *action;

	debug_user_trace( "[um]:__insert vap addr : %02x:%02x:%02x:%02x:%02x:%02x", user->vap[0],user->vap[1] ,user->vap[2] ,user->vap[3] ,user->vap[4] ,user->vap[5]);

    
    if (NULL==user) {
        return -EKEYNULL;
    }
    /*
    * have in list
    */
    else if (in_list(&user->node.list)) {
        return -EINLIST;
    }
        
    list_add(&user->node.list, &umc.head.list);
    if (is_good_mac(user->mac)) {
        hlist_add_head(&user->node.mac, &umc.head.mac[hashmac(user->mac)]);
    }
    if (user->ip) {
        hlist_add_head(&user->node.ip,  &umc.head.ip[haship(user->ip)]);
    }
    umc.head.count++;

    if (cb) {
        cb(user);

        action = "create";
    } else {
        action = "update";
    }

    debug_user_trace("[um]:%s user, count(%d)", action, umc.head.count);
    um_user_dump(user, action);
    
    return 0;
}

static struct apuser *
__create(byte mac[])
{
    struct apuser *user = (struct apuser *)os_malloc(sizeof(*user));
    if (NULL==user) {
        return NULL;
    }
    
    um_user_init(user, true);
    os_maccpy(user->mac, mac);
    user->wifi.uptime = time(NULL);
    
    return user;
}

void
__um_user_dump(struct apuser *user, char *action)
{
    debug_user_trace("[um]: =====%s user begin======", action);

	debug_user_trace("[um]: __um_user_dump vap addr : %02x:%02x:%02x:%02x:%02x:%02x\n",user->vap[0],user->vap[1] ,user->vap[2] ,user->vap[3] ,user->vap[4] ,user->vap[5]);

    debug_user_trace("\t[um]: ap            = %s",  um_macstring(user->ap));
    debug_user_trace("\t[um]: vap           = %s",  um_macstring(user->vap));
    debug_user_trace("\t[um]: mac           = %s",  um_macstring(user->mac));
    debug_user_trace("\t[um]: ip            = %s",  user->stdevinfo.ipaddr);
    debug_user_trace("\t[um]: ifname        = %s",  user->ifname);
    debug_user_trace("\t[um]: radioid       = %d",  user->radioid);
    debug_user_trace("\t[um]: wlanid        = %d",  user->wlanid);
    debug_user_trace("\t[um]: uptime        = %u",  user->wifi.uptime);
	debug_user_trace("\t[um]: livetime      = %u",  user->wifi.livetime);
    debug_user_trace("\t[um]: rx.bytes      = %llu",user->wifi.rx.bytes);
	debug_user_trace("\t[um]: rx.packets    = %u",  user->wifi.rx.packets);
	debug_user_trace("\t[um]: rx.rate       = %u",  user->wifi.rx.rate);
    debug_user_trace("\t[um]: rx.wifirate   = %u",  user->wifi.rx.wifirate);
    debug_user_trace("\t[um]: tx.bytes      = %llu",user->wifi.tx.bytes);
	debug_user_trace("\t[um]: tx.packets    = %u",  user->wifi.tx.packets);	
	debug_user_trace("\t[um]: tx.rate       = %u",  user->wifi.tx.rate);
  	debug_user_trace("\t[um]: tx.wifirate   = %u",  user->wifi.tx.wifirate);
	debug_user_trace("\t[um]: portal.state  = %d",  user->portal.state);	
	debug_user_trace("\t[um]: portal.type   = %d",  user->portal.type);
    debug_user_trace("\t[um]: portal.enable = %d",  user->portal.enable);
	debug_user_trace("\t[um]: portal.state  = %s",  um_user_portal_state(user));	
	debug_user_trace("\t[um]: portal.type   = %s",  um_user_portal_type(user));
    debug_user_trace("\t[um]: hostname      = %s",  user->stdevinfo.hostname);
    debug_user_trace("\t[um]: devtype       = %s",  user->stdevinfo.devtype);
    debug_user_trace("\t[um]: ostype        = %s",  user->stdevinfo.ostype);
    debug_user_trace("\t[um]: cputype       = %s",  user->stdevinfo.cputype);
    debug_user_trace("\t[um]: devmodel      = %s",  user->stdevinfo.devmodel);
    debug_user_trace("\t[um]: delaytime     = %u",  user->delaytime);
    debug_user_trace("\t[um]: packetloss    = %u",  user->packetloss);
    debug_user_trace("\t[um]: rx_retr       = %u",  user->rx_retr);
    debug_user_trace("\t[um]: tx_retr       = %u",  user->tx_retr);

    debug_user_trace("[um]: =====%s user end======", action);

    return;
}

static int um_devinfo_update(struct devinfo *pstdevinfo, const char *mac)
{
    struct devinfo stdevinfo;
    int ret = -1;
    int flag = -1;

    memset(&stdevinfo, 0, sizeof(stdevinfo));

    tid_rwlock_wrlock();
    ret = tid_get_devinfo(&stdevinfo, mac);
    tid_rwlock_unlock();
    if (ret == 0)
    {
        if ((stdevinfo.hostname[0] != 0) && (0 != strcasecmp(pstdevinfo->hostname, stdevinfo.hostname)))
        {
            memcpy(pstdevinfo->hostname, stdevinfo.hostname, sizeof(pstdevinfo->hostname));
            flag = 0;
        }
        if ((stdevinfo.cputype[0] != 0) && (0 != strcasecmp(pstdevinfo->cputype, stdevinfo.cputype)))
        {
            memcpy(pstdevinfo->cputype, stdevinfo.cputype, sizeof(pstdevinfo->cputype));
            flag = 0;
        }
        if ((stdevinfo.devtype[0] != 0) && (0 != strcasecmp(pstdevinfo->devtype, stdevinfo.devtype)))
        {
            memcpy(pstdevinfo->devtype, stdevinfo.devtype, sizeof(pstdevinfo->devtype));
            flag = 0;
        }
        if ((stdevinfo.devmodel[0] != 0) && (0 != strcasecmp(pstdevinfo->devmodel, stdevinfo.devmodel)))
        {
            memcpy(pstdevinfo->devmodel, stdevinfo.devmodel, sizeof(pstdevinfo->devmodel));
            flag = 0;
        }
        if ((stdevinfo.ostype[0] != 0) && (0 != strcasecmp(pstdevinfo->ostype, stdevinfo.ostype)))
        {
            memcpy(pstdevinfo->ostype, stdevinfo.ostype, sizeof(pstdevinfo->ostype));
            flag = 0;
        }
        if ((stdevinfo.mac[0] != 0) && (0 != strcasecmp(pstdevinfo->mac, stdevinfo.mac)))
        {
            memcpy(pstdevinfo->mac, stdevinfo.mac, sizeof(pstdevinfo->mac));
            flag = 0;
        }
        if ((stdevinfo.ipaddr[0] != 0) && (0 != strcasecmp(pstdevinfo->ipaddr, stdevinfo.ipaddr)))
        {
            memcpy(pstdevinfo->ipaddr, stdevinfo.ipaddr, sizeof(pstdevinfo->ipaddr));
            flag = 0;
        }
    }
    
    return flag;
}

struct apuser *
um_user_update(struct apuser *info, um_user_update_f *update)
{
    struct apuser *user = NULL;
    bool created = false;
    int devupdate = -1;

	debug_user_trace( "[um]:um_user_update vap addr : %02x:%02x:%02x:%02x:%02x:%02x\n",info->vap[0],info->vap[1] ,info->vap[2] ,info->vap[3] ,info->vap[4] ,info->vap[5]);
    
    /*
    * if no found, create new
    */
    user = um_user_getbymac(info->mac);
    if (NULL==user) {
        user = __create(info->mac);
        if (NULL==user) {
            return NULL;
        }
        created = true;
    }
    
    /*
    * maybe update hash key(user mac/ip)
    *   so, remove it first
    */
    __remove(user, NULL);
    (*update)(created, user, info);
    devupdate = um_devinfo_update(&user->stdevinfo, um_macstring(user->mac));
    um_rwlock_rdlock();
    delay_insert_ip(user->stdevinfo.ipaddr);
    delay_update_stadelay(user);
    um_rwlock_unlock();
    __insert(user, created?um_ubus_insert_cb:NULL);
    um_ubus_devinfo_cb(user);

    /*
    * reset aging
    */
    user->aging = um_agtimes();
    
    return user;
}

int
um_user_foreach(um_foreach_f *foreach, void *data)
{
    multi_value_u mv;
    struct apuser *user, *n;
    
    list_for_each_entry_safe(user, n, &umc.head.list, node.list) {
        mv.value = (*foreach)(user, data);
        if (mv2_is_break(mv)) {
            return mv2_result(mv);
        }
    }
    
    return 0;
}

struct apuser *
um_user_getbymac(byte mac[])
{
    struct apuser *user;
    struct hlist_head *head = &umc.head.mac[hashmac(mac)];
    
    hlist_for_each_entry(user, head, node.mac) {
        if (os_maceq(user->mac, mac)) {
            return user;
        }
    }

    return NULL;
}

struct apuser *
um_user_getbyip(uint32_t ip)
{
    struct apuser *user;
    struct hlist_head *head = &umc.head.ip[haship(ip)];
    
    hlist_for_each_entry(user, head, node.ip) {
        if (user->ip==ip) {
            return user;
        }
    }

    return NULL;
}

int
um_user_del(struct apuser *user)
{
    int ret = -1;

    ret = __remove(user, um_ubus_remove_cb);
    if (user != NULL)
    {
        free(user);
    }
    
    return ret;
}

static inline bool
macmatch(byte umac[], byte fmac[], byte mask[])
{
    if (is_good_mac(fmac)) {
        if (is_zero_mac(mask)) {
            /*
            * mac NOT zero
            * macmask zero
            *
            * use mac filter
            */
            if (false==os_maceq(umac, fmac)) {
                return false;
            }
        } else {
            /*
            * mac NOT zero
            * macmask NOT zero
            *
            * use mac/macmask filter
            */
            if (false==os_macmaskmach(umac, fmac, mask)) {
                return false;
            }
        }
    }

    return true;
}


static inline bool
ipmatch(unsigned int uip, unsigned int fip, unsigned int mask)
{
    if (fip) {
        if (0==mask) {
            /*
            * ip NOT zero
            * ipmask zero
            *
            * use ip filter
            */
            if (uip != fip) {
                return false;
            }
        } else {
            /*
            * ip NOT zero
            * ipmask NOT zero
            *
            * use ip/ipmask filter
            */
            if (false==os_ipmatch(uip, fip, mask)) {
                return false;
            }
        }
    }

    return true;
}

static bool
match(struct apuser *user, struct user_filter *filter)
{
    /* local not matched */
    if (filter->local && false==user->local) {
        return false;
    }
    
    if (false==macmatch(user->mac, filter->mac, filter->macmask)) {
        return false;
    }
    
    if (false==macmatch(user->ap, filter->ap, filter->apmask)) {
        return false;
    }
    
    if (false==ipmatch(user->ip, filter->ip, filter->ipmask)) {
        return false;
    }
    
    if (filter->radioid>=0 && user->radioid!=filter->radioid) {
        return false;
    }

    if (filter->wlanid>=0 && user->wlanid!=filter->wlanid) {
        return false;
    }

    /* all matched */
    return true;
}

static multi_value_t
delby_cb(struct apuser *user, void *data)
{
    struct user_filter *filter = (struct user_filter *)data;

    if (match(user, filter)) {
        __remove(user, um_ubus_remove_cb);
        if (NULL != user)
        {
            free(user);
        }
    }

    return mv2_OK;
}

int
um_user_delby(struct user_filter *filter)
{
    return um_user_foreach(delby_cb, filter);
}

static multi_value_t
getby_cb(struct apuser *user, void *data)
{
    void **param = (void **)data;
    struct user_filter *filter = (struct user_filter *)param[0];
    um_get_f *get = (um_get_f *)param[1];
    void *arg = param[2];
    
    if (match(user, filter)) {
        return (*get)(user, arg);
    } else {
        return mv2_OK;
    }
}

int
um_user_getby(struct user_filter *filter, um_get_f *get, void *data)
{
    void *param[] = {
        (void *)filter,
        (void *)get,
        (void *)data,
    };
    
    return um_user_foreach(getby_cb, param);
}

char *
um_macstring(byte mac[])
{
    static char macstring[1+MACSTRINGLEN_L];

    os_macsaprintf(mac, macstring, ':');

    return macstring;
}

/******************************************************************************/
