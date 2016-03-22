#include <pthread.h>

#include "utils.h"
#include "tid.h"
#include "um.h"

#define UM_MAX_IPADDR_LEN 16

struct umdelaynode{
    char ipaddr[UM_MAX_IPADDR_LEN];
    uint32_t delaytime;
    unsigned char packetloss;
    unsigned char agtime;
    struct umdelaynode *next;
};

struct umdelayhead{
    struct umdelaynode *next;
};

static struct umdelayhead delaylist = {
    .next = NULL,
};

void delay_insert_ip(char *ipaddr)
{
    struct umdelaynode *pstdelayinfonode = NULL;
    struct umdelaynode *pstcurnode = NULL;

    if (strlen(ipaddr) == 0)
    {
        return;
    }
    pstcurnode = delaylist.next;
    while (NULL != pstcurnode)
    {
        if (!strncmp(ipaddr, pstcurnode->ipaddr, sizeof(pstcurnode->ipaddr)))
        {
            return;
        }
        pstcurnode = pstcurnode->next;
    }

    pstdelayinfonode = malloc(sizeof(struct umdelaynode));
    if (NULL == pstdelayinfonode)
    {
        return;
    }

    memcpy(pstdelayinfonode->ipaddr, ipaddr, sizeof(pstdelayinfonode->ipaddr));
    pstdelayinfonode->delaytime = UM_MAX_DELAYTIME;
    pstdelayinfonode->packetloss = 100;
    pstdelayinfonode->agtime = 2;
    pstdelayinfonode->next = delaylist.next;
    delaylist.next = pstdelayinfonode;
    
    return;
}

void delay_aging_delaylist(void)
{
    struct umdelaynode *pstcurnode = NULL;
    struct umdelaynode *pstprenode = NULL;

    pstcurnode = delaylist.next;
    while(pstcurnode != NULL)
    {
        pstcurnode->agtime--;
        if (pstcurnode->agtime == 0)
        {
            if (pstcurnode == delaylist.next)
            {
                delaylist.next = pstcurnode->next;
                free(pstcurnode);
                pstcurnode = delaylist.next;
                pstprenode = pstcurnode;
            }
            else
            {
                pstprenode->next = pstcurnode->next;
                free(pstcurnode);
                pstcurnode = pstprenode->next;
            }
        }
        else
        {
            pstprenode = pstcurnode;
            pstcurnode = pstcurnode->next;
        }
    }

    return;
}

void delay_update_stadelay(struct apuser *user)
{
    struct umdelaynode *pstcurnode = NULL;

    pstcurnode = delaylist.next;
    while (NULL != pstcurnode)
    {
        if (!strncmp(user->stdevinfo.ipaddr, pstcurnode->ipaddr, sizeof(user->stdevinfo.ipaddr)))
        {
            user->delaytime = pstcurnode->delaytime;
            user->packetloss = pstcurnode->packetloss;
            pstcurnode->agtime = 2;
            break;
        }
        pstcurnode = pstcurnode->next;
    }

    return;
}

void delay_clear_stadelay(void)
{
    struct umdelaynode *pstcurnode = NULL;

    pstcurnode = delaylist.next;
    while (NULL != pstcurnode)
    {
        pstcurnode->delaytime = UM_MAX_DELAYTIME;
        pstcurnode->packetloss = 100;
        pstcurnode = pstcurnode->next;
    }

    return;
}

static void delay_handle_stadelay(char *delaystr)
{
    char *address = NULL;
    char *avgdelay = NULL;
    char *packageloss = NULL;
    struct umdelaynode *pstcurnode = NULL;
    
    address = strtok(delaystr, " ");
    if (NULL != address)
    {
        avgdelay = strtok(NULL, " ");
    }
    if (NULL != avgdelay)
    {
        avgdelay = avgdelay + 1;
        packageloss = strtok(NULL, " ");
    }
    if (NULL == packageloss)
    {
        return;
    }

    pstcurnode = delaylist.next;
    while (NULL != pstcurnode)
    {
        if(!strncmp(pstcurnode->ipaddr, address, strlen(pstcurnode->ipaddr)))
        {
            pstcurnode->delaytime = (unsigned int)(1000 * atof(avgdelay));
            pstcurnode->packetloss = (unsigned char)(atoi(packageloss));
            break;
        }
        pstcurnode = pstcurnode->next;
    }

    return;
}

static void delay_get_allstadelay(void)
{
    FILE *fp = NULL;
    struct umdelaynode *pstcurnode = NULL;
    char str_tmp_cmd[SPRINT_MAX_LEN];
    char delayinfo[SPRINT_MAX_LEN];
    
    memset(str_tmp_cmd, 0, sizeof(str_tmp_cmd));

    strcpy(str_tmp_cmd,  "fping ");
    
    um_rwlock_rdlock();
    pstcurnode = delaylist.next;
    if (pstcurnode == NULL)
    {
        um_rwlock_unlock();
        return;
    }
    while (NULL != pstcurnode)
    {
        sprintf(str_tmp_cmd + strlen(str_tmp_cmd),  "%s ", pstcurnode->ipaddr);
        pstcurnode = pstcurnode->next;
    }
    um_rwlock_unlock();

    sprintf(str_tmp_cmd + strlen(str_tmp_cmd), "-c 5 -t 1000 | awk '{print $1 \" \" $8 \" \" $10}'");

    fp=popen(str_tmp_cmd,"r");
    if(fp)
    {
        um_rwlock_wrlock();
        delay_clear_stadelay();
        do
        {
            memset(delayinfo, 0, sizeof(delayinfo));
            fgets(delayinfo, sizeof(delayinfo), fp);
            delay_handle_stadelay(delayinfo);
        }
        while (0 != strlen(delayinfo));
        um_rwlock_unlock();
        pclose(fp);
    } 

    return;
}

void *delay_pthreadhandle(void *data)
{
    while (1)
    {
        sleep(5);
        delay_get_allstadelay();
    }
    
    return NULL;
}
