/******************************************************************************
  文 件 名   : tid.c
  作    者   : wenjue
  生成日期   : 2014年11月19日
  功能描述   : um模块接收、存储、维护、删除设备信息
******************************************************************************/
#include <pthread.h>

#include "utils.h"
#include "tid.h"
#include "um.h"

#define ITD_PORT 5600
#define TID_RECV_BUF_MAXLEN 256

static struct devinfohead *g_pstdevinfohead = NULL;
/*****************************************************************************
 函 数 名  : tid_rwlock_rdlock
 功能描述  : 读锁定设备信息链表
 输入参数  : 无
 输出参数  : 无
 返 回 值  : int == 0 返回成功
                 != 0 返回失败
 作   者   : wenjue
*****************************************************************************/
int tid_rwlock_rdlock(void)
{
    return pthread_rwlock_rdlock(&(g_pstdevinfohead->rw_lock));
}

/*****************************************************************************
 函 数 名  : tid_rwlock_wrlock
 功能描述  : 写锁定设备信息链表
 输入参数  : 无
 输出参数  : 无
 返 回 值  : int == 0 返回成功
                 != 0 返回失败
 作   者   : wenjue
*****************************************************************************/
int tid_rwlock_wrlock(void)
{
    return pthread_rwlock_wrlock(&(g_pstdevinfohead->rw_lock));
}

/*****************************************************************************
 函 数 名  : tid_rwlock_unlock
 功能描述  : 解锁设备信息链表
 输入参数  : 无
 输出参数  : 无
 返 回 值  : int == 0 返回成功
                 != 0 返回失败
 作   者   : wenjue
*****************************************************************************/
int tid_rwlock_unlock(void)
{
    return pthread_rwlock_unlock(&(g_pstdevinfohead->rw_lock));
}

/*****************************************************************************
 函 数 名  : tid_init_devinfohead
 功能描述  : 初始化链表头
 输入参数  : 无
 输出参数  : 无
 返 回 值  : int == 0 返回成功
                 != 0 返回失败
 作   者   : wenjue
*****************************************************************************/
static int tid_init_devinfohead(void)
{
    int ret = -1;
    
    if (NULL == g_pstdevinfohead)
    {
        g_pstdevinfohead = malloc(sizeof(struct devinfohead));
        if (NULL != g_pstdevinfohead)
        {
            g_pstdevinfohead->next = NULL;
            ret = pthread_rwlock_init(&(g_pstdevinfohead->rw_lock), NULL);
        }
    }
    
    return ret;
}

/*****************************************************************************
 函 数 名  : tid_fini_devinfohead
 功能描述  : 去初始化链表头
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static void tid_fini_devinfohead(void)
{
    if (NULL != g_pstdevinfohead)
    {
        pthread_rwlock_destroy(&(g_pstdevinfohead->rw_lock));
        free(g_pstdevinfohead);
        g_pstdevinfohead = NULL;
    }

    return;
}

/*****************************************************************************
 函 数 名  : tid_add_devinfonode
 功能描述  : 添加一个设备信息节点
 输入参数  : const struct devinfo *pstdevinfo 设备信息结构
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static void tid_add_devinfonode(const struct devinfo *pstdevinfo)
{
    struct devinfonode *pstdevinfonode = NULL;

    if (NULL == pstdevinfo || NULL == g_pstdevinfohead)
    {
        return;
    }

    pstdevinfonode = malloc(sizeof(struct devinfonode));
    if (NULL == pstdevinfonode)
    {
        return;
    }
    memcpy(&pstdevinfonode->stdevinfo, pstdevinfo, sizeof(pstdevinfonode->stdevinfo));
    pstdevinfonode->aging = UM_AGING_TIMES;
    if (g_pstdevinfohead->next != NULL)
    {
        g_pstdevinfohead->next->prev = pstdevinfonode;
    }
    pstdevinfonode->next = g_pstdevinfohead->next;
    pstdevinfonode->prev = NULL;
    g_pstdevinfohead->next = pstdevinfonode;

    return;
}

/*****************************************************************************
 函 数 名  : tid_update_devinfonode
 功能描述  : 更新设备信息链表，判断老化字段aging，若长时间没访问某个设备信息，
             则删除此设备信息
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
void tid_update_devinfonode(void)
{
    struct devinfonode *pstcurnode = NULL;

    if (NULL == g_pstdevinfohead)
    {
        return;
    }

    pstcurnode = g_pstdevinfohead->next;
    while(pstcurnode != NULL)
    {
        if (pstcurnode->aging <= 0)
        {
            if (pstcurnode->prev == NULL && pstcurnode->next == NULL)
            {
                g_pstdevinfohead->next = NULL;
            }
            else if (pstcurnode->prev == NULL)
            {
                g_pstdevinfohead->next = pstcurnode->next;
                pstcurnode->next->prev = NULL;
            }
            else if (pstcurnode->next == NULL)
            {
                pstcurnode->prev->next = NULL;
            }
            else
            {
                pstcurnode->prev->next = pstcurnode->next;
                pstcurnode->next->prev = pstcurnode->prev;
            }
            free(pstcurnode);
            pstcurnode = NULL;
            break;
        }
        pstcurnode->aging--;
        pstcurnode = pstcurnode->next;
    }

    return;
}

/*****************************************************************************
 函 数 名  : tid_get_devinfo
 功能描述  : 获取设备信息
 输入参数  : const char *mac，标识设备信息的MAC地址
 输出参数  : struct devinfo *pstdevinfo， 获取得到的设备信息缓存
             注意，此传出参数需调用者提供空间
 返 回 值  : int == 0 获取成功
             int != 0 获取失败
 作   者   : wenjue
*****************************************************************************/
int tid_get_devinfo(struct devinfo *pstdevinfo, const char *mac)
{
    struct devinfonode *pstcurnode = NULL;
    int ret = -1;

    if (NULL == g_pstdevinfohead || NULL == mac || NULL == pstdevinfo)
    {
        return ret;
    }

    pstcurnode = g_pstdevinfohead->next;
    while(pstcurnode != NULL)
    {
        if (0 == strcasecmp(pstcurnode->stdevinfo.mac, mac))
        {
            memcpy(pstdevinfo, &(pstcurnode->stdevinfo), sizeof(struct devinfo));
            pstcurnode->aging = UM_AGING_TIMES;
            ret = 0;
            break;
        }
        pstcurnode = pstcurnode->next;
    }

    return ret;
}

/*****************************************************************************
 函 数 名  : tid_modify_devinfo
 功能描述  : 修改某个设备信息
 输入参数  : const struct devinfo *pstdevinfo，包含设备信息修改的内容
 输出参数  : 无
 返 回 值  : int == 0 连接表存在此设备信息，修改成功
             int != 0 链表中不存在此设备信息，修改失败
             注意，若修改内容与链表中的设备信息相同，返回成功
 作   者   : wenjue
*****************************************************************************/
static int tid_modify_devinfo(const struct devinfo *pstdevinfo)
{
    struct devinfonode *pstcurnode = NULL;
    int ret = -1;

    if (NULL == g_pstdevinfohead || NULL == pstdevinfo)
    {
        return ret;
    }

    pstcurnode = g_pstdevinfohead->next;
    while(pstcurnode != NULL)
    {
        if (0 == strcasecmp(pstcurnode->stdevinfo.mac, pstdevinfo->mac))
        {
            if (pstdevinfo->hostname[0] != 0)
            {
                memcpy(pstcurnode->stdevinfo.hostname, pstdevinfo->hostname, sizeof(pstcurnode->stdevinfo.hostname));
            }
            if (pstdevinfo->devtype[0] != 0)
            {
               memcpy(pstcurnode->stdevinfo.devtype, pstdevinfo->devtype, sizeof(pstcurnode->stdevinfo.devtype));
            }
            if (pstdevinfo->devmodel[0] != 0)
            {
                memcpy(pstcurnode->stdevinfo.devmodel, pstdevinfo->devmodel, sizeof(pstcurnode->stdevinfo.devmodel));
            }
            if (pstdevinfo->cputype[0] != 0)
            {
                memcpy(pstcurnode->stdevinfo.cputype, pstdevinfo->cputype, sizeof(pstcurnode->stdevinfo.cputype));
            }
            if (pstdevinfo->ostype[0] != 0)
            {
                memcpy(pstcurnode->stdevinfo.ostype, pstdevinfo->ostype, sizeof(pstcurnode->stdevinfo.ostype));
            }
            if (pstdevinfo->ipaddr[0] != 0)
            {
                memcpy(pstcurnode->stdevinfo.ipaddr, pstdevinfo->ipaddr, sizeof(pstcurnode->stdevinfo.ipaddr));
            }
            ret = 0;
            pstcurnode->aging = UM_AGING_TIMES;
            break;
        }
        pstcurnode = pstcurnode->next;
    }
    
    return ret;
}

/*****************************************************************************
 函 数 名  : tid_destroy_devinfo
 功能描述  : 销毁整个设备信息链表
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
void tid_destroy_devinfo(void)
{
    struct devinfonode *pstcurnode = NULL;
    struct devinfonode *freenode = NULL;

    if (NULL == g_pstdevinfohead)
    {
        return;
    }

    pstcurnode = g_pstdevinfohead->next;
    while(pstcurnode != NULL)
    {
        freenode = pstcurnode;
        pstcurnode = pstcurnode->next;
        free(freenode);
    }
    if (NULL != pstcurnode)
    {
        free(pstcurnode);
    }
    
    return;
}


/*****************************************************************************
 函 数 名  : tid_pthreadhandle
 功能描述  : um模块的线程处理函数，用来收集并存储设备信息
 输入参数  : void *data，线程处理函数的数据参数
 输出参数  : 无
 返 回 值  : void *线程处理函数返回值
 作   者   : wenjue
*****************************************************************************/
void *tid_pthreadhandle(void *data)
{
    struct sockaddr_in serv_addr;
    struct devinfo *pdevinfo = NULL;
    char buf[TID_RECV_BUF_MAXLEN] = {0};
    int socketfd = -1;
    int recvlen = 0;
    int ret = -1;
    
    if((socketfd = socket(AF_INET,SOCK_DGRAM,0)) < 0)
    {
        debug_tid_error("[um]: socket create failed, um exit!\r\n");     
        exit(1);
    } 
    if(0 != tid_init_devinfohead())
    {
        close(socketfd); 
        debug_tid_error("[um]: Devinfohead init failed, um exit!\r\n");    
        exit(1);
    }
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(ITD_PORT);
    if(bind(socketfd,(struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        debug_tid_error("[um]: socket bind failed, um exit!\r\n");     
        close(socketfd);     
        exit(1);
    }

    while (1)
    {
        recvlen = recvfrom(socketfd, buf, sizeof(buf), 0, NULL, NULL);
        if (recvlen == sizeof(struct devinfo))
        {
            debug_tid_trace("[um]: RecvMsg From Tid Success!\r\n");
            pdevinfo = (struct devinfo *)buf;
            tid_rwlock_wrlock();
            ret = tid_modify_devinfo(pdevinfo);
            if (ret != 0)
            {
                tid_add_devinfonode(pdevinfo);
            }
            tid_rwlock_unlock();
        }
        else
        {
            debug_tid_waring("[um]: RecvMsg From Tid Failed!\r\n");
        }
    }
    tid_fini_devinfohead();
    close(socketfd);

    return NULL;
}

