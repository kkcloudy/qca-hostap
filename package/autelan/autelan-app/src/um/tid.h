/******************************************************************************
  文 件 名   : tid.h
  作    者   : wenjue
  生成日期   : 2014年11月19日
  功能描述   : tid.c的头文件
******************************************************************************/
#ifndef _UM_TID_H_
#define _UM_TID_H_

#define TID_MAC_MAXLEN       20
#define TID_HOSTNAME_MAXLEN  128
#define TID_OSTYPE_MAXLEN    32
#define TID_CPUTYPE_MAXLEN   32
#define TID_DEVTYPE_MAXLEN   8
#define TID_DEVMODEL_MAXLEN   16
#define TID_IPADDR_MAXLEN   16

struct devinfo{
    char hostname[TID_HOSTNAME_MAXLEN];
    char mac[TID_MAC_MAXLEN];
    char ostype[TID_OSTYPE_MAXLEN];
    char cputype[TID_CPUTYPE_MAXLEN];
    char devmodel[TID_DEVMODEL_MAXLEN];
    char devtype[TID_DEVTYPE_MAXLEN];
    char ipaddr[TID_IPADDR_MAXLEN];
};

struct devinfonode{
    int aging;
    struct devinfo stdevinfo;
    struct devinfonode *prev;
    struct devinfonode *next;
};

struct devinfohead{
    struct devinfonode *next;
    pthread_rwlock_t rw_lock;
};

void *tid_pthreadhandle(void *data);
int tid_get_devinfo(struct devinfo *pstdevinfo, const char *mac);
void tid_update_devinfonode(void);
int tid_rwlock_unlock(void);
int tid_rwlock_rdlock(void);
int tid_rwlock_wrlock(void);

#endif
