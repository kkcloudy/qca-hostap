#ifndef _TID_DEBUG_H_
#define _TID_DEBUG_H_

#include <syslog.h>

extern unsigned char tid_debug_level;

#define tid_debug_waring(fmt, args...)  do{     \
        if (tid_debug_level > 1)                \
        {                                       \
            printf(fmt, ##args);                \
            printf("\r\n");                     \
   	        openlog("tid", 0, LOG_DAEMON);      \
            syslog(LOG_WARNING, fmt, ##args);   \
            closelog();                         \
        }                                       \
}while(0)

#define tid_debug_error(fmt, args...)   do{ \
        if (tid_debug_level > 0)            \
        {                                   \
            printf(fmt, ##args);            \
            printf("\r\n");                 \
            openlog("tid", 0, LOG_DAEMON);  \
            syslog(LOG_ERR, fmt, ##args);   \
            closelog();                     \
        }                                   \
}while(0)

#define tid_debug_trace(fmt, args...)   do{ \
        if (tid_debug_level > 2)            \
        {                                   \
            printf(fmt, ##args);            \
            printf("\r\n");                 \
   	        openlog("tid", 0, LOG_DAEMON);  \
            syslog(LOG_DEBUG, fmt, ##args); \
            closelog();                     \
        }                                   \
}while(0)

#endif