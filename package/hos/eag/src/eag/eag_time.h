#ifndef _EAG_TIME_H
#define _EAG_TIME_H
#include <sys/time.h>

int eag_time_init();
int 
eag_time_gettimeofday(struct timeval *tp, void *tzp);
#if 0
void
eag_time_get_relativetime(struct timeval * tp);
#endif
int 
eag_time_set_time(struct timeval *time);

struct timeval
timeval_adjust(struct timeval a);

struct timeval
timeval_subtract(struct timeval a, struct timeval b);

long
timeval_cmp(struct timeval a, struct timeval b);

unsigned long
timeval_elapsed(struct timeval a, struct timeval b);

#endif/*_EAG_TIME_H*/

