#ifndef _NMP_MUTEX_H
#define _NMP_MUTEX_H

struct nmp_mutex
{
	int fd;
	char filename[128];
}; 

typedef struct nmp_mutex nmp_mutex_t;

extern int nmp_mutex_init(nmp_mutex_t *mutex, const char *file);

extern int nmp_mutex_destroy(nmp_mutex_t *mutex);

//extern int nmp_mutex_trylock(nmp_mutex_t *mutex);

extern int nmp_mutex_lock(nmp_mutex_t *mutex);

extern int nmp_mutex_unlock(nmp_mutex_t *mutex);

#endif        /* _NMP_MUTEX_H */

