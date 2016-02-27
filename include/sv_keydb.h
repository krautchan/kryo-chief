#ifndef SV_KEYDB_H_
#define SV_KEYDB_H_

#include <pthread.h>
#include <stdint.h>

int keydb_init(const char *basedir, const uint32_t n_pregen, const uint32_t n_regen);
pthread_t keydb_spawngen(void);

#endif
