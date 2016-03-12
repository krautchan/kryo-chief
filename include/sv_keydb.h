#ifndef SV_KEYDB_H_

#define SV_KEYDB_H_

#include <pthread.h>
#include <stdint.h>

#include "rsa.h"

rsa_keypair_t *release_key(const uint8_t *keyid);
rsa_keypair_t *issue_key(void);
int keydb_init(const char *basedir, const uint32_t n_pregen, const uint32_t n_regen);
void keydb_free(void);
pthread_t keydb_spawngen(void);

#endif
