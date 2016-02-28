#ifndef HTAB_H_
#define HTAB_H_
#include <stdint.h>
#include <stdlib.h>

typedef size_t (*hfunc_t)(const uint8_t *key, const size_t klen);
typedef struct htab_t htab_t;

htab_t *htab_new(const size_t tabsize, hfunc_t hfunc, freefunc_t ffunc);
int htab_insert(htab_t *htab, const uint8_t *key, const size_t klen, void *data);
int htab_delete(htab_t *htab, const uint8_t *key, const size_t klen);
void *htab_lookup(const htab_t *htab, const uint8_t *key, const size_t klen);
void htab_free(htab_t *htab);

#endif
