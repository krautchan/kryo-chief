#ifndef DYNARR_H_
#define DYNARR_H_

#include <stdlib.h>

#include "etc.h"

typedef struct dynarr_t dynarr_t;

dynarr_t *dynarr_new(const size_t size_entry, const size_t prealloc, freefunc_t ffunc);
int dynarr_add(dynarr_t *arr, void *data);
size_t dynarr_get_size(const dynarr_t *arr);
void *dynarr_get_index(const dynarr_t *arr, const size_t idx);
void dynarr_free(dynarr_t *arr);

#endif
