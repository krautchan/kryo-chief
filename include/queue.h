#ifndef QUEUE_H_
#define QUEUE_H_

#include <stdlib.h>

typedef struct queue_t queue_t;

queue_t *queue_new(void);
int queue_push(queue_t *queue, void *data);
void *queue_pull(queue_t *queue);
void queue_free(queue_t *queue);
size_t queue_get_size(queue_t *queue);

#endif
