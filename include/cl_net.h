#ifndef CL_NET_H_
#define CL_NET_H_

#include <stdint.h>

#include "net.h"

int cl_connect(const char *remote_addr, const uint16_t port);
uint8_t *cl_oneshot(const char *remote_addr, const uint16_t port, const uint8_t *data, const size_t len, size_t *reply_len);

#endif
