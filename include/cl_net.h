#ifndef CL_NET_H_
#define CL_NET_H_

#include <stdint.h>

#include "net.h"

int cl_connect(const char *remote_addr, const uint16_t port);

#endif
