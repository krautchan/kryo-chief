#ifndef SV_NET_H_
#define SV_NET_H_

#include <stdint.h>

#include "net.h"

void sv_accept(int list_sock);
int sv_listen(const uint16_t port);

#endif 
