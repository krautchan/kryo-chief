#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "cl_net.h"

int cl_connect(const char *remote_addr, const uint16_t port) {
	int conn_sock;
	struct sockaddr_in addr;
	struct hostent *resolved;
	int i = 0;

	if((resolved = gethostbyname(remote_addr)) == NULL) return INVALID_SOCKET;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if(resolved->h_addr_list[0]) {
		addr.sin_addr.s_addr = *(uint32_t*)resolved->h_addr_list[i];
	} else {
		addr.sin_addr.s_addr = inet_addr(remote_addr);
	}

	if((conn_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) 
		return INVALID_SOCKET;
	if(connect(conn_sock, (struct sockaddr*)(&addr), sizeof(struct sockaddr)) == SOCKET_ERROR) 
		return INVALID_SOCKET;

	return conn_sock;
}
