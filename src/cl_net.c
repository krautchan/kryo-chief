#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "cl_net.h"
#include "etc.h"

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

uint8_t *cl_oneshot(const char *remote_addr, const uint16_t port, const uint8_t *data, const size_t len, size_t *reply_len) {
	int conn_sock;
	uint8_t headerbuf[4], *pakbuf;
	size_t paklen;
	
	if((conn_sock = cl_connect(remote_addr, port)) == INVALID_SOCKET) return NULL;

	if(send(conn_sock, data, len, 0) == -1) return NULL;
	if(recv(conn_sock, headerbuf, 4, 0) == -1) return NULL;

	paklen = arrtoint(headerbuf);
	if(*reply_len)
		*reply_len = paklen;

	if((pakbuf = malloc(paklen)) == NULL) {
		close(conn_sock);
		return NULL;
	}

	if(recv(conn_sock, pakbuf, paklen, 0) == -1) {
		free(pakbuf);
		pakbuf = NULL;
	}

	close(conn_sock);
	return pakbuf;
}
