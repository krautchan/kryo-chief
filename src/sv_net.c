#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "sv_net.h"

#define BACKLOG		16

int sv_shutdown = 0;

typedef struct {
	int list_sock, acc_sock;
} conninfo_t;

static void *net_thread(void *arg) {
	conninfo_t *inarg, info;
	int connected = 1;
	char buf[128];
	size_t recvd;

	if((inarg = arg) == NULL) return NULL;
	info.list_sock = inarg->list_sock;
	info.acc_sock = inarg->acc_sock;
	free(inarg);

	printf("GOT SOMETHING!\n");
	while(connected) {
		if((recvd = recv(info.acc_sock, buf, 128, 0)) == 0) {
			printf("%d: disconnected\n", info.acc_sock);
			connected = 0;
		} else {
			printf("%d: '%s'\n", info.acc_sock, buf);
		}
	}
	return NULL;
}

void sv_accept(int list_sock) {
	int acc_sock;
	pthread_t newthread;
	conninfo_t *info;

	while(sv_shutdown == 0) {
		if((info = malloc(sizeof(conninfo_t))) == NULL) continue;
		if((acc_sock = accept(list_sock, NULL, NULL)) == INVALID_SOCKET) continue;

		info->list_sock = list_sock;
		info->acc_sock = acc_sock;

		if((newthread = pthread_create(&newthread, NULL, net_thread, info)) != 0)
			close(acc_sock);
	}
}

int sv_listen(const uint16_t port) {
	struct sockaddr_in addr;
	int sock;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) return 0;
	if(bind(sock, (struct sockaddr*)(&addr), sizeof(struct sockaddr)) == SOCKET_ERROR) return 0;
	if(listen(sock, BACKLOG) == SOCKET_ERROR) return 0;

	return sock;
}
