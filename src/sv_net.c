#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "ccard.h"
#include "config.h"
#include "etc.h"
#include "protocol.h"
#include "rsa.h"
#include "rsa_io.h"
#include "sha256.h"
#include "sv_keydb.h"
#include "sv_net.h"

#define BACKLOG		16
#define CONF_PASS_LEN	64

#define TOKEN_PASS	1
#define TOKEN_FAIL	0
#define TOKEN_OLD	-1

int sv_shutdown = 0;
extern int genthread_shutdown;

typedef struct {
	int list_sock, acc_sock;
} conninfo_t;

static uint8_t shutdown_pass[32];
static const char digrams[65] = "pulexegezacebisousesarmaindireaseratenberalavetiedorquanteisrion";

static int setpass(void) {
	uint8_t rnd[8];
	size_t i, idx1, idx2;
	FILE *fp;

	while(getrand(rnd, 8, NULL) != 8);

	if((fp = fopen(CONFIG_DATADIR "shutdown_pass", "w")) == NULL) return 0;

	printf("Shutdown password: ");
	for(i = 0; i < 8; i++) {
		idx1 = (rnd[i] >> 4) & 0x0f;
		idx2 = (rnd[i] & 0x0f) + 0x10;
		
		shutdown_pass[4 * i + 0] = digrams[idx1 * 2];
		shutdown_pass[4 * i + 1] = digrams[idx1 * 2 + 1];
		shutdown_pass[4 * i + 2] = digrams[idx2 * 2];
		shutdown_pass[4 * i + 3] = digrams[idx2 * 2 + 1];

		printf("%c%c%c%c", 
				shutdown_pass[4 * i + 0],
				shutdown_pass[4 * i + 1],
				shutdown_pass[4 * i + 2],
				shutdown_pass[4 * i + 3]);

		fwrite(shutdown_pass + 4 * i, 4, 1, fp);
	}
	printf("\n");
	fclose(fp);

	return 1;
}

static int reply(int socket, const uint8_t msgtype, const uint8_t *data, const uint32_t len) {
	uint8_t *reply, paksize[4];
	uint32_t replen;
	int ret = 0;

	replen = len + 1;
	if((reply = malloc(replen)) == NULL) return 0;

	inttoarr(replen, paksize);

	reply[0] = msgtype;
	if(data)
		memcpy(reply + 1, data, len);

	if(send(socket, paksize, 4, 0) == -1) goto end;
	if(send(socket, reply, replen, 0) == -1) goto end;

	ret = 1;

end:
	free(reply);
	return ret;
}

int verify_token(const uint8_t *token, const size_t tlen) {
	int check_result = cc_check(token, tlen);

	if(check_result == CC_OK) {
		cc_save(token, tlen, CONFIG_DATADIR "release_tokens");
		return TOKEN_PASS;
	}

	if(check_result == CC_KNOWN)
		return TOKEN_OLD;
	
	return TOKEN_FAIL;
}

static void dispatch_packet(int socket, const uint8_t *data, const uint32_t len) {
	uint8_t msgtype = data[0];
	rsa_keypair_t *pair;
	uint8_t *serial;
	size_t klen;
	int check_result;

	switch(msgtype) {
		case NET_CL_REQ_PUBLIC:

			if(len != 1) goto reterr;

			printf("Got key issue request!\n");
			if((pair = issue_key()) == NULL) goto reterr;
			if((serial = rsa_serialize_public(pair, &klen)) == NULL) goto reterr;
			if(reply(socket, NET_SV_PUBLIC, serial, klen) != 1) goto reterr;
			free(serial);
			break;
		case NET_CL_REQ_SECRET:

			if(len < SHA256_SIZE + 1)
				goto reterr;

			printf("Got secret key request!\n");
			printf("Release token verification: ");

			check_result = verify_token(data + SHA256_SIZE + 1, len - SHA256_SIZE - 1);

			if(check_result == TOKEN_FAIL) {
				printf("Failed.\n");
				goto reterr;
			}

			if(check_result == TOKEN_OLD) {
				printf("Known token! ");
				if(is_released(data + 1)) {
					printf("(key released)\n");
					if((pair = release_key(data + 1, 0)) == NULL) goto reterr;
					if((serial = rsa_serialize_pair(pair, &klen)) == NULL) goto reterr;
					if(reply(socket, NET_SV_SECRET, serial, klen) != 1) goto reterr;
					free(serial);
				} else {
					printf("(key unreleased)\n");
					goto reterr;
				}
			} else {
				printf("Passed\n");
				if((pair = release_key(data + 1, 1)) == NULL) goto reterr;
				if((serial = rsa_serialize_pair(pair, &klen)) == NULL) goto reterr;
				if(reply(socket, NET_SV_SECRET, serial, klen) != 1) goto reterr;
				free(serial);
			}
			break;

		case NET_CTL_SHUTDOWN:

			if(len < 33) goto reterr;
			printf("Received shutdown request. ");

			if(!memcmp(data + 1, shutdown_pass, 32)) {
				printf("Shutting down.\n");
				sv_shutdown = 1;
				genthread_shutdown = 1;
			} else
				printf("Wrong password.\n");

			break;

		default:
			goto reterr;
	}
	return;

reterr:
	reply(socket, NET_ERROR, NULL, 0);
}

static void *net_thread(void *arg) {
	conninfo_t *inarg, info;
	int connected = 1;
	uint8_t buf[4], *data;
	size_t recvd;
	uint32_t paksize;

	if((inarg = arg) == NULL) return NULL;
	info.list_sock = inarg->list_sock;
	info.acc_sock = inarg->acc_sock;
	free(inarg);

	while(connected) {
		if(sv_shutdown != 0)
			connected = 0;
		else if((recvd = recv(info.acc_sock, buf, 4, 0)) == 0) {
			connected = 0;
		} else {
			paksize = arrtoint(buf);
			
			if(paksize > NET_PACKET_MAX) {
				reply(info.acc_sock, NET_ERROR, NULL, 0);
				continue;

			} else {
				if((paksize == 0) || (data = malloc(paksize)) == NULL) {
					reply(info.acc_sock, NET_ERROR, NULL, 0);
					continue;
				}

				recv(info.acc_sock, data, paksize, 0);
				dispatch_packet(info.acc_sock, data, paksize);
				free(data);
			}
		}
	}

	shutdown(info.acc_sock, 2);

	if(sv_shutdown)
		pthread_exit(NULL);

	return NULL;
}

void sv_accept(int list_sock) {
	int acc_sock;
	pthread_t newthread;
	conninfo_t *info;

	setpass();

	while(sv_shutdown == 0) {
		if((info = malloc(sizeof(conninfo_t))) == NULL) continue;
		if((acc_sock = accept(list_sock, NULL, NULL)) == INVALID_SOCKET) continue;

		info->list_sock = list_sock;
		info->acc_sock = acc_sock;

		if((newthread = pthread_create(&newthread, NULL, net_thread, info)) != 0)
			shutdown(acc_sock, 2);

		sleep(1);
	}

	if(sv_shutdown == 1) {
		printf("sv_accept(): Shutting down.\n");
		shutdown(list_sock, 2);
		sv_shutdown = 2;
	}
}

int sv_listen(const uint16_t port) {
	struct sockaddr_in addr;
	int sock;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		printf("socket() failed\n");
		return INVALID_SOCKET;
	}
	if(bind(sock, (struct sockaddr*)(&addr), sizeof(struct sockaddr)) == SOCKET_ERROR) {
		close(sock);
		printf("bind() failed.\n");
		return INVALID_SOCKET;
	}
	if(listen(sock, BACKLOG) == SOCKET_ERROR) return INVALID_SOCKET;

	return sock;
}
