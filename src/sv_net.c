#include <errno.h>
#include <fcntl.h>
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

#define MAX_LINE	16384

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

typedef struct fd_state_t {
	uint8_t peer[4];
	uint8_t read_buf[MAX_LINE];
	size_t read_len;
	
	uint32_t paksize;
	uint8_t msg_type;
	uint8_t *data;
	int packet_ready;

	uint8_t *reply_data;
	size_t reply_len;

	int write_ready;

	size_t n_written;
} fd_state_t;

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

fd_state_t *fd_state_new(struct sockaddr_in *addr) {
	fd_state_t *out;
	uint32_t peer;

	if((out = malloc(sizeof(fd_state_t))) == NULL)
		return NULL;


	if(addr != NULL) {
		peer = addr->sin_addr.s_addr;
		inttoarr(peer, out->peer);
	} else {
		memset(out->peer, 0, 4);
	}

	out->read_len = 0;
	out->paksize = 0;
	out->msg_type = 0;
	out->data = NULL;
	out->packet_ready = 0;

	out->reply_data = NULL;
	out->reply_len = 0;

	out->write_ready = 0;
	out->n_written = 0;

	return out;
}

static int doread(int fd, fd_state_t *state) {
	ssize_t res;

	while(1) {
		res = recv(fd, state->read_buf + state->read_len, sizeof(state->read_buf) - state->read_len, 0);
		
		if(res <= 0) {
			break;
		} else {
			state->read_len += res;
		}
	}

	if(state->read_len >= 4) {
		state->paksize = arrtoint(state->read_buf);
		if(state->paksize + 4 > sizeof(state->read_buf))
			return -1;
	}

	if(state->read_len >= 5) {
		state->msg_type = state->read_buf[4];
		state->data = state->read_buf + 5;
	}

	if(state->read_len >= state->paksize) {
		state->packet_ready = 1;
	}
	
	if(res == 0)
		return 1;
	else if(res < 0) {
		if(errno == EAGAIN)
			return 0;
		return -1;
	}
	
	return 0;
}

static int dowrite(int fd, fd_state_t *state) {
	ssize_t res;

	if(state->reply_data == NULL)
		return -1;
	
	while(state->n_written < state->reply_len) {
		res = send(fd, state->reply_data + state->n_written,
				state->reply_len - state->n_written, 0);

		if(res < 0) {
			if(errno == EAGAIN)
				return 0;
			return -1;
		}

		if(res == 0)
			return -1;

		state->n_written += res;
	}

	if(state->n_written == state->reply_len)
		state->n_written = state->reply_len = 0;

	free(state->reply_data);

	state->packet_ready = 0;
	state->write_ready = 0;

	return -1;
}

uint8_t *packetforge(const uint8_t msg_type, const size_t datalen, const uint8_t *data, size_t *outlen) {
	uint8_t *out;
	
	if(data == NULL)
		return NULL;

	*outlen = sizeof(uint32_t) + 1 + datalen;

	if((out = malloc(*outlen)) == 0)
		return NULL;

	inttoarr(datalen + 1, out);
	out[4] = msg_type;
	memcpy(out + sizeof(uint32_t) + 1, data, datalen);

	return out;
}

int replyforge(fd_state_t *state) {
	rsa_keypair_t *pair;
	uint8_t *serial;
	size_t klen;
	int check_result;
	int release_secret = 0;

	if(state == 0)
		return -1;

	if(state->packet_ready == 0)
		return -1;

	uint32_t len = state->paksize;

	state->reply_data = NULL;
	state->reply_len = 0;

	printaddr(state->peer);
	switch(state->msg_type) {
		case NET_CL_REQ_PUBLIC:
			if(len != 1) goto error;

			printf("Got key issue request!\n");
			if((pair = issue_key()) == NULL) goto error;
			if((serial = rsa_serialize_public(pair, &klen)) == NULL) goto error;
			state->reply_data = packetforge(NET_SV_PUBLIC, klen, serial, &state->reply_len);
			state->write_ready = 1;

			free(serial);
			break;

		case NET_CL_REQ_SECRET:
			if(len < SHA256_SIZE + 1) goto error;
			printf("Got secret key Request!\n");

			printaddr(state->peer);
			printf("Token verification: ");
			check_result = verify_token((state->data) + SHA256_SIZE, len - SHA256_SIZE - 1);
			
			release_secret = 0;
			if(check_result == TOKEN_PASS) {
				printf("Passed.");
				release_secret = 1;
			} else if(check_result == TOKEN_FAIL) {
				printf("Failed.");
				release_secret = 0;
			}else if(check_result == TOKEN_OLD) {
				printf("Known token! ");
				if(is_released(state->data)) {
					printf("(Key released)");
					release_secret = 1;
				} else {
					printf("(Key unreleased)");
				}
			}

			if(release_secret == 1) {
				printf(" --> Request granted.\n");
				if((pair = release_key(state->data)) == NULL) goto error;
				if((serial = rsa_serialize_pair(pair, &klen)) == NULL) goto error;
				state->reply_data = packetforge(NET_SV_SECRET, klen, serial, &state->reply_len);
				free(serial);
			} else {
				printf(" --> Request denied.\n");
			}

			break;


		case NET_CTL_SHUTDOWN:
			if(len < 33) goto error;
			printf("Received shutdown request. ");

			if(!memcmp(state->data, shutdown_pass, 32)) {
				printf("Shutting down.\n");
				sv_shutdown = 1;
				genthread_shutdown = 1;
			} else
				printf("Wrong password.\n");

			break;
	}

error:
	state->write_ready = 1;
	return 0;
}

int sv_listen(const uint16_t port) {
	struct sockaddr_in addr;
	int list_sock = INVALID_SOCKET, maxfd, i, fd, r;
	fd_set readset, writeset, exset;
	fd_state_t *state[FD_SETSIZE];
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if((list_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		printf("socket() failed\n");
		goto error;
	}

	fcntl(list_sock, F_SETFL, O_NONBLOCK);

	if(bind(list_sock, (struct sockaddr*)(&addr), sizeof(struct sockaddr)) == SOCKET_ERROR) {
		close(list_sock);
		printf("bind() failed.\n");
		goto error;
	}
	if(listen(list_sock, BACKLOG) == SOCKET_ERROR) goto error;
	
	setpass();
	
	for(i = 0; i < FD_SETSIZE; i++)
		state[i] = NULL;


	while(sv_shutdown == 0) {
		maxfd = list_sock;

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_ZERO(&exset);

		FD_SET(list_sock, &readset);

		for(i = 0; i < FD_SETSIZE; i++) {
			if(state[i]) {
				if(i > maxfd)
					maxfd = i;
				FD_SET(i, &readset);
				if(state[i]->write_ready)
					FD_SET(i, &writeset);
			}
		}

		if((r = select(maxfd + 1, &readset, &writeset, &exset, NULL)) < 0) {
			printf("select() failed.\n");
			goto error;
		}

		if(FD_ISSET(list_sock, &readset)) {
			fd = accept(list_sock, (struct sockaddr*)&ss, &slen);
			if(fd < 0) {
				printf("accept() failed.\n");
				return INVALID_SOCKET;
			} else if(fd > FD_SETSIZE) {
				close(fd);
			} else {
				fcntl(fd, F_SETFL, O_NONBLOCK);
				if((state[fd] = fd_state_new((struct sockaddr_in*)&ss)) == NULL) {
					printf("fd_state_new() failed.\n");
					goto error;
				}
			}
		}

		for(i = 0; i < maxfd + 1; i++) {
			r = 0;
			if(i == list_sock)
				continue;

			if(FD_ISSET(i, &readset)) {
				r = doread(i, state[i]);
				if(state[i]->packet_ready) {
					replyforge(state[i]);
				}
			}

			if((r == 0) && FD_ISSET(i, &writeset)) {
				r = dowrite(i, state[i]);
			}

			if((r != 0) || (sv_shutdown != 0)) {
				free(state[i]);
				state[i] = NULL;
				close(i);
			}

		}
	}

	return 1;
error:
	if(list_sock != INVALID_SOCKET)
		close(list_sock);

	sv_shutdown = 1;
	return 0;
}
