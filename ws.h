#ifndef ws_h
#define ws_h
#include "base64.h"
#include "sha1.h"
#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct ws_client_t {
  int fd;
  char *address;
  char *port;
} ws_client_t;

typedef struct {
  size_t count;
  size_t capacity;
  ws_client_t *items;
} ws_clients;

typedef struct ws_header_t {
  char *key;
  char *value;
} ws_header_t;

typedef struct ws_headers {
  ws_header_t *items;
  size_t count;
  size_t capacity;
} ws_headers;

typedef struct ws_request_t {
  char *method;
  char *path;
  char *version;
  ws_headers headers;
} ws_request_t;

typedef struct __attribute__((__packed__)) {
  uint8_t opcode : 4;
  uint8_t rsv3 : 1;
  uint8_t rsv2 : 1;
  uint8_t rsv1 : 1;
  uint8_t fin : 1;
  uint8_t payload_len : 7;
  uint8_t masked : 1;
  union {
    uint16_t len16 : 16;
    uint64_t len64 : 64;
  } ext_payload_len;
  uint8_t mask_key[4];
  uint8_t *payload;
} ws_frame_t; // 22 bytes

typedef void(ws_on_message_t)(const ws_client_t *client, const char *msg,
                              const size_t len);

typedef struct ws_server_t {
  uint16_t port;
  char *address;
  int fd;
  ws_clients clients;
  size_t max_conn;
	int *client_fds;
	int client_n;
  ws_on_message_t *on_message;
} ws_server_t;

ws_server_t ws_server_new(const uint16_t port, const char *address);

void ws_on_message(ws_server_t *server, ws_on_message_t *on_message);

void ws_server_start(ws_server_t *server);

#endif // !ws_h
