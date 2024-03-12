#ifndef ws_h
#define ws_h
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

#define O_FIN 0x80          // b1000 0000
#define O_RSV1 0x40         // b0100 0000
#define O_RSV2 0x20         // b0010 0000
#define O_RSV3 0x10         // b0001 0000
#define O_OPCODE_CONT 0x00  // b0000 0000
#define O_OPCODE_TXT 0x01   // b0000 0001
#define O_OPCODE_BIN 0x02   // b0000 0011
#define O_OPCODE_CLOSE 0x08 // b0000 1000
#define O_OPCODE_PING 0x09  // b0000 1001
#define O_OPCODE_PONG 0x0A  // b0000 1011
#define O_OPCODE_ALL 0x0F   // b0000 1111
#define M_PAYLOAD_LEN 0x7F  // b0111 1111
#define M_MASK 0x80         // b1000 0000

typedef struct {
  long *items;
  size_t count;
  size_t capacity;
} ws_arr_long_t;

typedef struct ws_client_t {
  int fd;
  char *address;
  char *port;
} ws_client_t;

typedef struct {
  size_t count;
  size_t capacity;
  ws_client_t *items;
  ws_arr_long_t removed;
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

typedef struct ws_server_t ws_server_t;

typedef void(ws_on_message_t)(const ws_server_t *, const ws_client_t *,
                              const char *, const size_t);

typedef struct ws_server_t {
  uint16_t port;
  char *address;
  int fd;
  ws_clients clients;
  size_t max_conn;
  ws_on_message_t *on_message;
} ws_server_t;

typedef struct ws_status_t {
  uint16_t code;
  char *reason;
} ws_status_t;

#define ws_status_n 3
extern const ws_status_t status_map[ws_status_n];

typedef struct {
  uint8_t *data;
  size_t len;
} ws_byte_arr_t;

#ifdef __cplusplus
extern "C" {
#endif
extern size_t ws_get_payload_len(ws_frame_t *frame);

extern uint8_t *ws_unmask_payload(uint8_t *s, size_t len, uint8_t *mask_key);

extern ws_frame_t ws_make_ws_frame(uint8_t *payload, size_t payload_len,
                                   uint16_t options);

extern void ws_headers_append(ws_headers *headers, ws_header_t header);

extern size_t ws_parse_http_method(const char *s);

extern bool ws_is_valid_http_method(const char *s);

extern bool ws_is_valid_http_version(const char *s);

extern void ws_print_request(ws_request_t *req);

extern char *ws_make_token(const char *s, size_t len);

extern const char *ws_get_header(ws_request_t *req, const char *header);

extern void ws_print_header(ws_header_t *hdr);

extern ws_request_t *ws_parse_request(char *buf);

extern int setnonblocking(int fd);

extern const char *ws_get_status_reason(const uint16_t code);

extern bool ws_is_websocket_conn(ws_request_t *);

extern void ws_close_connection(ws_server_t *, const size_t);

void ws_clients_remove_client(ws_clients *clients, size_t i);

extern char *ws_headers_to_str(ws_headers *hdrs);

extern ws_header_t ws_make_header(const char *key, const char *val);

extern int ws_write_http_response(const int fd, uint16_t code, const char *msg,
                                  ws_headers *hdrs);

extern void ws_clients_append(ws_clients *clients, ws_client_t client);

extern ws_client_t ws_make_client(int fd, struct sockaddr_in *addr,
                                  socklen_t len);

extern void ws_print_ws_frame(ws_frame_t *frame);

extern void ws_print_hex_arr(const uint8_t *frame);

extern ws_byte_arr_t ws_serialize_ws_frame(ws_frame_t *frame);

extern int ws_send_ws_frame(int client_fd, ws_frame_t *frame);

extern int ws_send_ws_msg(int client_fd, const uint8_t *msg, size_t msg_len,
                          uint8_t options);

extern char *ws_make_accept_key(const char *sec_ws_key);

extern void ws_free_headers(ws_headers *hdrs);

extern void ws_free_request(ws_request_t *req);

extern ws_frame_t ws_parse_ws_frame(uint8_t *buff, size_t len);

extern void ws_free_frame(ws_frame_t *frame);

extern ws_server_t ws_server_new(const uint16_t port, const char *address);

extern void ws_on_message(ws_server_t *server, ws_on_message_t *on_message);

extern void ws_server_start(ws_server_t *server);

extern void ws_die(const char *s);

extern void ws_error(const char *s);

extern void ws_panic(const char *s);

extern void ws_log(const char *s);

extern char *ws_concat_str(const char *s1, const char *s2);

#ifdef __cplusplus
}
#endif

#endif // !ws_h
