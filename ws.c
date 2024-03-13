#include "ws.h"
#define BASE64_ENC_IMPLEMENTATION
#include "base64.h"

static const size_t MAX_MSG_LEN = 125 * 1024;
static const char *WS_SHA_SUFFIX = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
static const byte SHA1_HASH_LEN = 20;

const uint8_t WS_LEN_IS_2BYTES = 126;
const uint8_t WS_LEN_IS_8BYTES = 127;

const size_t WS_PAYLOAD_LEN_LIMIT = 126;
const size_t WS_EXT_PAYLOAD_LEN_LIMIT_16 = 65536;
// const long WS_EXT_PAYLOAD_LEN_LIMIT_64 = 18446744073709551615;

size_t ws_get_payload_len(ws_frame_t *frame) {
  if (frame->payload_len == WS_LEN_IS_2BYTES) {
    return be16toh(frame->ext_payload_len.len16);
  }
  if (frame->payload_len == WS_LEN_IS_8BYTES) {
    return be64toh(frame->ext_payload_len.len64);
  }
  return frame->payload_len;
}

uint8_t *ws_unmask_payload(uint8_t *s, size_t len, uint8_t *mask_key) {
  for (size_t i = 0; i < len; ++i) {
    s[i] = s[i] ^ mask_key[i % 4];
  }
  return s;
}

// OPTIONS: (8 bits)
// fin/cont (1 bit), rsv1 (1 bit), rsv2 (1 bit), rsv3 (1 bit), opcode (4 bits)
// Don't use while parsing as masking is not allowed only on server side.
ws_frame_t ws_make_ws_frame(uint8_t *payload, size_t payload_len,
                            uint16_t options) {
  ws_frame_t frame = {0};
  frame.fin = (options & O_FIN) >> 7;
  frame.rsv1 = (options & O_RSV1) >> 6;
  frame.rsv2 = (options & O_RSV2) >> 5;
  frame.rsv3 = (options & O_RSV3) >> 4;
  frame.opcode = (options & O_OPCODE_ALL);
  frame.masked = 0;
  if (payload_len < 126) {
    frame.payload_len = payload_len;
  } else if (payload_len < 65536) {
    frame.payload_len = 126;
    frame.ext_payload_len.len16 = htobe16(payload_len);
  } else {
    // no payload length will ever be this big!
    // assert(payload_len < (uint64_t)18446744073709551615 &&
    //        "Payload length exceeds 64 bit integer.");
    frame.payload_len = 127;
    frame.ext_payload_len.len64 = htobe64(payload_len);
  }
  frame.payload = payload;
  return frame;
}

void ws_die(const char *s) {
  perror(s);
  exit(1);
}

void ws_error(const char *s) { printf("[ERROR] %s: %s\n", s, strerror(errno)); }

void ws_panic(const char *s) {
  printf("[PANIC] %s: %s\n", s, strerror(errno));
  exit(1);
}

void ws_log(const char *s) { printf("[LOG] %s\n", s); }

char *ws_concat_str(const char *s1, const char *s2) {
  assert(s1 != NULL && s2 != NULL && "Provided string should not be NULL");
  size_t s1_len = strlen(s1);
  size_t s2_len = strlen(s2);
  size_t s_len = s1_len + s2_len;
  char *s = (char *)malloc(s_len + 1);
  memset(s, '\0', s_len + 1);
  memcpy(s, s1, s1_len);
  memcpy(s + s1_len, s2, s2_len);
  return s;
}

void ws_headers_append(ws_headers *headers, ws_header_t header) {
  if (headers->count >= headers->capacity) {
    headers->capacity = headers->capacity == 0 ? 2 : headers->capacity * 2;
    headers->items = (ws_header_t *)realloc(
        headers->items, headers->capacity * sizeof(ws_header_t));
    assert(headers != NULL && "Null after reallocation");
  }
  headers->items[headers->count++] = header;
}

const size_t http_methods_n = 5;
const char *http_methods[] = {"GET",   "POST",   "PUT",
                              "PATCH", "DELETE", "OPTIONS"};

size_t ws_parse_http_method(const char *s) {
  for (size_t i = 0; i < http_methods_n; ++i) {
    if (strncmp(s, http_methods[i], strlen(http_methods[i])) == 0) {
      return i;
    }
  }
  return -1;
}

bool ws_is_valid_http_method(const char *s) {
  for (size_t i = 0; i < http_methods_n; ++i) {
    if (strncmp(s, http_methods[i], strlen(http_methods[i])) == 0) {
      return true;
    }
  }
  return false;
}

bool ws_is_valid_http_version(const char *s) {
  if (strncmp(s, "HTTP/1.1", 8) == 0) {
    return true;
  }
  return false;
}

void ws_print_request(ws_request_t *req) {
  if (req == NULL) {
    ws_log("Request is NULL");
    return;
  }
  printf("Request:\n%s %s %s\nTotal Headers: %zu\n", req->method, req->path,
         req->version, req->headers.count);
  for (size_t i = 0; i < req->headers.count; ++i) {
    printf("%s: %s\n", req->headers.items[i].key, req->headers.items[i].value);
  }
}

char *ws_make_token(const char *s, size_t len) {
  char *token = (char *)malloc(len + 1);
  memset(token, '\0', len + 1);
  memcpy(token, s, len);
  return token;
}

const char *ws_get_header(ws_request_t *req, const char *header) {
  for (size_t i = 0; i < req->headers.count; ++i) {
    if (strncmp(req->headers.items[i].key, header, strlen(header)) == 0) {
      return req->headers.items[i].value;
    }
  }
  return NULL;
}

void ws_print_header(ws_header_t *hdr) {
  printf("{%s: %s}\n", hdr->key, hdr->value);
}

ws_request_t *ws_parse_request(char *buf) {
  // printf("Actual Request:\n%s\n", buf);
  ws_request_t *request = (ws_request_t *)malloc(sizeof(ws_request_t));
  char *token = strtok(buf, " \r\n");
  if (token == NULL) {
    return NULL;
  }
  if (!ws_is_valid_http_method(token)) {
    return NULL;
  }
  request->method = ws_make_token(token, strlen(token));

  // TODO: Check if the path is valid
  token = strtok(NULL, " \r\n");
  if (token == NULL) {
    return NULL;
  }
  request->path = ws_make_token(token, strlen(token));

  token = strtok(NULL, " \r\n");
  if (token == NULL) {
    return NULL;
  }
  if (!ws_is_valid_http_version(token)) {
    return NULL;
  }
  request->version = ws_make_token(token, strlen(token));

  ws_headers headers = {0};
  while (token != NULL) {
    // header key
    token = strtok(NULL, " \r\n");
    if (token != NULL) {
      ws_header_t h = {0};
      h.key = ws_make_token(token, strlen(token) - 1);
      // header value
      token = strtok(NULL, "\r\n");
      if (token == NULL) {
        return NULL;
      }
      h.value = ws_make_token(token, strlen(token));
      ws_headers_append(&headers, h);
    }
  }
  request->headers = headers;
  return request;
}

int setnonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  flags |= O_NONBLOCK;
  if (fcntl(fd, F_SETFL, flags) == -1) {
    return -1;
  }
  return 0;
}

ws_server_t ws_server_new(const uint16_t port, const char *address) {
  ws_server_t server = {0};
  server.port = port;
  server.address = (char *)address;
  server.max_conn = 1000;
  server.on_message = NULL;
  server.on_close = NULL;
  ws_clients clients = {
      .count = 0,
      .capacity = server.max_conn,
      .items = (ws_client_t *)malloc(sizeof(ws_client_t) * server.max_conn),
      .removed =
          {
              .items = (long *)malloc(sizeof(long) * server.max_conn),
              .count = 0,
              .capacity = server.max_conn,
          },
  };
  server.clients = clients;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) {
    ws_panic("Could not create socket");
  }
  int option_value = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option_value,
                 sizeof(int)) == -1) {
    ws_panic("Could not set socket options");
  };
  setnonblocking(fd);
  server.fd = fd;
  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(address);
  socklen_t addr_len = sizeof(addr);

  if (bind(fd, (struct sockaddr *)&addr, addr_len) == -1) {
    ws_panic("Could not bind");
  };
  if (listen(fd, 4096) == -1) {
    ws_panic("Could not listen");
  };
  return server;
}

// #define ws_expected_headers_n 6
// static const ws_header_t expected_headers[ws_expected_headers_n] = {
//     {"Upgrade", "websocket"},
//     {"Connection", "upgrade"},
//     {"Origin", NULL},
//     {"Sec-WebSocket-Key", NULL},
//     {"Sec-WebSocket-Protocol", "chat, superchat"},
//     {"Sec-WebSocket-Version", NULL},
// };

#define ws_status_n 3
const ws_status_t status_map[ws_status_n] = {
    {101, "Switching Protocols"},
    {200, "OK"},
    {400, "Bad Request"},
};

const char *ws_get_status_reason(const uint16_t code) {
  size_t i = 0;
  for (; i < ws_status_n - 1; ++i) {
    if (code >= status_map[i].code && code < status_map[i + 1].code) {
      return status_map[i].reason;
    }
  }
  if (code == status_map[i].code) {
    return status_map[i].reason;
  }
  assert(false && "Not yet supported.");
  return "";
}

bool ws_is_websocket_conn(ws_request_t *req) {
  if (strncmp(req->method, "GET", 3) != 0) {
    return false;
  }
  if (strncmp(req->version, "HTTP/1.1", 8) != 0) {
    return false;
  }
  size_t match_headers_count = 0;
  size_t expected_match_count = 3;
  for (size_t i = 0; i < req->headers.count; ++i) {
    ws_header_t h = req->headers.items[i];
    if (strncmp(h.key, "Upgrade", 7) == 0) {
      if (strncmp(h.value, "websocket", 9) != 0) {
        return false;
      }
      match_headers_count++;
    }
    if (strncmp(h.key, "Connection", 10) == 0) {
      if (strncmp(h.value, "Upgrade", 7) != 0) {
        return false;
      }
      match_headers_count++;
    }
    if (strncmp(h.key, "Sec-WebSocket-Key", 17) == 0) {
      match_headers_count++;
    }
  }
  if (match_headers_count < expected_match_count) {
    return false;
  }
  return true;
}

char *ws_headers_to_str(ws_headers *hdrs) {
  assert(hdrs != NULL && "Headers are null.");
  size_t hdrs_len = 0;
  for (size_t i = 0; i < hdrs->count; ++i) {
    hdrs_len += strlen(hdrs->items[i].key) + strlen(hdrs->items[i].value) +
                strlen(": \r\n");
  }
  char *hdrs_str = (char *)malloc(hdrs_len + 1);
  memset(hdrs_str, '\0', hdrs_len + 1);
  size_t offset = 0;
  for (size_t i = 0; i < hdrs->count; ++i) {
    ws_header_t h = hdrs->items[i];
    offset += sprintf(hdrs_str + offset, "%s: %s\r\n", h.key, h.value);
  }
  return hdrs_str;
}

ws_header_t ws_make_header(const char *key, const char *val) {
  ws_header_t hdr = {0};
  hdr.key = (char *)key;
  hdr.value = (char *)val;
  return hdr;
}

int ws_write_http_response(const int fd, uint16_t code, const char *msg,
                           ws_headers *hdrs) {
  assert(msg != NULL && "Message should not be NULL");
  const char *reason = ws_get_status_reason(code);
  const char *http_version = "HTTP/1.1";
  char *headers = NULL;
  if (hdrs != NULL) {
    headers = ws_headers_to_str(hdrs);
  }
  size_t len =
      strlen(http_version) + strlen(reason) + 6 + strlen(headers) + strlen(msg);
  assert(len <= MAX_MSG_LEN && "Response body exceeds MAX set memory.");
  char *s = (char *)malloc(MAX_MSG_LEN);
  memset(s, '\0', MAX_MSG_LEN);
  sprintf(s, "%s %u %s\r\n%s\r\n%s", http_version, code, reason, headers, msg);
  int n = write(fd, s, strlen(s));
  if (n == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      ws_log("could not write to the socket bc eagain or would block.");
    }
    ws_error("Could not write to the connection");
    return -1;
  }
  printf("Response:\n%s\n", s);
  free(s);
  if (hdrs != NULL) {
    free(headers);
  }
  return 0;
}

void ws_arr_push(ws_arr_long_t *arr, long item) {
  if (arr->count >= arr->capacity) {
    arr->capacity = arr->capacity == 0 ? 1000 : arr->capacity * 1.25;
    arr->items = (long *)realloc(arr->items, arr->capacity * sizeof(long));
    assert(arr != NULL && "Null after reallocation");
  }
  arr->items[arr->count++] = item;
}

long ws_arr_pop(ws_arr_long_t *arr) {
  if (arr->count > 0) {
    arr->count--;
    return arr->items[arr->count];
  }
  return -1;
}

void ws_clients_append(ws_clients *clients, ws_client_t client) {
  long rem_i = ws_arr_pop(&clients->removed);
  if (rem_i != -1) {
    printf("===Reusing the client=== %ld\n", rem_i);
    clients->items[rem_i] = client;
    return;
  }
  if (clients->count >= clients->capacity) {
    if (clients->capacity == 0) {
      clients->capacity = 1000;
    } else if (clients->capacity <= 1000) {
      clients->capacity *= 2;
    } else {
      clients->capacity *= 1.25;
    }
    clients->items = (ws_client_t *)realloc(
        clients->items, clients->capacity * sizeof(ws_client_t));
    assert(clients != NULL && "Null after reallocation");
  }
  clients->items[clients->count++] = client;
}

void ws_close_connection(ws_server_t *server, const size_t i) {
  ws_arr_push(&server->clients.removed, i);
  if (close(server->clients.items[i].fd) == -1) {
    ws_error("Could not close the connection");
  };
  server->clients.items[i].fd = -1;
}

ws_client_t ws_make_client(int fd, struct sockaddr_in *addr, socklen_t len) {
  ws_client_t client = {.fd = fd,
                        .address = inet_ntoa(addr->sin_addr),
                        .port = be16toh(addr->sin_port)};
  printf("Acception connection on fd: %d, host=%s, port=%d\n", fd,
         client.address, client.port);
  return client;
}

void ws_print_ws_frame(ws_frame_t *frame) {
  assert(frame != NULL && "Cannot print frame = NULL");
  printf("fin: %u\n", frame->fin);
  printf("rsv1: %u\n", frame->rsv1);
  printf("rsv2: %u\n", frame->rsv2);
  printf("rsv3: %u\n", frame->rsv3);
  printf("opcode: %x\n", frame->opcode);
  printf("masked: %u\n", frame->masked);
  printf("payload len: %u\n", frame->payload_len);
  size_t plen = frame->payload_len;
  if (frame->payload_len == 126) {
    plen = be16toh(frame->ext_payload_len.len16);
    printf("ext payload len: %zu\n", plen);
  }
  if (frame->payload_len == 127) {
    plen = be64toh(frame->ext_payload_len.len64);
    printf("ext payload len: %zu\n", plen);
  }
  if (frame->masked) {
    printf("mask key: ");
    for (size_t i = 0; i < 4; ++i) {
      printf("%x", frame->mask_key[i]);
    }
    printf("\n");
  }
  printf("payload: %*s\n", (int)plen, frame->payload);
}

void ws_print_hex_arr(const uint8_t *frame) {
  for (size_t i = 0; i < strlen((char *)frame); ++i) {
    printf("%x ", frame[i]);
  }
}

ws_byte_arr_t ws_serialize_ws_frame(ws_frame_t *frame) {
  assert(frame != NULL && "Cannot serialize for frame = NULL.");
  size_t payload_len = ws_get_payload_len(frame);
  size_t max_frame_len = sizeof(ws_frame_t) + payload_len;
  uint8_t *frame_data = (uint8_t *)malloc(max_frame_len + 1);
  memset(frame_data, '\0', max_frame_len + 1);
  size_t curr_frame_len = 0;
  if (frame->payload_len < 126) {
    curr_frame_len += 2;
    memcpy(frame_data, frame, 2);
  }
  if (frame->payload_len == 126) {
    curr_frame_len += 4;
    memcpy(frame_data, frame, 4);
  }
  if (frame->payload_len == 127) {
    curr_frame_len += 10;
    memcpy(frame_data, frame, 10);
  }
  if (frame->masked) {
    curr_frame_len += 4;
    memcpy(frame_data + curr_frame_len, frame, 4);
  }
  memcpy(frame_data + curr_frame_len, frame->payload, payload_len);
  curr_frame_len += payload_len;
  ws_byte_arr_t res = {0};
  res.data = frame_data;
  res.len = curr_frame_len;
  return res;
}

int ws_send_ws_frame(int client_fd, ws_frame_t *frame) {
  ws_byte_arr_t s = ws_serialize_ws_frame(frame);
  if (write(client_fd, s.data, s.len) == -1) {
    ws_error("Could not write to the connection");
    return -1;
  }
  return 0;
}

int ws_send_ws_msg(int client_fd, const uint8_t *msg, size_t msg_len,
                   uint8_t options) {
  ws_frame_t frame = ws_make_ws_frame((uint8_t *)msg, msg_len, options);
  ws_byte_arr_t s = ws_serialize_ws_frame(&frame);
  if (write(client_fd, s.data, s.len) == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      ws_log("try again");
      return 1;
    }
    ws_error("Could not write to the connection");
    return -1;
  }
  return 0;
}

char *ws_make_accept_key(const char *sec_ws_key) {
  assert(sec_ws_key != NULL && "Sec-WebSocket-Key should not be NULL");
  char *new_key = ws_concat_str(sec_ws_key, WS_SHA_SUFFIX);
  char *hash =
      (char *)malloc(sizeof(uint8_t) * SHA1_HASH_LEN); // SHA1 hash is 20 bytes

  SHA1Context sha1 = {0};
  SHA1Reset(&sha1);
  SHA1Input(&sha1, (uint8_t *)new_key, strlen(new_key));
  SHA1Result(&sha1, (uint8_t *)hash);

  char *enc_key = (char *)base64_encode((byte *)hash, SHA1_HASH_LEN);

  free(hash);
  free(new_key);
  return enc_key;
}

void ws_free_headers(ws_headers *hdrs) {
  if (hdrs != NULL) {
    free(hdrs->items);
    hdrs->count = 0;
    hdrs->capacity = 0;
  }
}

void ws_free_request(ws_request_t *req) {
  if (req != NULL) {
    ws_free_headers(&req->headers);
    free(req);
    req = NULL;
  }
}

ws_frame_t ws_parse_ws_frame(uint8_t *buff, size_t len) {
  assert(buff != NULL && "Buffer should not be NULL");
  ws_frame_t frame = {0};
  frame.fin = (buff[0] & O_FIN) >> 7;
  frame.rsv1 = (buff[0] & O_RSV1) >> 6;
  frame.rsv2 = (buff[0] & O_RSV2) >> 5;
  frame.rsv3 = (buff[0] & O_RSV3) >> 4;
  frame.opcode = (buff[0] & O_OPCODE_ALL);
  frame.masked = (buff[1] & M_MASK) >> 7;
  frame.payload_len = (buff[1] & M_PAYLOAD_LEN);
  size_t offset = 2;
  size_t payload_len = 0;
  if (frame.payload_len < 126) {
    payload_len = frame.payload_len;
  } else if (frame.payload_len == 126) {
    frame.ext_payload_len.len16 = *(uint16_t *)(buff + offset);
    payload_len = be16toh(frame.ext_payload_len.len16);
    offset += 2;
  } else if (frame.payload_len == 127) {
    frame.ext_payload_len.len64 = (*(uint64_t *)(buff + offset));
    payload_len = be64toh(frame.ext_payload_len.len64);
    offset += 8;
  }
  if (frame.masked) {
    memcpy(frame.mask_key, buff + offset, 4);
    offset += 4;
  }

  uint8_t *payload = (uint8_t *)malloc(payload_len + 1);
  memset(payload, '\0', payload_len + 1);

  memcpy(payload, buff + offset, payload_len);
  offset += payload_len;

  printf("offset: %zu, payload_len: %zu\n", offset, len);
  assert(offset == len && "Did not parse the frame correctly.");

  if (frame.masked) {
    ws_unmask_payload(payload, payload_len, frame.mask_key);
  }
  frame.payload = payload;
  return frame;
}

void ws_free_frame(ws_frame_t *frame) {
  assert(frame != NULL && "Cannot free frame data = NULL");
  if (frame != NULL) {
    free(frame->payload);
  }
}

void ws_on_message(ws_server_t *server, ws_on_message_t *on_message) {
  server->on_message = on_message;
}

void ws_on_open(ws_server_t *server, ws_on_open_t *on_open) {
  server->on_open = on_open;
}

void ws_on_close(ws_server_t *server, ws_on_close_t *on_close) {
  server->on_close = on_close;
}

ws_frame_t ws_make_close_frame(const uint16_t status_code) {
  uint16_t nosc = htobe16(status_code);
  uint8_t sc[2] = {0};
  sc[0] = nosc & 0xFF00;
  sc[1] = nosc & 0x00FF;
  return ws_make_ws_frame(sc, 2, O_FIN | O_OPCODE_CLOSE);
}

#define MAX_EVENTS 100

void ws_server_start(ws_server_t *server) {
  assert(server != NULL && "Server should not be NULL");
  struct epoll_event ev, events[MAX_EVENTS];
  int epoll_fd = epoll_create(server->max_conn);
  if (epoll_fd == -1) {
    ws_panic("Could not create epoll fd.");
  }
  ev.events = EPOLLIN;
  ev.data.fd = server->fd;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server->fd, &ev) == -1) {
    ws_panic("Could not add server fd to epoll.");
  }

  int n, i, client_fd;
  bool is_existing_ws_conn = false;
  struct sockaddr_in addr = {0};
  socklen_t addr_len = sizeof(addr);
  char *buf = (char *)malloc(MAX_MSG_LEN * sizeof(char));
  size_t buf_len = MAX_MSG_LEN;

  while (true) {
    n = epoll_wait(epoll_fd, events, MAX_EVENTS, 30000);
    if (n == -1) {
      ws_panic("could not wait for events.");
    }
    for (i = 0; i < n; ++i) {
      if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) ||
          !(events[i].events & EPOLLIN)) {
        ws_error("Epoll error [EPOLLERR | EPOLLHUP | EPOLLIN]");
        close(events[i].data.fd);
        continue;
      }
      client_fd = events[i].data.fd;
      if (client_fd == -1) {
        continue;
      }
      if (events[i].data.fd == server->fd) {
        client_fd = accept(server->fd, (struct sockaddr *)&addr, &addr_len);
        if (client_fd == -1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
          }
          ws_error("Could not accept connection.");
          continue;
        }
        if (setnonblocking(client_fd) == -1) {
          ws_error("Could not make client non blocking.");
          close(client_fd);
          continue;
        };
        ev.data.fd = client_fd;
        ev.events = EPOLLIN;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) == -1) {
          ws_error("Could not add client fd to epoll list.");
          continue;
        };
      } else {
        for (size_t j = 0; j < server->clients.count; ++j) {
          printf("%d \n", server->clients.items[j].fd);
          if (client_fd == server->clients.items[j].fd) {
            is_existing_ws_conn = true;
            int len = recv(client_fd, buf, buf_len, O_NONBLOCK);
            if (len == -1) {
              if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
              }
              ws_error("Could not read on client fd.");
              continue;
            }
            ws_frame_t frame = ws_parse_ws_frame((uint8_t *)buf, len);
            ws_log("Received Frame: ");
            ws_print_ws_frame(&frame);
            if (!frame.fin ||
                (frame.opcode != O_OPCODE_TXT && frame.opcode != O_OPCODE_BIN &&
                 frame.opcode != O_OPCODE_CLOSE &&
                 frame.opcode != O_OPCODE_CONT)) {
              goto reset;
            }
            if (frame.opcode == O_OPCODE_CLOSE) {
              if (server->on_close != NULL) {
                server->on_close();
              }
              ws_close_connection(server, j);
              goto reset;
            }
            if (server->on_message != NULL) {
              server->on_message(server, &server->clients.items[j],
                                 (const char *)frame.payload,
                                 ws_get_payload_len(&frame));
            }
            ws_free_frame(&frame);
            goto reset;
          }
        }
        if (is_existing_ws_conn) {
          is_existing_ws_conn = false;
          continue;
        }
        if (recv(client_fd, buf, buf_len, O_NONBLOCK) == -1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
          }
          ws_error("Could not read on client fd.");
          continue;
        };
        ws_request_t *req = ws_parse_request(buf);
        ws_print_request(req);
        if (req == NULL) {
          ws_log("Could not parse request");
          ws_write_http_response(client_fd, 400,
                                 "Request so bad I couldn't read", NULL);
          close(client_fd);
          goto reset;
          continue;
        }
        if (!ws_is_websocket_conn(req)) {
          ws_write_http_response(
              client_fd, 400, "Only websocket connections are accepted.", NULL);
          close(client_fd);
          goto reset;
          continue;
        }
        const char *sec_ws_key = ws_get_header(req, "Sec-WebSocket-Key");
        if (sec_ws_key == NULL) {
          ws_log("Sec-WebSocket-Key header is missing.");
          ws_headers hdrs = {0};
          ws_headers_append(&hdrs, ws_make_header("Content-Type", "json"));
          ws_write_http_response(
              client_fd, 400,
              "{\"error\": \"we shill websocket connection sir.\"}", &hdrs);
          ws_free_headers(&hdrs);
          close(client_fd);
          goto reset;
        }
        char *accept_key = ws_make_accept_key(sec_ws_key);
        ws_headers headers = {0};
        ws_headers_append(&headers, ws_make_header("Upgrade", "websocket"));
        ws_headers_append(&headers, ws_make_header("Connection", "Upgrade"));
        ws_headers_append(&headers,
                          ws_make_header("Sec-WebSocket-Accept", accept_key));

        ws_write_http_response(client_fd, 101, "", &headers);
        ws_free_headers(&headers);

        ws_clients_append(&server->clients,
                          ws_make_client(client_fd, &addr, addr_len));
        server->on_open();
      }
    reset:
      memset(buf, '\0', MAX_MSG_LEN);
    }
  }
}
