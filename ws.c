#include "base64.h"
#include "sha1.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

const static size_t MAX_MSG_LEN = 4096;

typedef struct ws_server_t {
  uint16_t port;
  char *address;
  int server_fd;
  int *clients;
  size_t client_n;
  size_t max_conn;
} ws_server;

typedef struct ws_client_t {
  int fd;
} Client;

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

void ws_die(const char *s) {
  perror(s);
  exit(1);
}

void ws_error(const char *s) { printf("[ERROR] %s: %s\n", s, strerror(errno)); }

void ws_log(const char *s) { printf("[LOG] %s\n", s); }

char *ws_concat_str(const char *s1, const char *s2) {
  assert(s1 != NULL && s2 != NULL && "Provided string should not be NULL");
  size_t s1_len = strlen(s1);
  size_t s2_len = strlen(s2);
  size_t s_len = s1_len + s2_len + 1;
  char *s = malloc(sizeof(char) * s_len);
  memset(s, '\0', s_len);
  strncat(s, s1, s1_len);
  strncat(s, s2, s2_len);
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

void ws_free_request(ws_request_t *req) {
  if (req != NULL) {
    free(req);
    req = NULL;
  }
}

const size_t http_methods_n = 5;
const char *http_methods[] = {"GET",   "POST",   "PUT",
                              "PATCH", "DELETE", "OPTIONS"};
// const size_t http_headers_n = 4;
// const char *http_headers[] = {"Host", "User-Agent", "Accept",
// "Content-Type"};

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

// bool ws_is_valid_http_header(const char *s) {
//   for (size_t i = 0; i < http_headers_n; ++i) {
//     if (strncmp(s, http_headers[i], strlen(http_headers[i])) == 0) {
//       return true;
//     }
//   }
//   return false;
// }

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
  char *token = malloc((len + 1) * sizeof(char));
  memset(token, '\0', len + 1);
  strncpy(token, s, len);
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
    printf("Token: %s\n", token);
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

ws_server ws_server_new(uint16_t port, const char *address) {
  ws_server server = {0};
  server.max_conn = 1000;
  int clients[1000] = {0};
  server.clients = clients;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) {
    ws_die("server socket");
  }
  int option_value = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option_value,
                 sizeof(int)) == -1) {
    ws_die("server setsocketopt");
  };
  server.server_fd = fd;

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(address);
  socklen_t addr_len = sizeof(addr);

  if (bind(fd, (struct sockaddr *)&addr, addr_len) == -1) {
    ws_die("server bind");
  };
  if (listen(fd, 4096) == -1) {
    ws_die("server listen");
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

typedef struct ws_status_t {
  uint16_t code;
  char *reason;
} ws_status_t;

#define ws_status_n 3
static const ws_status_t status_map[ws_status_n] = {
    {101, "Switching Protocols"},
    {200, "OK"},
    {400, "Bad Request"},
};

const char *ws_get_status_reason(uint16_t code) {
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
  size_t expected_match_count = 2;
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
  }
  if (match_headers_count < expected_match_count) {
    return false;
  }
  return true;
}

void ws_close_connection(int fd) {
  if (close(fd) == -1) {
    ws_error("Could not close connection");
  };
}

char *ws_headers_to_str(ws_headers *hdrs) {
  assert(hdrs != NULL && "Headers are null.");
  size_t hdrs_len = 0;
  for (size_t i = 0; i < hdrs->count; ++i) {
    hdrs_len += strlen(hdrs->items[i].key) + strlen(hdrs->items[i].value) +
                strlen(": \r\n");
  }
  // for null terminator
  hdrs_len++;
  char *hdrs_str = (char *)malloc(hdrs_len);
  memset(hdrs_str, '\0', hdrs_len);
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

// char *ws_to_char_arr(uint8_t *str) {
//
//
// }

void ws_write_http_response(int fd, uint16_t code, const char *msg,
                            ws_headers *hdrs) {
  assert(msg != NULL && "Message should not be NULL");
  const char *reason = ws_get_status_reason(code);
  const char *http_version = "HTTP/1.1";
  char *headers = "";
  if (hdrs != NULL) {
    headers = ws_headers_to_str(hdrs);
  }
  size_t len =
      strlen(http_version) + strlen(reason) + 6 + strlen(headers) + strlen(msg);

  assert(len <= MAX_MSG_LEN && "Response body exceeds MAX set memory.");

  char *s = malloc(MAX_MSG_LEN * sizeof(char));
  memset(s, '\0', MAX_MSG_LEN);
  sprintf(s, "%s %u %s\r\n%s\r\n%s", http_version, code, reason, headers, msg);
  if (write(fd, s, strlen(s)) == -1) {
    ws_error("Could not write to the connection");
  }
  printf("Response:\n%s\n", s);
  free(s);
  if (hdrs != NULL) {
    free(headers);
  }
}

size_t ws_add_client(ws_server *server, int client_fd) {
  if (server->client_n < server->max_conn) {
    server->clients[server->client_n++] = client_fd;
    return server->client_n - 1;
  }
  assert(false && "TODO: Handle more than max connections.");
}

void ws_broadcast_ws_msg(ws_server *server, char *msg) {
  for (size_t i = 0; i < server->client_n; ++i) {
    write(server->clients[i], msg, strlen(msg));
  }
}

void ws_server_start(ws_server *server) {
  while (true) {
    struct sockaddr_in addr = {0};
    socklen_t addr_len = sizeof(addr);
    int client_fd =
        accept(server->server_fd, (struct sockaddr *)&addr, &addr_len);
    if (client_fd == -1) {
      ws_die("server accept");
    };
    char *buf = (char *)malloc(MAX_MSG_LEN * sizeof(char));
    size_t n = MAX_MSG_LEN;
    if (recv(client_fd, buf, n, 0) == -1) {
      ws_die("server read request");
    };
    ws_request_t *req = ws_parse_request(buf);
    free(buf);
    ws_print_request(req);
    if (req == NULL) {
      ws_log("Could not parse request");
      ws_write_http_response(client_fd, 400, "sorry bro", NULL);
      ws_close_connection(client_fd);
      continue;
    }
    if (!ws_is_websocket_conn(req)) {
      ws_log("Not a websocket connection");
    }
    const char *magic_no = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const char *sec_ws_key = ws_get_header(req, "Sec-WebSocket-Key");
    if (sec_ws_key == NULL) {
      ws_log("Sec-WebSocket-Key header is missing.");
      ws_headers hdrs = {0};
      ws_headers_append(&hdrs, ws_make_header("fuck", "off"));
      ws_write_http_response(client_fd, 400, "Bad websocket request", &hdrs);
      ws_close_connection(client_fd);
      continue;
    }

    char *new_key = ws_concat_str(sec_ws_key, magic_no);
    uint8_t *hash = malloc(sizeof(uint8_t) * 20);
    printf("New Key: %s\n", new_key);

    SHA1Context sha1 = {0};
    SHA1Reset(&sha1);
    SHA1Input(&sha1, (uint8_t *)new_key, strlen(new_key));
    SHA1Result(&sha1, hash);

    printf("Hash: ");
    for (int i = 0; i < 20; ++i) {
      printf("%x", hash[i]);
    }
    printf("\n");

    char *hash_value = (char *)malloc(40 * sizeof(char));
    memset(hash_value, '\0', 40);
    Base64encode(hash_value, (char *)hash, strlen((char *)hash));
    printf("Base64 encoded value: %s\n", hash_value);

    ws_headers headers = {0};
    ws_headers_append(&headers, ws_make_header("Upgrade", "websocket"));
    ws_headers_append(&headers, ws_make_header("Connection", "Upgrade"));
    ws_headers_append(&headers,
                      ws_make_header("Sec-WebSocket-Accept", hash_value));

    ws_write_http_response(client_fd, 101, "", &headers);
    ws_add_client(server, client_fd);
		// send web socket frame in msg
    free(hash_value);
    // ws_close_connection(client_fd);
  }
}

int main(void) {
  ws_server server = ws_server_new(8080, "127.0.0.1");
  ws_server_start(&server);
}
