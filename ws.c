#include <arpa/inet.h>
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

void die(const char *s) {
  perror(s);
  exit(1);
}

const static size_t MAX_MSG_LEN = 4096;

int main(void) {
  char *PORT = getenv("PORT");
  if (PORT == NULL) {
    printf("[ERROR] Could not get PORT from env\n");
    exit(1);
  }
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    die("server fd");
  }
  struct sockaddr_in server_addr = {0};
  server_addr.sin_port = htons(atoi(PORT));
  printf("port: %u\n", server_addr.sin_port);
  server_addr.sin_family = AF_INET;
  // server_addr.sin_addr.s_addr = (uint32_t)0x7f000001;
  server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  socklen_t server_addr_len = sizeof(server_addr);
  if (bind(server_fd, (struct sockaddr *)&server_addr, server_addr_len) == -1) {
    die("bind");
  }
  if (listen(server_fd, 4096) == -1) {
    die("listen");
  }
  while (true) {
    struct sockaddr_in client_addr = {0};
    socklen_t client_addr_len = sizeof(client_addr);
    int client_fd =
        accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd == -1) {
      die("client fd");
    }
    char *buf = (char *)malloc(MAX_MSG_LEN * sizeof(char));
    size_t len = MAX_MSG_LEN;
    memset(buf, '\0', len);
    if (recv(client_fd, buf, len, 0) == -1) {
      die("recv");
    }
    printf("Msg from client: %s\n", buf);
    char *resp = "HTTP/1.1 200\r\n\r\nhello from server";
    if (write(client_fd, resp, strlen(resp)) == -1) {
      die("write");
    };
    if (close(client_fd) == -1) {
      die("close");
    }
  }
}
