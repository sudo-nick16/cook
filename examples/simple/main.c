#include "../../ws.h"

void callback(const ws_client_t *client, const char *msg, const size_t len) {
  printf("Address: %s, Port: %s\n", client->address, client->port);
  printf("Received message: %s of length %zu\n", msg, len);
}

int main(void) {
  ws_server_t server = ws_server_new(8080, "127.0.0.1");
  ws_on_message(&server, callback);
  ws_server_start(&server);
  return 0;
}
