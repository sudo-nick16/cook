#include "../../ws.h"
#include <map>
#include <string>
#include <vector>

static const int COMMAND = 0;
static const int ROOM_ID = 1;
static const int MSG = 2;

std::map<std::string, std::vector<ws_client_t *>> rooms;

void on_close() { printf("client closed the conection.\n"); }

void on_open() { printf("opened the conection.\n"); }

void on_message(const ws_server_t *server, const ws_client_t *client,
                const char *msg, const size_t len) {
  std::string s = std::string(msg);
  std::vector<std::string> message;
  int prev = 0;
  printf("len: %ld, slen: %ld\n", len, s.length());
  int token_count = 0;
  for (int i = 0; i < s.length(); ++i) {
    if (token_count == 2) {
      message.push_back(s.substr(prev, s.length() - prev));
      break;
    }
    if (s[i] == ' ') {
      message.push_back(s.substr(prev, i - prev));
      prev = i + 1;
      token_count++;
    }
    if (i == s.length() - 1) {
      message.push_back(s.substr(prev, i - prev + 1));
      prev = i + 1;
      token_count++;
    }
  }
  printf("message: len: %ld\n", message.size());
  for (auto m : message) {
    printf("token: %s\n", m.c_str());
  }
  if (message.size() == 2 && message[COMMAND] == "join") {
    std::string room_id = message[ROOM_ID];
    printf("room- id: %s\n", room_id.c_str());
    if (rooms.find(room_id) != rooms.end()) {
      rooms[room_id].push_back((ws_client_t *)client);
      ws_log("added to the room");
    } else {
      rooms[room_id] = std::vector<ws_client_t *>({(ws_client_t *)client});
      ws_log("created room and added client");
    }
  }
  printf("rooms size: %ld", rooms.size());
  if (message.size() >= 3 && message[COMMAND] == "emit") {
    std::string room_id = message[ROOM_ID];
    printf("room- id: %s\n", room_id.c_str());
    std::string txt = message[MSG];
    if (rooms.find(room_id) != rooms.end()) {
      ws_log("found room");
      for (auto c : rooms[room_id]) {
        ws_send_ws_msg(c->fd, (uint8_t *)txt.c_str(), txt.length(),
                       O_FIN | O_OPCODE_TXT);
      }
    } else {
      ws_log("could not find room");
    }
  }
}

int main(void) {
  printf("pid: %ld, ppid: %ld\n", (long)getpid(), (long)getppid());
  ws_server_t server = ws_server_new(8080, "127.0.0.1");
  ws_on_open(&server, on_open);
  ws_on_message(&server, on_message);
  ws_on_close(&server, on_close);
  ws_server_start(&server);
  return 0;
}
