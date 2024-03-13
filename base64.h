#ifndef BASE64_ENC
#define BASE64_ENC

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t byte;

#ifdef __cplusplus
extern "C" {
#endif

extern const char ENCODING[64];
extern byte *base64_encode(byte *s, size_t s_len);

#ifdef __cplusplus
}
#endif

#ifdef BASE64_ENC_IMPLEMENTATION
const char ENCODING[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

static const char PAD = '=';

byte *base64_encode(byte *s, size_t s_len) {
  size_t enc_len = 4 * ((s_len + 3 - 1) / 3);
  byte *enc = (byte *)malloc(enc_len + 1);
  if (enc == NULL) {
    printf("[BASE64 ERROR] Could not allocate memory for the encoded "
           "string.");
    return NULL;
  }
  memset(enc, '\0', enc_len + 1);
  size_t off = 0;
  for (size_t i = 0; i < s_len; i += 3) {
    enc[off++] = ENCODING[(s[i] & 0xFC) >> 2];
    if (i + 1 < s_len) {
      enc[off++] = ENCODING[((s[i] & 0x03) << 4) | ((s[i + 1] & 0xF0) >> 4)];
    } else {
      enc[off++] = ENCODING[(s[i] & 0x03) << 4];
      enc[off++] = PAD;
      enc[off++] = PAD;
      break;
    }
    if (i + 2 < s_len) {
      enc[off++] =
          ENCODING[((s[i + 1] & 0x0F) << 2) | ((s[i + 2] & 0xC0) >> 6)];
    } else {
      enc[off++] = ENCODING[(s[i + 1] & 0x0F) << 2];
      enc[off++] = PAD;
      break;
    }
    enc[off++] = ENCODING[s[i + 2] & 0x3F];
  }
  return enc;
};
#endif // BASE64_ENC_IMPLEMENTATION

#endif // !BASE64_ENC
