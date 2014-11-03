// hex decoder

#include "hex.h"
#include <string.h>

int hex_decode(const char *encoded, uint8_t *result, int bufSize) {
  int bufpos = 0;
  uint8_t temp = 0;
  uint8_t halfbyte = 0;
  const char* ptr;
  for (ptr = encoded; bufpos<bufSize && *ptr; ptr++) {
      if (*ptr >= '0' && *ptr <='9') {
	  temp <<= 4;
      	  temp |= *ptr - '0';
      	  halfbyte++;
            } else
      	if (*ptr >='a' && *ptr <='f') {
      	    temp <<= 4;
      	    temp |= *ptr - 'a' + 0x0a;
      	    halfbyte++;
      	} else
      	  if (*ptr >='A' && *ptr <='F') {
      	      temp <<= 4;
      	      temp |= *ptr - 'A' + 0x0a;
      	      halfbyte++;
      	  }

      if (halfbyte == 2) {
	  result[bufpos] = temp;
	  bufpos++;
	  temp = 0;
	  halfbyte = 0;
      }
  }
  return bufpos;
}
