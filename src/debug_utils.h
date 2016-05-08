#ifndef _DEBUG_UTILS_H_
#define _DEBUG_UTILS_H_

// Internal helper function. Just shorthand.
static int _is_printable(int ch) {
  return (ch >= '0' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
}

// Renders a buffer as side-by-side hex and ASCII printable dump.
static void debug_dump(unsigned char *buf, unsigned int buflen) {
  unsigned char *end = buf + buflen;
  int i;
  for (i = 0; buf < end; i++, buf++) {
    if (i && !(i % 16)) {
      printf(" ");
      for (int j = 0; j < 16; j++)
        printf("%c", _is_printable(buf[j - 16]) ? buf[j - 16] : '.');
      printf("\n");
    }
    printf("%02x ", *buf);
  }
  while ((i % 16)) {
    printf("   ");
    buf++;
    i++;
  }
  printf(" ");
  buf -= 16;
  while (buf < end) {
    printf("%c", _is_printable(*buf) ? *buf : '.');
    buf++;
  }
  printf("\n");
}

#endif // _DEBUG_UTILS_H_
