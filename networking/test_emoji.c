#include <stdio.h>

#include "emoji.h"
#include "../ref/randombytes.h"

#define LENGTH 32
int main() {

  unsigned char key[LENGTH];
  randombytes(key, LENGTH);

  char* emojified_key[4];

  emojify(key, emojified_key);

  for (int i = 0; i < 4; i++) {
    printf("%s ", emojified_key[i]);
  }
  printf("\n");
  return 0;
}
