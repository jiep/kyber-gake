#include <stdio.h>

#include "emoji.h"
#include "../ref/randombytes.h"

#define LENGTH 32
int main() {

  unsigned char key[LENGTH];
  randombytes(key, LENGTH);

  char* emojified_key[4];

  emojify(key, emojified_key);

  print_emojified_key(emojified_key);
  return 0;
}
