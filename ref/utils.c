#include "utils.h"

// https://cboard.cprogramming.com/c-programming/101643-mod-negatives.html
int mod(int x, int y){
   int t = x - ((x / y) * y);
   if (t < 0) t += y;
   return t;
}

void print_key(uint8_t *key, int length) {
  for(int j = 0; j < length; j++){
    printf("%02x", key[j]);
  }
  printf("\n");
}

void init_to_zero(uint8_t *key, int length){
  for(int i = 0; i < length; i++){
    key[i] = 0;
  }
}

void print_short_key(uint8_t *key, int length, int show) {
  for (int i = 0; i < show; i++) {
    printf("%02x", key[i]);
  }
  printf("...");
  for (int i = length - show; i < length; i++) {
    printf("%02x", key[i]);
  }
  printf("\n");
}
