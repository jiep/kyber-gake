#include <string.h>

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

void print_short_key_sep(uint8_t *key, int length, int show, char* sep) {
  for (int i = 0; i < show; i++) {
    printf("%02x", key[i]);
  }
  printf("...");
  for (int i = length - show; i < length; i++) {
    printf("%02x", key[i]);
  }
  printf("%s", sep);
}

void itoa(int n, char s[]) {
     int i, sign;

     if ((sign = n) < 0)  /* record sign */
         n = -n;          /* make n positive */
     i = 0;
     do {       /* generate digits in reverse order */
         s[i++] = n % 10 + '0';   /* get next digit */
     } while ((n /= 10) > 0);     /* delete it */
     if (sign < 0)
         s[i++] = '-';
     s[i] = '\0';
     reverse(s);
}

void reverse(char s[]) {
    int i, j;
    char c;

    for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
        c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}
