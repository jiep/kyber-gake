#include <stdio.h>
#include "stdint.h"

#define getName(var)  #var

int mod(int x, int y);
void print_key(uint8_t *key, int length);
void print_short_key(uint8_t *key, int length, int show);
void init_to_zero(uint8_t *key, int length);
void itoa(int n, char s[]);
void reverse(char s[]);
