#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include "stdint.h"

#define getName(var)  #var

#ifndef PID_LENGTH
#define PID_LENGTH 20
#endif

int mod(int x, int y);
void print_key(uint8_t *key, int length);
void print_short_key(uint8_t *key, int length, int show);
void print_short_key_sep(uint8_t *key, int length, int show, char* sep);
void init_to_zero(uint8_t *key, int length);
void itoa(int n, char s[]);
void reverse(char s[]);

#endif
