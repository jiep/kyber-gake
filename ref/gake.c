#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "api.h"
#include "kex.h"
#include "indcpa.h"
#include "randombytes.h"
#include "symmetric.h"
#include "gake.h"

// https://cboard.cprogramming.com/c-programming/101643-mod-negatives.html
int mod(int x, int y){
   int t = x - ((x / y) * y);
   if (t < 0) t += y;
   return t;
}

void xor_keys(uint8_t *x_a, uint8_t *x_b, uint8_t *x_out){

  for (int j = 0; j < KEX_SSBYTES; j++) {
    x_out[j] = x_a[j] ^ x_b[j];
  }
}

void print_key(uint8_t *key, int length) {
  for(int j = 0; j < length; j++){
    printf("%02x", key[j]);
  }
  printf("\n");
}

int check_keys(uint8_t *ka, uint8_t *kb, uint8_t *zero) {
  if(memcmp(ka, kb, KEX_SSBYTES) != 0){
    return 1;
  }

  if(!memcmp(ka, zero, KEX_SSBYTES)){
    return 2;
  }

  return 0;
}

void two_ake(uint8_t *pka, uint8_t *pkb, uint8_t *ska, uint8_t *skb, uint8_t *ka, uint8_t *kb){

  unsigned char eska[CRYPTO_SECRETKEYBYTES];

  unsigned char ake_senda[KEX_AKE_SENDABYTES];
  unsigned char ake_sendb[KEX_AKE_SENDBBYTES];

  unsigned char tk[KEX_SSBYTES];

  // Perform mutually authenticated key exchange
  kex_ake_initA(ake_senda, tk, eska, pkb); // Run by Alice
  kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pka); // Run by Bob
  kex_ake_sharedA(ka, ake_sendb, tk, eska, ska); // Run by Alice
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

void concat_masterkey(MasterKey* mk, int num_parties, uint8_t *concat_mk) {
  for (int i = 0; i < num_parties; i++) {
    memcpy(concat_mk + i*KEX_SSBYTES, &mk[i], KEX_SSBYTES);
  }
}

void print_party(Party* parties, int i, int num_parties, int show) {
  printf("Party %d\n", i);

  printf("\tPublic key: ");
  print_short_key(parties[i].public_key, CRYPTO_PUBLICKEYBYTES, show);

  printf("\tSecret key: ");
  print_short_key(parties[i].secret_key, CRYPTO_SECRETKEYBYTES, show);

  printf("\tLeft key: ");
  print_short_key(parties[i].key_left, KEX_SSBYTES, show);

  printf("\tRight key: ");
  print_short_key(parties[i].key_right, KEX_SSBYTES, show);

  printf("\tSession id: ");
  print_short_key(parties[i].sid, KEX_SSBYTES, show);

  printf("\tSession key: ");
  print_short_key(parties[i].sk, KEX_SSBYTES, show);

  printf("\tX: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tX%d: ", j);
    print_short_key(parties[i].xs[j], KEX_SSBYTES, show);
  }

  printf("\tCoins: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tr%d: ", j);
    print_short_key(parties[i].coins[j], KEX_SSBYTES, show);
  }

  printf("\tCommitments:\n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tc%d: ", j);
    print_short_key(parties[i].commitments[j], KYBER_INDCPA_BYTES, show);
  }

  printf("\tMaster Key: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tk%d: ", j);
    print_short_key(parties[i].masterkey[j], KEX_SSBYTES, show);
  }

  printf("\tPids: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tpid%d: %s\n", j, *parties[i].pids[j]);
  }
}
