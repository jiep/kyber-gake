#include <stdio.h>
#include <string.h>

#include "kem_qrom.h"
#include "indcpa.h"
#include "randombytes.h"
#include "utils.h"

int main() {

  unsigned char pk[KYBER_INDCPA_PUBLICKEYBYTES];
  unsigned char sk[KYBER_INDCPA_SECRETKEYBYTES];
  unsigned char K[KYBER_SYMBYTES];
  unsigned char K_prime[KYBER_SYMBYTES];
  unsigned char c[KYBER_INDCPA_BYTES];
  unsigned char coins[KYBER_INDCPA_MSGBYTES];


  for (int i = 0; i < 1000; i++) {

    kem_qrom_keypair(pk, sk);

    // printf("pk: ");
    // print_short_key(pk, KYBER_INDCPA_PUBLICKEYBYTES, 10);

    // printf("sk: ");
    // print_short_key(sk, KYBER_INDCPA_SECRETKEYBYTES, 10);

    randombytes(coins, KYBER_INDCPA_MSGBYTES);

    // printf("coins: ");
    // print_short_key(coins, KYBER_INDCPA_MSGBYTES, 10);

    kem_qrom_encaps(pk, coins, K, c);

    // printf("c: ");
    // print_key(c, KYBER_INDCPA_BYTES);

    // printf("K: ");
    // print_key(K, KYBER_SYMBYTES);

    kem_qrom_decaps(pk, sk, c, K_prime);

    // printf("K': ");
    // print_key(K_prime, KYBER_SYMBYTES);

    if(memcmp(K, K_prime, KYBER_SYMBYTES) != 0) {
      printf("Error\n");
      return 1;
    }
  }

  printf("OK!\n");

  return 0;
}
