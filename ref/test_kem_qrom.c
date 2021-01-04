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

    randombytes(coins, KYBER_INDCPA_MSGBYTES);

    kem_qrom_encaps(pk, coins, K, c);

    kem_qrom_decaps(pk, sk, c, K_prime);

    if(memcmp(K, K_prime, KYBER_SYMBYTES) != 0) {
      printf("Error\n");
      return 1;
    }
  }

  printf("OK!\n");

  return 0;
}
