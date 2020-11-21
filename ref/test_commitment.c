#include <stdio.h>
#include <string.h>

#include "commitment.h"
#include "indcca.h"
#include "utils.h"
#include "randombytes.h"
#include "api.h"

int main() {

  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char m[1000] = "Hello! This a commitment.";
  unsigned char coins[COMMITMENTCOINSBYTES];
  unsigned char coins2[COMMITMENTCOINSBYTES];

  pke_keypair(pk, sk);

  randombytes(coins, COMMITMENTCOINSBYTES);
  printf("coins: ");
  print_key(coins, COMMITMENTCOINSBYTES);

  Commitment* commitment = (Commitment*) malloc(sizeof(Commitment));

  commit(pk, m, coins, commitment);

  print_commitment(commitment);

  int equal = check_commitment(pk, m, coins, commitment);


  if (equal == 0) {
    printf("Commitments are equal!\n");
  } else {
    printf("Commitments are NOT equal!\n");
  }

  unsigned char m2[1000] = "Hello! This a commitment2.";
  commit(pk, m2, coins, commitment);

  int equal2 = check_commitment(pk, m, coins, commitment);

  if (equal2 == 0) {
    printf("Commitments are equal!\n");
  } else {
    printf("Commitments are NOT equal!\n");
  }

  commit(pk, m2, coins2, commitment);

  randombytes(coins2, COMMITMENTCOINSBYTES);
  printf("coins2: ");
  print_key(coins2, COMMITMENTCOINSBYTES);

  int equal3 = check_commitment(pk, m, coins2, commitment);

  if (equal3 == 0) {
    printf("Commitments are equal!\n");
  } else {
    printf("Commitments are NOT equal!\n");
  }

  free(commitment);



  return 0;
}
