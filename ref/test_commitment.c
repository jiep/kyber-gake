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
  unsigned char m[1000];
  unsigned char m2[1000];
  unsigned char coins[COMMITMENTCOINSBYTES];
  unsigned char coins2[COMMITMENTCOINSBYTES];

  pke_keypair(pk, sk);

  randombytes(m, 1000);
  printf("m: ");
  print_key(m, DEM_LEN);

  randombytes(coins, COMMITMENTCOINSBYTES);
  printf("coins: ");
  print_key(coins, COMMITMENTCOINSBYTES);

  Commitment* commitment = (Commitment*) malloc(sizeof(Commitment));
  Commitment* commitment2 = (Commitment*) malloc(sizeof(Commitment));

  commit(pk, m, DEM_LEN, coins, commitment);

  print_commitment(commitment);
  printf(".............................................................\n");

  int equal = check_commitment(pk, m, coins, commitment);


  if (equal == 0) {
    printf("Commitments are equal!\n");
  } else {
    printf("Commitments are NOT equal!\n");
  }

  memcpy(coins2, coins, COMMITMENTCOINSBYTES);
  memcpy(m2, m, 1000);

  int equal1 = check_commitment(pk, m2, coins2, commitment);

  if (equal1 == 0) {
    printf("Commitments are equal!\n");
  } else {
    printf("Commitments are NOT equal!\n");
  }

  free(commitment);
  free(commitment2);

  return 0;
}
