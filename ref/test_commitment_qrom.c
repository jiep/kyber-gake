#include <stdio.h>
#include <string.h>

#include "commitment_qrom.h"
#include "indcca_qrom.h"
#include "utils.h"
#include "randombytes.h"

int main() {

  unsigned char pk[KYBER_INDCPA_PUBLICKEYBYTES];
  unsigned char sk[KYBER_INDCPA_SECRETKEYBYTES];
  unsigned char m[1000] = "Hello! This a commitment.";
  unsigned char coins[COMMITMENTQROMCOINSBYTES];

  pke_qrom_keypair(pk, sk);

  randombytes(coins, COMMITMENTQROMCOINSBYTES);

  CommitmentQROM* commitment = (CommitmentQROM*) malloc(sizeof(CommitmentQROM));

  for (int i = 0; i < 5; i++) {
    printf("coins: ");
    print_key(coins, COMMITMENTQROMCOINSBYTES);

    commit(pk, m, DEM_QROM_LEN, coins, commitment);

    print_commitment(commitment);

    int equal = check_commitment(pk, m, coins, commitment);

    if (equal == 0) {
      printf("Commitments are equal!\n");
    } else {
      printf("Commitments are NOT equal!\n");
    }
  }

  free(commitment);

  return 0;
}
