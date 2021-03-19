#include <time.h>
#include <stdio.h>
#include <string.h>

#include "commitment_chacha20poly1305.h"
#include "indcca_chacha20poly1305.h"
#include "utils.h"
#include "randombytes.h"
#include "api.h"
#include "kex.h"
#include "kem_det.h"

int test_check_commitment(int);

int test_check_commitment(int tests) {
  double sum_commit = 0;
  double sum_check = 0;

  for(int i = 0; i < tests; i++){
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char m[DEM_LEN];
    unsigned char coins[COMMITMENTCOINSBYTES];

    pke_chacha20poly1305_keypair(pk, sk);

    randombytes(m, DEM_LEN);

    randombytes(coins, COMMITMENTCOINSBYTES);

    Commitment* commitment = (Commitment*) malloc(sizeof(Commitment));

    clock_t commit_init = clock();
    commit(pk, m, DEM_LEN, coins, commitment);
    clock_t commit_end  = clock();

    int equal = check_commitment(pk, m, coins, commitment);
    clock_t check_end  = clock();

    if (equal != 0) {
      return 1;
    }

    free(commitment);

    double time_commit = (double)(commit_end - commit_init) / CLOCKS_PER_SEC;
    double time_check  = (double)(check_end  - commit_end)  / CLOCKS_PER_SEC;
    sum_commit += time_commit;
    sum_check += time_check;
  }

  printf("\n\nCommitment CHACHA20-POLY1305\n");
  printf("\tCommit time: %.12fs\n", (double) (sum_commit/tests));
  printf("\tCheck  time: %.12fs\n", (double) (sum_check /tests));
  return 0;
}

int main(int argc, char const *argv[]) {

  if (argc != 2) {
    printf("You must provide the number of tests!\n");
    return 1;
  }

  int tests = atoi(argv[1]);

  test_check_commitment(tests);
  return 0;
}
