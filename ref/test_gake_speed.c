#include <time.h>
#include <stdio.h>
#include <string.h>

#include "commitment.h"
#include "indcca.h"
#include "utils.h"
#include "randombytes.h"
#include "api.h"
#include "kex.h"
#include "kem_det.h"

int test_check_commitment(int);
int test_check_2_ake(int);
int test_check_kem(int);

int test_check_commitment(int tests) {
  double sum_commit = 0;
  double sum_check = 0;

  for(int i = 0; i < tests; i++){
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char m[36];
    unsigned char coins[COMMITMENTCOINSBYTES];

    pke_keypair(pk, sk);

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

  printf("\n\nCommitment\n");
  printf("\tCommit time: %.12fs\n", (double) (sum_commit/tests));
  printf("\tCheck  time: %.12fs\n", (double) (sum_check /tests));
  return 0;
}

int test_check_2_ake(int tests) {
  double sum_initA    = 0;
  double sum_sharedB  = 0;
  double sum_sharedA  = 0;

  for (int i = 0; i < tests; i++) {
    unsigned char pkb[CRYPTO_PUBLICKEYBYTES];
    unsigned char skb[CRYPTO_SECRETKEYBYTES];

    unsigned char pka[CRYPTO_PUBLICKEYBYTES];
    unsigned char ska[CRYPTO_SECRETKEYBYTES];

    unsigned char eska[CRYPTO_SECRETKEYBYTES];

    unsigned char ake_senda[KEX_AKE_SENDABYTES];
    unsigned char ake_sendb[KEX_AKE_SENDBBYTES];

    unsigned char tk[KEX_SSBYTES];
    unsigned char ka[KEX_SSBYTES];
    unsigned char kb[KEX_SSBYTES];
    unsigned char zero[KEX_SSBYTES];

    for(int j=0;j<KEX_SSBYTES;j++)
      zero[j] = 0;

    crypto_kem_keypair(pkb, skb);

    crypto_kem_keypair(pka, ska);

    clock_t initA_init = clock();
    kex_ake_initA(ake_senda, tk, eska, pkb);
    clock_t initA_end = clock();

    kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pka);
    clock_t sharedB_end = clock();

    kex_ake_sharedA(ka, ake_sendb, tk, eska, ska);
    clock_t sharedA_end = clock();

    if(memcmp(ka, kb, KEX_SSBYTES))
      return 1;

    if(!memcmp(ka, zero, KEX_SSBYTES))
      return 1;

    double time_initA    = (double)(initA_end   - initA_init)   / CLOCKS_PER_SEC;
    double time_sharedB  = (double)(sharedB_end - initA_end)    / CLOCKS_PER_SEC;
    double time_sharedA  = (double)(sharedA_end - sharedB_end)  / CLOCKS_PER_SEC;

    sum_initA   += time_initA;
    sum_sharedB += time_sharedB;
    sum_sharedA += time_sharedA;
  }

  printf("\n\n2-AKE\n");
  printf("\tinitA   time: %.12fs\n", (double) (sum_initA/tests));
  printf("\tsharedB time: %.12fs\n", (double) (sum_sharedB/tests));
  printf("\tsharedA time: %.12fs\n", (double) (sum_sharedA/tests));

  return 0;
}

int test_check_kem(int tests) {
  double sum_kg = 0;
  double sum_encaps = 0;
  double sum_decaps = 0;
  for (int i = 0; i < tests; i++) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char key_a[CRYPTO_BYTES];
    unsigned char key_b[CRYPTO_BYTES];
    unsigned char coins[KYBER_SYMBYTES];

    randombytes(coins, KYBER_SYMBYTES);

    clock_t init_kg = clock();
    crypto_kem_det_keypair(pk, sk);
    clock_t end_kg = clock();

    crypto_kem_det_enc(ct, key_b, pk, coins);
    clock_t end_encaps = clock();

    crypto_kem_det_dec(key_a, ct, sk);
    clock_t end_decaps = clock();

    if(memcmp(key_a, key_b, CRYPTO_BYTES))
      return 1;

    double time_kg      = (double)(end_kg      - init_kg)     / CLOCKS_PER_SEC;
    double time_encaps  = (double)(end_encaps  - end_kg)      / CLOCKS_PER_SEC;
    double time_decaps  = (double)(end_decaps  - end_encaps)  / CLOCKS_PER_SEC;

    sum_kg += time_kg;
    sum_encaps += time_encaps;
    sum_decaps += time_decaps;

  }

  printf("\n\nKEM\n");
  printf("\tkeygen time: %.12fs\n", (double) (sum_kg/tests));
  printf("\tencaps time: %.12fs\n", (double) (sum_encaps/tests));
  printf("\tdecaps time: %.12fs\n", (double) (sum_decaps/tests));

  return 0;
}

int main(int argc, char const *argv[]) {

  if (argc != 2) {
    printf("You must provide the number of tests!\n");
    return 1;
  }

  int tests = atoi(argv[1]);

  test_check_commitment(tests);
  test_check_2_ake(tests);
  test_check_kem(tests);
  return 0;
}
