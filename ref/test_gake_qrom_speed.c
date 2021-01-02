#include <time.h>
#include <stdio.h>
#include <string.h>

#include "commitment_qrom.h"
#include "indcca_qrom.h"
#include "utils.h"
#include "randombytes.h"
#include "api.h"
#include "kex_qrom.h"
#include "kex.h"
#include "kem_qrom.h"

int test_check_qrom_commitment(int);
int test_check_qrom_2_ake(int);
int test_check_qrom_kem(int);

int test_check_qrom_commitment(int tests) {
  double sum_commit = 0;
  double sum_check = 0;

  for(int i = 0; i < tests; i++){
    unsigned char pk[KYBER_INDCPA_PUBLICKEYBYTES];
    unsigned char sk[KYBER_INDCPA_SECRETKEYBYTES];
    unsigned char m[36];
    unsigned char coins[COMMITMENTQROMCOINSBYTES];

    pke_qrom_keypair(pk, sk);

    randombytes(m, DEM_QROM_LEN);

    randombytes(coins, COMMITMENTQROMCOINSBYTES);

    CommitmentQROM* commitment = (CommitmentQROM*) malloc(sizeof(CommitmentQROM));

    clock_t commit_init = clock();
    commit(pk, m, DEM_QROM_LEN, coins, commitment);
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

int test_check_qrom_2_ake(int tests) {
  double sum_init     = 0;
  double sum_der_resp = 0;
  double sum_der_init = 0;

  for (int k = 0; k < tests; k++) {
    unsigned char pki[KYBER_INDCPA_PUBLICKEYBYTES];
    unsigned char ski[KYBER_INDCPA_SECRETKEYBYTES];

    unsigned char pkj[KYBER_INDCPA_PUBLICKEYBYTES];
    unsigned char skj[KYBER_INDCPA_SECRETKEYBYTES];

    unsigned char M[KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES];
    unsigned char M_prime[2*KYBER_INDCPA_BYTES];
    unsigned char st[KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_MSGBYTES + KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES];
    unsigned char K[KEX_SSBYTES];
    unsigned char K_prime[KEX_SSBYTES];

    int i = 1;
    int j = 2;

    indcpa_keypair(pki, ski);
    indcpa_keypair(pkj, skj);

    clock_t init_init = clock();
    init(pkj, M, st);
    clock_t init_end = clock();

    der_resp(skj, pki, pkj, M, i, j, K, M_prime);
    clock_t der_resp_end = clock();

    der_init(ski, pki, M_prime, st, i, j, K_prime);
    clock_t der_init_end = clock();

    if(memcmp(K, K_prime, KEX_SSBYTES) != 0) {
      return 1;
    }

    double time_init     = (double)(init_end     - init_init)    / CLOCKS_PER_SEC;
    double time_der_resp = (double)(der_resp_end - init_end)     / CLOCKS_PER_SEC;
    double time_der_init = (double)(der_init_end - der_resp_end) / CLOCKS_PER_SEC;

    sum_init   += time_init;
    sum_der_resp += time_der_resp;
    sum_der_init += time_der_init;
  }

  printf("\n\n2-AKE\n");
  printf("\tinit     time: %.12fs\n", (double) (sum_init/tests));
  printf("\tder_resp time: %.12fs\n", (double) (sum_der_resp/tests));
  printf("\tder_init time: %.12fs\n", (double) (sum_der_init/tests));

  return 0;
}

int test_check_qrom_kem(int tests) {
  double sum_kg = 0;
  double sum_encaps = 0;
  double sum_decaps = 0;
  for (int i = 0; i < tests; i++) {
    unsigned char pk[KYBER_INDCPA_PUBLICKEYBYTES];
    unsigned char sk[KYBER_INDCPA_SECRETKEYBYTES];
    unsigned char K[KYBER_SYMBYTES];
    unsigned char K_prime[KYBER_SYMBYTES];
    unsigned char c[KYBER_INDCPA_BYTES];
    unsigned char coins[KYBER_INDCPA_MSGBYTES];

    randombytes(coins, KYBER_SYMBYTES);

    clock_t init_kg = clock();
    kem_qrom_keypair(pk, sk);
    clock_t end_kg = clock();

    kem_qrom_encaps(pk, coins, K, c);
    clock_t end_encaps = clock();

    kem_qrom_decaps(pk, sk, c, K_prime);
    clock_t end_decaps = clock();

    if(memcmp(K, K_prime, KYBER_SYMBYTES) != 0) {
      return 1;
    }

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

  test_check_qrom_commitment(tests);
  test_check_qrom_2_ake(tests);
  test_check_qrom_kem(tests);
  return 0;
}
