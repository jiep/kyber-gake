#include <stdio.h>
#include <string.h>

#include "kex_qrom.h"
#include "indcpa.h"
#include "utils.h"
#include "kex.h"
#include "ds_benchmark.h"

int main() {

  unsigned char pki[KYBER_INDCPA_PUBLICKEYBYTES];
  unsigned char ski[KYBER_INDCPA_SECRETKEYBYTES];

  unsigned char pkj[KYBER_INDCPA_PUBLICKEYBYTES];
  unsigned char skj[KYBER_INDCPA_SECRETKEYBYTES];

  unsigned char M[KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES];
  unsigned char M_prime[2*KYBER_INDCPA_BYTES];
  unsigned char st[KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_MSGBYTES + KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES];
  unsigned char K[KEX_SSBYTES];
  unsigned char K_prime[KEX_SSBYTES];

  indcpa_keypair(pki, ski);
  indcpa_keypair(pkj, skj);

  int ik = 1;
  int jk = 2;
  int iterations = 10000;

  PRINT_TIMER_HEADER

  TIME_OPERATION_ITERATIONS(
    init(pkj, M, st),
    "init",
    iterations
  )

  TIME_OPERATION_ITERATIONS(
    der_resp(skj, pki, pkj, M, ik, jk, K, M_prime),
    "der_resp",
    iterations
  )

  TIME_OPERATION_ITERATIONS(
    der_init(ski, pki, M_prime, st, ik, jk, K_prime),
    "der_init",
    iterations
  )

  PRINT_TIMER_FOOTER

  // if(memcmp(K, K_prime, KEX_SSBYTES) != 0) {
  //   printf("Error! \n");
  //   return 1;
  // }

  // printf("OK!\n");
  return 0;
}
