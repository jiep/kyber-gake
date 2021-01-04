#include <stdio.h>
#include <string.h>

#include "kex_qrom.h"
#include "indcpa.h"
#include "utils.h"
#include "kex.h"

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

  for (int k = 0; k < 1000; k++) {
    indcpa_keypair(pki, ski);
    indcpa_keypair(pkj, skj);

    int i = 1;
    int j = 2;

    init(pkj, M, st);

    der_resp(skj, pki, pkj, M, i, j, K, M_prime);

    der_init(ski, pki, M_prime, st, i, j, K_prime);

    if(memcmp(K, K_prime, KEX_SSBYTES) != 0) {
      printf("Error! \n");
      return 1;
    }
  }

  printf("OK!\n");
  return 0;
}
