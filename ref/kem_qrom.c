#include <string.h>
#include <stdio.h>

#include "kem_qrom.h"
#include "indcpa.h"
#include "symmetric.h"
#include "utils.h"

void kem_qrom_keypair(unsigned char* pk, unsigned char* sk) {
  indcpa_keypair(pk, sk);
}

void kem_qrom_encaps(unsigned char* pk, unsigned char* coins,
                     unsigned char* K, unsigned char* c) {

  unsigned char hash_coins[KYBER_SYMBYTES];

  hash_h(hash_coins, coins, KYBER_SYMBYTES);
  indcpa_enc(c, coins, pk, hash_coins);
  hash_h(K, coins, KYBER_SYMBYTES);
}

void kem_qrom_decaps(unsigned char* pk, unsigned char* sk, unsigned char* c,
                     unsigned char* K) {

  unsigned char m_prime[KYBER_INDCPA_MSGBYTES];
  unsigned char c_prime[KYBER_INDCPA_BYTES];
  unsigned char hash_m[KYBER_SYMBYTES];
  unsigned char hash_key[KYBER_SYMBYTES];

  indcpa_dec(m_prime, c, sk);
  hash_h(hash_m, m_prime, KYBER_SYMBYTES);
  indcpa_enc(c_prime, m_prime, pk, hash_m);

  if(memcmp(c_prime, c, KYBER_INDCPA_BYTES) != 0) {
    hash_h(hash_key, c, KYBER_SYMBYTES);
    memcpy(K, hash_key, KYBER_SYMBYTES);
    printf("Error decaps\n");
  } else {
    hash_h(hash_key, m_prime, KYBER_SYMBYTES);
    memcpy(K, hash_key, KYBER_SYMBYTES);
  }
}
