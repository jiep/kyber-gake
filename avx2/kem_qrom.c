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

  __attribute__((aligned(32)))
  uint8_t hash_coins[KYBER_SYMBYTES];

  __attribute__((aligned(32)))
  uint8_t buf_coins[KYBER_SYMBYTES];
  memcpy(buf_coins, coins, KYBER_SYMBYTES);

  hash_h(hash_coins, buf_coins, KYBER_SYMBYTES);
  indcpa_enc(c, buf_coins, pk, hash_coins);
  hash_h(K, buf_coins, KYBER_SYMBYTES);
}

void kem_qrom_decaps(unsigned char* pk, unsigned char* sk, unsigned char* c,
                     unsigned char* K) {

  __attribute__((aligned(32)))
  uint8_t m_prime[KYBER_INDCPA_MSGBYTES];
  __attribute__((aligned(32)))
  uint8_t c_prime[KYBER_INDCPA_BYTES];
  __attribute__((aligned(32)))
  uint8_t hash_m[KYBER_SYMBYTES];
  __attribute__((aligned(32)))
  uint8_t hash_key[KYBER_SYMBYTES];

  indcpa_dec(m_prime, c, sk);
  hash_h(hash_m, m_prime, KYBER_SYMBYTES);
  // printf("coins (decaps): ");
  // print_short_key(m_prime, KYBER_INDCPA_MSGBYTES, 10);
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
