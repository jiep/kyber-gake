#include <string.h>

#include "kem.h"
#include "kem_det.h"
#include "randombytes.h"
#include "symmetric.h"
#include "verify.h"
#include "indcpa.h"
#include "utils.h"

int crypto_kem_det_keypair(unsigned char *pk, unsigned char *sk) {
  return crypto_kem_keypair(pk, sk);
}

int crypto_kem_det_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk,
                   const unsigned char *coins) {

  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  randombytes(buf, KYBER_SYMBYTES);
  memcpy(buf, coins, KYBER_SYMBYTES);
  memcpy(buf+KYBER_SYMBYTES, coins, KYBER_SYMBYTES);

  /* Don't release system RNG output */
  hash_h(buf, buf, KYBER_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);

  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}


int crypto_kem_det_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk) {

  return crypto_kem_dec(ss, ct, sk);
}
