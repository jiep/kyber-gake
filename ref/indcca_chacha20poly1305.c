#include <string.h>

#include "indcca_chacha20poly1305.h"
#include "chacha20poly1305.h"
#include "randombytes.h"
#include "api.h"
#include "utils.h"
#include "kem_det.h"

void print_data(unsigned char* m,
                int len_m,
                unsigned char* pk,
                unsigned char* ciphertext_kem,
                unsigned char* ciphertext_dem,
                unsigned char* tag,
                unsigned char* iv,
                unsigned char* coins) {

  printf("Ciphertext KEM: ");
  print_key(ciphertext_kem, KYBER_CIPHERTEXTBYTES);

  printf("Ciphertext DEM: ");
  print_key(ciphertext_dem, 32);

  printf("Tag: ");
  print_key(tag, CHACHA20POLY1305_TAG_LENGTH);

  printf("IV: ");
  print_key(iv, CHACHA20POLY1305_IVEC_LENGTH);

  printf("\tcoins: ");
  print_key(coins, KYBER_SYMBYTES);

  printf("\tpk: ");
  print_short_key(pk, CRYPTO_PUBLICKEYBYTES, 10);

  print_key(m, len_m);
}

int pke_chacha20poly1305_keypair(unsigned char* pk, unsigned char* sk) {
  return crypto_kem_keypair(pk, sk);
}

int pke_chacha20poly1305_enc(unsigned char* m,
            int len_m,
            unsigned char* pk,
            unsigned char* ciphertext_kem,
            unsigned char* ciphertext_dem,
            unsigned char* tag,
            unsigned char* iv,
            unsigned char* coins) {

  unsigned char K[CHACHA20POLY1305_KEY_LENGTH];

  unsigned char* aad = (unsigned char*) "";

  crypto_kem_det_enc(ciphertext_kem, K, pk, coins);

  int ret = chacha20poly1305_encrypt(m, len_m,
                                     aad, strlen((char*) aad),
                                     K,
                                     iv,
                                     ciphertext_dem,
                                     tag);

  return ret;

}

int pke_chacha20poly1305_dec(unsigned char* sk,
            unsigned char* ciphertext_kem,
            unsigned char* ciphertext_dem,
            int ciphertext_dem_len,
            unsigned char* tag,
            unsigned char* iv,
            unsigned char* m) {

  unsigned char K[CRYPTO_BYTES];

  unsigned char* aad = (unsigned char*) "";

  crypto_kem_det_dec(K, ciphertext_kem, sk);

  int ret = chacha20poly1305_decrypt(ciphertext_dem, ciphertext_dem_len,
                                     aad, 0,
                                     tag,
                                     K,
                                     iv, CHACHA20POLY1305_IVEC_LENGTH,
                                     m);

  return ret;
}
