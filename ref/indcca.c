#include <string.h>

#include "indcca.h"
#include "aes256gcm.h"
#include "randombytes.h"
#include "api.h"
#include "utils.h"

int pke_keypair(unsigned char* pk, unsigned char* sk) {
  return crypto_kem_keypair(pk, sk);
}

int pke_enc(unsigned char* m,
            unsigned char* pk,
            unsigned char* ciphertext_kem,
            unsigned char* ciphertext_dem,
            unsigned char* tag,
            unsigned char* iv) {

  unsigned char K[AES_256_KEY_LENGTH];

  unsigned char* aad = (unsigned char*) "";

  crypto_kem_enc(ciphertext_kem, K, pk);

  randombytes(iv, AES_256_IVEC_LENGTH);

  int ret = gcm_encrypt(m, strlen((char*) m),
                        aad, strlen((char*) aad),
                        K,
                        iv, strlen((char*) iv),
                        ciphertext_dem,
                        tag);

  return ret;

}

int pke_dec(unsigned char* sk,
            unsigned char* ciphertext_kem,
            unsigned char* ciphertext_dem,
            int ciphertext_dem_len,
            unsigned char* tag,
            unsigned char* iv,
            unsigned char* m) {

  unsigned char K[CRYPTO_BYTES];

  unsigned char* aad = (unsigned char*) "";

  crypto_kem_dec(K, ciphertext_kem, sk);

  int ret = gcm_decrypt(ciphertext_dem, ciphertext_dem_len,
                        aad, 0,
                        tag,
                        K,
                        iv, AES_256_IVEC_LENGTH,
                        m);

  return ret;
}
