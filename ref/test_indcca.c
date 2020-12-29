#include <string.h>

#include "indcca.h"
#include "utils.h"
#include "api.h"
#include "aes256gcm.h"
#include "randombytes.h"

int main() {

  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char ciphertext_kem[CRYPTO_CIPHERTEXTBYTES];
  unsigned char ciphertext_dem[2000];
  unsigned char tag[AES_256_GCM_TAG_LENGTH];
  unsigned char iv[AES_256_IVEC_LENGTH];
  unsigned char coins[KYBER_SYMBYTES];

  printf("Key generation\n");
  pke_keypair(pk, sk);

  randombytes(coins, KYBER_SYMBYTES);

  randombytes(iv, AES_256_IVEC_LENGTH);
  printf("iv to function: ");
  print_key(iv, AES_256_IVEC_LENGTH);

  unsigned char* m = (unsigned char *) "The quick brown fox jumps over the lazy dog";

  printf("\tplaintext: %s\n", m);

  for (int i = 0; i < 5; i++) {

    printf("Encryption\n");
    size_t len_m = strlen((char*) m);
    int ciphertext_dem_len = pke_enc(m, len_m,  pk, ciphertext_kem,
                                     ciphertext_dem, tag, iv, coins);

    if (ciphertext_dem_len == -1) {
      printf("Error!\n");
      return 1;
    }

    unsigned char m_dec[2000];

    int ret = pke_dec(sk, ciphertext_kem,
                ciphertext_dem,
                ciphertext_dem_len,
                tag,
                iv,
                m_dec);

    if (ret == -1) {
      printf("Error!\n");
      return 1;
    }

    m_dec[ret] = '\0';
    printf("Plaintext: %s\n", m_dec);
  }

  return 0;
}
