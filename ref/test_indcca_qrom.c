#include <stdio.h>
#include <string.h>

#include "indcca_qrom.h"
#include "utils.h"
#include "indcpa.h"
#include "randombytes.h"
#include "aes256gcm.h"

int main() {

  unsigned char pk[KYBER_INDCPA_PUBLICKEYBYTES];
  unsigned char sk[KYBER_INDCPA_SECRETKEYBYTES];

  unsigned char ciphertext_kem[KYBER_INDCPA_BYTES];
  unsigned char ciphertext_dem[2000];
  unsigned char iv[AES_256_IVEC_LENGTH];
  unsigned char tag[AES_256_GCM_TAG_LENGTH];
  unsigned char coins[KYBER_INDCPA_MSGBYTES];

  pke_qrom_keypair(pk, sk);

  printf("sk: (encaps)");
  print_short_key(sk, KYBER_INDCPA_SECRETKEYBYTES, 10);

  randombytes(coins, KYBER_INDCPA_MSGBYTES);
  randombytes(iv, AES_256_IVEC_LENGTH);

  unsigned char m[2000] = "This is a test";
  int len_m = strlen((char*) m);
  int ciphertext_dem_len = pke_qrom_enc(m, len_m, pk, ciphertext_kem, ciphertext_dem, tag, iv, coins);

  if (ciphertext_dem_len == -1) {
    printf("Error!\n");
    return 1;
  }

  unsigned char m_dec[2000];

  int ret = pke_qrom_dec(pk, sk, ciphertext_kem,
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

  return 0;
}
