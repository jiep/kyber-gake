#include <string.h>

#include "commitment.h"
#include "indcca.h"
#include "utils.h"
#include "randombytes.h"
#include "api.h"

void print_commitment(Commitment* commitment) {
  print_short_key_sep(commitment->ciphertext_kem, KYBER_CIPHERTEXTBYTES, 10, "|");
  print_short_key_sep(commitment->ciphertext_dem, DEM_LEN, 10, "|");
  print_key(commitment->tag, AES_256_GCM_TAG_LENGTH);
}

int commit(unsigned char* pk,
           unsigned char* m,
           int len_m,
           unsigned char* coins,
           Commitment* commitment) {

   // Coins = iv + coins kem
   unsigned char iv[AES_256_IVEC_LENGTH];
   unsigned char coins_kem[KEX_SSBYTES];

   memcpy(iv, coins, AES_256_IVEC_LENGTH);
   memcpy(coins_kem, coins + AES_256_IVEC_LENGTH, KEX_SSBYTES);

   int ret = pke_enc(m, len_m,
                     pk,
                     commitment->ciphertext_kem,
                     commitment->ciphertext_dem,
                     commitment->tag,
                     iv,
                     coins_kem);

  return ret;
}

int check_commitment(unsigned char* pk,
                     unsigned char* m,
                     unsigned char* coins,
                     Commitment* commitment_check){

  Commitment* commitment = (Commitment*) malloc(sizeof(Commitment));
  init_to_zero(commitment->ciphertext_kem, KYBER_CIPHERTEXTBYTES);
  init_to_zero(commitment->ciphertext_dem, DEM_LEN);
  init_to_zero(commitment->tag, AES_256_GCM_TAG_LENGTH);

  commit(pk, m, DEM_LEN, coins, commitment);

  int ret_ct_kem = memcmp(commitment->ciphertext_kem, commitment_check->ciphertext_kem, KYBER_CIPHERTEXTBYTES);
  int ret_ct_dem = memcmp(commitment->ciphertext_dem, commitment_check->ciphertext_dem, DEM_LEN);
  int ret_tag    = memcmp(commitment->tag, commitment_check->tag, AES_256_GCM_TAG_LENGTH);

  free(commitment);

  if (ret_ct_kem != 0 || ret_ct_dem != 0 || ret_tag != 0) {
    return 1;
  }

  return 0;

}
