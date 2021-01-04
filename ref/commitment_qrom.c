#include <string.h>

#include "commitment_qrom.h"
#include "indcca_qrom.h"
#include "utils.h"
#include "randombytes.h"

void print_commitment(CommitmentQROM* commitment) {
  print_short_key_sep(commitment->ciphertext_kem, KYBER_INDCPA_BYTES, 10, "|");
  print_short_key_sep(commitment->ciphertext_dem, DEM_QROM_LEN, 10, "|");
  print_key(commitment->tag, AES_256_GCM_TAG_LENGTH);
}

int commit(unsigned char* pk,
           unsigned char* m,
           int len_m,
           unsigned char* coins,
           CommitmentQROM* commitment) {

   // Coins = iv + coins kem
   unsigned char iv[AES_256_IVEC_LENGTH];
   unsigned char coins_kem[KYBER_INDCPA_MSGBYTES];

   memcpy(iv, coins, AES_256_IVEC_LENGTH);
   memcpy(coins_kem, coins + AES_256_IVEC_LENGTH, KYBER_INDCPA_MSGBYTES);

   return pke_qrom_enc(m, len_m,
                       pk,
                       commitment->ciphertext_kem,
                       commitment->ciphertext_dem,
                       commitment->tag,
                       iv,
                       coins_kem);

}

int check_commitment(unsigned char* pk,
                     unsigned char* m,
                     unsigned char* coins,
                     CommitmentQROM* commitment_check){

  CommitmentQROM* commitment = (CommitmentQROM*) malloc(sizeof(CommitmentQROM));

  commit(pk, m, DEM_QROM_LEN, coins, commitment);

  int ret_ct_kem = memcmp(commitment->ciphertext_kem, commitment_check->ciphertext_kem, KYBER_INDCPA_BYTES);
  int ret_ct_dem = memcmp(commitment->ciphertext_dem, commitment_check->ciphertext_dem, DEM_QROM_LEN);
  int ret_tag    = memcmp(commitment->tag, commitment_check->tag, AES_256_GCM_TAG_LENGTH);

  free(commitment);

  if (ret_ct_kem != 0 || ret_ct_dem != 0 || ret_tag != 0) {
    return 1;
  }

  return 0;

}
