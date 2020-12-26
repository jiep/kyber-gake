#include <string.h>

#include "commitment.h"
#include "indcca.h"
#include "utils.h"
#include "randombytes.h"
#include "api.h"

void print_commitment(Commitment* commitment) {
  // print_short_key_sep(commitment->ciphertext_kem, KYBER_CIPHERTEXTBYTES, 10, "|");
  // print_short_key_sep(commitment->ciphertext_dem, 384, 10, "|");
  // print_short_key(commitment->tag, AES_256_GCM_TAG_LENGTH, 10);

  printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
  print_key(commitment->ciphertext_kem, KYBER_CIPHERTEXTBYTES);
  print_key(commitment->ciphertext_dem, 384);
  print_key(commitment->tag, AES_256_GCM_TAG_LENGTH);
  printf("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

}

int commit(unsigned char* pk,
           unsigned char* m,
           int len_m,
           unsigned char* coins,
           Commitment* commitment) {

   // Coins = iv + coins kem
   unsigned char iv[AES_256_IVEC_LENGTH];
   unsigned char coins_kem[KEX_SSBYTES];

   // printf("coins (in): ");
   // print_key(coins, COMMITMENTCOINSBYTES);
   //
   memcpy(iv, coins, AES_256_IVEC_LENGTH);
   memcpy(coins_kem, coins + AES_256_IVEC_LENGTH, KEX_SSBYTES);
   //
   // printf("iv (in): ");
   // print_key(iv, AES_256_IVEC_LENGTH);
   //
   // printf("coins_kem (in): ");
   // print_key(coins_kem, KEX_SSBYTES);

   int ret = pke_enc(m, len_m,
                  pk,
                  commitment->ciphertext_kem,
                  commitment->ciphertext_dem,
                  commitment->tag,
                  iv,
                  coins_kem);

  printf("Inside commit function: \n");
  print_commitment(commitment);
  return ret;
}

int check_commitment(unsigned char* pk,
                     unsigned char* m,
                     unsigned char* coins,
                     Commitment* commitment_check){

  Commitment* commitment = (Commitment*) malloc(sizeof(Commitment));

  commit(pk, m, 384, coins, commitment);

  printf("Inside check_commitment function: \n");
  print_commitment(commitment);
  print_commitment(commitment_check);

  // printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
  // print_commitment(commitment_check);
  // print_commitment(commitment);

  // printf("Inside-----\n");
  // print_commitment(commitment);
  // print_commitment(commitment_check);

  // printf("Public key (in): ");
  // print_short_key(pk, CRYPTO_PUBLICKEYBYTES, 10);
  //
  // printf("Coins (check): ");
  // print_key(coins, COMMITMENTCOINSBYTES);
  // printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");

  int ret_ct_kem = memcmp(commitment->ciphertext_kem, commitment_check->ciphertext_kem, KYBER_CIPHERTEXTBYTES);
  int ret_ct_dem = memcmp(commitment->ciphertext_dem, commitment_check->ciphertext_dem, 384);
  // int ret_iv     = memcmp(commitment->iv, commitment_check->iv, AES_256_IVEC_LENGTH);
  int ret_tag    = memcmp(commitment->tag, commitment_check->tag, AES_256_GCM_TAG_LENGTH);

  free(commitment);

  if (ret_ct_kem != 0 || ret_ct_dem != 0 || ret_tag != 0) {
    return 1;
  }

  return 0;

}
