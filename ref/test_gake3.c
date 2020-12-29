#include <stdio.h>
#include <string.h>

#include "api.h"
#include "kex.h"
#include "indcpa.h"
#include "symmetric.h"
#include "randombytes.h"
#include "gake.h"

void xor_three_keys(uint8_t *x_a, uint8_t *x_b, uint8_t *x_c, uint8_t *x_out);
void print_key_start(uint8_t *key, int length, int start);
void print_master_key(uint8_t *key_a, uint8_t *key_b, uint8_t *key_c, int length);

void xor_three_keys(uint8_t *x_a, uint8_t *x_b, uint8_t *x_c, uint8_t *x_out){

  for (int j = 0; j < KEX_SSBYTES; j++) {
    x_out[j] = x_a[j] ^ x_b[j] ^ x_c[j];
  }
}

void print_key_start(uint8_t *key, int length, int start) {
  for(int j = start; j < length; j++){
    printf("%02x", key[j]);
  }
  printf("\n");
}

void print_master_key(uint8_t *key_a, uint8_t *key_b, uint8_t *key_c, int length) {
  for(int j = 0; j < length; j++){
    printf("%02x", key_a[j]);
  }
  for(int j = 0; j < length; j++){
    printf("%02x", key_b[j]);
  }
  for(int j = 0; j < length; j++){
    printf("%02x", key_c[j]);
  }
  printf("\n");
}

int main(void) {

  unsigned char pkb[CRYPTO_PUBLICKEYBYTES];
  unsigned char skb[CRYPTO_SECRETKEYBYTES];

  unsigned char pka[CRYPTO_PUBLICKEYBYTES];
  unsigned char ska[CRYPTO_SECRETKEYBYTES];

  unsigned char pkc[CRYPTO_PUBLICKEYBYTES];
  unsigned char skc[CRYPTO_SECRETKEYBYTES];


  unsigned char ka_left[KEX_SSBYTES];
  unsigned char ka_right[KEX_SSBYTES];

  unsigned char kb_left[KEX_SSBYTES];
  unsigned char kb_right[KEX_SSBYTES];

  unsigned char kc_left[KEX_SSBYTES];
  unsigned char kc_right[KEX_SSBYTES];

  unsigned char x_a[KEX_SSBYTES];
  unsigned char x_b[KEX_SSBYTES];
  unsigned char x_c[KEX_SSBYTES];

  unsigned char x_check[KEX_SSBYTES];

  unsigned char keya_a[KEX_SSBYTES];
  unsigned char keya_b[KEX_SSBYTES];
  unsigned char keya_c[KEX_SSBYTES];

  unsigned char keyb_a[KEX_SSBYTES];
  unsigned char keyb_b[KEX_SSBYTES];
  unsigned char keyb_c[KEX_SSBYTES];

  unsigned char keyc_a[KEX_SSBYTES];
  unsigned char keyc_b[KEX_SSBYTES];
  unsigned char keyc_c[KEX_SSBYTES];

  unsigned char master_key_a[3*KEX_SSBYTES];
  unsigned char master_key_b[3*KEX_SSBYTES];
  unsigned char master_key_c[3*KEX_SSBYTES];


  unsigned char zero[KEX_SSBYTES];
  int result;

  for(int i=0;i<KEX_SSBYTES;i++)
    zero[i] = 0;

  crypto_kem_keypair(pka, ska); // A
  crypto_kem_keypair(pkb, skb); // B
  crypto_kem_keypair(pkc, skc); // C


  // ----------------------------------------------- A
  printf("Party A\n");

  // // A -> C (left)
  printf("\t A -> C\n");
  two_ake(pka, pkc, ska, skc, ka_left, kc_right);
  result = check_keys(ka_left, kc_right, zero);
  printf("\t\tResult: %d\n", result);
  switch (result) {
    case 1:
      printf("\t\t\tKeys are not equal!\n");
      break;
    case 2:
      printf("\t\t\tKey is zero!\n");
      break;
    default:
      break;
  }
  printf("\t\t\t%s: ", getName(ka_left));
  print_key(ka_left, KEX_SSBYTES);

  printf("\t\t\t%s: ", getName(kc_right));
  print_key(kc_right, KEX_SSBYTES);

  // // A -> B (right)
  printf("\t A -> B\n");
  two_ake(pka, pkb, ska, skb, ka_right, kb_left);
  result = check_keys(ka_right, kb_left, zero);
  printf("\t\tResult: %d\n", result);
  switch (result) {
    case 1:
      printf("\t\t\tKeys are not equal!\n");
      break;
    case 2:
      printf("\t\t\tKey are zero!\n");
      break;
    default:
      break;
  }

  printf("\t\t\t%s: ", getName(ka_right));
  print_key(ka_right, KEX_SSBYTES);

  printf("\t\t\t%s: ", getName(kb_left));
  print_key(kb_left, KEX_SSBYTES);

  // XOR keys
  printf("\t\tXored key\n");
  xor_keys(ka_left, ka_right, x_a);
  printf("\t\t\t%s: ", getName(x_a));
  print_key(x_a, KEX_SSBYTES);

  // ----------------------------------------------- B
  printf("Party B\n");

  // // B -> C (right)
  printf("\t B -> C\n");
  two_ake(pkb, pkc, skb, skc, kb_right, kc_left);
  result = check_keys(kb_right, kc_left, zero);
  printf("\t\tResult: %d\n", result);
  switch (result) {
    case 1:
      printf("\t\t\tKeys are not equal!\n");
      break;
    case 2:
      printf("\t\t\tKey are zero!\n");
      break;
    default:
      break;
  }
  printf("\t\t\t%s: ", getName(kb_right));
  print_key(kb_right, KEX_SSBYTES);

  printf("\t\t\t%s: ", getName(kc_left));
  print_key(kc_left, KEX_SSBYTES);

  // // B -> A (left)
  printf("\t B -> A\n");

  printf("\t\t\t%s: ", getName(kb_right));
  print_key(kb_left, KEX_SSBYTES);

  // XOR keys
  printf("\t\tXored key\n");
  xor_keys(kb_left, kb_right, x_b);
  printf("\t\t\t%s: ", getName(x_b));
  print_key(x_b, KEX_SSBYTES);

  // ----------------------------------------------- B
  printf("Party C\n");

  // // C -> A (right)
  printf("\t C -> A\n");
  printf("\t\t\t%s: ", getName(kc_right));
  print_key(kc_right, KEX_SSBYTES);

  // // C -> B (left)
  printf("\t C -> B\n");
  printf("\t\t\t%s: ", getName(kc_left));
  print_key(kc_left, KEX_SSBYTES);

  // XOR keys
  printf("\t\tXored key\n");
  xor_keys(kc_left, kc_right, x_c);
  printf("\t\t\t%s: ", getName(x_c));
  print_key(x_c, KEX_SSBYTES);

  // Commitment
  uint8_t commit_pka[KYBER_INDCPA_PUBLICKEYBYTES];
  uint8_t commit_pkb[KYBER_INDCPA_PUBLICKEYBYTES];
  uint8_t commit_pkc[KYBER_INDCPA_PUBLICKEYBYTES];

  uint8_t commit_ska[KYBER_INDCPA_SECRETKEYBYTES];
  uint8_t commit_skb[KYBER_INDCPA_SECRETKEYBYTES];
  uint8_t commit_skc[KYBER_INDCPA_SECRETKEYBYTES];

  uint8_t commitment_a[KYBER_INDCPA_BYTES];
  uint8_t commitment_b[KYBER_INDCPA_BYTES];
  uint8_t commitment_c[KYBER_INDCPA_BYTES];

  uint8_t coins_a[KYBER_SYMBYTES];
  uint8_t coins_b[KYBER_SYMBYTES];
  uint8_t coins_c[KYBER_SYMBYTES];

  indcpa_keypair(commit_pka, commit_ska);
  indcpa_keypair(commit_pkb, commit_skb);
  indcpa_keypair(commit_pkc, commit_skc);

  randombytes(coins_a, KYBER_SYMBYTES);
  randombytes(coins_b, KYBER_SYMBYTES);
  randombytes(coins_c, KYBER_SYMBYTES);

  indcpa_enc(commitment_a, x_a, commit_pka, coins_a);
  indcpa_enc(commitment_b, x_b, commit_pkb, coins_b);
  indcpa_enc(commitment_c, x_c, commit_pkc, coins_c);

  printf("Party A\n");
  printf("\tCoins: ");
  print_key(coins_a, KYBER_SYMBYTES);

  printf("\tCommitment: \n");
  print_key(commitment_a, KYBER_INDCPA_BYTES);


  printf("Party B\n");
  printf("\tCoins: ");
  print_key(coins_b, KYBER_SYMBYTES);

  printf("\tCommitment: \n");
  print_key(commitment_b, KYBER_INDCPA_BYTES);

  printf("Party C\n");
  printf("\tCoins: ");
  print_key(coins_c, KYBER_SYMBYTES);

  printf("\tCommitment: \n");
  print_key(commitment_c, KYBER_INDCPA_BYTES);

  xor_three_keys(x_a, x_b, x_c, x_check);

  result = memcmp(x_a, zero, KEX_SSBYTES);

  if(!result) printf("Wrong check!\n");
  else printf("Right check!\n");

  printf("Master key\n");

  // Party A
  printf("Party A\n");

  // keya_a
  memcpy(keya_a, ka_left, KEX_SSBYTES);
  printf("\t K_a: ");
  print_key(keya_a, KEX_SSBYTES);

  // keya_b
  xor_three_keys(ka_left, x_c, x_b, keya_b);
  printf("\t K_b: ");
  print_key(keya_b, KEX_SSBYTES);

  // keya_c
  xor_keys(ka_left, x_c, keya_c);
  printf("\t K_c: ");
  print_key(keya_c, KEX_SSBYTES);

  // Concat master key
  // TODO: Add pid_i
  memcpy(master_key_a, keya_a, KEX_SSBYTES);
  memcpy(master_key_a + KEX_SSBYTES, keya_b, KEX_SSBYTES);
  memcpy(master_key_a + 2*KEX_SSBYTES, keya_c, KEX_SSBYTES);

  printf("Master key: ");
  print_key(master_key_a, 3*KEX_SSBYTES);


  // Party B
  printf("Party B\n");

  // keyb_a
  xor_keys(kb_left, x_a, keyb_a);
  printf("\t K_a: ");
  print_key(keyb_a, KEX_SSBYTES);

  // keyb_b
  memcpy(keyb_b, kb_left, KEX_SSBYTES);
  printf("\t K_b: ");
  print_key(keyb_b, KEX_SSBYTES);

  // keyb_c
  xor_three_keys(kb_left, x_a, x_c, keyb_c);
  printf("\t K_c: ");
  print_key(keyb_c, KEX_SSBYTES);

  // Concat master key
  // TODO: Add pid_i
  memcpy(master_key_b, keyb_a, KEX_SSBYTES);
  memcpy(master_key_b + KEX_SSBYTES, keyb_b, KEX_SSBYTES);
  memcpy(master_key_b + 2*KEX_SSBYTES, keyb_c, KEX_SSBYTES);

  printf("Master key: ");
  print_key(master_key_b, 3*KEX_SSBYTES);


  // Party C
  printf("Party C\n");

  // keyc_a
  xor_three_keys(kc_left, x_b, x_a, keyc_a);
  printf("\t K_a: ");
  print_key(keyc_a, KEX_SSBYTES);

  // keyc_b
  xor_keys(kc_left, x_b, keyc_b);
  printf("\t K_b: ");
  print_key(keyc_b, KEX_SSBYTES);

  // keyc_c
  memcpy(keyc_c, kc_left, KEX_SSBYTES);
  printf("\t K_c: ");
  print_key(keyc_c, KEX_SSBYTES);

  // Concat master key
  // TODO: Add pid_i
  memcpy(master_key_c, keyc_a, KEX_SSBYTES);
  memcpy(master_key_c + KEX_SSBYTES, keyc_b, KEX_SSBYTES);
  memcpy(master_key_c + 2*KEX_SSBYTES, keyc_c, KEX_SSBYTES);

  printf("Master key: ");
  print_key(master_key_c, 3*KEX_SSBYTES);

  int ret1 = memcmp(master_key_a, master_key_b, 3*KEX_SSBYTES);
  int ret2 = memcmp(master_key_b, master_key_c, 3*KEX_SSBYTES);

  if (ret1 == ret2) {
    printf("Master keys are equal\n");
  }


  unsigned char sk_sid[2*KEX_SSBYTES];

  hash_g(sk_sid, master_key_a, 2*KYBER_SYMBYTES);

  printf("SK & SID\n");

  print_key(sk_sid, 2*KEX_SSBYTES);

  printf("SK: ");
  print_key(sk_sid, KEX_SSBYTES);
  printf("SID: ");
  print_key_start(sk_sid, 2*KEX_SSBYTES, KEX_SSBYTES);

  return 0;
}
