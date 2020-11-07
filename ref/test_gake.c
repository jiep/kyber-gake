#include <stdio.h>
#include <string.h>

#include "api.h"
#include "kex.h"
#include "indcpa.h"
#include "symmetric.h"


#define getName(var)  #var

int mod(int x, int y){
   int t = x - ((x / y) * y);
   if (t < 0) t += y;
   return t;
}

void xor_keys(uint8_t *x_a, uint8_t *x_b, uint8_t *x_out){

  for (int j = 0; j < KEX_SSBYTES; j++) {
    x_out[j] = x_a[j] ^ x_b[j];
  }
}

void xor_three_keys(uint8_t *x_a, uint8_t *x_b, uint8_t *x_c, uint8_t *x_out){

  for (int j = 0; j < KEX_SSBYTES; j++) {
    x_out[j] = x_a[j] ^ x_b[j] ^ x_c[j];
  }
}

void print_key(uint8_t *key, int length) {
  for(int j = 0; j < length; j++){
    printf("%02x", key[j]);
  }
  printf("\n");
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

int check_keys(uint8_t *ka, uint8_t *kb, uint8_t *zero) {
  if(memcmp(ka, kb, KEX_SSBYTES) != 0){
    return 1;
  }

  if(!memcmp(ka, zero, KEX_SSBYTES)){
    return 2;
  }

  return 0;
}

void two_ake(uint8_t *pka, uint8_t *pkb, uint8_t *ska, uint8_t *skb, uint8_t *ka, uint8_t *kb){

  unsigned char eska[CRYPTO_SECRETKEYBYTES];

  unsigned char ake_senda[KEX_AKE_SENDABYTES];
  unsigned char ake_sendb[KEX_AKE_SENDBBYTES];

  unsigned char tk[KEX_SSBYTES];

  // Perform mutually authenticated key exchange
  kex_ake_initA(ake_senda, tk, eska, pkb); // Run by Alice
  kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pka); // Run by Bob
  kex_ake_sharedA(ka, ake_sendb, tk, eska, ska); // Run by Alice
}

int main(void)
{
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
  two_ake(&pka, &pkc, &ska, &skc, &ka_left, &kc_right);
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
  print_key(&ka_left, KEX_SSBYTES);

  printf("\t\t\t%s: ", getName(kc_right));
  print_key(&kc_right, KEX_SSBYTES);

  // // A -> B (right)
  printf("\t A -> B\n");
  two_ake(&pka, &pkb, &ska, &skb, &ka_right, &kb_left);
  result = check_keys(&ka_right, &kb_left, &zero);
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
  print_key(&ka_right, KEX_SSBYTES);

  printf("\t\t\t%s: ", getName(kb_left));
  print_key(&kb_left, KEX_SSBYTES);

  // XOR keys
  printf("\t\tXored key\n");
  xor_keys(&ka_left, &ka_right, &x_a);
  printf("\t\t\t%s: ", getName(x_a));
  print_key(&x_a, KEX_SSBYTES);

  // ----------------------------------------------- B
  printf("Party B\n");

  // // B -> C (right)
  printf("\t B -> C\n");
  two_ake(&pkb, &pkc, &skb, &skc, &kb_right, &kc_left);
  result = check_keys(&kb_right, &kc_left, &zero);
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
  print_key(&kb_right, KEX_SSBYTES);

  printf("\t\t\t%s: ", getName(kc_left));
  print_key(&kc_left, KEX_SSBYTES);

  // // B -> A (left)
  printf("\t B -> A\n");
  // memcpy(&kb_left, &ka_right, KEX_SSBYTES);

  printf("\t\t\t%s: ", getName(kb_right));
  print_key(&kb_left, KEX_SSBYTES);

  // printf("\t\t\t%s: ", getName(kb));
  // print_key(&kb, KEX_SSBYTES);

  // XOR keys
  printf("\t\tXored key\n");
  xor_keys(&kb_left, &kb_right, &x_b);
  printf("\t\t\t%s: ", getName(x_b));
  print_key(&x_b, KEX_SSBYTES);

  // ----------------------------------------------- B
  printf("Party C\n");

  // // C -> A (right)
  printf("\t C -> A\n");
  // memcpy(&kc_right, &ka_left, KEX_SSBYTES);
  printf("\t\t\t%s: ", getName(kc_right));
  print_key(&kc_right, KEX_SSBYTES);

  // // C -> B (left)
  printf("\t C -> B\n");
  // memcpy(&kc_left, &kb_right, KEX_SSBYTES);
  printf("\t\t\t%s: ", getName(kc_left));
  print_key(&kc_left, KEX_SSBYTES);

  // printf("\t\t\t%s: ", getName(kc));
  // print_key(&kc, KEX_SSBYTES);

  // XOR keys
  printf("\t\tXored key\n");
  xor_keys(&kc_left, &kc_right, &x_c);
  printf("\t\t\t%s: ", getName(x_c));
  print_key(&x_c, KEX_SSBYTES);

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

  // m = X_i || i; // Fix: concat with i
  // uint8_t m1_a[KYBER_INDCPA_MSGBYTES];
  // uint8_t m1_b[KYBER_INDCPA_MSGBYTES];
  // uint8_t m1_c[KYBER_INDCPA_MSGBYTES];

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

  int ret1 = strcmp(master_key_a,master_key_b);
  int ret2 = strcmp(master_key_b, master_key_c);

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



// #include <stdio.h>
// #include <string.h>
//
// #include "api.h"
// #include "kex.h"
// #include "indcpa.h"
// #include "symmetric.h"
//
// typedef unsigned char PublicKey[CRYPTO_PUBLICKEYBYTES];
// typedef unsigned char SecretKey[CRYPTO_SECRETKEYBYTES];
//
// struct Party {
//   PublicKey *pk;
//   SecretKey *sk;
//   // int sid;
//   // int pid;
// };
//
// void two_ake(uint8_t *pka, uint8_t *pkb, uint8_t *ska, uint8_t *skb, uint8_t *ka, uint8_t *kb);
// int mod(int x, int y);
//
//
// int main(void){
//
//   int PARTIES = 3;
//
//   struct Party parties[PARTIES];
//
//   //
//   for(int i = 0; i < PARTIES; i++){
//     printf("Party %d\n", i);
//     unsigned char pk[CRYPTO_PUBLICKEYBYTES];
//     unsigned char sk[CRYPTO_SECRETKEYBYTES];
//
//     // unsigned char ka[KEX_SSBYTES];
//     // unsigned char kb[KEX_SSBYTES];
//
//     crypto_kem_keypair(pk, sk);
//     printf("Generating static auth keys for party %d...\n", i);
//
//     parties[i].pk = &pk;
//     parties[i].sk = &sk;
//
//     for(int j = 0; j < CRYPTO_PUBLICKEYBYTES; j++){
//       printf("pk: %02x; parties_pk: %02x\n", pk[j], (*parties[i].pk)[j]);
//       if (j==1) {
//         break;
//       }
//     }
//
//     for(int k = 0; k < CRYPTO_SECRETKEYBYTES; k++){
//       printf("sk: %02x; parties_sk: %02x\n", sk[k], (*parties[i].sk)[k]);
//       if (k==1) {
//         break;
//       }
//     }
//   }
//
//   for (int i = 0; i < PARTIES; i++) {
//     printf("Party %d\n", i);
//     int left  = mod(i-1, PARTIES);
//     int right = mod(i+1, PARTIES);;
//     printf("left: %d; right: %d\n", left, right);
//
//     unsigned char k_right[KEX_SSBYTES];
//     unsigned char k_left[KEX_SSBYTES];
//     unsigned char k_i[KEX_SSBYTES];
//     //
//     unsigned char X_i[KEX_SSBYTES];
//     //
//     PublicKey *pk_i = parties[i].pk;
//     PublicKey *pk_right = parties[right].pk;
//     PublicKey *pk_left  = parties[left].pk;
//
//     // for(int j = 0; j < CRYPTO_PUBLICKEYBYTES; j++){
//     //   printf("pk: %02x\n", *pk_i[j]);
//     //   if (j==1) {
//     //     break;
//     //   }
//     // }
//     //
//     // printf("Address: %02x\n", &parties[i].pk);
//
//     SecretKey *sk_i = parties[i].sk;
//     SecretKey *sk_right = parties[right].sk;
//     SecretKey *sk_left  = parties[left].sk;
//
//
//     //
//     two_ake(pk_i, pk_right, sk_i, sk_right, k_i, k_right);
//
//     if(memcmp(k_i, k_right, KEX_SSBYTES))
//       printf("Error in UAKE\n");
//
//     if(!memcmp(k_i, k_right, KEX_SSBYTES))
//       printf("Error: UAKE produces zero key\n");
//
//     for(int j = 0; j < KEX_SSBYTES; j++){
//       printf("k1: %02x; k2: %02x\n", k_right[j], k_i[j]);
//       if (j==1) {
//         break;
//       }
//     }
//
//     two_ake(pk_i, pk_left, sk_i, sk_left, k_i, k_left);
//
//     if(memcmp(k_i, k_left, KEX_SSBYTES))
//       printf("Error in UAKE\n");
//
//     if(!memcmp(k_i, k_left, KEX_SSBYTES))
//       printf("Error: UAKE produces zero key\n");
//
//     for(int j = 0; j < KEX_SSBYTES; j++){
//       printf("k1: %02x; k2: %02x\n", k_left[j], k_i[j]);
//       if (j==1) {
//         break;
//       }
//     }
//
//     // XOR
//     printf("XOR\n");
//     for (int j = 0; j < KEX_SSBYTES; j++) {
//       X_i[j] = k_left[j] ^ k_right[j];
//     }
//
//     for(int j = 0; j < KEX_SSBYTES; j++){
//       printf("%02x\n", X_i[j]);
//       if (j==1) {
//         break;
//       }
//     }
//
//
//     // Commitment
//     uint8_t commit_pk[KYBER_INDCPA_PUBLICKEYBYTES];
//     uint8_t commit_sk[KYBER_INDCPA_SECRETKEYBYTES];
//
//     uint8_t commitment[KYBER_INDCPA_BYTES];
//     uint8_t open_commitment[KYBER_INDCPA_MSGBYTES];
//
//     uint8_t m[KYBER_INDCPA_MSGBYTES];
//     uint8_t coins[KYBER_SYMBYTES];
//
//     indcpa_keypair(commit_pk, commit_sk);
//
//     for(int j = 0; j < KYBER_INDCPA_PUBLICKEYBYTES; j++){
//       printf("commit_pk %02x\n", commit_pk[j]);
//       if (j==1) {
//         break;
//       }
//     }
//
//     for(int j = 0; j < KYBER_INDCPA_SECRETKEYBYTES; j++){
//       printf("commit_sk %02x\n", commit_sk[j]);
//       if (j==1) {
//         break;
//       }
//     }
//
//     randombytes(coins, KYBER_SYMBYTES);
//     for(int j = 0; j < KYBER_SYMBYTES; j++){
//       printf("%02x", coins[j]);
//       if (j==1) {
//         // break;
//       }
//     }
//     printf("\n");
//     // m = X_i || i; // Fix: concat with i
//
//     indcpa_enc(commitment, X_i, commit_pk, coins);
//
//     for(int j = 0; j < KYBER_INDCPA_SECRETKEYBYTES; j++){
//       printf("commitment %02x\n", commitment[j]);
//       if (j==1) {
//         break;
//       }
//     }
//
//     printf("Message:\n");
//     for(int j = 0; j < KEX_SSBYTES; j++){
//       printf("%02x", X_i[j]);
//       if (j==1) {
//         // break;
//       }
//     }
//     printf("\n");
//
//     indcpa_dec(open_commitment, commitment, commit_sk);
//
//     printf("Open commitment:\n");
//     for(int j = 0; j < KYBER_INDCPA_MSGBYTES; j++){
//       printf("%02x", open_commitment[j]);
//       if (j==1) {
//         // break;
//       }
//     }
//     printf("\n\n\n\n");
//
//     for (int j = 0; j < PARTIES; j++) {
//       printf("K[%d] = K_left[%d] ^ X[%d]\n", mod(i-j, PARTIES), mod(i-j+1, PARTIES), mod(i-j, PARTIES));
//     }
//   }
//   printf("\n");
//
//   unsigned char master_key[KEX_SSBYTES*PARTIES];
//   unsigned char sk_sid[2*KEX_SSBYTES];
//
//   randombytes(master_key, KEX_SSBYTES*PARTIES);
//
//   printf("Master key:\n");
//   for (int j = 0; j < KEX_SSBYTES*PARTIES; j++) {
//     printf("%02x", master_key[j]);
//   }
//   printf("\n\n\n");
//
//
//   hash_g(sk_sid, master_key, 2*KYBER_SYMBYTES);
//
//   printf("Session key/ Session ID\n");
//   for (int j = 0; j < 2*KYBER_SYMBYTES; j++) {
//     if(j==KYBER_SYMBYTES) printf("\n");
//     printf("%02x", sk_sid[j]);
//   }
//   printf("\n");
//
//
//   // ----------------------------------------------------------
//
//   // unsigned char pkb[CRYPTO_PUBLICKEYBYTES];
//   // unsigned char skb[CRYPTO_SECRETKEYBYTES];
//   //
//   // unsigned char pka[CRYPTO_PUBLICKEYBYTES];
//   // unsigned char ska[CRYPTO_SECRETKEYBYTES];
//   //
//   // unsigned char ka[KEX_SSBYTES];
//   // unsigned char kb[KEX_SSBYTES];
//   //
//   // crypto_kem_keypair(pkb, skb); // Generate static key for Bob
//   // crypto_kem_keypair(pka, ska); // Generate static key for Alice
//
//   // twoAKE(pka, pkb, ska, skb, ka, kb);
//
//   // unsigned char eska[CRYPTO_SECRETKEYBYTES];
//   //
//   // unsigned char ake_senda[KEX_AKE_SENDABYTES];
//   // unsigned char ake_sendb[KEX_AKE_SENDBBYTES];
//   //
//   // unsigned char tk[KEX_SSBYTES];
//   // unsigned char ka[KEX_SSBYTES];
//   // unsigned char kb[KEX_SSBYTES];
//
//
//
//   // -----------------------------------------
//   // unsigned char zero[KEX_SSBYTES];
//   //
//   // for(int i = 0; i < KEX_SSBYTES; i++)
//   //   zero[i] = 0;
//   //
//   // if(memcmp(ka, kb, KEX_SSBYTES))
//   //   printf("Error in AKE\n");
//   //
//   // if(!memcmp(ka, zero, KEX_SSBYTES))
//   //   printf("Error: AKE produces zero key\n");
//   //
//   // for(int j=0; j<KEX_SSBYTES; j++)
//   //   printf("ka: %02x; kb: %02x\n", ka[j], kb[j]);
//   // ---------------------------------------------------
//
//   // crypto_kem_keypair(pkb, skb); // Generate static key for Bob
//   // crypto_kem_keypair(pka, ska); // Generate static key for Alice
//
//   // Perform mutually authenticated key exchange
//   // kex_ake_initA(ake_senda, tk, eska, pkb); // Run by Alice
//   // kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pka); // Run by Bob
//   // kex_ake_sharedA(ka, ake_sendb, tk, eska, ska); // Run by Alice
//   //
//   // if(memcmp(ka, kb, KEX_SSBYTES))
//   //   printf("Error in AKE\n");
//   //
//   // if(!memcmp(ka, zero, KEX_SSBYTES))
//   //   printf("Error: AKE produces zero key\n");
//   //
//   // for(int j=0; j<KEX_SSBYTES; j++)
//   //   printf("ka: %02x; kb: %02x\n", ka[j], kb[j]);
//
//   return 0;
// }
//
// void two_ake(uint8_t *pka, uint8_t *pkb, uint8_t *ska, uint8_t *skb, uint8_t *ka, uint8_t *kb){
//
//   unsigned char eska[CRYPTO_SECRETKEYBYTES];
//
//   unsigned char ake_senda[KEX_AKE_SENDABYTES];
//   unsigned char ake_sendb[KEX_AKE_SENDBBYTES];
//
//   unsigned char tk[KEX_SSBYTES];
//
//   // Perform mutually authenticated key exchange
//   kex_ake_initA(ake_senda, tk, eska, pkb); // Run by Alice
//   kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pka); // Run by Bob
//   kex_ake_sharedA(ka, ake_sendb, tk, eska, ska); // Run by Alice
// }
//
// // https://cboard.cprogramming.com/c-programming/101643-mod-negatives.html
// int mod(int x, int y){
//    int t = x - ((x / y) * y);
//    if (t < 0) t += y;
//    return t;
// }
