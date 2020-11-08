#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "api.h"
#include "kex.h"
#include "indcpa.h"
#include "randombytes.h"
#include "symmetric.h"

typedef unsigned char Commitment[KYBER_INDCPA_PUBLICKEYBYTES];
typedef unsigned char MasterKey[KEX_SSBYTES];
typedef unsigned char X[KEX_SSBYTES];
typedef char * Pid[20];
typedef unsigned char Coins[KYBER_SYMBYTES];

typedef struct Party {
    unsigned char public_key[CRYPTO_PUBLICKEYBYTES];
    unsigned char secret_key[CRYPTO_SECRETKEYBYTES];
    unsigned char key_left[KEX_SSBYTES];
    unsigned char key_right[KEX_SSBYTES];
    unsigned char sid[KEX_SSBYTES];
    unsigned char sk[KEX_SSBYTES];
    X* xs;
    Coins* coins;
    Commitment* commitments;
    MasterKey* masterkey;
    Pid* pids;
} Party;


#define getName(var)  #var

int mod(int x, int y);
void xor_keys(uint8_t *x_a, uint8_t *x_b, uint8_t *x_out);
void print_key(uint8_t *key, int length);
void print_key_start(uint8_t *key, int length, int start);
int check_keys(uint8_t *ka, uint8_t *kb, uint8_t *zero);
void two_ake(uint8_t *pka, uint8_t *pkb, uint8_t *ska, uint8_t *skb, uint8_t *ka, uint8_t *kb);
void print_short_key(uint8_t *key, int length, int show);
void init_to_zero(uint8_t *key, int length);
void print_party(Party* parties, int i, int num_parties, int show);
void concat_masterkey(MasterKey* mk, int num_parties, uint8_t *concat_mk);

void concat_masterkey(MasterKey* mk, int num_parties, uint8_t *concat_mk) {
  for (int i = 0; i < num_parties; i++) {
    memcpy(concat_mk + i*KEX_SSBYTES, &mk[i], KEX_SSBYTES);
  }
}

void print_party(Party* parties, int i, int num_parties, int show) {
  printf("Party %d\n", i);

  printf("\tPublic key: ");
  print_short_key(parties[i].public_key, CRYPTO_PUBLICKEYBYTES, show);

  printf("\tSecret key: ");
  print_short_key(parties[i].secret_key, CRYPTO_SECRETKEYBYTES, show);

  printf("\tLeft key: ");
  print_short_key(parties[i].key_left, KEX_SSBYTES, show);

  printf("\tRight key: ");
  print_short_key(parties[i].key_right, KEX_SSBYTES, show);

  printf("\tSession id: ");
  print_short_key(parties[i].sid, KEX_SSBYTES, show);

  printf("\tSession key: ");
  print_short_key(parties[i].sk, KEX_SSBYTES, show);

  printf("\tX: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tX%d: ", j);
    print_short_key(parties[i].xs[j], KEX_SSBYTES, show);
  }

  printf("\tCoins: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tr%d: ", j);
    print_short_key(parties[i].coins[j], KEX_SSBYTES, show);
  }

  printf("\tCommitments:\n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tc%d: ", j);
    print_short_key(parties[i].commitments[j], KEX_SSBYTES, show);
  }

  printf("\tMaster Key: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tk%d: ", j);
    print_short_key(parties[i].masterkey[j], KEX_SSBYTES, show);
  }

  printf("\tPids: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tpid%d: %s\n", j, *parties[i].pids[j]);
  }
}

int main(int argc, char** argv){

  if(argc != 2){
    printf("You must provide the number of parties!\n");
    return 1;
  }

  int NUM_PARTIES = atoi(argv[1]);

  int SHOW = 10;

  Party *pointer_to_parties;

  pointer_to_parties = (struct Party*) malloc(sizeof(Party) * NUM_PARTIES);

  for (int i = 0; i < NUM_PARTIES; i++) {
    pointer_to_parties[i].commitments = malloc(sizeof(Commitment) * NUM_PARTIES);
    pointer_to_parties[i].masterkey = malloc(sizeof(MasterKey) * NUM_PARTIES);
    pointer_to_parties[i].pids = malloc(sizeof(Pid) * NUM_PARTIES);
    pointer_to_parties[i].coins = malloc(sizeof(Coins) * NUM_PARTIES);
    pointer_to_parties[i].xs = malloc(sizeof(X) * NUM_PARTIES);

    for (int j = 0; j < NUM_PARTIES; j++) {
      char* pid = malloc(20*sizeof(char));
      sprintf(pid, "%s %d", "Party", j);
      *(pointer_to_parties[i].pids)[j] = pid;
    }
    // for (int j = 0; j < NUM_PARTIES; j++) {
    //   printf("pid %d: %s\n", j, *(pointer_to_parties[i].pids)[j]);
    // }

    init_to_zero(pointer_to_parties[i].sid, KEX_SSBYTES);
    init_to_zero(pointer_to_parties[i].sk, KEX_SSBYTES);

    // printf("Party %d\n", i);
    // printf("ID: %s\n", *pointer_to_parties[i].pids[i]);
    crypto_kem_keypair(pointer_to_parties[i].public_key, pointer_to_parties[i].secret_key);

    print_party(pointer_to_parties, i, NUM_PARTIES, SHOW);

    // printf("%s: ", getName(pointer_to_parties[i].public_key));
    // print_short_key(pointer_to_parties[i].public_key, CRYPTO_PUBLICKEYBYTES, SHOW);
    //
    // printf("%s: ", getName(pointer_to_parties[i].secret_key));
    // print_short_key(pointer_to_parties[i].secret_key, CRYPTO_SECRETKEYBYTES, SHOW);
    //
    // printf("%s: ", getName(pointer_to_parties[i].sid));
    // print_short_key(pointer_to_parties[i].sid, KEX_SSBYTES, SHOW);
    //
    // printf("%s: ", getName(pointer_to_parties[i].sk));
    // print_short_key(pointer_to_parties[i].sk, KEX_SSBYTES, SHOW);
    //
    // printf("%s: ", getName(pointer_to_parties[i].key_left));
    // print_short_key(pointer_to_parties[i].key_left, KEX_SSBYTES, SHOW);
    //
    // printf("%s: ", getName(pointer_to_parties[i].key_right));
    // print_short_key(pointer_to_parties[i].key_right, KEX_SSBYTES, SHOW);

    // free(pointer_to_parties[i].commitments);
    // free(pointer_to_parties[i].masterkey);
    // free(pointer_to_parties[i].pids);
    // free(pointer_to_parties[i].coins);
    // free(pointer_to_parties[i].xs);

  }

  unsigned char zero[KEX_SSBYTES];

  for(int i = 0; i < KEX_SSBYTES; i++){
    zero[i] = 0;
  }

  // Round 1-2
  printf("Round 1-2\n");
  for (int i = 0; i < NUM_PARTIES; i++) {
    int right = mod(i+1, NUM_PARTIES);
    int left = mod(i-1, NUM_PARTIES);

    two_ake(pointer_to_parties[i].public_key, pointer_to_parties[right].public_key,
            pointer_to_parties[i].secret_key, pointer_to_parties[right].secret_key,
            pointer_to_parties[i].key_right,   pointer_to_parties[right].key_left);

    two_ake(pointer_to_parties[i].public_key, pointer_to_parties[left].public_key,
            pointer_to_parties[i].secret_key, pointer_to_parties[left].secret_key,
            pointer_to_parties[i].key_left,   pointer_to_parties[left].key_right);
  }

  for (int i = 0; i < NUM_PARTIES; i++) {
    // printf("Party %d\n", i);
    //
    // printf("\t%s: ", getName(pointer_to_parties[i].key_left));
    // print_short_key(pointer_to_parties[i].key_left, KEX_SSBYTES, SHOW);
    //
    // printf("\t%s: ", getName(pointer_to_parties[i].key_right));
    // print_short_key(pointer_to_parties[i].key_right, KEX_SSBYTES, SHOW);

    print_party(pointer_to_parties, i, NUM_PARTIES, SHOW);
  }

  // Round 3
  printf("Round 3\n");
  for (int i = 0; i < NUM_PARTIES; i++) {
    X xi;
    Coins ri;
    Commitment ci;

    xor_keys(pointer_to_parties[i].key_right, pointer_to_parties[i].key_left, xi);
    randombytes(ri, KYBER_SYMBYTES);
    indcpa_enc(ci, pointer_to_parties[i].xs[i], pointer_to_parties[i].public_key, ri);

    for (int j = 0; j < NUM_PARTIES; j++) {
      memcpy(pointer_to_parties[j].xs[i], &xi, KEX_SSBYTES);
      memcpy(pointer_to_parties[j].coins[i], &ri, KYBER_SYMBYTES);
      memcpy(pointer_to_parties[j].commitments[i], &ci, KYBER_INDCPA_BYTES);
    }
  }

  for (int i = 0; i < NUM_PARTIES; i++) {
      // printf("Party %d\n", i);
      // for (int j = 0; j < NUM_PARTIES; j++) {
      // printf("\tPublic key (party %d): ", j);
      // print_short_key(pointer_to_parties[j].public_key, CRYPTO_PUBLICKEYBYTES, SHOW);

      // printf("\tXi (party %d): ", j);
      // print_key(pointer_to_parties[i].xs[j], KEX_SSBYTES);
      // printf("\tCoins (party %d): ", j);
      // print_short_key(pointer_to_parties[i].coins[j], KYBER_SYMBYTES, SHOW);
      //
      // printf("\tCommitment (party %d): ", j);
      // print_key(pointer_to_parties[i].commitments[j], KYBER_INDCPA_BYTES);
      //
      // printf("\n");
      // }
      print_party(pointer_to_parties, i, NUM_PARTIES, SHOW);
  }

  // Round 4
  printf("Round 4\n");
  for (int i = 0; i < NUM_PARTIES; i++) {
    printf("Party %d\n", i);

    // Check Xi
    X check;
    memcpy(check, pointer_to_parties[i].xs[0], KEX_SSBYTES);
    for (int j = 0; j < NUM_PARTIES - 1; j++) {
      xor_keys(pointer_to_parties[i].xs[j+1], check, check);
    }

    int res = memcmp(check, zero, KEX_SSBYTES);
    if (res == 0) {
      printf("Xi are zero!\n");
    } else {
      printf("Xi are not zero!\n");
      return 1;
    }
  }

  // TODO: Fix check commitments
  // for (int i = 0; i < NUM_PARTIES; i++) {
  //
  //   printf("Party %d\n", i);
  //   for (int j = 0; i < NUM_PARTIES; j++) {
  //     Commitment ci_check, ci_check2;
  //
  //     indcpa_enc(ci_check, pointer_to_parties[i].xs[j], pointer_to_parties[j].public_key, pointer_to_parties[i].coins[j]);
  //     indcpa_enc(ci_check2, pointer_to_parties[i].xs[j], pointer_to_parties[j].public_key, pointer_to_parties[i].coins[j]);
  //
  //     printf("ci_check: ");
  //     print_short_key(ci_check, KYBER_INDCPA_BYTES, SHOW);
  //
  //     printf("ci_check2: ");
  //     print_short_key(ci_check, KYBER_INDCPA_BYTES, SHOW);
  //
  //     printf("x0: ");
  //     print_short_key(pointer_to_parties[i].xs[j], KEX_SSBYTES, SHOW);
  //
  //     printf("pk: ");
  //     print_short_key(pointer_to_parties[j].public_key, CRYPTO_PUBLICKEYBYTES, SHOW);
  //
  //     printf("coins: ");
  //     print_short_key(pointer_to_parties[i].coins[j], KYBER_SYMBYTES, SHOW);
  //
  //     printf("commitment: ");
  //     print_short_key(pointer_to_parties[i].commitments[j], KYBER_INDCPA_BYTES, SHOW);
  //
  //
  //     int res_check = memcmp(ci_check, pointer_to_parties[i].commitments[j], KYBER_INDCPA_BYTES);
  //     if (res_check == 0) {
  //       printf("Commitments are right!\n");
  //     } else {
  //       printf("Commitments are wrong!\n");
  //       return 1;
  //     }
  //   }
  // }

  // Master Key
  for (int i = 0; i < NUM_PARTIES; i++) {
    printf("Party %d\n", i);

    printf("K[%d] = K_left[%d]\n", i, i);
    memcpy(pointer_to_parties[i].masterkey[i], pointer_to_parties[i].key_left, KEX_SSBYTES);

    for (int j = 1; j < NUM_PARTIES; j++) {
      MasterKey mk;
      memcpy(mk, pointer_to_parties[i].key_left, KEX_SSBYTES);
      printf("K[%d] = K_left[%d]", mod(i-j, NUM_PARTIES), i);
      for (int k = 0; k < j; k++) {
        xor_keys(mk, pointer_to_parties[i].xs[mod(i-k-1,NUM_PARTIES)], mk);
        printf("^X[%d]", mod(i-k-1,NUM_PARTIES));
      }

      memcpy(pointer_to_parties[i].masterkey[mod(i-j, NUM_PARTIES)], mk, KEX_SSBYTES);

      printf("\n");
    }
    printf("\n");
    print_party(pointer_to_parties, i, NUM_PARTIES, SHOW);

  }

  // Compute session key and session identifier
  for (int i = 0; i < NUM_PARTIES; i++) {
    MasterKey mki;
    // Concat master key
    concat_masterkey(pointer_to_parties[i].masterkey, NUM_PARTIES, mki);
    printf("masterkey (party %d):\n", i);
    print_key(mki, NUM_PARTIES*KEX_SSBYTES);

    unsigned char sk_sid[2*KEX_SSBYTES];

    hash_g(sk_sid, mki, 2*KYBER_SYMBYTES);

    printf("SK & SID\n");

    print_key(sk_sid, 2*KEX_SSBYTES);

    printf("SK: ");
    print_key(sk_sid, KEX_SSBYTES);
    printf("SID: ");
    print_key_start(sk_sid, 2*KEX_SSBYTES, KEX_SSBYTES);

    memcpy(pointer_to_parties[i].sk, sk_sid, KEX_SSBYTES);
    memcpy(pointer_to_parties[i].sid, sk_sid + KEX_SSBYTES, KEX_SSBYTES);

    print_party(pointer_to_parties, i, NUM_PARTIES, SHOW);
  }

  free(pointer_to_parties);

  return 0;
}

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

void init_to_zero(uint8_t *key, int length){
  for(int i = 0; i < length; i++){
    key[i] = 0;
  }
}

void print_short_key(uint8_t *key, int length, int show) {
  for (int i = 0; i < show; i++) {
    printf("%02x", key[i]);
  }
  printf("...");
  for (int i = length - show; i < length; i++) {
    printf("%02x", key[i]);
  }
  printf("\n");
}
