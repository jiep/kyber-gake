#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "api.h"
#include "kex.h"
#include "indcpa.h"
#include "randombytes.h"
#include "symmetric.h"
#include "gake.h"

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

    init_to_zero(pointer_to_parties[i].sid, KEX_SSBYTES);
    init_to_zero(pointer_to_parties[i].sk, KEX_SSBYTES);

    crypto_kem_keypair(pointer_to_parties[i].public_key,
                       pointer_to_parties[i].secret_key);

    print_party(pointer_to_parties, i, NUM_PARTIES, SHOW);
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
      print_party(pointer_to_parties, i, NUM_PARTIES, SHOW);
  }

  // Round 4
  printf("Round 4\n");
  for (int i = 0; i < NUM_PARTIES; i++) {

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
    memcpy(pointer_to_parties[i].masterkey[i],
           pointer_to_parties[i].key_left, KEX_SSBYTES);

    for (int j = 1; j < NUM_PARTIES; j++) {
      MasterKey mk;
      memcpy(mk, pointer_to_parties[i].key_left, KEX_SSBYTES);
      for (int k = 0; k < j; k++) {
        xor_keys(mk, pointer_to_parties[i].xs[mod(i-k-1,NUM_PARTIES)], mk);
      }

      memcpy(pointer_to_parties[i].masterkey[mod(i-j, NUM_PARTIES)],
             mk, KEX_SSBYTES);

    }

    print_party(pointer_to_parties, i, NUM_PARTIES, SHOW);

  }

  // Compute session key and session identifier
  for (int i = 0; i < NUM_PARTIES; i++) {
    MasterKey mki;

    // Concat master key
    concat_masterkey(pointer_to_parties[i].masterkey, NUM_PARTIES, mki);

    unsigned char sk_sid[2*KEX_SSBYTES];

    hash_g(sk_sid, mki, 2*KYBER_SYMBYTES);

    memcpy(pointer_to_parties[i].sk, sk_sid, KEX_SSBYTES);
    memcpy(pointer_to_parties[i].sid, sk_sid + KEX_SSBYTES, KEX_SSBYTES);

    print_party(pointer_to_parties, i, NUM_PARTIES, SHOW);
  }

  // Free resources
  for (int i = 0; i < NUM_PARTIES; i++) {
    free(pointer_to_parties[i].commitments);
    free(pointer_to_parties[i].masterkey);
    free(pointer_to_parties[i].pids);
    free(pointer_to_parties[i].coins);
    free(pointer_to_parties[i].xs);
  }
  free(pointer_to_parties);

  return 0;
}
