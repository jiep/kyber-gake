#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "gake.h"

void print_sk(uint8_t *key) {
  for(int j = 0; j < KEX_SSBYTES; j++){
    printf("%02x", key[j]);
  }
  printf("\n");
}

void xor_keys(uint8_t *x_a, uint8_t *x_b, uint8_t *x_out){

  for (int j = 0; j < KEX_SSBYTES; j++) {
    x_out[j] = x_a[j] ^ x_b[j];
  }
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

void concat_masterkey(MasterKey* mk, Pid* pids, int num_parties, uint8_t *concat_mk) {
  for (int i = 0; i < num_parties; i++) {
    memcpy(concat_mk + i*KEX_SSBYTES, mk[i], KEX_SSBYTES);
  }

  for (int j = 0; j < num_parties; j++) {
    memcpy(concat_mk + num_parties*KEX_SSBYTES + PID_LENGTH*j, pids[j], PID_LENGTH);
  }
}

void print_party(Party* parties, int i, int num_parties, int show) {
  printf("Party %d\n", i);

  printf("\tPublic key:  ");
  print_short_key(parties[i].public_key, CRYPTO_PUBLICKEYBYTES, show);

  printf("\tSecret key:  ");
  print_short_key(parties[i].secret_key, CRYPTO_SECRETKEYBYTES, show);

  printf("\tLeft key:    ");
  print_short_key(parties[i].key_left, KEX_SSBYTES, show);

  printf("\tRight key:   ");
  print_short_key(parties[i].key_right, KEX_SSBYTES, show);

  printf("\tSession id:  ");
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
    print_short_key(parties[i].coins[j], COMMITMENTCOINSBYTES, show);
  }

  printf("\tCommitments:\n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tc%d: ", j);
    print_commitment(&parties[i].commitments[j]);
  }

  printf("\tMaster Key: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tk%d: ", j);
    print_short_key(parties[i].masterkey[j], KEX_SSBYTES, show);
  }

  printf("\tPids: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tpid%d: %s\n", j, (char*) parties[i].pids[j]);
  }

  printf("\tAccepted:   %d\n", parties[i].acc);
  printf("\tTerminated: %d\n", parties[i].term);
}

void init_parties(Party* parties, int num_parties) {
  for (int i = 0; i < num_parties; i++) {
    parties[i].commitments = malloc(sizeof(Commitment) * num_parties);
    parties[i].masterkey = malloc(sizeof(MasterKey) * num_parties);
    parties[i].pids = malloc(sizeof(Pid) * num_parties);
    parties[i].coins = malloc(sizeof(Coins) * num_parties);
    parties[i].xs = malloc(sizeof(X) * num_parties);

    for (int j = 0; j < num_parties; j++) {
      char pid[PID_LENGTH];
      sprintf(pid, "%s %d", "Party", j);
      memcpy(parties[i].pids[j], pid, PID_LENGTH);
    }

    for (int j = 0; j < num_parties; j++) {
      init_to_zero(parties[i].commitments[j].ciphertext_kem, KYBER_CIPHERTEXTBYTES);
      init_to_zero(parties[i].commitments[j].ciphertext_dem, DEM_LEN);
      init_to_zero(parties[i].commitments[j].tag, AES_256_GCM_TAG_LENGTH);
      init_to_zero(parties[i].coins[j], COMMITMENTCOINSBYTES);
      init_to_zero(parties[i].masterkey[j], KEX_SSBYTES);
      init_to_zero(parties[i].xs[j], KEX_SSBYTES);
    }

    init_to_zero(parties[i].sid, KEX_SSBYTES);
    init_to_zero(parties[i].sk, KEX_SSBYTES);
    init_to_zero(parties[i].key_left, KEX_SSBYTES);
    init_to_zero(parties[i].key_right, KEX_SSBYTES);

    crypto_kem_keypair(parties[i].public_key,
                       parties[i].secret_key);

    parties[i].acc = 0;
    parties[i].term = 0;

  }
}

void print_parties(Party* parties, int num_parties, int show) {
  for (int i = 0; i < num_parties; i++) {
    print_party(parties, i, num_parties, show);
  }
}

void free_parties(Party* parties, int num_parties) {
  for (int i = 0; i < num_parties; i++) {
    free(parties[i].commitments);
    free(parties[i].masterkey);
    free(parties[i].pids);
    free(parties[i].coins);
    free(parties[i].xs);
  }
  free(parties);
}

void compute_sk_sid(Party* parties, int num_parties) {
  for (int i = 0; i < num_parties; i++) {
    unsigned char mki[(KEX_SSBYTES + PID_LENGTH*sizeof(char))*num_parties];

    // Concat master key
    concat_masterkey(parties[i].masterkey, parties[i].pids, num_parties, mki);

    unsigned char sk_sid[2*KEX_SSBYTES];

    hash_g(sk_sid, mki, 2*KEX_SSBYTES);

    memcpy(parties[i].sk, sk_sid, KEX_SSBYTES);
    memcpy(parties[i].sid, sk_sid + KEX_SSBYTES, KEX_SSBYTES);

    parties[i].acc = 1;
    parties[i].term = 1;
  }
}

void compute_masterkey(Party* parties, int num_parties) {

  for (int i = 0; i < num_parties; i++) {
    memcpy(parties[i].masterkey[i],
           parties[i].key_left, KEX_SSBYTES);

    for (int j = 1; j < num_parties; j++) {
      MasterKey mk;
      memcpy(mk, parties[i].key_left, KEX_SSBYTES);
      for (int k = 0; k < j; k++) {
        xor_keys(mk, parties[i].xs[mod(i-k-1,num_parties)], mk);
      }

      memcpy(parties[i].masterkey[mod(i-j, num_parties)],
             mk, KEX_SSBYTES);

    }
  }
}

int check_commitments(Party* parties, int i, int num_parties) {
  for (int j = 0; j < num_parties; j++) {
    unsigned char msg[KEX_SSBYTES + sizeof(int)];
    char buf_int[sizeof(int)];
    init_to_zero((unsigned char*) buf_int, sizeof(int));
    itoa(j, buf_int);
    memcpy(msg, parties[i].xs[j], KEX_SSBYTES);
    memcpy(msg + KEX_SSBYTES, buf_int, sizeof(int));

    int res_check = check_commitment(parties[j].public_key,
                     msg,
                     parties[i].coins[j],
                     &parties[i].commitments[j]);

    if (res_check != 0) {
      return 1;
    }
  }
  return 0;
}

int check_xs(Party* parties, int i, int num_parties) {
  unsigned char zero[KEX_SSBYTES];

  for(int j = 0; j < KEX_SSBYTES; j++){
    zero[j] = 0;
  }

  X check;
  memcpy(check, parties[i].xs[0], KEX_SSBYTES);
  for (int j = 0; j < num_parties - 1; j++) {
    xor_keys(parties[i].xs[j+1], check, check);
  }

  int res = memcmp(check, zero, KEX_SSBYTES);
  if (res != 0) {
    return 1;
  }
  return 0;
}

void compute_xs_commitments(Party* parties, int num_parties) {
  for (int i = 0; i < num_parties; i++) {
    X xi;
    Coins ri;
    Commitment ci;

    unsigned char msg[KEX_SSBYTES + sizeof(int)];
    init_to_zero(msg, KEX_SSBYTES + sizeof(int));
    char buf_int[sizeof(int)];
    init_to_zero((unsigned char*) buf_int, KEX_SSBYTES + sizeof(int));
    itoa(i, buf_int);

    xor_keys(parties[i].key_right, parties[i].key_left, xi);
    randombytes(ri, COMMITMENTCOINSBYTES);

    memcpy(msg, &xi, KEX_SSBYTES);
    memcpy(msg + KEX_SSBYTES, &buf_int, sizeof(int));
    commit(parties[i].public_key, msg, DEM_LEN, ri, &ci);

    for (int j = 0; j < num_parties; j++) {
      memcpy(parties[j].xs[i], &xi, KEX_SSBYTES);
      memcpy(parties[j].coins[i], &ri, COMMITMENTCOINSBYTES);
      parties[j].commitments[i] = ci;
    }
  }
}

void compute_left_right_keys(Party* parties, int num_parties) {
  for (int i = 0; i < num_parties; i++) {
    int right = mod(i+1, num_parties);
    int left = mod(i-1, num_parties);

    two_ake(parties[i].public_key, parties[right].public_key,
            parties[i].secret_key, parties[right].secret_key,
            parties[i].key_right,   parties[right].key_left);

    two_ake(parties[i].public_key, parties[left].public_key,
            parties[i].secret_key, parties[left].secret_key,
            parties[i].key_left,   parties[left].key_right);
  }
}

int check_all_keys(Party* parties, int num_parties) {
  unsigned char  sk[KEX_SSBYTES];
  unsigned char sid[KEX_SSBYTES];

  for (int i = 0; i < num_parties - 1; i++) {
    memcpy(sk,  parties[i].sk,  KEX_SSBYTES);
    memcpy(sid, parties[i].sid, KEX_SSBYTES);

    int res_sk  = memcmp(sk, parties[i+1].sk,  KEX_SSBYTES);
    int res_sid = memcmp(sid, parties[i+1].sid, KEX_SSBYTES);

    if (res_sk != 0 || res_sid != 0) {
      return 1;
    }

    memcpy(sk,  parties[i+1].sk,  KEX_SSBYTES);
    memcpy(sid, parties[i+1].sid, KEX_SSBYTES);

  }
  return 0;
}

void print_stats(clock_t end_init,
                 clock_t end_12,
                 clock_t end_3,
                 clock_t end_4,
                 clock_t begin_total) {

   double time_init  = (double)(end_init - begin_total) / CLOCKS_PER_SEC;
   double time_12    = (double)(end_12 - end_init) / CLOCKS_PER_SEC;
   double time_3     = (double)(end_3 - end_12) / CLOCKS_PER_SEC;
   double time_4     = (double)(end_4 - end_3) / CLOCKS_PER_SEC;
   double time_total = (double)(end_4 - begin_total) / CLOCKS_PER_SEC;

   printf("\n\nTime stats\n");
   printf("\tInit time      : %.3fs (%.2f%%)\n", time_init, time_init*100/time_total);
   printf("\tRound 1-2 time : %.3fs (%.2f%%)\n", time_12, time_12*100/time_total);
   printf("\tRound 3 time   : %.3fs (%.2f%%)\n", time_3, time_3*100/time_total);
   printf("\tRound 4 time   : %.3fs (%.2f%%)\n", time_4, time_4*100/time_total);
   printf("\tTotal time     : %.3fs (%.2f%%)\n", time_total, time_total*100/time_total);
}
