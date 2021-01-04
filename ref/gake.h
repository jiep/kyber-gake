#ifndef GAKE_H
#define GAKE_H

#include <time.h>

#include "kex.h"
#include "indcpa.h"
#include "randombytes.h"
#include "api.h"
#include "symmetric.h"
#include "commitment.h"
#include "utils.h"

typedef unsigned char MasterKey[KEX_SSBYTES];
typedef unsigned char X[KEX_SSBYTES];
typedef char * Pid[PID_LENGTH];
typedef unsigned char Coins[COMMITMENTCOINSBYTES];

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
    uint8_t acc;
    uint8_t term;
} Party;

void print_sk(uint8_t *key);
int check_keys(uint8_t *ka, uint8_t *kb, uint8_t *zero);
void xor_keys(uint8_t *x_a, uint8_t *x_b, uint8_t *x_out);
void two_ake(uint8_t *pka, uint8_t *pkb, uint8_t *ska, uint8_t *skb, uint8_t *ka, uint8_t *kb);
void print_party(Party* parties, int i, int num_parties, int show);
void print_parties(Party* parties, int num_parties, int show);
void concat_masterkey(MasterKey* mk, Pid* pids, int num_parties, uint8_t *concat_mk);
void init_parties(Party* parties, int num_parties);
void free_parties(Party* parties, int num_parties);
void compute_sk_sid(Party* parties, int num_parties);
void compute_masterkey(Party* parties, int num_parties);
int check_commitments(Party* parties, int i, int num_parties);
int check_xs(Party* parties, int i, int num_parties);
void compute_xs_commitments(Party* parties, int num_parties);
void compute_left_right_keys(Party* parties, int num_parties);
int check_all_keys(Party* parties, int num_parties);
void print_stats(clock_t end_init,
                 clock_t end_12,
                 clock_t end_3,
                 clock_t end_4,
                 clock_t begin_total);

#endif
