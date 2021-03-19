#include "kem_det.h"
#include "chacha20poly1305.h"
#include "kex.h"

#ifndef COMMITMENTCOINSBYTES
#define COMMITMENTCOINSBYTES (CHACHA20POLY1305_IVEC_LENGTH + KEX_SSBYTES)
#endif

#ifndef DEM_LEN
#define DEM_LEN (KEX_SSBYTES + sizeof(int))
#endif

#ifndef COMMITMENT_LENGTH
#define COMMITMENT_LENGTH (KYBER_CIPHERTEXTBYTES + DEM_LEN + CHACHA20POLY1305_TAG_LENGTH)
#endif

typedef struct Commitment {
    unsigned char ciphertext_kem[KYBER_CIPHERTEXTBYTES];
    unsigned char ciphertext_dem[DEM_LEN];
    unsigned char tag[CHACHA20POLY1305_TAG_LENGTH];
} Commitment;

void print_commitment(Commitment* commitment);

void copy_commitment(uint8_t* buf, Commitment* commitment);

int is_zero_commitment(Commitment* commitment);

int commit(unsigned char* pk,
           unsigned char* m,
           int len_m,
           unsigned char* coins,
           Commitment* commitment);

int check_commitment(unsigned char* pk,
                     unsigned char* m,
                     unsigned char* coins,
                     Commitment* commitment_check);
