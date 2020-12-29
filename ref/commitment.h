#include "kem_det.h"
#include "aes256gcm.h"
#include "kex.h"

#ifndef COMMITMENTCOINSBYTES
#define COMMITMENTCOINSBYTES (AES_256_IVEC_LENGTH + KEX_SSBYTES)
#endif

#ifndef DEM_LEN
#define DEM_LEN (KEX_SSBYTES + sizeof(int))
#endif

typedef struct Commitment {
    unsigned char ciphertext_kem[KYBER_CIPHERTEXTBYTES];
    unsigned char ciphertext_dem[DEM_LEN];
    unsigned char tag[AES_256_GCM_TAG_LENGTH];
} Commitment;

void print_commitment(Commitment* commitment);

int commit(unsigned char* pk,
           unsigned char* m,
           int len_m,
           unsigned char* coins,
           Commitment* commitment);

int check_commitment(unsigned char* pk,
                     unsigned char* m,
                     unsigned char* coins,
                     Commitment* commitment_check);
