#include "kem_det.h"
#include "aes256gcm.h"

#ifndef COMMITMENTCOINSBYTES
#define COMMITMENTCOINSBYTES (AES_256_IVEC_LENGTH + KYBER_SYMBYTES)
#endif

typedef struct Commitment {
    unsigned char ciphertext_kem[KYBER_CIPHERTEXTBYTES];
    unsigned char ciphertext_dem[384];
    unsigned char tag[AES_256_GCM_TAG_LENGTH];
} Commitment;

void print_commitment(Commitment* commitment);

int commit(unsigned char* pk,
           unsigned char* m,
           unsigned char* coins,
           Commitment* commitment);

int check_commitment(unsigned char* pk,
                     unsigned char* m,
                     unsigned char* coins,
                     Commitment* commitment_check);
