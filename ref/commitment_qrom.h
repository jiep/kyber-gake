#include "kem_qrom.h"
#include "aes256gcm.h"
#include "indcpa.h"

#ifndef COMMITMENTQROMCOINSBYTES
#define COMMITMENTQROMCOINSBYTES (AES_256_IVEC_LENGTH + KYBER_INDCPA_MSGBYTES)
#endif

#ifndef DEM_QROM_LEN
#define DEM_QROM_LEN (KYBER_INDCPA_MSGBYTES + sizeof(int))
#endif

typedef struct CommitmentQROM {
    unsigned char ciphertext_kem[KYBER_INDCPA_BYTES];
    unsigned char ciphertext_dem[DEM_QROM_LEN];
    unsigned char tag[AES_256_GCM_TAG_LENGTH];
} CommitmentQROM;

void print_commitment(CommitmentQROM* commitment);

int commit(unsigned char* pk,
           unsigned char* m,
           int len_m,
           unsigned char* coins,
           CommitmentQROM* commitment);

int check_commitment(unsigned char* pk,
                     unsigned char* m,
                     unsigned char* coins,
                     CommitmentQROM* commitment_check);
