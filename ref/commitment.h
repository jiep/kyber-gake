typedef struct Commitment {
    unsigned char ciphertext_kem[KYBER_CIPHERTEXTBYTES];
    unsigned char ciphertext_dem[384];
    unsigned char tag[AES_256_GCM_TAG_LENGTH];
    unsigned char iv[AES_256_IVEC_LENGTH];
} Commitment;

int commit(unsigned char* pk,
           unsigned char* m,
           unsigned char* coins,
           Commitment* commitment);
