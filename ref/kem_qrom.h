void kem_qrom_keypair(unsigned char* pk, unsigned char* sk);

void kem_qrom_encaps(unsigned char* pk, unsigned char* coins,
                     unsigned char* K, unsigned char* c);

void kem_qrom_decaps(unsigned char* pk, unsigned char* sk, unsigned char* c,
                    unsigned char* K);
