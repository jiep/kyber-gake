#ifndef KEM_QROM_H
#define KEM_QROM_H

void kem_qrom_keypair(unsigned char* pk, unsigned char* sk);

void kem_qrom_encaps(unsigned char* pk, unsigned char* coins,
                     unsigned char* K, unsigned char* c);

void kem_qrom_decaps(unsigned char* pk, unsigned char* sk, unsigned char* c,
                    unsigned char* K);

#endif
