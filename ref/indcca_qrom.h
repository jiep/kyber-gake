#ifndef INDCCA_QROM_H
#define INDCCA_QROM_H

int pke_qrom_keypair(unsigned char* pk, unsigned char* sk);

int pke_qrom_enc(unsigned char* m,
                 int len_m,
                 unsigned char* pk,
                 unsigned char* ciphertext_kem,
                 unsigned char* ciphertext_dem,
                 unsigned char* tag,
                 unsigned char* iv,
                 unsigned char* coins);

int pke_qrom_dec(unsigned char* pk,
                 unsigned char* sk,
                 unsigned char* ciphertext_kem,
                 unsigned char* ciphertext_dem,
                 int ciphertext_dem_len,
                 unsigned char* tag,
                 unsigned char* iv,
                 unsigned char* m);

#endif
