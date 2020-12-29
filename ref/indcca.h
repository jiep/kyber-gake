#ifndef INDCCA_H
#define INDCCA_H

// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Decryption_using_GCM_mode
void print_data(unsigned char* m,
                int len_m,
                unsigned char* pk,
                unsigned char* ciphertext_kem,
                unsigned char* ciphertext_dem,
                unsigned char* tag,
                unsigned char* iv,
                unsigned char* coins);

int pke_keypair(unsigned char* pk, unsigned char* sk);

int pke_enc(unsigned char* m,
            int len_m,
            unsigned char* pk,
            unsigned char* ciphertext_kem,
            unsigned char* ciphertext_dem,
            unsigned char* tag,
            unsigned char* iv,
            unsigned char* coins);

int pke_dec(unsigned char* sk,
            unsigned char* ciphertext_kem,
            unsigned char* ciphertext_dem,
            int ciphertext_dem_len,
            unsigned char* tag,
            unsigned char* iv,
            unsigned char* m);

#endif
