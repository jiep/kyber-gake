#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <openssl/evp.h>
#include <openssl/err.h>

#define CHACHA20POLY1305_KEY_LENGTH    32
#define CHACHA20POLY1305_IVEC_LENGTH   12
#define CHACHA20POLY1305_TAG_LENGTH    16

void handleErrors(void);

int chacha20poly1305_encrypt(unsigned char *plaintext, int plaintext_len,
                             unsigned char *aad, int aad_len,
                             unsigned char *key,
                             unsigned char *iv,
                             unsigned char *ciphertext,
                             unsigned char *tag);

int chacha20poly1305_decrypt(unsigned char *ciphertext, int ciphertext_len,
                             unsigned char *aad, int aad_len,
                             unsigned char *tag,
                             unsigned char *key,
                             unsigned char *iv, int iv_len,
                             unsigned char *plaintext);

#endif
