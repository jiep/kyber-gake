#ifndef AES256GCM_H
#define AES256GCM_H

#include <openssl/evp.h>
#include <openssl/err.h>

#define AES_256_KEY_LENGTH        32
#define AES_256_KEY_LENGTH_BITS   256
#define AES_256_IVEC_LENGTH       12
#define AES_256_GCM_TAG_LENGTH    16

void handleErrors(void);

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag);

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);

#endif
