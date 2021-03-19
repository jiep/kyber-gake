#ifndef AES256CCM_H
#define AES256CCM_H

#include <openssl/evp.h>
#include <openssl/err.h>

#define AES_256_KEY_LENGTH        32
#define AES_256_KEY_LENGTH_BITS   256
#define AES_256_IVEC_LENGTH       7
#define AES_256_CCM_TAG_LENGTH    14

void handleErrors(void);

int ccm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag);

int ccm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *plaintext);

#endif
