#include "chacha20poly1305.h"

void handleErrors(void) {
  printf("Error!\n");
  ERR_print_errors_fp(stderr);
  abort();
}

int chacha20poly1305_encrypt(unsigned char *plaintext, int plaintext_len,
                             unsigned char *aad, int aad_len,
                             unsigned char *key,
                             unsigned char *iv,
                             unsigned char *ciphertext,
                             unsigned char *tag) {


  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  if(!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  if(1 != EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL))
    handleErrors();

  if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
    handleErrors();

  if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    handleErrors();

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();

  ciphertext_len = len;

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();

  ciphertext_len += len;

  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
    handleErrors();

  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int chacha20poly1305_decrypt(unsigned char *ciphertext, int ciphertext_len,
                             unsigned char *aad, int aad_len,
                             unsigned char *tag,
                             unsigned char *key,
                             unsigned char *iv, int iv_len,
                             unsigned char *plaintext) {

  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int ret;

  if(!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  if(!EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL))
    handleErrors();

  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL))
    handleErrors();

  if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    handleErrors();

  if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    handleErrors();

  if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();

  plaintext_len = len;

  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
    handleErrors();

  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  EVP_CIPHER_CTX_free(ctx);

  if(ret > 0) {
    plaintext_len += len;
    return plaintext_len;
  } else {
    return -1;
  }
}
