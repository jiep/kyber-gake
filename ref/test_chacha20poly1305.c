#include <string.h>

#include "chacha20poly1305.h"
#include "randombytes.h"
#include "utils.h"

int main() {

  unsigned char* plaintext = (unsigned char *) "The quick brown fox jumps over the lazy dog";
  int plaintext_len = strlen((char *) plaintext);

  unsigned char* aad = (unsigned char *) "";
  int aad_len = strlen((char *) plaintext);

  unsigned char key[CHACHA20POLY1305_KEY_LENGTH];
  unsigned char iv[CHACHA20POLY1305_IVEC_LENGTH];

  randombytes(key, CHACHA20POLY1305_KEY_LENGTH);
  randombytes(iv,  CHACHA20POLY1305_IVEC_LENGTH);

  printf("key: ");
  print_key(key, CHACHA20POLY1305_KEY_LENGTH);
  printf("iv: ");
  print_key(iv, CHACHA20POLY1305_IVEC_LENGTH);

  printf("plaintext: %s\n", plaintext);

  unsigned char ciphertext[1000];
  unsigned char tag[CHACHA20POLY1305_TAG_LENGTH];

  int ciphertext_len = chacha20poly1305_encrypt(plaintext, plaintext_len,
                                                aad, aad_len,
                                                key,
                                                iv,
                                                ciphertext,
                                                tag);

  if (ciphertext_len == -1) {
    printf("Error!\n");
    return 1;
  }

  printf("Ciphertext: ");
  print_key(ciphertext, ciphertext_len);
  printf("Tag: ");
  print_key(tag, CHACHA20POLY1305_TAG_LENGTH);

  unsigned char plaintext_dec[1000];

  plaintext_len = chacha20poly1305_decrypt(ciphertext, ciphertext_len,
                                           aad, aad_len,
                                           tag,
                                           key,
                                           iv, CHACHA20POLY1305_IVEC_LENGTH,
                                           plaintext_dec);

  if (plaintext_len == -1) {
    printf("Error!\n");
    return 1;
  }

  plaintext_dec[plaintext_len] = '\0';
  printf("Plaintext: %s\n", plaintext_dec);

  return 0;
}