#include <string.h>

#include "kex_qrom.h"
#include "indcpa.h"
#include "symmetric.h"
#include "randombytes.h"
#include "kex.h"
#include "utils.h"

void init(unsigned char* pkj,
          unsigned char* M, unsigned char* st) {

  __attribute__((aligned(32)))
  uint8_t mj[KYBER_INDCPA_MSGBYTES];
  __attribute__((aligned(32)))
  uint8_t cj[KYBER_INDCPA_BYTES];
  __attribute__((aligned(32)))
  uint8_t pk_tilde[KYBER_INDCPA_PUBLICKEYBYTES];
  __attribute__((aligned(32)))
  uint8_t sk_tilde[KYBER_INDCPA_SECRETKEYBYTES];
  __attribute__((aligned(32)))
  uint8_t hash_mj[KYBER_SYMBYTES];

  randombytes(mj, KYBER_INDCPA_MSGBYTES);

  // printf("mj: ");
  // print_key(mj, KYBER_INDCPA_MSGBYTES);

  hash_h(hash_mj, mj, KYBER_SYMBYTES);

  // printf("G(mj): ");
  // print_key(hash_mj, KYBER_SYMBYTES);

  indcpa_enc(cj, mj, pkj, hash_mj);

  indcpa_keypair(pk_tilde, sk_tilde);

  memcpy(M, pk_tilde, KYBER_INDCPA_PUBLICKEYBYTES);
  memcpy(M + KYBER_INDCPA_PUBLICKEYBYTES, cj, KYBER_INDCPA_BYTES);

  memcpy(st, sk_tilde, KYBER_INDCPA_SECRETKEYBYTES);
  memcpy(st + KYBER_INDCPA_SECRETKEYBYTES, mj, KYBER_INDCPA_MSGBYTES);
  memcpy(st + KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_MSGBYTES, M, KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES);
}

void der_resp(unsigned char* skj, unsigned char* pki, unsigned char* pkj, unsigned char* M, int i, int j,
              unsigned char* K, unsigned char* M_prime) {

  __attribute__((aligned(32)))
  uint8_t pk_tilde[KYBER_INDCPA_PUBLICKEYBYTES];
  __attribute__((aligned(32)))
  uint8_t ci[KYBER_INDCPA_BYTES];
  __attribute__((aligned(32)))
  uint8_t cj[KYBER_INDCPA_BYTES];
  __attribute__((aligned(32)))
  uint8_t c_tilde[KYBER_INDCPA_BYTES];
  __attribute__((aligned(32)))
  uint8_t cj_tilde[KYBER_INDCPA_BYTES];
  __attribute__((aligned(32)))
  uint8_t mi[KYBER_INDCPA_MSGBYTES];
  __attribute__((aligned(32)))
  uint8_t m_tilde[KYBER_INDCPA_MSGBYTES];
  __attribute__((aligned(32)))
  uint8_t mj_prime[KYBER_INDCPA_MSGBYTES];
  __attribute__((aligned(32)))
  uint8_t hash_mi[KYBER_SYMBYTES];
  __attribute__((aligned(32)))
  uint8_t hash_mtilde[KYBER_SYMBYTES];
  __attribute__((aligned(32)))
  uint8_t hash_mjprime[KYBER_SYMBYTES];

  memcpy(pk_tilde, M, KYBER_INDCPA_PUBLICKEYBYTES);
  memcpy(cj, M + KYBER_INDCPA_PUBLICKEYBYTES, KYBER_INDCPA_BYTES);

  // printf("cj: ");
  // print_key(cj, KYBER_INDCPA_BYTES);

  // printf("pk': ");
  // print_key(pk_tilde, KYBER_INDCPA_PUBLICKEYBYTES);

  randombytes(mi, KYBER_INDCPA_MSGBYTES);
  randombytes(m_tilde, KYBER_INDCPA_MSGBYTES);

  // printf("mi: ");
  // print_key(mi, KYBER_INDCPA_MSGBYTES);

  // printf("m~: ");
  // print_key(m_tilde, KYBER_INDCPA_MSGBYTES);

  hash_h(hash_mi, mi, KYBER_SYMBYTES);
  hash_h(hash_mtilde, m_tilde, KYBER_SYMBYTES);

  indcpa_enc(ci, mi, pki, hash_mi);
  indcpa_enc(c_tilde, m_tilde, pk_tilde, hash_mtilde);

  memcpy(M_prime, ci, KYBER_INDCPA_BYTES);
  memcpy(M_prime + KYBER_INDCPA_BYTES, c_tilde, KYBER_INDCPA_BYTES);

  indcpa_dec(mj_prime, cj, skj);

  // printf("mj': ");
  // print_key(mj_prime, KYBER_INDCPA_MSGBYTES);

  hash_h(hash_mjprime, mj_prime, KYBER_SYMBYTES);

  // printf("mj': ");
  // print_key(mj_prime, KYBER_INDCPA_MSGBYTES);
  indcpa_enc(cj_tilde, mj_prime, pkj, hash_mjprime);

  // printf("cj': ");
  // print_key(cj_tilde, KYBER_INDCPA_BYTES);
  //
  // printf("cj: ");
  // print_key(cj, KYBER_INDCPA_BYTES);

  if(memcmp(cj, cj_tilde, KYBER_INDCPA_BYTES) != 0){
    printf("Error\n");
    // unsigned char key[KEX_SSBYTES];
    // randombytes(key, KEX_SSBYTES);
    // prf(K, KEX_SSBYTES, key, key);
  } else {
    char str_buf[20];
    unsigned char msg[3*KYBER_INDCPA_MSGBYTES + 2*sizeof(int) + KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES + 2*KYBER_INDCPA_BYTES];
    memcpy(msg, mi, KYBER_INDCPA_MSGBYTES);
    memcpy(msg + KYBER_INDCPA_MSGBYTES, mj_prime, KYBER_INDCPA_MSGBYTES);
    memcpy(msg + 2*KYBER_INDCPA_MSGBYTES, m_tilde, KYBER_INDCPA_MSGBYTES);
    itoa(i, str_buf);
    memcpy(msg + 3*KYBER_INDCPA_MSGBYTES, str_buf, sizeof(int));
    itoa(j, str_buf);
    memcpy(msg + 3*KYBER_INDCPA_MSGBYTES + sizeof(int), str_buf, sizeof(int));
    memcpy(msg + 3*KYBER_INDCPA_MSGBYTES + 2*sizeof(int), M, KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES);
    memcpy(msg + 3*KYBER_INDCPA_MSGBYTES + 2*sizeof(int) + KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES,
      M_prime, 2*KYBER_INDCPA_BYTES);

    // printf("msg: ");
    // print_key(msg, 3*KYBER_INDCPA_MSGBYTES + 2*sizeof(int) + KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES + 2*KYBER_INDCPA_BYTES);

    hash_h(K, msg, KEX_SSBYTES);
  }
}

void der_init(unsigned char* ski, unsigned char* pki, unsigned char* M_prime, unsigned char* st, int i, int j,
              unsigned char* K_prime) {

  __attribute__((aligned(32)))
  uint8_t ci[KYBER_INDCPA_BYTES];
  __attribute__((aligned(32)))
  uint8_t c_tilde[KYBER_INDCPA_BYTES];
  __attribute__((aligned(32)))
  uint8_t ci_tilde[KYBER_INDCPA_BYTES];
  __attribute__((aligned(32)))
  uint8_t sk_tilde[KYBER_INDCPA_SECRETKEYBYTES];
  __attribute__((aligned(32)))
  uint8_t mj[KYBER_INDCPA_MSGBYTES];
  __attribute__((aligned(32)))
  uint8_t mi_prime[KYBER_INDCPA_MSGBYTES];
  __attribute__((aligned(32)))
  uint8_t mi_tilde[KYBER_INDCPA_MSGBYTES];
  __attribute__((aligned(32)))
  uint8_t M[KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES];
  __attribute__((aligned(32)))
  uint8_t hash_mjprime[KYBER_SYMBYTES];

  memcpy(ci, M_prime, KYBER_INDCPA_BYTES);
  memcpy(c_tilde, M_prime + KYBER_INDCPA_BYTES, KYBER_INDCPA_BYTES);

  memcpy(sk_tilde, st, KYBER_INDCPA_SECRETKEYBYTES);
  memcpy(mj, st + KYBER_INDCPA_SECRETKEYBYTES, KYBER_INDCPA_MSGBYTES);
  memcpy(M, st + KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_MSGBYTES, KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES);

  indcpa_dec(mi_prime, ci, ski);
  indcpa_dec(mi_tilde, c_tilde, sk_tilde);

  // printf("mi': ");
  // print_key(mi_prime, KYBER_INDCPA_MSGBYTES);

  // printf("mi~: ");
  // print_key(mi_tilde, KYBER_INDCPA_MSGBYTES);

  hash_h(hash_mjprime, mi_prime, KYBER_SYMBYTES);
  indcpa_enc(ci_tilde, mi_prime, pki, hash_mjprime);

  if(memcmp(ci_tilde, ci, KYBER_INDCPA_BYTES) != 0){

  } else {
    char str_buf[20];
    unsigned char msg[3*KYBER_INDCPA_MSGBYTES + 2*sizeof(int) + KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES + 2*KYBER_INDCPA_BYTES];
    memcpy(msg, mi_prime, KYBER_INDCPA_MSGBYTES);
    memcpy(msg + KYBER_INDCPA_MSGBYTES, mj, KYBER_INDCPA_MSGBYTES);
    memcpy(msg + 2*KYBER_INDCPA_MSGBYTES, mi_tilde, KYBER_INDCPA_MSGBYTES);
    itoa(i, str_buf);
    memcpy(msg + 3*KYBER_INDCPA_MSGBYTES, str_buf, sizeof(int));
    itoa(j, str_buf);
    memcpy(msg + 3*KYBER_INDCPA_MSGBYTES + sizeof(int), str_buf, sizeof(int));
    memcpy(msg + 3*KYBER_INDCPA_MSGBYTES + 2*sizeof(int), M, KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES);
    memcpy(msg + 3*KYBER_INDCPA_MSGBYTES + 2*sizeof(int) + KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_BYTES,
      M_prime, 2*KYBER_INDCPA_BYTES);

    hash_h(K_prime, msg, KEX_SSBYTES);
  }
}
