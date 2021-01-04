#ifndef KEM_DEC_H
#define KEM_DEC_H

#include "params.h"

int crypto_kem_det_keypair(unsigned char *pk, unsigned char *sk);

int crypto_kem_det_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk,
                   const unsigned char *coins);

int crypto_kem_det_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk);

#endif
