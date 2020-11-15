#include "commitment.h"
#include "kem_det.h"

int int commit(unsigned char* pk,
           unsigned char* m,
           unsigned char* coins,
           Commitment* commitment) {

   return pke_enc(m,
                  pk,
                  commitment.ciphertext_kem,
                  commitment.ciphertext_dem,
                  commitment.tag,
                  commitment.iv,
                  coins);
}
