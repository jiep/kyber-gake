#ifndef KEX_QROM_H
#define KEX_QROM_H

void init(unsigned char* pkj,
          unsigned char* M, unsigned char* st);

void der_resp(unsigned char* skj, unsigned char* pki, unsigned char* pkj, unsigned char* M, int i, int j,
              unsigned char* K, unsigned char* M_prime);

void der_init(unsigned char* ski, unsigned char* pki, unsigned char* M_prime, unsigned char* st, int i, int j,
              unsigned char* K_prime);

#endif
