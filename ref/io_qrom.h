#include <stdint.h>
#include "api.h"

typedef uint8_t ip_t[4];

typedef struct keys_qrom_t {
  uint8_t public_key[KYBER_INDCPA_PUBLICKEYBYTES];
  uint8_t secret_key[KYBER_INDCPA_SECRETKEYBYTES];
} keys_qrom_t;

typedef struct ca_qrom_public {
  uint8_t public_key[KYBER_INDCPA_PUBLICKEYBYTES];
  ip_t ip;
} ca_qrom_public;

int read_keys(char* filename, keys_qrom_t* data);
int read_ca_data(char* filename, int* parties, ca_qrom_public* data);
int get_pk(char* ip_str, uint8_t* pk, ca_qrom_public* data, int length);
void set_ip(char* ip_str, ip_t* ip);
void ip_to_str(ip_t ip, char* ip_str);
void set_message(uint8_t* iv, uint8_t* tag, uint8_t* ct, int ct_len, uint8_t* message);
void unset_message(uint8_t* message, uint8_t* iv, uint8_t* tag, uint8_t* ct, int* ct_len);
int write_keys(keys_qrom_t* key, char* outfile);
int read_ips(char* filename, ip_t* ips);
int write_ca_info(ca_qrom_public* pps, int num_parties, char* outfile);
int count_lines(char* filename);
int get_index(ip_t* ips, int length, char* ip);
int file_exists(char* filename);
int get_ca_length(char* filename);
