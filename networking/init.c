#include <string.h>

#include "../ref/gake.h"

typedef uint8_t ip_t[4];

typedef struct keys_t {
  uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
  uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
} keys_t;

typedef struct ca_public {
  uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
  ip_t ip;
} ca_public;

void print_ip_hex(ip_t ip);
int read_ips(char* filename, ip_t* ips);

void ip_to_str(ip_t ip, char* ip_str) {
  sprintf(ip_str, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

void print_ip_hex(ip_t ip) {
  for (short i = 0; i < 4; i++) {
    printf("%02x", ip[i]);
  }
  printf("\n");
}

int read_ca_data(char* filename, int num_parties, ca_public* data) {
  FILE* fp;
  fp = fopen(filename, "rb");
  if (fp == NULL)
    return 1;

  if (fread(data, sizeof(ca_public), num_parties, fp)) {
    return 1;
  }
  fclose(fp);
  return 0;
}

int write_keys(keys_t* key, char* outfile) {
  FILE* fp;
  size_t len = 0;
  ssize_t read;
  fp = fopen(outfile, "wb");
  if (fp == NULL)
    return 1;

  fwrite(key, sizeof(keys_t), 1, fp);

  fclose(fp);

  return 0;
}

int read_keys(char* filename, keys_t* data) {
  FILE* fp;
  fp = fopen(filename, "rb");
  if (fp == NULL)
    return 1;

  if (fread(data, sizeof(keys_t), 1, fp)) {
    return 1;
  }
  fclose(fp);
  return 0;
}

int read_ips(char* filename, ip_t* ips) {
  FILE* fp;
  char* line = NULL;
  size_t len = 0;
  ssize_t read;
  fp = fopen(filename, "r");
  if (fp == NULL)
    return 1;

  int i = 0;
  while ((read = getline(&line, &len, fp)) != -1) {
    char* token;
    int j = 0;
    ip_t ip;
    while (token = strsep(&line, ".")){
      ip[j] = atoi(token);
      j++;
    }
    print_ip_hex(ip);
    memcpy(ips[i], ip, sizeof(ip_t));
    i++;
  }

  fclose(fp);
  if (line) free(line);

  return 0;
}

int write_ca_info(ca_public* pps, int num_parties, char* outfile) {
  FILE* fp;
  size_t len = 0;
  ssize_t read;
  fp = fopen(outfile, "wb");
  if (fp == NULL)
    return 1;

  fwrite(pps, sizeof(ca_public), num_parties, fp);

  fclose(fp);

  return 0;
}

int main() {
  int NUM_PARTIES = 2;
  char* filename_ca = "ca.bin";
  char* filename_keys = "keys.bin";
  char* filename_ips = "ips.txt";

  ip_t* ips = (ip_t*) malloc(sizeof(ip_t) * NUM_PARTIES);

  read_ips(filename_ips, ips);

  for (size_t i = 0; i < NUM_PARTIES; i++) {
    print_ip_hex(ips[i]);
  }

  ca_public* pps = (ca_public*) malloc(sizeof(ca_public)*NUM_PARTIES);

  Party *parties = (Party*) malloc(sizeof(Party) * NUM_PARTIES);

  init_parties(parties, NUM_PARTIES);

  // for (int i = 0; i < NUM_PARTIES; i++) {
  //   crypto_kem_keypair(parties[i].public_key, parties[i].secret_key);
  //   print_short_key(parties[i].public_key, CRYPTO_PUBLICKEYBYTES, 10);
  //   printf("-----------------------------------------------\n");
  //   print_short_key(parties[i].secret_key, CRYPTO_SECRETKEYBYTES, 10);
  //   printf("-----------------------------------------------\n");
  //   print_ip_hex(ips[i]);
  //   printf("-----------------------------------------------\n");
  //
  //   memcpy(pps[i].ip, ips[i], sizeof(ip_t));
  //   memcpy(pps[i].public_key, parties[i].public_key, CRYPTO_PUBLICKEYBYTES);
  //
  //   keys_t keys;
  //   memcpy(keys.public_key, parties[i].public_key, CRYPTO_PUBLICKEYBYTES);
  //   memcpy(keys.secret_key, parties[i].secret_key, CRYPTO_SECRETKEYBYTES);
  //
  //   char filename[21];
  //   char ip_str[17];
  //   ip_to_str(ips[i], ip_str);
  //   sprintf(filename, "%s.bin", ip_str);
  //   write_keys(&keys, filename);
  // }

  // write_ca_info(pps, NUM_PARTIES, filename_ca);
  ca_public* data = (ca_public*) malloc(NUM_PARTIES*sizeof(ca_public));
  read_ca_data(filename_ca, NUM_PARTIES, data);

  printf("Read data___________________________________________________\n");
  for (size_t i = 0; i < NUM_PARTIES; i++) {
    printf("public_key: ");
    print_short_key(data[i].public_key, CRYPTO_PUBLICKEYBYTES, 10);
    print_ip_hex(data[i].ip);

    // char filename[20];
    // char ip_str[17];
    // ip_to_str(ips[i], ip_str);
    // sprintf(filename, "%s.sk", ip_str);
    // printf("filename %s\n", filename);
    // keys_t keys_read;
    // read_keys(filename, &keys_read);
    // printf("w (sk): ");
    // print_key(keys_read.secret_key, CRYPTO_SECRETKEYBYTES);
    // printf("w (pk): ");
    // print_key(keys_read.public_key, CRYPTO_PUBLICKEYBYTES);
  }

  free(pps);
  free(data);
  free(ips);
  free(parties);
  return 0;
}
