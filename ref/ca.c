#include <string.h>

#include "io.h"
#include "gake.h"

void print_ip_hex(ip_t ip);

void print_ip_hex(ip_t ip) {
  for (short i = 0; i < 4; i++) {
    printf("%02x", ip[i]);
  }
  printf("\n");
}

int main(int argc, char* argv[]) {
  if(argc != 4){
    printf("You must provide a path for ca, a path for ips and a folder to save keys\n");
    exit(1);
  }

  char* filename_ca = argv[1];
  char* filename_ips = argv[2];
  char* output_folder = argv[3];

  int NUM_PARTIES = count_lines(filename_ips);
  printf("IPs read: %d\n", NUM_PARTIES);

  ip_t* ips = (ip_t*) malloc(sizeof(ip_t) * NUM_PARTIES);

  read_ips(filename_ips, ips);

  for (int i = 0; i < NUM_PARTIES; i++) {
    print_ip_hex(ips[i]);
  }

  ca_public* pps = (ca_public*) malloc(sizeof(ca_public) * NUM_PARTIES);

  Party *parties = (Party*) malloc(sizeof(Party) * NUM_PARTIES);

  init_parties(parties, NUM_PARTIES);

  for (int i = 0; i < NUM_PARTIES; i++) {
    crypto_kem_keypair(parties[i].public_key, parties[i].secret_key);
    print_short_key(parties[i].public_key, CRYPTO_PUBLICKEYBYTES, 10);
    printf("-----------------------------------------------\n");
    print_short_key(parties[i].secret_key, CRYPTO_SECRETKEYBYTES, 10);
    printf("-----------------------------------------------\n");
    print_ip_hex(ips[i]);
    printf("-----------------------------------------------\n");

    memcpy(pps[i].ip, ips[i], sizeof(ip_t));
    memcpy(pps[i].public_key, parties[i].public_key, CRYPTO_PUBLICKEYBYTES);

    keys_t keys;
    memcpy(keys.public_key, parties[i].public_key, CRYPTO_PUBLICKEYBYTES);
    memcpy(keys.secret_key, parties[i].secret_key, CRYPTO_SECRETKEYBYTES);

    char filename[21];
    char ip_str[17];
    ip_to_str(ips[i], ip_str);
    sprintf(filename, "%s.bin", ip_str);
    char fin_filename[256];
    strcpy(fin_filename, output_folder);
    strcat(fin_filename, "/");
    strcat(fin_filename, filename);
    write_keys(&keys, fin_filename);
  }

  write_ca_info(pps, NUM_PARTIES, filename_ca);
  ca_public* data = (ca_public*) malloc(NUM_PARTIES*sizeof(ca_public));
  int ca_length = 0;
  ca_public* data2 = (ca_public*) malloc(NUM_PARTIES*sizeof(ca_public));
  read_ca_data(filename_ca, &ca_length, data2);
  printf("ca_length: %d\n", ca_length);

  printf("Read data___________________________________________________\n");
  for (int i = 0; i < ca_length; i++) {
    printf("public_key: ");
    print_short_key(data2[i].public_key, CRYPTO_PUBLICKEYBYTES, 10);
    print_ip_hex(data2[i].ip);

    char filename[21];
    char ip_str[17];
    ip_to_str(ips[i], ip_str);
    sprintf(filename, "%s.bin", ip_str);
    printf("filename %s\n", filename);
    keys_t keys_read;
    read_keys(filename, &keys_read);
    printf("w (sk): ");
    print_short_key(keys_read.secret_key, CRYPTO_SECRETKEYBYTES, 10);
    printf("w (pk): ");
    print_short_key(keys_read.public_key, CRYPTO_PUBLICKEYBYTES, 10);
  }

  free(pps);
  free(data);
  free(ips);
  free(parties);
  return 0;
}
