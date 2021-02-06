#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

#include "io.h"
#include "common.h"
#include "../ref/utils.h"
#include "../ref/gake.h"

void start_server(uint8_t* pk, uint8_t* sk, uint8_t* pk_client, uint8_t* key) {
  struct sockaddr_in serveraddress, client;
  socklen_t length;
  int sockert_file_descriptor, connection, bind_status, connection_status;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd == -1){
    printf("Socket creation failed!\n");
    exit(1);
  } else {
    printf("Socket fd: %d\n", fd);
  }

  int enable = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
    printf("setsockopt(SO_REUSEADDR) failed!\n");
    exit(1);
  }

  bzero(&serveraddress, sizeof(serveraddress));
  serveraddress.sin_addr.s_addr = htonl(INADDR_ANY);
  serveraddress.sin_port = htons(PORT);
  serveraddress.sin_family = AF_INET;

  bind_status = bind(fd, (SA*)&serveraddress, sizeof(serveraddress));

  if(bind_status == -1){
    printf("Socket binding failed.!\n");
    exit(1);
  }

  connection_status = listen(fd, 5);

  if(connection_status == -1) {
    printf("Socket is unable to listen for new connections!\n");
    exit(1);
  } else {
    printf("Server is listening for new connection: \n");
  }

  length = sizeof(client);
  connection = accept(fd, (SA*)&client, &length);

  if(connection == -1){
    printf("Server is unable to accept the data from client!\n");
    exit(1);
  }

  unsigned char pka[CRYPTO_PUBLICKEYBYTES];
  unsigned char ake_sendb[KEX_AKE_SENDBBYTES];
  unsigned char ake_senda[KEX_AKE_SENDABYTES];
  unsigned char kb[KEX_SSBYTES];

  bzero(ake_senda, sizeof(ake_senda));
  bzero(kb, sizeof(kb));

  int bytes = 0;

  read(connection, ake_senda, sizeof(ake_senda));
  printf("[C] ake_senda: ");
  print_short_key(ake_senda, KEX_AKE_SENDABYTES, 10);

  kex_ake_sharedB(ake_sendb, kb, ake_senda, sk, pk_client);
  printf("[S] ake_sendb: ");
  print_short_key(ake_sendb, KEX_AKE_SENDABYTES, 10);

  // Send second message
  bytes = write(connection, ake_sendb, sizeof(ake_sendb));
  if(bytes >= 0){
    printf("Data sent successfully!\n");
  }

  printf("[S] key: ");
  print_key(kb, KEX_SSBYTES);

  close(fd);
}

void init_party(Party* party, int num_parties, ip_t* ips, keys_t* keys) {
  party->commitments = malloc(sizeof(Commitment) * num_parties);
  party->masterkey = malloc(sizeof(MasterKey) * num_parties);
  party->pids = malloc(sizeof(Pid) * num_parties);
  party->coins = malloc(sizeof(Coins) * num_parties);
  party->xs = malloc(sizeof(X) * num_parties);

  for (int j = 0; j < num_parties; j++) {
    char pid[PID_LENGTH];
    ip_to_str(ips[j], pid);
    memcpy(party->pids[j], pid, PID_LENGTH);
  }

  for (int j = 0; j < num_parties; j++) {
    init_to_zero(party->commitments[j].ciphertext_kem, KYBER_CIPHERTEXTBYTES);
    init_to_zero(party->commitments[j].ciphertext_dem, DEM_LEN);
    init_to_zero(party->commitments[j].tag, AES_256_GCM_TAG_LENGTH);
    init_to_zero(party->coins[j], COMMITMENTCOINSBYTES);
    init_to_zero(party->masterkey[j], KEX_SSBYTES);
    init_to_zero(party->xs[j], KEX_SSBYTES);
  }

  init_to_zero(party->sid, KEX_SSBYTES);
  init_to_zero(party->sk, KEX_SSBYTES);
  init_to_zero(party->key_left, KEX_SSBYTES);
  init_to_zero(party->key_right, KEX_SSBYTES);

  memcpy(party->public_key, keys->public_key, CRYPTO_PUBLICKEYBYTES);
  memcpy(party->secret_key, keys->secret_key, CRYPTO_SECRETKEYBYTES);

  party->acc = 0;
  party->term = 0;
}


int main(int argc, char* argv[]) {

  if (argc != 5) {
    printf("Usage: server <private key file> <ca keys file> <parties ips file> <ip>\n");
    exit(1);
  }

  int NUM_PARTIES = count_lines(argv[3]);
  printf("IPs read: %d\n", NUM_PARTIES);

  keys_t keys;
  ca_public* data = (ca_public*) malloc(NUM_PARTIES*sizeof(ca_public));

  ip_t* ips = (ip_t*) malloc(NUM_PARTIES*sizeof(ip_t));

  read_ips(argv[3], ips);
  int index = -1;
  if ((index = get_index(ips, NUM_PARTIES, argv[4])) == -1) {
    printf("Index not found!\n");
    return 1;
  }

  printf("index: %d\n", index);

  read_keys(argv[1], &keys);
  printf("pk: ");
  print_short_key(keys.public_key, CRYPTO_PUBLICKEYBYTES, 10);
  printf("sk: ");
  print_short_key(keys.secret_key, CRYPTO_SECRETKEYBYTES, 10);

  read_ca_data(argv[2], NUM_PARTIES, data);

  printf("Reading CA data...\n");
  printf("---------------------------------------------------\n");
  for (int i = 0; i < NUM_PARTIES; i++) {
    char ip_str[17];
    ip_to_str(data[i].ip, ip_str);
    printf("ip: %s\n", ip_str);
    printf("pk: ");
    print_short_key(data[i].public_key, CRYPTO_PUBLICKEYBYTES, 10);
    printf("---------------------------------------------------\n");
  }

  Party party;

  init_party(&party, NUM_PARTIES, ips, &keys);
  print_party(&party, 0, NUM_PARTIES, 10);

  int left = mod(index - 1, NUM_PARTIES);
  int right = mod(index + 1, NUM_PARTIES);
  printf("left: %s\n", (char*) party.pids[left]);
  printf("right: %s\n", (char*) party.pids[right]);

  char ip_str[17];
  unsigned char pka[CRYPTO_PUBLICKEYBYTES];
  get_pk((char*) party.pids[left], pka, data, NUM_PARTIES);

  printf("pk (c): ");
  print_short_key(pka, CRYPTO_PUBLICKEYBYTES, 10);

  start_server(party.public_key, party.secret_key, pka, party.key_left);
  free(ips);
  free(data);
  return 0;
}
