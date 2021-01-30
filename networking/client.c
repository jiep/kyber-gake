#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "../ref/gake.h"
#include "io.h"
#include "common.h"

// Global Data
int socket_file_descriptor, connection;
struct sockaddr_in serveraddress, client;
char message[1024];

int main(int argc, char *argv[]){

  if (argc != 4) {
    printf("Usage: client <private key file> <ca keys file> <server ip>\n");
    exit(1);
  }

  socket_file_descriptor = socket(AF_INET, SOCK_STREAM, 0);
  if(socket_file_descriptor == -1){
    printf("Creation of Socket failed.!\n");
    exit(1);
  }

  bzero(&serveraddress, sizeof(serveraddress));
  serveraddress.sin_addr.s_addr = inet_addr(argv[3]);
  serveraddress.sin_port = htons(PORT);
  serveraddress.sin_family = AF_INET;

  connection = connect(socket_file_descriptor, (SA*)&serveraddress, sizeof(serveraddress));
  if(connection == -1){
    printf("Connection with the server failed.!\n");
    exit(1);
  }

  keys_t keys;
  ca_public* data = (ca_public*) malloc(2*sizeof(ca_public));

  unsigned char pkb[CRYPTO_PUBLICKEYBYTES];

  unsigned char eska[CRYPTO_SECRETKEYBYTES];
  unsigned char ake_senda[KEX_AKE_SENDABYTES];
  unsigned char ake_sendb[KEX_AKE_SENDBBYTES];
  unsigned char tk[KEX_SSBYTES];

  unsigned char ka[KEX_SSBYTES];

  read_keys(argv[1], &keys);
  printf("pk (c): ");
  print_short_key(keys.public_key, CRYPTO_PUBLICKEYBYTES, 10);
  printf("sk (c): ");
  print_short_key(keys.secret_key, CRYPTO_SECRETKEYBYTES, 10);

  read_ca_data(argv[2], 2, data);

  // for (int i = 0; i < 2; i++) {
  //   printf("[%d] ", i);
  //   print_short_key(data[i].public_key, CRYPTO_PUBLICKEYBYTES, 10);
  //   printf("ip: %d\n", data[i].ip[0]);
  //   printf("---------------\n");
  // }

  char ip_str[17];
  memcpy(ip_str, argv[3], 17);
  get_pk(ip_str, pkb, data, 2);

  printf("pk (s): ");
  print_short_key(pkb, CRYPTO_PUBLICKEYBYTES, 10);

  kex_ake_initA(ake_senda, tk, eska, pkb);
  printf("[C] ake_senda: ");
  print_short_key(ake_senda, KEX_AKE_SENDABYTES, 10);

  ssize_t bytes = 0;

  bytes = write(socket_file_descriptor, ake_senda, sizeof(ake_senda));

  // if(bytes >= 0){
  //   printf("Data sent successfully!\n");
  // }

  read(socket_file_descriptor, ake_sendb, sizeof(ake_sendb));
  printf("[S] ake_sendb: ");
  print_short_key(ake_sendb, KEX_AKE_SENDABYTES, 10);

  kex_ake_sharedA(ka, ake_sendb, tk, eska, keys.secret_key);
  printf("[C] key: ");
  print_key(ka, KEX_SSBYTES);

  char b = 1;

  while (1) {
    char plaintext[MESSAGE_LENGTH];
    bzero(plaintext, MESSAGE_LENGTH);

    if (b == 1) {
      printf("[C] Enter the message you want to send to the server: ");
      scanf("%[^\n]%*c", plaintext);
      if(memcmp(plaintext, "end", 3) == 0){
        printf("Closing connection...\n");
        break;
      }
    } else {
      memcpy(plaintext, TEST_MESSAGE, sizeof(TEST_MESSAGE));
      printf("[C] plaintext: %s", plaintext);
    }

    encrypt(plaintext, ka, message);

    printf("[C] encrypted: ");
    print_short_key(message, MESSAGE_LENGTH, 10);

    bytes = write(socket_file_descriptor, message, sizeof(message));

    // if(bytes >= 0){
    //   printf("Data sent successfully!\n");
    // }

    bzero(message, MESSAGE_LENGTH);
    read(socket_file_descriptor, message, sizeof(message));
    unsigned char pt[MESSAGE_LENGTH];
    decrypt(message, ka, pt);

    if(b == 1) {
      if (memcmp(pt, TEST_MESSAGE, sizeof(TEST_MESSAGE)) == 0) {
        b = 1;
      }
    }

    printf("[C] pt: %s\n", pt);
    bzero(pt, MESSAGE_LENGTH);
  }

  free(data);
  close(socket_file_descriptor);
  return 0;
}
