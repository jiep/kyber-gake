#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netdb.h>
#include<netinet/in.h>

#include "../ref/gake.h"
#include "io.h"

#define MESSAGE_LENGTH 1024 // Maximum number of data that can transfer
#define PORT 8888 // port number to connect
#define SA struct sockaddr
#define TEST_MESSAGE "hello"

struct sockaddr_in serveraddress, client;
socklen_t length;
int sockert_file_descriptor, connection, bind_status, connection_status;
char message[MESSAGE_LENGTH];

int main(){

  sockert_file_descriptor = socket(AF_INET, SOCK_STREAM, 0);
  if(sockert_file_descriptor == -1){
    printf("Socket creation failed.!\n");
    exit(1);
  } else {
    printf("Socket fd: %d\n", sockert_file_descriptor);
  }

  bzero(&serveraddress, sizeof(serveraddress));
  serveraddress.sin_addr.s_addr = htonl(INADDR_ANY);
  serveraddress.sin_port = htons(PORT);
  serveraddress.sin_family = AF_INET;

  bind_status = bind(sockert_file_descriptor, (SA*)&serveraddress, sizeof(serveraddress));

  if(bind_status == -1){
    printf("Socket binding failed.!\n");
    exit(1);
  }

  connection_status = listen(sockert_file_descriptor, 5);

  if(connection_status == -1) {
    printf("Socket is unable to listen for new connections.!\n");
    exit(1);
  } else {
    printf("Server is listening for new connection: \n");
  }

  length = sizeof(client);
  connection = accept(sockert_file_descriptor, (SA*)&client, &length);

  if(connection == -1){
    printf("Server is unable to accept the data from client.!\n");
    exit(1);
  }

  keys_t keys;
  ca_public* data = (ca_public*) malloc(2*sizeof(ca_public));

  unsigned char pka[CRYPTO_PUBLICKEYBYTES];
  unsigned char ake_sendb[KEX_AKE_SENDBBYTES];
  unsigned char ake_senda[KEX_AKE_SENDABYTES];
  unsigned char kb[KEX_SSBYTES];

  read_keys("10.0.2.15.bin", &keys);
  // printf("pk (c): ");
  // print_short_key(keys.public_key, CRYPTO_PUBLICKEYBYTES, 10);
  // printf("sk (c): ");
  // print_short_key(keys.secret_key, CRYPTO_SECRETKEYBYTES, 10);

  read_ca_data("ca.bin", 2, data);

  // for (int i = 0; i < 2; i++) {
  //   printf("[%d] ", i);
  //   print_short_key(data[i].public_key, CRYPTO_PUBLICKEYBYTES, 10);
  // }

  char ip_str[17] = "192.168.68.111";
  get_pk(ip_str, pka, data, 2);

  // printf("pk (c): ");
  // print_short_key(pka, CRYPTO_PUBLICKEYBYTES, 10);

  bzero(ake_senda, sizeof(ake_senda));
  int bytes = 0;

  read(connection, ake_senda, sizeof(ake_senda));
  printf("[C] ake_senda: ");
  print_short_key(ake_senda, KEX_AKE_SENDABYTES, 10);

  kex_ake_sharedB(ake_sendb, kb, ake_senda, keys.secret_key, pka);
  printf("[S] ake_sendb: ");
  print_short_key(ake_sendb, KEX_AKE_SENDABYTES, 10);

  // Send second message
  bytes = write(connection, ake_sendb, sizeof(ake_sendb));
  // if(bytes >= 0){
  //   printf("Data sent successfully!\n");
  // }

  printf("[S] key: ");
  print_key(kb, KEX_SSBYTES);

  char b = 1;

  while (1) {
    read(connection, message, sizeof(message));

    printf("[S] encrypted: ");
    print_short_key(message, sizeof(message), 10);

    unsigned char pt[MESSAGE_LENGTH];

    decrypt(message, kb, pt);

    printf("[C] pt: %s\n", pt);

    if(b == 1) {
      if (memcmp(pt, TEST_MESSAGE, sizeof(TEST_MESSAGE)) == 0) {
        b = 1;
      }
    }

    char plaintext[MESSAGE_LENGTH];

    bzero(message, MESSAGE_LENGTH);

    if (b == 1) {
      read(0, plaintext, MESSAGE_LENGTH);
    } else {
      memcpy(plaintext, TEST_MESSAGE, sizeof(TEST_MESSAGE));
    }

    encrypt(plaintext, kb, message);

    bytes = write(connection, message, sizeof(message));

    // if(bytes >= 0){
    //   printf("Data sent successfully!\n");
    // }

    printf("[C]: %s\n", plaintext);
  }

  free(data);
  close(sockert_file_descriptor);
  return 0;
}
