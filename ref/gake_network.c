#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

#include "gake_network.h"
#include "common.h"
#include "emoji.h"
#include "utils.h"
#include "gake.h"


void compute_masterkey_i(Party* party, int num_parties, int index) {

  memcpy(party->masterkey[index],
         party->key_left, KEX_SSBYTES);

  for (int j = 1; j < num_parties; j++) {
    MasterKey mk;
    memcpy(mk, party->key_left, KEX_SSBYTES);
    for (int k = 0; k < j; k++) {
      xor_keys(mk, party->xs[mod(index-k-1,num_parties)], mk);
    }

    memcpy(party->masterkey[mod(index-j, num_parties)],
           mk, KEX_SSBYTES);

  }
}

void compute_xs_commitment(Party* party, int index) {
  X xi;
  Coins ri;
  Commitment ci;

  unsigned char msg[KEX_SSBYTES + sizeof(int)];
  init_to_zero(msg, KEX_SSBYTES + sizeof(int));
  char buf_int[sizeof(int)];
  init_to_zero((unsigned char*) buf_int, KEX_SSBYTES + sizeof(int));
  itoa(index, buf_int);

  xor_keys(party->key_right, party->key_left, xi);
  randombytes(ri, COMMITMENTCOINSBYTES);

  memcpy(msg, &xi, KEX_SSBYTES);
  memcpy(msg + KEX_SSBYTES, &buf_int, sizeof(int));
  commit(party->public_key, msg, DEM_LEN, ri, &ci);

  memcpy(party->xs[index], &xi, KEX_SSBYTES);
  memcpy(party->coins[index], &ri, COMMITMENTCOINSBYTES);
  party->commitments[index] = ci;
}

void compute_sk_sid_i(Party* party, int num_parties) {

  unsigned char mki[(KEX_SSBYTES + PID_LENGTH*sizeof(char))*num_parties];

  // Concat master key
  concat_masterkey(party->masterkey, party->pids, num_parties, mki);

  unsigned char sk_sid[2*KEX_SSBYTES];

  hash_g(sk_sid, mki, 2*KEX_SSBYTES);

  memcpy(party->sk, sk_sid, KEX_SSBYTES);
  memcpy(party->sid, sk_sid + KEX_SSBYTES, KEX_SSBYTES);

  party->acc = 1;
  party->term = 1;
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
    // sprintf(pid, "%s", pid);
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

void set_m1(Party* party, int index, uint8_t* message) {
  // U_i || C_i
  memcpy(message, party->pids[index], PID_LENGTH);
  memcpy(message + PID_LENGTH, &party->commitments[index], COMMITMENT_LENGTH);
}

void set_m2(Party* party, int index, uint8_t* message) {
  // U_i || X_i || r_i
  memcpy(message, party->pids[index], PID_LENGTH);
  memcpy(message + PID_LENGTH, party->xs[index], KEX_SSBYTES);
  memcpy(message + PID_LENGTH + KEX_SSBYTES, party->coins[index], COMMITMENTCOINSBYTES);
}

int check_m1_received(Party* party, int num_parties) {
  for (int i = 0; i < num_parties; i++) {
    if(is_zero_commitment(&party->commitments[i]) != 0){
      return 1;
    }
  }
  return 0;
}

int is_zero_xs_coins(X* xs, Coins* coins) {
  unsigned char zero[COMMITMENTCOINSBYTES];
  init_to_zero(zero, COMMITMENTCOINSBYTES);

  if(memcmp(xs, zero, KEX_SSBYTES) != 0 ||
     memcmp(coins, zero, COMMITMENTCOINSBYTES) != 0) {
       return 1;
  }
  return 0;
}

int check_m2_received(Party* party, int num_parties) {
  for (int i = 0; i < num_parties; i++) {
    if(is_zero_xs_coins(&party->xs[i], &party->coins[i])){
      return 1;
    }
  }
  return 0;
}

int check_xs_i(Party* party, int num_parties) {
  unsigned char zero[KEX_SSBYTES];

  for(int j = 0; j < KEX_SSBYTES; j++){
    zero[j] = 0;
  }

  X check;
  memcpy(check, party->xs[0], KEX_SSBYTES);
  for (int j = 0; j < num_parties - 1; j++) {
    xor_keys(party->xs[j+1], check, check);
  }

  int res = memcmp(check, zero, KEX_SSBYTES);
  if (res != 0) {
    return 1;
  }
  return 0;
}

int check_commitments_i(Party* party, int num_parties, ca_public* data, int ca_length) {
  for (int j = 0; j < num_parties; j++) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    get_pk((char*) party->pids[j], pk, data, ca_length);
    unsigned char msg[KEX_SSBYTES + sizeof(int)];
    char buf_int[sizeof(int)];
    init_to_zero((unsigned char*) buf_int, sizeof(int));
    itoa(j, buf_int);
    memcpy(msg, party->xs[j], KEX_SSBYTES);
    memcpy(msg + KEX_SSBYTES, buf_int, sizeof(int));

    int res_check = check_commitment(pk,
                     msg,
                     party->coins[j],
                     &party->commitments[j]);

    if (res_check != 0) {
      return 1;
    }
  }
  return 0;
}

void read_n_bytes(int socket, int x, unsigned char* buffer) {
  int bytesRead = 0;
  int result;
  while (bytesRead < x) {
    result = read(socket, buffer + bytesRead, x - bytesRead);
    if (result < 1) {
      printf("Error!\n");
    }
    bytesRead += result;
  }
}

void free_party(Party* party, int num_parties) {
  for (int j = 0; j < num_parties; j++) {
    init_to_zero(party->commitments[j].ciphertext_kem, KYBER_CIPHERTEXTBYTES);
    init_to_zero(party->commitments[j].ciphertext_dem, DEM_LEN);
    init_to_zero(party->commitments[j].tag, AES_256_GCM_TAG_LENGTH);
    init_to_zero(party->coins[j], COMMITMENTCOINSBYTES);
    init_to_zero(party->masterkey[j], KEX_SSBYTES);
    init_to_zero(party->xs[j], KEX_SSBYTES);
    init_to_zero((unsigned char*) party->pids[j], PID_LENGTH);
  }
  init_to_zero(party->sid, KEX_SSBYTES);
  init_to_zero(party->sk, KEX_SSBYTES);
  init_to_zero(party->key_left, KEX_SSBYTES);
  init_to_zero(party->key_right, KEX_SSBYTES);
  init_to_zero(party->public_key, CRYPTO_PUBLICKEYBYTES);
  init_to_zero(party->secret_key, CRYPTO_SECRETKEYBYTES);
  party->term = 0;
  party->acc = 0;

  free(party->commitments);
  free(party->masterkey);
  free(party->pids);
  free(party->coins);
  free(party->xs);
}

int main(int argc, char* argv[]) {

  if (argc != 5) {
    printf("Usage: server <private key file> <ca keys file> <parties ips file> <ip>\n");
    exit(1);
  }

  if(!file_exists(argv[1])) {
    printf("File %s does not exist!\n", argv[1]);
    exit(1);
  }

  if(!file_exists(argv[2])) {
    printf("File %s does not exist!\n", argv[2]);
    exit(1);
  }

  if(!file_exists(argv[3])) {
    printf("File %s does not exist!\n", argv[3]);
    exit(1);
  }

  int NUM_PARTIES = count_lines(argv[3]);

  keys_t keys;

  ip_t* ips = (ip_t*) malloc(NUM_PARTIES*sizeof(ip_t));

  read_ips(argv[3], ips);
  int index = -1;
  if ((index = get_index(ips, NUM_PARTIES, argv[4])) == -1) {
    printf("Index not found!\n");
    return 1;
  }

  read_keys(argv[1], &keys);

  int ca_length = get_ca_length(argv[2]);
  ca_public* data = (ca_public*) malloc(ca_length * sizeof(ca_public));
  read_ca_data(argv[2], &ca_length, data);

  for (int i = 0; i < ca_length; i++) {
    print_short_key(data[i].public_key, CRYPTO_PUBLICKEYBYTES, 10);
  }

  Party party;

  init_party(&party, NUM_PARTIES, ips, &keys);

  int left = mod(index - 1, NUM_PARTIES);
  int right = mod(index + 1, NUM_PARTIES);

  unsigned char pk_left[CRYPTO_PUBLICKEYBYTES];
  unsigned char pk_right[CRYPTO_PUBLICKEYBYTES];
  get_pk((char*) party.pids[left], pk_left, data, ca_length);
  get_pk((char*) party.pids[right], pk_right, data, ca_length);

  int pi_d, pid;
  int fd1[2], fd2[2];

  if(pipe(fd1)){};
  if(pipe(fd2)){};

  // Round 1-2
  printf("Round 1-2\n");
  pi_d = fork();
  if(pi_d == 0){

    struct sockaddr_in serveraddress, client;
    socklen_t length;
    int connection, bind_status, connection_status;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == -1){
      printf("\tSocket creation failed!\n");
      exit(1);
    } else {
      printf("\tSocket fd: %d\n", fd);
    }

    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
      printf("\tsetsockopt(SO_REUSEADDR) failed!\n");
      exit(1);
    }

    bzero(&serveraddress, sizeof(serveraddress));
    serveraddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddress.sin_port = htons(PORT);
    serveraddress.sin_family = AF_INET;

    bind_status = bind(fd, (SA*)&serveraddress, sizeof(serveraddress));

    if(bind_status == -1){
      printf("\tSocket binding failed.!\n");
      exit(1);
    }

    connection_status = listen(fd, 5);

    if(connection_status == -1) {
      printf("\tSocket is unable to listen for new connections!\n");
      exit(1);
    } else {
      printf("\tServer is listening for new connection: \n");
    }

    length = sizeof(client);
    connection = accept(fd, (SA*)&client, &length);

    if(connection == -1){
      printf("\tServer is unable to accept the data from client!\n");
      exit(1);
    }

    unsigned char ake_sendb[KEX_AKE_SENDBBYTES];
    unsigned char ake_senda[KEX_AKE_SENDABYTES];

    int bytes = 0;

    read_n_bytes(connection, KEX_AKE_SENDABYTES, ake_senda);

    kex_ake_sharedB(ake_sendb, party.key_left, ake_senda, party.secret_key, pk_left);

    // Send second message
    bytes = write(connection, ake_sendb, sizeof(ake_sendb));
    if(bytes == KEX_AKE_SENDBBYTES){
      printf("\tData sent successfully!\n");
    }

    if(write(fd1[1], party.key_left, sizeof(party.key_left))){};
    close(fd1[1]);
    close(connection);
    exit(0);
  }

  if(pi_d > 0){
    pid = fork();
    if(pid > 0){
      close(fd1[1]);
      close(fd2[1]);
      if(read(fd1[0], party.key_left, sizeof(party.key_left))){};

      if(read(fd2[0], party.key_right, sizeof(party.key_right))){};

      close(fd1[0]);
      close(fd2[0]);
    }
    else if(pid == 0){
      struct sockaddr_in serveraddress;

      int fd = socket(AF_INET, SOCK_STREAM, 0);
      if(fd == -1){
        printf("\tCreation of socket failed.!\n");
        exit(1);
      }

      bzero(&serveraddress, sizeof(serveraddress));
      serveraddress.sin_addr.s_addr = inet_addr((char*) party.pids[right]);
      serveraddress.sin_port = htons(PORT);
      serveraddress.sin_family = AF_INET;

      int connection;
      do {
        connection = connect(fd, (SA*)&serveraddress, sizeof(serveraddress));

        if(connection == -1){
          printf("\tWaiting for the server %s to be ready...\n", (char*) party.pids[right]);
          sleep(3);
        }
      } while(connection == -1);

      unsigned char eska[CRYPTO_SECRETKEYBYTES];
      unsigned char ake_senda[KEX_AKE_SENDABYTES];
      unsigned char ake_sendb[KEX_AKE_SENDBBYTES];
      unsigned char tk[KEX_SSBYTES];

      kex_ake_initA(ake_senda, tk, eska, pk_right);

      ssize_t bytes = 0;

      bytes = write(fd, ake_senda, sizeof(ake_senda));

      if(bytes == KEX_AKE_SENDABYTES){
        printf("\tData sent successfully!\n");
      }
      read_n_bytes(fd, KEX_AKE_SENDBBYTES, ake_sendb);

      kex_ake_sharedA(party.key_right, ake_sendb, tk, eska, party.secret_key);

      if(write(fd2[1], &party.key_right, sizeof(party.key_right))){};
      close(fd2[1]);
      exit(0);
    }
  }

  pid_t wpid;
  int status = 0;
  while ((wpid = wait(&status)) > 0); // Wait to finish child processes

  print_party(&party, 0, NUM_PARTIES, 10);

  // Round 3
  printf("Round 3\n");
  compute_xs_commitment(&party, index);
  print_party(&party, 0, NUM_PARTIES, 10);

  unsigned char m1[PID_LENGTH + COMMITMENT_LENGTH];
  set_m1(&party, index, m1);

  int pid_3, pid2_3;
  int fd_3[2];

  if(pipe(fd_3)){};

  pid_3 = fork();
  if (pid_3 == 0) {
    for (int i = 0; i < NUM_PARTIES; i++) {
      if(i != index) {
        struct sockaddr_in serveraddress;

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if(fd == -1){
          printf("\tCreation of socket failed!\n");
          exit(1);
        }

        bzero(&serveraddress, sizeof(serveraddress));
        serveraddress.sin_addr.s_addr = inet_addr((char*) party.pids[i]);
        serveraddress.sin_port = htons(PORT);
        serveraddress.sin_family = AF_INET;

        int connection;
        do {
          connection = connect(fd, (SA*)&serveraddress, sizeof(serveraddress));

          if(connection == -1){
            printf("\tWaiting for the server %s to be ready...\n", (char*) party.pids[i]);
            sleep(3);
          }
        } while(connection == -1);

        ssize_t bytes = write(fd, m1, sizeof(m1));

        if(bytes > 0){
          printf("\tSent %ld bytes to %s!\n", bytes, (char*) party.pids[i]);
        }
      }
    }
    exit(0);
  }

  if (pid_3 > 0) {
    pid2_3 = fork();
    if(pid2_3 > 0) {
      for (int i = 0; i < NUM_PARTIES - 1; i++) {
        close(fd_3[1]);
        unsigned char m1_i[PID_LENGTH + COMMITMENT_LENGTH];
        char u_i[PID_LENGTH];
        if(read(fd_3[0], m1_i, PID_LENGTH + COMMITMENT_LENGTH)){};
        memcpy(u_i, m1_i, PID_LENGTH);
        int ind2 = get_index(ips, NUM_PARTIES, u_i);
        Commitment ci;
        copy_commitment(m1_i + PID_LENGTH, &ci);
        party.commitments[ind2] = ci;
      }
    } else if(pid2_3 == 0) {
      int fd = socket(AF_INET, SOCK_STREAM, 0);
      if(fd == -1){
        printf("\tSocket creation failed!\n");
        exit(1);
      } else {
        printf("\tSocket fd: %d\n", fd);
      }

      int enable = 1;
      if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
        printf("\tsetsockopt(SO_REUSEADDR) failed!\n");
        exit(1);
      }
      struct sockaddr_in serveraddress, client;

      bzero(&serveraddress, sizeof(serveraddress));
      serveraddress.sin_addr.s_addr = htonl(INADDR_ANY);
      serveraddress.sin_port = htons(PORT);
      serveraddress.sin_family = AF_INET;

      int bind_status = bind(fd, (SA*)&serveraddress, sizeof(serveraddress));

      if(bind_status == -1){
        printf("\tSocket binding failed.!\n");
        exit(1);
      }

      int connection_status = listen(fd, 5);

      if(connection_status == -1) {
        printf("\tSocket is unable to listen for new connections!\n");
        exit(1);
      } else {
        printf("\tServer is listening for new connection: \n");
      }

      int count = 0;
      while(check_m1_received(&party, NUM_PARTIES) != 0) {

        socklen_t length = sizeof(client);
        int new = accept(fd, (SA*)&client, &length);

        if(new == -1){
          printf("\tServer is unable to accept the data from client!\n");
          exit(1);
        }
        printf("\tConnection from %s.\n", inet_ntoa(client.sin_addr));

        unsigned char m1_i[PID_LENGTH + COMMITMENT_LENGTH];
        read_n_bytes(new, PID_LENGTH + COMMITMENT_LENGTH, m1_i);

        char u_i[PID_LENGTH];
        bzero(u_i, PID_LENGTH);
        memcpy(u_i, m1_i, PID_LENGTH);
        if(write(fd_3[1], m1_i, sizeof(m1_i))){};
        bzero(m1_i, PID_LENGTH + COMMITMENT_LENGTH);
        count++;
        if(count == NUM_PARTIES - 1){
          exit(0);
        }
      }
      exit(0);
    }
  }

  int status2, wpid2;
  while ((wpid2 = wait(&status2)) > 0); // Wait to finish child processes

  print_party(&party, 0, NUM_PARTIES, 10);

  // Round 4
  printf("Round 4\n");

  unsigned char m2[PID_LENGTH + KEX_SSBYTES + COMMITMENTCOINSBYTES];
  set_m2(&party, index, m2);

  int pid_4, pid2_4;
  int fd_4[2];

  if(pipe(fd_4)){};

  pid_4 = fork();
  if (pid_4 == 0) {
    for (int i = 0; i < NUM_PARTIES; i++) {
      if(i != index) {
        struct sockaddr_in serveraddress;

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if(fd == -1){
          printf("\tCreation of Socket failed!\n");
          exit(1);
        }

        bzero(&serveraddress, sizeof(serveraddress));
        serveraddress.sin_addr.s_addr = inet_addr((char*) party.pids[i]);
        serveraddress.sin_port = htons(PORT);
        serveraddress.sin_family = AF_INET;

        int connection;
        do {
          connection = connect(fd, (SA*)&serveraddress, sizeof(serveraddress));

          if(connection == -1){
            printf("\tWaiting for the server %s to be ready...\n", (char*) party.pids[i]);
            sleep(3);
          }
        } while(connection == -1);

        ssize_t bytes = write(fd, m2, sizeof(m2));

        if(bytes > 0){
          printf("\tSent %ld bytes to %s!\n", bytes, (char*) party.pids[i]);
        }
      }
    }
    exit(0);
  }

  if (pid_4 > 0) {
    pid2_4 = fork();
    if(pid2_4 > 0) {
      for (int i = 0; i < NUM_PARTIES - 1; i++) {
        close(fd_4[1]);
        unsigned char m2_i[PID_LENGTH + KEX_SSBYTES + COMMITMENTCOINSBYTES];
        char u_i[PID_LENGTH];
        if(read(fd_4[0], m2_i, PID_LENGTH + KEX_SSBYTES + COMMITMENTCOINSBYTES)){};
        memcpy(u_i, m2_i, PID_LENGTH);
        int ind = get_index(ips, NUM_PARTIES, u_i);
        memcpy(party.xs[ind], m2_i + PID_LENGTH, KEX_SSBYTES);
        memcpy(party.coins[ind], m2_i + PID_LENGTH + KEX_SSBYTES, COMMITMENTCOINSBYTES);
      }
    } else if(pid2_4 == 0) {
      int fd = socket(AF_INET, SOCK_STREAM, 0);
      if(fd == -1){
        printf("\tSocket creation failed!\n");
        exit(1);
      } else {
        printf("\tSocket fd: %d\n", fd);
      }

      int enable = 1;
      if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
        printf("\tsetsockopt(SO_REUSEADDR) failed!\n");
        exit(1);
      }
      struct sockaddr_in serveraddress, client;

      bzero(&serveraddress, sizeof(serveraddress));
      serveraddress.sin_addr.s_addr = htonl(INADDR_ANY);
      serveraddress.sin_port = htons(PORT);
      serveraddress.sin_family = AF_INET;

      int bind_status = bind(fd, (SA*)&serveraddress, sizeof(serveraddress));

      if(bind_status == -1){
        printf("\tSocket binding failed.!\n");
        exit(1);
      }

      int connection_status = listen(fd, 5);

      if(connection_status == -1) {
        printf("\tSocket is unable to listen for new connections!\n");
        exit(1);
      } else {
        printf("\tServer is listening for new connection: \n");
      }

      int count2 = 0;
      while(check_m2_received(&party, NUM_PARTIES) != 0) {

        socklen_t length = sizeof(client);
        int new = accept(fd, (SA*)&client, &length);

        if(new == -1){
          printf("\tServer is unable to accept the data from client!\n");
          exit(1);
        }
        printf("\tConnection from %s.\n", inet_ntoa(client.sin_addr));

        unsigned char m2_i[PID_LENGTH + KEX_SSBYTES + COMMITMENTCOINSBYTES];
        if(read(new, m2_i, sizeof(m2_i))){};

        char u_i[PID_LENGTH];
        bzero(u_i, PID_LENGTH);
        memcpy(u_i, m2_i, PID_LENGTH);
        if(write(fd_4[1], m2_i, sizeof(m2_i))){};
        bzero(m2_i, PID_LENGTH + KEX_SSBYTES + COMMITMENTCOINSBYTES);
        count2++;
        if(count2 == NUM_PARTIES - 1){
          exit(0);
        }
      }
      exit(0);
    }
  }

  int status3, wpid3;
  while ((wpid3 = wait(&status3)) > 0); // Wait to finish child processes

  int res = check_xs_i(&party, NUM_PARTIES); // Check Xi
  int result = check_commitments_i(&party, NUM_PARTIES, data, ca_length); // Check commitments

  if (res == 0) {
    printf("\tXi are zero!\n");
  } else {
    printf("\tXi are not zero!\n");
    party.acc = 0;
    party.term = 1;
    return 1;
  }

  if (result == 0) {
    printf("\tCommitments are correct!\n");
  } else {
    printf("\tCommitments are not correct!\n");
    party.acc = 0;
    party.term = 1;
    return 1;
  }

  compute_masterkey_i(&party, NUM_PARTIES, index);
  compute_sk_sid_i(&party, NUM_PARTIES);
  print_party(&party, 0, NUM_PARTIES, 10);

  char* emojified_key[4];

  printf("\n\nsk: ");
  emojify(party.sk, emojified_key);
  print_emojified_key(emojified_key);

  free(ips);
  free_party(&party, NUM_PARTIES);
  printf("Removed secrets from memory!\n");
  return 0;
}
