#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/times.h>

#include "gake_network.h"
#include "common.h"
#include "emoji.h"
#include "utils.h"
#include "gake.h"

#define MAXMSG 4096

pthread_mutex_t lock;

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
      // printf("Read error!\n");
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

void initSocketAddress(struct sockaddr_in *serveraddress,
                       char *ip,
                       unsigned short int port){

  // bzero(serveraddress, sizeof(serveraddress));
  serveraddress->sin_addr.s_addr = inet_addr((char*) ip);
  serveraddress->sin_port = htons(port);
  serveraddress->sin_family = AF_INET;
}

void* sendMessage(void* params) {
  client_info* client_inf = (client_info*) params;
  int sockfd = client_inf->socket;

  printf("[sendMessage] Sending '%s' to socket %d\n", client_inf->message, sockfd);
  int nOfBytes = 0;

  do {
    nOfBytes = write(sockfd, client_inf->message, client_inf->size);
    perror("[sendMessage] Unable to write data!\n");
  } while(nOfBytes < 0);

  printf("[sendMessage] Sent %d bytes to socket %d!\n", nOfBytes, sockfd);

  return NULL;
}

void broadcast(int* sock, int n, unsigned char* message, int msg_length, int index) {
  pthread_t t_id[n];
  printf("[broadcast] Creating threads...\n");
  for (int i = 0; i < n; i++) {
    if(i != index) {
      struct client_info* client_inf = malloc(sizeof(struct client_info));
      client_inf->message = malloc(msg_length);
      client_inf->size = msg_length;
      client_inf->socket = sock[i];
      memcpy(client_inf->message, message, msg_length);
      printf("[broadcast] message: ");
      print_short_key(message, msg_length, 10);
      printf("[broadcast] client_inf->message: ");
      print_short_key(client_inf->message, msg_length, 10);
      int read;
      do {
        read = pthread_create(&t_id[i], NULL, sendMessage, (void *) client_inf);
        printf("[broadcast] Thread %d created successfully!\n", i);
      } while(read < 0);

      fflush(stdout);
    }
  }

  for (int i = 0; i < n; i++) {
    pthread_join(t_id[i], NULL);
  }

}

int create_client(char* ip, int port) {
  struct sockaddr_in servername;

  printf("[create_client] Create_client\n");

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  printf("[create_client] sock: %d\n", sock);
  if(sock < 0) {
    perror("[create_client] Could not create a socket\n");
  }

  bzero(&servername, sizeof(servername));
  initSocketAddress(&servername, ip, port);

  int connection;
  do {
    printf("Connecting to server %s \n", (char*) ip);
    connection = connect(sock, (SA *) &servername, sizeof(servername));
    printf("connection: %d\n", connection);
    if(connection == -1){
      printf("\tWaiting for the server %s to be ready...\n", (char*) ip);
      usleep(500000);
    } else {
      printf("Connected to server %s \n", (char*) ip);
    }
  } while(connection == -1);
  fflush(stdout);
  return sock;
}

void run_client(Pid* pids, int port, int n, unsigned char* message, int msg_length, int index) {
  printf("[run_client] Init client...\n");
  int sock[n];
  for (int i = 0; i < n; i++) {
    if(i != index){
      printf("[run_client] Creating client %s\n", (char*) pids[i]);
      sock[i] = create_client((char*) pids[i], port);
      printf("[run_client] Created client\n");
    }
  }
  broadcast(sock, n, (void*) message, msg_length, index);
  printf("[run_client] Acaba broadcast\n");
  fflush(stdout);
}

int read_from_client(int filedes) {
  char buffer[MAXMSG];
  int nbytes;

  nbytes = read(filedes, buffer, MAXMSG);
  if (nbytes < 0) {
    perror ("read");
    exit (EXIT_FAILURE);
  } else if (nbytes == 0){
    return -1;
  } else {
    fprintf (stderr, "Server: got message: `%s'\n", buffer);
    return 0;
  }
}

void* server_connection_handler(void *socket_desc) {
  int sock = *(int*)socket_desc;
  int msg_length = *((int*)(socket_desc) + 1);
  int read_size;
  // char client_message[MAXMSG];

  printf("msg_length: %d\n", msg_length);
  struct server_info *info = malloc(sizeof(struct server_info));
  info->message = malloc(msg_length);
  bzero(info->message, msg_length);
  info->size = MAXMSG;
  unsigned char client_message[msg_length];

  // read_n_bytes(sock, msg_length, info->message);

  while((read_size = recv(sock, client_message, msg_length, 0)) > 0) {
    printf("Client[%d]: %s\n", sock, info->message);
  }
  memcpy(info->message, client_message, msg_length);
  // printf("read_size: %d\n", read_size);
  // printf("[thread] info->message: ");
  // print_short_key(info->message, 1640, 10);

  if(read_size == 0) {
    printf("Client[%d] disconnected\n", sock);
    fflush(stdout);
  } else if(read_size == -1) {
    perror("recv failed");
  }

  free(socket_desc);
  pthread_exit(info);
}

int make_server_socket(unsigned short int port) {
    int sock;
    struct sockaddr_in name;
    /* Create a socket. */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {
      perror("Could not create a socket\n");
      exit(EXIT_FAILURE);
    }
    name.sin_family = AF_INET;
    name.sin_port = htons(port);
    name.sin_addr.s_addr = htonl(INADDR_ANY);

    int enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
      printf("\tsetsockopt(SO_REUSEADDR) failed!\n");
      exit(1);
    }

    if(bind(sock, (SA *)&name, sizeof(name)) < 0) {
      perror("Could not bind a name to the socket\n");
      exit(EXIT_FAILURE);
    }
    return(sock);
}

int run_server(int port, unsigned char* msgs, int num_parties, int msg_length) {
  int sock;
  int clientSocket;
  int i;
  int *new_sock;
  fd_set activeFdSet, readFdSet;
  struct sockaddr_in clientName;
  socklen_t size;
  void* thread_result[num_parties - 1];
  printf("int %d\n", msg_length);

  printf("num_parties: %d\n", num_parties);

  sock = make_server_socket(port);
  if(listen(sock, num_parties) < 0) {
      perror("Could not listen for connections\n");
      exit(EXIT_FAILURE);
  }
  FD_ZERO(&activeFdSet);
  FD_SET(sock, &activeFdSet);
  int count = 0;
  printf("Waiting for connections\n");
  readFdSet = activeFdSet;
  if(select(FD_SETSIZE, &readFdSet, NULL, NULL, NULL) < 0) {
    perror("Select failed\n");
    exit(EXIT_FAILURE);
  }

  for(i = 0; i < FD_SETSIZE; i++) {
    if(FD_ISSET(i, &readFdSet)) {
      if(i == sock) {
        size = sizeof(struct sockaddr_in);
        pthread_t sniffer_thread;
        while((clientSocket = accept(sock, (struct sockaddr *)&clientName, (socklen_t *)&size))) {
          printf("Connection accepted\n");
          new_sock = malloc(2);
          *new_sock = clientSocket;
          *(new_sock + 1) = msg_length;
          if(pthread_create(&sniffer_thread, NULL, server_connection_handler, (void*) new_sock) < 0) {
            perror("could not create thread");
            return 1;
          }

          // void* thread_result[num_parties - 1];
          pthread_join(sniffer_thread, &thread_result[count]);
          puts("Handler assigned");
          FD_SET(*new_sock, &activeFdSet);

          count += 1;
          if(count == num_parties - 1){
            break;
          }

        }
        if(clientSocket < 0) {
           perror("Could not accept connection\n");
           exit(EXIT_FAILURE);
        }

      } else {
        if (read_from_client(i) < 0) {
          close(i);
          FD_CLR(i, &activeFdSet);
        }
      }
    }
  }

  for (int j = 0; j < num_parties - 1; j++) {
    struct server_info* message = thread_result[j];
    memcpy(msgs + j*msg_length, message->message, msg_length);
    free(message->message);
    free(message);
  }
  return 0;
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

  clock_t begin_total = times(NULL);

  Party party;

  init_party(&party, NUM_PARTIES, ips, &keys);

  int left = mod(index - 1, NUM_PARTIES);
  int right = mod(index + 1, NUM_PARTIES);

  unsigned char pk_left[CRYPTO_PUBLICKEYBYTES];
  unsigned char pk_right[CRYPTO_PUBLICKEYBYTES];
  get_pk((char*) party.pids[left], pk_left, data, ca_length);
  get_pk((char*) party.pids[right], pk_right, data, ca_length);

  clock_t end_init = times(NULL);

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
      printf("\t[Round 1-2] Socket creation failed!\n");
      exit(1);
    } else {
      printf("\t[Round 1-2] Socket fd: %d\n", fd);
    }

    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
      printf("\t[Round 1-2] setsockopt(SO_REUSEADDR) failed!\n");
      exit(1);
    }

    bzero(&serveraddress, sizeof(serveraddress));
    serveraddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddress.sin_port = htons(PORT);
    serveraddress.sin_family = AF_INET;

    bind_status = bind(fd, (SA*)&serveraddress, sizeof(serveraddress));

    if(bind_status == -1){
      printf("\t[Round 1-2] Socket binding failed.!\n");
      exit(1);
    }

    connection_status = listen(fd, NUM_PARTIES);

    if(connection_status == -1) {
      printf("\t[Round 1-2] Socket is unable to listen for new connections!\n");
      exit(1);
    } else {
      printf("\t[Round 1-2] Server is listening for new connection: \n");
    }

    length = sizeof(client);
    connection = accept(fd, (SA*)&client, &length);

    if(connection == -1){
      printf("\t[Round 1-2] Server is unable to accept the data from client!\n");
      exit(1);
    }

    unsigned char ake_sendb[KEX_AKE_SENDBBYTES];
    unsigned char ake_senda[KEX_AKE_SENDABYTES];

    int bytes = 0;

    printf("[Round 1-2] KEX_AKE_SENDABYTES\n");
    read_n_bytes(connection, KEX_AKE_SENDABYTES, ake_senda);

    kex_ake_sharedB(ake_sendb, party.key_left, ake_senda, party.secret_key, pk_left);

    // Send second message
    bytes = write(connection, ake_sendb, sizeof(ake_sendb));
    if(bytes == KEX_AKE_SENDBBYTES){
      printf("\t[Round 1-2] Data sent successfully!\n");
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
        printf("\t[Round 1-2] Creation of socket failed.!\n");
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
          printf("\t[Round 1-2] Waiting for the server %s to be ready...\n", (char*) party.pids[right]);
          usleep(500000);
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
        printf("\t[Round 1-2] Data sent successfully!\n");
      }
      printf("[Round 1-2] KEX_AKE_SENDBBYTES\n");
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

  clock_t end_12 = times(NULL);

  // print_party(&party, 0, NUM_PARTIES, 10);

  // Round 3
  printf("Round 3\n");
  compute_xs_commitment(&party, index);
  // print_party(&party, 0, NUM_PARTIES, 10);

  int m1_length = PID_LENGTH + COMMITMENT_LENGTH;
  unsigned char m1[m1_length];
  set_m1(&party, index, m1);

  int pid_3, pid2_3;
  int fd_3[2];

  if(pipe(fd_3)){};

  fflush(stdout);
  pid_3 = fork();
  if (pid_3 == 0) {
    run_client(party.pids, PORT, NUM_PARTIES, m1, m1_length, index);
    printf("Acaba ronda 3\n");
    fflush(stdout);
    exit(0);
  }

  if (pid_3 > 0) {
    pid2_3 = fork();
    if(pid2_3 > 0) {
      for (int i = 0; i < NUM_PARTIES - 1; i++) {
        close(fd_3[1]);
        unsigned char m1_i[PID_LENGTH + COMMITMENT_LENGTH];
        char u_i[PID_LENGTH];
        bzero(m1_i, PID_LENGTH + COMMITMENT_LENGTH);
        if(read(fd_3[0], m1_i, PID_LENGTH + COMMITMENT_LENGTH)){};
        memcpy(u_i, m1_i, PID_LENGTH);
        int ind2 = get_index(ips, NUM_PARTIES, u_i);
        Commitment ci;
        copy_commitment(m1_i + PID_LENGTH, &ci);
        party.commitments[ind2] = ci;
      }
    } else if(pid2_3 == 0) {

      printf("[Round 3]\n");
      unsigned char* m1_s = malloc((NUM_PARTIES-1)*m1_length);
      bzero(m1_s, (NUM_PARTIES-1)*m1_length);
      run_server(PORT, m1_s, NUM_PARTIES, m1_length);

      for (int i = 0; i < NUM_PARTIES - 1; i++) {
        if(write(fd_3[1], m1_s + i*m1_length, m1_length)){};
      }
      free(m1_s);
      exit(0);
    }
  }

  int status2, wpid2;
  while ((wpid2 = wait(&status2)) > 0); // Wait to finish child processes
  clock_t end_3 = times(NULL);
  print_party(&party, 0, NUM_PARTIES, 10);

  // Round 4
  printf("Round 4\n");

  int m2_length = PID_LENGTH + KEX_SSBYTES + COMMITMENTCOINSBYTES;
  unsigned char m2[m2_length];
  set_m2(&party, index, m2);

  printf("Llega\n");

  int pid_4, pid2_4;
  int fd_4[2];

  if(pipe(fd_4)){};

  pid_4 = fork();
  if (pid_4 == 0) {
    run_client(party.pids, PORT, NUM_PARTIES, m2, m2_length, index);
    printf("Acaba ronda 4\n");
    fflush(stdout);
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
        printf("ind: %d\n", ind);
        printf("u_i: %s\n", u_i);
        memcpy(party.xs[ind], m2_i + PID_LENGTH, KEX_SSBYTES);
        memcpy(party.coins[ind], m2_i + PID_LENGTH + KEX_SSBYTES, COMMITMENTCOINSBYTES);
      }
    } else if(pid2_4 == 0) {

      unsigned char* m2_s = malloc((NUM_PARTIES-1)*m2_length);
      bzero(m2_s, (NUM_PARTIES-1)*m2_length);
      run_server(PORT, m2_s, NUM_PARTIES, m2_length);

      for (int i = 0; i < NUM_PARTIES - 1; i++) {
        if(write(fd_4[1], m2_s + i*m2_length, m2_length)){};
      }
      free(m2_s);
      exit(0);
    }
  }

  int status3, wpid3;
  while ((wpid3 = wait(&status3)) > 0); // Wait to finish child processes

  int res = check_xs_i(&party, NUM_PARTIES); // Check Xi
  int result = check_commitments_i(&party, NUM_PARTIES, data, ca_length); // Check commitments

  if (res == 0) {
    printf("\t[Round 4] Xi are zero!\n");
  } else {
    printf("\t[Round 4] Xi are not zero!\n");
    party.acc = 0;
    party.term = 1;
    // return 1;
  }

  if (result == 0) {
    printf("\t[Round 4] Commitments are correct!\n");
  } else {
    printf("\t[Round 4] Commitments are not correct!\n");
    party.acc = 0;
    party.term = 1;
    // return 1;
  }

  compute_masterkey_i(&party, NUM_PARTIES, index);
  compute_sk_sid_i(&party, NUM_PARTIES);
  print_party(&party, 0, NUM_PARTIES, 10);

  char* emojified_key[4];

  printf("\n\nsk: ");
  emojify(party.sk, emojified_key);
  print_emojified_key(emojified_key);
  free(ips);
  printf("Removed secrets from memory!\n");
  clock_t end_4 = times(NULL);
  print_stats(end_init, end_12, end_3, end_4, begin_total);
  return 0;
}
