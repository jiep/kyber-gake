#include "gake_qrom.h"
#include "io.h"

typedef struct client_info {
  unsigned char* message;
  size_t size;
  int socket;
} client_info;

typedef struct server_info {
   unsigned char* message;
   int size;
} server_info;

void compute_masterkey_i(Party* party, int num_parties, int index);
void compute_xs_commitment(Party* party, int index);
void compute_sk_sid_i(Party* party, int num_parties);
void init_party(Party* party, int num_parties, ip_t* ips, keys_t* keys);
void set_m1(Party* party, int index, uint8_t* message);
void set_m2(Party* party, int index, uint8_t* message);
int check_m1_received(Party* party, int num_parties);
int is_zero_xs_coins(X* xs, Coins* coins);
int check_m2_received(Party* party, int num_parties);
int check_xs_i(Party* party, int num_parties);
int check_commitments_i(Party* party, int num_parties, ca_public* data, int ca_length);
void read_n_bytes(int socket, int x, unsigned char* buffer);
void free_party(Party* party, int num_parties);
void initSocketAddress(struct sockaddr_in *serveraddress, char *ip, unsigned short int port);
void* sendMessage(void * params);
void broadcast(Pid* pids, int port, int n, unsigned char* message, int msg_length, int index);
int create_client(char* ip, int port);
void run_client(Pid* pids, int port, int n, unsigned char* message, int msg_length, int index);
void* server_connection_handler(void *socket_desc);
int make_server_socket(unsigned short int port);
int run_server(int port, unsigned char* msgs, int num_parties, int msg_length);
int read_from_client(int filedes);
