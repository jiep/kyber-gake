#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "api.h"
#include "kex.h"
#include "indcpa.h"
#include "randombytes.h"
#include "symmetric.h"
#include "gake.h"

int main(int argc, char** argv){

  if(argc != 2){
    printf("You must provide the number of parties!\n");
    return 1;
  }

  int NUM_PARTIES = atoi(argv[1]);
  int SHOW = 10;

  Party *pointer_to_parties;

  pointer_to_parties = (Party*) malloc(sizeof(Party) * NUM_PARTIES);

  init_parties(pointer_to_parties, NUM_PARTIES);
  // print_parties(pointer_to_parties, NUM_PARTIES, SHOW);

  // Round 1-2
  printf("Round 1-2\n");
  compute_left_right_keys(pointer_to_parties, NUM_PARTIES);
  // print_parties(pointer_to_parties, NUM_PARTIES, SHOW);

  // Round 3
  printf("Round 3\n");
  compute_xs_commitments(pointer_to_parties, NUM_PARTIES);
  // print_parties(pointer_to_parties, NUM_PARTIES, SHOW);

  // Round 4
  printf("Round 4\n");
  for (int i = 0; i < NUM_PARTIES; i++) {
    printf("\tParty %d\n", i);

    int res = check_xs(pointer_to_parties, i, NUM_PARTIES); // Check Xi
    int result = check_commitments(pointer_to_parties, i, NUM_PARTIES); // Check commitments

    if (res == 0) {
      printf("\t\tXi are zero!\n");
    } else {
      printf("\t\tXi are not zero!\n");
      pointer_to_parties[i].acc = 0;
      pointer_to_parties[i].term = 1;
      return 1;
    }

    if (result == 0) {
      printf("\t\tCommitments are correct!\n");
    } else {
      printf("\t\tCommitments are not correct!\n");
      pointer_to_parties[i].acc = 0;
      pointer_to_parties[i].term = 1;
      return 1;
    }
  }

  // Master Key
  compute_masterkey(pointer_to_parties, NUM_PARTIES);
  // print_parties(pointer_to_parties, NUM_PARTIES, SHOW);

  // Compute session key and session identifier
  compute_sk_sid(pointer_to_parties, NUM_PARTIES);
  print_parties(pointer_to_parties, NUM_PARTIES, SHOW);

  // Free resources
  free_parties(pointer_to_parties, NUM_PARTIES);

  return 0;
}
