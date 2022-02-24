#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "gake_qrom.h"
#include "ds_benchmark.h"

int main(int argc, char** argv){

  if(argc < 2){
    printf("You must provide the number of parties!\n");
    return 1;
  }

  int NUM_PARTIES = atoi(argv[1]);
  int ITERATIONS = 1;

  // clock_t begin_total = clock();

  Party *pointer_to_parties;

  pointer_to_parties = (Party*) malloc(sizeof(Party) * NUM_PARTIES);


  PRINT_TIMER_HEADER

  TIME_OPERATION_ITERATIONS(
    init_parties(pointer_to_parties, NUM_PARTIES),
    "init",
    ITERATIONS
  )


  TIME_OPERATION_ITERATIONS(
    compute_left_right_keys(pointer_to_parties, NUM_PARTIES),
    "round12",
    ITERATIONS
  )

  // Round 3
  TIME_OPERATION_ITERATIONS(
    compute_xs_commitments(pointer_to_parties, NUM_PARTIES),
    "round3",
    ITERATIONS
  )

  // Round 4
  TIME_OPERATION_ITERATIONS(
    for (int k = 0; k < NUM_PARTIES; k++) {

      int res = check_xs(pointer_to_parties, k, NUM_PARTIES); // Check Xi
      int result = check_commitments(pointer_to_parties, k, NUM_PARTIES); // Check commitments

      if (res == 0) {
      } else {
        pointer_to_parties[k].acc = 0;
        pointer_to_parties[k].term = 1;
        return 1;
      }

      if (result == 0) {
      } else {
        pointer_to_parties[k].acc = 0;
        pointer_to_parties[k].term = 1;
        return 1;
      }
    }

    // Master Key
    compute_masterkey(pointer_to_parties, NUM_PARTIES);

    // Compute session key and session identifier
    compute_sk_sid(pointer_to_parties, NUM_PARTIES),
    "round4",
    ITERATIONS
  )

  // Free resources
  free_parties(pointer_to_parties, NUM_PARTIES);

  // clock_t end_4 = clock();

  return 0;
}
