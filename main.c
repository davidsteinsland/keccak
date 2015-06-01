#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>

#include <string.h>

#include "keccak_test.h"
#include "keccak.h"

// uint32_t state[25]; /* keccak-f[800] */
// uint16_t state[25]; /* keccak-f[400] */
// uint8_t state[25];  /* keccak-f[200] */

int digest2str(uint8_t* digest, char* P, int len)
{
  int i, j = 0;
  for (i = 0; i < len; ++i) {
    j += sprintf(&P[i * 2], "%02x", (unsigned int)digest[i]);
  }

  return j;
}

int main()
{
  if (test_one() != 0) {
    return -1;
  }

  if (test_two() != 0) {
    return -1;
  }

  if (test_three() != 0) {
    return -1;
  }

  return 0;
}
