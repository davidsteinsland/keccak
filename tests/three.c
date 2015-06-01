#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include "../keccak_test.h"
#include "../keccak.h"

int test_three()
{
  int length = 16;
  int output_length = 28;
  uint8_t output[28];

  char teststr[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };

  char expected[64] = {
    0x3, 0x89, 0x7, 0xe8, 0x9c, 0x91, 0x9c, 0xd8,
    0xf9, 0xa, 0x7f, 0xbc, 0x5a, 0x88, 0xff, 0x92,
    0x78, 0x10, 0x8d, 0xae, 0xf3, 0xeb, 0xcd, 0xa0,
    0xce, 0xb3, 0x83, 0xe1
  };

  int res = sha3_224((uint8_t*)teststr, length, output);

  if (res != 0) {
  fprintf(stderr, "Test failed with %d\n", res);
  return -1;
  }

  if (memcmp(output, expected, output_length)) {
    printf("test_three FAILED\n");
    return -1;
  }

  printf("test_three OK\n");

  return 0;
}
