#include <assert.h>
#include <string.h> /* memcpy, memset */
#include <stdio.h>
#include <stdlib.h> /* malloc */

#include "keccak.h"

/* Round constants */
const uint64_t RC[24] =
{
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
  0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
  0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
  0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
  0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

/* Rotation offsets, y vertically, x horizontally: r[y * 5 + x] */
const int rx[25] = {
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14
};

keccak_t perms[7] = {
  /* b,  l, w,  nr */
  {25,   0, 1,  12},
  {50,   1, 2,  14},
  {100,  2, 4,  16},
  {200,  3, 8,  18},
  {400,  4, 16, 20},
  {800,  5, 32, 22},
  {1600, 6, 64, 24},
};

void compute_rho(int w)
{
  int rho[25];

  /* x = y = 0 is zero */
  rho[0] = 0;

  uint32_t x, y, z;
  x = 1; y = 0;

  uint32_t t, n;
  for (t = 0; t < 24; ++t) {
    /* rotation length */
    n = ((t + 1) * (t + 2) / 2) % w;

    rho[y * 5 + x] = n;

    z = (0 * x + 1 * y) % 5;
    y = (2 * x + 3 * y) % 5;
    x = z;
  }
}

/* Keccak-F[b] round function */
void keccak_round(int nr, uint64_t* state)
{
  uint64_t B[25] = {
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0
  };
  uint64_t C[5] = {0, 0, 0, 0, 0};
  uint64_t D[5] = {0, 0, 0, 0, 0};

  /* Theta */
  int x, y;
  for (x = 0; x < 5; ++x) {
    C[x] = state[x] ^ state[5 + x] ^ state[10 + x] ^ state[15 + x] ^ state[20 + x];
  }

  for (x = 0; x < 5; ++x) {
    /* in order to avoid negative mod values, 
      we've replaced "(x - 1) % 5" with "(x + 4) % 5" */
    D[x] = C[(x + 4) % 5] ^ ROTL64(C[(x + 1) % 5], 1);

    for (y = 0; y < 5; ++y) {
      state[y * 5 + x] = state[y * 5 + x] ^ D[x];
    }
  }

  /* Rho and Pi */
  for (y = 0; y < 5; ++y) {
    for (x = 0; x < 5; ++x) {
      B[5 * ((2*x + 3*y) % 5) + y] = ROTL64(state[y * 5 + x], rx[y * 5 + x]);
    }
  }

  /* Chi */
  for (y = 0; y < 5; ++y) {
    for (x = 0; x < 5; ++x) {
      state[y * 5 + x] = B[y * 5 + x] ^ ((~B[y * 5 + ((x + 1) % 5)] & B[y * 5 + ((x + 2) % 5)])); 
    }
  }

  /* Iota */
  /* XXX: truncate RC[i] if w < 64 */
  state[0] = state[0] ^ RC[nr];
}

/* Keccak-F[b] function */
int keccakf(int rounds, uint64_t* state)
{
  int i;
  for (i = 0; i < rounds; ++i) {
    keccak_round(i, state);
  }

  return 0;
}

int sha3_512(uint8_t* M, int l, uint8_t* O)
{
  return keccak(576, 1024, 64, l, M, O);
}

int sha3_384(uint8_t* M, int l, uint8_t* O)
{
  return keccak(832, 768, 48, l, M, O);
}

int sha3_256(uint8_t* M, int l, uint8_t* O)
{
  return keccak(1088, 512, 32, l, M, O);
}

int sha3_224(uint8_t* M, int l, uint8_t* O)
{
  return keccak(1152, 448, 28, l, M, O);
}

/* Keccak */
/*
r = bit rate
c = capacity
n = output length
l = message length
M = message of bytes
O = output
*/
int keccak(int r, int c, int n, int l, uint8_t* M, uint8_t* O)
{
  /* check parameters */

  /* bit rate must be a multiple of the lane size */
  if (r < 0 || (r % 8 != 0)) {
    return -1;
  }

  /* check permutation width */
  int b = r + c;

  int i, j = -1;
  for (i = 0; i < 7; ++i) {
    if (b == perms[i].b) {
      j = i;
      break;
    }
  }

  if (j == -1) {
    return -3;
  }

  /* state of 5x5 lanes, each of length 64 (for Keccak-f[1600]) */
  uint64_t A[25];
  /* zero out the state */
  memset(A, 0, 25 * sizeof(uint64_t));

  /* lane width */
  int w = perms[j].w;
  int block_size = r/8;

  int blocks = l / block_size;
  /* make room for padding, if necessary */
  uint8_t P[block_size * (blocks + 1)];

  /* zero out data and copy M into P */
  memset(P, 0, (blocks + 1) * block_size * sizeof(uint8_t));
  for (i = 0; i < l; ++i) {
      P[i] = M[i];
  }

  /* padding */
  if (l % block_size != 0) {
    /* round up */
    blocks = (block_size + l + 1) / block_size;

    /* add padding bytes */
    P[l] = 0x01;
    l = block_size * blocks;
    P[l - 1] = 0x80;
  }

  /* absorbing phase */
  int x;
  /* for every block Pi in P */
  for (i = 0; i < blocks; ++i) {
    uint64_t* block = (uint64_t*)P + i * r/w;

    /* S[x, y] = S[x, y] ⊕ Pi[x + 5y],   ∀(x, y) such that x + 5y < r/w */
    for (x = 0; x < (r/w); ++x) {
      A[x] = A[x] ^ block[x];
    }

    /* S = Keccak-f[r + c](S) */
    keccakf(perms[j].nr, A);
  }

  /*
    We have r/8 > n in any case, i.e., the squeezing phase
      consists of one round.
   */

  /* copy output */
  memcpy(O, A, n);

  return 0;
}
