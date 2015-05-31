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

int test_round(int nr, uint64_t* state)
{
	int x, y;
	for (y = 0; y < 5; ++y) {
		for (x = 0; x < 5; ++x) {
			if (expected[nr][y * 5 + x] != state[y * 5 + x]) {
				return -1;
			}
		}
	}

	return 0;
}

int test_one()
{
	uint64_t A[25]; /* keccak-f[1600] */

	/* zero out state */
	int i, j;
	for (j = 0; j < 5; ++j) {
		for (i = 0; i < 5; ++i) {
			A[j * 5 + i] = 0;
		}
	}

	if (keccakf(24, A) == -1) {
		printf("Invalid Keccak-F value.\n");
		return -1;
	}

	printf("Final result:\n");

	if (test_round(24, A) == -1) {
		printf("TEST FAILED\n");
	} else {
		printf("TEST OK!\n");
	}

	return 0;
}

typedef struct {
	int r;
	int c;
    int mdlen; /* output size in bytes */
    char *msgstr; /* message */
    uint8_t md[64]; /* expected result */
} test_triplet_t;

int test_two()
{
	/*
	SHA3-512 = keccak(576, 1024, 64, l, M)
	SHA3-384 = keccak(832, 768, 48, l, M)
	SHA3-256 = keccak(1088, 512, 32, l, M)
	SHA3-224 = keccak(1152, 448, 28, l, M)
	 */
	
    test_triplet_t testvec[6] = {
    	{
    		1152, 448, 28, "", {
                0x3, 0x89, 0x7, 0xe8, 0x9c, 0x91, 0x9c, 0xd8, 
				0xf9, 0xa, 0x7f, 0xbc, 0x5a, 0x88, 0xff, 0x92, 
				0x78, 0x10, 0x8d, 0xae, 0xf3, 0xeb, 0xcd, 0xa0, 
				0xce, 0xb3, 0x83, 0xe1
            }
    	},
        {
            1152, 448, 28, "Keccak-224 Test Hash", {
                0x30, 0x04, 0x5B, 0x34, 0x94, 0x6E, 0x1B, 0x2E,
                0x09, 0x16, 0x13, 0x36, 0x2F, 0xD2, 0x2A, 0xA0,
                0x8E, 0x2B, 0xEA, 0xFE, 0xC5, 0xE8, 0xDA, 0xEE,
                0x42, 0xC2, 0xE6, 0x65
            }
        }, {
            1088, 512, 32, "Keccak-256 Test Hash", {
                0xA8, 0xD7, 0x1B, 0x07, 0xF4, 0xAF, 0x26, 0xA4,
                0xFF, 0x21, 0x02, 0x7F, 0x62, 0xFF, 0x60, 0x26,
                0x7F, 0xF9, 0x55, 0xC9, 0x63, 0xF0, 0x42, 0xC4,
                0x6D, 0xA5, 0x2E, 0xE3, 0xCF, 0xAF, 0x3D, 0x3C
            }
        }, {
            832, 768, 48, "Keccak-384 Test Hash", {
                0xE2, 0x13, 0xFD, 0x74, 0xAF, 0x0C, 0x5F, 0xF9,
                0x1B, 0x42, 0x3C, 0x8B, 0xCE, 0xEC, 0xD7, 0x01,
                0xF8, 0xDD, 0x64, 0xEC, 0x18, 0xFD, 0x6F, 0x92,
                0x60, 0xFC, 0x9E, 0xC1, 0xED, 0xBD, 0x22, 0x30,
                0xA6, 0x90, 0x86, 0x65, 0xBC, 0xD9, 0xFB, 0xF4,
                0x1A, 0x99, 0xA1, 0x8A, 0x7D, 0x9E, 0x44, 0x6E 
            }
        }, {
            576, 1024, 64, "Keccak-512 Test Hash", {
                0x96, 0xEE, 0x47, 0x18, 0xDC, 0xBA, 0x3C, 0x74,
                0x61, 0x9B, 0xA1, 0xFA, 0x7F, 0x57, 0xDF, 0xE7,
                0x76, 0x9D, 0x3F, 0x66, 0x98, 0xA8, 0xB3, 0x3F,
                0xA1, 0x01, 0x83, 0x89, 0x70, 0xA1, 0x31, 0xE6,
                0x21, 0xCC, 0xFD, 0x05, 0xFE, 0xFF, 0xBC, 0x11,
                0x80, 0xF2, 0x63, 0xC2, 0x7F, 0x1A, 0xDA, 0xB4,
                0x60, 0x95, 0xD6, 0xF1, 0x25, 0x33, 0x14, 0x72,
                0x4B, 0x5C, 0xBF, 0x78, 0x28, 0x65, 0x8E, 0x6A 
            }
        }, {
            576, 1024, 64, "The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog.The quick brown fox jumps over the lazy dog...", {
                0x89, 0x22, 0x9e, 0xcb, 0x2c, 0x30, 0x55, 0xde, 
				0xdc, 0x83, 0x8, 0x88, 0xd3, 0xba, 0x4, 0x57, 
				0xa7, 0x4, 0x7f, 0x38, 0x4f, 0xc3, 0x63, 0xe5, 
				0xb3, 0x1, 0x2c, 0x4a, 0x0, 0xcc, 0x67, 0x79, 
				0x78, 0x3, 0xd7, 0x9f, 0xcb, 0xc4, 0x46, 0x84, 
				0xd7, 0x58, 0x7e, 0xe1, 0x49, 0x78, 0x0, 0xbc, 
				0x11, 0xa9, 0x16, 0x23, 0x7f, 0x64, 0x9a, 0x80, 
				0x9b, 0x80, 0x3e, 0x69, 0x8d, 0x3c, 0x73, 0x33
            }
        }
    };

    char teststr[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
    testvec[0].msgstr = teststr;

    int i, j, fails;
    uint8_t md[64];

    fails = 0;
    for (i = 0; i < 6; i++) {
    	int len = 0;

    	if (i > 0) {
    		len = strlen(testvec[i].msgstr);
    	} else {
    		len = 16;
    	}

    	int res = keccak(testvec[i].r, testvec[i].c, testvec[i].mdlen,
    		len,
    		(uint8_t*) testvec[i].msgstr,
    		md
    	);

    	if (res != 0) {
    		fprintf(stderr, "Test failed with %d\n", res);
    		continue;
    	}

        if (memcmp(md, testvec[i].md, testvec[i].mdlen)) {
            fails++;
            fprintf(stderr, "Keccak-%d FAILED.\n", testvec[i].mdlen * 8);

            printf("Byte at pos");
            for (j = 0; j < testvec[i].mdlen; ++j) {
            	if (testvec[i].md[j] != md[j]) {
            		 printf(" %d", j);
            	}
            }
            printf(" wrong.\n");

            for (j = 0; j < testvec[i].mdlen; ++j) {
            	printf("0x%x\t", md[j]);

            	if ((j + 1) % 8 == 0) {
            		printf("\n");
            	}
            }
            printf("\n");
        } else {
        	printf("Keccak-%d OK\n", testvec[i].mdlen * 8);
        }
    }

    return fails;
}

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