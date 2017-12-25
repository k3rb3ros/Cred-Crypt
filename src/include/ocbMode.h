#pragma once

/*
 * Offset Codebook (OCB) mode of operation for Threefish512 implemented from the
 * white paper found at http://web.cs.ucdavis.edu/~rogaway/papers/ocb-full.pdf
 *
 * There exists a tag collision attack against OCB
 * published here http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/comments/General_Comments/papers/Ferguson.pdf
 *
 * This implementation uses a 512 bit cipher that should mitigate this risk but encrypting
 * > 64Gb in a single operation is not recommended
 */

#ifdef __cplusplus
extern "C"
{
#endif /*C++ protection */

#include <assert.h> //assert()
#include <limits.h> //uint_xx types and size_t
#include <math.h> //ceil()
#include <stdbool.h> //bool
#include <stdint.h> //uintxx_t types
#include <stdlib.h> //realloc()
#include <string.h> //memcpy()
#include "constants.h" //Crypto size constants
#include "cryptoStructs.h" //tf_tweak
#include "threefishApi.h" //theefish cipher functions
#include "util.h" //clearBuff()

typedef uint64_t block_t[CIPHER_WORD_SIZE];

typedef struct
{
    ThreefishKey_t tf_ctx; //K
    block_t nonce; //N
}ocbCtx;

/* A Table of Low-Weight Binary Irreducible Polynomials
* can be found here http://www.hpl.hp.com/techreports/98/HPL-98-135.pdf
*/
/* P512(x) = X^512 + X^8 + X^5 + X^2 + 1
 * The bit field for this is as follows
 */
const static block_t bitfield_512  = { 0x8000000000000000ull, 0x0ull, 0x0ull, 0x0ull, 0x0ull, 0x0ull, 0x0ull, 0x125 };

/* 
* OCB.Enc K (N, M)
*/
void ocbEncrypt(ocbCtx* ctx, const void* in, void* out, size_t enc_bytes);

/* 
 * Returns true on successful decryption and validation, false if message is invalid
 * OCB.Dec K (N, C)
 */
bool ocbDecrypt(ocbCtx* ctx, const void* in, void* out, size_t dec_bytes);

/*
 * setup threefish
 */
bool ocbSetup(ocbCtx* ctx, uint64_t* key, const uint64_t* nonce);

#ifdef __cplusplus
}
#endif /* end C++ protection */
