#pragma once

/*
 * Counter mode of operation for the threefish block cipher
 * Counter mode acts as a stream cipher so we have the added benefit of not having to null pad string buffers to block sizes
 */

#ifdef __cplusplus
extern "C"
{
#endif /*C++ */

#include <assert.h> //assert()
#include <limits.h> //ULLONG_MAX
#include <stdint.h> //uint_xx types and size_t
#include "constants.h" //predefined constants
#include "cryptoStructs.h" //tf_tweak
#include "threefishApi.h" //threefish cipher functions

/*These functions assume a 512bit cipher block size if it is ever changed they need to modified */

/* ctr encrypt the given plain text */
void ctrEncrypt(uint8_t* bfr, const size_t num_bytes,
                const uint64_t* nonce, uint64_t* key);

/* In ctr decryption is the exact same operation as encryption */
/* ctr decrypt the given cipher text */
void ctrDecrypt(uint8_t* bfr, const size_t num_bytes,
                const uint64_t* nonce, uint64_t* key);

#ifdef __cplusplus
}
#endif /*C++ */
