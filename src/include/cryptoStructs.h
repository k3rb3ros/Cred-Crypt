#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h> //uintxx_t types
#include "constants.h" // predefined constants

/* an arbitrary tweak so this implementation of threefish won't output the same values as
 *  attacker x's threefish (unless they have these values)
 */
static uint64_t tf_tweak[2] = { 0x5368616C6C206E6ULL, 0X26520646976756CULL };

typedef uint64_t skein_hash[HASH_WORD_SIZE];

#ifdef __cplusplus
}
#endif /* end c++ */
