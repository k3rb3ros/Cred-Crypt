#pragma once

/* this function encapsulate the act of hashing with Skein 512 */

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h> //bool types
#include "constants.h" // predefined constants
#include "skeinApi.h" //skein hash functions

/* hash an input of given size into an output of given size with Skein512 
 * returns true on success
 */
bool skeinHash(const uint8_t* input,
               const size_t in_bytes,
               uint8_t* output,
               const size_t out_byte);

#ifdef __cplusplus
}
#endif /* end c++ */
