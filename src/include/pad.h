#pragma once

#ifdef __cplusplus
extern "C"
{
#endif /*C++ */

#include "skeinApi.h" //SkeinSize_t
#include <stdio.h> //perror()
#include <stdint.h> //stdint types
#include <stdlib.h> //calloc()
#include <string.h> //memcpy()

size_t getNumBlocks(const size_t plain_text_size, const SkeinSize_t skein_size);

size_t getPadSize(const size_t plain_text_size, const SkeinSize_t skein_size);

uint64_t* pad(const uint8_t* input, const size_t input_length, const SkeinSize_t skein_size);

#ifdef __cplusplus
}
#endif /*C++ */
