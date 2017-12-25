#include "include/hash.h"

bool skeinHash(const uint8_t* input, const size_t in_bytes,
               uint8_t* output, size_t out_bytes)
{
    bool success = false;

    if (input != NULL || in_bytes > 0 || output != NULL || out_bytes > 0)
    {
        struct SkeinCtx skein_ctx;
        skeinCtxPrepare(&skein_ctx, SKEIN_SIZE); //Set up the Skein context
        skeinInit(&skein_ctx, out_bytes*8); //tell skein how long the output will be (in bits)
        skeinUpdate(&skein_ctx, input, in_bytes); //hash the input
        success = (skeinFinal(&skein_ctx, output) == 0) ? true : false; //fill output with the hash
    }

    return success;
}
