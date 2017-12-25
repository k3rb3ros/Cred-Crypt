#include "include/ctrMode.h"

static inline void incrementCounter(uint64_t* counter, uint8_t* word)
{
    if (counter[*(word)] == ULLONG_MAX) { *word = ((*word -1) % 7); }
    /* decrement the word counter if we overflow that word of the buffer
     * realistically this will probably never happen but this prevents the cipher from cycling
     * every 9*10^16 bytes or so
     */
    counter[*(word)]++;
}

static inline void ctrCipher(uint8_t* buffer, const size_t num_bytes,
                             const uint64_t* nonce, uint64_t* key)
{
    assert(CIPHER_WORD_SIZE == 8); //keep future code changes from breaking anything
    ThreefishKey_t tf_key;
    uint8_t counter_word = 7; //keep track of what word of the counter we are updating
    uint64_t cipher_text[CIPHER_WORD_SIZE] = { 0 }; //used to store the cipher output
    //in ctr mode a block size cipher is used as the plain text input into the cipher
    uint64_t counter[CIPHER_WORD_SIZE] = { 0 };
    
    //start the counter at the nonce value (which should be seeded randomly)
    counter[0] = nonce[0];
    counter[1] = nonce[1];
    counter[2] = nonce[2];
    counter[3] = nonce[3];
    counter[4] = nonce[4];
    counter[5] = nonce[5];
    counter[6] = nonce[6];
    counter[7] = nonce[7];

    //set up threefish
    threefishSetKey(&tf_key, (ThreefishSize_t)THREE_FISH_SIZE, key, tf_tweak);

    for (size_t b=0; b<num_bytes; ++b)
    {
        /* encrypt the counter with the block cipher this is our source of randomnesss */
        if (b%CIPHER_BYTE_SIZE == 0)
        {
            threefishEncryptBlockWords(&tf_key, counter, cipher_text);
        }

        //xor to encrypt/decrypt XOR the input with the source of randomness
        uint8_t* encrypted_block = (uint8_t*)cipher_text;
        buffer[b] ^= encrypted_block[b%CIPHER_BYTE_SIZE]; 

        /* At the end of every block we increment the counter which generates a new block
         * of randomness when run throw the block cipher during the next iteration of the
         * loop
         */
        if (b%CIPHER_BYTE_SIZE == 0)
        { incrementCounter((uint64_t*)&counter, &counter_word); }
    }
}

void ctrDecrypt(uint8_t* bfr, const size_t num_bytes,
                const uint64_t* nonce, uint64_t* key)
{
    ctrCipher(bfr, num_bytes, nonce, key);
}


void ctrEncrypt(uint8_t* bfr, const size_t num_bytes,
                const uint64_t* nonce, uint64_t* key)
{
    ctrCipher(bfr, num_bytes, nonce, key);
}
