#pragma once
/*
 * A key checker stores the Skein512 hash of a key when given the byte string of a key
 * can calculate the hash of this key and compare it to the stored one.
 * Indicating if the key has been correctly reconstructed.
 */

#include "constants.h" //size macros
#include "hash.h" //skeinHash()
#include "util.h" //clearBuff()

class keyChecker
{
    private:
    /***************
    * Private Data *
    ***************/
    uint64_t hash_[HASH_WORD_SIZE] = { 0 };

    /******************
    * Private Methods *
    ******************/
    void hashKeyInternal();

    public:
    /**************
    * Constructor *
    **************/
    keyChecker();

    /*************
    * Destructor *
    *************/
    ~keyChecker();

    bool checkKey(const uint64_t* key, const size_t key_word_size);

    bool hashKey(const uint64_t* key, const size_t key_word_size);
};
