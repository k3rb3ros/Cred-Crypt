#include "include/keyChecker.hpp"

keyChecker::keyChecker() { /* nop */ }

keyChecker::~keyChecker() { clearBuff((uint8_t*)hash_, HASH_BYTE_SIZE); }

bool keyChecker::checkKey(const uint64_t* key, const size_t key_word_size)
{
    bool success = false;
    uint64_t compare[HASH_WORD_SIZE] = { 0 };

    if (skeinHash((uint8_t*)key, key_word_size/8, (uint8_t*)compare, HASH_BYTE_SIZE))
    {
        success = (compareWordBuff(hash_, compare, HASH_WORD_SIZE) == 0) ? true : false;
    }

    return success;
}

bool keyChecker::hashKey(const uint64_t* key, const size_t key_word_size)
{
    return skeinHash((uint8_t*)key, key_word_size/8, (uint8_t*)hash_, HASH_BYTE_SIZE);
}
