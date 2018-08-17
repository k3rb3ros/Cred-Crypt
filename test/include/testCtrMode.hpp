#pragma once

#include <memory> //unique_ptr
#include <stdio.h> //memcpy(), memcmp()
#include <string.h> //strcpy() //strlen()
#include "gtest/gtest.h"
#include "constants.h"
#include "ctrMode.h"

using std::unique_ptr;

class unitTestCtrMode : public ::testing::Test
{
    protected:

    size_t pt_len;

    unique_ptr<uint8_t[]> test_plain_text;
    uint64_t nonce[CIPHER_WORD_SIZE];
    uint64_t key[KEY_WORD_SIZE];
    uint64_t null_block[KEY_WORD_SIZE];

    /***********************************
    * Test fixture set up an tear down *
    ***********************************/
    virtual void SetUp();
};
