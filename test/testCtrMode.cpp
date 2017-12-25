#include "include/testCtrMode.hpp"

void unitTestCtrMode::SetUp()
{
    test_plain_text = unique_ptr<uint8_t[]>(new uint8_t[81]());
    strcpy((char*)test_plain_text.get(), "How now brown cow. The quick red fox jumped over the lazy brown dog. Hurpa Derp.");
    pt_len = strlen((char*)test_plain_text.get());

    key[0] = 0x467563bULL; key[1] = 0x20796f75ULL; key[2] = 0x7220636fULL; key[3] = 0x75636820ULL;
    key[4] = 0x6e69767ULL; key[5] = 0x61212042ULL; key[6] = 0x75792061ULL; key[7] = 0x6e6f7468ULL;

    nonce[0] = 0x12345678ULL; nonce[1] = 0x9abcdef0ULL; nonce[2] = 0x0fdecba9ULL; nonce[3] = 0x87654321ULL;
    nonce[4] = 0x87654321ULL; nonce[5] = 0x0fdecba9ULL; nonce[6] = 0x9abcdef0ULL; nonce[7] = 0x12345678ULL;

    null_block[0] = 0; null_block[1] = 0; null_block[2] = 0; null_block[3] = 0;
    null_block[4] = 0; null_block[5] = 0; null_block[6] = 0; null_block[7] = 0;
}

TEST_F(unitTestCtrMode, CtrEncryptNullwNull)
{
    const static uint8_t three_512_ctr_01_expected_results[] =
    {
        253, 117, 6, 210, 107, 246, 161, 146, 17, 218,
        119, 45, 100, 51, 56, 111, 199, 236, 191, 77,
        41, 9, 32, 100, 221, 93, 22, 173, 154, 46,
        213, 186, 225, 66 ,44, 153, 91, 217, 33, 162,
        120, 138, 154, 12, 20, 44, 102, 204, 10, 176, 
        252, 175, 198, 100, 139, 247, 81, 148, 238, 101,
        139, 195, 68, 85, 161, 221, 126, 48, 62, 233,
        167, 102, 200, 202, 80, 47, 131, 17, 168, 20,
        '\0'
    };

    uint8_t* test_buffer = new uint8_t[pt_len+1]();
    uint8_t* test_cmp = new uint8_t[pt_len+1]();

    ctrEncrypt(test_buffer, pt_len, (uint64_t*)null_block, (uint64_t*)null_block);
    ASSERT_EQ(memcmp(test_buffer, three_512_ctr_01_expected_results, pt_len), 0);

    delete[] test_buffer;
    delete[] test_cmp;
}

TEST_F(unitTestCtrMode, CtrEncDecCycleNullwNull)
{
    uint8_t* test_buffer = new uint8_t[pt_len+1]();
    uint8_t* test_cmp = new uint8_t[pt_len+1]();

    ctrEncrypt(test_buffer, pt_len, (uint64_t*)null_block, (uint64_t*)null_block);
    ctrDecrypt(test_buffer, pt_len, (uint64_t*)null_block, (uint64_t*)null_block);
    ASSERT_EQ(memcmp(test_buffer, test_cmp, pt_len), 0);

    delete[] test_buffer;
    delete[] test_cmp;
}

TEST_F(unitTestCtrMode, CtrEncryptTestText)
{
    const static uint8_t three_512_ctr_00_expected_results[] =
    {
        206, 158, 107, 127, 100, 62, 187, 123, 195, 173,
        129, 126, 2, 225, 224, 140, 57, 170, 14, 59,
        253, 234, 45, 87, 55, 253, 121, 68, 240, 137,
        44, 76, 217, 101, 7, 99, 73, 7, 13, 19,
        249, 62, 40, 34, 42, 67, 156, 206, 6, 90,
        239, 200, 252, 96, 12, 81, 217, 85, 163, 104,
        210, 194, 235, 120, 18, 221, 14, 191, 63, 44,
        101, 192, 106, 77, 84, 194, 119, 15, 223, 195,
        '\0'
    };

    uint8_t* test_buffer = new uint8_t[pt_len+1]();
    memcpy(test_buffer, test_plain_text.get(), pt_len);
    ASSERT_STREQ((char*)test_plain_text.get(), (char*)test_buffer);

    ctrEncrypt(test_buffer, pt_len, (uint64_t*)nonce, (uint64_t*)key);
    ASSERT_EQ(memcmp(test_buffer, three_512_ctr_00_expected_results, pt_len), 0);

    delete[] test_buffer;
}


TEST_F(unitTestCtrMode, CtrEncDecCycleTestText)
{
    uint8_t* test_buffer = new uint8_t[pt_len+1]();
    memcpy(test_buffer, test_plain_text.get(), pt_len);
    ASSERT_STREQ((char*)test_plain_text.get(), (char*)test_buffer);
    
    ctrEncrypt(test_buffer, pt_len, (uint64_t*)nonce, (uint64_t*)key);
    ctrDecrypt(test_buffer, pt_len, (uint64_t*)nonce, (uint64_t*)key);
    ASSERT_STREQ((char*)test_buffer, (char*)test_plain_text.get());
    
    delete[] test_buffer;
}

//TODO Finish me
/*
TEST_F(unitTestCtrMode, DISABLED_CtrEncNonceDiffsCT)
{
    uint8_t* enc_deflt = new uint8_t[pt_len+1]();
    uint8_t* enc_new_nonce = new uint8_t[pt_len+1]();

    memcpy((void*)enc_deflt, (void*)test_plain_text, pt_len);
    memcpy((void*)enc_new_nonce, (void*)test_plain_text, pt_len);

    ASSERT_STREQ((char*)test_plain_text, (char*)enc_deflt);
    ASSERT_STREQ((char*)test_plain_text, (char*)enc_new_nonce);

    delete[] enc_deflt;
    delete[] enc_new_nonce;
}*/

//TODO Finish me
TEST_F(unitTestCtrMode, DISABLED_CtrEncKeyDiffsCT)
{
}
