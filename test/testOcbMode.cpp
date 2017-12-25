#include "include/testOcbMode.hpp"

void swapBlocks(uint64_t* bfr, const uint_fast8_t b1, const uint_fast8_t b2)
{
    ASSERT_EQ(CIPHER_WORD_SIZE, 8);
    uint_fast8_t i1 = b1*CIPHER_WORD_SIZE;
    uint_fast8_t i2 = b2*CIPHER_WORD_SIZE;
    uint64_t temp;

    temp = bfr[i1+0]; bfr[i1+0] = bfr[i2+0]; bfr[i2+0] = temp;
    temp = bfr[i1+1]; bfr[i1+1] = bfr[i2+1]; bfr[i2+1] = temp;
    temp = bfr[i1+2]; bfr[i1+2] = bfr[i2+2]; bfr[i2+2] = temp;
    temp = bfr[i1+3]; bfr[i1+3] = bfr[i2+3]; bfr[i2+3] = temp;
    temp = bfr[i1+4]; bfr[i1+4] = bfr[i2+4]; bfr[i2+4] = temp;
    temp = bfr[i1+5]; bfr[i1+5] = bfr[i2+5]; bfr[i2+5] = temp;
    temp = bfr[i1+6]; bfr[i1+6] = bfr[i2+6]; bfr[i2+6] = temp;
    temp = bfr[i1+7]; bfr[i1+7] = bfr[i2+7]; bfr[i2+7] = temp;
}

void xorBlocks(uint64_t* bfr, const uint_fast8_t src, const uint_fast8_t dst)
{
    ASSERT_EQ(CIPHER_WORD_SIZE, 8);
    uint_fast8_t i1 = dst*CIPHER_WORD_SIZE;
    uint_fast8_t i2 = src*CIPHER_WORD_SIZE;

    bfr[i1+0] ^= bfr[i2+0];
    bfr[i1+1] ^= bfr[i2+1];
    bfr[i1+2] ^= bfr[i2+2];
    bfr[i1+3] ^= bfr[i2+3];
    bfr[i1+4] ^= bfr[i2+4];
    bfr[i1+5] ^= bfr[i2+5];
    bfr[i1+6] ^= bfr[i2+6];
    bfr[i1+7] ^= bfr[i2+7];
}

/*
 * oscbSetup should copy the key to ctx->tf_ctx->key
 * and copy the nonce to ctx->nonce
 */
TEST(unitTestOcbMode, OCbSetupWorks)
{
    ASSERT_EQ(KEY_WORD_SIZE, 8);
    ocbCtx ctx;
    uint64_t key[KEY_WORD_SIZE] = { 1234, 1234, 1234, 1234, 1234, 1234, 1234, 1234 };
    uint64_t nonce[KEY_WORD_SIZE] = { 0 };

    ASSERT_TRUE(ocbSetup(&ctx, key, nonce));

    ASSERT_EQ(ctx.tf_ctx.key[0], key[0]);
    ASSERT_EQ(ctx.tf_ctx.key[1], key[1]);
    ASSERT_EQ(ctx.tf_ctx.key[2], key[2]);
    ASSERT_EQ(ctx.tf_ctx.key[3], key[3]);
    ASSERT_EQ(ctx.tf_ctx.key[4], key[4]);
    ASSERT_EQ(ctx.tf_ctx.key[5], key[5]);
    ASSERT_EQ(ctx.tf_ctx.key[6], key[6]);
    ASSERT_EQ(ctx.tf_ctx.key[7], key[7]);

    ASSERT_EQ(ctx.nonce[0], nonce[0]);
    ASSERT_EQ(ctx.nonce[1], nonce[1]);
    ASSERT_EQ(ctx.nonce[2], nonce[2]);
    ASSERT_EQ(ctx.nonce[3], nonce[3]);
    ASSERT_EQ(ctx.nonce[4], nonce[4]);
    ASSERT_EQ(ctx.nonce[5], nonce[5]);
    ASSERT_EQ(ctx.nonce[6], nonce[6]);
    ASSERT_EQ(ctx.nonce[7], nonce[7]);
}

TEST(unitTestOcbMode, EncryptOfNullData)
{
    ASSERT_EQ(KEY_WORD_SIZE, 8);
    ASSERT_EQ(OCB_TAG_WORD_SIZE, 1);
    ocbCtx ctx;
    const size_t msg_word_size = 9;
    uint64_t key[KEY_WORD_SIZE] = { 1234, 1234, 1234, 1234, 1234, 1234, 1234, 1234 };
    uint64_t nonce[KEY_WORD_SIZE] = { 0 };

    uint64_t message[msg_word_size] = { 0 };
    const uint64_t expected_ct[msg_word_size+OCB_TAG_WORD_SIZE] =
    {
        258367096995043748ULL, 14248616103057875222ULL, 9778431943379953370ULL,
        7896445063147268631ULL, 11320723114353407375ULL, 13707374308352115843ULL,
        4258231730921475566ULL, 11183116521604978059ULL, 10873252467634560338ULL,
        1736507367973081621ULL
    };

    ASSERT_TRUE(ocbSetup(&ctx, key, nonce));
    ocbEncrypt(&ctx,
               (uint8_t*)message,
               (uint8_t*)message,
               (msg_word_size*sizeof(uint64_t)));

    for (size_t s=0; s<(msg_word_size+OCB_TAG_WORD_SIZE); ++s)
    {
        ASSERT_EQ(message[s], expected_ct[s]);
    }
}

TEST(unitTestOcbMode, EncryptDecryptCycleOfNullData)
{
    ASSERT_EQ(KEY_WORD_SIZE, 8);
    ocbCtx ctx;
    uint64_t key[KEY_WORD_SIZE] = { 1234, 1234, 1234, 1234, 1234, 1234, 1234, 1234 };
    uint64_t nonce[KEY_WORD_SIZE] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    const size_t pt_word_len = 69;
    uint64_t plain_text[pt_word_len] = { 0 };
    uint64_t cipher_text[pt_word_len+OCB_TAG_WORD_SIZE] = { 0 };

    ASSERT_TRUE(ocbSetup(&ctx, key, nonce));
    ocbEncrypt(&ctx, (uint8_t*)plain_text, (uint8_t*)cipher_text, pt_word_len*sizeof(uint64_t));
    //cipher text is different from plain text
    for (uint_fast8_t b=0; b<9; ++b) { ASSERT_NE(plain_text[b], cipher_text[b]); }

    for (uint_fast8_t b=0; b<OCB_TAG_WORD_SIZE; ++b)
    { ASSERT_NE(cipher_text[b], 0ULL); } //tag got written

    //decryption succeeded (tags match)
    ASSERT_TRUE(ocbDecrypt(&ctx,
                           (uint8_t*)cipher_text,
                           (uint8_t*)plain_text,
                           (pt_word_len+OCB_TAG_WORD_SIZE)*sizeof(uint64_t)));
    //Original plain text of all nulls recovered
    for (uint_fast8_t b=0; b<9; ++b)
    { ASSERT_EQ(plain_text[b], 0ULL); } //text is now different
}

//encrypt 2 blocks of plain text and ensure we get consistent output with the same key and nonce
TEST(unitTestOcbMode, EncryptOfArbitraryData)
{
    ASSERT_EQ(KEY_WORD_SIZE, 8);
    ASSERT_EQ(OCB_TAG_WORD_SIZE, 1);
    ocbCtx ctx;
    uint64_t key[KEY_WORD_SIZE] = { 1337, 1337, 1337, 1337, 1337, 1337, 1337, 1337 };
    uint64_t nonce[KEY_WORD_SIZE] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    uint64_t pt[2*CIPHER_WORD_SIZE] =
    {
        101, 131, 151, 181, 191, 313, 353,
        373, 383, 727, 757, 787, 797, 919
    };
    uint64_t ct[(2*CIPHER_WORD_SIZE)+OCB_TAG_WORD_SIZE] = { 0 };
    uint64_t expected_ct[(2*CIPHER_WORD_SIZE)+OCB_TAG_WORD_SIZE] =
    {
        9634808006693877913ULL, 16073925650257485052ULL, 11895756725326533287ULL,
        14759149743327866337ULL, 4744429815209355564ULL, 4265912968000912077ULL,
        11762586551314343459ULL, 10938400095866213030ULL, 18292925695481658178ULL,
        9848604567901134372ULL, 11901439766578830800ULL, 6390728535410258339ULL,
        6239413917498022059ULL, 2789991583404169844ULL, 17829381699394861171ULL,
        13159312263341863122ULL, 5044294201860054335ULL
    };

    ASSERT_TRUE(ocbSetup(&ctx, key, nonce));
    ocbEncrypt(&ctx, (void*)pt, (void*)ct, 2*CIPHER_BYTE_SIZE);

    for (uint_fast8_t i=0; i<((2*CIPHER_WORD_SIZE)+OCB_TAG_WORD_SIZE); ++i)
    { ASSERT_EQ(ct[i], expected_ct[i]); }
}

TEST(unitTestOcbMode, ChangingKeyDiffsCt)
{
    ASSERT_EQ(KEY_WORD_SIZE, 8);
    ocbCtx ctx;
    uint64_t key1[KEY_WORD_SIZE] = { 8080, 8080, 8080, 8080, 4458, 4458, 4458, 4458 };
    uint64_t key2[KEY_WORD_SIZE] = { 8081, 8080, 8080, 8080, 4458, 4458, 4458, 4458 };
    uint64_t nonce[KEY_WORD_SIZE] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    uint64_t ct1[(CIPHER_WORD_SIZE/2)+OCB_TAG_WORD_SIZE] = { 0 };
    uint64_t ct2[(CIPHER_WORD_SIZE/2)+OCB_TAG_WORD_SIZE] = { 0 };
    uint64_t pt[CIPHER_WORD_SIZE/2] = { 0 };

    //encrypt the same message with the same nonce but two keys (varying by 1 bit)
    ASSERT_TRUE(ocbSetup(&ctx, key1, nonce));
    ocbEncrypt(&ctx, (void*)pt, (void*) ct1, CIPHER_BYTE_SIZE/2);
    ASSERT_TRUE(ocbSetup(&ctx, key2, nonce));
    ocbEncrypt(&ctx, (void*)pt, (void*) ct2, CIPHER_BYTE_SIZE/2);

    //Assert that we get completely different cipher text
    for (uint_fast8_t i=0; i<(CIPHER_WORD_SIZE/2)+OCB_TAG_WORD_SIZE; ++i)
    {
        ASSERT_NE(ct1[i], ct2[i]);
    }

    //Assert that trying to decrypt the same message encrypted with a different key fails
    ASSERT_FALSE(ocbDecrypt(&ctx,
                            (void*)ct1,
                            (void*)pt,
                            (CIPHER_BYTE_SIZE/2)+(OCB_TAG_WORD_SIZE*sizeof(uint64_t))));

    //Finally for good measure assert that we didn't get the original plain text out of it
    for (uint_fast8_t i=0; i<(CIPHER_WORD_SIZE/2); ++i)
    {
        ASSERT_NE(pt[i], 0ULL);
    }
}

TEST(unitTestOcbMode, ChangingNonceDiffsCt)
{
    ASSERT_EQ(KEY_WORD_SIZE, 8);
    ocbCtx ctx;
    uint64_t key[KEY_WORD_SIZE] = { 8080, 8080, 8080, 8080, 4458, 4458, 4458, 4458 };
    uint64_t nonce1[KEY_WORD_SIZE] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    uint64_t nonce2[KEY_WORD_SIZE] = { 8, 7, 6, 5, 4, 3, 2, 0 };
    uint64_t ct1[(CIPHER_WORD_SIZE)+2] = { 0 };
    uint64_t ct2[(CIPHER_WORD_SIZE)+2] = { 0 };
    uint64_t pt[CIPHER_WORD_SIZE] = { 0 };

    //encrypt the same message with the same key but 2 diff nonces we should get diff cipher text
    ASSERT_TRUE(ocbSetup(&ctx, key, nonce1));
    ocbEncrypt(&ctx, (void*)pt, (void*) ct1, CIPHER_BYTE_SIZE);
    ASSERT_TRUE(ocbSetup(&ctx, key, nonce2));
    ocbEncrypt(&ctx, (void*)pt, (void*) ct2, CIPHER_BYTE_SIZE);

    //Assert that we get completely different cipher text
    for (uint_fast8_t i=0; i<(CIPHER_WORD_SIZE)+OCB_TAG_WORD_SIZE; ++i)
    {
        ASSERT_NE(ct1[i], ct2[i]);
    }

    //Assert that trying to decrypt the same message encrypted with a different nonce fails
    ASSERT_FALSE(ocbDecrypt(&ctx,
                            (void*)ct1,
                            (void*)pt,
                            (CIPHER_BYTE_SIZE)+(2*sizeof(uint64_t))));

    //Finally for good measure assert that we didn't get the original plain text out of it
    for (uint_fast8_t i=0; i<(CIPHER_WORD_SIZE); ++i)
    {
        ASSERT_NE(pt[i], 0ULL);
    }
}

TEST(unitTestOcbMode, flipBitWorks)
{
    uint16_t one = 0x1;
    uint16_t max = 0x8000;
    uint16_t zero = 0x0;

    flipBit(&one, 0);
    flipBit(&max, 15);
    flipBit(&zero, 0);

    ASSERT_EQ(one, 0);
    ASSERT_EQ(max, 0);
    ASSERT_EQ(zero, 1);
}

TEST(unitTestOcbMode, FlippingCTBitsCausesTagFail)
{
    ASSERT_EQ(CIPHER_WORD_SIZE, 8);
    ocbCtx ctx;
    const size_t pt_word_len = 16;
    uint64_t key[KEY_WORD_SIZE] = { 1234, 1234, 1234, 1234, 1234, 1234, 1234, 1234 };
    uint64_t nonce[KEY_WORD_SIZE] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    uint64_t pt[pt_word_len] = { 0 };
    uint64_t orig_ct[pt_word_len+OCB_TAG_WORD_SIZE] = { 0 };
    uint64_t scratch_ct[pt_word_len+OCB_TAG_WORD_SIZE] = { 0 };

    ASSERT_TRUE(ocbSetup(&ctx, key, nonce));
    ocbEncrypt(&ctx, (uint8_t*)pt, (uint8_t*)orig_ct, pt_word_len*sizeof(uint64_t));

    /* Flip every bit in the cipher text and ensure that it being flipped causes a validation
     * fail on decryption*/
    const size_t ct_bits = (pt_word_len*sizeof(uint64_t))*8;
    for (size_t s=0; s<ct_bits; ++s)
    {
        //copy the ct to the scratch buffer;
        memcpy(scratch_ct, orig_ct, (pt_word_len+2)*sizeof(uint64_t));
        flipBit(scratch_ct, s); //flip a bit in it
        ASSERT_FALSE(ocbDecrypt(&ctx,
                                (uint8_t*)scratch_ct,
                                (uint8_t*)pt,
                                (pt_word_len+OCB_TAG_WORD_SIZE)*sizeof(uint64_t)));
    }
}

TEST(unitTestOcbMode, FlippingCTBytesCausesTagFail)
{
    ASSERT_EQ(CIPHER_WORD_SIZE, 8);
    ocbCtx ctx;
    const size_t pt_word_len = 16;
    uint64_t key[KEY_WORD_SIZE] = { 1234, 1234, 1234, 1234, 1234, 1234, 1234, 1234 };
    uint64_t nonce[KEY_WORD_SIZE] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    uint64_t pt[pt_word_len] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    uint64_t orig_ct[pt_word_len+OCB_TAG_WORD_SIZE] = { 0 };
    uint64_t scratch_ct[pt_word_len+OCB_TAG_WORD_SIZE] = { 0 };

    ASSERT_TRUE(ocbSetup(&ctx, key, nonce));
    ocbEncrypt(&ctx, pt, orig_ct, pt_word_len*sizeof(uint64_t));

    /* Flip every byte in the cipher text and ensure that it being flipped causes a validation
     * fail on decryption*/
    uint8_t* ct_byte = (uint8_t*)scratch_ct;
    for (size_t s=0; s<(pt_word_len*sizeof(uint64_t)); ++s)
    {
        //copy the ct to the scratch buffer;
        memcpy(scratch_ct, orig_ct, (pt_word_len+2)*sizeof(uint64_t));
        ct_byte[s] = ~(ct_byte[s]); //flip a byte in it
        ASSERT_FALSE(ocbDecrypt(&ctx,
                                scratch_ct,
                                pt,
                                (pt_word_len+OCB_TAG_WORD_SIZE)*sizeof(uint64_t)));
    }
}

TEST(unitTestOcbMode, SwappingCTBlocksCausesTagFail)
{
    ASSERT_EQ(CIPHER_WORD_SIZE, 8);
    ocbCtx ctx;
    const size_t pt_word_len = 3*CIPHER_WORD_SIZE;
    uint64_t key[KEY_WORD_SIZE] = { 1234, 1234, 1234, 1234, 4321, 1234, 1234, 1234 };
    uint64_t nonce[KEY_WORD_SIZE] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    uint64_t pt[pt_word_len] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };
    uint64_t pt_scratch[pt_word_len] = { 0 };
    uint64_t ct[pt_word_len+OCB_TAG_WORD_SIZE];
    uint64_t ct_scratch[pt_word_len+OCB_TAG_WORD_SIZE];

    ASSERT_TRUE(ocbSetup(&ctx, key, nonce));
    ocbEncrypt(&ctx, pt, ct, pt_word_len*sizeof(uint64_t));

    for (size_t s=0; s<((pt_word_len-1)/CIPHER_WORD_SIZE); ++s)
    {
        memcpy(ct_scratch, ct, (pt_word_len+OCB_TAG_WORD_SIZE)*sizeof(uint64_t));
        swapBlocks(ct_scratch, s, s+1);
        //swap 2 blocks and try to decrypt
        //Assert that decrypt is invalid
        ASSERT_FALSE(ocbDecrypt(&ctx, ct_scratch, pt_scratch, (pt_word_len+OCB_TAG_WORD_SIZE)*sizeof(uint64_t)));
    }
}

TEST(unitTestOcbMode, XORingCTBlocksCausesTagFail)
{
    ASSERT_EQ(CIPHER_WORD_SIZE, 8);
    ocbCtx ctx;
    const size_t pt_word_len = 3*CIPHER_WORD_SIZE;
    uint64_t key[KEY_WORD_SIZE] = { 1234, 1234, 1234, 1234, 4321, 1234, 1234, 1234 };
    uint64_t nonce[KEY_WORD_SIZE] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    uint64_t pt[pt_word_len] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };
    uint64_t pt_scratch[pt_word_len] = { 0 };
    uint64_t ct[pt_word_len+OCB_TAG_WORD_SIZE];

    ASSERT_TRUE(ocbSetup(&ctx, key, nonce));
    ocbEncrypt(&ctx, pt, ct, pt_word_len*sizeof(uint64_t));

    //XOR all the block from left to right in succession
    //no combination of these should produce a valid tag on decryption
    for (size_t s=0; s<((pt_word_len-1)/CIPHER_WORD_SIZE); ++s)
    {
        xorBlocks(ct, s, s+1);
        //Assert that decrypt is invalid
        ASSERT_FALSE(ocbDecrypt(&ctx, ct, pt_scratch, (pt_word_len+OCB_TAG_WORD_SIZE)*sizeof(uint64_t)));
    }
}
