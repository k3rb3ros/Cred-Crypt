#include "include/ocbMode.h"

static bool tagsMatch(const uint64_t* T, const uint64_t* T_prime)
{
    assert(OCB_TAG_WORD_SIZE == 1);
    return (T[0] == T_prime[0]);
}

static uint_fast8_t lastBit(const block_t blk)
{
    //Return the Most Significant Bit
    return ((blk[0] & 0x8000000000000000ull) >> 63);
}

static void clearBlock(block_t blk)
{
    assert(CIPHER_WORD_SIZE == 8);
    blk[0] = 0;
    blk[1] = 0;
    blk[2] = 0;
    blk[3] = 0;
    blk[4] = 0;
    blk[5] = 0;
    blk[6] = 0;
    blk[7] = 0;
}

static void clearWords(uint64_t* words, size_t num_words)
{
    for (;num_words>0; num_words--)
    {
        words[num_words-1] = 0;
    }
}

//This is used to calculate L * X^-1
static void GF_2N_Mult(const block_t a, block_t dst)
{
    assert(CIPHER_WORD_SIZE == 8);
    /*
     * It is similarly easy to divide a ∈ {0, 1}
     * by x (i.e., to multiply a by the multi-plicative inverse of x).
     * If the last bit of a is 0, then a · x^−1 is a>>1
     */
    if (lastBit(a) == 0)
    {
        dst[0] = a[0] >> 1;
        dst[1] = a[1] >> 1;
        dst[2] = a[2] >> 1;
        dst[3] = a[3] >> 1;
        dst[4] = a[4] >> 1;
        dst[5] = a[5] >> 1;
        dst[6] = a[6] >> 1;
        dst[7] = a[7] >> 1;
    }
    else
    /*
     * If the last bit of a is 1 then we must add (xor) to a>>1 the value x^−1
     * x^-1 = P512(x) = X^512 + X^8 + X^5 + X^2 + 1
     */
    {
        assert(lastBit(a) > 0);
        dst[0] = (a[0] >> 1) ^ bitfield_512[0];
        dst[1] = (a[1] >> 1) ^ bitfield_512[1];
        dst[2] = (a[2] >> 1) ^ bitfield_512[2];
        dst[3] = (a[3] >> 1) ^ bitfield_512[3];
        dst[4] = (a[4] >> 1) ^ bitfield_512[4];
        dst[5] = (a[5] >> 1) ^ bitfield_512[5];
        dst[6] = (a[6] >> 1) ^ bitfield_512[6];
        dst[7] = (a[7] >> 1) ^ bitfield_512[7];
    }
}

static uint_fast8_t ntz(uint64_t i)
{
    //return the number of trailing zeros in the direction of the least significant bit
    uint_fast8_t trailing_zeros = 0;

    while ((i & 0x1) == 0)
    {
        trailing_zeros++;
        i = (i >> 1);
    }

    return trailing_zeros;
}

static void cpyBlock(const block_t src, uint64_t* dst)
{
    assert(CIPHER_WORD_SIZE == 8);
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
    dst[4] = src[4];
    dst[5] = src[5];
    dst[6] = src[6];
    dst[7] = src[7];
}

static void updGrayCodeInBlk(block_t Z, const block_t L, const uint64_t i)
{
    assert(CIPHER_WORD_SIZE == 8);
    if (i > 0)
    {
        Z[0] = Z[0] ^ (L[0] << ntz(i));
        Z[1] = Z[1] ^ (L[1] << ntz(i));
        Z[2] = Z[2] ^ (L[2] << ntz(i));
        Z[3] = Z[3] ^ (L[3] << ntz(i));
        Z[4] = Z[4] ^ (L[4] << ntz(i));
        Z[5] = Z[5] ^ (L[5] << ntz(i));
        Z[6] = Z[6] ^ (L[6] << ntz(i));
        Z[7] = Z[7] ^ (L[7] << ntz(i));
    }
}

static void xorBlock(const block_t lhs, const block_t rhs, block_t dst)
{
    assert(CIPHER_WORD_SIZE == 8);

    dst[0] = lhs[0] ^ rhs[0];
    dst[1] = lhs[1] ^ rhs[1];
    dst[2] = lhs[2] ^ rhs[2];
    dst[3] = lhs[3] ^ rhs[3];
    dst[4] = lhs[4] ^ rhs[4];
    dst[5] = lhs[5] ^ rhs[5];
    dst[6] = lhs[6] ^ rhs[6];
    dst[7] = lhs[7] ^ rhs[7];
}

//zero pads unused space in a block
static void zeroPadBlock(block_t blk, size_t occ_bytes)
{
    uint8_t* fill = (uint8_t*)blk;

    for (;occ_bytes < CIPHER_BYTE_SIZE; occ_bytes++)
    {
        fill[occ_bytes] = 0;
    }
}

void ocbEncrypt(ocbCtx* ctx, const void* in, void* out, size_t enc_bytes)
{
    block_t Checksum = { 0 }; //Used to compute the Tag
    block_t C_op = { 0 }; //Used to store the Cipher text block before writting it to out
    block_t L = { 0 }; //Precompute L
    block_t M_op = { 0 }; //Used to store the Message Block before encryption
    block_t R = { 0 }; //Precompute R
    block_t T = { 0 }; //Tag
    block_t X = { 0 }; //Input of Encryption
    block_t Y = { 0 }; //Output of the Encryption
    block_t Z = { 0 }; //Gray Code Block
    uint64_t* M = (uint64_t*) in;
    uint64_t* C = (uint64_t*) out;
    //Partition M into M[1]...M[m]
    size_t i = 0; //block operation counter
    size_t loop_ops = (enc_bytes % CIPHER_BYTE_SIZE == 0) ?
        (enc_bytes/CIPHER_BYTE_SIZE)-1 : (enc_bytes/CIPHER_BYTE_SIZE);

    threefishEncryptBlockWords(&ctx->tf_ctx, L, L); //L = Ek(0^n)
    //R = Ek(N XOR L)
    xorBlock(ctx->nonce, L, R); //R = (N XOR L)
    threefishEncryptBlockWords(&ctx->tf_ctx, R, R); //R = Ek(R)

    //Yi is the cannonical Gray code at zero it is defined as Z[0] = (L XOR R)
    xorBlock(L, R, Z);

    //for i <- 1 to m-1 (this leaves room for a final block operation)
    for (; //i initialized to zero
         i<(loop_ops*CIPHER_WORD_SIZE); //i gets incremented by CIPHER_WORD_SIZE each loop
         i+=CIPHER_WORD_SIZE, enc_bytes-=CIPHER_BYTE_SIZE) //increment i and decrypment enc_bytes
    {
        cpyBlock(&M[i], M_op); //M_op = M[i]

        //Checksum = M[1] XOR ... XOR M[m-1] XOR C[m]0* XOR Y[m]
        if (i == 0) { cpyBlock(M_op, Checksum); }
        else { xorBlock(Checksum, M_op, Checksum); }

        updGrayCodeInBlk(Z, L, i); //Z[i] = Yi * (L XOR R)
        //C[i] = Ek(M[i] XOR Z[i]) XOR Z[i]
        xorBlock(M_op, Z, M_op); //M_op = (M[i] XOR Z[i])
        threefishEncryptBlockWords(&ctx->tf_ctx, M_op, C_op); //C_op = Ek(M_op)
        xorBlock(C_op, Z, C_op); // C_op = (C_op XOR Z)
        cpyBlock(C_op, &C[i]); //C[i] = C_op
    }

    assert(enc_bytes <= CIPHER_BYTE_SIZE);

    //Last Block to encrypt(may be partial)
    clearBlock(M_op); //zero fill M_op
    M_op[CIPHER_WORD_SIZE-1] = enc_bytes; //M_op = len(M[m])

    //X[m] = len(M[m]) XOR L * X^-1 XOR Z[m]
    GF_2N_Mult(L, X); //X[m] = L * X^-1
    xorBlock(M_op, X, X); //X[m] = M[m] XOR (L * X^-1)
    updGrayCodeInBlk(Z, L, i); //get the next Gray Code Z[m]
    xorBlock(X, Z, X); //X[m] = X[m] XOR Z[m]

    clearBlock(M_op); //clear M_op to resuse it
    memcpy(M_op, &M[i], enc_bytes); //put M[m] into M_op so we can treat it as a whole block
    threefishEncryptBlockWords(&ctx->tf_ctx, X, Y); //Y[m] = Ek(X[m])
    xorBlock(Y, M_op, C_op); //C[m] = Y[m] XOR M[m]
    memcpy(&C[i], C_op, enc_bytes); // write C[m] to output

    //Checksum <- M[1] XOR ... XOR M[m-1] XOR (C[m]0*) XOR Y[m]
    zeroPadBlock(C_op, enc_bytes); //C_op = C[m]0*
    xorBlock(Checksum, C_op, Checksum); //... XOR (C[m]0*)
    xorBlock(Checksum, Y, Checksum); //... XOR Y[m]

    //T = Ek(Checksum XOR Z[m]) [first T bits]
    assert(OCB_TAG_WORD_SIZE > 0);
    xorBlock(Checksum, Z, T); //T = Checksum XOR Z[m]
    threefishEncryptBlockWords(&ctx->tf_ctx, T, T); //T =  Ek(T);
    void* tag_append = ((uint8_t*)&C[i])+enc_bytes;
    memcpy(tag_append, T, OCB_TAG_BYTE_SIZE); //Append the tag to the end of the cipher text
}

bool ocbDecrypt(ocbCtx* ctx, const void* in, void* out, size_t dec_bytes)
{
    bool valid = false;

    if (ctx != NULL &&
        in != NULL &&
        out != NULL &&
        dec_bytes > OCB_TAG_BYTE_SIZE) //only continue if there is something to decrypt
    {
        block_t Checksum = { 0 }; //Used to compute the Tag
        block_t C_op = { 0 }; //Stores result of operations on the Cipher Text block
        block_t L = { 0 }; //Precompute L
        block_t M_op = { 0 }; //Stores the result of operations on the Message block
        block_t R = { 0 }; //Precompute R
        block_t T_prime = { 0 }; //Calculated Tag
        block_t X = { 0 }; //Input of decryption
        block_t Y = { 0 }; //Result of the decryption operation
        block_t Z = { 0 }; //Gray Code
        size_t i = 0; //block operation counter
        uint64_t* C = (uint64_t*) in;
        uint64_t* M = (uint64_t*) out;
        //Partition C into C[1]...C[m]T

        dec_bytes -= OCB_TAG_BYTE_SIZE; //remove the size of the Tag from loop op calculations
        size_t loop_ops = (dec_bytes % CIPHER_BYTE_SIZE == 0) ?
            (dec_bytes/CIPHER_BYTE_SIZE)-1 : //true
            (dec_bytes/CIPHER_BYTE_SIZE); //false

        threefishEncryptBlockWords(&ctx->tf_ctx, L, L); //L = Ek(0^n)
        //R = Ek(N XOR L)
        xorBlock(ctx->nonce, L, R); //R = (N XOR L)
        threefishEncryptBlockWords(&ctx->tf_ctx, R, R); //R = Ek(R)

        //Yi is the cannonical Gray code at zero it is defined as Z[0] = (L XOR R)
        xorBlock(L, R, Z);

        //for i <- 1 to m-1 (this leaves room for a final block operation)
        for (; //i gets initialized to zero at declaration
             i<(loop_ops*CIPHER_WORD_SIZE); //i gets incremented by CIPHER_WORD_SIZE each loop
             i+=CIPHER_WORD_SIZE, dec_bytes-=CIPHER_BYTE_SIZE)
        {
            cpyBlock(&C[i], C_op);
            updGrayCodeInBlk(Z, L, i); //Z[i] = Yi * (L XOR R)
            //M[i] = Ek(C[i] XOR Z[i]) XOR Z[i]
            xorBlock(C_op, Z, C_op); //C_op = (C[i] XOR Z[i])
            threefishDecryptBlockWords(&ctx->tf_ctx, C_op, M_op); //C_op = Ek(C[i])
            xorBlock(M_op, Z, M_op); //M_op = (M[i] XOR Z) //decryption is complete here

            //Checksum = M[1] XOR ... XOR M[m-1] XOR C[m]0* XOR Y[m]
            if (i == 0) { cpyBlock(M_op, Checksum); }
            else { xorBlock(Checksum, M_op, Checksum); }

            //copy the decrypted block to the output buffer
            cpyBlock(M_op, &M[i]); //M[i] = M_op
        }

        assert(dec_bytes <= CIPHER_BYTE_SIZE);

        //Last Block to decrypt(may be partial)
        clearBlock(C_op); //zero fill C_op
        C_op[CIPHER_WORD_SIZE-1] = dec_bytes; //C_op = len(C[m])

        //X[m] = len(C[m]) XOR L * X^-1 XOR Z[m]
        GF_2N_Mult(L, X); //X[m] = L * X^-1
        xorBlock(C_op, X, X); //X[m] = C[m] XOR (L * X^-1)
        updGrayCodeInBlk(Z, L, i); //get the next Gray Code Z[m]
        xorBlock(X, Z, X); //X[m] = X[m] XOR Z[m]

        memcpy(C_op, &C[i], dec_bytes); //C_op = C[m] //store the Cipher text
        zeroPadBlock(C_op, dec_bytes); //C_op = C[m]0*

        threefishEncryptBlockWords(&ctx->tf_ctx, X, Y); //Y[m] = Ek(X[m])
        xorBlock(Y, C_op, M_op); //M_op = Y[m] XOR C[m] Decrypt the cipher text
        memcpy(&M[i], M_op, dec_bytes); //M = M[1]...M[m]

        //Checksum <- M[1] XOR ... XOR M[m-1] XOR (C[m]0*) XOR Y[m]
        xorBlock(Checksum, C_op, Checksum); //... XOR (C[m]0*)
        xorBlock(Checksum, Y, Checksum); //... XOR Y[m]

        //T = Ek(Checksum XOR Z[m]) [first T bits]
        assert(OCB_TAG_WORD_SIZE > 0);
        xorBlock(Checksum, Z, T_prime); //T = Checksum XOR Z[m]
        threefishEncryptBlockWords(&ctx->tf_ctx, T_prime, T_prime); //T =  Ek(T);
        void* T = ((uint8_t*)&C[i])+dec_bytes;

        if (tagsMatch(T, T_prime)) //we have succesfully decrypted a valid cipher text
        {
            valid = true;
            //if we are decrypting in place then zero fill the tag
            if (C == M) { clearWords((uint64_t*)T, OCB_TAG_WORD_SIZE); }
        }
    }

    return valid;
}

bool ocbSetup(ocbCtx* ctx, uint64_t* key, const uint64_t* nonce)
{
    bool success = false;

    if (ctx != NULL && key != NULL && nonce != NULL)
    {
        cpyBlock(nonce, ctx->nonce);
        threefishSetKey(&ctx->tf_ctx, Threefish512, key, tf_tweak);
        if (ctx->tf_ctx.key[0] != 0ULL) { success = true; } //Null keys are not allowed
    }

    return success;
}
