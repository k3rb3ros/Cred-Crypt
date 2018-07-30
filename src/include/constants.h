/*
 * This header file allows compile time constants to be in a single place decoupling them
 * from any c++ code allowing them to be easily changed and viewed.
*/

#pragma once

//TODO make all of these that aren't referenced in C code constexpr

#ifdef __cplusplus
extern "C"
{
#endif

    #include "skeinApi.h"
    #include "threefishApi.h"

    #ifndef KeyScheduleConst
    #error "Threefish macros not defined"
    #endif

    /*************************
    * Crypto primative sizes *
    **************************/
    #define CIPHER_BIT_SIZE 512
    #define CIPHER_BYTE_SIZE ((CIPHER_BIT_SIZE)/8)
    #define CIPHER_WORD_SIZE ((CIPHER_BYTE_SIZE)/8)
    #define HASH_BIT_SIZE 512
    #define HASH_BYTE_SIZE ((HASH_BIT_SIZE)/8)
    #define HASH_WORD_SIZE ((HASH_BYTE_SIZE)/8)
    #define KEY_BYTE_SIZE ((CIPHER_BIT_SIZE)/8)
    #define KEY_WORD_SIZE ((KEY_BYTE_SIZE)/8)
    #define OCB_TAG_BIT_SIZE 64
    #define OCB_TAG_BYTE_SIZE ((OCB_TAG_BIT_SIZE)/8)
    #define OCB_TAG_WORD_SIZE ((OCB_TAG_BYTE_SIZE)/8)
    #define SALT_BIT_SIZE CIPHER_BIT_SIZE
    #define SALT_BYTE_SIZE ((SALT_BIT_SIZE)/8)
    #define SALT_WORD_SIZE ((SALT_BYTE_SIZE)/8)
    #define SKEIN_SIZE Skein512
    #define THREE_FISH_SIZE Threefish512

    /***********************
    * credential constants *
    ***********************/
    #define ID_BYTE_SIZE HASH_BYTE_SIZE
    #define ID_WORD_SIZE HASH_WORD_SIZE
    #define MIN_SER_CRED_SIZE 48

    /***********************
    * header element sizes *
    ***********************/
    #define MAGIC_NUM_BYTE_SIZE sizeof(uint64_t)
    #define CREDENTIAL_BYTE_SIZE sizeof(uint64_t)
    #define VERSION_MAJ_BYTE_SIZE sizeof(double)
    #define VERSION_MIN_BYTE_SIZE sizeof(double)
    #define HEADER_DATA_BYTE_SIZE MAGIC_NUM_BYTE_SIZE + VERSION_MAJ_BYTE_SIZE + VERSION_MIN_BYTE_SIZE + CREDENTIAL_BYTE_SIZE
    #define HEADER_DATA_WORD_SIZE ((HEADER_DATA_BYTE_SIZE)/sizeof(uint64_t))

    /********************
    * scrypt parameters *
    *********************/
    //if these get changed any previously saved credentials will no longer decryptable
    #define SCRYPT_N 16384
    #define SCRYPT_R 32
    #define SCRYPT_P 1

    /*********************
    * White space MACROS *
    *********************/
    #define TAB "    " 
#ifdef __cplusplus
}
#endif //end extern "C"
