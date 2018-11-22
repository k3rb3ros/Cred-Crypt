/*
* These are misc utility functions that other functions and class methods use internally but aren't complicated enough to warrant their own class
*/
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h> //bool types
#include <stddef.h> //size_t
#include <stdint.h> //uint64_t type
#include <sys/stat.h> //stat struct, stat()
#include <termios.h> //tcgetattr()

/****************************
* Hex Encoding lookup table *
****************************/
typedef struct
{
    uint8_t hex;
    uint8_t byte;
} hex_byte_lookup;

//used in inline hexDeLookup()
const static hex_byte_lookup hex_table[] =
{
    { '0', 0 }, { '1', 1 }, { '2', 2 }, { '3', 3 }, { '4', 4 }, { '5', 5 },
    { '6', 6 }, { '7', 7 }, { '8', 8 }, { '9', 9 }, { 'a', 10 }, { 'b', 11 },
    { 'c', 12 }, { 'd', 13 }, { 'e', 14 }, { 'f', 15 }
};

//return true if the passed in filename exists on the mounted file system
bool exists(const char* filename);

//returns true if the selected buffer is NULL filled
bool isEmpty(const uint8_t* buffer, size_t byte_size);

//return true if ch is a number
bool isNum(const char ch);

// return false if an invalid serialized character is present
bool isValidChar(const char ch);

//compare two same sized uint64_t buffers
int_fast8_t compareWordBuff(const uint64_t* buf_1, const uint64_t* buf_2, size_t word_len);

//Return the Gray (Reflected Binary) Code of the given byte
uint_fast8_t bin2GrayByte(const uint_fast8_t bin);

//Return the Gray (Reflected Binary) Code of the given word
uint64_t bin2Gray(const uint64_t bin);

/*
 * Decodes a hex string back to its original ascii values
 * assumes a buffer of 1/2 the size of the hex string is correctly allocated
 */
uint8_t* hexDecode(const uint8_t* hex, uint8_t* buffer, const size_t hex_byte_size);

/* Encodes any given byte into its hexidecimal value
 * assumes buffer is a correctly allocated ptr to a buffer of 2x the byte size of txt
 */
uint8_t* hexEncode(const uint8_t* text, uint8_t* buffer, const size_t txt_byte_size);

/*zero fills the given buffer of given size*/
void clearBuff(void* buffer, size_t byte_size);

//Flip the given bit in a buffer (of at least that size)
void flipBit(void* buffer, const size_t bit_to_flip);

#ifdef __cplusplus
}
#endif /* c++ */
