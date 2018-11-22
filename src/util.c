#include "include/util.h"

bool exists(const char* filename)
{
    struct stat st;

    return (stat(filename, &st) == 0 && (st.st_mode & S_IROTH));
}

bool isEmpty(const uint8_t* buffer, size_t byte_size)
{
    for (;byte_size>0; --byte_size)
    {
        if (buffer[byte_size-1] != 0) { return false; }
    }

    return true;
}

bool isNum(const char ch)
{
    return (ch == '0' || ch == '1' || ch == '2' || ch == '3' || ch == '4' || 
            ch == '5' || ch == '6' || ch == '7' || ch == '8' || ch == '9');
}

bool isValidChar(const char ch)
{
    return (
               (ch >= 0x30 && ch <= 0x39) ||
               (ch >= 0x61 && ch <= 0x7a) ||
               (ch >= 0x41 && ch <= 0x5a) ||
               ch == '_' || ch == ',' || ch == '"'
           );
}

//looks up the hex encoding for a nibble value (between 0-15)
static char hexNibbleLookup(const uint8_t hex_nibble)
{
    return (hex_nibble <= 0xF) ? hex_table[hex_nibble].hex : '\0';
}

static uint8_t hexDeLookup(const uint8_t* hex)
{
    uint8_t ch = '\0';

    if (hex != NULL)
    {
        uint8_t hex1 = *hex;
        uint8_t hex2 = *(hex + 1);

        /* iterate through the table and lookup the ascii character for the 
         * corresponding hex
         * shift the 1st hex number encoding left by 4 bits
         * and add the 2nd hex number encoding in place
         */
        for (uint8_t c=0; c<=0xF; ++c)
        {
            if (hex_table[c].hex == hex1)
            { ch |= (hex_table[c].byte<<4); }
            if (hex_table[c].hex == hex2)
            { ch |= hex_table[c].byte; }
        }
    }

    return ch;
}

int_fast8_t compareWordBuff(const uint64_t* buf_1, const uint64_t* buf_2, size_t buf_len)
{
    for (; buf_len > 0; buf_1++, buf_2++, --buf_len)
    {
        if (*buf_1 != *buf_2)
        {
            return (*buf_1 < *buf_2) ? -1 : +1;
        }
    }

    return 0;
}

uint_fast8_t bin2GrayByte(const uint_fast8_t bin) { return (bin ^ (bin >> 1)); }

uint64_t bin2Gray(const uint64_t bin) { return (bin ^ (bin >> 1)); }

uint8_t* hexDecode(const uint8_t* hex, uint8_t* buffer, const size_t hex_byte_size)
{
    uint8_t* text = NULL;

    if (hex!= NULL && hex_byte_size%2 == 0)
    {
        size_t a = 0;
        for (size_t b=0; b<hex_byte_size; b+=2)
        {
            buffer[a++] = hexDeLookup(&hex[b]);
        }
        text = buffer;
    }

    return text;
}

uint8_t* hexEncode(const uint8_t* text, uint8_t* buffer, const size_t txt_byte_size)
{
    uint8_t* hex = NULL;
    if (buffer != NULL && txt_byte_size > 0)
    {
        for (size_t i=0; i<txt_byte_size; ++i)
        {
            buffer[(2*i)+0] = hexNibbleLookup((text[i]&0xF0)>>4);
            buffer[(2*i)+1] = hexNibbleLookup(text[i]&0xF);
        }
        hex = buffer;
    }

    return hex;
}

void clearBuff(void* buffer, size_t byte_size)
{
    for (;byte_size>0; --byte_size) { ((uint8_t*)buffer)[byte_size-1] = 0; }
}

void flipBit(void* buffer, const size_t bit_to_flip)
{
    size_t ind = bit_to_flip/8;
    size_t bit = bit_to_flip % 8;

    //flip the bit
    ((uint8_t*)buffer)[ind] ^= (1 << bit);
}
