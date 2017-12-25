#pragma once

#include <fstream> //ifstream
#include <stdint.h> //uintx_t types
#include "util.h" //exists()

#define HW_RNG "/dev/hwrng" //hardware random number device
#define PRNG "/dev/urandom" //*nix pseudo random number device
#define LRNG "/dev/random" //*nix random number source (blocks)
/*
* This class is an interface to connect to the sources of random entropy provided by *nix operating systems.
* It tries to open /dev/hwrng first
* then /dev/urandom
*/

class Random
{
    public:

    /*******
    * CTOR *
    ********/
    Random();

    /*****************
    * public members *
    *****************/
    bool isGood();
    bool getBytes(uint8_t* buffer, size_t byte_size);
    uint8_t getByte();
    uint8_t getByte(uint8_t upper_lim);
    uint32_t getInt();
    uint32_t getInt(uint32_t upper_lim);
    uint64_t getLong();
    uint64_t getLong(uint64_t upper_lim);
    uint8_t* getBytes(size_t byte_size);

    /*******
    * DTOR *
    *******/
    ~Random();

    /***************
    * private data *
    ***************/
    private:
    bool is_good;
    std::ifstream rand;
};
