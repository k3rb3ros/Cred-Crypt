#pragma once

/*
 * The header class is used to store the information required to decrypt serialized credentials
 */

#include <algorithm> //std::copy, std::fill
#include <array> //std::aray
#include <cstdint> //uintxx_t types
#include "constants.h" //SALT_WORD_SIZE
#include "exceptions.hpp" //nullKeyException
#include "masterKey.hpp" //masterKey class
#include "version.h" //VERSION_MAJ, VERSION_MIN macros

//A randomly selected 19 digit prime used to uniquely identify a CredCrypt header
#define MAGIC_NUMBER 0x4797DF36484F57BDULL

/*
 * The MAGIC_NUMBER is stored as a 64 bit unsigned integer
 * The VERSION_MAJOR is stored as a double (64 bit floating point number)
 * The VERSION_MINOR is stored as a double (64 bit floating point number)
 * The total header is 88bytes
 *                          HEADER STRUCTURE
 *|##############################SALT###############################|
 *|MAGIC_NUMBER|CREDENTIAL_SIZE|VERSION_MAJOR|VERSION_MINOR|TAG|
 */
struct header
{
    //Crypto section
    std::array<uint64_t, SALT_WORD_SIZE> salt{};
    //data section
    uint64_t magic_number{MAGIC_NUMBER};
    uint64_t data_size{0};
    double version_major{VERSION_MAJOR};
    uint64_t version_minor{VERSION_MINOR};
    //end data section
    std::array<uint64_t, OCB_TAG_WORD_SIZE> tag{}; //does not count as header data
};

//TODO add a reference to the timer to prevent the key from timing out when performing operations that need it
class headerBase
{
    public:
    /**************
    * Constructor *
    **************/
    explicit headerBase(masterKey& master_key) : mk_(master_key)
    {
        //copy the salt to the header if the masterKey is salted
        if (mk_.isSalted())
        {
            std::copy(mk_.saltBytes(), mk_.saltBytes()+mk_.byteSize(), (uint8_t*)header_.salt.data());
        }
    }

    /*************
    * Destructor *
    *************/
    ~headerBase() noexcept
    {
        std::fill((uint8_t*)&header_, (uint8_t*)&header_ + sizeof(header), 0);
    }

    bool isValid() const
    {
        return (mk_.isSalted() &&
                header_.salt[0] != 0 &&
                header_.salt[SALT_WORD_SIZE-1] != 0);
    }

    protected:
    /*****************
    * Protected Data *
    *****************/
    masterKey& mk_;
    header header_{};
};
