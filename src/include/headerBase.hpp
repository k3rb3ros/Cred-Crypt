#pragma once

/*
 * The header class is used to store the information required to decrypt serialized credentials
 */

#include <cstdint> //uintxx_t types
#include <cstring> //memcpy
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
    uint64_t salt[SALT_WORD_SIZE] = { 0 };
    //data section
    uint64_t magic_number = MAGIC_NUMBER;
    uint64_t data_size = 0;
    double version_major = VERSION_MAJOR;
    uint64_t version_minor = VERSION_MINOR;
    //end data section
    uint64_t tag[OCB_TAG_WORD_SIZE] = { 0 }; //does not count as header data
};

//TODO add a reference to the timer to prevent the key from timing out when performing operations that need it
class headerBase
{
    public:
    /**************
    * Constructor *
    **************/
    explicit headerBase(masterKey* master_key) : mk_(master_key)
    {
        if (mk_ != nullptr)
        {
            //copy the salt to the header if the masterKey is salted
            if (mk_->isSalted())
            {
                memcpy((uint8_t*)header_.salt, mk_->saltBytes(), SALT_BYTE_SIZE);
            }
        }
        else { throw NullKeyException(); }
    }
    
    /*************
    * Destructor *
    *************/
    ~headerBase() noexcept
    {
        clearBuff((uint8_t*)&header_, sizeof(header));
    }

    bool isValid() const
    {
        return (mk_ != nullptr &&
                mk_->isSalted() &&
                header_.salt[0] != 0 &&
                header_.salt[SALT_WORD_SIZE-1] != 0);
    }
    
    protected:
    /*****************
    * Protected Data *
    *****************/
    masterKey* mk_;
    header header_;
};
