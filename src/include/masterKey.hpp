#pragma once
/* This class contains data and all the supporting methods for the credCrypt master key */

#include <cstring> //memcpy()
#include <stdint.h> //uintxx_t types
#include <stdlib.h> //size_t
#include "constants.h" // predefined constants
#include "keyBase.hpp" //keyBase class
#include "random.hpp" //get6Bytes()
#include "secureString.hpp" //secStr class
#include "scrypt.h" //kdf_scrypt()
#include "util.h" //hexDecode()

//TODO make this thread safe
class masterKey : public keyBase
{
    private:
    /***************
    * private data *
    ***************/ 
    bool salted_;
    bool keyed_;
    uint64_t salt_[SALT_WORD_SIZE];

    public:
    /***************
    * constructors *
    ***************/ 
    explicit masterKey();
    masterKey(masterKey &Key) = delete; //Copy Ctor not allowed
    masterKey& operator =(masterKey &key) = delete; //Copy assignment not allowed
    masterKey& operator =(masterKey &&key) = delete; //Move assignment nod allowed

    /*****************
    * public members *
    *****************/
    bool genKey(secStr& pw);
    bool inputPassword(secStr& pw);
    bool isSalted() const;
    bool setSalt(const uint64_t* salt_words);
    bool isValid() const;

    /**************************
    * overloaded base members *
    **************************/
    const uint8_t* keyBytes() const;
    const uint8_t* saltBytes() const;
    void clearKey();
    void clearSalt();

    /*************
    * destructor *
    *************/
    ~masterKey();
};
