#pragma once
/* This class contains data and all the supporting methods for the credCrypt master key */

#include <array> //std::array
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
class masterKey : protected keyBase<CIPHER_WORD_SIZE>
{
    private:
    /******************
    * private members *
    ******************/
    bool passwordMeetsRequirements(const secStr& pw);

    public:
    /***************
    * constructors *
    ***************/
    explicit masterKey();
    explicit masterKey(secStr& salt_hex);
    masterKey(const masterKey &Key) = delete; //Copy Ctor not allowed
    masterKey(masterKey &Key) = delete; //Copy Ctor not allowed
    masterKey& operator =(masterKey &key) = delete; //Copy assignment not allowed
    masterKey& operator =(masterKey &&key) = delete; //Move assignment nod allowed

    /*************
    * destructor *
    *************/
    ~masterKey() = default;

    /*****************
    * public members *
    *****************/
    bool genKey(secStr& pw);
    bool isKeyed() const;
    bool isSalted() const;
    bool isValid() const;
    bool inputPassword(secStr& pw);
    bool setKey(const uint64_t* key_words);
    bool setSalt(const uint64_t* salt_words);
    const uint8_t* keyBytes() const;
    const uint64_t* keyData() const;
    const uint8_t* saltBytes() const;

    size_t size() const;
    void clearSalt();
    void clearKey();

    /************
    * operators *
    ************/
    bool operator == (const keyBase& rhs) const;
    bool operator == (const keyBase* rhs) const;
};
