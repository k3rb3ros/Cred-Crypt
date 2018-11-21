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
class masterKey : public keyBase
{
    private:
    /***************
    * private data *
    ***************/
    bool salted_{false};
    std::array<uint64_t, SALT_WORD_SIZE> salt_{};
    std::array<uint64_t, KEY_WORD_SIZE> key_{};

    bool passwordMeetsRequirements(const secStr& pw);

    public:
    /***************
    * constructors *
    ***************/
    explicit masterKey() = default;
    masterKey(masterKey &Key) = delete; //Copy Ctor not allowed
    masterKey& operator =(masterKey &key) = delete; //Copy assignment not allowed
    masterKey& operator =(masterKey &&key) = delete; //Move assignment nod allowed

    /**************************
    * overloaded base members *
    **************************/
    bool isKeyed() const;
    const uint8_t* keyBytes() const;
    const uint64_t* getData() const;
    const uint8_t* saltBytes() const;

    size_t size() const;

    bool operator == (const keyBase& rhs) const;
    bool operator == (const keyBase* rhs) const;

    void clearKey();

    /*****************
    * public members *
    *****************/
    bool genKey(secStr& pw);
    bool inputPassword(secStr& pw);
    bool isSalted() const;
    bool setKey(const uint64_t* key_words);
    bool setSalt(const uint64_t* salt_words);
    bool isValid() const;
    void clearSalt();

    /*************
    * destructor *
    *************/
    ~masterKey();
};
