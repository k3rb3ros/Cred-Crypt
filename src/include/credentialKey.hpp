/* This class contains data and all the supporting methods for cryptographic keys for credentials.
 * Credential keys are derrived from from the master key by xoring their own randomly generated salt with the master key and hashing that with Skein.
 * They can be regenerated only if the master key is present (returning non null keys with getKeyBytes()) and the credentialKey is salted.
 */

#pragma once

#include <memory> //std::unique_ptr
#include <stdint.h> //uintxx_t types
#include "constants.h" //SALT_BYTE_SIZE
#include "exceptions.hpp" //NullKeyException
#include "hash.h" //skeinHash()
#include "masterKey.hpp" //masterKey* type
#include "random.hpp" //getBytes()
#include "secureString.hpp" //secStr class
#include "util.h" //clearBuff(), hexDecode()

using std::unique_ptr;
#ifdef KEY_DEBUG
#include <iostream> //std::cout, std::endl
using std::cout;
using std::endl;
#endif

class credentialKey : public keyBase
{
    private:
    /***************
    * private data *
    ***************/
    bool salted_;
    bool valid_;
    const masterKey* mk_;
    uint64_t salt_[SALT_WORD_SIZE];

    public:
    /***************
    * constructors *
    ***************/
    credentialKey() = delete; //default Ctor not allowed
    explicit credentialKey(const masterKey* mk);
    explicit credentialKey(const masterKey* mk, secStr& salt_hex);

    credentialKey(credentialKey &Key) = delete; //Copy Ctor not allowed
    credentialKey& operator =(credentialKey &Key) = delete; //Copy assignment not allowed
    credentialKey& operator =(credentialKey &&Key) = delete; //Move asgnmnt not allowed

    /*****************
    * public members *
    *****************/
    bool genKey();
    bool isValid() const;
    const uint8_t* saltBytes() const;

    /**************************
    * overloaded base members *
    **************************/
    size_t size() const;
    secStr saltHex() const;
    const uint8_t* keyBytes() const;
    void clearKey();

    #ifdef KEY_DEBUG
    void debugKey() const;
    #endif

    /*************
    * destructor *
    *************/
    ~credentialKey();
};
