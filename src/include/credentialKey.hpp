#pragma once

#include <array> // std::array
#include <memory> //std::unique_ptr
#include <stdint.h> //uintxx_t types
#include "constants.h" //SALT_BYTE_SIZE
#include "exceptions.hpp" //NullKeyException
#include "hash.h" //skeinHash()
#include "masterKey.hpp" //masterKey* type
#include "random.hpp" //getBytes()
#include "secureString.hpp" //secStr class
#include "util.h" //clearBuff(), hexDecode()

#ifdef KEY_DEBUG
#include <iostream> //std::cout, std::endl
using std::cout;
using std::endl;
#endif

/* This class contains data and all the supporting methods for cryptographic keys for credentials.
 * Credential keys are derrived from from the master key by xoring their own randomly generated salt with the master key and hashing that with Skein.
 * They can be regenerated only if the master key is present (returning non null keys with getKeyBytes()) and the credentialKey is salted.
 */
class credentialKey : protected keyBase<CIPHER_WORD_SIZE>
{
    private:
    /***************
    * private data *
    ***************/
    const masterKey& mk_;

    public:
    /***************
    * constructors *
    ***************/
    explicit credentialKey(const masterKey& mk);
    explicit credentialKey(const masterKey& mk, secStr& salt_hex);
    credentialKey() = delete; //default construction not allowed
    credentialKey(const credentialKey &Key) = delete; //Copy construction not allowed
    credentialKey(credentialKey &Key) = delete; //Copy Ctor construction not allowed
    credentialKey& operator =(credentialKey &Key) = delete; //Copy assignment not allowed
    credentialKey& operator =(credentialKey &&Key) = delete; //Move asgnmnt not allowed

    /*************
    * destructor *
    *************/
    ~credentialKey() = default;

    /*****************
    * public members *
    *****************/
    bool genKey();
    bool isSalted() const;
    bool isValid() const;
    const uint8_t* saltBytes() const;
    const uint8_t* keyBytes() const;
    const uint64_t* keyData() const;
    secStr saltHex() const;
    constexpr size_t byteSize() const;
    constexpr size_t dataSize() const;
    void clearKey();

    #ifdef KEY_DEBUG
    void debugKey() const;
    #endif
};
